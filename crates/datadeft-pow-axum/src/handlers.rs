//! Headless proof-of-work admission glue.
//!
//! The library runs the PoW checks and returns structured results. The
//! consuming app owns routing, body extraction, `Content-Type`, and origin
//! checks (its admission concern) and renders the response. Two steps:
//!
//! 1. [`mint_pow_challenge`]: stateless challenge mint for `pow/create`.
//! 2. [`verify_pow_solution`]: verify a posted solution for `pow/validate`
//!    and, on success, return the `Set-Cookie` header that admits the browser.
//!
//! Every verification failure collapses into [`PowFlowError::Rejected`] so the
//! app can answer with one generic status and leak nothing about which check
//! failed.

use core::fmt;

use axum::http::HeaderValue;
use datadeft_auth_token_core::keyring::KeyRing;
use datadeft_pow_core::{
    Challenge, MAX_DIFFICULTY, MAX_FUTURE_SKEW_SECS, PowProofCookie, PowSecret, Solution,
    UnixMillis, mint_challenge, mint_pow_proof_cookie, verify_solution_with_clock_skew,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::cookie::PowProofCookieConfig;

/// Default challenge lifetime: a solution must arrive within two minutes of
/// its mint. Matches the shipped deployment.
pub const DEFAULT_POW_CHALLENGE_MAX_AGE_SECS: u64 = 120;

/// Validated proof-of-work admission policy shared by mint and verify.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PowPolicy {
    difficulty: u8,
    challenge_max_age_secs: u64,
    clock_skew_secs: u64,
}

/// The configured PoW policy is out of range.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PowPolicyError {
    /// Difficulty must be in `1..=MAX_DIFFICULTY`.
    InvalidDifficulty,
    /// The challenge lifetime must be nonzero.
    InvalidChallengeMaxAge,
}

impl fmt::Display for PowPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDifficulty => "PoW difficulty must be in 1..=MAX_DIFFICULTY",
            Self::InvalidChallengeMaxAge => "PoW challenge max age must be nonzero",
        })
    }
}

impl std::error::Error for PowPolicyError {}

impl PowPolicy {
    /// Build a validated policy. `difficulty` must be in `1..=MAX_DIFFICULTY`
    /// and `challenge_max_age_secs` nonzero.
    pub fn new(difficulty: u8, challenge_max_age_secs: u64) -> Result<Self, PowPolicyError> {
        if difficulty == 0 || difficulty > MAX_DIFFICULTY {
            return Err(PowPolicyError::InvalidDifficulty);
        }
        if challenge_max_age_secs == 0 {
            return Err(PowPolicyError::InvalidChallengeMaxAge);
        }
        Ok(Self {
            difficulty,
            challenge_max_age_secs,
            clock_skew_secs: MAX_FUTURE_SKEW_SECS,
        })
    }

    #[must_use]
    pub fn difficulty(&self) -> u8 {
        self.difficulty
    }

    #[must_use]
    pub fn challenge_max_age_secs(&self) -> u64 {
        self.challenge_max_age_secs
    }

    /// Allow challenge timestamps this many seconds ahead of the verifier.
    /// Defaults to 60 seconds; use 30 for CeleraTax NFR-SEC-012, or zero
    /// for strict clocks. This does not extend the challenge's maximum age.
    /// Configure proof-cookie verification separately with the same bound.
    #[must_use]
    pub fn with_clock_skew_secs(mut self, clock_skew_secs: u64) -> Self {
        self.clock_skew_secs = clock_skew_secs;
        self
    }

    /// Maximum accepted future timestamp offset, in seconds.
    #[must_use]
    pub fn clock_skew_secs(&self) -> u64 {
        self.clock_skew_secs
    }
}

/// Challenge as served to the client: `{ chg, dif, tim, tag }`.
#[derive(Debug, Clone, Serialize)]
pub struct PowChallengeResponse {
    pub chg: String,
    pub dif: u8,
    pub tim: String,
    pub tag: String,
}

impl From<Challenge> for PowChallengeResponse {
    fn from(challenge: Challenge) -> Self {
        Self {
            chg: challenge.chg,
            dif: challenge.dif,
            tim: challenge.tim,
            tag: challenge.tag,
        }
    }
}

/// Solution exactly as the browser client posts it: `{ chg, sol, non, tim,
/// tag }`. The client never sends `dif`. The server fills it from policy, and
/// the HMAC tag makes a mismatch fail closed. Unknown fields are rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowSolutionRequest {
    pub chg: String,
    pub sol: String,
    pub non: String,
    pub tim: String,
    pub tag: String,
}

/// Failure of the admission flow, mapped to HTTP by the caller.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PowFlowError {
    /// The solution failed any verification check. Answer with one generic
    /// status (for example `403 Forbidden`).
    Rejected,
    /// Minting or encoding the proof cookie faulted server-side. Answer `500`.
    Internal,
}

impl fmt::Display for PowFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "proof-of-work solution rejected",
            Self::Internal => "proof-of-work admission failed internally",
        })
    }
}

impl std::error::Error for PowFlowError {}

/// Mint a stateless challenge. The caller injects the current time as
/// [`UnixMillis`] and 16 bytes of fresh entropy from its CSPRNG.
///
/// Fails [`PowFlowError::Internal`] only on a server clock outside the
/// RFC3339-formattable range. The difficulty is already bounded by
/// [`PowPolicy`].
pub fn mint_pow_challenge(
    secret: &PowSecret,
    policy: PowPolicy,
    now: UnixMillis,
    entropy: [u8; 16],
) -> Result<PowChallengeResponse, PowFlowError> {
    mint_challenge(secret, policy.difficulty, now, entropy)
        .map(PowChallengeResponse::from)
        .map_err(|_| PowFlowError::Internal)
}

/// Successful admission: the proof cookie to set, plus the server-derived
/// solve-timing signal.
#[derive(Debug, Clone)]
pub struct PowAdmission {
    /// `Set-Cookie` header to append to the response.
    pub set_cookie: HeaderValue,
    /// Mint→verify delta in milliseconds ([`datadeft_pow_core::Verified::mint_to_verify_ms`]):
    /// inflatable but not deflatable, so an implausibly small value is
    /// definitive evidence of a native-speed solver. Use for risk tagging,
    /// histograms, and difficulty tuning — never for hard blocking of slow
    /// solves.
    pub mint_to_verify_ms: u64,
}

/// Verify a posted solution and, on success, mint the `dd_pow` proof cookie.
///
/// Returns the `Set-Cookie` header to append to the response together with
/// the mint→verify timing signal. The client never sends `dif`; it is
/// supplied from `policy` and bound by the HMAC tag.
///
/// `classify_solve` maps the server-derived mint→verify delta to the opaque
/// solve-class byte stamped into the proof cookie's encrypted body, making
/// the app's classification available statelessly at later
/// `verify_pow_proof_cookie` gate checks. Quantization policy is the app's;
/// return `None` (e.g. `|_| None`) to mint the v1 body without a class.
#[allow(clippy::too_many_arguments)] // Headless glue: every dependency is injected.
pub fn verify_pow_solution<R, C>(
    secret: &PowSecret,
    policy: PowPolicy,
    request: &PowSolutionRequest,
    keyring: &KeyRing<PowProofCookie>,
    cookie_config: &PowProofCookieConfig,
    rng: &mut R,
    now: UnixMillis,
    classify_solve: C,
) -> Result<PowAdmission, PowFlowError>
where
    R: RngCore + CryptoRng + ?Sized,
    C: FnOnce(u64) -> Option<u8>,
{
    let solution = Solution {
        chg: request.chg.clone(),
        sol: request.sol.clone(),
        non: request.non.clone(),
        dif: policy.difficulty,
        tim: request.tim.clone(),
        tag: request.tag.clone(),
    };
    let verified = verify_solution_with_clock_skew(
        secret,
        &solution,
        now,
        policy.challenge_max_age_secs,
        policy.difficulty,
        policy.clock_skew_secs,
    )
    .map_err(|_| PowFlowError::Rejected)?;

    // The proof-cookie layer stamps whole seconds.
    let solve_class = classify_solve(verified.mint_to_verify_ms);
    let cookie = mint_pow_proof_cookie(&verified.tid, solve_class, keyring, rng, now.as_secs())
        .map_err(|_| PowFlowError::Internal)?;
    let set_cookie = cookie_config
        .set_header(cookie.as_secret_value())
        .map_err(|_| PowFlowError::Internal)?;
    Ok(PowAdmission {
        set_cookie,
        mint_to_verify_ms: verified.mint_to_verify_ms,
    })
}

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;

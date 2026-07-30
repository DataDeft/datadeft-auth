//! Headless proof-of-work admission glue.
//!
//! The library runs the PoW checks and returns structured results. The
//! consuming app owns routing, body extraction, `Content-Type`, and origin
//! checks (its admission concern) and renders the response. Two steps:
//!
//! 1. [`mint_pow_challenge`] — stateless challenge mint for `pow/create`.
//! 2. [`verify_pow_solution`] — verify a posted solution for `pow/validate`
//!    and, on success, return the `Set-Cookie` header that admits the browser.
//!
//! Every verification failure collapses into [`PowFlowError::Rejected`] so the
//! app can answer with one generic status and leak nothing about which check
//! failed.

use core::fmt;

use axum::http::HeaderValue;
use dd_auth_token_core::keyring::KeyRing;
use dd_pow_core::{
    Challenge, MAX_DIFFICULTY, PowProofCookie, PowSecret, Solution, mint_challenge,
    mint_pow_proof_cookie, verify_solution,
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

/// Mint a stateless challenge. The caller injects the current time as RFC3339
/// and 16 bytes of fresh entropy from its CSPRNG.
///
/// Fails [`PowFlowError::Internal`] only on a malformed server-supplied time.
/// The difficulty is already bounded by [`PowPolicy`].
pub fn mint_pow_challenge(
    secret: &PowSecret,
    policy: PowPolicy,
    now_rfc3339: &str,
    entropy: [u8; 16],
) -> Result<PowChallengeResponse, PowFlowError> {
    mint_challenge(secret, policy.difficulty, now_rfc3339, entropy)
        .map(PowChallengeResponse::from)
        .map_err(|_| PowFlowError::Internal)
}

/// Verify a posted solution and, on success, mint the `dd_pow` proof cookie.
///
/// Returns the `Set-Cookie` header to append to the response. The client never
/// sends `dif`; it is supplied from `policy` and bound by the HMAC tag.
pub fn verify_pow_solution<R>(
    secret: &PowSecret,
    policy: PowPolicy,
    request: &PowSolutionRequest,
    keyring: &KeyRing<PowProofCookie>,
    cookie_config: &PowProofCookieConfig,
    rng: &mut R,
    now_unix: u64,
) -> Result<HeaderValue, PowFlowError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    let solution = Solution {
        chg: request.chg.clone(),
        sol: request.sol.clone(),
        non: request.non.clone(),
        dif: policy.difficulty,
        tim: request.tim.clone(),
        tag: request.tag.clone(),
    };
    let verified = verify_solution(
        secret,
        &solution,
        now_unix,
        policy.challenge_max_age_secs,
        policy.difficulty,
    )
    .map_err(|_| PowFlowError::Rejected)?;

    let cookie = mint_pow_proof_cookie(&verified.tid, keyring, rng, now_unix)
        .map_err(|_| PowFlowError::Internal)?;
    cookie_config
        .set_header(cookie.as_secret_value())
        .map_err(|_| PowFlowError::Internal)
}

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;

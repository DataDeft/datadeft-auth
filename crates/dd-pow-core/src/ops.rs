//! Challenge minting and solution verification.
//!
//! Deterministic: same secret/difficulty/time/entropy always produce the same
//! challenge, and verification is a pure pipeline. The caller injects time and
//! entropy; this module never reads the clock or generates randomness.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::challenge::{Challenge, Solution, Verified};
use crate::error::PowError;
use crate::secret::PowSecret;

type HmacSha256 = Hmac<Sha256>;

/// How many seconds a solution's `tim` may lie in the future of `now` before
/// it is rejected. Covers small clock skew between server instances; anything
/// beyond it means a forged or misconfigured timestamp.
pub const MAX_FUTURE_SKEW_SECS: u64 = 30;

/// Domain/version separator prefixed to every authenticated tag message,
/// satisfying the versioned + domain-separated challenge requirement
/// (`docs/security.md`). The string is library-level and role-unique
/// ("this is the PoW *tag* message") rather than product-specific, so the
/// crate stays reusable; consumers that want product-unique domain strings
/// should fork or override the constant. The browser client never computes
/// the tag — it only echoes it — so this prefix is a server-side concern;
/// bumping it cleanly invalidates every previously minted challenge.
pub(crate) const TAG_DOMAIN: &str = "pow-tag-v1";

/// Mint a challenge. Deterministic: same secret/difficulty/time/entropy
/// always produce the same challenge. The caller supplies `now_rfc3339`
/// (e.g. `OffsetDateTime::now_utc().format(&Rfc3339)`) and 16 bytes of
/// fresh entropy.
#[must_use]
pub fn mint_challenge(
    secret: &PowSecret,
    difficulty: u8,
    now_rfc3339: &str,
    entropy: [u8; 16],
) -> Challenge {
    // `chg` is a hash of entropy + time only (no IP/client binding).
    let chg_raw = format!("Time={now_rfc3339}:Nonce={}", hex::encode(entropy));
    let chg = blake3::hash(chg_raw.as_bytes()).to_string();
    let tag = hmac_tag_hex(secret, &tag_message(&chg, difficulty, now_rfc3339));
    Challenge {
        chg,
        dif: difficulty,
        tim: now_rfc3339.to_string(),
        tag,
    }
}

/// Verify a proof-of-work solution.
///
/// Pipeline:
/// 1. Authenticity: `tag == HMAC-SHA256(secret, "{TAG_DOMAIN}:{chg}:{dif}:{tim}")`,
///    constant-time compare.
/// 2. Freshness: `tim` parses as RFC3339, is not more than
///    [`MAX_FUTURE_SKEW_SECS`] ahead of `now_unix`, and
///    `now_unix - tim <= max_age_secs` (boundary accepted).
/// 3. Difficulty floor: `dif >= max(min_difficulty, 1)` — proof-of-work must
///    always require at least one leading zero, so a misconfigured
///    `min_difficulty = 0` can never yield a zero-work pass. Downgrade
///    protection beyond this comes from the tag, which binds the minted `dif`:
///    a later server-side difficulty bump invalidates every in-flight solve as
///    [`PowError::InvalidTag`].
/// 4. Work: `sol` has `dif` leading `'0'` hex chars and equals
///    `hex(SHA-256(chg + non))`, constant-time compare.
///
/// On success returns [`Verified`] with the stable `tid`.
pub fn verify_solution(
    secret: &PowSecret,
    solution: &Solution,
    now_unix: u64,
    max_age_secs: u64,
    min_difficulty: u8,
) -> Result<Verified, PowError> {
    // 1. Authenticity: recompute the tag over the claimed (chg, dif, tim).
    let expected_tag = hmac_tag_raw(
        secret,
        &tag_message(&solution.chg, solution.dif, &solution.tim),
    );
    let client_tag = hex::decode(&solution.tag).map_err(|_| PowError::InvalidTag)?;
    // subtle's slice ct_eq returns 0 on length mismatch without panicking.
    if expected_tag.ct_eq(&client_tag).unwrap_u8() != 1 {
        return Err(PowError::InvalidTag);
    }

    // 2. Freshness. `tim` is authenticated by the tag at this point.
    let tim_unix = OffsetDateTime::parse(&solution.tim, &Rfc3339)
        .map_err(|_| PowError::InvalidTimestamp)?
        .unix_timestamp();
    let now = i64::try_from(now_unix).map_err(|_| PowError::InvalidTimestamp)?;
    let skew = i64::try_from(MAX_FUTURE_SKEW_SECS).expect("small constant");
    if tim_unix > now.saturating_add(skew) {
        return Err(PowError::FutureTimestamp);
    }
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    if now.saturating_sub(tim_unix) > max_age {
        return Err(PowError::Expired);
    }

    // 3. Difficulty floor. The effective minimum is at least 1, so a
    //    misconfigured `min_difficulty = 0` (or a directly injected `dif = 0`)
    //    can never produce a zero-work pass. NOTE: this floor is a defensive
    //    backstop; primary downgrade protection comes from the tag binding the
    //    minted difficulty — a server-side difficulty bump kills in-flight
    //    solves via `InvalidTag`, which is checked first.
    let floor = min_difficulty.max(1);
    if solution.dif < floor {
        return Err(PowError::DifficultyTooLow);
    }

    // 4. Work: leading zeros, then hash correctness.
    if !has_leading_zero_prefix(&solution.sol, solution.dif) {
        return Err(PowError::InvalidSolution);
    }
    let solution_input = format!("{}{}", solution.chg, solution.non);
    let server_hash = hex::encode(Sha256::digest(solution_input.as_bytes()));
    if solution
        .sol
        .as_bytes()
        .ct_eq(server_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(PowError::InvalidSolution);
    }

    // 5. Stable token identity for replay handling upstream.
    let tid = blake3::hash(solution.chg.as_bytes()).to_string();
    Ok(Verified { tid })
}

pub(crate) fn tag_message(chg: &str, dif: u8, tim: &str) -> String {
    format!("{TAG_DOMAIN}:{chg}:{dif}:{tim}")
}

/// True when `sol` begins with at least `dif` `'0'` bytes — the leading-zero
/// work check. Allocation-free equivalent of
/// `sol.starts_with(&"0".repeat(usize::from(dif)))`: `'0'` is single-byte
/// ASCII, so a byte-prefix comparison matches the `&str` prefix exactly.
pub(crate) fn has_leading_zero_prefix(sol: &str, dif: u8) -> bool {
    sol.as_bytes()
        .get(..usize::from(dif))
        .is_some_and(|prefix| prefix.iter().all(|&byte| byte == b'0'))
}

pub(crate) fn hmac_tag_raw(secret: &PowSecret, message: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().into()
}

pub(crate) fn hmac_tag_hex(secret: &PowSecret, message: &str) -> String {
    hex::encode(hmac_tag_raw(secret, message))
}

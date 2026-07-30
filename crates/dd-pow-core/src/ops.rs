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
/// it is rejected. Covers small clock skew between server instances; aligned
/// with the token-cookie layer so one auth path has one skew policy.
pub const MAX_FUTURE_SKEW_SECS: u64 = 60;
/// Maximum useful difficulty for a 64-character lowercase hex SHA-256 digest.
pub const MAX_DIFFICULTY: u8 = 64;
/// Recommended production minimum. Difficulty 1–3 is useful for tests only;
/// production should tune for roughly 1–3 seconds in target browsers, typically
/// around 5–6 leading zero hex characters for this simple SHA-256 loop.
pub const RECOMMENDED_PRODUCTION_MIN_DIFFICULTY: u8 = 5;

const CHG_HEX_BYTES: usize = 64;
const SOL_HEX_BYTES: usize = 64;
const TAG_HEX_BYTES: usize = 64;
const MAX_NON_BYTES: usize = 20;
const MAX_TIM_BYTES: usize = 32;

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
pub fn mint_challenge(
    secret: &PowSecret,
    difficulty: u8,
    now_rfc3339: &str,
    entropy: [u8; 16],
) -> Result<Challenge, PowError> {
    if difficulty > MAX_DIFFICULTY {
        return Err(PowError::DifficultyTooHigh);
    }
    if now_rfc3339.len() > MAX_TIM_BYTES {
        return Err(PowError::InvalidTimestamp);
    }
    // `chg` is a hash of entropy + time only (no IP/client binding).
    let chg_raw = format!("Time={now_rfc3339}:Nonce={}", hex::encode(entropy));
    let chg = blake3::hash(chg_raw.as_bytes()).to_string();
    let tag = hmac_tag_hex(secret, &tag_message(&chg, difficulty, now_rfc3339));
    Ok(Challenge {
        chg,
        dif: difficulty,
        tim: now_rfc3339.to_string(),
        tag,
    })
}

/// Verify a proof-of-work solution.
///
/// Pipeline:
/// 1. Shape caps: reject hostile overlong fields before any HMAC or hash work.
/// 2. Authenticity: `tag == HMAC-SHA256(secret, framed(TAG_DOMAIN, chg, dif, tim))`,
///    constant-time compare.
/// 3. Freshness: `tim` parses as RFC3339, is not more than
///    [`MAX_FUTURE_SKEW_SECS`] ahead of `now_unix`, and
///    `now_unix - tim <= max_age_secs` (boundary accepted).
/// 4. Difficulty floor: `dif >= max(min_difficulty, 1)` — proof-of-work must
///    always require at least one leading zero, so a misconfigured
///    `min_difficulty = 0` can never yield a zero-work pass. The client/API
///    echoes the minted `dif`; the tag prevents lowering it, while this floor
///    lets callers reject still-authentic in-flight challenges after raising
///    their minimum.
/// 5. Work: `sol` has `dif` leading `'0'` hex chars and equals
///
/// On success returns [`Verified`] with the stable `tid`.
pub fn verify_solution(
    secret: &PowSecret,
    solution: &Solution,
    now_unix: u64,
    max_age_secs: u64,
    min_difficulty: u8,
) -> Result<Verified, PowError> {
    if min_difficulty > MAX_DIFFICULTY {
        return Err(PowError::DifficultyTooHigh);
    }
    let max_age = i64::try_from(max_age_secs).map_err(|_| PowError::MaxAgeTooLarge)?;
    validate_solution_shape(solution)?;
    let expected_tag = hmac_tag_raw(
        secret,
        &tag_message(&solution.chg, solution.dif, &solution.tim),
    );
    // The shape check above guarantees `tag` is exactly 64 lowercase hex
    // chars, so this decodes into the stack buffer without allocating; the
    // error mapping is kept as a defensive backstop.
    let mut client_tag = [0u8; 32];
    hex::decode_to_slice(&solution.tag, &mut client_tag).map_err(|_| PowError::InvalidTag)?;
    if expected_tag.ct_eq(&client_tag).unwrap_u8() != 1 {
        return Err(PowError::InvalidTag);
    }

    // 2. Freshness. `tim` is authenticated by the tag at this point.
    let tim_unix = OffsetDateTime::parse(&solution.tim, &Rfc3339)
        .map_err(|_| PowError::InvalidTimestamp)?
        .unix_timestamp();
    let now = i64::try_from(now_unix).map_err(|_| PowError::InvalidTimestamp)?;
    let skew = i64::try_from(MAX_FUTURE_SKEW_SECS).map_err(|_| PowError::InvalidTimestamp)?;
    if tim_unix > now.saturating_add(skew) {
        return Err(PowError::FutureTimestamp);
    }
    if now.saturating_sub(tim_unix) > max_age {
        return Err(PowError::Expired);
    }

    // 3. Difficulty floor. The effective minimum is at least 1, so a
    //    misconfigured `min_difficulty = 0` (or a directly injected `dif = 0`)
    //    can never produce a zero-work pass. NOTE: this floor is a defensive
    //    backstop; primary downgrade protection comes from the tag binding the
    //    echoed minted difficulty, while the caller's current `min_difficulty`
    //    can still reject old-but-authentic in-flight challenges.
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

fn validate_solution_shape(solution: &Solution) -> Result<(), PowError> {
    if !is_lower_hex_len(&solution.chg, CHG_HEX_BYTES) {
        return Err(PowError::InvalidTag);
    }
    if !is_lower_hex_len(&solution.tag, TAG_HEX_BYTES) {
        return Err(PowError::InvalidTag);
    }
    if !is_lower_hex_len(&solution.sol, SOL_HEX_BYTES) {
        return Err(PowError::InvalidSolution);
    }
    if solution.tim.len() > MAX_TIM_BYTES {
        return Err(PowError::InvalidTimestamp);
    }
    if solution.non.len() > MAX_NON_BYTES {
        return Err(PowError::InvalidSolution);
    }
    if solution.dif > MAX_DIFFICULTY {
        return Err(PowError::DifficultyTooHigh);
    }
    Ok(())
}

fn is_lower_hex_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn tag_message(chg: &str, dif: u8, tim: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_DOMAIN.len() + 1 + 2 + chg.len() + 1 + 2 + tim.len());
    out.extend_from_slice(TAG_DOMAIN.as_bytes());
    out.push(0);
    append_len_prefixed(&mut out, chg.as_bytes());
    out.push(dif);
    append_len_prefixed(&mut out, tim.as_bytes());
    out
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = match u16::try_from(bytes.len()) {
        Ok(len) => len,
        Err(_) => u16::MAX,
    };
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
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

pub(crate) fn hmac_tag_raw(secret: &PowSecret, message: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length, so `new_from_slice` cannot fail.
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

pub(crate) fn hmac_tag_hex(secret: &PowSecret, message: &[u8]) -> String {
    hex::encode(hmac_tag_raw(secret, message))
}

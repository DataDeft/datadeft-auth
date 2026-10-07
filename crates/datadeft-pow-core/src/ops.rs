//! Challenge minting and solution verification.
//!
//! Deterministic: same secret/difficulty/time/entropy always produce the same
//! challenge, and verification is a pure pipeline. The caller injects time and
//! entropy. This module never reads the clock or generates randomness.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::challenge::{Challenge, Solution, Verified};
use crate::clock::UnixMillis;
use crate::error::PowError;
use crate::secret::PowSecret;

type HmacSha256 = Hmac<Sha256>;

/// Default seconds a solution's `tim` may lie ahead of `now`. Covers small
/// clock skew between server instances and matches the token-cookie default.
/// Use [`verify_solution_with_clock_skew`] to configure another tolerance.
pub const MAX_FUTURE_SKEW_SECS: u64 = 60;
/// Maximum useful difficulty for a 64-character lowercase hex SHA-256 digest.
pub const MAX_DIFFICULTY: u8 = 64;
/// Recommended production minimum. Difficulty 1–3 is useful for tests only.
/// Production should tune for roughly 1–3 seconds in target browsers, typically
/// around 5–6 leading zero hex characters for this simple SHA-256 loop.
pub const RECOMMENDED_PRODUCTION_MIN_DIFFICULTY: u8 = 5;

const CHG_HEX_BYTES: usize = 64;
const SOL_HEX_BYTES: usize = 64;
const TAG_HEX_BYTES: usize = 64;
const MAX_NON_BYTES: usize = 20;
const MAX_TIM_BYTES: usize = 32;

/// Domain/version separator. The server prefixes it to every authenticated tag
/// message. It satisfies the versioned + domain-separated challenge requirement
/// (`docs/security.md`). The string is library-level and role-unique
/// ("this is the PoW *tag* message") rather than product-specific, so the
/// crate stays reusable. Consumers that want product-unique domain strings
/// should fork or override the constant. The browser client never computes
/// the tag: it only echoes it: so this prefix is a server-side concern. A
/// bump to it cleanly invalidates every previously minted challenge.
pub(crate) const TAG_DOMAIN: &str = "pow-tag-v1";

/// Mint a challenge. Deterministic: same secret/difficulty/time/entropy
/// always produce the same challenge. The caller supplies the current time
/// as [`UnixMillis`] and 16 bytes of fresh entropy.
///
/// `tim` is formatted here, RFC3339 with millisecond precision, so every
/// minted challenge carries a sub-second mint time and the verify-side
/// mint→verify delta ([`Verified::mint_to_verify_ms`]) is never quantized by
/// the mint path. A whole-second value formats without a fraction, matching
/// challenges minted before millisecond resolution.
pub fn mint_challenge(
    secret: &PowSecret,
    difficulty: u8,
    now: UnixMillis,
    entropy: [u8; 16],
) -> Result<Challenge, PowError> {
    if difficulty > MAX_DIFFICULTY {
        return Err(PowError::DifficultyTooHigh);
    }
    let tim = rfc3339_from_millis(now)?;
    // `chg` is a hash of entropy + time only (no IP/client binding).
    let chg_raw = format!("Time={tim}:Nonce={}", hex::encode(entropy));
    let chg = blake3::hash(chg_raw.as_bytes()).to_string();
    let tag = hmac_tag_hex(secret, &tag_message(&chg, difficulty, &tim));
    Ok(Challenge {
        chg,
        dif: difficulty,
        tim,
        tag,
    })
}

/// RFC3339 `tim` for a millisecond clock value. Fails only when the value
/// falls outside the formattable calendar range (year 10000+).
fn rfc3339_from_millis(now: UnixMillis) -> Result<String, PowError> {
    let nanos = i128::from(now.as_millis()) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| PowError::InvalidTimestamp)?
        .format(&Rfc3339)
        .map_err(|_| PowError::InvalidTimestamp)
}

/// Verify a proof-of-work solution.
///
/// Pipeline:
/// 1. Shape caps: reject hostile overlong fields before any HMAC or hash work.
/// 2. Authenticity: `tag == HMAC-SHA256(secret, framed(TAG_DOMAIN, chg, dif, tim))`,
///    constant-time compare.
/// 3. Freshness, in milliseconds: `tim` parses as RFC3339, is not more than
///    [`MAX_FUTURE_SKEW_SECS`] ahead of `now`, and
///    `now - tim <= max_age_secs * 1000` (boundary accepted).
/// 4. Difficulty floor: `dif >= max(min_difficulty, 1)`: proof-of-work must
///    always require at least one leading zero, so a misconfigured
///    `min_difficulty = 0` can never yield a zero-work pass. The client/API
///    echoes the minted `dif`. The tag prevents lowering it, while this floor
///    lets callers reject still-authentic in-flight challenges after raising
///    their minimum.
/// 5. Work: `sol` has `dif` leading `'0'` hex chars and equals
///
/// On success returns [`Verified`] with the stable `tid` and the
/// server-derived mint→verify delta in milliseconds.
pub fn verify_solution(
    secret: &PowSecret,
    solution: &Solution,
    now: UnixMillis,
    max_age_secs: u64,
    min_difficulty: u8,
) -> Result<Verified, PowError> {
    verify_solution_with_clock_skew(
        secret,
        solution,
        now,
        max_age_secs,
        min_difficulty,
        MAX_FUTURE_SKEW_SECS,
    )
}

/// Verify a solution with a caller-configured future clock-skew tolerance.
///
/// Applies the same authenticated verification pipeline as [`verify_solution`],
/// accepting `tim` at most `clock_skew_secs` ahead of `now`. The boundary is
/// inclusive at millisecond precision; zero rejects every future timestamp.
/// Clock skew never extends `max_age_secs`, and accepted future timestamps
/// report a zero [`Verified::mint_to_verify_ms`]. Every `u64` tolerance is safe
/// from arithmetic overflow. Use the same tolerance for proof-cookie checks.
pub fn verify_solution_with_clock_skew(
    secret: &PowSecret,
    solution: &Solution,
    now: UnixMillis,
    max_age_secs: u64,
    min_difficulty: u8,
    clock_skew_secs: u64,
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
    // chars, so this decodes into the stack buffer without allocating. The
    // code keeps the error mapping as a defensive backstop.
    let mut client_tag = [0u8; 32];
    hex::decode_to_slice(&solution.tag, &mut client_tag).map_err(|_| PowError::InvalidTag)?;
    if expected_tag.ct_eq(&client_tag).unwrap_u8() != 1 {
        return Err(PowError::InvalidTag);
    }

    // 2. Freshness, in milliseconds. `tim` is authenticated by the tag at
    //    this point. All arithmetic is i128: every u64 clock value and every
    //    parseable RFC3339 instant fits with headroom, so nothing saturates.
    let tim_ms = OffsetDateTime::parse(&solution.tim, &Rfc3339)
        .map_err(|_| PowError::InvalidTimestamp)?
        .unix_timestamp_nanos()
        .div_euclid(1_000_000);
    let now_ms = i128::from(now.as_millis());
    let skew_ms = i128::from(clock_skew_secs) * 1000;
    if tim_ms > now_ms + skew_ms {
        return Err(PowError::FutureTimestamp);
    }
    let age_ms = now_ms - tim_ms;
    if age_ms > i128::from(max_age) * 1000 {
        return Err(PowError::Expired);
    }

    // 3. Difficulty floor. The effective minimum is at least 1, so a
    //    misconfigured `min_difficulty = 0` (or a directly injected `dif = 0`)
    //    can never produce a zero-work pass. NOTE: this floor is a defensive
    //    backstop. Primary downgrade protection comes from the tag binding the
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

    // 5. Stable token identity for replay handling upstream, plus the
    //    mint→verify delta. Clamped at zero: within the future-skew window
    //    the delta is negative and carries no timing information. The
    //    `u64::MAX` fallback is unreachable for any post-1970 `tim` (the age
    //    already passed the max-age bound) and only guards hostile ancient
    //    timestamps combined with an enormous configured max age.
    let tid = blake3::hash(solution.chg.as_bytes()).to_string();
    let mint_to_verify_ms = u64::try_from(age_ms.max(0)).unwrap_or(u64::MAX);
    Ok(Verified {
        tid,
        mint_to_verify_ms,
    })
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
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// True when `sol` begins with at least `dif` `'0'` bytes: the leading-zero
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

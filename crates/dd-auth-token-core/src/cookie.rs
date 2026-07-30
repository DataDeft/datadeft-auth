//! Cookie wrapper helpers for `v1.{kid}.{branca-token}` values.
//!
//! This module owns the shared wrapper grammar, early `kid` validation, redacted
//! debug output, generic public error mapping for verification, freshness
//! enforcement, and encrypted payload binding. Every high-level cookie payload
//! stores its `typ`, `kid`, and issue time (`iat`) inside the AEAD-protected body
//! and verifies them against the outer `v1.{kid}.` wrapper and the caller's
//! freshness bounds after decrypt.
//!
//! # Freshness is mandatory
//!
//! Validation entry points require a [`MaxAge`]. A caller cannot obtain a
//! [`VerifiedCookie`] without stating a TTL. Two clocks are checked: the Branca
//! timestamp is *last activity* (idle bound) and the payload `iat` is *first
//! issue* (absolute bound), so a re-minted sliding session cannot outlive its
//! absolute lifetime. Future-dated timestamps (a skewed or rewound minting host)
//! are rejected beyond [`CLOCK_SKEW_TOLERANCE_SECS`]. All verification failures
//! funnel to the single generic [`TokenError::InvalidToken`] at the public edge.
//! Mint/configuration failures remain distinct so operators can alarm on them.
//!
//! # Payload sizing
//!
//! [`branca::MAX_PAYLOAD_BYTES`] is a hard primitive ceiling, but each purpose
//! has a smaller [`KeyPurpose::MAX_BODY_BYTES`] application budget. Use
//! [`max_body_bytes`] to compute the effective body budget for a purpose.

use std::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::branca::{self, Jti, Verified};
use crate::error::TokenError;
use crate::keyring::{KeyId, KeyPurpose, KeyRing};

/// Cookie value version prefix (`v1.{kid}.{token}`).
pub const TOKEN_VERSION_PREFIX: &str = "v1";

/// A token whose timestamp/`iat` is at most this far in the future is still
/// accepted, to tolerate minting-host clock skew. Anything further ahead is
/// treated as expired (a rewound or badly skewed clock must not read as fresh).
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

/// Bound cookie payload version byte (internal binary framing).
const PAYLOAD_V1: u8 = 1;

/// Freshness bounds every cookie validation MUST supply.
///
/// `idle_secs` bounds time since last activity (the Branca timestamp).
/// `absolute_secs` bounds time since first issue (`iat`). For cookies with a
/// single TTL (e.g. PoW proof cookies), use [`MaxAge::fixed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaxAge {
    /// Maximum seconds since last activity (the Branca timestamp).
    pub idle_secs: u64,
    /// Maximum seconds since first issue (the payload `iat`).
    pub absolute_secs: u64,
}

impl MaxAge {
    /// Distinct idle and absolute bounds (sliding sessions).
    #[must_use]
    pub fn new(idle_secs: u64, absolute_secs: u64) -> Self {
        Self {
            idle_secs,
            absolute_secs,
        }
    }

    /// Single-TTL cookie: idle and absolute bounds are identical.
    #[must_use]
    pub fn fixed(ttl_secs: u64) -> Self {
        Self {
            idle_secs: ttl_secs,
            absolute_secs: ttl_secs,
        }
    }
}

/// Parsed cookie wrapper. Debug deliberately redacts both fields: `kid` is
/// attacker-controlled metadata and `token` is bearer material.
pub struct CookieParts<'a> {
    kid: KeyId,
    token: &'a str,
}

impl<'a> CookieParts<'a> {
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    #[must_use]
    pub fn token(&self) -> &'a str {
        self.token
    }
}

impl fmt::Debug for CookieParts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieParts")
            .field("kid", &"KeyId(..)")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Parse `v1.{kid}.{token}` and validate `kid` before any lookup.
///
/// Returns [`TokenError::InvalidToken`] for every malformed wrapper shape,
/// including bad version, missing pieces, invalid `kid` length/charset, empty
/// token, or extra `.` inside the token segment.
pub fn parse_cookie_wrapper(value: &str) -> Result<CookieParts<'_>, TokenError> {
    let (version, rest) = value.split_once('.').ok_or(TokenError::InvalidToken)?;
    let (kid, token) = rest.split_once('.').ok_or(TokenError::InvalidToken)?;

    if version != TOKEN_VERSION_PREFIX || token.is_empty() || token.contains('.') {
        return Err(TokenError::InvalidToken);
    }

    let kid = KeyId::parse(kid).map_err(|_| TokenError::InvalidToken)?;
    Ok(CookieParts { kid, token })
}

/// Parse wrapper, select key, decrypt, and enforce the idle freshness bound on
/// the Branca timestamp. Preserves one generic public error (`InvalidToken`) for
/// malformed input, unknown key id, expired key, bad MAC, wrong key,
/// non-canonical base62, a future-dated/stale timestamp, or any other failure.
///
/// `max_age_secs` bounds seconds since the Branca timestamp (last activity).
/// Lower-level primitives keep more specific errors for tests/configuration, but
/// cookie validation paths must not let attackers enumerate which stage failed.
pub(crate) fn decrypt_wrapped_token<P: KeyPurpose>(
    value: &str,
    keyring: &KeyRing<P>,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<(KeyId, Verified), TokenError> {
    let parts = parse_cookie_wrapper(value)?;
    if parts.token().len() > max_cookie_token_bytes::<P>(parts.kid()) {
        return Err(TokenError::InvalidToken);
    }

    let key = keyring
        .verification_key_at(parts.kid(), now_unix)
        .map_err(|_| TokenError::InvalidToken)?;
    let verified = branca::decode(parts.token(), key.key().as_bytes())
        .map_err(|_| TokenError::InvalidToken)?;
    check_timestamp_fresh(verified.timestamp, now_unix, max_age_secs)
        .map_err(|_| TokenError::InvalidToken)?;
    Ok((parts.kid, verified))
}

/// Verified bound cookie payload.
pub struct VerifiedCookie {
    kid: KeyId,
    timestamp: u32,
    iat: u32,
    jti: Jti,
    body: Vec<u8>,
}

impl VerifiedCookie {
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    /// Last-activity time (the Branca timestamp) in unix seconds.
    #[must_use]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// First-issue time (`iat`) in unix seconds.
    #[must_use]
    pub fn iat(&self) -> u32 {
        self.iat
    }

    #[must_use]
    pub fn jti(&self) -> Jti {
        self.jti
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Drop for VerifiedCookie {
    fn drop(&mut self) {
        self.body.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for VerifiedCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCookie")
            .field("kid", &"KeyId(..)")
            .field("timestamp", &self.timestamp)
            .field("iat", &self.iat)
            .field("jti", &self.jti)
            .field(
                "body",
                &format_args!("<{} bytes redacted>", self.body.len()),
            )
            .finish()
    }
}

/// Mint a `v1.{kid}.{branca}` value with `typ`, `kid`, and `iat` bound inside the
/// encrypted payload.
///
/// `timestamp` is the last-activity/mint time (stored in the Branca header).
/// `iat` is the first-issue anchor for the absolute lifetime. On a first mint
/// pass `iat == timestamp`. On a sliding re-mint carry the original `iat` forward
/// with a fresh `timestamp`. `timestamp` must be within
/// [`CLOCK_SKEW_TOLERANCE_SECS`] of `now_unix`, and `iat` must not postdate
/// `timestamp`.
///
/// Unlike verification, minting does not funnel keyring/configuration failures
/// into [`TokenError::InvalidToken`]. Rotation faults must be visible to
/// operators as distinct errors.
pub fn mint_bound_cookie<P, R>(
    body: &[u8],
    keyring: &KeyRing<P>,
    rng: &mut R,
    timestamp: u32,
    iat: u32,
    now_unix: u64,
) -> Result<String, TokenError>
where
    P: KeyPurpose,
    R: RngCore + CryptoRng + ?Sized,
{
    check_mint_timestamp(timestamp, now_unix)?;
    if iat > timestamp {
        return Err(TokenError::InvalidTimestamp);
    }

    let active = keyring.minting_key_at(now_unix)?;
    // The body-size cap (`max_body_bytes`) is enforced inside
    // `encode_bound_payload`, which fails with `TokenError::PayloadTooLarge`.
    let mut payload = encode_bound_payload::<P>(P::TOKEN_TYPE, active.kid().as_str(), iat, body)?;
    let token = match branca::encode(&payload, active.key().as_bytes(), rng, timestamp) {
        Ok(token) => token,
        Err(err) => {
            payload.as_mut_slice().zeroize();
            return Err(err);
        }
    };
    payload.as_mut_slice().zeroize();

    Ok(format!(
        "{TOKEN_VERSION_PREFIX}.{}.{}",
        active.kid().as_str(),
        token
    ))
}

/// Parse and decrypt a bound cookie value, require encrypted `typ`/`kid` to match
/// the expected purpose and outer wrapper, and enforce both freshness bounds.
pub fn parse_bound_cookie<P: KeyPurpose>(
    value: &str,
    keyring: &KeyRing<P>,
    now_unix: u64,
    max_age: MaxAge,
) -> Result<VerifiedCookie, TokenError> {
    // Enforces the idle bound (and skew) on the Branca timestamp.
    let (kid, verified) = decrypt_wrapped_token(value, keyring, now_unix, max_age.idle_secs)?;

    let payload = decode_bound_payload(&verified.payload).map_err(|_| TokenError::InvalidToken)?;

    if payload.typ != P::TOKEN_TYPE.as_bytes() || payload.kid != kid.as_str().as_bytes() {
        return Err(TokenError::InvalidToken);
    }

    check_absolute_fresh(
        payload.iat,
        verified.timestamp,
        now_unix,
        max_age.absolute_secs,
    )
    .map_err(|_| TokenError::InvalidToken)?;

    Ok(VerifiedCookie {
        kid,
        timestamp: verified.timestamp,
        iat: payload.iat,
        jti: verified.jti(),
        body: payload.body.to_vec(),
    })
}

/// Maximum application body bytes that fit in the encrypted bound-cookie payload
/// for purpose `P` and this validated `kid`.
///
/// The Branca payload cap applies after internal framing:
/// `v(1) || iat(4) || typ_len(1) || typ || kid_len(1) || kid || body`.
#[must_use]
pub fn max_body_bytes<P: KeyPurpose>(kid: &KeyId) -> usize {
    max_body_bytes_for_parts::<P>(P::TOKEN_TYPE, kid.as_str())
}

fn max_body_bytes_for_parts<P: KeyPurpose>(typ: &str, kid: &str) -> usize {
    branca::MAX_PAYLOAD_BYTES
        .min(P::MAX_BODY_BYTES)
        .saturating_sub(bound_payload_overhead(typ, kid))
}

fn max_cookie_token_bytes<P: KeyPurpose>(kid: &KeyId) -> usize {
    branca::max_token_chars_for_payload(
        bound_payload_overhead(P::TOKEN_TYPE, kid.as_str())
            .saturating_add(max_body_bytes::<P>(kid)),
    )
}

fn bound_payload_overhead(typ: &str, kid: &str) -> usize {
    1 + 4 + 1 + typ.len() + 1 + kid.len()
}

fn check_mint_timestamp(timestamp: u32, now_unix: u64) -> Result<(), TokenError> {
    let timestamp = u64::from(timestamp);
    if timestamp > now_unix.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
        return Err(TokenError::InvalidTimestamp);
    }
    if now_unix > timestamp.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
        return Err(TokenError::InvalidTimestamp);
    }
    Ok(())
}

/// Idle-bound freshness on the Branca timestamp (last activity). Returns
/// [`TokenError::Expired`] internally. Callers funnel it to the generic error.
fn check_timestamp_fresh(
    timestamp: u32,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<(), TokenError> {
    let ts = u64::from(timestamp);
    if ts > now_unix.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
        return Err(TokenError::Expired); // future-dated beyond tolerance
    }
    if now_unix.saturating_sub(ts) > max_age_secs {
        return Err(TokenError::Expired); // stale
    }
    Ok(())
}

/// Absolute-bound freshness on `iat` (first issue). `iat` must not postdate the
/// last-activity timestamp, nor be future-dated beyond tolerance.
fn check_absolute_fresh(
    iat: u32,
    timestamp: u32,
    now_unix: u64,
    absolute_secs: u64,
) -> Result<(), TokenError> {
    let iat = u64::from(iat);
    if iat > u64::from(timestamp) {
        return Err(TokenError::Expired); // anchor postdates activity → malformed
    }
    if iat > now_unix.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
        return Err(TokenError::Expired); // future-dated beyond tolerance
    }
    if now_unix.saturating_sub(iat) > absolute_secs {
        return Err(TokenError::Expired); // beyond absolute lifetime
    }
    Ok(())
}

/// Decoded view over the internal bound-cookie payload framing.
struct DecodedPayload<'a> {
    iat: u32,
    typ: &'a [u8],
    kid: &'a [u8],
    body: &'a [u8],
}

/// Encode the bound payload with a fixed binary framing. This payload is
/// internal and never parsed by a client, so it uses a compact length-prefixed
/// layout rather than JSON — no byte-array expansion and no self-describing
/// codec surface:
///
/// `v(1) || iat(4 BE) || typ_len(1) || typ || kid_len(1) || kid || body`
fn encode_bound_payload<P: KeyPurpose>(
    typ: &str,
    kid: &str,
    iat: u32,
    body: &[u8],
) -> Result<Vec<u8>, TokenError> {
    if body.len() > max_body_bytes_for_parts::<P>(typ, kid) {
        return Err(TokenError::PayloadTooLarge);
    }

    let typ = typ.as_bytes();
    let kid = kid.as_bytes();
    // `typ` is a small crate constant and `kid` is <= 64 bytes via KeyId::parse.
    // The length prefixes are single bytes, so both must fit in a u8.
    if typ.len() > usize::from(u8::MAX) || kid.len() > usize::from(u8::MAX) {
        return Err(TokenError::Internal);
    }

    let mut out = Vec::with_capacity(1 + 4 + 1 + typ.len() + 1 + kid.len() + body.len());
    out.push(PAYLOAD_V1);
    out.extend_from_slice(&iat.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)] // bounded above
    out.push(typ.len() as u8);
    out.extend_from_slice(typ);
    #[allow(clippy::cast_possible_truncation)] // bounded above
    out.push(kid.len() as u8);
    out.extend_from_slice(kid);
    out.extend_from_slice(body);
    Ok(out)
}

/// Parse the fixed binary framing. Every field is bounds-checked. Any short or
/// malformed buffer is a generic failure. The buffer is authenticated by the
/// AEAD before it reaches here, so this only guards against our own invariants.
fn decode_bound_payload(buf: &[u8]) -> Result<DecodedPayload<'_>, TokenError> {
    if *buf.first().ok_or(TokenError::InvalidToken)? != PAYLOAD_V1 {
        return Err(TokenError::InvalidToken);
    }
    let iat_bytes = buf.get(1..5).ok_or(TokenError::InvalidToken)?;
    let iat = u32::from_be_bytes([iat_bytes[0], iat_bytes[1], iat_bytes[2], iat_bytes[3]]);
    let mut i = 5usize;

    let typ_len = usize::from(*buf.get(i).ok_or(TokenError::InvalidToken)?);
    i += 1;
    let typ = buf.get(i..i + typ_len).ok_or(TokenError::InvalidToken)?;
    i += typ_len;

    let kid_len = usize::from(*buf.get(i).ok_or(TokenError::InvalidToken)?);
    i += 1;
    let kid = buf.get(i..i + kid_len).ok_or(TokenError::InvalidToken)?;
    i += kid_len;

    let body = buf.get(i..).ok_or(TokenError::InvalidToken)?;
    Ok(DecodedPayload {
        iat,
        typ,
        kid,
        body,
    })
}

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;

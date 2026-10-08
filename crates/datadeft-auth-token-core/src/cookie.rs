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
//! are rejected beyond [`CLOCK_SKEW_TOLERANCE_SECS`] by default. The
//! `*_with_clock_skew` entry points accept an explicit tolerance in seconds;
//! this tolerance never extends the idle or absolute lifetime. All verification
//! failures funnel to the single generic [`TokenError::InvalidToken`] at the
//! public edge. Mint/configuration failures remain distinct so operators can
//! alarm on them.
//!
//! # Payload sizing
//!
//! [`branca::MAX_PAYLOAD_BYTES`] is a hard primitive ceiling, but each purpose
//! has a smaller [`KeyPurpose::MAX_BODY_BYTES`] application budget. Use
//! [`max_body_bytes`] to compute the effective body budget for a purpose.

mod freshness;
mod payload;

use std::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::branca::{self, Jti, Verified};
use crate::error::TokenError;
use crate::keyring::{KeyId, KeyPurpose, KeyRing};

use self::freshness::*;
use self::payload::*;

/// Cookie value version prefix (`v1.{kid}.{token}`).
pub const TOKEN_VERSION_PREFIX: &str = "v1";

/// Default tolerance: a token whose timestamp/`iat` is at most this far in the
/// future is still accepted, to tolerate minting-host clock skew. Anything
/// further ahead is treated as expired (a rewound or badly skewed clock must not
/// read as fresh).
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

/// Largest tolerance the `*_with_clock_skew` entry points accept. Skew only
/// absorbs small clock differences between hosts; a larger value is a
/// misconfiguration (`u64::MAX` would switch the future-date check off).
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

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
/// `clock_skew_secs` bounds how far the timestamp may be in the future.
/// Lower-level primitives keep more specific errors for tests/configuration, but
/// cookie validation paths must not let attackers enumerate which stage failed.
pub(crate) fn decrypt_wrapped_token<P: KeyPurpose>(
    value: &str,
    keyring: &KeyRing<P>,
    now_unix: u64,
    max_age_secs: u64,
    clock_skew_secs: u64,
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
    check_timestamp_fresh(
        verified.timestamp(),
        now_unix,
        max_age_secs,
        clock_skew_secs,
    )
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
    mint_bound_cookie_with_clock_skew(
        body,
        keyring,
        rng,
        timestamp,
        iat,
        now_unix,
        CLOCK_SKEW_TOLERANCE_SECS,
    )
}

/// Mint a bound cookie with an explicit clock-skew tolerance in seconds.
///
/// This applies the same payload, key, and first-issue invariants as
/// [`mint_bound_cookie`]. `timestamp` must be within `clock_skew_secs` of
/// `now_unix` in either direction, inclusively. Zero requires an exact match.
/// `iat` must not postdate `timestamp`; on sliding refresh it remains the
/// original first-issue time. The wire format is unchanged.
pub fn mint_bound_cookie_with_clock_skew<P, R>(
    body: &[u8],
    keyring: &KeyRing<P>,
    rng: &mut R,
    timestamp: u32,
    iat: u32,
    now_unix: u64,
    clock_skew_secs: u64,
) -> Result<String, TokenError>
where
    P: KeyPurpose,
    R: RngCore + CryptoRng + ?Sized,
{
    check_clock_skew(clock_skew_secs)?;
    check_mint_timestamp(timestamp, now_unix, clock_skew_secs)?;
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
/// Uses [`CLOCK_SKEW_TOLERANCE_SECS`] for future-dated timestamps.
pub fn parse_bound_cookie<P: KeyPurpose>(
    value: &str,
    keyring: &KeyRing<P>,
    now_unix: u64,
    max_age: MaxAge,
) -> Result<VerifiedCookie, TokenError> {
    parse_bound_cookie_with_clock_skew(value, keyring, now_unix, max_age, CLOCK_SKEW_TOLERANCE_SECS)
}

/// Parse a bound cookie with an explicit clock-skew tolerance in seconds.
///
/// Both the last-activity timestamp and first-issue anchor may be at most
/// `clock_skew_secs` ahead of `now_unix`, inclusively. Zero rejects every
/// future-dated cookie. Skew never extends either [`MaxAge`] bound or key
/// validity. All validation failures remain [`TokenError::InvalidToken`].
pub fn parse_bound_cookie_with_clock_skew<P: KeyPurpose>(
    value: &str,
    keyring: &KeyRing<P>,
    now_unix: u64,
    max_age: MaxAge,
    clock_skew_secs: u64,
) -> Result<VerifiedCookie, TokenError> {
    check_clock_skew(clock_skew_secs)?;
    check_max_age::<P>(max_age)?;
    // Enforces the idle bound (and skew) on the Branca timestamp.
    let (kid, verified) =
        decrypt_wrapped_token(value, keyring, now_unix, max_age.idle_secs, clock_skew_secs)?;

    let payload = decode_bound_payload(verified.payload()).map_err(|_| TokenError::InvalidToken)?;

    if payload.typ != P::TOKEN_TYPE.as_bytes() || payload.kid != kid.as_str().as_bytes() {
        return Err(TokenError::InvalidToken);
    }

    check_absolute_fresh(
        payload.iat,
        verified.timestamp(),
        now_unix,
        max_age.absolute_secs,
        clock_skew_secs,
    )
    .map_err(|_| TokenError::InvalidToken)?;

    Ok(VerifiedCookie {
        kid,
        timestamp: verified.timestamp(),
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

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;

//! Cookie wrapper helpers for `v1.{kid}.{branca-token}` values.
//!
//! This module owns the shared wrapper grammar, early `kid` validation, redacted
//! debug output, generic public error mapping, and encrypted payload binding.
//! Every high-level cookie payload stores both its `typ` and `kid` inside the
//! AEAD-protected JSON and verifies them against the outer `v1.{kid}.` wrapper
//! after decrypt.

use std::fmt;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::branca::{self, Jti, Verified};
use crate::error::TokenError;
use crate::keyring::{KeyId, KeyPurpose, KeyRing};

/// Cookie value version prefix (`v1.{kid}.{token}`).
pub const TOKEN_VERSION_PREFIX: &str = "v1";

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

/// Parse wrapper, select key, and decrypt while preserving one generic public
/// error (`InvalidToken`) for malformed input, unknown key id, expired key, bad
/// MAC, wrong key, non-canonical base62, or any other token failure.
///
/// Lower-level primitives keep more specific errors for tests/configuration, but
/// cookie validation paths should not let attackers enumerate which stage failed.
pub fn decrypt_wrapped_token<P: KeyPurpose>(
    value: &str,
    keyring: &KeyRing<P>,
    now_unix: u64,
) -> Result<(KeyId, Verified), TokenError> {
    let parts = parse_cookie_wrapper(value)?;
    let key = keyring
        .verification_key_at(parts.kid(), now_unix)
        .map_err(|_| TokenError::InvalidToken)?;
    let verified = branca::decode(parts.token(), key.key().as_bytes())
        .map_err(|_| TokenError::InvalidToken)?;
    Ok((parts.kid, verified))
}

#[derive(Serialize, Deserialize)]
struct BoundCookiePayload {
    v: u8,
    typ: String,
    kid: String,
    body: Vec<u8>,
}

/// Verified bound cookie payload.
#[derive(Clone)]
pub struct VerifiedCookie {
    kid: KeyId,
    timestamp: u32,
    jti: Jti,
    body: Vec<u8>,
}

impl VerifiedCookie {
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    #[must_use]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
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

impl fmt::Debug for VerifiedCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCookie")
            .field("kid", &"KeyId(..)")
            .field("timestamp", &self.timestamp)
            .field("jti", &self.jti)
            .field(
                "body",
                &format_args!("<{} bytes redacted>", self.body.len()),
            )
            .finish()
    }
}

/// Mint a `v1.{kid}.{branca}` value with `typ` and `kid` bound inside the
/// encrypted JSON payload.
pub fn mint_bound_cookie<P, R>(
    body: &[u8],
    keyring: &KeyRing<P>,
    rng: &mut R,
    timestamp: u32,
    now_unix: u64,
) -> Result<String, TokenError>
where
    P: KeyPurpose,
    R: RngCore + CryptoRng + ?Sized,
{
    let active = keyring
        .minting_key_at(now_unix)
        .map_err(|_| TokenError::InvalidToken)?;
    let payload = BoundCookiePayload {
        v: 1,
        typ: P::TOKEN_TYPE.to_owned(),
        kid: active.kid().as_str().to_owned(),
        body: body.to_vec(),
    };
    let json = serde_json::to_vec(&payload).map_err(|_| TokenError::Internal)?;
    let token = branca::encode(&json, active.key().as_bytes(), rng, timestamp)
        .map_err(|_| TokenError::InvalidToken)?;
    Ok(format!(
        "{TOKEN_VERSION_PREFIX}.{}.{}",
        active.kid().as_str(),
        token
    ))
}

/// Parse and decrypt a bound cookie value, then require encrypted `typ` and
/// `kid` to match the expected purpose and outer wrapper.
pub fn parse_bound_cookie<P: KeyPurpose>(
    value: &str,
    keyring: &KeyRing<P>,
    now_unix: u64,
) -> Result<VerifiedCookie, TokenError> {
    let (kid, verified) = decrypt_wrapped_token(value, keyring, now_unix)?;
    let payload: BoundCookiePayload =
        serde_json::from_slice(&verified.payload).map_err(|_| TokenError::InvalidToken)?;

    if payload.v != 1 || payload.typ != P::TOKEN_TYPE || payload.kid != kid.as_str() {
        return Err(TokenError::InvalidToken);
    }

    Ok(VerifiedCookie {
        kid,
        timestamp: verified.timestamp,
        jti: verified.jti(),
        body: payload.body,
    })
}

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;

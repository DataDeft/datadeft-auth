//! Cookie wrapper helpers for `v1.{kid}.{branca-token}` values.
//!
//! This module does not define session/PoW payloads yet. It owns the shared
//! wrapper grammar, early `kid` validation, redacted debug output, and generic
//! public error mapping for token validation paths.

use std::fmt;

use crate::branca::{self, Verified};
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

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;

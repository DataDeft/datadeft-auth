//! Validated identifier and key types: rate-limit keys, user, session, and attempt ids.

use core::fmt;

use crate::error::MagicLinkServiceError;

/// Rate-limit bucket key derived from keyed email or selector material and
/// redacted in `Debug`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RateLimitKey(String);

impl RateLimitKey {
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_valid_key_component(value, 256) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    /// Wrap a key the service itself assembled from validated components,
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_valid_key_component(&value, 256),
            "service-built rate-limit key must be canonical"
        );
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RateLimitKey(..)")
    }
}

/// Stable application user id. Not bearer material, but redacted by default.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct UserId(String);

impl UserId {
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_prefixed_hex_id(value, "usr_", 32) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    /// Wrap an id the service generated itself (`usr_` + 32 lowercase hex),
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_prefixed_hex_id(&value, "usr_", 32),
            "service-built user id must be canonical"
        );
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserId(..)")
    }
}

/// Server-side session id. This is bearer-equivalent while a cookie containing
/// it is valid. Storage should use keyed lookup material, not raw ids.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_prefixed_hex_id(value, "sid_", 64) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    /// Wrap an id the service generated itself (`sid_` + 64 lowercase hex),
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_prefixed_hex_id(&value, "sid_", 64),
            "service-built session id must be canonical"
        );
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(..)")
    }
}

/// Transaction-scoped idempotency id for one exact authentication plan.
///
/// The canonical representation is `aid_` followed by 32 lowercase hexadecimal
/// characters encoding an independent 128-bit CSPRNG draw. It is not
/// authentication state and must not be persisted. See
/// [`MagicLinkAuthenticationRepository`](crate::traits::MagicLinkAuthenticationRepository)
/// for retry semantics.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AuthenticationAttemptId(String);

impl AuthenticationAttemptId {
    /// Parse the single canonical authentication-attempt id representation.
    pub fn parse(value: &str) -> Result<Self, MagicLinkServiceError> {
        if is_prefixed_hex_id(value, "aid_", 32) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkServiceError::Internal)
        }
    }

    /// Wrap an id the service generated itself (`aid_` + 32 lowercase hex),
    /// without re-scanning or re-allocating it. Debug builds re-check the
    /// canonical form. Untrusted input must go through [`Self::parse`].
    pub(crate) fn from_service_built(value: String) -> Self {
        debug_assert!(
            is_prefixed_hex_id(&value, "aid_", 32),
            "service-built attempt id must be canonical"
        );
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthenticationAttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationAttemptId(..)")
    }
}

pub(super) fn is_prefixed_hex_id(value: &str, prefix: &str, hex_len: usize) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == hex_len
        && rest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(super) fn is_valid_key_component(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
}

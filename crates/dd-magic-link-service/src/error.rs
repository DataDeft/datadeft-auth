//! Service-layer errors.

use core::fmt;

/// Dependency failures returned by repository, limiter, and outbox traits.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DependencyError {
    /// Backend dependency is temporarily unavailable.
    Unavailable,
    /// Conditional write failed because another actor won a race.
    ConditionalWriteFailed,
    /// Backend rejected or throttled the operation.
    RateLimited,
    /// Backend reported an internal invariant or serialization failure.
    Internal,
}

/// Atomic magic-link consume failures from storage.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConsumeMagicLinkError {
    /// Missing, expired, consumed, or verifier-mismatched record.
    Unavailable,
    /// Backend dependency is temporarily unavailable.
    DependencyUnavailable,
    /// Backend reported an internal invariant or serialization failure.
    Internal,
}

/// Public service errors. Variants never carry tokens, emails, session IDs, or
/// key material.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkServiceError {
    /// Caller input was malformed before any security-sensitive lookup.
    BadRequest,
    /// PoW proof is required by policy but was absent or invalid.
    PowRequired,
    /// Magic link could not be consumed. This intentionally covers missing,
    /// expired, already-consumed, throttled, and wrong-verifier cases.
    MagicLinkUnavailable,
    /// Dependency is unavailable; callers may retry later.
    Unavailable,
    /// Internal configuration or invariant failure.
    Internal,
}

impl fmt::Display for MagicLinkServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MagicLinkServiceError::BadRequest => f.write_str("bad request"),
            MagicLinkServiceError::PowRequired => f.write_str("proof of work required"),
            MagicLinkServiceError::MagicLinkUnavailable => f.write_str("magic link unavailable"),
            MagicLinkServiceError::Unavailable => f.write_str("service unavailable"),
            MagicLinkServiceError::Internal => f.write_str("internal service error"),
        }
    }
}

impl std::error::Error for MagicLinkServiceError {}

impl From<DependencyError> for MagicLinkServiceError {
    fn from(value: DependencyError) -> Self {
        match value {
            DependencyError::Unavailable | DependencyError::RateLimited => {
                MagicLinkServiceError::Unavailable
            }
            DependencyError::ConditionalWriteFailed => MagicLinkServiceError::Unavailable,
            DependencyError::Internal => MagicLinkServiceError::Internal,
        }
    }
}

impl From<dd_magic_link_core::MagicLinkError> for MagicLinkServiceError {
    fn from(value: dd_magic_link_core::MagicLinkError) -> Self {
        match value {
            dd_magic_link_core::MagicLinkError::InvalidToken
            | dd_magic_link_core::MagicLinkError::InvalidEmail => MagicLinkServiceError::BadRequest,
            dd_magic_link_core::MagicLinkError::EntropyUnavailable => {
                MagicLinkServiceError::Unavailable
            }
            dd_magic_link_core::MagicLinkError::BadKeyLength
            | dd_magic_link_core::MagicLinkError::Internal => MagicLinkServiceError::Internal,
        }
    }
}

impl From<dd_auth_token_core::TokenError> for MagicLinkServiceError {
    fn from(value: dd_auth_token_core::TokenError) -> Self {
        match value {
            dd_auth_token_core::TokenError::EntropyUnavailable
            | dd_auth_token_core::TokenError::KeyExpired => MagicLinkServiceError::Unavailable,
            dd_auth_token_core::TokenError::KeyringMisconfigured
            | dd_auth_token_core::TokenError::PayloadTooLarge
            | dd_auth_token_core::TokenError::InvalidTimestamp
            | dd_auth_token_core::TokenError::Internal => MagicLinkServiceError::Internal,
            _ => MagicLinkServiceError::MagicLinkUnavailable,
        }
    }
}

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

/// Public service errors. Variants never carry tokens, emails, session IDs, or
/// key material.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkServiceError {
    /// Caller input was malformed before any security-sensitive lookup.
    BadRequest,
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
            MagicLinkServiceError::MagicLinkUnavailable => f.write_str("magic link unavailable"),
            MagicLinkServiceError::Unavailable => f.write_str("service unavailable"),
            MagicLinkServiceError::Internal => f.write_str("internal service error"),
        }
    }
}

impl std::error::Error for MagicLinkServiceError {}

/// Browser disposition for temporary scanner-flow and PoW state.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TemporaryAuthStateAction {
    Preserve,
    Clear,
}

/// Scanner-flow error with a structurally derived temporary-state disposition.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MagicLinkFlowError {
    public_error: MagicLinkServiceError,
}

impl MagicLinkFlowError {
    pub(crate) const fn from_public_error(public_error: MagicLinkServiceError) -> Self {
        Self { public_error }
    }

    #[must_use]
    pub const fn public_error(&self) -> MagicLinkServiceError {
        self.public_error
    }

    #[must_use]
    pub const fn temporary_state_action(&self) -> TemporaryAuthStateAction {
        match self.public_error {
            MagicLinkServiceError::Unavailable => TemporaryAuthStateAction::Preserve,
            MagicLinkServiceError::BadRequest
            | MagicLinkServiceError::MagicLinkUnavailable
            | MagicLinkServiceError::Internal => TemporaryAuthStateAction::Clear,
        }
    }
}

impl fmt::Display for MagicLinkFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.public_error.fmt(f)
    }
}

impl std::error::Error for MagicLinkFlowError {}

/// Outcome of the atomic authentication transaction.
///
/// See [`MagicLinkAuthenticationRepository`](crate::traits::MagicLinkAuthenticationRepository)
/// for atomicity and retry requirements.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CommitMagicLinkAuthenticationError {
    /// The challenge no longer satisfies the expected unconsumed, unexpired,
    /// consent, or immutable-field conditions.
    Rejected,
    /// The planned existing-user conditions or conditional user creation lost
    /// a race.
    UserConflict,
    /// The conditional session or user-session-index creation lost a race.
    SessionConflict,
    /// The dependency outcome may be ambiguous.
    DependencyUnavailable,
    /// The adapter detected malformed data, an invalid command, or an internal
    /// invariant failure.
    Internal,
}

impl fmt::Display for CommitMagicLinkAuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("authentication transaction rejected"),
            Self::UserConflict => f.write_str("authentication user conflict"),
            Self::SessionConflict => f.write_str("authentication session conflict"),
            Self::DependencyUnavailable => f.write_str("authentication dependency unavailable"),
            Self::Internal => f.write_str("internal authentication transaction error"),
        }
    }
}

impl std::error::Error for CommitMagicLinkAuthenticationError {}

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

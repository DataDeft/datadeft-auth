//! Typed magic-link primitive errors.

use core::fmt;

/// Errors from IO-free magic-link parsing, validation, and HMAC helpers.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkError {
    /// Magic-link token shape, selector, or verifier was malformed.
    InvalidToken,
    /// Normalized email structure was invalid for this product boundary.
    InvalidEmail,
    /// HMAC key material was not 32 bytes.
    BadKeyLength,
    /// Caller-supplied RNG failed while minting token entropy.
    EntropyUnavailable,
    /// Internal invariant failure that carries no sensitive data.
    Internal,
}

impl fmt::Display for MagicLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MagicLinkError::InvalidToken => f.write_str("invalid magic-link token"),
            MagicLinkError::InvalidEmail => f.write_str("invalid normalized email"),
            MagicLinkError::BadKeyLength => f.write_str("HMAC key must be 32 bytes"),
            MagicLinkError::EntropyUnavailable => f.write_str("entropy source unavailable"),
            MagicLinkError::Internal => f.write_str("internal magic-link error"),
        }
    }
}

impl std::error::Error for MagicLinkError {}

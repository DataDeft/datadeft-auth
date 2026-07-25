//! Typed errors for token / session / cookie operations.
//!
//! This is a closed enum. No variant carries token bytes, keys, nonces, or
//! session identifiers — errors are safe to log and surface generically.

use std::fmt;

/// A token / session / cookie failure.
///
/// Variants are intentionally coarse and non-enumerating: a caller cannot
/// distinguish "wrong key" from "tampered ciphertext" from "bad base62", which
/// is the desired property for cookie validation paths. The keyring variants
/// (`UnknownKey`, `KeyExpired`, `KeyringMisconfigured`) are distinct because
/// they signal configuration / rotation problems rather than a bad token.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TokenError {
    /// Input was not valid base62 (bad character, wrong shape).
    InvalidBase62,
    /// Branca version byte did not match `0xBA`.
    InvalidTokenVersion,
    /// Branca key was not exactly 32 bytes.
    BadKeyLength,
    /// Branca nonce was not exactly 24 bytes.
    BadNonceLength,
    /// AEAD decryption failed (tag mismatch / wrong key / tamper).
    DecryptFailed,
    /// Entropy source failed while minting a token.
    EntropyUnavailable,
    /// AEAD encryption failed (should not happen for valid inputs).
    EncryptFailed,
    /// Payload exceeded the documented size guard (DoS backstop).
    PayloadTooLarge,
    /// Cookie wrapper, payload purpose, or session id was malformed.
    MalformedCookie,
    /// Key id was not found in the keyring.
    UnknownKey,
    /// Key exists but is outside its minting or verification window.
    KeyExpired,
    /// Keyring has no single active key, duplicate kids, or no matching active.
    KeyringMisconfigured,
    /// Token / cookie TTL has been exceeded.
    Expired,
    /// Catch-all for JSON / overflow / invariant failures (never carries data).
    Internal,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidBase62 => f.write_str("invalid base62 encoding"),
            TokenError::InvalidTokenVersion => f.write_str("invalid token version"),
            TokenError::BadKeyLength => f.write_str("key must be 32 bytes"),
            TokenError::BadNonceLength => f.write_str("nonce must be 24 bytes"),
            TokenError::DecryptFailed => f.write_str("token decryption failed"),
            TokenError::EntropyUnavailable => f.write_str("entropy source unavailable"),
            TokenError::EncryptFailed => f.write_str("token encryption failed"),
            TokenError::PayloadTooLarge => f.write_str("payload too large"),
            TokenError::MalformedCookie => f.write_str("malformed cookie"),
            TokenError::UnknownKey => f.write_str("unknown key id"),
            TokenError::KeyExpired => f.write_str("key is outside its validity window"),
            TokenError::KeyringMisconfigured => f.write_str("keyring is misconfigured"),
            TokenError::Expired => f.write_str("token has expired"),
            TokenError::Internal => f.write_str("internal token error"),
        }
    }
}

impl std::error::Error for TokenError {}

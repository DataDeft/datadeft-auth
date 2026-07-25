//! Magic-link token grammar and generation.
//!
//! Current token format is exactly:
//!
//! ```text
//! mlv1.<selector>.<verifier>
//! ```
//!
//! `selector` is 128 bits of CSPRNG entropy encoded as 32 lowercase hex
//! characters. `verifier` is 256 bits encoded as 64 lowercase hex characters.
//! The `mlv1` prefix is the explicit wire-format version marker. `selector` is
//! the lower-value lookup half; the verifier is the bearer secret. Store only
//! keyed lookup/HMAC material for both halves.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::error::MagicLinkError;

/// Magic-link token wire-format version prefix.
pub const MAGIC_LINK_TOKEN_VERSION_PREFIX: &str = "mlv1";

/// Raw selector entropy bytes.
pub const SELECTOR_BYTES: usize = 16;
/// Raw verifier entropy bytes.
pub const VERIFIER_BYTES: usize = 32;
/// Lowercase-hex selector length.
pub const SELECTOR_HEX_LEN: usize = SELECTOR_BYTES * 2;
/// Lowercase-hex verifier length.
pub const VERIFIER_HEX_LEN: usize = VERIFIER_BYTES * 2;

/// Random lookup half of a magic-link token.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct MagicLinkSelector(String);

impl MagicLinkSelector {
    /// Parse a selector in the current canonical lowercase-hex format.
    pub fn parse(value: &str) -> Result<Self, MagicLinkError> {
        if is_lower_hex_len(value, SELECTOR_HEX_LEN) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkError::InvalidToken)
        }
    }

    /// Generate from caller-supplied entropy.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, MagicLinkError> {
        let mut bytes = [0u8; SELECTOR_BYTES];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| MagicLinkError::EntropyUnavailable)?;
        let value = hex::encode(bytes);
        bytes.zeroize();
        Ok(Self(value))
    }

    /// Value used as input to selector lookup HMAC. Do not store raw.
    #[must_use]
    pub fn as_lookup_value(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MagicLinkSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkSelector(..)")
    }
}

/// Secret verifier half of a magic-link token.
#[derive(Clone, Eq, PartialEq)]
pub struct MagicLinkVerifier(String);

impl MagicLinkVerifier {
    /// Parse a verifier in the current canonical lowercase-hex format.
    pub fn parse(value: &str) -> Result<Self, MagicLinkError> {
        if is_lower_hex_len(value, VERIFIER_HEX_LEN) {
            Ok(Self(value.to_owned()))
        } else {
            Err(MagicLinkError::InvalidToken)
        }
    }

    /// Generate from caller-supplied entropy.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, MagicLinkError> {
        let mut bytes = [0u8; VERIFIER_BYTES];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| MagicLinkError::EntropyUnavailable)?;
        let value = hex::encode(bytes);
        bytes.zeroize();
        Ok(Self(value))
    }

    /// Bearer secret value. Never log or store raw.
    #[must_use]
    pub fn as_secret_value(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MagicLinkVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkVerifier(..)")
    }
}

/// Full bearer magic-link token.
#[derive(Clone, Eq, PartialEq)]
pub struct MagicLinkToken {
    selector: MagicLinkSelector,
    verifier: MagicLinkVerifier,
}

impl MagicLinkToken {
    /// Generate a fresh selector/verifier token from caller-supplied CSPRNG.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, MagicLinkError> {
        Ok(Self {
            selector: MagicLinkSelector::generate(rng)?,
            verifier: MagicLinkVerifier::generate(rng)?,
        })
    }

    /// Parse `mlv1.<selector>.<verifier>` with no extra segments or whitespace.
    pub fn parse(value: &str) -> Result<Self, MagicLinkError> {
        let mut parts = value.split('.');
        let Some(version) = parts.next() else {
            return Err(MagicLinkError::InvalidToken);
        };
        let Some(selector) = parts.next() else {
            return Err(MagicLinkError::InvalidToken);
        };
        let Some(verifier) = parts.next() else {
            return Err(MagicLinkError::InvalidToken);
        };
        if parts.next().is_some() || version != MAGIC_LINK_TOKEN_VERSION_PREFIX {
            return Err(MagicLinkError::InvalidToken);
        }
        Ok(Self {
            selector: MagicLinkSelector::parse(selector)?,
            verifier: MagicLinkVerifier::parse(verifier)?,
        })
    }

    #[must_use]
    pub fn selector(&self) -> &MagicLinkSelector {
        &self.selector
    }

    #[must_use]
    pub fn verifier(&self) -> &MagicLinkVerifier {
        &self.verifier
    }

    /// Render the bearer token for an email URL. Never log this value.
    #[must_use]
    pub fn as_secret_value(&self) -> String {
        format!(
            "{MAGIC_LINK_TOKEN_VERSION_PREFIX}.{}.{}",
            self.selector.as_lookup_value(),
            self.verifier.as_secret_value()
        )
    }
}

impl fmt::Debug for MagicLinkToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkToken(..)")
    }
}

fn is_lower_hex_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
#[path = "magic_link_tests.rs"]
mod tests;

//! Purpose-separated HMAC lookup material for magic-link flows.
//!
//! Storage lookup keys and verifier hashes are secret-keyed HMACs. Raw
//! selectors and verifiers should never be stored. An adapter may store the
//! normalized email as a record attribute (for sending mail and identifying
//! the account), but should not use it as a lookup key.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::confirm_cookie::{
    ConfirmAccountBinding, ConfirmSelectorBinding, ConfirmVerifierBinding,
};
use crate::email::NormalizedEmail;
use crate::error::MagicLinkError;
use crate::magic_link::{MagicLinkSelector, MagicLinkVerifier, is_lower_hex_len};

type HmacSha256 = Hmac<Sha256>;

/// Required HMAC key/pepper length.
pub const HMAC_KEY_BYTES: usize = 32;
const HMAC_DOMAIN: &[u8] = b"magic-link-lookup-v1";
const HMAC_BYTES: usize = 32;
const HMAC_HEX_LEN: usize = HMAC_BYTES * 2;

/// Storage prefix for normalized-email lookup HMACs.
pub const EMAIL_LOOKUP_PREFIX: &str = "emh";
/// Storage prefix for magic-link selector lookup HMACs.
pub const SELECTOR_LOOKUP_PREFIX: &str = "mlh";
/// Storage prefix for magic-link verifier HMACs.
pub const VERIFIER_HASH_PREFIX: &str = "mlv";

/// Loaded HMAC key/pepper material. The `Debug` impl redacts it. The bytes
/// zeroize on drop.
pub struct LookupHmacKey([u8; HMAC_KEY_BYTES]);

impl LookupHmacKey {
    #[must_use]
    pub fn new(bytes: [u8; HMAC_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, MagicLinkError> {
        let array: [u8; HMAC_KEY_BYTES] =
            bytes.try_into().map_err(|_| MagicLinkError::BadKeyLength)?;
        Ok(Self::new(array))
    }

    fn as_bytes(&self) -> &[u8; HMAC_KEY_BYTES] {
        &self.0
    }
}

impl Drop for LookupHmacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for LookupHmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LookupHmacKey(..)")
    }
}

/// Secret-derived lookup key, e.g. `mlh_<hex>` or `emh_<hex>`.
#[derive(Clone, Eq, PartialEq)]
pub struct LookupHmac(String);

impl LookupHmac {
    #[must_use]
    pub fn as_storage_value(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LookupHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LookupHmac(..)")
    }
}

/// Secret-derived verifier hash, e.g. `mlv_<hex>`.
///
/// There is deliberately no `==`: an early-exit comparison would leak timing.
/// Compare with [`VerifierHash::matches_hash_constant_time`]. This does not
/// compile:
///
/// ```compile_fail
/// use datadeft_magic_link_core::VerifierHash;
/// fn leaks_timing(stored: &VerifierHash, presented: &VerifierHash) -> bool {
///     stored == presented
/// }
/// ```
#[derive(Clone)]
pub struct VerifierHash(String);

impl VerifierHash {
    /// Parse the one canonical verifier-hash storage representation:
    /// exactly `mlv_` followed by 64 lowercase hexadecimal characters.
    pub fn parse_storage_value(value: &str) -> Result<Self, MagicLinkError> {
        // One canonical-shape definition: delegate to the same decoder the
        // flow bindings use, discarding the decoded bytes.
        let mut decoded = decode_canonical_hmac(value, VERIFIER_HASH_PREFIX)?;
        decoded.zeroize();
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_storage_value(&self) -> &str {
        &self.0
    }

    /// Constant-time compare with another stored verifier hash.
    #[must_use]
    pub fn matches_hash_constant_time(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).unwrap_u8() == 1
    }

    /// HMAC `verifier` with `key`, then constant-time compare to this hash.
    pub fn matches_verifier_constant_time(
        &self,
        key: &LookupHmacKey,
        verifier: &MagicLinkVerifier,
    ) -> Result<bool, MagicLinkError> {
        let computed = verifier_hash(key, verifier)?;
        Ok(self.matches_hash_constant_time(&computed))
    }
}

impl fmt::Debug for VerifierHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifierHash(..)")
    }
}

pub fn email_lookup_hmac(
    key: &LookupHmacKey,
    email: &NormalizedEmail,
) -> Result<LookupHmac, MagicLinkError> {
    hmac_prefixed(key, EMAIL_LOOKUP_PREFIX, email.as_str()).map(LookupHmac)
}

pub fn selector_lookup_hmac(
    key: &LookupHmacKey,
    selector: &MagicLinkSelector,
) -> Result<LookupHmac, MagicLinkError> {
    hmac_prefixed(key, SELECTOR_LOOKUP_PREFIX, selector.as_lookup_value()).map(LookupHmac)
}

pub fn verifier_hash(
    key: &LookupHmacKey,
    verifier: &MagicLinkVerifier,
) -> Result<VerifierHash, MagicLinkError> {
    hmac_prefixed(key, VERIFIER_HASH_PREFIX, verifier.as_secret_value()).map(VerifierHash)
}

/// Convert a canonical selector lookup HMAC into its flow binding.
pub fn confirm_selector_binding(
    lookup: &LookupHmac,
) -> Result<ConfirmSelectorBinding, MagicLinkError> {
    let mut decoded = decode_canonical_hmac(lookup.as_storage_value(), SELECTOR_LOOKUP_PREFIX)?;
    let binding = ConfirmSelectorBinding::new(decoded);
    decoded.zeroize();
    Ok(binding)
}

/// Reconstruct the canonical selector lookup HMAC authenticated by a confirm cookie.
#[must_use]
pub fn selector_lookup_hmac_from_confirm_binding(binding: &ConfirmSelectorBinding) -> LookupHmac {
    LookupHmac(format!(
        "{SELECTOR_LOOKUP_PREFIX}_{}",
        hex::encode(binding.as_sensitive_bytes())
    ))
}

/// Convert a canonical verifier hash into its flow binding.
pub fn confirm_verifier_binding(
    hash: &VerifierHash,
) -> Result<ConfirmVerifierBinding, MagicLinkError> {
    let mut decoded = decode_canonical_hmac(hash.as_storage_value(), VERIFIER_HASH_PREFIX)?;
    let binding = ConfirmVerifierBinding::new(decoded);
    decoded.zeroize();
    Ok(binding)
}

/// Reconstruct the canonical verifier hash authenticated by a confirm cookie.
#[must_use]
pub fn verifier_hash_from_confirm_binding(binding: &ConfirmVerifierBinding) -> VerifierHash {
    VerifierHash(format!(
        "{VERIFIER_HASH_PREFIX}_{}",
        hex::encode(binding.as_sensitive_bytes())
    ))
}

/// Convert a canonical account lookup HMAC into its flow binding.
pub fn confirm_account_binding(
    lookup: &LookupHmac,
) -> Result<ConfirmAccountBinding, MagicLinkError> {
    let mut decoded = decode_canonical_hmac(lookup.as_storage_value(), EMAIL_LOOKUP_PREFIX)?;
    let binding = ConfirmAccountBinding::new(decoded);
    decoded.zeroize();
    Ok(binding)
}

fn decode_canonical_hmac(
    value: &str,
    expected_prefix: &str,
) -> Result<[u8; HMAC_BYTES], MagicLinkError> {
    let Some(encoded) = value.strip_prefix(expected_prefix) else {
        return Err(MagicLinkError::InvalidToken);
    };
    let Some(encoded) = encoded.strip_prefix('_') else {
        return Err(MagicLinkError::InvalidToken);
    };
    if !is_lower_hex_len(encoded, HMAC_HEX_LEN) {
        return Err(MagicLinkError::InvalidToken);
    }

    let mut decoded = [0_u8; HMAC_BYTES];
    if hex::decode_to_slice(encoded, &mut decoded).is_err() {
        decoded.zeroize();
        return Err(MagicLinkError::InvalidToken);
    }
    Ok(decoded)
}

/// Compute a domain-separated, prefixed lookup HMAC.
///
/// Framing: `HMAC-SHA256(key, domain || 0x00 || prefix || 0x00 || value)`,
/// rendered as `{prefix}_{lowercase hex}`. This is the single keyed-lookup
/// framing for the workspace. Adapters that store their own keyed lookup
/// material bind a distinct `domain` and key, so their derived values are
/// cryptographically unrelated to magic-link lookup values even for equal
/// prefixes and inputs.
pub fn domain_separated_lookup_hmac(
    key: &LookupHmacKey,
    domain: &[u8],
    prefix: &str,
    value: &str,
) -> Result<String, MagicLinkError> {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| MagicLinkError::Internal)?;
    mac.update(domain);
    mac.update(&[0]);
    mac.update(prefix.as_bytes());
    mac.update(&[0]);
    mac.update(value.as_bytes());
    Ok(format!(
        "{prefix}_{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

fn hmac_prefixed(key: &LookupHmacKey, prefix: &str, value: &str) -> Result<String, MagicLinkError> {
    domain_separated_lookup_hmac(key, HMAC_DOMAIN, prefix, value)
}

#[cfg(test)]
#[path = "hmac_lookup_tests.rs"]
mod tests;

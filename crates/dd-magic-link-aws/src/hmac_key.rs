//! Storage lookup HMAC helpers.

use core::fmt;

use dd_magic_link_service::{LookupHmacKey, domain_separated_lookup_hmac};

use crate::error::AwsAdapterError;

/// Storage HMAC key length.
pub const STORAGE_HMAC_KEY_BYTES: usize = 32;
/// Storage prefix for session-id lookup HMACs.
pub const SESSION_LOOKUP_HMAC_PREFIX: &str = "sih";
/// Storage prefix for normalized-email lookup HMACs.
///
/// Same three-letter spelling as magic-link-core's `EMAIL_LOOKUP_PREFIX`, but
/// keyed under the adapter storage domain, so the derived values are unrelated.
pub const EMAIL_LOOKUP_HMAC_PREFIX: &str = "emh";
/// Storage prefix for rate-limit counter lookup HMACs.
pub const RATE_LOOKUP_HMAC_PREFIX: &str = "rlh";

const STORAGE_HMAC_DOMAIN: &[u8] = b"magic-link-aws-storage-v1";

/// Loaded storage lookup HMAC key/pepper, bound to the adapter storage domain.
///
/// Wraps magic-link-core's key type and its shared keyed-lookup framing; only
/// the `magic-link-aws-storage-v1` domain binding lives here, so the framing
/// cannot drift from the lookup HMACs the service derives. Debug is redacted;
/// bytes zeroize on drop via the wrapped key type.
pub struct StorageHmacKey(LookupHmacKey);

impl StorageHmacKey {
    #[must_use]
    pub fn new(bytes: [u8; STORAGE_HMAC_KEY_BYTES]) -> Self {
        Self(LookupHmacKey::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AwsAdapterError> {
        LookupHmacKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| AwsAdapterError::Internal)
    }

    pub(crate) fn hmac(&self, prefix: &str, value: &str) -> Result<String, AwsAdapterError> {
        domain_separated_lookup_hmac(&self.0, STORAGE_HMAC_DOMAIN, prefix, value)
            .map_err(|_| AwsAdapterError::Internal)
    }
}

impl fmt::Debug for StorageHmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageHmacKey(..)")
    }
}

#[cfg(test)]
#[path = "hmac_key_tests.rs"]
mod tests;

//! Storage lookup HMAC helpers.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::AwsAdapterError;

type HmacSha256 = Hmac<Sha256>;

/// Storage HMAC key length.
pub const STORAGE_HMAC_KEY_BYTES: usize = 32;
/// Storage prefix for session-id lookup HMACs.
pub const SESSION_LOOKUP_HMAC_PREFIX: &str = "sih";

const STORAGE_HMAC_DOMAIN: &[u8] = b"magic-link-aws-storage-v1";

/// Loaded storage lookup HMAC key/pepper. Debug is redacted; bytes zeroize on
/// drop on a best-effort basis.
pub struct StorageHmacKey([u8; STORAGE_HMAC_KEY_BYTES]);

impl StorageHmacKey {
    #[must_use]
    pub fn new(bytes: [u8; STORAGE_HMAC_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AwsAdapterError> {
        let array: [u8; STORAGE_HMAC_KEY_BYTES] =
            bytes.try_into().map_err(|_| AwsAdapterError::Internal)?;
        Ok(Self::new(array))
    }

    pub(crate) fn hmac(&self, prefix: &str, value: &str) -> Result<String, AwsAdapterError> {
        let mut mac = HmacSha256::new_from_slice(&self.0).map_err(|_| AwsAdapterError::Internal)?;
        mac.update(STORAGE_HMAC_DOMAIN);
        mac.update(&[0]);
        mac.update(prefix.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        Ok(format!(
            "{prefix}_{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }
}

impl Drop for StorageHmacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for StorageHmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageHmacKey(..)")
    }
}

//! Storage lookup HMAC helpers.

use core::fmt;

use subtle::ConstantTimeEq;

use datadeft_magic_link_service::{LookupHmacKey, domain_separated_lookup_hmac};

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
const LIFETIME_COUNTER_DOMAIN: &[u8] = b"magic-link-aws-lifetime-counter-v1";

/// The storage id of a lifetime counter: a domain-separated SHA-256 of the
/// rate-limit key, deliberately **not** keyed by the storage HMAC key. A
/// budget must stay one counter through a storage-key rotation, or a rotation
/// would split or reset it. Lifetime keys therefore must never carry personal
/// data or secrets; the per-solve PoW budget keys on the solve's `tid`, a hash
/// of the public challenge.
pub(crate) fn lifetime_counter_id(key: &datadeft_magic_link_service::RateLimitKey) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(LIFETIME_COUNTER_DOMAIN);
    hasher.update([0u8]);
    hasher.update(key.as_str().as_bytes());
    format!("lt_{}", hex::encode(hasher.finalize()))
}
// Never a storage prefix, so the probe value is never written anywhere.
const KEY_PROBE_PREFIX: &str = "key-probe";
const KEY_PROBE_VALUE: &str = "storage-key-identity";

/// Loaded storage lookup HMAC key/pepper, bound to the adapter storage domain.
///
/// Wraps magic-link-core's key type and its shared keyed-lookup framing. Only
/// the `magic-link-aws-storage-v1` domain binding lives here, so the framing
/// cannot drift from the lookup HMACs the service derives. The `Debug` impl
/// redacts the key. The bytes zeroize on drop via the wrapped key type.
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

    /// Whether both keys hold the same bytes, compared in constant time
    /// through one fixed probe HMAC so the raw key never leaves its type.
    fn same_key_as(&self, other: &Self) -> bool {
        match (
            self.hmac(KEY_PROBE_PREFIX, KEY_PROBE_VALUE),
            other.hmac(KEY_PROBE_PREFIX, KEY_PROBE_VALUE),
        ) {
            (Ok(left), Ok(right)) => left.as_bytes().ct_eq(right.as_bytes()).into(),
            _ => false,
        }
    }
}

impl fmt::Debug for StorageHmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageHmacKey(..)")
    }
}

/// The current storage key plus, during a rotation window, the previous one.
///
/// Writes always use [`Self::current`]. Reads that miss under the current key
/// retry under [`Self::previous`], so records written before a rotation stay
/// reachable. Both stores share this type so their fallback cannot drift.
///
/// A previous key equal to the current one is dropped: it adds nothing, and
/// a create would otherwise put the same email row twice in one transaction,
/// which DynamoDB rejects.
pub(crate) struct StorageHmacKeys {
    current: StorageHmacKey,
    previous: Option<StorageHmacKey>,
}

impl StorageHmacKeys {
    pub(crate) fn new(current: StorageHmacKey, previous: Option<StorageHmacKey>) -> Self {
        let previous = previous.filter(|previous| !previous.same_key_as(&current));
        Self { current, previous }
    }

    pub(crate) fn current(&self) -> &StorageHmacKey {
        &self.current
    }

    pub(crate) fn previous(&self) -> Option<&StorageHmacKey> {
        self.previous.as_ref()
    }

    /// Every key a record may live under: current first, then previous. A
    /// create claims its email row under all of them, so a node still on the
    /// previous key finds the account during a rotation.
    pub(crate) fn all(&self) -> impl Iterator<Item = &StorageHmacKey> {
        core::iter::once(&self.current).chain(self.previous.as_ref())
    }

    #[cfg(feature = "aws")]
    pub(crate) fn set_previous(&mut self, previous: StorageHmacKey) {
        self.previous = Some(previous).filter(|previous| !previous.same_key_as(&self.current));
    }
}

impl fmt::Debug for StorageHmacKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageHmacKeys(..)")
    }
}

#[cfg(test)]
#[path = "hmac_key_tests.rs"]
mod tests;

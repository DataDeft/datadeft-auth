//! HMAC secret for the proof-of-work challenge tag.

use zeroize::Zeroize;

/// 32-byte secret key for the challenge HMAC.
///
/// The `Drop` impl uses the audited `zeroize` crate to zero the key on drop, so
/// key material does not linger in memory. This is best-effort hygiene: like any
/// in-process key, the HMAC implementation and the OS may briefly hold copies
/// elsewhere.
pub struct PowSecret([u8; 32]);

impl PowSecret {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Key bytes, for crate-internal HMAC construction only.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for PowSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for PowSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PowSecret(..)")
    }
}

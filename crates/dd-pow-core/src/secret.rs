//! HMAC secret for the proof-of-work challenge tag.

/// 32-byte secret key for the challenge HMAC.
///
/// Best-effort zeroed on drop. The workspace does not depend on `zeroize` and
/// this crate adds no new dependencies, so the drop impl uses volatile writes
/// plus a compiler fence — the standard hand-rolled equivalent for a fixed
/// array. If `zeroize` ever enters the workspace tree, switch to it.
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
        for b in &mut self.0 {
            // SAFETY: `b` is a valid, aligned, exclusive reference into self.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl core::fmt::Debug for PowSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PowSecret(..)")
    }
}

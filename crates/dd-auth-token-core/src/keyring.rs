//! Key material wrappers for future typed keyrings.
//!
//! This module currently owns only loaded secret/key bytes. Rotation slots,
//! HKDF purpose derivation, and cookie keyrings are added in later packets.
//!
//! # Zeroization is best-effort only
//!
//! [`RootSecret`] and [`BrancaKey`] zero their in-process byte arrays on drop via
//! the audited `zeroize` crate. This is useful defense-in-depth, but it is not a
//! hard security guarantee: AWS SDK buffers, base64 strings, serde parse buffers,
//! allocator copies, compiler moves, crash dumps, and AEAD internals may hold
//! additional copies this crate cannot control. Treat zeroization as hygiene,
//! not as proof that key material never existed elsewhere in memory.

use std::fmt;
use std::marker::PhantomData;

use zeroize::Zeroize;

/// Required length of all root and Branca key material in this crate.
pub const KEY_BYTES: usize = 32;

/// Loaded root secret material.
///
/// Adapter/setup code loads this from a secret manager or local development
/// config, then core code derives purpose-specific keys from it. `Debug` is
/// redacted; bytes are zeroized on drop on a best-effort basis.
pub struct RootSecret([u8; KEY_BYTES]);

impl RootSecret {
    /// Wrap loaded 256-bit root secret material.
    #[must_use]
    pub fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    #[allow(dead_code)] // used once HKDF derivation lands
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl Drop for RootSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for RootSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootSecret(..)")
    }
}

/// A derived 32-byte Branca key for purpose marker `P`.
///
/// The marker is currently only a type tag for future typed keyrings. `Debug` is
/// redacted; bytes are zeroized on drop on a best-effort basis.
pub struct BrancaKey<P = ()> {
    bytes: [u8; KEY_BYTES],
    _purpose: PhantomData<P>,
}

impl<P> BrancaKey<P> {
    /// Wrap derived/loaded Branca key material.
    #[must_use]
    pub fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self {
            bytes,
            _purpose: PhantomData,
        }
    }

    #[allow(dead_code)] // used by cookie encryption once cookie wrappers land
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

impl<P> Drop for BrancaKey<P> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P> fmt::Debug for BrancaKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrancaKey(..)")
    }
}

#[cfg(test)]
#[path = "keyring_tests.rs"]
mod tests;

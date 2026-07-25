//! Key material wrappers for future typed keyrings.
//!
//! This module currently owns loaded root secret material and purpose-derived
//! Branca keys. Rotation slots and cookie keyrings are added in later packets.
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

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::TokenError;

/// Required length of all root and Branca key material in this crate.
pub const KEY_BYTES: usize = 32;

/// HKDF purpose marker for keys derived from a [`RootSecret`].
pub trait KeyPurpose {
    /// Versioned HKDF `info` string. Changing this invalidates every token
    /// minted with the derived key, so constants are pinned by tests.
    const HKDF_INFO: &'static [u8];
}

/// Session-cookie key purpose.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionCookie {}

impl KeyPurpose for SessionCookie {
    const HKDF_INFO: &'static [u8] = b"auth/session-v1";
}

/// PoW proof-cookie key purpose.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PowCookie {}

impl KeyPurpose for PowCookie {
    const HKDF_INFO: &'static [u8] = b"auth/pow-v1";
}

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

    /// Derive a purpose-specific Branca key with HKDF-SHA256.
    ///
    /// AWS/adapters load only the root bytes; purpose separation is enforced by
    /// the KDF `info` string, not a runtime flag. A session key and PoW key
    /// derived from the same root are unrelated AEAD keys.
    pub fn derive_key<P: KeyPurpose>(&self) -> Result<BrancaKey<P>, TokenError> {
        let mut out = [0u8; KEY_BYTES];
        Hkdf::<Sha256>::new(None, self.as_bytes())
            .expand(P::HKDF_INFO, &mut out)
            .map_err(|_| TokenError::Internal)?;
        Ok(BrancaKey::new(out))
    }

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

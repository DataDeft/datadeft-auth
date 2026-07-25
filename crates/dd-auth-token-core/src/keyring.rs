//! Purpose-derived key material and typed in-memory keyrings.
//!
//! This module owns loaded root secret material, HKDF-derived Branca keys, and
//! purpose-typed keyrings. Cookie wrappers and AWS/Secrets Manager loading are
//! separate packets: this core module only accepts already-loaded bytes and
//! deterministic timestamps/windows.
//!
//! # Zeroization is best-effort only
//!
//! [`RootSecret`] and [`BrancaKey`] zero their in-process byte arrays on drop via
//! the audited `zeroize` crate. This is useful defense-in-depth, but it is not a
//! hard security guarantee: AWS SDK buffers, base64 strings, serde parse buffers,
//! allocator copies, compiler moves, crash dumps, and AEAD internals may hold
//! additional copies this crate cannot control. Treat zeroization as hygiene,
//! not as proof that key material never existed elsewhere in memory.
//!
//! # Purpose separation
//!
//! A single root secret is expanded into independent Branca keys with
//! HKDF-SHA256. The `info` string is a versioned constant per purpose
//! (`auth/session-v1`, `auth/pow-v1`). Keyrings are also typed: a
//! `KeyRing<SessionCookie>` cannot be passed where a `KeyRing<PowCookie>` is
//! expected.

use std::collections::HashSet;
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
/// `Debug` is redacted; bytes are zeroized on drop on a best-effort basis.
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

impl<P> Clone for BrancaKey<P> {
    fn clone(&self) -> Self {
        Self::new(self.bytes)
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

/// Valid key states. There is intentionally no `Retired` state: retired means
/// absent from the keyring, not kept in memory.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyStatus {
    /// May mint new tokens and verify existing ones while inside its windows.
    Active,
    /// May verify existing tokens only; never used for minting.
    VerifyOnly,
}

/// A validated, opaque key identifier.
///
/// `kid` is attacker-controlled input when parsing cookie wrappers, so `Debug`
/// is redacted even though the value is not cryptographic secret material.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Parse a key id. Must be 1..=64 bytes of `[A-Za-z0-9_-]`.
    pub fn parse(value: &str) -> Result<Self, TokenError> {
        if is_valid_key_id(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(TokenError::InvalidToken)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyId(..)")
    }
}

fn is_valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// One purpose-typed keyring slot.
#[derive(Clone, Debug)]
pub struct KeySlot<P: KeyPurpose> {
    kid: KeyId,
    key: BrancaKey<P>,
    status: KeyStatus,
    mint_until_unix: u64,
    verify_until_unix: u64,
}

impl<P: KeyPurpose> KeySlot<P> {
    /// Active key with no window bound (use only for tests/dev).
    #[must_use]
    pub fn active(kid: KeyId, key: BrancaKey<P>) -> Self {
        Self::active_with_windows(kid, key, u64::MAX, u64::MAX)
    }

    /// Active key with explicit mint and verify windows.
    #[must_use]
    pub fn active_with_windows(
        kid: KeyId,
        key: BrancaKey<P>,
        mint_until_unix: u64,
        verify_until_unix: u64,
    ) -> Self {
        Self {
            kid,
            key,
            status: KeyStatus::Active,
            mint_until_unix,
            verify_until_unix,
        }
    }

    /// Verify-only key retained during rotation.
    #[must_use]
    pub fn verify_only(kid: KeyId, key: BrancaKey<P>, verify_until_unix: u64) -> Self {
        Self {
            kid,
            key,
            status: KeyStatus::VerifyOnly,
            mint_until_unix: 0,
            verify_until_unix,
        }
    }

    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    #[must_use]
    pub fn key(&self) -> &BrancaKey<P> {
        &self.key
    }

    #[must_use]
    pub fn status(&self) -> KeyStatus {
        self.status
    }

    fn accepts_minting_at(&self, now_unix: u64) -> bool {
        self.status == KeyStatus::Active && now_unix <= self.mint_until_unix
    }

    fn accepts_verification_at(&self, now_unix: u64) -> bool {
        now_unix <= self.verify_until_unix
    }
}

/// Purpose-typed Branca keyring.
///
/// A `KeyRing<SessionCookie>` cannot be passed where a `KeyRing<PowCookie>` is
/// expected. Purpose separation is enforced both by HKDF output and Rust type.
#[derive(Clone, Debug)]
pub struct KeyRing<P: KeyPurpose> {
    active_kid: KeyId,
    keys: Vec<KeySlot<P>>,
}

impl<P: KeyPurpose> KeyRing<P> {
    /// Build a ring with exactly one active key and no duplicate `kid`s.
    pub fn new(active_kid: KeyId, keys: Vec<KeySlot<P>>) -> Result<Self, TokenError> {
        if keys.is_empty() || has_duplicate_key_ids(&keys) {
            return Err(TokenError::KeyringMisconfigured);
        }

        let active_count = keys
            .iter()
            .filter(|slot| slot.status == KeyStatus::Active)
            .count();
        let active_matches = keys
            .iter()
            .any(|slot| slot.status == KeyStatus::Active && slot.kid == active_kid);

        if active_count != 1 || !active_matches {
            return Err(TokenError::KeyringMisconfigured);
        }

        Ok(Self { active_kid, keys })
    }

    /// The active slot, if the ring invariant still holds.
    pub fn active(&self) -> Result<&KeySlot<P>, TokenError> {
        self.keys
            .iter()
            .find(|slot| slot.status == KeyStatus::Active && slot.kid == self.active_kid)
            .ok_or(TokenError::KeyringMisconfigured)
    }

    /// Active key allowed to mint at `now_unix`.
    pub fn minting_key_at(&self, now_unix: u64) -> Result<&KeySlot<P>, TokenError> {
        let key = self.active()?;
        if key.accepts_minting_at(now_unix) {
            Ok(key)
        } else {
            Err(TokenError::KeyExpired)
        }
    }

    /// Verification key for `kid`, if still inside its verify window.
    pub fn verification_key_at(
        &self,
        kid: &KeyId,
        now_unix: u64,
    ) -> Result<&KeySlot<P>, TokenError> {
        let key = self
            .keys
            .iter()
            .find(|slot| &slot.kid == kid)
            .ok_or(TokenError::UnknownKey)?;
        if key.accepts_verification_at(now_unix) {
            Ok(key)
        } else {
            Err(TokenError::KeyExpired)
        }
    }
}

fn has_duplicate_key_ids<P: KeyPurpose>(keys: &[KeySlot<P>]) -> bool {
    let mut seen = HashSet::new();
    keys.iter().any(|slot| !seen.insert(&slot.kid))
}

#[cfg(test)]
#[path = "keyring_tests.rs"]
mod tests;

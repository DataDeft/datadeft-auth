//! Optional construction-time audience separation for purpose-derived rings.

use core::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::{BrancaKey, KEY_BYTES, KeyPurpose, KeyRing, KeySlot};
use crate::TokenError;

const AUDIENCE_KEY_DOMAIN: &[u8] = b"datadeft-auth/keyring-audience-v1";

/// A trusted startup audience identifier, not a value accepted from a cookie.
///
/// Identifiers are exact, case-sensitive ASCII, 1..=128 bytes, restricted to
/// letters, digits and `-._:/`. No trimming or normalization is performed.
/// Audience names are configuration, not credentials; Debug still redacts them.
#[derive(Clone, Eq, PartialEq)]
pub struct Audience(String);

impl Audience {
    /// Validate an audience identifier. Invalid input is a setup error.
    pub fn parse(value: &str) -> Result<Self, TokenError> {
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':' | b'/')
            })
        {
            return Err(TokenError::KeyringMisconfigured);
        }
        Ok(Self(value.to_owned()))
    }

    /// Exact configured value. Never use it as an authorization decision.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Audience(..)")
    }
}

impl<P: KeyPurpose> KeyRing<P> {
    /// Build a ring with every slot bound to one startup audience.
    ///
    /// HKDF-SHA256 derives a new key per purpose, kid and exact audience
    /// before returning the validated ring. No partially scoped ring is exposed,
    /// and there is no post-construction rebinding operation. Both active and
    /// verify-only slots keep their status/windows,
    /// and ring validation is exactly [`KeyRing::new`]'s. Verification never
    /// tries unscoped or other-audience keys: a wrong scope fails the
    /// existing AEAD tag check, not a string comparison after decode.
    ///
    /// Enabling/changing the audience invalidates old cookies. Configure the
    /// same scope on mint, validation, refresh and logout on every node. This
    /// isolates cookie use, not holders of the shared root secret, and does not
    /// replace authorization. It does not change the token/storage wire format.
    pub fn new_with_audience(
        keys: Vec<KeySlot<P>>,
        audience: &Audience,
    ) -> Result<Self, TokenError> {
        let mut ring = Self::new(keys)?;
        for slot in &mut ring.keys {
            slot.key = scoped_key(slot, audience)?;
        }
        Ok(ring)
    }
}

fn scoped_key<P: KeyPurpose>(
    slot: &KeySlot<P>,
    audience: &Audience,
) -> Result<BrancaKey<P>, TokenError> {
    let mut info = AUDIENCE_KEY_DOMAIN.to_vec();
    // Fixed-width big-endian lengths prevent field-boundary ambiguity, even
    // for application-owned purposes. All inputs here are public configuration.
    for field in [
        P::HKDF_INFO,
        slot.kid.as_str().as_bytes(),
        audience.as_str().as_bytes(),
    ] {
        let length = u64::try_from(field.len()).map_err(|_| TokenError::KeyringMisconfigured)?;
        info.extend_from_slice(&length.to_be_bytes());
        info.extend_from_slice(field);
    }
    let mut out = [0u8; KEY_BYTES];
    if Hkdf::<Sha256>::new(None, slot.key.as_bytes())
        .expand(&info, &mut out)
        .is_err()
    {
        out.zeroize();
        return Err(TokenError::Internal);
    }
    let key = BrancaKey::new(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
#[path = "audience_tests.rs"]
mod tests;

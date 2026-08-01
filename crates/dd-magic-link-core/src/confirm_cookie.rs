//! Purpose-separated encrypted state for scanner-safe magic-link confirmation.
//!
//! Built on the generic bound-cookie primitives in `dd-auth-token-core`. This
//! module carries only fixed-size, keyed bindings. It never carries a raw
//! magic-link token, selector, verifier, or account identifier. The
//! caller derives the bindings, supplies the current time and an injected CSPRNG,
//! and caps the explicit expiry by the remaining magic-link lifetime.

use core::fmt;
use core::marker::PhantomData;

use dd_auth_token_core::TokenError;
use dd_auth_token_core::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use dd_auth_token_core::keyring::{KeyPurpose, KeyRing};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::magic_link::is_lower_hex_len;

/// HKDF-SHA256 info string for magic-link confirm-cookie Branca keys.
pub const HKDF_INFO_MAGIC_LINK_CONFIRM_COOKIE_V1: &[u8] = b"auth/magic-link-confirm-v1";
/// Encrypted payload `typ` for magic-link confirm cookies.
pub const TOKEN_TYPE_MAGIC_LINK_CONFIRM_COOKIE_V1: &str = "ml-confirm-v1";

/// Short-lived magic-link confirmation cookie key purpose.
///
/// Owned here: next to the flow that uses it: so the five-minute policy and
/// the versioned derivation constants live with the feature, not in the
/// generic token crate.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkConfirmCookie {}

impl KeyPurpose for MagicLinkConfirmCookie {
    const HKDF_INFO: &'static [u8] = HKDF_INFO_MAGIC_LINK_CONFIRM_COOKIE_V1;
    const TOKEN_TYPE: &'static str = TOKEN_TYPE_MAGIC_LINK_CONFIRM_COOKIE_V1;
    const MAX_BODY_BYTES: usize = 256;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 5 * 60;
}

/// Hard maximum age for a magic-link confirm cookie: five minutes.
pub const MAGIC_LINK_CONFIRM_MAX_AGE_SECS: u64 = MagicLinkConfirmCookie::MAX_ABSOLUTE_AGE_SECS;
/// Size of each keyed selector, verifier, and account binding.
pub const MAGIC_LINK_CONFIRM_BINDING_BYTES: usize = 32;
/// Entropy bytes in the confirmation nonce submitted separately from the cookie.
const MAGIC_LINK_CONFIRM_NONCE_BYTES: usize = 32;

const CONFIRM_BODY_V1: u8 = 1;
const CONFIRMATION_HEX_BYTES: usize = MAGIC_LINK_CONFIRM_NONCE_BYTES * 2;
const CONFIRM_BODY_BYTES: usize = 133;

/// Role marker giving each confirm binding a distinct type and redacted `Debug`
/// name. The roles exist so selector, verifier, and account bindings cannot be
/// interchanged: the same marker-type pattern as `KeyPurpose`.
pub trait ConfirmBindingRole {
    /// Redacted `Debug` rendering for this role's binding.
    const DEBUG_NAME: &'static str;
}

/// Role of the keyed selector identity binding.
#[derive(Debug)]
pub enum SelectorBindingRole {}

impl ConfirmBindingRole for SelectorBindingRole {
    const DEBUG_NAME: &'static str = "ConfirmSelectorBinding(..)";
}

/// Role of the keyed verifier proof binding.
#[derive(Debug)]
pub enum VerifierBindingRole {}

impl ConfirmBindingRole for VerifierBindingRole {
    const DEBUG_NAME: &'static str = "ConfirmVerifierBinding(..)";
}

/// Role of the keyed intended-account identity binding.
#[derive(Debug)]
pub enum AccountBindingRole {}

impl ConfirmBindingRole for AccountBindingRole {
    const DEBUG_NAME: &'static str = "ConfirmAccountBinding(..)";
}

/// Keyed 256-bit value bound into a magic-link confirmation flow, typed by
/// [`ConfirmBindingRole`] so the three binding kinds cannot be interchanged.
/// The bytes zeroize on drop. The `Debug` impl redacts each role.
pub struct ConfirmBinding<Role: ConfirmBindingRole> {
    bytes: [u8; MAGIC_LINK_CONFIRM_BINDING_BYTES],
    _role: PhantomData<Role>,
}

/// Keyed selector identity bound into a magic-link confirmation flow.
pub type ConfirmSelectorBinding = ConfirmBinding<SelectorBindingRole>;
/// Keyed verifier proof bound into a magic-link confirmation flow.
pub type ConfirmVerifierBinding = ConfirmBinding<VerifierBindingRole>;
/// Keyed intended-account identity bound into a magic-link confirmation flow.
pub type ConfirmAccountBinding = ConfirmBinding<AccountBindingRole>;

impl<Role: ConfirmBindingRole> ConfirmBinding<Role> {
    /// Wrap a purpose-separated 256-bit binding.
    #[must_use]
    pub fn new(bytes: [u8; MAGIC_LINK_CONFIRM_BINDING_BYTES]) -> Self {
        Self {
            bytes,
            _role: PhantomData,
        }
    }

    /// Compare two same-role bindings in constant time.
    #[must_use]
    pub fn matches_constant_time(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).unwrap_u8() == 1
    }

    /// Borrow the sensitive binding bytes to rebuild the canonical storage
    /// form. Do not log or compare these bytes directly.
    #[must_use]
    pub(crate) fn as_sensitive_bytes(&self) -> &[u8; MAGIC_LINK_CONFIRM_BINDING_BYTES] {
        &self.bytes
    }
}

impl<Role: ConfirmBindingRole> Drop for ConfirmBinding<Role> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<Role: ConfirmBindingRole> fmt::Debug for ConfirmBinding<Role> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Role::DEBUG_NAME)
    }
}

/// Bindings and explicit expiry used to mint one confirmation flow.
pub struct MagicLinkConfirmBindings {
    selector: ConfirmSelectorBinding,
    verifier: ConfirmVerifierBinding,
    account: ConfirmAccountBinding,
    expires_at_unix: u32,
}

impl MagicLinkConfirmBindings {
    /// Construct complete state for a new confirm cookie.
    #[must_use]
    pub fn new(
        selector: ConfirmSelectorBinding,
        verifier: ConfirmVerifierBinding,
        account: ConfirmAccountBinding,
        expires_at_unix: u32,
    ) -> Self {
        Self {
            selector,
            verifier,
            account,
            expires_at_unix,
        }
    }
}

impl fmt::Debug for MagicLinkConfirmBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkConfirmBindings(..)")
    }
}

/// Opaque encrypted cookie value. `Debug` is always redacted.
pub struct MagicLinkConfirmCookieValue(String);

impl MagicLinkConfirmCookieValue {
    /// Borrow the opaque bearer value for a secure cookie header.
    #[must_use]
    pub fn as_secret_value(&self) -> &str {
        &self.0
    }
}

impl Drop for MagicLinkConfirmCookieValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for MagicLinkConfirmCookieValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkConfirmCookieValue(..)")
    }
}

/// Canonical lowercase-hex confirmation value rendered into the same-origin POST.
pub struct MagicLinkConfirmationValue(String);

impl MagicLinkConfirmationValue {
    /// Borrow the canonical 64-character lowercase-hex value.
    #[must_use]
    pub fn as_value(&self) -> &str {
        &self.0
    }
}

impl Drop for MagicLinkConfirmationValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for MagicLinkConfirmationValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkConfirmationValue(..)")
    }
}

/// Cookie and separate confirmation value minted for one scanner-safe flow.
pub struct MintedMagicLinkConfirm {
    cookie: MagicLinkConfirmCookieValue,
    confirmation: MagicLinkConfirmationValue,
}

impl MintedMagicLinkConfirm {
    /// Opaque encrypted confirm cookie.
    #[must_use]
    pub fn cookie(&self) -> &MagicLinkConfirmCookieValue {
        &self.cookie
    }

    /// Separate confirmation nonce to submit from the same-origin page.
    #[must_use]
    pub fn confirmation(&self) -> &MagicLinkConfirmationValue {
        &self.confirmation
    }
}

impl fmt::Debug for MintedMagicLinkConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MintedMagicLinkConfirm(..)")
    }
}

/// Authenticated, fresh bindings recovered from a confirm cookie.
pub struct VerifiedMagicLinkConfirm {
    selector: ConfirmSelectorBinding,
    verifier: ConfirmVerifierBinding,
    account: ConfirmAccountBinding,
    expires_at_unix: u32,
}

impl VerifiedMagicLinkConfirm {
    /// Authenticated keyed selector binding.
    #[must_use]
    pub fn selector(&self) -> &ConfirmSelectorBinding {
        &self.selector
    }

    /// Authenticated keyed verifier binding.
    #[must_use]
    pub fn verifier(&self) -> &ConfirmVerifierBinding {
        &self.verifier
    }

    /// Authenticated keyed account binding.
    #[must_use]
    pub fn account(&self) -> &ConfirmAccountBinding {
        &self.account
    }

    /// Authenticated explicit expiry. The verification call has already enforced it.
    #[must_use]
    pub fn expires_at_unix(&self) -> u32 {
        self.expires_at_unix
    }
}

impl fmt::Debug for VerifiedMagicLinkConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedMagicLinkConfirm(..)")
    }
}

/// Mint a five-minute-or-shorter encrypted magic-link confirmation flow.
///
/// `expires_at_unix` may equal `now_unix`, but cannot be earlier or more than
/// five minutes later. The caller must additionally cap it to the backing
/// magic-link record's expiry. Minting draws an independent 256-bit confirmation
/// nonce before the Branca nonce, both from the injected CSPRNG.
pub fn mint_magic_link_confirm<R>(
    bindings: MagicLinkConfirmBindings,
    keyring: &KeyRing<MagicLinkConfirmCookie>,
    rng: &mut R,
    now_unix: u64,
) -> Result<MintedMagicLinkConfirm, TokenError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    let now_u32 = u32::try_from(now_unix).map_err(|_| TokenError::InvalidTimestamp)?;
    let latest_expiry = now_unix
        .checked_add(MAGIC_LINK_CONFIRM_MAX_AGE_SECS)
        .ok_or(TokenError::InvalidTimestamp)?;
    let expires_at = u64::from(bindings.expires_at_unix);
    if expires_at < now_unix || expires_at > latest_expiry {
        return Err(TokenError::InvalidTimestamp);
    }

    let mut confirmation_bytes = [0u8; MAGIC_LINK_CONFIRM_NONCE_BYTES];
    if rng.try_fill_bytes(&mut confirmation_bytes).is_err() {
        confirmation_bytes.zeroize();
        return Err(TokenError::EntropyUnavailable);
    }
    let confirmation_nonce = MagicLinkConfirmNonce(confirmation_bytes);
    confirmation_bytes.zeroize();

    let mut body = encode_confirm_body(&bindings, &confirmation_nonce);
    let cookie = mint_bound_cookie::<MagicLinkConfirmCookie, _>(
        &body, keyring, rng, now_u32, now_u32, now_unix,
    );
    body.zeroize();
    let cookie = cookie?;

    Ok(MintedMagicLinkConfirm {
        cookie: MagicLinkConfirmCookieValue(cookie),
        confirmation: MagicLinkConfirmationValue(hex::encode(&confirmation_nonce.0)),
    })
}

/// Verify an encrypted confirm cookie and its separately submitted confirmation value.
///
/// The caller must state a nonzero maximum age no greater than five minutes.
/// Cookie age, authenticated explicit expiry, canonical confirmation syntax, and
/// confirmation equality are enforced together. Every verification failure is
/// collapsed to [`TokenError::InvalidToken`].
pub fn verify_magic_link_confirm(
    cookie_value: &str,
    confirmation_value: &str,
    keyring: &KeyRing<MagicLinkConfirmCookie>,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<VerifiedMagicLinkConfirm, TokenError> {
    if max_age_secs == 0 || max_age_secs > MAGIC_LINK_CONFIRM_MAX_AGE_SECS {
        return Err(TokenError::InvalidToken);
    }

    let submitted_confirmation =
        parse_confirmation(confirmation_value).map_err(|_| TokenError::InvalidToken)?;
    let verified = parse_bound_cookie::<MagicLinkConfirmCookie>(
        cookie_value,
        keyring,
        now_unix,
        MaxAge::fixed(max_age_secs),
    )
    .map_err(|_| TokenError::InvalidToken)?;
    let decoded = decode_confirm_body(verified.body()).map_err(|_| TokenError::InvalidToken)?;

    let expires_at = u64::from(decoded.expires_at_unix);
    let iat = u64::from(verified.iat());
    let confirmation_matches = decoded
        .confirmation
        .matches_constant_time(&submitted_confirmation);
    if expires_at < iat
        || now_unix > expires_at
        || expires_at > iat.saturating_add(max_age_secs)
        || !confirmation_matches
    {
        return Err(TokenError::InvalidToken);
    }

    Ok(VerifiedMagicLinkConfirm {
        selector: decoded.selector,
        verifier: decoded.verifier,
        account: decoded.account,
        expires_at_unix: decoded.expires_at_unix,
    })
}

struct MagicLinkConfirmNonce([u8; MAGIC_LINK_CONFIRM_NONCE_BYTES]);

impl MagicLinkConfirmNonce {
    fn matches_constant_time(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

impl Drop for MagicLinkConfirmNonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for MagicLinkConfirmNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkConfirmNonce(..)")
    }
}

struct DecodedConfirmBody {
    selector: ConfirmSelectorBinding,
    verifier: ConfirmVerifierBinding,
    account: ConfirmAccountBinding,
    confirmation: MagicLinkConfirmNonce,
    expires_at_unix: u32,
}

fn encode_confirm_body(
    bindings: &MagicLinkConfirmBindings,
    confirmation: &MagicLinkConfirmNonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONFIRM_BODY_BYTES);
    out.push(CONFIRM_BODY_V1);
    out.extend_from_slice(&bindings.selector.bytes);
    out.extend_from_slice(&bindings.verifier.bytes);
    out.extend_from_slice(&bindings.account.bytes);
    out.extend_from_slice(&confirmation.0);
    out.extend_from_slice(&bindings.expires_at_unix.to_be_bytes());
    out
}

fn decode_confirm_body(body: &[u8]) -> Result<DecodedConfirmBody, TokenError> {
    if body.len() != CONFIRM_BODY_BYTES || body[0] != CONFIRM_BODY_V1 {
        return Err(TokenError::InvalidToken);
    }

    let mut offset = 1usize;
    let selector = ConfirmSelectorBinding::new(take_array(body, &mut offset)?);
    let verifier = ConfirmVerifierBinding::new(take_array(body, &mut offset)?);
    let account = ConfirmAccountBinding::new(take_array(body, &mut offset)?);
    let confirmation = MagicLinkConfirmNonce(take_array(body, &mut offset)?);
    let expiry_bytes: [u8; 4] = take_array(body, &mut offset)?;
    if offset != body.len() {
        return Err(TokenError::InvalidToken);
    }

    Ok(DecodedConfirmBody {
        selector,
        verifier,
        account,
        confirmation,
        expires_at_unix: u32::from_be_bytes(expiry_bytes),
    })
}

fn take_array<const N: usize>(body: &[u8], offset: &mut usize) -> Result<[u8; N], TokenError> {
    let end = offset.checked_add(N).ok_or(TokenError::InvalidToken)?;
    let value: [u8; N] = body
        .get(*offset..end)
        .ok_or(TokenError::InvalidToken)?
        .try_into()
        .map_err(|_| TokenError::InvalidToken)?;
    *offset = end;
    Ok(value)
}

fn parse_confirmation(value: &str) -> Result<MagicLinkConfirmNonce, TokenError> {
    // `hex::decode_to_slice` alone would accept uppercase spellings. The
    // canonical-form check must stay charset-strict.
    if !is_lower_hex_len(value, CONFIRMATION_HEX_BYTES) {
        return Err(TokenError::InvalidToken);
    }
    let mut decoded = [0u8; MAGIC_LINK_CONFIRM_NONCE_BYTES];
    if hex::decode_to_slice(value, &mut decoded).is_err() {
        decoded.zeroize();
        return Err(TokenError::InvalidToken);
    }
    let nonce = MagicLinkConfirmNonce(decoded);
    decoded.zeroize();
    Ok(nonce)
}

#[cfg(test)]
#[path = "confirm_cookie_tests.rs"]
mod tests;

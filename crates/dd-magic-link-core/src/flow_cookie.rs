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

/// HKDF-SHA256 info string for magic-link flow-cookie Branca keys.
pub const HKDF_INFO_MAGIC_LINK_FLOW_COOKIE_V1: &[u8] = b"auth/magic-link-flow-v1";
/// Encrypted payload `typ` for magic-link flow cookies.
pub const TOKEN_TYPE_MAGIC_LINK_FLOW_COOKIE_V1: &str = "ml-flow-v1";

/// Short-lived magic-link confirmation flow-cookie key purpose.
///
/// Owned here — next to the flow that uses it — so the five-minute policy and
/// the versioned derivation constants live with the feature, not in the
/// generic token crate.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkFlowCookie {}

impl KeyPurpose for MagicLinkFlowCookie {
    const HKDF_INFO: &'static [u8] = HKDF_INFO_MAGIC_LINK_FLOW_COOKIE_V1;
    const TOKEN_TYPE: &'static str = TOKEN_TYPE_MAGIC_LINK_FLOW_COOKIE_V1;
    const MAX_BODY_BYTES: usize = 256;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 5 * 60;
}

/// Hard maximum age for a magic-link flow cookie: five minutes.
pub const MAGIC_LINK_FLOW_MAX_AGE_SECS: u64 = MagicLinkFlowCookie::MAX_ABSOLUTE_AGE_SECS;
/// Size of each keyed selector, verifier, and account binding.
pub const MAGIC_LINK_FLOW_BINDING_BYTES: usize = 32;
/// Entropy bytes in the confirmation nonce submitted separately from the cookie.
const MAGIC_LINK_FLOW_NONCE_BYTES: usize = 32;

const FLOW_BODY_V1: u8 = 1;
const CONFIRMATION_HEX_BYTES: usize = MAGIC_LINK_FLOW_NONCE_BYTES * 2;
const FLOW_BODY_BYTES: usize = 133;

/// Role marker giving each flow binding a distinct type and redacted `Debug`
/// name. The roles exist so selector, verifier, and account bindings cannot be
/// interchanged — the same marker-type pattern as `KeyPurpose`.
pub trait FlowBindingRole {
    /// Redacted `Debug` rendering for this role's binding.
    const DEBUG_NAME: &'static str;
}

/// Role of the keyed selector identity binding.
#[derive(Debug)]
pub enum SelectorBindingRole {}

impl FlowBindingRole for SelectorBindingRole {
    const DEBUG_NAME: &'static str = "FlowSelectorBinding(..)";
}

/// Role of the keyed verifier proof binding.
#[derive(Debug)]
pub enum VerifierBindingRole {}

impl FlowBindingRole for VerifierBindingRole {
    const DEBUG_NAME: &'static str = "FlowVerifierBinding(..)";
}

/// Role of the keyed intended-account identity binding.
#[derive(Debug)]
pub enum AccountBindingRole {}

impl FlowBindingRole for AccountBindingRole {
    const DEBUG_NAME: &'static str = "FlowAccountBinding(..)";
}

/// Keyed 256-bit value bound into a magic-link confirmation flow, typed by
/// [`FlowBindingRole`] so the three binding kinds cannot be interchanged.
/// The bytes zeroize on drop. The `Debug` impl redacts each role.
pub struct FlowBinding<Role: FlowBindingRole> {
    bytes: [u8; MAGIC_LINK_FLOW_BINDING_BYTES],
    _role: PhantomData<Role>,
}

/// Keyed selector identity bound into a magic-link confirmation flow.
pub type FlowSelectorBinding = FlowBinding<SelectorBindingRole>;
/// Keyed verifier proof bound into a magic-link confirmation flow.
pub type FlowVerifierBinding = FlowBinding<VerifierBindingRole>;
/// Keyed intended-account identity bound into a magic-link confirmation flow.
pub type FlowAccountBinding = FlowBinding<AccountBindingRole>;

impl<Role: FlowBindingRole> FlowBinding<Role> {
    /// Wrap a purpose-separated 256-bit binding.
    #[must_use]
    pub fn new(bytes: [u8; MAGIC_LINK_FLOW_BINDING_BYTES]) -> Self {
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
    pub(crate) fn as_sensitive_bytes(&self) -> &[u8; MAGIC_LINK_FLOW_BINDING_BYTES] {
        &self.bytes
    }
}

impl<Role: FlowBindingRole> Drop for FlowBinding<Role> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<Role: FlowBindingRole> fmt::Debug for FlowBinding<Role> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Role::DEBUG_NAME)
    }
}

/// Bindings and explicit expiry used to mint one confirmation flow.
pub struct MagicLinkFlowBindings {
    selector: FlowSelectorBinding,
    verifier: FlowVerifierBinding,
    account: FlowAccountBinding,
    expires_at_unix: u32,
}

impl MagicLinkFlowBindings {
    /// Construct complete state for a new flow cookie.
    #[must_use]
    pub fn new(
        selector: FlowSelectorBinding,
        verifier: FlowVerifierBinding,
        account: FlowAccountBinding,
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

impl fmt::Debug for MagicLinkFlowBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkFlowBindings(..)")
    }
}

/// Opaque encrypted cookie value. `Debug` is always redacted.
pub struct MagicLinkFlowCookieValue(String);

impl MagicLinkFlowCookieValue {
    /// Borrow the opaque bearer value for a secure cookie header.
    #[must_use]
    pub fn as_secret_value(&self) -> &str {
        &self.0
    }
}

impl Drop for MagicLinkFlowCookieValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for MagicLinkFlowCookieValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkFlowCookieValue(..)")
    }
}

/// Canonical lowercase-hex confirmation value rendered into the same-origin POST.
pub struct MagicLinkFlowConfirmation(String);

impl MagicLinkFlowConfirmation {
    /// Borrow the canonical 64-character lowercase-hex value.
    #[must_use]
    pub fn as_value(&self) -> &str {
        &self.0
    }
}

impl Drop for MagicLinkFlowConfirmation {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for MagicLinkFlowConfirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkFlowConfirmation(..)")
    }
}

/// Cookie and separate confirmation value minted for one scanner-safe flow.
pub struct MintedMagicLinkFlow {
    cookie: MagicLinkFlowCookieValue,
    confirmation: MagicLinkFlowConfirmation,
}

impl MintedMagicLinkFlow {
    /// Opaque encrypted flow cookie.
    #[must_use]
    pub fn cookie(&self) -> &MagicLinkFlowCookieValue {
        &self.cookie
    }

    /// Separate confirmation nonce to submit from the same-origin page.
    #[must_use]
    pub fn confirmation(&self) -> &MagicLinkFlowConfirmation {
        &self.confirmation
    }
}

impl fmt::Debug for MintedMagicLinkFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MintedMagicLinkFlow(..)")
    }
}

/// Authenticated, fresh bindings recovered from a flow cookie.
pub struct VerifiedMagicLinkFlow {
    selector: FlowSelectorBinding,
    verifier: FlowVerifierBinding,
    account: FlowAccountBinding,
    expires_at_unix: u32,
}

impl VerifiedMagicLinkFlow {
    /// Authenticated keyed selector binding.
    #[must_use]
    pub fn selector(&self) -> &FlowSelectorBinding {
        &self.selector
    }

    /// Authenticated keyed verifier binding.
    #[must_use]
    pub fn verifier(&self) -> &FlowVerifierBinding {
        &self.verifier
    }

    /// Authenticated keyed account binding.
    #[must_use]
    pub fn account(&self) -> &FlowAccountBinding {
        &self.account
    }

    /// Authenticated explicit expiry. The verification call has already enforced it.
    #[must_use]
    pub fn expires_at_unix(&self) -> u32 {
        self.expires_at_unix
    }
}

impl fmt::Debug for VerifiedMagicLinkFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedMagicLinkFlow(..)")
    }
}

/// Mint a five-minute-or-shorter encrypted magic-link confirmation flow.
///
/// `expires_at_unix` may equal `now_unix`, but cannot be earlier or more than
/// five minutes later. The caller must additionally cap it to the backing
/// magic-link record's expiry. Minting draws an independent 256-bit confirmation
/// nonce before the Branca nonce, both from the injected CSPRNG.
pub fn mint_magic_link_flow<R>(
    bindings: MagicLinkFlowBindings,
    keyring: &KeyRing<MagicLinkFlowCookie>,
    rng: &mut R,
    now_unix: u64,
) -> Result<MintedMagicLinkFlow, TokenError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    let now_u32 = u32::try_from(now_unix).map_err(|_| TokenError::InvalidTimestamp)?;
    let latest_expiry = now_unix
        .checked_add(MAGIC_LINK_FLOW_MAX_AGE_SECS)
        .ok_or(TokenError::InvalidTimestamp)?;
    let expires_at = u64::from(bindings.expires_at_unix);
    if expires_at < now_unix || expires_at > latest_expiry {
        return Err(TokenError::InvalidTimestamp);
    }

    let mut confirmation_bytes = [0u8; MAGIC_LINK_FLOW_NONCE_BYTES];
    if rng.try_fill_bytes(&mut confirmation_bytes).is_err() {
        confirmation_bytes.zeroize();
        return Err(TokenError::EntropyUnavailable);
    }
    let confirmation_nonce = MagicLinkFlowNonce(confirmation_bytes);
    confirmation_bytes.zeroize();

    let mut body = encode_flow_body(&bindings, &confirmation_nonce);
    let cookie = mint_bound_cookie::<MagicLinkFlowCookie, _>(
        &body, keyring, rng, now_u32, now_u32, now_unix,
    );
    body.zeroize();
    let cookie = cookie?;

    Ok(MintedMagicLinkFlow {
        cookie: MagicLinkFlowCookieValue(cookie),
        confirmation: MagicLinkFlowConfirmation(hex::encode(&confirmation_nonce.0)),
    })
}

/// Verify an encrypted flow cookie and its separately submitted confirmation value.
///
/// The caller must state a nonzero maximum age no greater than five minutes.
/// Cookie age, authenticated explicit expiry, canonical confirmation syntax, and
/// confirmation equality are enforced together. Every verification failure is
/// collapsed to [`TokenError::InvalidToken`].
pub fn verify_magic_link_flow(
    cookie_value: &str,
    confirmation_value: &str,
    keyring: &KeyRing<MagicLinkFlowCookie>,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<VerifiedMagicLinkFlow, TokenError> {
    if max_age_secs == 0 || max_age_secs > MAGIC_LINK_FLOW_MAX_AGE_SECS {
        return Err(TokenError::InvalidToken);
    }

    let submitted_confirmation =
        parse_confirmation(confirmation_value).map_err(|_| TokenError::InvalidToken)?;
    let verified = parse_bound_cookie::<MagicLinkFlowCookie>(
        cookie_value,
        keyring,
        now_unix,
        MaxAge::fixed(max_age_secs),
    )
    .map_err(|_| TokenError::InvalidToken)?;
    let decoded = decode_flow_body(verified.body()).map_err(|_| TokenError::InvalidToken)?;

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

    Ok(VerifiedMagicLinkFlow {
        selector: decoded.selector,
        verifier: decoded.verifier,
        account: decoded.account,
        expires_at_unix: decoded.expires_at_unix,
    })
}

struct MagicLinkFlowNonce([u8; MAGIC_LINK_FLOW_NONCE_BYTES]);

impl MagicLinkFlowNonce {
    fn matches_constant_time(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

impl Drop for MagicLinkFlowNonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for MagicLinkFlowNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkFlowNonce(..)")
    }
}

struct DecodedFlowBody {
    selector: FlowSelectorBinding,
    verifier: FlowVerifierBinding,
    account: FlowAccountBinding,
    confirmation: MagicLinkFlowNonce,
    expires_at_unix: u32,
}

fn encode_flow_body(
    bindings: &MagicLinkFlowBindings,
    confirmation: &MagicLinkFlowNonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FLOW_BODY_BYTES);
    out.push(FLOW_BODY_V1);
    out.extend_from_slice(&bindings.selector.bytes);
    out.extend_from_slice(&bindings.verifier.bytes);
    out.extend_from_slice(&bindings.account.bytes);
    out.extend_from_slice(&confirmation.0);
    out.extend_from_slice(&bindings.expires_at_unix.to_be_bytes());
    out
}

fn decode_flow_body(body: &[u8]) -> Result<DecodedFlowBody, TokenError> {
    if body.len() != FLOW_BODY_BYTES || body[0] != FLOW_BODY_V1 {
        return Err(TokenError::InvalidToken);
    }

    let mut offset = 1usize;
    let selector = FlowSelectorBinding::new(take_array(body, &mut offset)?);
    let verifier = FlowVerifierBinding::new(take_array(body, &mut offset)?);
    let account = FlowAccountBinding::new(take_array(body, &mut offset)?);
    let confirmation = MagicLinkFlowNonce(take_array(body, &mut offset)?);
    let expiry_bytes: [u8; 4] = take_array(body, &mut offset)?;
    if offset != body.len() {
        return Err(TokenError::InvalidToken);
    }

    Ok(DecodedFlowBody {
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

fn parse_confirmation(value: &str) -> Result<MagicLinkFlowNonce, TokenError> {
    // `hex::decode_to_slice` alone would accept uppercase spellings. The
    // canonical-form check must stay charset-strict.
    if !is_lower_hex_len(value, CONFIRMATION_HEX_BYTES) {
        return Err(TokenError::InvalidToken);
    }
    let mut decoded = [0u8; MAGIC_LINK_FLOW_NONCE_BYTES];
    if hex::decode_to_slice(value, &mut decoded).is_err() {
        decoded.zeroize();
        return Err(TokenError::InvalidToken);
    }
    let nonce = MagicLinkFlowNonce(decoded);
    decoded.zeroize();
    Ok(nonce)
}

#[cfg(test)]
#[path = "flow_cookie_tests.rs"]
mod tests;

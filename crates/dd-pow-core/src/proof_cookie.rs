//! `ct_pow` proof cookie: evidence that this browser recently solved a PoW
//! challenge.
//!
//! Minted and verified with the generic bound-cookie primitives in
//! `dd-auth-token-core` — the same Branca/keyring machinery that backs the
//! session and magic-link flow cookies — but under a distinct key purpose
//! (`pow-proof-v1`) so a proof cookie can never validate as a session or flow
//! cookie, and vice versa, even under the same root secret.
//!
//! The payload carries only the replay-safe solve identity [`crate::Verified::tid`]
//! (hex BLAKE3 of the challenge). The cookie is a stateless "recently solved"
//! proof: it stays valid for its whole configured lifetime and is not
//! single-use. The admission layer treats a valid proof cookie as permission
//! to skip re-challenging this browser; it never treats `tid` as a capability.

use core::fmt;

use dd_auth_token_core::TokenError;
use dd_auth_token_core::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use dd_auth_token_core::keyring::{KeyPurpose, KeyRing};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// HKDF-SHA256 info string for PoW proof-cookie Branca keys.
pub const HKDF_INFO_POW_PROOF_COOKIE_V1: &[u8] = b"auth/pow-proof-v1";
/// Encrypted payload `typ` for PoW proof cookies.
pub const TOKEN_TYPE_POW_PROOF_COOKIE_V1: &str = "pow-proof-v1";

/// Hard ceiling on a proof cookie's lifetime: 24 hours. A deployment tunes the
/// runtime lifetime down from here (see [`DEFAULT_POW_PROOF_TTL_SECS`]); it can
/// never validate a proof cookie older than this bound.
pub const POW_PROOF_MAX_AGE_SECS: u64 = 24 * 60 * 60;
/// Documented default proof-cookie lifetime: 3 hours. Matches the shipped
/// `ct_pow` cookie. Override per deployment within `1..=POW_PROOF_MAX_AGE_SECS`.
pub const DEFAULT_POW_PROOF_TTL_SECS: u64 = 3 * 60 * 60;

/// `tid` is `hex(BLAKE3(chg))`: exactly 64 lowercase hex characters.
const TID_HEX_LEN: usize = 64;
/// Raw BLAKE3 digest bytes carried in the payload.
const TID_BYTES: usize = 32;

const POW_PROOF_BODY_V1: u8 = 1;
const POW_PROOF_BODY_BYTES: usize = 1 + TID_BYTES;

/// PoW proof-cookie key purpose.
///
/// Owned here — next to the challenge/verify logic it protects — so the
/// versioned derivation constants and the lifetime ceiling live with the
/// feature, not in the generic token crate.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PowProofCookie {}

impl KeyPurpose for PowProofCookie {
    const HKDF_INFO: &'static [u8] = HKDF_INFO_POW_PROOF_COOKIE_V1;
    const TOKEN_TYPE: &'static str = TOKEN_TYPE_POW_PROOF_COOKIE_V1;
    const MAX_BODY_BYTES: usize = 64;
    const MAX_ABSOLUTE_AGE_SECS: u64 = POW_PROOF_MAX_AGE_SECS;
}

/// Opaque encrypted proof-cookie value. `Debug` is always redacted.
pub struct PowProofCookieValue(String);

impl PowProofCookieValue {
    /// Borrow the opaque bearer value for a secure cookie header.
    #[must_use]
    pub fn as_secret_value(&self) -> &str {
        &self.0
    }
}

impl Drop for PowProofCookieValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PowProofCookieValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PowProofCookieValue(..)")
    }
}

/// Authenticated solve identity recovered from a proof cookie.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedPowProof {
    tid: String,
}

impl VerifiedPowProof {
    /// The replay-safe solve identity: 64 lowercase hex characters. Derived
    /// from public challenge inputs, so it is an identity, never a capability.
    #[must_use]
    pub fn tid(&self) -> &str {
        &self.tid
    }
}

impl fmt::Debug for VerifiedPowProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPowProof(..)")
    }
}

/// `tid` must be exactly 64 lowercase hex characters.
fn is_valid_tid(value: &str) -> bool {
    value.len() == TID_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Mint an encrypted `ct_pow` proof cookie for a verified solve identity.
///
/// The lifetime is enforced at verification time from the caller's configured
/// max age, so minting only stamps the current time. Fails closed if `tid` is
/// not a canonical 64-character lowercase-hex value.
pub fn mint_pow_proof_cookie<R>(
    tid: &str,
    keyring: &KeyRing<PowProofCookie>,
    rng: &mut R,
    now_unix: u64,
) -> Result<PowProofCookieValue, TokenError>
where
    R: RngCore + CryptoRng + ?Sized,
{
    if !is_valid_tid(tid) {
        return Err(TokenError::InvalidToken);
    }
    let now_u32 = u32::try_from(now_unix).map_err(|_| TokenError::InvalidTimestamp)?;

    let mut tid_bytes = [0u8; TID_BYTES];
    hex::decode_to_slice(tid, &mut tid_bytes).map_err(|_| TokenError::InvalidToken)?;
    let mut body = Vec::with_capacity(POW_PROOF_BODY_BYTES);
    body.push(POW_PROOF_BODY_V1);
    body.extend_from_slice(&tid_bytes);
    tid_bytes.zeroize();

    let cookie =
        mint_bound_cookie::<PowProofCookie, _>(&body, keyring, rng, now_u32, now_u32, now_unix);
    body.zeroize();

    Ok(PowProofCookieValue(cookie?))
}

/// Verify a `ct_pow` proof-cookie value and recover the solve identity.
///
/// `max_age_secs` is the deployment's configured lifetime and must be in
/// `1..=POW_PROOF_MAX_AGE_SECS`. Both freshness bounds (last activity and first
/// issue) are enforced against it. Every failure collapses to
/// [`TokenError::InvalidToken`] so nothing leaks which check failed.
pub fn verify_pow_proof_cookie(
    cookie_value: &str,
    keyring: &KeyRing<PowProofCookie>,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<VerifiedPowProof, TokenError> {
    if max_age_secs == 0 || max_age_secs > POW_PROOF_MAX_AGE_SECS {
        return Err(TokenError::InvalidToken);
    }

    let verified = parse_bound_cookie::<PowProofCookie>(
        cookie_value,
        keyring,
        now_unix,
        MaxAge::fixed(max_age_secs),
    )
    .map_err(|_| TokenError::InvalidToken)?;

    let body = verified.body();
    if body.len() != POW_PROOF_BODY_BYTES || body[0] != POW_PROOF_BODY_V1 {
        return Err(TokenError::InvalidToken);
    }
    let tid = hex::encode(&body[1..]);

    Ok(VerifiedPowProof { tid })
}

#[cfg(test)]
#[path = "proof_cookie_tests.rs"]
mod tests;

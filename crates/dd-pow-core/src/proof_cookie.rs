//! `dd_pow` proof cookie: evidence that this browser recently solved a PoW
//! challenge.
//!
//! Minted and verified with the generic bound-cookie primitives in
//! `dd-auth-token-core`: the same Branca/keyring machinery that backs the
//! session and magic-link confirm cookies: but under a distinct key purpose
//! (`pow-proof-v1`) so a proof cookie can never validate as a session or flow
//! cookie, and vice versa, even under the same root secret.
//!
//! The payload carries the replay-safe solve identity [`crate::Verified::tid`]
//! (hex BLAKE3 of the challenge) and, in the v2 body, one optional
//! app-supplied solve-class byte (typically a quantized
//! [`crate::Verified::mint_to_verify_ms`]). The library assigns the byte no
//! meaning: classification policy stays in the app, the cookie only carries
//! it statelessly to later gate checks. The cookie is a stateless "recently
//! solved" proof: it stays valid for its whole configured lifetime and is not
//! single-use. The admission layer treats a valid proof cookie as permission
//! to skip re-challenging this browser. It never treats `tid` as a capability.

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
/// runtime lifetime down from here (see [`DEFAULT_POW_PROOF_TTL_SECS`]). It can
/// never validate a proof cookie older than this bound.
pub const POW_PROOF_MAX_AGE_SECS: u64 = 24 * 60 * 60;
/// Documented default proof-cookie lifetime: 3 hours. Matches the shipped
/// `dd_pow` cookie. Override per deployment within `1..=POW_PROOF_MAX_AGE_SECS`.
pub const DEFAULT_POW_PROOF_TTL_SECS: u64 = 3 * 60 * 60;

/// `tid` is `hex(BLAKE3(chg))`: exactly 64 lowercase hex characters.
const TID_HEX_LEN: usize = 64;
/// Raw BLAKE3 digest bytes carried in the payload.
const TID_BYTES: usize = 32;

const POW_PROOF_BODY_V1: u8 = 1;
const POW_PROOF_BODY_V2: u8 = 2;
const POW_PROOF_BODY_V1_BYTES: usize = 1 + TID_BYTES;
const POW_PROOF_BODY_V2_BYTES: usize = POW_PROOF_BODY_V1_BYTES + 1;

/// PoW proof-cookie key purpose.
///
/// Owned here: next to the challenge/verify logic it protects: so the
/// versioned derivation constants and the lifetime ceiling live with the
/// feature, not in the generic token crate.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PowProofCookie {}

impl KeyPurpose for PowProofCookie {
    const HKDF_INFO: &'static [u8] = HKDF_INFO_POW_PROOF_COOKIE_V1;
    const TOKEN_TYPE: &'static str = TOKEN_TYPE_POW_PROOF_COOKIE_V1;
    // The budget covers payload framing (7 bytes), the 12-byte `typ`, the
    // kid, and the body. At 64, the 34-byte v2 body squeezed the kid budget
    // from 12 bytes (the v1 contract, relied on by deployments) down to 11;
    // 65 restores it. v2 body (34) + framing (7) + typ (12) + kid (12) = 65.
    const MAX_BODY_BYTES: usize = 65;
    const MAX_ABSOLUTE_AGE_SECS: u64 = POW_PROOF_MAX_AGE_SECS;
}

/// Opaque encrypted proof-cookie value. The `Debug` impl always redacts it.
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
    solve_class: Option<u8>,
}

impl VerifiedPowProof {
    /// The replay-safe solve identity: 64 lowercase hex characters. Derived
    /// from public challenge inputs, so it is an identity, never a capability.
    #[must_use]
    pub fn tid(&self) -> &str {
        &self.tid
    }

    /// The app-supplied solve-class byte stamped at mint, or `None` for a v1
    /// cookie minted without one. Authenticated: it is inside the encrypted
    /// body, so a client cannot alter it. The library assigns it no meaning;
    /// the minting app defines the quantization and the reading app the
    /// policy.
    #[must_use]
    pub fn solve_class(&self) -> Option<u8> {
        self.solve_class
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

/// Mint an encrypted `dd_pow` proof cookie for a verified solve identity.
///
/// `solve_class` is an optional opaque app-defined byte (typically a
/// quantized [`crate::Verified::mint_to_verify_ms`]) carried inside the
/// encrypted body. `None` mints the v1 body, byte-identical to cookies minted
/// before the field existed; `Some` mints the versioned v2 body. The library
/// assigns the byte no meaning.
///
/// Verification enforces the lifetime from the caller's configured max age, so
/// minting only stamps the current time. Fails closed if `tid` is not a
/// canonical 64-character lowercase-hex value.
pub fn mint_pow_proof_cookie<R>(
    tid: &str,
    solve_class: Option<u8>,
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
    let mut body = Vec::with_capacity(POW_PROOF_BODY_V2_BYTES);
    body.push(match solve_class {
        None => POW_PROOF_BODY_V1,
        Some(_) => POW_PROOF_BODY_V2,
    });
    body.extend_from_slice(&tid_bytes);
    if let Some(class) = solve_class {
        body.push(class);
    }
    tid_bytes.zeroize();

    let cookie =
        mint_bound_cookie::<PowProofCookie, _>(&body, keyring, rng, now_u32, now_u32, now_unix);
    body.zeroize();

    Ok(PowProofCookieValue(cookie?))
}

/// Verify a `dd_pow` proof-cookie value and recover the solve identity.
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

    // Exact version/length pairing: a v1 tag with a trailing byte or a v2
    // tag without one is malformed, not "close enough".
    let body = verified.body();
    let (tid_bytes, solve_class) = match (body.first(), body.len()) {
        (Some(&POW_PROOF_BODY_V1), POW_PROOF_BODY_V1_BYTES) => (&body[1..], None),
        (Some(&POW_PROOF_BODY_V2), POW_PROOF_BODY_V2_BYTES) => {
            (&body[1..=TID_BYTES], Some(body[1 + TID_BYTES]))
        }
        _ => return Err(TokenError::InvalidToken),
    };
    let tid = hex::encode(tid_bytes);

    Ok(VerifiedPowProof { tid, solve_class })
}

#[cfg(test)]
#[path = "proof_cookie_tests.rs"]
mod tests;

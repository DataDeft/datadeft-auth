//! Branca v1 tokens — authenticated encryption over arbitrary payloads.
//!
//! Wire format:
//! ```text
//! Version(1B = 0xBA) || Timestamp(4B, BE) || Nonce(24B) || Ciphertext(*B) || Tag(16B)
//! ```
//! The whole binary blob is base62-encoded (see [`crate::base62`]). The
//! 29-byte header (version + timestamp + nonce) is bound as AEAD additional
//! data, so a tampered timestamp or nonce fails decryption.
//!
//! # Determinism
//!
//! [`encode`] does NOT generate the nonce. The caller supplies a 24-byte
//! nonce, which for production MUST come from an OS CSPRNG. This keeps the
//! crate IO-free and matches the entropy-injection pattern used by the other
//! core crates in this workspace.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use subtle::ConstantTimeEq;

use crate::base62;
use crate::error::TokenError;

/// Branca magic version byte.
pub const VERSION: u8 = 0xBA;
/// Required Branca key length.
pub const KEY_BYTES: usize = 32;
/// Required XChaCha20 nonce length.
pub const NONCE_BYTES: usize = 24;
const HEADER_BYTES: usize = 1 + 4 + NONCE_BYTES; // 29
const TAG_BYTES: usize = 16;
/// Encode-side payload guard: a Branca token encrypts a small JSON payload,
/// not arbitrary blobs. Caps work on the auth hot path.
pub const MAX_PAYLOAD_BYTES: usize = 1024;
/// Decode-side guard on the base62 token string.
pub const MAX_TOKEN_BYTES: usize = 2048;

/// String-independent identity of a Branca token, for revocation / replay /
/// dedup keys.
///
/// Wraps the token's 24-byte nonce, which lives in the AEAD-authenticated header
/// rather than in the mutable base62 spelling. Every encoding of a given token —
/// including non-canonical, zero-prefixed forms — therefore maps to the *same*
/// `Jti`. Revocation lists, replay caches, and rate-limit rows MUST key on this,
/// never on the raw token string: type such stores as `Set<Jti>` / `Map<Jti, _>`
/// so a caller cannot accidentally key on the malleable string.
///
/// This holds even without the canonicality gate in [`decode`] — keying on the
/// nonce is the primary defense; the parser gate is defense in depth.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Jti([u8; NONCE_BYTES]);

impl Jti {
    /// The raw 24-byte identity bytes (the authenticated token nonce).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for Jti {
    // The nonce is not itself a secret, but keep `Debug` opaque so token-linked
    // identifiers do not leak verbatim into logs (see the logging rules).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Jti(..)")
    }
}

/// A decrypted, authenticated Branca token.
///
/// Returned by [`decode`] instead of a bare tuple so callers key on typed,
/// canonical fields — never on the raw token string, which is not a unique
/// handle for the token (see the malleability note on [`decode`]).
#[derive(Clone)]
pub struct Verified {
    /// Mint time in unix seconds (authenticated as AAD). TTL is the caller's
    /// responsibility; this function performs no clock check.
    pub timestamp: u32,
    /// The 24-byte per-token nonce from the authenticated header. Use
    /// [`Verified::jti`] to key revocation / replay on it.
    pub nonce: [u8; NONCE_BYTES],
    /// Decrypted plaintext payload.
    pub payload: Vec<u8>,
}

impl Verified {
    /// The string-independent token identity, safe as a revocation / replay key.
    #[must_use]
    pub fn jti(&self) -> Jti {
        Jti(self.nonce)
    }
}

impl fmt::Debug for Verified {
    // Redact the payload; it is plaintext and may be secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("timestamp", &self.timestamp)
            .field("jti", &self.jti())
            .field(
                "payload",
                &format_args!("<{} bytes redacted>", self.payload.len()),
            )
            .finish()
    }
}

/// Encrypt `data` into a Branca token string.
///
/// `key` must be exactly 32 bytes and `nonce` exactly 24 bytes. `timestamp` is
/// the mint time in unix seconds (stored big-endian and authenticated as AAD).
/// The nonce is NOT generated here — production callers MUST supply a fresh
/// CSPRNG nonce per token (see the crate-level warning on reuse).
pub fn encode(
    data: &[u8],
    key: &[u8],
    nonce: &[u8; NONCE_BYTES],
    timestamp: u32,
) -> Result<String, TokenError> {
    if data.len() > MAX_PAYLOAD_BYTES {
        return Err(TokenError::PayloadTooLarge);
    }
    if key.len() != KEY_BYTES {
        return Err(TokenError::BadKeyLength);
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    // Header = version || timestamp(BE) || nonce, authenticated as AAD.
    let mut header = [0u8; HEADER_BYTES];
    header[0] = VERSION;
    header[1..5].copy_from_slice(&timestamp.to_be_bytes());
    header[5..29].copy_from_slice(nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: data,
                aad: &header,
            },
        )
        .map_err(|_| TokenError::EncryptFailed)?;

    let mut blob = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&ciphertext);

    Ok(base62::encode(&blob))
}

/// Decrypt a Branca token, returning a [`Verified`] (timestamp, nonce,
/// plaintext) without any clock check. TTL is the caller's responsibility (the
/// cookie layers apply it with an injected `now_unix`), which keeps this
/// function deterministic and IO-free.
///
/// Fails closed with a single coarse [`TokenError`] for every malformed /
/// tampered / wrong-key input so a caller cannot distinguish failure reasons.
///
/// # Canonical tokens only
///
/// base62 is a big-integer encoding, so leading `'0'` digits carry no weight:
/// without a check, `token`, `"0"+token`, `"00"+token`, … would all decode to
/// the same blob and authenticate identically, giving one token unboundedly many
/// valid spellings (token *malleability* — not forgery; the AEAD payload is
/// unchanged). This function rejects every non-canonical spelling so the token
/// string is a unique handle. Prefer keying revocation / replay on
/// [`Verified::jti`] regardless.
pub fn decode(token: &str, key: &[u8]) -> Result<Verified, TokenError> {
    if key.len() != KEY_BYTES {
        return Err(TokenError::BadKeyLength);
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::PayloadTooLarge);
    }

    // Canonicality, cheap reject first: the standard base62 encoder never emits
    // a leading '0' digit (leading zeros are dropped on encode), so a canonical
    // token never starts with '0'. Reject the whole zero-prefixed family before
    // allocating a decode buffer.
    if token.as_bytes().first() == Some(&b'0') {
        return Err(TokenError::InvalidBase62);
    }

    let blob = base62::decode(token).map_err(|_| TokenError::InvalidBase62)?;

    // Canonicality backstop: require the token to be the *unique* base62 spelling
    // of its bytes. Re-encode and demand an exact match. This subsumes the cheap
    // check above and also rejects embedded-newline forms that `base62::decode`
    // otherwise tolerates — neither belongs in a token.
    if base62::encode(&blob) != token {
        return Err(TokenError::InvalidBase62);
    }

    // Header (29) + at least the Poly1305 tag (16). A shorter blob cannot be a
    // well-formed token; reject before touching the AEAD.
    if blob.len() < HEADER_BYTES + TAG_BYTES {
        return Err(TokenError::InvalidBase62);
    }

    // Constant-time version check so a timing signal cannot distinguish
    // "wrong version" from "wrong key".
    if blob[0].ct_eq(&VERSION).unwrap_u8() == 0 {
        return Err(TokenError::InvalidTokenVersion);
    }

    let header = &blob[..HEADER_BYTES];
    let timestamp = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&blob[5..HEADER_BYTES]);
    let ciphertext = &blob[HEADER_BYTES..];

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let payload = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| TokenError::DecryptFailed)?;

    Ok(Verified {
        timestamp,
        nonce,
        payload,
    })
}

#[cfg(test)]
#[path = "branca_tests.rs"]
mod tests;

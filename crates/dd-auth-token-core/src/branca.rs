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
//! [`encode`] draws the 24-byte nonce internally from the caller-supplied
//! [`CryptoRng`]. This is API hygiene, not a proof that callers cannot build a
//! deterministic RNG: `CryptoRng` is a marker trait. Production callers MUST use
//! an OS-backed CSPRNG. Fixed raw nonce bytes are additionally hidden from the
//! default public API; `encode_with_nonce` is available only for crate tests and
//! the explicit `test-support` feature. CI guards that gate so the fixed-nonce
//! helper cannot accidentally enter the default public API.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

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
/// Maximum decoded Branca blob: header + 1 KiB payload ciphertext + tag.
pub const MAX_TOKEN_BLOB_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD_BYTES + TAG_BYTES;
/// Decode-side guard on the base62 token string for [`MAX_PAYLOAD_BYTES`].
pub const MAX_TOKEN_BYTES: usize = 1437;

/// String-independent identity of one Branca token instance.
///
/// Wraps the token's 24-byte nonce, which lives in the AEAD-authenticated header
/// rather than in the mutable base62 spelling. Every accepted spelling of the
/// same token therefore maps to the same `Jti`. Use it for replay/single-use
/// caches where the credential itself is the thing being consumed (magic links,
/// PoW proofs, one-time flow tokens).
///
/// Do **not** use `Jti` as a session revocation key for sliding sessions. A
/// sliding re-mint intentionally produces a fresh nonce and therefore a fresh
/// `Jti`. Session logout/compromise revocation must key on a caller-supplied
/// stable session id inside the encrypted body that survives re-minting.
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

impl Drop for Verified {
    fn drop(&mut self) {
        self.payload.as_mut_slice().zeroize();
    }
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

/// Encrypt `data` into a Branca token string using a nonce drawn from `rng`.
///
/// `key` must be exactly 32 bytes. `timestamp` is the mint time in unix
/// seconds (stored big-endian and authenticated as AAD). Production callers
/// MUST pass an OS-backed CSPRNG. Nonce reuse under the same key is
/// catastrophic. The public API draws nonce bytes internally for hygiene, but
/// callers still control the RNG object; production code must pass a reviewed
/// OS-backed CSPRNG, not a deterministic fixture RNG.
pub fn encode<R: RngCore + CryptoRng + ?Sized>(
    data: &[u8],
    key: &[u8],
    rng: &mut R,
    timestamp: u32,
) -> Result<String, TokenError> {
    let mut nonce = [0u8; NONCE_BYTES];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| TokenError::EntropyUnavailable)?;
    // Input validation happens once, in `encode_with_nonce_inner`, which every
    // encode path funnels through.
    encode_with_nonce_inner(data, key, &nonce, timestamp)
}

/// Encrypt `data` using a caller-supplied nonce.
///
/// This exists for official test vectors and deterministic fixtures only. It
/// is deliberately hidden from the default public API because choosing nonces
/// by hand is a security footgun: XChaCha20-Poly1305 nonce reuse under the same
/// key is catastrophic.
#[cfg(any(test, feature = "test-support"))]
pub fn encode_with_nonce(
    data: &[u8],
    key: &[u8],
    nonce: &[u8; NONCE_BYTES],
    timestamp: u32,
) -> Result<String, TokenError> {
    encode_with_nonce_inner(data, key, nonce, timestamp)
}

fn encode_with_nonce_inner(
    data: &[u8],
    key: &[u8],
    nonce: &[u8; NONCE_BYTES],
    timestamp: u32,
) -> Result<String, TokenError> {
    validate_encode_inputs(data, key)?;

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

fn validate_encode_inputs(data: &[u8], key: &[u8]) -> Result<(), TokenError> {
    if data.len() > MAX_PAYLOAD_BYTES {
        return Err(TokenError::PayloadTooLarge);
    }
    if key.len() != KEY_BYTES {
        return Err(TokenError::BadKeyLength);
    }
    Ok(())
}

/// Upper bound on base62 characters for a Branca token carrying `payload_bytes`
/// bytes of plaintext.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
#[must_use]
pub fn max_token_chars_for_payload(payload_bytes: usize) -> usize {
    let blob_bytes = HEADER_BYTES
        .saturating_add(TAG_BYTES)
        .saturating_add(payload_bytes);
    ((blob_bytes as f64) * (256_f64.ln() / 62_f64.ln())).ceil() as usize
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

    // Header (29) + at least the Poly1305 tag (16), and no more than the
    // configured payload cap.
    if blob.len() < HEADER_BYTES + TAG_BYTES {
        return Err(TokenError::InvalidBase62);
    }
    if blob.len() > MAX_TOKEN_BLOB_BYTES {
        return Err(TokenError::PayloadTooLarge);
    }

    // Canonicality: base62 decoding is many-to-one in exactly two ways —
    // leading '0' digits (rejected above, before decoding) and bytes outside
    // the alphabet, which `base62::decode` rejects rather than skips (embedded
    // newlines included). So every token that reaches this point is already
    // the unique spelling of `blob`; re-encoding to compare would be O(n²)
    // work that can never fail. Debug builds re-verify the equivalence.
    debug_assert_eq!(
        base62::encode(&blob),
        token,
        "accepted token must be the unique canonical spelling of its blob"
    );

    // The version byte is a public constant, not secret, so a plain compare
    // leaks nothing a constant-time compare would hide. The distinct error is
    // kept for logs/tests; the cookie edge funnels it to a generic failure.
    if blob[0] != VERSION {
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

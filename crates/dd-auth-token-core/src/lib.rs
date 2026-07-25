//! `dd-auth-token-core` — reusable token, keyring, and cookie primitives.
//!
//! The crate currently owns the low-level Phase 2 authentication-token building
//! blocks:
//!
//! - [`base62`]: standard `0-9A-Za-z` radix-62 encoding used by Branca tokens,
//!   with token-layer canonicality checks for non-unique integer spellings.
//! - [`branca`]: Branca-compatible XChaCha20-Poly1305 authenticated encryption
//!   over small payloads with caller-injected entropy and canonical decoding.
//! - [`keyring`]: loaded root secrets, HKDF-SHA256 purpose/`kid` derivation,
//!   typed keyrings, active/verify-only rotation windows, and key-material
//!   redaction / best-effort zeroization.
//! - [`cookie`]: `v1.{kid}.{token}` cookie wrappers, fixed binary payload
//!   framing, `typ`/`kid` binding inside the encrypted payload, mandatory idle
//!   and absolute freshness checks, and generic verification failures.
//! - [`TokenError`]: typed errors that do not carry token bytes, cookie values,
//!   key material, or raw identifiers.
//!
//! # Determinism contract
//!
//! Core APIs never read the system clock, environment, filesystem, network, or a
//! random number generator directly. Callers inject `now_unix`, TTLs, loaded key
//! material/keyrings, and RNG objects. Branca minting draws nonce bytes from the
//! caller-supplied [`rand_core::CryptoRng`]; production callers must pass an
//! OS-CSPRNG-backed RNG and never reuse a `(key, nonce)` pair. The marker trait
//! is API hygiene, not runtime enforcement, so deterministic RNGs remain test
//! fixtures only. Fixed raw nonce bytes are hidden behind crate tests / the
//! explicit `test-support` feature and guarded in CI.
//!
//! # Memory hygiene scope
//!
//! Key material wrappers zeroize their in-process byte arrays on drop on a
//! best-effort basis. Cookie-owned plaintext buffers are redacted in `Debug` and
//! zeroized where this crate owns their lifetime, but raw [`branca::Verified`]
//! payloads are ordinary `Vec<u8>` values returned to callers; callers that put
//! session identifiers or other sensitive plaintext there own any additional
//! zeroization policy.

#![forbid(unsafe_code)]

pub mod base62;
pub mod branca;
pub mod cookie;
pub mod error;
pub mod keyring;

pub use error::TokenError;

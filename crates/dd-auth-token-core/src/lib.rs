//! `dd-auth-token-core` — reusable base62 and Branca token primitives.
//!
//! This first Phase 2 packet intentionally contains only the low-level token
//! building blocks:
//!
//! - [`base62`]: standard `0-9A-Za-z` radix-62 encoding used by Branca tokens.
//! - [`branca`]: Branca-compatible XChaCha20-Poly1305 authenticated encryption.
//! - [`TokenError`]: coarse typed errors that do not carry token bytes or key
//!   material.
//!
//! # Determinism contract
//!
//! Core APIs never read the system clock, environment, filesystem, network, or
//! a random number generator directly. Branca minting takes a caller-supplied
//! [`rand_core::CryptoRng`] and draws the nonce internally; production callers
//! MUST pass an OS-CSPRNG-backed RNG and never reuse a `(key, nonce)` pair.
//! Fixed-nonce encoding is hidden behind tests / the explicit `test-support`
//! feature for official vectors only.
//!
//! Cookie wrappers, keyrings, session IDs, and PoW proof cookies are deliberately
//! out of scope for this packet.

#![forbid(unsafe_code)]

pub mod base62;
pub mod branca;
pub mod error;

pub use error::TokenError;

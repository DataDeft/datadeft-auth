#![forbid(unsafe_code)]

//! `dd-pow-core` — pure, IO-free proof-of-work challenge mint/verify.
//!
//! Deterministic: the caller injects clock, entropy, difficulty, max age, and
//! secret. This crate never logs, never reads the clock, and never generates
//! randomness, so every function is fully testable.
//!
//! # Wire contract
//!
//! The browser client and this crate must agree byte-for-byte:
//!
//! - Challenge JSON: `{ chg, dif, tim, tag }`.
//! - Solution JSON as the client posts it: `{ chg, sol, non, tim, tag }`.
//!   The client does **not** echo `dif`. The API layer must fill
//!   [`Solution::dif`] with the server's current difficulty — the HMAC tag
//!   binds the minted difficulty, so a wrong value fails closed as
//!   [`PowError::InvalidTag`].
//! - The worker hashes `SHA-256(chg + String(nonce))` (UTF-8, decimal nonce),
//!   hex-encodes lowercase, and requires `dif` leading zero hex characters
//!   (checked nibble-by-nibble).
//! - The tag is `HMAC-SHA256(secret, "pow-tag-v1:{chg}:{dif}:{tim}")` — server-minted
//!   and domain-separated so the same key cannot validate a tag minted for a
//!   different protocol/version. The client never computes the tag, only
//!   echoes it.
//!
//! # Replay identity
//!
//! There is no server-side replay counter in this crate. [`Verified::tid`] is
//! a stable hash of `chg`, so the caller gets a replay-safe identity for
//! idempotency and per-tid budgets.

mod challenge;
mod error;
mod ops;
mod secret;

pub use challenge::{Challenge, Solution, Verified};
pub use error::PowError;
pub use ops::{MAX_FUTURE_SKEW_SECS, mint_challenge, verify_solution};
pub use secret::PowSecret;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

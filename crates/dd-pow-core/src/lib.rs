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
//! - Solution JSON as the client posts it: `{ chg, sol, non, dif, tim, tag }`.
//!   The client/API must echo the minted `dif`; the HMAC tag binds that value,
//!   preventing a client from lowering it, while the server's `min_difficulty`
//!   check can reject still-authentic in-flight challenges after a difficulty
//!   bump.
//! - The worker hashes `SHA-256(chg + String(nonce))` (UTF-8, decimal nonce),
//!   hex-encodes lowercase, and requires `dif` leading zero hex characters
//!   (checked nibble-by-nibble).
//! - The tag is `HMAC-SHA256(secret, framed("pow-tag-v1", chg, dif, tim))`:
//!   server-minted, length-prefixed, and domain-separated so the same key cannot
//!   validate a tag minted for a different protocol/version. The client never
//!   computes the tag, only echoes it.
//!
//! # Difficulty guidance
//!
//! Difficulty 1–3 is for deterministic tests and local development only. A
//! production deployment should tune for a target solve time (usually about 1–3
//! seconds in supported browsers); for this simple SHA-256 loop that usually
//! starts around 5–6 leading zero hex nibbles.
//!
//! # Secret rotation
//!
//! `PowSecret` is intentionally a single loaded secret, not a full keyring. A
//! consuming service that needs smooth rotation should hold current plus
//! verify-only previous secrets and try verification against both for at most
//! the configured challenge `max_age`. Rotating the only secret, or changing the
//! tag domain/framing, deliberately invalidates in-flight challenges for that
//! short window.
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
pub use ops::{
    MAX_DIFFICULTY, MAX_FUTURE_SKEW_SECS, RECOMMENDED_PRODUCTION_MIN_DIFFICULTY, mint_challenge,
    verify_solution,
};
pub use secret::PowSecret;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#![forbid(unsafe_code)]

//! `dd-pow-core`: pure, IO-free proof-of-work challenge mint/verify plus the
//! `dd_pow` proof cookie that records a successful solve.
//!
//! Deterministic: the caller injects clock, entropy, difficulty, max age,
//! secret, and (for the proof cookie) a CSPRNG and keyring. This crate never
//! logs, never reads the clock, and never generates randomness on its own, so
//! every function is fully testable.
//!
//! # Proof cookie
//!
//! [`mint_pow_proof_cookie`] / [`verify_pow_proof_cookie`] turn a
//! [`Verified`] solve into the stateless, encrypted [`PowProofCookie`] value
//! that upper layers set as `dd_pow`. The purpose separation and lifetime
//! policy live on [`PowProofCookie`].
//!
//! # Wire contract
//!
//! The browser client and this crate must agree byte-for-byte:
//!
//! - Challenge JSON: `{ chg, dif, tim, tag }`. `tim` is RFC3339 with
//!   millisecond precision, minted from the caller-injected [`UnixMillis`]
//!   clock; the client echoes it back byte-for-byte.
//! - Solution JSON as the client posts it: `{ chg, sol, non, dif, tim, tag }`.
//!   The client/API must echo the minted `dif`. The HMAC tag binds that value
//!   and stops a client from lowering it. The server's `min_difficulty` check
//!   can reject still-authentic in-flight challenges after a difficulty bump.
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
//! seconds in supported browsers). For this simple SHA-256 loop that usually
//! starts around 5–6 leading zero hex characters.
//!
//! # Secret rotation
//!
//! `PowSecret` is intentionally a single loaded secret, not a full keyring. A
//! consuming service that needs rotation without downtime should hold current
//! plus verify-only previous secrets. It tries verification against both for at
//! most the configured challenge `max_age`. Rotating the only secret, or changing the
//! tag domain/framing, deliberately invalidates in-flight challenges for that
//! short window.
//!
//! # Replay identity
//!
//! There is no server-side replay counter in this crate. [`Verified::tid`] is
//! a stable hash of `chg`, so the caller gets a replay-safe identity for
//! idempotency and per-tid budgets.
//!
//! # Solve timing
//!
//! [`Verified::mint_to_verify_ms`] reports how long after mint a solution
//! arrived, computed entirely from the server's own clock (`tim` is
//! HMAC-bound, so a client cannot backdate it). The value is inflatable but
//! not deflatable: use it as a soft bot-detection signal and a
//! difficulty-tuning instrument, never as a hard block on slow solves.

mod challenge;
mod clock;
mod error;
mod ops;
mod proof_cookie;
mod secret;

pub use challenge::{Challenge, Solution, Verified};
pub use clock::UnixMillis;
pub use error::PowError;
pub use ops::{
    MAX_DIFFICULTY, MAX_FUTURE_SKEW_SECS, RECOMMENDED_PRODUCTION_MIN_DIFFICULTY, mint_challenge,
    verify_solution,
};
pub use proof_cookie::{
    DEFAULT_POW_PROOF_TTL_SECS, HKDF_INFO_POW_PROOF_COOKIE_V1, POW_PROOF_MAX_AGE_SECS,
    PowProofCookie, PowProofCookieValue, TOKEN_TYPE_POW_PROOF_COOKIE_V1, VerifiedPowProof,
    mint_pow_proof_cookie, verify_pow_proof_cookie,
};
pub use secret::PowSecret;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

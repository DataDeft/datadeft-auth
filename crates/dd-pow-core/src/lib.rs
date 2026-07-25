//! `dd-pow-core` — pure, IO-free proof-of-work challenge mint/verify.
//!
//! Deterministic: the caller injects clock, entropy, difficulty, max age, and
//! secret. No Axum, Tokio, AWS SDK, filesystem, environment, or logging.

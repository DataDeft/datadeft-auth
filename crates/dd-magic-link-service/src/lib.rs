//! `dd-magic-link-service` — framework-neutral magic-link orchestration.
//!
//! Request and consume flows built on traits for storage, rate limiting,
//! users, sessions, the email outbox, the clock, and randomness. Public
//! errors are generic and non-enumerating. No Axum or AWS dependency.

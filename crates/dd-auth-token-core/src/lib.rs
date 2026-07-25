//! `dd-auth-token-core` — token/session/cookie primitives.
//!
//! Cookie name, issuer, audience, TTLs, key IDs, and key material are all
//! configurable. `Debug` is redacted for secrets. Core APIs never read the
//! environment or the clock directly.

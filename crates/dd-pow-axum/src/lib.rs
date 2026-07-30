#![forbid(unsafe_code)]

//! `dd-pow-axum` — optional Axum HTTP glue for the `dd-pow-core` proof-of-work
//! admission gate.
//!
//! Proof-of-work is an admission gate that stands in front of the rest of
//! auth: a client solves a challenge, and the `dd_pow` proof cookie records
//! that solve so the edge does not re-challenge a browser that recently
//! passed. This crate is deliberately headless — it validates and mints, and
//! returns structured values and `Set-Cookie` headers for the app to send. The
//! app owns the router, body limits, `Content-Type`, and origin checks.
//!
//! # Wiring
//!
//! - `POST /…/pow/create` → [`mint_pow_challenge`], serialize the
//!   [`PowChallengeResponse`] as JSON.
//! - `POST /…/pow/validate` → deserialize a [`PowSolutionRequest`], call
//!   [`verify_pow_solution`], and on `Ok` append the returned `Set-Cookie`
//!   header. Map [`PowFlowError::Rejected`] to a generic `403` and
//!   [`PowFlowError::Internal`] to `500`.

mod cookie;
mod handlers;

pub use cookie::{
    DEFAULT_POW_PROOF_COOKIE_NAME, DEFAULT_POW_PROOF_COOKIE_PATH, PowCookieConfigError,
    PowCookieError, PowProofCookieConfig, SameSite,
};
pub use handlers::{
    DEFAULT_POW_CHALLENGE_MAX_AGE_SECS, PowChallengeResponse, PowFlowError, PowPolicy,
    PowPolicyError, PowSolutionRequest, mint_pow_challenge, verify_pow_solution,
};

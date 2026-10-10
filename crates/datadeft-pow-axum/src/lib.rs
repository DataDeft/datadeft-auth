#![forbid(unsafe_code)]

//! `datadeft-pow-axum`: optional Axum HTTP glue for the `datadeft-pow-core` proof-of-work
//! admission gate.
//!
//! Proof-of-work is an admission gate that stands in front of the rest of
//! auth: a client solves a challenge, and the `dd_pow` proof cookie records
//! that solve so the edge does not re-challenge a browser that recently
//! passed. This crate is deliberately headless: it validates and mints, and
//! returns structured values and `Set-Cookie` headers for the app to send. The
//! app owns the router, body limits, `Content-Type`, and origin checks.
//!
//! # Wiring
//!
//! - `POST /…/pow/create` → [`mint_pow_challenge`], serialize the
//!   [`PowChallengeResponse`] as JSON.
//! - `POST /…/pow/validate` → deserialize a [`PowSolutionRequest`], call
//!   [`verify_pow_solution`], and on `Ok` append the returned
//!   [`PowAdmission::set_cookie`] header. On `Err`, return the
//!   [`PowFlowError`] itself: it renders `401` + `WWW-Authenticate: DD-PoW`
//!   or the constant `503`.
//! - Every gated route → [`admit_proof`] with the shared [`ProofBudget`]: it
//!   verifies the `dd_pow` cookie and spends one unit of its solve's budget.
//!   Return the [`ProofRejection`] itself on `Err`.
//!
//! # Response contract
//!
//! `401` + `WWW-Authenticate: DD-PoW` means "solve, then retry once"; the
//! constant `503` means "back off with jitter and retry". The library never
//! sends `403`, which stays the app's.
//!   [`PowAdmission::mint_to_verify_ms`] is the server-derived solve-timing
//!   signal for the app's metrics and risk tagging.

mod admission;
mod cookie;
mod handlers;
mod response;

pub use admission::{
    AdmittedProof, MAX_PROOF_BUDGET_PER_SOLVE, ProofBudgetPolicy, ProofBudgetPolicyError,
    ProofRejection, admit_proof,
};
pub use cookie::{
    DEFAULT_POW_PROOF_COOKIE_NAME, DEFAULT_POW_PROOF_COOKIE_PATH, PowCookieConfigError,
    PowCookieError, PowProofCookieConfig, SameSite,
};
/// The strict incoming-cookie selector shared with `datadeft-magic-link-axum`:
/// read the proof cookie with
/// `select_cookie(headers.get_all(COOKIE).iter().map(HeaderValue::as_bytes), config.name())`.
pub use datadeft_auth_token_core::cookie_header::{CookieHeaderError, select_cookie};
pub use datadeft_pow_core::{ProofBudget, ProofBudgetDecision, ProofBudgetUnavailable};
pub use handlers::{
    DEFAULT_POW_CHALLENGE_MAX_AGE_SECS, PowAdmission, PowChallengeResponse, PowFlowError,
    PowPolicy, PowPolicyError, PowSolutionRequest, mint_pow_challenge, verify_pow_solution,
};
pub use response::{
    DD_POW_AUTH_SCHEME, UNAVAILABLE_BODY, UnavailableBody, pow_required_response,
    unavailable_response,
};

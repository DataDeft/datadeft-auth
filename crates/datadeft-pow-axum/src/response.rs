//! The public HTTP contract for proof-of-work admission.
//!
//! - `401` with `WWW-Authenticate: DD-PoW`: the proof is missing, invalid,
//!   or expired, or a posted solution failed. The client solves a challenge
//!   and retries once. `@datadeft/protect-client` acts only on this header,
//!   so an app's own `401`/`403` handling is unaffected.
//! - One constant `503` for everything security-sensitive or failed: an
//!   exhausted per-solve budget, a store or server fault. The client backs off
//!   with jitter and retries; the reason stays internal.
//! - The library never sends `403`; that status is the app's.

use axum::Json;
use axum::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// `WWW-Authenticate` value of the proof-of-work challenge.
pub const DD_POW_AUTH_SCHEME: &str = "DD-PoW";

/// The body of every `503`, identical across the datadeft Axum crates.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct UnavailableBody {
    /// Machine-readable code: always `unavailable`.
    pub error: &'static str,
    /// Human-readable text, the same for every reason.
    pub message: &'static str,
}

/// The one `503` body.
pub const UNAVAILABLE_BODY: UnavailableBody = UnavailableBody {
    error: "unavailable",
    message: "The service is temporarily unavailable. Try again later.",
};

#[derive(Serialize)]
struct PowRequiredBody {
    error: &'static str,
    message: &'static str,
}

/// `401` + `WWW-Authenticate: DD-PoW`: solve a challenge, then retry.
#[must_use]
pub fn pow_required_response() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(PowRequiredBody {
            error: "pow_required",
            message: "Proof of work required.",
        }),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(DD_POW_AUTH_SCHEME),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The constant `503`: same status, headers, and body for every reason.
#[must_use]
pub fn unavailable_response() -> Response {
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, Json(UNAVAILABLE_BODY)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

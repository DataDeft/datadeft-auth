//! Generic public HTTP error variants, JSON error/success bodies, and the
//! generic accepted response for magic-link endpoints.

use axum::Json;
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use datadeft_magic_link_service::MagicLinkServiceError;
use serde::Serialize;

/// Public HTTP error variants for general-purpose request-magic-link helpers.
/// Variants never carry email, token, session id, or key material.
///
/// The response contract: shape errors (bad JSON or email syntax, wrong
/// content type, oversize body) are one generic `400`, which leaks nothing;
/// every dependency or server fault is the constant `503`, identical to the
/// one `datadeft-pow-axum` sends. The library never sends `403` or `500`.
///
/// The variant is the typed reason; [`Self::reason`] is its stable label for
/// logs and metrics. Neither is ever sent.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkHttpError {
    BadRequest,
    UnsupportedMediaType,
    PayloadTooLarge,
    MagicLinkUnavailable,
    Unavailable,
    Internal,
}

/// `error` code of the constant `503` body.
pub const UNAVAILABLE_ERROR_CODE: &str = "unavailable";
/// `message` of the constant `503` body.
pub const UNAVAILABLE_MESSAGE: &str = "The service is temporarily unavailable. Try again later.";

impl MagicLinkHttpError {
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::BadRequest
            | Self::UnsupportedMediaType
            | Self::PayloadTooLarge
            | Self::MagicLinkUnavailable => StatusCode::BAD_REQUEST,
            Self::Unavailable | Self::Internal => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::BadRequest | Self::UnsupportedMediaType | Self::PayloadTooLarge => "bad_request",
            Self::MagicLinkUnavailable => "magic_link_unavailable",
            Self::Unavailable | Self::Internal => UNAVAILABLE_ERROR_CODE,
        }
    }

    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::BadRequest | Self::UnsupportedMediaType | Self::PayloadTooLarge => {
                "Invalid request."
            }
            Self::MagicLinkUnavailable => "You cannot use this magic link. Request a new one.",
            Self::Unavailable | Self::Internal => UNAVAILABLE_MESSAGE,
        }
    }

    /// Stable internal reason code for logs and metrics, never sent.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::PayloadTooLarge => "payload_too_large",
            Self::MagicLinkUnavailable => "magic_link_unavailable",
            Self::Unavailable => "dependency_unavailable",
            Self::Internal => "internal",
        }
    }
}

impl From<MagicLinkServiceError> for MagicLinkHttpError {
    fn from(value: MagicLinkServiceError) -> Self {
        match value {
            MagicLinkServiceError::BadRequest => Self::BadRequest,
            MagicLinkServiceError::MagicLinkUnavailable => Self::MagicLinkUnavailable,
            MagicLinkServiceError::Unavailable => Self::Unavailable,
            MagicLinkServiceError::Internal => Self::Internal,
        }
    }
}

impl IntoResponse for MagicLinkHttpError {
    fn into_response(self) -> Response {
        let mut response = (self.status(), Json(ErrorBody::from(self))).into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// JSON error body returned by [`MagicLinkHttpError`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub message: &'static str,
}

impl From<MagicLinkHttpError> for ErrorBody {
    fn from(value: MagicLinkHttpError) -> Self {
        Self {
            error: value.code(),
            message: value.message(),
        }
    }
}

/// Generic success body for magic-link request endpoints.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct GenericAcceptedBody {
    pub status: &'static str,
}

/// Create a generic accepted JSON response for request-magic-link endpoints.
#[must_use]
pub fn generic_accepted_response() -> Response {
    (StatusCode::OK, Json(GenericAcceptedBody { status: "ok" })).into_response()
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;

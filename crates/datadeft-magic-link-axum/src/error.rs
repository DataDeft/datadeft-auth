//! Generic public HTTP error variants, JSON error/success bodies, and the
//! generic accepted response for magic-link endpoints.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use datadeft_magic_link_service::MagicLinkServiceError;
use serde::Serialize;

/// Public HTTP error variants for general-purpose request-magic-link helpers.
/// Variants never carry email, token, session id, or key material.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkHttpError {
    BadRequest,
    Forbidden,
    UnsupportedMediaType,
    PayloadTooLarge,
    MagicLinkUnavailable,
    Unavailable,
    Internal,
}

impl MagicLinkHttpError {
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::BadRequest | Self::MagicLinkUnavailable => StatusCode::BAD_REQUEST,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Forbidden => "forbidden",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::PayloadTooLarge => "payload_too_large",
            Self::MagicLinkUnavailable => "magic_link_unavailable",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }

    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::BadRequest | Self::UnsupportedMediaType | Self::PayloadTooLarge => {
                "Invalid request."
            }
            Self::Forbidden => "Forbidden.",
            Self::MagicLinkUnavailable => "You cannot use this magic link. Request a new one.",
            Self::Unavailable => "The service is temporarily unavailable. Try again later.",
            Self::Internal => "Internal server error.",
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
        (self.status(), Json(ErrorBody::from(self))).into_response()
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

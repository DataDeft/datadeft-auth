//! `dd-magic-link-axum` — optional Axum HTTP integration.
//!
//! This crate owns bounded HTTP decoding, scanner-safe magic-link handlers,
//! cookie response helpers, and generic public errors. It does not own token or
//! session cryptography and does not force an application router shape.
//!
//! # Mandatory deployment gate
//!
//! A magic-link token is present in the landing request target before an Axum
//! handler runs. Production deployments **must** configure proxy/load-balancer
//! request-line bounds and prove that outer access logs, application middleware,
//! tracing, metrics, diagnostics, error reporting, and panic capture use route
//! templates and never retain raw request targets, route captures, query fields,
//! tokens, confirmations, or cookies. Representative production-like probes must
//! verify the emitted logs and telemetry. These handlers prove non-reflection only
//! after handler entry; they cannot make an unreviewed outer HTTP stack safe.

#![forbid(unsafe_code)]

mod cookie;
mod cookie_parse;
mod error;
mod extract;
mod handlers;
mod origin;
mod scanner_config;
mod session_auth;

#[cfg(test)]
pub(crate) mod test_fixtures;

pub use cookie::{
    CookieConfigError, DEFAULT_SESSION_COOKIE_NAME, DEFAULT_SESSION_COOKIE_PATH, SameSite,
    SessionCookieConfig, TemporaryCookieConfig, clear_session_cookie_header,
    clear_temporary_cookie_header, session_set_cookie_header, set_temporary_cookie_header,
};
pub use error::{ErrorBody, GenericAcceptedBody, MagicLinkHttpError, generic_accepted_response};
pub use extract::{
    APPLICATION_JSON, CLOUDFRONT_VIEWER_COUNTRY, FORM_URLENCODED, GuardedBody,
    MAX_MAGIC_LINK_BODY_BYTES, MAX_MAGIC_LINK_LANDING_QUERY_BYTES, MagicLinkConfirmationBody,
    MagicLinkLandingToken, MagicLinkRequestJson, content_type_matches, guarded_body,
    parse_magic_link_request_json, viewer_country,
};
pub use handlers::{
    apply_magic_link_security_headers, handle_magic_link_confirmation, handle_magic_link_landing,
    handle_magic_link_request_json,
};
pub use origin::{OriginConfigError, SameOriginPostConfig, SameOriginRedirect};
pub use scanner_config::{MagicLinkScannerFlowConfig, MagicLinkScannerFlowConfigError};
pub use session_auth::{SessionAuthRejection, SessionCookieValue, authenticate_session};

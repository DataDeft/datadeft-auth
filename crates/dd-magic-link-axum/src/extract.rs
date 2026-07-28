//! Bounded request decoding: guarded body reads, request/confirmation DTOs,
//! landing-token extraction, and header-derived request context.

use core::fmt;

use axum::body::{Bytes, to_bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName};
use dd_magic_link_service::{NormalizedEmail, RequestMagicLinkCommand};
use serde::Deserialize;
use zeroize::Zeroize;

use crate::error::MagicLinkHttpError;

/// Maximum raw query size accepted by the scanner landing helper.
pub const MAX_MAGIC_LINK_LANDING_QUERY_BYTES: usize = 768;
/// Maximum pre-auth body size accepted by the helpers.
pub const MAX_MAGIC_LINK_BODY_BYTES: usize = 4096;
/// JSON content type accepted by request and confirmation helpers.
pub const APPLICATION_JSON: &str = "application/json";
/// Form content type accepted by the confirmation helper.
pub const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
/// CloudFront country header commonly used for session country context.
pub const CLOUDFRONT_VIEWER_COUNTRY: &str = "cloudfront-viewer-country";

/// Request JSON accepted by
/// [`handle_magic_link_request_json`](crate::handle_magic_link_request_json).
///
/// This crate is language-agnostic: the request JSON carries no locale. An
/// application that localizes emails parses its own request shape and selects
/// the language in its [`MagicLinkOutbox`](dd_magic_link_service::MagicLinkOutbox)
/// (for example a request-scoped outbox), so the library never sees it.
#[derive(Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MagicLinkRequestJson {
    pub email: String,
    pub terms_accepted: bool,
    pub privacy_accepted: bool,
}

impl fmt::Debug for MagicLinkRequestJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkRequestJson")
            .field("email", &"<redacted>")
            .field("terms_accepted", &self.terms_accepted)
            .field("privacy_accepted", &self.privacy_accepted)
            .finish()
    }
}

impl MagicLinkRequestJson {
    pub fn into_command(self) -> Result<RequestMagicLinkCommand, MagicLinkHttpError> {
        let email =
            NormalizedEmail::parse(&self.email).map_err(|_| MagicLinkHttpError::BadRequest)?;
        Ok(RequestMagicLinkCommand::new(
            email,
            self.terms_accepted,
            self.privacy_accepted,
        ))
    }
}

/// Confirmation JSON/form body carrying only confirmation and optional country context.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MagicLinkConfirmationBody {
    pub(crate) confirmation: String,
}

impl fmt::Debug for MagicLinkConfirmationBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkConfirmationBody")
            .field("confirmation", &"<redacted>")
            .finish()
    }
}

impl Drop for MagicLinkConfirmationBody {
    fn drop(&mut self) {
        self.confirmation.zeroize();
    }
}

/// Body and headers returned by [`guarded_body`].
#[derive(Clone, Eq, PartialEq)]
pub struct GuardedBody {
    pub headers: HeaderMap,
    pub bytes: Bytes,
    pub is_json: bool,
}

impl fmt::Debug for GuardedBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuardedBody(..)")
    }
}

/// Read a bounded request body after checking content type and declared length.
pub async fn guarded_body(
    request: Request,
    allowed_content_types: &[&str],
    max_body_bytes: usize,
) -> Result<GuardedBody, MagicLinkHttpError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let content_type = unique_header_str(&headers, CONTENT_TYPE)
        .ok_or(MagicLinkHttpError::UnsupportedMediaType)?;
    if !allowed_content_types
        .iter()
        .any(|expected| content_type_matches_value(content_type, expected))
    {
        return Err(MagicLinkHttpError::UnsupportedMediaType);
    }
    if content_length_exceeds(&headers, max_body_bytes)? {
        return Err(MagicLinkHttpError::PayloadTooLarge);
    }
    let bytes = to_bytes(body, max_body_bytes)
        .await
        .map_err(|_| MagicLinkHttpError::PayloadTooLarge)?;
    if bytes.is_empty() {
        return Err(MagicLinkHttpError::BadRequest);
    }
    let is_json = content_type_matches_value(content_type, APPLICATION_JSON);
    Ok(GuardedBody {
        headers,
        bytes,
        is_json,
    })
}

/// Case-insensitive content-type comparison that ignores parameters.
#[must_use]
pub fn content_type_matches(headers: &HeaderMap, expected: &str) -> bool {
    unique_header_str(headers, CONTENT_TYPE)
        .is_some_and(|actual| content_type_matches_value(actual, expected))
}

/// Parse the supported request JSON body into a service command.
pub fn parse_magic_link_request_json(
    body: &[u8],
) -> Result<RequestMagicLinkCommand, MagicLinkHttpError> {
    serde_json::from_slice::<MagicLinkRequestJson>(body)
        .map_err(|_| MagicLinkHttpError::BadRequest)?
        .into_command()
}

/// Extract a unique trusted-edge viewer country (ISO 3166-1 alpha-2) from the
/// given header.
///
/// Country is opportunistic: when the edge supplies the header it is validated
/// and bound into the session; when absent, the flow proceeds without a
/// country. The header is only meaningful if the CDN/edge strips or overwrites
/// it on every request and the origin is not directly reachable — otherwise a
/// caller can omit it. Never source country from request bodies.
#[must_use]
pub fn viewer_country_from(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
    let value = unique_header_str(headers, name.clone())?;
    if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Some(value.to_owned())
    } else {
        None
    }
}

/// [`viewer_country_from`] with the CloudFront viewer-country header.
#[must_use]
pub fn viewer_country(headers: &HeaderMap) -> Option<String> {
    viewer_country_from(headers, &HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY))
}

/// Extract the raw `token=` candidate from the landing query, bounded only by
/// the outer query-size guard. The service command
/// ([`BeginMagicLinkLandingCommand`](dd_magic_link_service::BeginMagicLinkLandingCommand))
/// owns the raw-token cap and its zeroization, and the core parser owns the
/// grammar — so the candidate travels as a plain string.
pub(crate) fn extract_landing_token(query: Option<&str>) -> Result<String, MagicLinkHttpError> {
    let query = query.ok_or(MagicLinkHttpError::BadRequest)?;
    if query.is_empty()
        || query.len() > MAX_MAGIC_LINK_LANDING_QUERY_BYTES
        || !query.is_ascii()
        || query.contains('&')
        || query.contains('%')
    {
        return Err(MagicLinkHttpError::BadRequest);
    }
    let value = query
        .strip_prefix("token=")
        .ok_or(MagicLinkHttpError::BadRequest)?;
    if value.is_empty() || value.contains('=') {
        return Err(MagicLinkHttpError::BadRequest);
    }
    Ok(value.to_owned())
}

fn content_type_matches_value(actual: &str, expected: &str) -> bool {
    actual
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
}

fn unique_header_str(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn content_length_exceeds(
    headers: &HeaderMap,
    max_body_bytes: usize,
) -> Result<bool, MagicLinkHttpError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(MagicLinkHttpError::BadRequest);
    }
    let value = value.to_str().map_err(|_| MagicLinkHttpError::BadRequest)?;
    let length = value
        .parse::<usize>()
        .map_err(|_| MagicLinkHttpError::BadRequest)?;
    Ok(length > max_body_bytes)
}

#[cfg(test)]
#[path = "extract_tests.rs"]
mod tests;

//! `dd-magic-link-axum` — optional Axum HTTP integration.
//!
//! Request guards, body decoding helpers, cookie response helpers, and safe
//! HTTP error mapping. This crate does not own core token/session logic and does
//! not force an application router shape.

#![forbid(unsafe_code)]

use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use dd_magic_link_service::{
    ClientKey, ConsumeMagicLinkOutcome, EmailLocale, MagicLinkServiceError, NormalizedEmail,
    RequestMagicLinkCommand, RequestMagicLinkOutcome,
};
use serde::{Deserialize, Serialize};

/// Default maximum pre-auth body size accepted by the helpers.
pub const MAX_MAGIC_LINK_BODY_BYTES: usize = 4 * 1024;
/// JSON content type accepted by the request helper.
pub const APPLICATION_JSON: &str = "application/json";
/// Form content type accepted by the consume helper.
pub const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
/// Conservative default primary session cookie name.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "dd_session";
/// Primary session cookies are app-wide by default.
pub const DEFAULT_SESSION_COOKIE_PATH: &str = "/";
/// Default browser cookie max age matching the 30-day service absolute session baseline.
pub const DEFAULT_SESSION_COOKIE_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;
/// CloudFront country header commonly used to bind a session country.
pub const CLOUDFRONT_VIEWER_COUNTRY: &str = "cloudfront-viewer-country";

const CACHE_CONTROL: HeaderName = HeaderName::from_static("cache-control");
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");

/// Public HTTP error variants for the adapter. Variants never carry email,
/// token, session id, or key material.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkHttpError {
    BadRequest,
    Forbidden,
    UnsupportedMediaType,
    PayloadTooLarge,
    MagicLinkUnavailable,
    PowRequired,
    Unavailable,
    Internal,
}

impl MagicLinkHttpError {
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::BadRequest | Self::MagicLinkUnavailable => StatusCode::BAD_REQUEST,
            Self::Forbidden | Self::PowRequired => StatusCode::FORBIDDEN,
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
            Self::PowRequired => "pow_required",
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
            Self::Forbidden | Self::PowRequired => "Forbidden.",
            Self::MagicLinkUnavailable => "This magic link cannot be used. Request a new one.",
            Self::Unavailable => "Service temporarily unavailable. Try again later.",
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

/// Request JSON accepted by [`handle_magic_link_request_json`].
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct MagicLinkRequestJson {
    pub email: String,
    pub locale: String,
    pub terms_accepted: bool,
    pub privacy_accepted: bool,
    #[serde(default)]
    pub client_key: Option<String>,
}

impl MagicLinkRequestJson {
    pub fn into_command(
        self,
        fallback_client_key: Option<ClientKey>,
    ) -> Result<RequestMagicLinkCommand, MagicLinkHttpError> {
        let email =
            NormalizedEmail::parse(&self.email).map_err(|_| MagicLinkHttpError::BadRequest)?;
        let locale = parse_locale(&self.locale)?;
        let body_client_key = parse_optional_client_key(self.client_key.as_deref())?;
        let client_key = fallback_client_key.or(body_client_key);
        Ok(RequestMagicLinkCommand::new(
            email,
            locale,
            self.terms_accepted,
            self.privacy_accepted,
            client_key,
        ))
    }
}

/// Consume JSON/form body accepted by [`handle_magic_link_consume`].
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct MagicLinkConsumeBody {
    pub token: String,
    #[serde(default)]
    pub client_key: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
}

impl MagicLinkConsumeBody {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn client_key(
        &self,
        fallback_client_key: Option<ClientKey>,
    ) -> Result<Option<ClientKey>, MagicLinkHttpError> {
        let body_client_key = parse_optional_client_key(self.client_key.as_deref())?;
        Ok(fallback_client_key.or(body_client_key))
    }

    pub fn country(&self, fallback_country: Option<String>) -> Option<String> {
        fallback_country.or_else(|| self.country.clone())
    }
}

/// SameSite policy for cookie helper output.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SameSite {
    Lax,
    Strict,
    None,
}

impl SameSite {
    fn as_cookie_value(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

/// Configuration for primary session cookie response helpers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionCookieConfig {
    pub name: String,
    pub path: String,
    pub max_age_secs: u64,
    pub secure: bool,
    pub same_site: SameSite,
}

impl SessionCookieConfig {
    /// Production-safe defaults: lower snake-case name, host-only scope,
    /// `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, and explicit max age.
    pub fn production() -> Self {
        Self {
            name: DEFAULT_SESSION_COOKIE_NAME.to_owned(),
            path: DEFAULT_SESSION_COOKIE_PATH.to_owned(),
            max_age_secs: DEFAULT_SESSION_COOKIE_MAX_AGE_SECS,
            secure: true,
            same_site: SameSite::Lax,
        }
    }

    /// Explicit local-development variant. Production code should prefer
    /// [`SessionCookieConfig::production`].
    pub fn local_development() -> Self {
        Self {
            secure: false,
            ..Self::production()
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    pub fn with_max_age_secs(mut self, max_age_secs: u64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }

    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    fn validate(&self) -> Result<(), MagicLinkHttpError> {
        if !is_lower_snake_cookie_name(&self.name)
            || !is_valid_cookie_path(&self.path)
            || self.max_age_secs == 0
            || (self.same_site == SameSite::None && !self.secure)
        {
            return Err(MagicLinkHttpError::BadRequest);
        }
        Ok(())
    }
}

/// Config for a successful magic-link consume HTTP response.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConsumeSuccessConfig {
    pub session_cookie: SessionCookieConfig,
    pub redirect: SameOriginRedirect,
}

impl ConsumeSuccessConfig {
    pub fn new(redirect: SameOriginRedirect) -> Self {
        Self {
            session_cookie: SessionCookieConfig::production(),
            redirect,
        }
    }
}

/// Same-origin redirect target. Only clean absolute paths such as `/app` or
/// `/auth/complete?next=dashboard` are accepted.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SameOriginRedirect(String);

impl SameOriginRedirect {
    pub fn parse(value: impl Into<String>) -> Result<Self, MagicLinkHttpError> {
        let value = value.into();
        if is_safe_same_origin_path(&value) {
            Ok(Self(value))
        } else {
            Err(MagicLinkHttpError::BadRequest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Body and headers returned by [`guarded_body`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GuardedBody {
    pub headers: HeaderMap,
    pub bytes: Bytes,
    pub is_json: bool,
}

/// Read a bounded request body after checking content type.
pub async fn guarded_body(
    request: Request,
    allowed_content_types: &[&str],
    max_body_bytes: usize,
) -> Result<GuardedBody, MagicLinkHttpError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
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
    let is_json = content_type_matches_value(content_type, APPLICATION_JSON);
    Ok(GuardedBody {
        headers,
        bytes,
        is_json,
    })
}

/// Case-insensitive content-type comparison that ignores parameters such as
/// `charset=utf-8`.
#[must_use]
pub fn content_type_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|actual| content_type_matches_value(actual, expected))
}

/// Parse the supported request JSON body into a service command.
pub fn parse_magic_link_request_json(
    body: &[u8],
    client_key: Option<ClientKey>,
) -> Result<RequestMagicLinkCommand, MagicLinkHttpError> {
    serde_json::from_slice::<MagicLinkRequestJson>(body)
        .map_err(|_| MagicLinkHttpError::BadRequest)?
        .into_command(client_key)
}

/// Parse a supported consume JSON or form body. The token is intentionally not
/// parsed here; invalid bearer syntax is delegated to the service so its
/// malformed-consume limiter can run with the supplied client key.
pub fn parse_magic_link_consume_body(
    body: &[u8],
    is_json: bool,
) -> Result<MagicLinkConsumeBody, MagicLinkHttpError> {
    if is_json {
        serde_json::from_slice(body).map_err(|_| MagicLinkHttpError::BadRequest)
    } else {
        serde_urlencoded::from_bytes(body).map_err(|_| MagicLinkHttpError::BadRequest)
    }
}

/// Extract a bounded service client key from a header such as `x-client-key`.
pub fn client_key_from_header(
    headers: &HeaderMap,
    header_name: &str,
) -> Result<Option<ClientKey>, MagicLinkHttpError> {
    let name = HeaderName::from_bytes(header_name.as_bytes())
        .map_err(|_| MagicLinkHttpError::BadRequest)?;
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| MagicLinkHttpError::BadRequest)?;
    ClientKey::parse(value)
        .map(Some)
        .map_err(|_| MagicLinkHttpError::BadRequest)
}

/// Extract a CloudFront viewer country header as an ISO 3166-1 alpha-2 code.
#[must_use]
pub fn viewer_country(headers: &HeaderMap) -> Option<String> {
    let name = HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY);
    let value = headers.get(name)?.to_str().ok()?;
    if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Some(value.to_owned())
    } else {
        None
    }
}

/// Create a generic accepted JSON response for request-magic-link endpoints.
#[must_use]
pub fn generic_accepted_response() -> Response {
    (StatusCode::OK, Json(GenericAcceptedBody { status: "ok" })).into_response()
}

/// Create a `Set-Cookie` header value for a freshly minted session cookie.
pub fn session_set_cookie_header(
    config: &SessionCookieConfig,
    token: &str,
) -> Result<HeaderValue, MagicLinkHttpError> {
    config.validate()?;
    if !is_valid_cookie_value(token) {
        return Err(MagicLinkHttpError::Internal);
    }
    let secure = if config.secure { "; Secure" } else { "" };
    let header = format!(
        "{}={token}; Path={}; HttpOnly{secure}; SameSite={}; Max-Age={}",
        config.name,
        config.path,
        config.same_site.as_cookie_value(),
        config.max_age_secs
    );
    HeaderValue::from_str(&header).map_err(|_| MagicLinkHttpError::Internal)
}

/// Create a `Set-Cookie` header value that clears the primary session cookie.
pub fn clear_session_cookie_header(
    config: &SessionCookieConfig,
) -> Result<HeaderValue, MagicLinkHttpError> {
    config.validate()?;
    let secure = if config.secure { "; Secure" } else { "" };
    let header = format!(
        "{}=; Path={}; HttpOnly{secure}; SameSite={}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        config.name,
        config.path,
        config.same_site.as_cookie_value()
    );
    HeaderValue::from_str(&header).map_err(|_| MagicLinkHttpError::Internal)
}

/// Create a successful consume response: `303 See Other`, clean same-origin
/// `Location`, and a host-only primary session cookie.
pub fn consume_success_response(
    outcome: &ConsumeMagicLinkOutcome,
    config: &ConsumeSuccessConfig,
) -> Result<Response, MagicLinkHttpError> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    let location = HeaderValue::from_str(config.redirect.as_str())
        .map_err(|_| MagicLinkHttpError::Internal)?;
    response.headers_mut().insert(LOCATION, location);
    let set_cookie = session_set_cookie_header(&config.session_cookie, &outcome.session_cookie)?;
    response.headers_mut().append(SET_COOKIE, set_cookie);
    Ok(response)
}

/// Handle a JSON magic-link request by parsing/guarding HTTP input, delegating
/// to the provided service closure, and returning the generic public response.
pub async fn handle_magic_link_request_json<F>(
    request: Request,
    fallback_client_key: Option<ClientKey>,
    handle: F,
) -> Response
where
    F: FnOnce(RequestMagicLinkCommand) -> Result<RequestMagicLinkOutcome, MagicLinkServiceError>,
{
    match handle_magic_link_request_json_inner(request, fallback_client_key, handle).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn handle_magic_link_request_json_inner<F>(
    request: Request,
    fallback_client_key: Option<ClientKey>,
    handle: F,
) -> Result<Response, MagicLinkHttpError>
where
    F: FnOnce(RequestMagicLinkCommand) -> Result<RequestMagicLinkOutcome, MagicLinkServiceError>,
{
    let guarded = guarded_body(request, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES).await?;
    let command = parse_magic_link_request_json(&guarded.bytes, fallback_client_key)?;
    handle(command).map_err(MagicLinkHttpError::from)?;
    Ok(generic_accepted_response())
}

/// Handle a JSON or form magic-link consume request. Invalid token syntax is
/// delegated to the service closure for limiter-aware handling.
pub async fn handle_magic_link_consume<F>(
    request: Request,
    fallback_client_key: Option<ClientKey>,
    config: &ConsumeSuccessConfig,
    handle: F,
) -> Response
where
    F: FnOnce(
        &str,
        Option<ClientKey>,
        Option<String>,
    ) -> Result<ConsumeMagicLinkOutcome, MagicLinkServiceError>,
{
    match handle_magic_link_consume_inner(request, fallback_client_key, config, handle).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn handle_magic_link_consume_inner<F>(
    request: Request,
    fallback_client_key: Option<ClientKey>,
    config: &ConsumeSuccessConfig,
    handle: F,
) -> Result<Response, MagicLinkHttpError>
where
    F: FnOnce(
        &str,
        Option<ClientKey>,
        Option<String>,
    ) -> Result<ConsumeMagicLinkOutcome, MagicLinkServiceError>,
{
    let guarded = guarded_body(
        request,
        &[APPLICATION_JSON, FORM_URLENCODED],
        MAX_MAGIC_LINK_BODY_BYTES,
    )
    .await?;
    let fallback_country = viewer_country(&guarded.headers);
    let body = parse_magic_link_consume_body(&guarded.bytes, guarded.is_json)?;
    let client_key = body.client_key(fallback_client_key)?;
    let country = body.country(fallback_country);
    let outcome = handle(body.token(), client_key, country).map_err(MagicLinkHttpError::from)?;
    consume_success_response(&outcome, config)
}

/// Minimal scanner-safe landing page: `GET` renders only a confirmation form;
/// only the same-origin `POST` target should call the consume helper.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MagicLinkLandingPage {
    pub token: String,
    pub post_action: SameOriginRedirect,
    pub account_label: Option<String>,
}

/// Render a no-store, no-referrer, frame-denied confirmation page that posts the
/// bearer token in the request body rather than consuming it on `GET`.
pub fn magic_link_landing_response(
    page: &MagicLinkLandingPage,
) -> Result<Response, MagicLinkHttpError> {
    if !is_safe_hidden_value(&page.token) {
        return Err(MagicLinkHttpError::BadRequest);
    }
    let account = page
        .account_label
        .as_deref()
        .map(|label| format!("<p>Sign in as <strong>{}</strong>.</p>", escape_html(label)))
        .unwrap_or_else(|| "<p>Confirm sign in for this magic link.</p>".to_owned());
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Confirm sign in</title></head><body><main><h1>Confirm sign in</h1>{account}<form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"token\" value=\"{}\"><button type=\"submit\">Continue</button></form></main></body></html>",
        escape_html(page.post_action.as_str()),
        escape_html(&page.token)
    );
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    apply_magic_link_security_headers(response.headers_mut());
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(response)
}

/// Apply security headers suitable for magic-link landing and consume responses.
pub fn apply_magic_link_security_headers(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
}

fn parse_locale(value: &str) -> Result<EmailLocale, MagicLinkHttpError> {
    match value {
        "en" => Ok(EmailLocale::En),
        "hu" => Ok(EmailLocale::Hu),
        _ => Err(MagicLinkHttpError::BadRequest),
    }
}

fn parse_optional_client_key(value: Option<&str>) -> Result<Option<ClientKey>, MagicLinkHttpError> {
    value
        .map(ClientKey::parse)
        .transpose()
        .map_err(|_| MagicLinkHttpError::BadRequest)
}

fn content_type_matches_value(actual: &str, expected: &str) -> bool {
    actual
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
}

fn content_length_exceeds(
    headers: &HeaderMap,
    max_body_bytes: usize,
) -> Result<bool, MagicLinkHttpError> {
    let Some(value) = headers.get(CONTENT_LENGTH) else {
        return Ok(false);
    };
    let value = value.to_str().map_err(|_| MagicLinkHttpError::BadRequest)?;
    let length = value
        .parse::<usize>()
        .map_err(|_| MagicLinkHttpError::BadRequest)?;
    Ok(length > max_body_bytes)
}

fn is_lower_snake_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
}

fn is_valid_cookie_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && byte != b';')
}

fn is_valid_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !matches!(byte, b';' | b',' | b' ' | b'\t'))
}

fn is_safe_same_origin_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 2048
        && !value.contains("mlv1.")
        && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn is_safe_hidden_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2048 && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

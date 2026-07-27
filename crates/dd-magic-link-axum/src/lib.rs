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

use core::fmt;
use core::future::Future;

use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use dd_magic_link_service::{
    BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, EmailLocale, KeyPurpose, MAX_RAW_MAGIC_LINK_TOKEN_BYTES,
    MagicLinkConfigError, MagicLinkFlowCookie, MagicLinkFlowError, MagicLinkServiceConfig,
    MagicLinkServiceError, NormalizedEmail, RequestMagicLinkCommand, RequestMagicLinkOutcome,
    SessionValidationError, TemporaryAuthStateAction, ValidatedSession,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Maximum raw query size accepted by the scanner landing helper.
pub const MAX_MAGIC_LINK_LANDING_QUERY_BYTES: usize = 768;
/// Maximum pre-auth body size accepted by the helpers.
pub const MAX_MAGIC_LINK_BODY_BYTES: usize = 4096;
/// JSON content type accepted by request and confirmation helpers.
pub const APPLICATION_JSON: &str = "application/json";
/// Form content type accepted by the confirmation helper.
pub const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
/// Conservative default primary session cookie name.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "dd_session";
/// Primary session cookies are app-wide by default.
pub const DEFAULT_SESSION_COOKIE_PATH: &str = "/";
/// CloudFront country header commonly used for session country context.
pub const CLOUDFRONT_VIEWER_COUNTRY: &str = "cloudfront-viewer-country";

const DEFAULT_FLOW_COOKIE_NAME: &str = "dd_auth_flow";
const DEFAULT_TEMPORARY_COOKIE_PATH: &str = "/auth";
const MAX_COOKIE_HEADER_FIELDS: usize = 8;
const MAX_COOKIE_HEADER_BYTES: usize = 8192;
const MAX_SELECTED_COOKIE_VALUE_BYTES: usize = 4096;
const CACHE_CONTROL: HeaderName = HeaderName::from_static("cache-control");
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const COOKIE_EPOCH: &str = "Thu, 01 Jan 1970 00:00:00 GMT";

/// Precomputed clear headers for the default cookie shapes, so the infallible
/// `*_defaults()` constructors need no fallible header build. Each must stay
/// byte-for-byte in lockstep with [`cookie_header`] output — pinned by the
/// `precomputed_clear_headers_match_freshly_built_ones` test.
const DEFAULT_FLOW_CLEAR_HEADER: &str = "dd_auth_flow=; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
const DEFAULT_FLOW_CLEAR_HEADER_INSECURE: &str = "dd_auth_flow=; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
const DEFAULT_SESSION_CLEAR_HEADER: &str = "dd_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
const DEFAULT_SESSION_CLEAR_HEADER_INSECURE: &str =
    "dd_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
const TERMINAL_INVALID_BODY: &str = "Invalid confirmation.\n";

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
#[derive(Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MagicLinkRequestJson {
    pub email: String,
    pub locale: String,
    pub terms_accepted: bool,
    pub privacy_accepted: bool,
}

impl fmt::Debug for MagicLinkRequestJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkRequestJson")
            .field("email", &"<redacted>")
            .field("locale", &self.locale)
            .field("terms_accepted", &self.terms_accepted)
            .field("privacy_accepted", &self.privacy_accepted)
            .finish()
    }
}

impl MagicLinkRequestJson {
    pub fn into_command(self) -> Result<RequestMagicLinkCommand, MagicLinkHttpError> {
        let email =
            NormalizedEmail::parse(&self.email).map_err(|_| MagicLinkHttpError::BadRequest)?;
        let locale = parse_locale(&self.locale)?;
        Ok(RequestMagicLinkCommand::new(
            email,
            locale,
            self.terms_accepted,
            self.privacy_accepted,
        ))
    }
}

/// Bounded, redacted raw landing candidate. Token grammar remains owned by the
/// service/core parser.
pub struct MagicLinkLandingToken(String);

impl MagicLinkLandingToken {
    /// Accept a candidate only within the service-owned pre-parse resource cap.
    pub fn new(mut value: String) -> Result<Self, MagicLinkHttpError> {
        if value.is_empty() || value.len() > MAX_RAW_MAGIC_LINK_TOKEN_BYTES {
            value.zeroize();
            return Err(MagicLinkHttpError::BadRequest);
        }
        Ok(Self(value))
    }

    fn into_string(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for MagicLinkLandingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkLandingToken(..)")
    }
}

impl Drop for MagicLinkLandingToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Confirmation JSON/form body carrying only confirmation and optional country context.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MagicLinkConfirmationBody {
    confirmation: String,
    #[serde(default)]
    country: Option<String>,
}

impl fmt::Debug for MagicLinkConfirmationBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkConfirmationBody")
            .field("confirmation", &"<redacted>")
            .field("country", &self.country)
            .finish()
    }
}

impl Drop for MagicLinkConfirmationBody {
    fn drop(&mut self) {
        self.confirmation.zeroize();
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

/// Typed cookie setup failures.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CookieConfigError {
    InvalidName,
    InvalidPath,
    SameSiteNoneRequiresSecure,
}

impl fmt::Display for CookieConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "invalid cookie name",
            Self::InvalidPath => "invalid cookie path",
            Self::SameSiteNoneRequiresSecure => "SameSite=None requires Secure",
        })
    }
}

impl std::error::Error for CookieConfigError {}

/// Validated host-only temporary auth cookie policy.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TemporaryCookieConfig {
    name: String,
    path: String,
    secure: bool,
    same_site: SameSite,
    clear_header: HeaderValue,
}

impl TemporaryCookieConfig {
    pub fn production(
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, CookieConfigError> {
        Self::build(name.into(), path.into(), true)
    }

    pub fn local_development(
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, CookieConfigError> {
        Self::build(name.into(), path.into(), false)
    }

    fn build(name: String, path: String, secure: bool) -> Result<Self, CookieConfigError> {
        validate_cookie_name(&name)?;
        validate_cookie_path(&path)?;
        let same_site = SameSite::Lax;
        let clear_header = build_clear_cookie_header(&name, &path, secure, same_site)?;
        Ok(Self {
            name,
            path,
            secure,
            same_site,
            clear_header,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn secure(&self) -> bool {
        self.secure
    }

    #[must_use]
    pub fn same_site(&self) -> SameSite {
        self.same_site
    }
}

/// Validated magic-link flow-cookie policy.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthFlowCookieConfig {
    flow: TemporaryCookieConfig,
}

impl AuthFlowCookieConfig {
    #[must_use]
    pub fn new(flow: TemporaryCookieConfig) -> Self {
        Self { flow }
    }

    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            flow: TemporaryCookieConfig {
                name: DEFAULT_FLOW_COOKIE_NAME.to_owned(),
                path: DEFAULT_TEMPORARY_COOKIE_PATH.to_owned(),
                secure: true,
                same_site: SameSite::Lax,
                clear_header: HeaderValue::from_static(DEFAULT_FLOW_CLEAR_HEADER),
            },
        }
    }

    #[must_use]
    pub fn local_development_defaults() -> Self {
        let mut defaults = Self::production_defaults();
        defaults.flow.secure = false;
        defaults.flow.clear_header = HeaderValue::from_static(DEFAULT_FLOW_CLEAR_HEADER_INSECURE);
        defaults
    }

    #[must_use]
    pub fn flow(&self) -> &TemporaryCookieConfig {
        &self.flow
    }
}

/// Validated host-only primary session cookie configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionCookieConfig {
    name: String,
    path: String,
    max_age_secs: u64,
    secure: bool,
    same_site: SameSite,
    clear_header: HeaderValue,
}

impl SessionCookieConfig {
    /// Build production cookie policy from validated service session policy.
    pub fn production(policy: &MagicLinkServiceConfig) -> Result<Self, MagicLinkConfigError> {
        let max_age = policy.session_max_age()?;
        Ok(Self {
            name: DEFAULT_SESSION_COOKIE_NAME.to_owned(),
            path: DEFAULT_SESSION_COOKIE_PATH.to_owned(),
            max_age_secs: max_age.idle_secs,
            secure: true,
            same_site: SameSite::Lax,
            clear_header: HeaderValue::from_static(DEFAULT_SESSION_CLEAR_HEADER),
        })
    }

    /// Build explicit local-HTTP cookie policy from validated service policy.
    pub fn local_development(
        policy: &MagicLinkServiceConfig,
    ) -> Result<Self, MagicLinkConfigError> {
        let mut config = Self::production(policy)?;
        config.secure = false;
        config.clear_header = HeaderValue::from_static(DEFAULT_SESSION_CLEAR_HEADER_INSECURE);
        Ok(config)
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self, CookieConfigError> {
        let name = name.into();
        validate_cookie_name(&name)?;
        self.name = name;
        self.rebuild_clear_header()?;
        Ok(self)
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Result<Self, CookieConfigError> {
        let path = path.into();
        validate_cookie_path(&path)?;
        self.path = path;
        self.rebuild_clear_header()?;
        Ok(self)
    }

    pub fn with_same_site(mut self, same_site: SameSite) -> Result<Self, CookieConfigError> {
        if same_site == SameSite::None && !self.secure {
            return Err(CookieConfigError::SameSiteNoneRequiresSecure);
        }
        self.same_site = same_site;
        self.rebuild_clear_header()?;
        Ok(self)
    }

    fn rebuild_clear_header(&mut self) -> Result<(), CookieConfigError> {
        self.clear_header =
            build_clear_cookie_header(&self.name, &self.path, self.secure, self.same_site)?;
        Ok(())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    #[must_use]
    pub fn secure(&self) -> bool {
        self.secure
    }

    #[must_use]
    pub fn same_site(&self) -> SameSite {
        self.same_site
    }
}

/// Setup-validated same-origin redirect target.
///
/// Only canonical ASCII relative request targets with an absolute path are
/// accepted. The `Location` header is constructed during setup, before any
/// authentication transaction can commit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SameOriginRedirect {
    value: String,
    location: HeaderValue,
}

impl SameOriginRedirect {
    pub fn parse(value: impl Into<String>) -> Result<Self, MagicLinkHttpError> {
        let value = value.into();
        if !is_safe_same_origin_path(&value) {
            return Err(MagicLinkHttpError::BadRequest);
        }
        let uri = value
            .parse::<axum::http::Uri>()
            .map_err(|_| MagicLinkHttpError::BadRequest)?;
        if uri.scheme().is_some()
            || uri.authority().is_some()
            || uri
                .path_and_query()
                .is_none_or(|path_and_query| path_and_query.as_str() != value)
        {
            return Err(MagicLinkHttpError::BadRequest);
        }
        let location = HeaderValue::from_str(&value).map_err(|_| MagicLinkHttpError::BadRequest)?;
        Ok(Self { value, location })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    fn location_header(&self) -> HeaderValue {
        self.location.clone()
    }
}

/// Typed setup failures for the deliberately narrow Origin grammar.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OriginConfigError {
    InvalidScheme,
    InvalidAuthority,
    InvalidHost,
    InvalidPort,
    NonCanonical,
    InvalidHeaderValue,
}

impl fmt::Display for OriginConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidScheme => "invalid origin scheme",
            Self::InvalidAuthority => "invalid origin authority",
            Self::InvalidHost => "invalid origin host",
            Self::InvalidPort => "invalid origin port",
            Self::NonCanonical => "origin is not canonical",
            Self::InvalidHeaderValue => "origin is not a valid header value",
        })
    }
}

impl std::error::Error for OriginConfigError {}

/// Exact same-origin POST policy using a deliberately narrow canonical grammar.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SameOriginPostConfig {
    expected_origin: HeaderValue,
}

impl SameOriginPostConfig {
    pub fn parse(value: &str) -> Result<Self, OriginConfigError> {
        validate_origin(value)?;
        let expected_origin =
            HeaderValue::from_str(value).map_err(|_| OriginConfigError::InvalidHeaderValue)?;
        Ok(Self { expected_origin })
    }

    #[must_use]
    pub fn expected_origin(&self) -> &HeaderValue {
        &self.expected_origin
    }
}

/// Typed scanner-flow setup failures.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkScannerFlowConfigError {
    DuplicateCookieName,
    FlowCookiePathDoesNotCoverPostAction,
}

impl fmt::Display for MagicLinkScannerFlowConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DuplicateCookieName => "scanner cookie names must be pairwise distinct",
            Self::FlowCookiePathDoesNotCoverPostAction => {
                "flow cookie path does not cover confirmation action"
            }
        })
    }
}

impl std::error::Error for MagicLinkScannerFlowConfigError {}

/// Fully validated scanner-safe HTTP configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MagicLinkScannerFlowConfig {
    post_action: SameOriginRedirect,
    success_redirect: SameOriginRedirect,
    same_origin_post: SameOriginPostConfig,
    session_cookie: SessionCookieConfig,
    temporary_cookies: AuthFlowCookieConfig,
}

impl MagicLinkScannerFlowConfig {
    pub fn new(
        post_action: SameOriginRedirect,
        success_redirect: SameOriginRedirect,
        same_origin_post: SameOriginPostConfig,
        session_cookie: SessionCookieConfig,
        temporary_cookies: AuthFlowCookieConfig,
    ) -> Result<Self, MagicLinkScannerFlowConfigError> {
        let flow_name = temporary_cookies.flow().name();
        if session_cookie.name() == flow_name {
            return Err(MagicLinkScannerFlowConfigError::DuplicateCookieName);
        }
        let request_path = post_action
            .as_str()
            .split_once('?')
            .map_or(post_action.as_str(), |(path, _)| path);
        if !cookie_path_covers(temporary_cookies.flow().path(), request_path) {
            return Err(MagicLinkScannerFlowConfigError::FlowCookiePathDoesNotCoverPostAction);
        }
        Ok(Self {
            post_action,
            success_redirect,
            same_origin_post,
            session_cookie,
            temporary_cookies,
        })
    }

    #[must_use]
    pub fn post_action(&self) -> &SameOriginRedirect {
        &self.post_action
    }

    #[must_use]
    pub fn success_redirect(&self) -> &SameOriginRedirect {
        &self.success_redirect
    }

    #[must_use]
    pub fn same_origin_post(&self) -> &SameOriginPostConfig {
        &self.same_origin_post
    }

    #[must_use]
    pub fn session_cookie(&self) -> &SessionCookieConfig {
        &self.session_cookie
    }

    #[must_use]
    pub fn temporary_cookies(&self) -> &AuthFlowCookieConfig {
        &self.temporary_cookies
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

/// Extract a unique CloudFront viewer country as ISO 3166-1 alpha-2.
#[must_use]
pub fn viewer_country(headers: &HeaderMap) -> Option<String> {
    let name = HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY);
    let value = unique_header_str(headers, name)?;
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

/// Create a host-only session `Set-Cookie` value.
pub fn session_set_cookie_header(
    config: &SessionCookieConfig,
    token: &str,
) -> Result<HeaderValue, MagicLinkHttpError> {
    if !is_valid_cookie_value(token) {
        return Err(MagicLinkHttpError::Internal);
    }
    cookie_header(
        config.name(),
        token,
        config.path(),
        config.secure(),
        config.same_site(),
        Some(config.max_age_secs()),
        false,
    )
}

/// The byte-for-byte attribute-parity session clear header.
///
/// Precomputed when the config is constructed; this is a cheap refcounted
/// clone, not a per-response format-and-parse.
#[must_use]
pub fn clear_session_cookie_header(config: &SessionCookieConfig) -> HeaderValue {
    config.clear_header.clone()
}

/// Create a temporary auth-cookie set header with a lifetime in
/// `1..=`[`MagicLinkFlowCookie::MAX_ABSOLUTE_AGE_SECS`] (the flow-cookie cap
/// owned by the service layer).
pub fn set_temporary_cookie_header(
    config: &TemporaryCookieConfig,
    value: &str,
    max_age_secs: u64,
) -> Result<HeaderValue, MagicLinkHttpError> {
    if max_age_secs == 0
        || max_age_secs > MagicLinkFlowCookie::MAX_ABSOLUTE_AGE_SECS
        || !is_valid_cookie_value(value)
    {
        return Err(MagicLinkHttpError::Internal);
    }
    cookie_header(
        config.name(),
        value,
        config.path(),
        config.secure(),
        config.same_site(),
        Some(max_age_secs),
        false,
    )
}

/// The byte-for-byte attribute-parity temporary auth-cookie clear header.
///
/// Precomputed when the config is constructed; this is a cheap refcounted
/// clone, not a per-response format-and-parse.
#[must_use]
pub fn clear_temporary_cookie_header(config: &TemporaryCookieConfig) -> HeaderValue {
    config.clear_header.clone()
}

/// Handle a JSON magic-link request with a generic public response.
pub async fn handle_magic_link_request_json<F, Fut>(request: Request, handle: F) -> Response
where
    F: FnOnce(RequestMagicLinkCommand) -> Fut,
    Fut: Future<Output = Result<RequestMagicLinkOutcome, MagicLinkServiceError>>,
{
    match handle_magic_link_request_json_inner(request, handle).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn handle_magic_link_request_json_inner<F, Fut>(
    request: Request,
    handle: F,
) -> Result<Response, MagicLinkHttpError>
where
    F: FnOnce(RequestMagicLinkCommand) -> Fut,
    Fut: Future<Output = Result<RequestMagicLinkOutcome, MagicLinkServiceError>>,
{
    let guarded = guarded_body(request, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES).await?;
    let command = parse_magic_link_request_json(&guarded.bytes)?;
    handle(command).await.map_err(MagicLinkHttpError::from)?;
    Ok(generic_accepted_response())
}

/// Scanner-safe landing handler. The mandatory deployment logging gate described
/// in the crate documentation applies before this handler can be production-ready.
pub async fn handle_magic_link_landing<F, Fut>(
    request: Request,
    config: &MagicLinkScannerFlowConfig,
    begin: F,
) -> Response
where
    F: FnOnce(BeginMagicLinkLandingCommand) -> Fut,
    Fut: Future<Output = Result<BeginMagicLinkLandingOutcome, MagicLinkFlowError>>,
{
    let raw_token = match extract_landing_token(request.uri().query()) {
        Ok(token) => token.into_string(),
        Err(_) => String::new(),
    };
    let command = BeginMagicLinkLandingCommand::new(raw_token);
    match begin(command).await {
        Ok(outcome) => valid_landing_response(&outcome, config),
        Err(error) => landing_error_response(error, config),
    }
}

/// Scanner-safe confirmation handler. Origin is enforced before cookie, body, or
/// service work.
pub async fn handle_magic_link_confirmation<F, Fut>(
    request: Request,
    config: &MagicLinkScannerFlowConfig,
    confirm: F,
) -> Response
where
    F: FnOnce(ConfirmMagicLinkFlowCommand) -> Fut,
    Fut: Future<Output = Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError>>,
{
    if !request_is_same_origin(request.headers(), config.same_origin_post()) {
        return scanner_plain_response(
            StatusCode::FORBIDDEN,
            "Forbidden.\n",
            config,
            ClearMode::None,
        );
    }

    let flow_cookie =
        match extract_target_cookie(request.headers(), config.temporary_cookies().flow().name()) {
            Ok(value) => value,
            Err(_) => return terminal_invalid_confirmation(config),
        };

    let guarded = match guarded_body(
        request,
        &[APPLICATION_JSON, FORM_URLENCODED],
        MAX_MAGIC_LINK_BODY_BYTES,
    )
    .await
    {
        Ok(guarded) => guarded,
        Err(_) => return terminal_invalid_confirmation(config),
    };
    let mut body: MagicLinkConfirmationBody = if guarded.is_json {
        match serde_json::from_slice(&guarded.bytes) {
            Ok(body) => body,
            Err(_) => return terminal_invalid_confirmation(config),
        }
    } else {
        match serde_urlencoded::from_bytes(&guarded.bytes) {
            Ok(body) => body,
            Err(_) => return terminal_invalid_confirmation(config),
        }
    };
    let country = viewer_country(&guarded.headers).or_else(|| body.country.take());
    let confirmation = core::mem::take(&mut body.confirmation);
    let command = match ConfirmMagicLinkFlowCommand::new(flow_cookie, confirmation, country) {
        Ok(command) => command,
        Err(_) => return terminal_invalid_confirmation(config),
    };
    match confirm(command).await {
        Ok(outcome) => confirmation_success_response(&outcome, config),
        Err(error) => confirmation_error_response(error, config),
    }
}

/// Redacted, zeroized incoming primary session cookie.
pub struct SessionCookieValue(String);

impl SessionCookieValue {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionCookieValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCookieValue(..)")
    }
}

impl Drop for SessionCookieValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SessionHttpError {
    Unauthorized,
    Unavailable,
    Internal,
}

/// Opaque redacted rejection returned by [`authenticate_session`].
pub struct SessionAuthRejection {
    disposition: SessionHttpError,
    clear_cookie: Option<HeaderValue>,
}

impl fmt::Debug for SessionAuthRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionAuthRejection(..)")
    }
}

impl IntoResponse for SessionAuthRejection {
    fn into_response(self) -> Response {
        let error = match self.disposition {
            SessionHttpError::Unauthorized => MagicLinkHttpError::Forbidden,
            SessionHttpError::Unavailable => MagicLinkHttpError::Unavailable,
            SessionHttpError::Internal => MagicLinkHttpError::Internal,
        };
        let status = match self.disposition {
            SessionHttpError::Unauthorized => StatusCode::UNAUTHORIZED,
            SessionHttpError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            SessionHttpError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let mut response = (status, Json(ErrorBody::from(error))).into_response();
        if let Some(clear) = self.clear_cookie {
            response.headers_mut().append(SET_COOKIE, clear);
        }
        response
    }
}

/// Authenticate a unique, strictly parsed incoming session cookie.
///
/// Missing, empty, malformed, quoted, oversized, or duplicate cookies return the
/// same `401` response and do not invoke `validate`.
pub async fn authenticate_session<F, Fut>(
    headers: &HeaderMap,
    cookie_config: &SessionCookieConfig,
    validate: F,
) -> Result<ValidatedSession, SessionAuthRejection>
where
    F: FnOnce(SessionCookieValue) -> Fut,
    Fut: Future<Output = Result<ValidatedSession, SessionValidationError>>,
{
    let value = match extract_target_cookie(headers, cookie_config.name()) {
        Ok(value) => value,
        Err(_) => return Err(session_unauthorized(cookie_config)),
    };
    match validate(SessionCookieValue(value)).await {
        Ok(session) => Ok(session),
        Err(SessionValidationError::InvalidSession) => Err(session_unauthorized(cookie_config)),
        Err(SessionValidationError::Unavailable) => Err(SessionAuthRejection {
            disposition: SessionHttpError::Unavailable,
            clear_cookie: None,
        }),
        Err(SessionValidationError::Internal) => Err(SessionAuthRejection {
            disposition: SessionHttpError::Internal,
            clear_cookie: None,
        }),
    }
}

/// Apply no-store, no-referrer, CSP, and frame-denial headers to scanner results.
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

fn valid_landing_response(
    outcome: &BeginMagicLinkLandingOutcome,
    config: &MagicLinkScannerFlowConfig,
) -> Response {
    build_valid_landing_response(
        outcome.account_identity().as_str(),
        outcome.confirmation_value(),
        outcome.flow_cookie_value(),
        outcome.cookie_max_age_secs(),
        config,
    )
}

fn build_valid_landing_response(
    account_identity: &str,
    confirmation: &str,
    flow_cookie: &str,
    cookie_max_age_secs: u64,
    config: &MagicLinkScannerFlowConfig,
) -> Response {
    let set_cookie = match set_temporary_cookie_header(
        config.temporary_cookies().flow(),
        flow_cookie,
        cookie_max_age_secs,
    ) {
        Ok(header) => header,
        Err(_) => {
            return scanner_plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error.\n",
                config,
                ClearMode::Temporary,
            );
        }
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Confirm sign in</title></head><body><main><h1>Confirm sign in</h1><p>Sign in as <strong>{}</strong>.</p><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"confirmation\" value=\"{}\"><button type=\"submit\">Continue sign in</button></form></main></body></html>",
        escape_html(account_identity),
        escape_html(config.post_action().as_str()),
        escape_html(confirmation),
    );
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().append(SET_COOKIE, set_cookie);
    apply_magic_link_security_headers(response.headers_mut());
    response
}

fn landing_error_response(
    error: MagicLinkFlowError,
    config: &MagicLinkScannerFlowConfig,
) -> Response {
    match error.public_error() {
        MagicLinkServiceError::BadRequest | MagicLinkServiceError::MagicLinkUnavailable => {
            scanner_plain_response(
                StatusCode::OK,
                "Unable to continue sign in.\n",
                config,
                ClearMode::Temporary,
            )
        }
        MagicLinkServiceError::Unavailable => scanner_plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service temporarily unavailable.\n",
            config,
            ClearMode::None,
        ),
        MagicLinkServiceError::Internal => scanner_plain_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error.\n",
            config,
            ClearMode::Temporary,
        ),
    }
}

fn confirmation_success_response(
    outcome: &ConfirmMagicLinkFlowOutcome,
    config: &MagicLinkScannerFlowConfig,
) -> Response {
    build_confirmation_success_response(outcome.authentication().session_cookie_value(), config)
}

fn build_confirmation_success_response(
    session_cookie: &str,
    config: &MagicLinkScannerFlowConfig,
) -> Response {
    let session = match session_set_cookie_header(config.session_cookie(), session_cookie) {
        Ok(header) => header,
        Err(_) => {
            return scanner_plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error.\n",
                config,
                ClearMode::Temporary,
            );
        }
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response
        .headers_mut()
        .insert(LOCATION, config.success_redirect().location_header());
    response.headers_mut().append(SET_COOKIE, session);
    append_temporary_clears(response.headers_mut(), config.temporary_cookies());
    apply_magic_link_security_headers(response.headers_mut());
    response
}

fn confirmation_error_response(
    error: MagicLinkFlowError,
    config: &MagicLinkScannerFlowConfig,
) -> Response {
    match (error.public_error(), error.temporary_state_action()) {
        (
            MagicLinkServiceError::BadRequest | MagicLinkServiceError::MagicLinkUnavailable,
            TemporaryAuthStateAction::Clear,
        ) => terminal_invalid_confirmation(config),
        (MagicLinkServiceError::Unavailable, TemporaryAuthStateAction::Preserve) => {
            scanner_plain_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service temporarily unavailable.\n",
                config,
                ClearMode::None,
            )
        }
        _ => scanner_plain_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error.\n",
            config,
            ClearMode::Temporary,
        ),
    }
}

fn terminal_invalid_confirmation(config: &MagicLinkScannerFlowConfig) -> Response {
    scanner_plain_response(
        StatusCode::BAD_REQUEST,
        TERMINAL_INVALID_BODY,
        config,
        ClearMode::Temporary,
    )
}

#[derive(Clone, Copy)]
enum ClearMode {
    None,
    Temporary,
}

fn scanner_plain_response(
    status: StatusCode,
    body: &'static str,
    config: &MagicLinkScannerFlowConfig,
    clear_mode: ClearMode,
) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    apply_magic_link_security_headers(response.headers_mut());
    if matches!(clear_mode, ClearMode::Temporary) {
        append_temporary_clears(response.headers_mut(), config.temporary_cookies());
    }
    response
}

fn append_temporary_clears(headers: &mut HeaderMap, config: &AuthFlowCookieConfig) {
    headers.append(SET_COOKIE, clear_temporary_cookie_header(config.flow()));
}

fn session_unauthorized(config: &SessionCookieConfig) -> SessionAuthRejection {
    SessionAuthRejection {
        disposition: SessionHttpError::Unauthorized,
        clear_cookie: Some(clear_session_cookie_header(config)),
    }
}

fn extract_landing_token(query: Option<&str>) -> Result<MagicLinkLandingToken, MagicLinkHttpError> {
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
    if value.len() > MAX_RAW_MAGIC_LINK_TOKEN_BYTES || value.contains('=') {
        return Err(MagicLinkHttpError::BadRequest);
    }
    MagicLinkLandingToken::new(value.to_owned())
}

fn request_is_same_origin(headers: &HeaderMap, config: &SameOriginPostConfig) -> bool {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return false;
    };
    if origins.next().is_some() || origin != config.expected_origin() {
        return false;
    }
    let mut fetch_values = headers.get_all(SEC_FETCH_SITE).iter();
    let Some(fetch) = fetch_values.next() else {
        return true;
    };
    fetch_values.next().is_none() && fetch.as_bytes() == b"same-origin"
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CookieParseError {
    Missing,
    Malformed,
    Duplicate,
    Oversized,
}

fn extract_target_cookie(
    headers: &HeaderMap,
    target_name: &str,
) -> Result<String, CookieParseError> {
    let mut field_count = 0usize;
    let mut aggregate = 0usize;
    let mut selected: Option<String> = None;
    for field in headers.get_all(COOKIE).iter() {
        field_count = field_count
            .checked_add(1)
            .ok_or(CookieParseError::Oversized)?;
        if field_count > MAX_COOKIE_HEADER_FIELDS {
            return Err(CookieParseError::Oversized);
        }
        let bytes = field.as_bytes();
        aggregate = aggregate
            .checked_add(bytes.len())
            .ok_or(CookieParseError::Oversized)?;
        if aggregate > MAX_COOKIE_HEADER_BYTES || !bytes.is_ascii() {
            return Err(CookieParseError::Oversized);
        }
        for raw_pair in bytes.split(|byte| *byte == b';') {
            let pair = trim_cookie_pair(raw_pair);
            if pair.is_empty() {
                return Err(CookieParseError::Malformed);
            }
            let Some(equals) = pair.iter().position(|byte| *byte == b'=') else {
                return Err(CookieParseError::Malformed);
            };
            let name = &pair[..equals];
            let value = &pair[equals + 1..];
            if !is_cookie_pair_name(name) || !value.iter().copied().all(is_cookie_octet) {
                return Err(CookieParseError::Malformed);
            }
            if name == target_name.as_bytes() {
                if selected.is_some() {
                    return Err(CookieParseError::Duplicate);
                }
                if value.is_empty()
                    || value.len() > MAX_SELECTED_COOKIE_VALUE_BYTES
                    || value.first() == Some(&b'"')
                {
                    return Err(if value.len() > MAX_SELECTED_COOKIE_VALUE_BYTES {
                        CookieParseError::Oversized
                    } else {
                        CookieParseError::Malformed
                    });
                }
                let value = core::str::from_utf8(value)
                    .map_err(|_| CookieParseError::Malformed)?
                    .to_owned();
                selected = Some(value);
            }
        }
    }
    selected.ok_or(CookieParseError::Missing)
}

fn trim_cookie_pair(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_cookie_pair_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().copied().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

fn validate_origin(value: &str) -> Result<(), OriginConfigError> {
    if value.is_empty()
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(OriginConfigError::InvalidAuthority);
    }
    let (scheme, authority) = value
        .split_once("://")
        .ok_or(OriginConfigError::InvalidScheme)?;
    if scheme != "http" && scheme != "https" {
        return Err(OriginConfigError::InvalidScheme);
    }
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'/' | b'?' | b'#' | b',' | b'%' | b'@' | b'[' | b']' | b'\\'
                )
        })
    {
        return Err(OriginConfigError::InvalidAuthority);
    }
    let colon_count = authority.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return Err(OriginConfigError::InvalidAuthority);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    validate_origin_host(host)?;
    if let Some(port) = port {
        validate_origin_port(scheme, port)?;
    }
    Ok(())
}

fn validate_origin_host(host: &str) -> Result<(), OriginConfigError> {
    if host.is_empty() || host.len() > 253 || host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(OriginConfigError::InvalidHost);
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        let octets: Vec<&str> = host.split('.').collect();
        if octets.len() != 4 {
            return Err(OriginConfigError::InvalidHost);
        }
        for octet in octets {
            if octet.is_empty()
                || (octet.len() > 1 && octet.starts_with('0'))
                || octet.parse::<u8>().is_err()
            {
                return Err(OriginConfigError::NonCanonical);
            }
        }
        return Ok(());
    }
    if host.ends_with('.') {
        return Err(OriginConfigError::NonCanonical);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(OriginConfigError::InvalidHost);
        }
    }
    Ok(())
}

fn validate_origin_port(scheme: &str, port: &str) -> Result<(), OriginConfigError> {
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || (port.len() > 1 && port.starts_with('0'))
    {
        return Err(OriginConfigError::InvalidPort);
    }
    let parsed = port
        .parse::<u16>()
        .map_err(|_| OriginConfigError::InvalidPort)?;
    if parsed == 0 {
        return Err(OriginConfigError::InvalidPort);
    }
    if (scheme == "http" && parsed == 80) || (scheme == "https" && parsed == 443) {
        return Err(OriginConfigError::NonCanonical);
    }
    if parsed.to_string() != port {
        return Err(OriginConfigError::NonCanonical);
    }
    Ok(())
}

fn parse_locale(value: &str) -> Result<EmailLocale, MagicLinkHttpError> {
    match value {
        "en" => Ok(EmailLocale::En),
        "hu" => Ok(EmailLocale::Hu),
        _ => Err(MagicLinkHttpError::BadRequest),
    }
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

fn validate_cookie_name(value: &str) -> Result<(), CookieConfigError> {
    if is_lower_snake_cookie_name(value) {
        Ok(())
    } else {
        Err(CookieConfigError::InvalidName)
    }
}

fn validate_cookie_path(value: &str) -> Result<(), CookieConfigError> {
    if is_valid_cookie_path(value) {
        Ok(())
    } else {
        Err(CookieConfigError::InvalidPath)
    }
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
        && value.len() <= 128
        && !value.contains(['?', '#', '%', '\\', ',', ';'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn is_valid_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SELECTED_COOKIE_VALUE_BYTES
        && value.bytes().all(is_cookie_octet)
        && !value.starts_with('"')
}

/// Build the byte-for-byte clear header for a validated cookie shape. Runs at
/// config-construction time only; responses clone the stored value.
fn build_clear_cookie_header(
    name: &str,
    path: &str,
    secure: bool,
    same_site: SameSite,
) -> Result<HeaderValue, CookieConfigError> {
    // A validated name/path always forms a legal header value, so this error
    // path is unreachable; it maps to the fallible inputs rather than panicking.
    cookie_header(name, "", path, secure, same_site, Some(0), true)
        .map_err(|_| CookieConfigError::InvalidName)
}

fn cookie_header(
    name: &str,
    value: &str,
    path: &str,
    secure: bool,
    same_site: SameSite,
    max_age: Option<u64>,
    clear: bool,
) -> Result<HeaderValue, MagicLinkHttpError> {
    let secure = if secure { "; Secure" } else { "" };
    let max_age = max_age.map_or_else(String::new, |age| format!("; Max-Age={age}"));
    let expires = if clear {
        format!("; Expires={COOKIE_EPOCH}")
    } else {
        String::new()
    };
    let header = format!(
        "{name}={value}; Path={path}; HttpOnly{secure}; SameSite={}{max_age}{expires}",
        same_site.as_cookie_value(),
    );
    HeaderValue::from_str(&header).map_err(|_| MagicLinkHttpError::Internal)
}

fn cookie_path_covers(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path == request_path {
        return true;
    }
    let Some(remainder) = request_path.strip_prefix(cookie_path) else {
        return false;
    };
    cookie_path.ends_with('/') || remainder.starts_with('/')
}

fn is_safe_same_origin_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 2048
        && value.is_ascii()
        && !value.contains('\\')
        && !value.contains("mlv1.")
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && has_well_formed_percent_encoding(value)
}

fn has_well_formed_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(first) = bytes.get(index + 1) else {
                return false;
            };
            let Some(second) = bytes.get(index + 2) else {
                return false;
            };
            if !first.is_ascii_hexdigit() || !second.is_ascii_hexdigit() {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
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

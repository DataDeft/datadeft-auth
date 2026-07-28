//! Scanner-safe magic-link HTTP handlers and their fixed, non-reflective
//! response builders and security headers.

use core::future::Future;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use dd_magic_link_service::{
    BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, MagicLinkFlowError, MagicLinkServiceError,
    RequestMagicLinkCommand, RequestMagicLinkOutcome, TemporaryAuthStateAction,
};

use crate::cookie::{
    TemporaryCookieConfig, clear_temporary_cookie_header, session_set_cookie_header,
    set_temporary_cookie_header,
};
use crate::cookie_parse::extract_target_cookie;
use crate::error::{MagicLinkHttpError, generic_accepted_response};
use crate::extract::{
    APPLICATION_JSON, FORM_URLENCODED, MAX_MAGIC_LINK_BODY_BYTES, MagicLinkConfirmationBody,
    extract_landing_token, guarded_body, parse_magic_link_request_json, viewer_country,
};
use crate::origin::request_is_same_origin;
use crate::scanner_config::MagicLinkScannerFlowConfig;

const CACHE_CONTROL: HeaderName = HeaderName::from_static("cache-control");
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
pub(crate) const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");

const TERMINAL_INVALID_BODY: &str = "Invalid confirmation.\n";

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
        match extract_target_cookie(request.headers(), config.temporary_cookies().name()) {
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
        config.temporary_cookies(),
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

fn append_temporary_clears(headers: &mut HeaderMap, config: &TemporaryCookieConfig) {
    headers.append(SET_COOKIE, clear_temporary_cookie_header(config));
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
#[path = "handlers_tests.rs"]
mod tests;

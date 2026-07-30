//! Scanner-safe magic-link HTTP handlers and their fixed, non-reflective
//! response builders and security headers.

use core::future::Future;

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::{IntoResponse, Response};
use dd_magic_link_service::{
    BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, MagicLinkFlowError, MagicLinkServiceError,
    RequestMagicLinkCommand, RequestMagicLinkOutcome, TemporaryAuthStateAction,
};

use crate::cookie::{clear_flow_cookie_header, session_set_cookie_header, set_flow_cookie_header};
use crate::cookie_parse::extract_target_cookie;
use crate::error::{MagicLinkHttpError, generic_accepted_response};
use crate::extract::{
    APPLICATION_JSON, FORM_URLENCODED, MAX_MAGIC_LINK_BODY_BYTES, MagicLinkConfirmationBody,
    extract_landing_token, guarded_body, parse_magic_link_request_json, viewer_country_from,
};
use crate::origin::request_is_same_origin;
use crate::scanner_config::MagicLinkScannerFlowConfig;

const CACHE_CONTROL: HeaderName = HeaderName::from_static("cache-control");
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
pub(crate) const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");

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

/// Successful scanner-safe landing.
///
/// Carries the validated flow state to present (account identity + confirmation
/// value) and the `Set-Cookie` header for the short-lived flow cookie. The
/// caller renders the page/JSON and attaches [`flow_cookie`](Self::flow_cookie).
pub struct MagicLinkLanding {
    /// The validated landing outcome (account identity, confirmation value).
    pub outcome: BeginMagicLinkLandingOutcome,
    /// `Set-Cookie` value for the encrypted, short-lived flow cookie. Attach it
    /// to the landing response.
    pub flow_cookie: HeaderValue,
}

/// Why a scanner-safe landing or confirmation did not succeed.
///
/// The variants map to responses the caller produces:
///
/// - [`Rejected`](Self::Rejected): the request was malformed, or the link was
///   invalid/expired/already-used. Respond **uniformly** so link validity is
///   not enumerable — for a landing, use the **same HTTP status you return on
///   success**; for a confirmation, a single generic failure. On confirmation,
///   clear the flow cookie with [`clear_flow_cookie_header`].
/// - [`Unavailable`](Self::Unavailable): a dependency was down. Respond 503 and
///   **preserve** the flow cookie so the user can retry.
/// - [`Internal`](Self::Internal): an internal error. Respond 500; clearing the
///   flow cookie on confirmation is fine.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkFlowResponseError {
    Rejected,
    Unavailable,
    Internal,
}

/// Run the scanner-safe landing: extract the token, validate it via `begin`,
/// and prepare the flow cookie. **The landing is side-effect-free** — it does
/// not consume the magic link or create a session, so email security scanners
/// may fetch the landing URL repeatedly without burning the link. The caller
/// owns the response: a typical API returns JSON `{ account, confirmation }`
/// with [`flow_cookie`](MagicLinkLanding::flow_cookie) attached and lets the
/// browser POST the confirmation back same-origin.
///
/// On [`MagicLinkFlowResponseError::Rejected`], respond with the **same HTTP
/// status you use for success** so a caller cannot probe link validity. The
/// mandatory deployment logging gate in the crate docs applies before this is
/// production-ready.
pub async fn magic_link_landing<F, Fut>(
    request: Request,
    config: &MagicLinkScannerFlowConfig,
    begin: F,
) -> Result<MagicLinkLanding, MagicLinkFlowResponseError>
where
    F: FnOnce(BeginMagicLinkLandingCommand) -> Fut,
    Fut: Future<Output = Result<BeginMagicLinkLandingOutcome, MagicLinkFlowError>>,
{
    let raw_token = extract_landing_token(request.uri().query()).unwrap_or_default();
    let outcome = begin(BeginMagicLinkLandingCommand::new(raw_token))
        .await
        .map_err(map_flow_error)?;
    let flow_cookie = set_flow_cookie_header(
        config.flow_cookie(),
        outcome.flow_cookie_value(),
        outcome.cookie_max_age_secs(),
    )
    .map_err(|_| MagicLinkFlowResponseError::Internal)?;
    Ok(MagicLinkLanding {
        outcome,
        flow_cookie,
    })
}

/// Successful scanner-safe confirmation.
///
/// The magic link is consumed and the session is minted. Attach both cookie
/// headers to the response, then respond however the app prefers (a 303 to a
/// post-login page, a 200/204 for an SPA, etc.).
pub struct MagicLinkConfirmed {
    /// The authentication outcome (created/existing user, session).
    pub outcome: ConfirmMagicLinkFlowOutcome,
    /// `Set-Cookie` value that installs the session cookie.
    pub session_cookie: HeaderValue,
    /// `Set-Cookie` value that clears the now-spent flow cookie. Attach it too.
    pub clear_flow_cookie: HeaderValue,
}

/// Run the scanner-safe confirmation gauntlet: enforce same-origin, extract the
/// flow cookie, bound and parse the body, read the trusted-edge country, then
/// consume the link via `confirm`. **This is the only step that consumes the
/// magic link and mints a session, and it only runs for a same-origin POST.**
/// The caller maps the result to its own response and attaches the cookie
/// headers on success.
pub async fn magic_link_confirmation<F, Fut>(
    request: Request,
    config: &MagicLinkScannerFlowConfig,
    confirm: F,
) -> Result<MagicLinkConfirmed, MagicLinkFlowResponseError>
where
    F: FnOnce(ConfirmMagicLinkFlowCommand) -> Fut,
    Fut: Future<Output = Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError>>,
{
    if !request_is_same_origin(request.headers(), config.same_origin_post()) {
        return Err(MagicLinkFlowResponseError::Rejected);
    }

    let flow_cookie = extract_target_cookie(request.headers(), config.flow_cookie().name())
        .map_err(|_| MagicLinkFlowResponseError::Rejected)?;

    let guarded = guarded_body(
        request,
        &[APPLICATION_JSON, FORM_URLENCODED],
        MAX_MAGIC_LINK_BODY_BYTES,
    )
    .await
    .map_err(|_| MagicLinkFlowResponseError::Rejected)?;

    let mut body: MagicLinkConfirmationBody = if guarded.is_json {
        serde_json::from_slice(&guarded.bytes).map_err(|_| MagicLinkFlowResponseError::Rejected)?
    } else {
        serde_urlencoded::from_bytes(&guarded.bytes)
            .map_err(|_| MagicLinkFlowResponseError::Rejected)?
    };

    // Country comes only from the configured trusted-edge header — never from
    // request bodies (client-controlled).
    let country = viewer_country_from(&guarded.headers, config.country_header());
    let confirmation = core::mem::take(&mut body.confirmation);
    let command = ConfirmMagicLinkFlowCommand::new(flow_cookie, confirmation, country)
        .map_err(|_| MagicLinkFlowResponseError::Rejected)?;

    let outcome = confirm(command).await.map_err(map_flow_error)?;

    let session_cookie = session_set_cookie_header(
        config.session_cookie(),
        outcome.authentication().session_cookie_value(),
    )
    .map_err(|_| MagicLinkFlowResponseError::Internal)?;
    let clear_flow_cookie = clear_flow_cookie_header(config.flow_cookie());

    Ok(MagicLinkConfirmed {
        outcome,
        session_cookie,
        clear_flow_cookie,
    })
}

fn map_flow_error(error: MagicLinkFlowError) -> MagicLinkFlowResponseError {
    match (error.public_error(), error.temporary_state_action()) {
        (
            MagicLinkServiceError::BadRequest | MagicLinkServiceError::MagicLinkUnavailable,
            TemporaryAuthStateAction::Clear,
        ) => MagicLinkFlowResponseError::Rejected,
        (MagicLinkServiceError::Unavailable, TemporaryAuthStateAction::Preserve) => {
            MagicLinkFlowResponseError::Unavailable
        }
        _ => MagicLinkFlowResponseError::Internal,
    }
}

/// Apply no-store, no-referrer, CSP, and frame-denial headers to scanner-safe
/// responses. Callers that render their own landing/confirmation pages should
/// stamp these onto every such response.
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

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;

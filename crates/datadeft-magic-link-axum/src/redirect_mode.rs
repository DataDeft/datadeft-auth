//! The redirect landing mode (CeleraTax #2): for apps that serve their UI as
//! static files, so the confirm page cannot be rendered by the server.
//!
//! 1. `GET /…/landing?token=…` → [`magic_link_landing_redirect`]: validates
//!    the link without consuming it, sets the `HttpOnly` confirm cookie, and
//!    answers `303` to the configured static page. Every outcome redirects to
//!    the same page with no token material in `Location`; an unusable link
//!    gets a cookie-clearing header instead of a cookie.
//! 2. The static page `GET`s the flow-state route → [`magic_link_flow_state`]:
//!    `{ "usable": true, "account": …, "confirmation": … }` from the confirm
//!    cookie, or `{ "usable": false }` for any missing, invalid, expired or
//!    used cookie. Repeatable and read-only.
//! 3. The page shows the account and `POST`s `{ confirmation }` same-origin to
//!    the confirmation route, exactly as in the server-rendered mode.
//!
//! The token never reaches JavaScript; the confirmation value does, so the
//! static page must follow the landing-page rules: a strict CSP, no
//! third-party scripts or analytics.

use core::future::Future;

use axum::Json;
use axum::extract::Request;
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use datadeft_magic_link_service::{
    BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome, MagicLinkFlowError,
    MagicLinkFlowState, ReadMagicLinkFlowStateCommand,
};
use serde::Serialize;

use crate::cookie::clear_confirm_cookie_header;
use crate::cookie_parse::extract_target_cookie;
use crate::error::MagicLinkHttpError;
use crate::handlers::{
    MagicLinkFlowResponseError, SEC_FETCH_SITE, apply_magic_link_security_headers,
    magic_link_landing, map_flow_error,
};
use crate::scanner_config::MagicLinkScannerFlowConfig;

const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

/// Landing of the redirect mode: always `303` to the configured page, or the
/// constant `503` when a dependency is down. Needs
/// [`MagicLinkScannerFlowConfig::with_redirect_landing`]; without it the
/// response is the constant `503`.
pub async fn magic_link_landing_redirect<F, Fut>(
    request: Request,
    config: &MagicLinkScannerFlowConfig,
    begin: F,
) -> Response
where
    F: FnOnce(BeginMagicLinkLandingCommand) -> Fut,
    Fut: Future<Output = Result<BeginMagicLinkLandingOutcome, MagicLinkFlowError>>,
{
    let Some(redirect) = config.redirect_landing() else {
        return MagicLinkHttpError::Internal.into_response();
    };
    let Ok(location) = HeaderValue::from_str(redirect.page().as_str()) else {
        return MagicLinkHttpError::Internal.into_response();
    };
    let set_cookie = match magic_link_landing(request, config, begin).await {
        Ok(landing) => landing.confirm_cookie,
        // Same status and Location as success: the redirect itself does not
        // tell link states apart.
        Err(MagicLinkFlowResponseError::Rejected) => {
            clear_confirm_cookie_header(config.confirm_cookie())
        }
        Err(MagicLinkFlowResponseError::Unavailable) => {
            return MagicLinkHttpError::Unavailable.into_response();
        }
        Err(MagicLinkFlowResponseError::Internal) => {
            return MagicLinkHttpError::Internal.into_response();
        }
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    headers.insert(LOCATION, location);
    headers.append(SET_COOKIE, set_cookie);
    apply_magic_link_security_headers(headers);
    response
}

/// Flow-state body. `account` and `confirmation` are present only when
/// `usable`.
#[derive(Serialize)]
struct FlowStateBody<'a> {
    usable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmation: Option<&'a str>,
}

/// Flow-state route of the redirect mode (`GET`). Same-origin only: a request
/// without exactly `Sec-Fetch-Site: same-origin` is treated as unusable, and
/// no CORS headers are sent. Answers `no-store` with the
/// landing's security headers and `Cross-Origin-Resource-Policy: same-origin`.
/// A dependency failure is the constant `503` (retry later); every other
/// failure is the one `{ "usable": false }` answer, which also clears the
/// cookie.
pub async fn magic_link_flow_state<F, Fut>(
    headers: &HeaderMap,
    config: &MagicLinkScannerFlowConfig,
    read: F,
) -> Response
where
    F: FnOnce(ReadMagicLinkFlowStateCommand) -> Fut,
    Fut: Future<Output = Result<MagicLinkFlowState, MagicLinkFlowError>>,
{
    let cookie = if is_cross_site(headers) {
        None
    } else {
        extract_target_cookie(headers, config.confirm_cookie().name()).ok()
    };
    let state = match cookie {
        Some(cookie) => read(ReadMagicLinkFlowStateCommand::new(cookie))
            .await
            .map_err(map_flow_error),
        None => Err(MagicLinkFlowResponseError::Rejected),
    };
    let mut response = match &state {
        Ok(state) => Json(FlowStateBody {
            usable: true,
            account: Some(state.account_identity().as_str()),
            confirmation: Some(state.confirmation_value()),
        })
        .into_response(),
        Err(MagicLinkFlowResponseError::Rejected) => {
            let mut response = Json(FlowStateBody {
                usable: false,
                account: None,
                confirmation: None,
            })
            .into_response();
            response.headers_mut().append(
                SET_COOKIE,
                clear_confirm_cookie_header(config.confirm_cookie()),
            );
            response
        }
        Err(MagicLinkFlowResponseError::Unavailable) => {
            MagicLinkHttpError::Unavailable.into_response()
        }
        Err(MagicLinkFlowResponseError::Internal) => MagicLinkHttpError::Internal.into_response(),
    };
    let headers = response.headers_mut();
    apply_magic_link_security_headers(headers);
    headers.insert(
        CROSS_ORIGIN_RESOURCE_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Anything but exactly one `Sec-Fetch-Site: same-origin`, including a
/// missing header: every current browser sends it.
fn is_cross_site(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(SEC_FETCH_SITE).iter();
    match values.next() {
        None => true,
        Some(value) => value.as_bytes() != b"same-origin" || values.next().is_some(),
    }
}

#[cfg(test)]
#[path = "redirect_mode_tests.rs"]
mod tests;

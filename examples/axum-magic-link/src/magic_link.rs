//! Magic-link routes: request, scanner-safe landing, and confirmation.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use datadeft_magic_link_axum::{
    APPLICATION_JSON, MagicLinkFlowResponseError, MagicLinkHttpError, MagicLinkRequestJson,
    apply_magic_link_security_headers, clear_confirm_cookie_header, generic_accepted_response,
    guarded_body, magic_link_confirmation, magic_link_landing,
};
use datadeft_magic_link_service::{MagicLinkFlowService, MagicLinkRequestService};
use rand_core::OsRng;
use serde::Deserialize;

use super::pow::{PowSolutionJson, verify_pow_solution};
use super::state::{AppState, LocalClock};
use super::util::escape_html;

pub(super) async fn request_magic_link(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    match request_magic_link_inner(state, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn request_magic_link_inner(
    state: AppState,
    request: Request,
) -> Result<Response, MagicLinkHttpError> {
    let guarded = guarded_body(request, &[APPLICATION_JSON], 4096).await?;
    let body: RequestMagicLinkWithPow =
        serde_json::from_slice(&guarded.bytes).map_err(|_| MagicLinkHttpError::BadRequest)?;
    verify_pow_solution(&state, body.pow).map_err(|_| MagicLinkHttpError::Forbidden)?;
    let command = MagicLinkRequestJson {
        email: body.email,
        terms_accepted: body.terms_accepted,
        privacy_accepted: body.privacy_accepted,
    }
    .into_command()?;

    let mut rng = OsRng;
    let mut service = MagicLinkRequestService {
        magic_links: &state.auth,
        limiter: &state.auth,
        outbox: &state.outbox,
        clock: &LocalClock,
        rng: &mut rng,
        lookup_hmac_key: state.lookup_hmac_key.as_ref(),
        config: state.config.clone(),
    };
    service
        .request_magic_link(command)
        .await
        .map_err(MagicLinkHttpError::from)?;
    Ok(generic_accepted_response())
}

// The landing GET is side-effect-free (the library guarantees it never
// consumes the link), so this application owns the interstitial page. It
// renders the account and a form that POSTs the confirmation back same-origin
// This step consumes the link. Errors are returned with the SAME
// 200 status as success so link validity is not enumerable.
pub(super) async fn landing_route(State(state): State<AppState>, request: Request) -> Response {
    let config = state.http_config.clone();
    let result = magic_link_landing(request, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        let mut service = MagicLinkFlowService {
            authentication: &state.auth,
            sessions: &state.auth,
            limiter: &state.auth,
            clock: &LocalClock,
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            previous_lookup_hmac_key: None,
            confirm_keyring: state.confirm_keyring.as_ref(),
            session_keyring: state.session_keyring.as_ref(),
            config: state.config.clone(),
        };
        service.begin_magic_link_landing(command).await
    })
    .await;

    match result {
        Ok(landing) => {
            let page = format!(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Confirm sign in</title></head><body><main><h1>Confirm sign in</h1><p>Sign in as <strong>{}</strong>.</p><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"confirmation\" value=\"{}\"><button type=\"submit\">Continue sign in</button></form></main></body></html>",
                escape_html(landing.outcome.account_identity().as_str()),
                escape_html(config.post_action().as_str()),
                escape_html(landing.outcome.confirmation_value()),
            );
            let mut response = Html(page).into_response();
            response
                .headers_mut()
                .append(SET_COOKIE, landing.confirm_cookie);
            apply_magic_link_security_headers(response.headers_mut());
            response
        }
        // Same 200 status as success (non-enumeration); dependency/internal
        // failures may use their own status.
        Err(MagicLinkFlowResponseError::Rejected) => scanner_page(
            StatusCode::OK,
            "<!doctype html><h1>Unable to continue sign in</h1><p>Request a new link.</p>",
        ),
        Err(MagicLinkFlowResponseError::Unavailable) => scanner_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service temporarily unavailable.",
        ),
        Err(MagicLinkFlowResponseError::Internal) => {
            scanner_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
        }
    }
}

// The confirmation POST is the only step that consumes the link and mints the
// session. On success this app 303-redirects to /auth/complete with the session
// cookie. An SPA would return JSON instead.
pub(super) async fn confirm_route(State(state): State<AppState>, request: Request) -> Response {
    let config = state.http_config.clone();
    let result = magic_link_confirmation(request, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        let mut service = MagicLinkFlowService {
            authentication: &state.auth,
            sessions: &state.auth,
            limiter: &state.auth,
            clock: &LocalClock,
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            previous_lookup_hmac_key: None,
            confirm_keyring: state.confirm_keyring.as_ref(),
            session_keyring: state.session_keyring.as_ref(),
            config: state.config.clone(),
        };
        service.confirm_magic_link_flow(command).await
    })
    .await;

    match result {
        Ok(confirmed) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SEE_OTHER;
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/auth/complete"));
            response
                .headers_mut()
                .append(SET_COOKIE, confirmed.session_cookie);
            response
                .headers_mut()
                .append(SET_COOKIE, confirmed.clear_confirm_cookie);
            apply_magic_link_security_headers(response.headers_mut());
            response
        }
        Err(MagicLinkFlowResponseError::Rejected) => {
            let mut response = scanner_page(StatusCode::BAD_REQUEST, "Invalid confirmation.");
            response.headers_mut().append(
                SET_COOKIE,
                clear_confirm_cookie_header(config.confirm_cookie()),
            );
            response
        }
        Err(MagicLinkFlowResponseError::Unavailable) => scanner_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service temporarily unavailable.",
        ),
        Err(MagicLinkFlowResponseError::Internal) => {
            scanner_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
        }
    }
}

fn scanner_page(status: StatusCode, body: &'static str) -> Response {
    let mut response = (status, Html(body)).into_response();
    apply_magic_link_security_headers(response.headers_mut());
    response
}

pub(super) async fn auth_complete() -> Html<&'static str> {
    Html(
        "<!doctype html><h1>Signed in</h1><p>The scanner-safe POST completed. Try <a href=\"/me\">/me</a>.</p>",
    )
}

#[derive(Debug, Deserialize)]
struct RequestMagicLinkWithPow {
    email: String,
    terms_accepted: bool,
    privacy_accepted: bool,
    pow: PowSolutionJson,
}

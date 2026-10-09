//! Session routes: the authenticated page with refresh, and logout.

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use datadeft_magic_link_axum::{
    apply_magic_link_security_headers, authenticate_session, clear_session_cookie_header,
    session_set_cookie_header, viewer_country_from,
};
use datadeft_magic_link_service::{MagicLinkFlowService, refresh_session_cookie, validate_session};
use rand_core::OsRng;

use super::state::{AppState, LocalClock};
use super::util::{escape_html, is_same_origin_post};

pub(super) async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth_state = state.clone();
    // Country pinning: pass the trusted-edge signal for this request. Sessions
    // issued without a country are unlocked and ignore it.
    let country = viewer_country_from(&headers, state.http_config.country_header());
    match authenticate_session(
        &headers,
        state.http_config.session_cookie(),
        move |cookie| async move {
            validate_session(
                cookie.as_str(),
                country.as_deref(),
                auth_state.session_keyring.as_ref(),
                &auth_state.auth,
                &LocalClock,
                &auth_state.config,
            )
            .await
        },
    )
    .await
    {
        Ok(session) => {
            let mut response = Html(format!(
                "<!doctype html><h1>Authenticated</h1><p>User: {}</p><p>Email: {}</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Logout</button></form>",
                escape_html(session.session().user_id.as_str()),
                escape_html(session.session().email.as_str()),
            ))
            .into_response();
            // Authenticated pages are never cacheable, and a refreshed bearer
            // cookie must not be stored by any shared cache: no-store et al.
            apply_magic_link_security_headers(response.headers_mut());
            // Sliding session: re-issue the cookie once half the idle lifetime
            // has passed. The absolute lifetime and revocation still apply.
            let mut rng = OsRng;
            match refresh_session_cookie(
                &session,
                state.session_keyring.as_ref(),
                &mut rng,
                &LocalClock,
                &state.config,
            ) {
                Ok(Some(refreshed)) => {
                    match session_set_cookie_header(
                        state.http_config.session_cookie(),
                        refreshed.as_secret_value(),
                    ) {
                        Ok(header) => {
                            response.headers_mut().append(SET_COOKIE, header);
                        }
                        Err(_) => {
                            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
                                .into_response();
                        }
                    }
                }
                // Not due yet: keep the current cookie.
                Ok(None) => {}
                // A failed refresh does not end a valid session, but operators
                // must see it: a lapsed session-key mint window would otherwise
                // silently log everyone out at the idle limit. The error kind
                // carries no secret.
                Err(error) => eprintln!("session refresh failed: {error}"),
            }
            response
        }
        Err(rejection) => rejection.into_response(),
    }
}

pub(super) async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_same_origin_post(&headers) {
        return (StatusCode::FORBIDDEN, "forbidden\n").into_response();
    }

    let auth_state = state.clone();
    let country = viewer_country_from(&headers, state.http_config.country_header());
    let session = match authenticate_session(
        &headers,
        state.http_config.session_cookie(),
        move |cookie| async move {
            validate_session(
                cookie.as_str(),
                country.as_deref(),
                auth_state.session_keyring.as_ref(),
                &auth_state.auth,
                &LocalClock,
                &auth_state.config,
            )
            .await
        },
    )
    .await
    {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };

    let mut rng = OsRng;
    let service = MagicLinkFlowService {
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
    if service
        .revoke_session(&session.session().session_id)
        .await
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "logout unavailable\n").into_response();
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/"));
    response.headers_mut().append(
        SET_COOKIE,
        clear_session_cookie_header(state.http_config.session_cookie()),
    );
    response
}

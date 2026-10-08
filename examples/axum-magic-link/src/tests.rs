//! Logout contract from docs/security.md: logout is a CSRF-protected
//! unsafe method, and it revokes server state before clearing the cookie.

use axum::extract::State;
use axum::http::header::{COOKIE, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use datadeft_magic_link_service::{
    BeginMagicLinkLandingCommand, ConfirmMagicLinkFlowCommand, MagicLinkFlowService,
    MagicLinkRequestService, NormalizedEmail, RequestMagicLinkCommand, SessionRepository,
};
use rand_core::OsRng;

use super::*;
use crate::util::current_unix;

/// Log in through the real services and return the session cookie value.
async fn logged_in(state: &AppState) -> (String, datadeft_magic_link_service::SessionId) {
    let mut rng = OsRng;
    MagicLinkRequestService {
        magic_links: &state.auth,
        limiter: &state.auth,
        outbox: &state.outbox,
        clock: &LocalClock,
        rng: &mut rng,
        lookup_hmac_key: state.lookup_hmac_key.as_ref(),
        config: state.config.clone(),
    }
    .request_magic_link(RequestMagicLinkCommand::new(
        NormalizedEmail::parse("logout-test@example.test").expect("email"),
        true,
        true,
    ))
    .await
    .expect("request");
    let email = state.outbox.recorded().expect("outbox").remove(0);
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
    let landing = service
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(
            email.token.as_secret_value().to_string(),
        ))
        .await
        .expect("landing");
    let outcome = service
        .confirm_magic_link_flow(
            ConfirmMagicLinkFlowCommand::new(
                landing.confirm_cookie_value().to_owned(),
                landing.confirmation_value().to_owned(),
                None,
            )
            .expect("command"),
        )
        .await
        .expect("confirm");
    (
        outcome.authentication().session_cookie_value().to_owned(),
        outcome.authentication().session_id().clone(),
    )
}

fn logout_headers(state: &AppState, cookie: &str, origin: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let name = state.http_config.session_cookie().name();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!("{name}={cookie}")).expect("cookie"),
    );
    if let Some(origin) = origin {
        headers.insert(ORIGIN, HeaderValue::from_str(origin).expect("origin"));
    }
    headers
}

async fn session_is_live(state: &AppState, id: &datadeft_magic_link_service::SessionId) -> bool {
    let now = current_unix().expect("clock");
    state
        .auth
        .find_session(id, now)
        .await
        .expect("find")
        .is_some()
}

#[tokio::test]
async fn logout_without_same_origin_is_forbidden_and_keeps_the_session() {
    let state = build_state().expect("state");
    let (cookie, session_id) = logged_in(&state).await;
    for origin in [None, Some("https://attacker.example.test"), Some("null")] {
        let response = logout(
            State(state.clone()),
            logout_headers(&state, &cookie, origin),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(SET_COOKIE).is_none());
        assert!(session_is_live(&state, &session_id).await);
    }
}

#[tokio::test]
async fn logout_revokes_server_state_and_old_cookie_stops_working() {
    let state = build_state().expect("state");
    let (cookie, session_id) = logged_in(&state).await;

    let response = logout(
        State(state.clone()),
        logout_headers(&state, &cookie, Some(LOCAL_ORIGIN)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cleared = response
        .headers()
        .get(SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("clearing cookie");
    assert!(cleared.contains("Max-Age=0"));
    // Server-side invalidation, not just cookie clearing.
    assert!(!session_is_live(&state, &session_id).await);

    // A captured copy of the old cookie no longer authenticates.
    let replay = logout(
        State(state.clone()),
        logout_headers(&state, &cookie, Some(LOCAL_ORIGIN)),
    )
    .await;
    assert_ne!(replay.status(), StatusCode::SEE_OTHER);
}

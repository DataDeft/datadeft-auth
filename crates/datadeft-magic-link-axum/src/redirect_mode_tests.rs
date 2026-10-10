//! Redirect landing mode: one redirect target, no token in Location, a
//! same-origin read-only flow-state route, and the response contract.

use std::cell::Cell;
use std::rc::Rc;

use axum::body::Body;
use axum::http::Method;
use axum::http::header::{CACHE_CONTROL, COOKIE};

use super::*;
use crate::origin::SameOriginRedirect;
use crate::test_fixtures::{FixtureFlowError, fixture_flow_error, response_parts, scanner_config};

const TOKEN: &str = "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

fn redirect_config() -> MagicLinkScannerFlowConfig {
    scanner_config()
        .with_redirect_landing(
            SameOriginRedirect::parse("/hu/login/confirm").expect("page"),
            SameOriginRedirect::parse("/auth/magic-link/flow-state").expect("flow state"),
        )
        .expect("redirect landing")
}

fn landing_request() -> Request {
    Request::builder()
        .method(Method::GET)
        .uri(format!("/auth/magic-link?token={TOKEN}"))
        .body(Body::empty())
        .expect("request")
}

#[test]
fn the_confirm_cookie_must_cover_the_flow_state_route() {
    assert_eq!(
        scanner_config()
            .with_redirect_landing(
                SameOriginRedirect::parse("/login/confirm").expect("page"),
                SameOriginRedirect::parse("/api/flow-state").expect("outside /auth"),
            )
            .unwrap_err(),
        crate::MagicLinkScannerFlowConfigError::ConfirmCookiePathDoesNotCoverFlowState
    );
    let config = redirect_config();
    let redirect = config.redirect_landing().expect("enabled");
    assert_eq!(redirect.page().as_str(), "/hu/login/confirm");
    assert_eq!(
        redirect.flow_state().as_str(),
        "/auth/magic-link/flow-state"
    );
}

#[tokio::test]
async fn an_unusable_link_redirects_to_the_same_page_and_clears_the_cookie() {
    let config = redirect_config();
    let response = magic_link_landing_redirect(landing_request(), &config, |_command| async {
        Err(fixture_flow_error(FixtureFlowError::MagicLinkUnavailable).await)
    })
    .await;
    let (status, headers, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location");
    assert_eq!(location, "/hu/login/confirm");
    assert!(!location.contains("mlv1"));
    let cookie = headers
        .get(SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("cookie");
    assert!(cookie.starts_with("dd_auth_confirm=;"), "{cookie}");
    assert!(cookie.contains("Max-Age=0"));
    assert_eq!(
        headers.get(CACHE_CONTROL).map(HeaderValue::as_bytes),
        Some(&b"no-store"[..])
    );
    assert!(body.is_empty());
}

#[tokio::test]
async fn landing_outages_and_a_missing_mode_are_the_constant_503() {
    let config = redirect_config();
    let unavailable = magic_link_landing_redirect(landing_request(), &config, |_command| async {
        Err(fixture_flow_error(FixtureFlowError::Unavailable).await)
    })
    .await;
    let internal = magic_link_landing_redirect(landing_request(), &config, |_command| async {
        Err(fixture_flow_error(FixtureFlowError::Internal).await)
    })
    .await;
    let called = Rc::new(Cell::new(false));
    let flag = Rc::clone(&called);
    let unconfigured =
        magic_link_landing_redirect(landing_request(), &scanner_config(), move |_command| {
            flag.set(true);
            async { Err(fixture_flow_error(FixtureFlowError::Internal).await) }
        })
        .await;
    assert!(!called.get(), "no landing work without the mode configured");
    let expected = response_parts(MagicLinkHttpError::Unavailable.into_response()).await;
    for response in [unavailable, internal, unconfigured] {
        assert_eq!(response_parts(response).await, expected);
    }
}

fn flow_state_headers(cookie: Option<&str>, fetch_site: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(cookie) = cookie {
        headers.insert(COOKIE, HeaderValue::from_str(cookie).expect("cookie"));
    }
    if let Some(site) = fetch_site {
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_str(site).expect("site"));
    }
    headers
}

#[tokio::test]
async fn flow_state_without_a_usable_cookie_is_one_generic_answer() {
    let config = redirect_config();
    let unusable = br#"{"usable":false}"#;
    for (name, headers) in [
        ("no cookie", flow_state_headers(None, Some("same-origin"))),
        (
            "no Sec-Fetch-Site",
            flow_state_headers(Some("dd_auth_confirm=value"), None),
        ),
        (
            "cross-site",
            flow_state_headers(Some("dd_auth_confirm=value"), Some("cross-site")),
        ),
        (
            "same-site",
            flow_state_headers(Some("dd_auth_confirm=value"), Some("same-site")),
        ),
    ] {
        let called = Rc::new(Cell::new(false));
        let flag = Rc::clone(&called);
        let response = magic_link_flow_state(&headers, &config, move |_command| {
            flag.set(true);
            async { Err(fixture_flow_error(FixtureFlowError::Internal).await) }
        })
        .await;
        assert!(!called.get(), "{name}: never read");
        let (status, headers, body) = response_parts(response).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_eq!(body, unusable, "{name}");
        assert!(
            headers
                .get(SET_COOKIE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("Max-Age=0")),
            "{name}: clears the cookie"
        );
        assert_eq!(
            headers
                .get(CROSS_ORIGIN_RESOURCE_POLICY)
                .map(HeaderValue::as_bytes),
            Some(&b"same-origin"[..])
        );
        assert!(headers.get("access-control-allow-origin").is_none());
    }

    // A cookie the service rejects gives the same answer.
    let response = magic_link_flow_state(
        &flow_state_headers(Some("dd_auth_confirm=value"), Some("same-origin")),
        &config,
        |_command| async { Err(fixture_flow_error(FixtureFlowError::MagicLinkUnavailable).await) },
    )
    .await;
    let (status, _, body) = response_parts(response).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, &unusable[..]));
}

#[tokio::test]
async fn flow_state_outages_are_the_constant_503() {
    let config = redirect_config();
    let response = magic_link_flow_state(
        &flow_state_headers(Some("dd_auth_confirm=value"), Some("same-origin")),
        &config,
        |_command| async { Err(fixture_flow_error(FixtureFlowError::Unavailable).await) },
    )
    .await;
    let (status, headers, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        headers.get(SET_COOKIE).is_none(),
        "the cookie survives an outage"
    );
    assert_eq!(
        body,
        br#"{"error":"unavailable","message":"The service is temporarily unavailable. Try again later."}"#
    );
}

use std::cell::Cell;
use std::rc::Rc;

use axum::http::header::COOKIE;

use super::*;
use crate::test_fixtures::{policy, response_parts};

#[tokio::test]
async fn session_auth_parser_skips_dependency_on_malformed_input() {
    let config = SessionCookieConfig::production(&policy()).expect("session");
    let mut malformed_headers = Vec::new();
    for cookie in [
        None,
        Some(""),
        Some("dd_session="),
        Some("dd_session=\"quoted\""),
        Some("other=x"),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(cookie) = cookie
            && !cookie.is_empty()
        {
            headers.insert(COOKIE, HeaderValue::from_str(cookie).expect("cookie"));
        }
        malformed_headers.push(headers);
    }
    let mut duplicate = HeaderMap::new();
    duplicate.append(COOKIE, HeaderValue::from_static("dd_session=one"));
    duplicate.append(COOKIE, HeaderValue::from_static("dd_session=two"));
    malformed_headers.push(duplicate);

    let mut fingerprints = Vec::new();
    for headers in malformed_headers {
        let called = Rc::new(Cell::new(false));
        let closure_called = Rc::clone(&called);
        let rejection = authenticate_session(&headers, &config, move |_cookie| {
            closure_called.set(true);
            async { Err(SessionValidationError::Internal) }
        })
        .await
        .expect_err("rejection");
        assert!(!called.get());
        let (status, headers, body) = response_parts(rejection.into_response()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
        fingerprints.push((status, headers, body));
    }
    let first = &fingerprints[0];
    for fingerprint in &fingerprints[1..] {
        assert_eq!(fingerprint, first);
    }
}

#[tokio::test]
async fn session_auth_maps_invalid_unavailable_and_internal_dispositions() {
    let config = SessionCookieConfig::production(&policy()).expect("session");
    let cases = [
        (
            SessionValidationError::InvalidSession,
            StatusCode::UNAUTHORIZED,
            1,
        ),
        (
            SessionValidationError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            0,
        ),
        (
            SessionValidationError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            0,
        ),
    ];
    for (error, status, clear_count) in cases {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("dd_session=secret-cookie"));
        let called = Rc::new(Cell::new(false));
        let closure_called = Rc::clone(&called);
        let rejection = authenticate_session(&headers, &config, move |cookie| {
            closure_called.set(true);
            assert_eq!(cookie.as_str(), "secret-cookie");
            assert!(!format!("{cookie:?}").contains("secret-cookie"));
            async move { Err(error) }
        })
        .await
        .expect_err("rejection");
        assert!(called.get());
        assert_eq!(format!("{rejection:?}"), "SessionAuthRejection(..)");
        let response = rejection.into_response();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get_all(SET_COOKIE).iter().count(),
            clear_count
        );
    }
}

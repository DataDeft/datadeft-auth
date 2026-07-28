use std::cell::Cell;
use std::rc::Rc;

use axum::http::Method;
use axum::http::header::{COOKIE, ORIGIN};

use super::*;
use crate::test_fixtures::{
    FixtureFlowError, fixture_flow_error, post_request, response_parts, scanner_config,
    terminal_fingerprint,
};

fn bad_request_flow_error() -> MagicLinkFlowError {
    ConfirmMagicLinkFlowCommand::new(
        "flow".to_owned(),
        "confirmation".to_owned(),
        Some("invalid-country".to_owned()),
    )
    .expect_err("invalid country")
}

#[tokio::test]
async fn request_handler_preserves_generic_success_regression() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(
            r#"{"email":"user@example.com","locale":"en","terms_accepted":true,"privacy_accepted":true}"#,
        ))
        .expect("request");
    let response = handle_magic_link_request_json(request, |command| async move {
        assert_eq!(command.email().as_str(), "user@example.com");
        Ok(RequestMagicLinkOutcome)
    })
    .await;
    let (status, _, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, br#"{"status":"ok"}"#);
}

#[tokio::test]
async fn unknown_request_field_is_rejected_generically_without_reflection() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(
            r#"{"email":"user@example.com","locale":"en","terms_accepted":true,"privacy_accepted":true,"unexpected":"unknown-value-sentinel"}"#,
        ))
        .expect("request");
    let response = handle_magic_link_request_json(request, |_| async {
        unreachable!("unknown request fields must not reach the service")
    })
    .await;
    let (status, _, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        br#"{"error":"bad_request","message":"Invalid request."}"#
    );
    assert!(
        !body
            .windows(b"unknown-value-sentinel".len())
            .any(|window| window == b"unknown-value-sentinel")
    );
}

#[tokio::test]
async fn valid_landing_html_identifies_and_escapes_account_without_raw_token() {
    let config = scanner_config();
    let response = build_valid_landing_response(
        "user<&>\"'@example.test",
        "confirmation-handle",
        "encrypted-flow-cookie",
        123,
        &config,
    );
    let (status, headers, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
    let set_cookie = headers.get(SET_COOKIE).expect("flow set cookie");
    assert!(
        set_cookie
            .as_bytes()
            .starts_with(b"dd_auth_flow=encrypted-flow-cookie")
    );
    let text = String::from_utf8(body).expect("utf8");
    assert!(text.contains("user&lt;&amp;&gt;&quot;&#39;@example.test"));
    assert!(!text.contains("user<&>\"'@example.test"));
    assert!(text.contains("name=\"confirmation\" value=\"confirmation-handle\""));
    assert_eq!(text.matches("type=\"hidden\"").count(), 1);
    assert!(text.contains("Continue sign in"));
    assert!(!text.contains("name=\"token\""));
    assert!(!text.contains("raw-token-secret"));
    assert!(!text.contains("encrypted-flow-cookie"));
}

#[tokio::test]
async fn request_handler_forwards_false_consent_to_service_behavior() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(
            r#"{"email":"user@example.com","locale":"en","terms_accepted":false,"privacy_accepted":true}"#,
        ))
        .expect("request");
    let response = handle_magic_link_request_json(request, |command| async move {
        assert!(!command.terms_accepted());
        assert!(command.privacy_accepted());
        Err(MagicLinkServiceError::BadRequest)
    })
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_landing_is_non_actionable_and_clears_temporary_state() {
    let config = scanner_config();
    let called = Rc::new(Cell::new(false));
    let closure_called = Rc::clone(&called);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/magic-link?token=not-a-token")
        .body(Body::from("body-must-not-be-read"))
        .expect("request");
    let response = handle_magic_link_landing(request, &config, move |_command| {
        closure_called.set(true);
        async { Err(bad_request_flow_error()) }
    })
    .await;
    assert!(called.get());
    let (status, headers, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).expect("utf8");
    assert!(!text.contains("<form"));
    assert!(!text.contains("confirmation"));
    assert!(!text.contains("not-a-token"));
    assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
    assert!(headers.get("content-security-policy").is_some());
}

#[tokio::test]
async fn origin_rejection_precedes_cookie_body_and_service_and_does_not_clear() {
    let config = scanner_config();
    for setup in ["missing", "mismatch", "duplicate", "bad-fetch"] {
        let called = Rc::new(Cell::new(false));
        let closure_called = Rc::clone(&called);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/auth/magic-link/confirm")
            .header(CONTENT_TYPE, "text/plain")
            .header(COOKIE, "malformed");
        builder = match setup {
            "mismatch" => builder.header(ORIGIN, "https://other.test"),
            "bad-fetch" => builder
                .header(ORIGIN, "https://example.test")
                .header("sec-fetch-site", "same-site"),
            _ => builder,
        };
        let mut request = builder
            .body(Body::from("oversized-not-read"))
            .expect("request");
        if setup == "duplicate" {
            request
                .headers_mut()
                .append(ORIGIN, HeaderValue::from_static("https://example.test"));
            request
                .headers_mut()
                .append(ORIGIN, HeaderValue::from_static("https://example.test"));
        }
        let response = handle_magic_link_confirmation(request, &config, move |_command| {
            closure_called.set(true);
            async { Err(bad_request_flow_error()) }
        })
        .await;
        assert!(!called.get(), "{setup}");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 0);
        assert!(response.headers().get("cache-control").is_some());
    }
}

#[tokio::test]
async fn confirmation_success_is_clean_303_with_fixed_cookie_order() {
    let config = scanner_config();
    let response = build_confirmation_success_response("session-secret", &config);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION).expect("location"),
        "/signed-in"
    );
    assert!(response.headers().get("cache-control").is_some());
    let cookies: Vec<&[u8]> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].starts_with(b"dd_session=session-secret"));
    assert!(cookies[1].starts_with(b"dd_auth_flow=;"));
    let (_, headers, body) = response_parts(response).await;
    assert!(body.is_empty());
    assert!(
        !headers
            .get(LOCATION)
            .expect("location")
            .as_bytes()
            .contains(&b'?')
    );
}

#[tokio::test]
async fn handler_internal_clears_but_unavailable_preserves_temporary_state() {
    let config = scanner_config();
    for (kind, expected_status, expected_clears) in [
        (
            FixtureFlowError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
        ),
        (
            FixtureFlowError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            0,
        ),
    ] {
        let response = handle_magic_link_confirmation(
            post_request(APPLICATION_JSON, Body::from(r#"{"confirmation":"x"}"#)),
            &config,
            move |_command| async move { Err(fixture_flow_error(kind).await) },
        )
        .await;
        assert_eq!(response.status(), expected_status);
        assert_eq!(
            response.headers().get_all(SET_COOKIE).iter().count(),
            expected_clears
        );
        assert!(response.headers().get("cache-control").is_some());
        assert!(response.headers().get("content-security-policy").is_some());
    }
}

#[tokio::test]
async fn terminal_invalid_confirmation_responses_are_byte_identical() {
    let config = scanner_config();
    let mut responses = Vec::new();

    for cookie in [
        None,
        Some("dd_auth_flow="),
        Some("malformed"),
        Some("dd_auth_flow=one; dd_auth_flow=two"),
    ] {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/auth/magic-link/confirm")
            .header(ORIGIN, "https://example.test")
            .header(CONTENT_TYPE, APPLICATION_JSON);
        if let Some(cookie) = cookie {
            builder = builder.header(COOKIE, cookie);
        }
        let request = builder
            .body(Body::from(r#"{"confirmation":"x"}"#))
            .expect("request");
        responses.push(
            handle_magic_link_confirmation(request, &config, |_| async {
                unreachable!("service must not run")
            })
            .await,
        );
    }

    for (content_type, body) in [
        ("text/plain", Body::from("bad")),
        (APPLICATION_JSON, Body::empty()),
        (APPLICATION_JSON, Body::from("{")),
        (
            APPLICATION_JSON,
            Body::from(r#"{"confirmation":"x","token":"forbidden"}"#),
        ),
        (FORM_URLENCODED, Body::from(vec![0xff])),
        (FORM_URLENCODED, Body::from("country=HU")),
    ] {
        responses.push(
            handle_magic_link_confirmation(post_request(content_type, body), &config, |_| async {
                unreachable!("service must not run")
            })
            .await,
        );
    }

    responses.push(
        handle_magic_link_confirmation(
            post_request(APPLICATION_JSON, Body::from(r#"{"confirmation":"x"}"#)),
            &config,
            |_| async { Err(bad_request_flow_error()) },
        )
        .await,
    );
    responses.push(
        handle_magic_link_confirmation(
            post_request(APPLICATION_JSON, Body::from(r#"{"confirmation":"x"}"#)),
            &config,
            |_| async { Err(fixture_flow_error(FixtureFlowError::MagicLinkUnavailable).await) },
        )
        .await,
    );

    let mut fingerprints = Vec::new();
    for response in responses {
        let (status, headers, body) = response_parts(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, TERMINAL_INVALID_BODY.as_bytes());
        assert_eq!(headers.get_all(SET_COOKIE).iter().count(), 1);
        assert!(headers.get(LOCATION).is_none());
        fingerprints.push(terminal_fingerprint(status, &headers, &body));
    }
    for fingerprint in &fingerprints[1..] {
        assert_eq!(fingerprint, &fingerprints[0]);
    }
}

#[tokio::test]
async fn body_stream_cap_applies_without_content_length() {
    let config = scanner_config();
    let body = Body::from(vec![b'a'; MAX_MAGIC_LINK_BODY_BYTES + 1]);
    let response =
        handle_magic_link_confirmation(post_request(APPLICATION_JSON, body), &config, |_| async {
            unreachable!("service must not run")
        })
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 1);
}

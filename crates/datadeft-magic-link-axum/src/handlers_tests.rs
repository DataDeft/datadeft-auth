use std::cell::Cell;
use std::rc::Rc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN};
use axum::http::{Method, StatusCode};
use datadeft_magic_link_aws::{FakeDynamoDbAuthStore, FakeMagicLinkOutbox, StorageHmacKey};
use datadeft_magic_link_service::{
    Clock, DependencyError, LookupHmacKey, MagicLinkConfirmCookie, MagicLinkFlowService,
    MagicLinkRequestService, MagicLinkServiceConfig, RequestMagicLinkCommand, SessionCookie,
};
use rand_core::OsRng;

use super::*;
use crate::test_fixtures::{
    FixtureFlowError, fixture_flow_error, fixture_keyring, post_request, response_parts,
    scanner_config,
};

fn bad_request_flow_error() -> MagicLinkFlowError {
    ConfirmMagicLinkFlowCommand::new(
        "flow".to_owned(),
        "confirmation".to_owned(),
        Some("invalid-country".to_owned()),
    )
    .expect_err("invalid country")
}

// --- request handler (unchanged generic-ack behavior) ---------------------

#[tokio::test]
async fn request_handler_preserves_generic_success_regression() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(
            r#"{"email":"user@example.com","terms_accepted":true,"privacy_accepted":true}"#,
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
            r#"{"email":"user@example.com","terms_accepted":true,"privacy_accepted":true,"unexpected":"unknown-value-sentinel"}"#,
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

// --- landing: side-effect-free, error mapping -----------------------------

#[tokio::test]
async fn landing_errors_map_without_consuming_and_run_the_closure() {
    let config = scanner_config();
    for (kind, expected) in [
        (
            FixtureFlowError::MagicLinkUnavailable,
            MagicLinkFlowResponseError::Rejected,
        ),
        (
            FixtureFlowError::Unavailable,
            MagicLinkFlowResponseError::Unavailable,
        ),
        (
            FixtureFlowError::Internal,
            MagicLinkFlowResponseError::Internal,
        ),
    ] {
        let called = Rc::new(Cell::new(false));
        let closure_called = Rc::clone(&called);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/auth/magic-link?token=not-a-token")
            .body(Body::from("body-must-not-be-read"))
            .expect("request");
        let result = magic_link_landing(request, &config, move |_command| {
            closure_called.set(true);
            async move { Err(fixture_flow_error(kind).await) }
        })
        .await;
        assert!(called.get(), "begin closure must run");
        assert_eq!(result.err(), Some(expected));
    }
}

// --- confirmation: gauntlet runs before the service ------------------------

#[tokio::test]
async fn origin_rejection_precedes_cookie_body_and_service() {
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
        let result = magic_link_confirmation(request, &config, move |_command| {
            closure_called.set(true);
            async { Err(bad_request_flow_error()) }
        })
        .await;
        assert!(!called.get(), "{setup}: service must not run");
        assert_eq!(result.err(), Some(MagicLinkFlowResponseError::Rejected));
    }
}

#[tokio::test]
async fn malformed_cookie_and_body_are_rejected_uniformly_without_service() {
    let config = scanner_config();

    // Malformed / missing / duplicate confirm cookie, valid body: all Rejected
    // before the service runs.
    for cookie in [
        None,
        Some("dd_auth_confirm="),
        Some("malformed"),
        Some("dd_auth_confirm=one; dd_auth_confirm=two"),
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
        let result = magic_link_confirmation(request, &config, |_| async {
            unreachable!("service must not run")
        })
        .await;
        assert_eq!(result.err(), Some(MagicLinkFlowResponseError::Rejected));
    }

    // Bad content-type / empty / non-JSON / unknown field / body country: all
    // Rejected before the service runs.
    for (content_type, body) in [
        ("text/plain", Body::from("bad")),
        (APPLICATION_JSON, Body::empty()),
        (APPLICATION_JSON, Body::from("{")),
        (
            APPLICATION_JSON,
            Body::from(r#"{"confirmation":"x","token":"forbidden"}"#),
        ),
        (
            APPLICATION_JSON,
            Body::from(r#"{"confirmation":"x","country":"HU"}"#),
        ),
        (FORM_URLENCODED, Body::from(vec![0xff])),
        (FORM_URLENCODED, Body::from("country=HU")),
    ] {
        let result =
            magic_link_confirmation(post_request(content_type, body), &config, |_| async {
                unreachable!("service must not run")
            })
            .await;
        assert_eq!(result.err(), Some(MagicLinkFlowResponseError::Rejected));
    }
}

#[tokio::test]
async fn confirmation_service_errors_map_to_response_errors() {
    let config = scanner_config();
    for (kind, expected) in [
        (
            FixtureFlowError::MagicLinkUnavailable,
            MagicLinkFlowResponseError::Rejected,
        ),
        (
            FixtureFlowError::Unavailable,
            MagicLinkFlowResponseError::Unavailable,
        ),
        (
            FixtureFlowError::Internal,
            MagicLinkFlowResponseError::Internal,
        ),
    ] {
        let result = magic_link_confirmation(
            post_request(APPLICATION_JSON, Body::from(r#"{"confirmation":"x"}"#)),
            &config,
            move |_command| async move { Err(fixture_flow_error(kind).await) },
        )
        .await;
        assert_eq!(result.err(), Some(expected));
    }
}

#[tokio::test]
async fn body_stream_cap_applies_without_content_length() {
    let config = scanner_config();
    let body = Body::from(vec![b'a'; MAX_MAGIC_LINK_BODY_BYTES + 1]);
    let result =
        magic_link_confirmation(post_request(APPLICATION_JSON, body), &config, |_| async {
            unreachable!("service must not run")
        })
        .await;
    assert_eq!(result.err(), Some(MagicLinkFlowResponseError::Rejected));
}

// --- end-to-end success through the headless handlers ---------------------

struct FlowClock;

impl Clock for FlowClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(20_000)
    }
}

fn cookie_value(set_cookie: &HeaderValue, name: &str) -> String {
    let text = set_cookie.to_str().expect("ascii cookie");
    let prefix = format!("{name}=");
    let rest = text.strip_prefix(&prefix).expect("cookie name prefix");
    rest.split(';').next().expect("cookie value").to_owned()
}

#[tokio::test]
async fn full_flow_through_handlers_lands_side_effect_free_then_confirms() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = FakeMagicLinkOutbox::default();
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let confirm_keyring = fixture_keyring::<MagicLinkConfirmCookie>();
    let session_keyring = fixture_keyring::<SessionCookie>();
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    let scanner = scanner_config();

    // Seed a magic link via the request service. Recover the token from the
    // fake outbox (stands in for the delivered email).
    {
        let mut rng = OsRng;
        let mut request = MagicLinkRequestService {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &FlowClock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        };
        request
            .request_magic_link(RequestMagicLinkCommand::new(
                datadeft_magic_link_service::NormalizedEmail::parse("user@example.com")
                    .expect("email"),
                true,
                true,
            ))
            .await
            .expect("request accepted");
    }
    let token = outbox
        .recorded()
        .expect("outbox")
        .pop()
        .expect("one email")
        .token
        .as_secret_value()
        .to_string();

    // Landing (GET) is side-effect-free: it neither consumes the link nor
    // creates a session.
    let landing_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/auth/magic-link?token={token}"))
        .body(Body::empty())
        .expect("landing request");
    let landing = magic_link_landing(landing_request, &scanner, |command| {
        let (store, lookup_key, confirm_keyring, session_keyring, config) = (
            &store,
            &lookup_key,
            &confirm_keyring,
            &session_keyring,
            &config,
        );
        async move {
            let mut rng = OsRng;
            let mut service = MagicLinkFlowService {
                authentication: store,
                sessions: store,
                limiter: store,
                clock: &FlowClock,
                rng: &mut rng,
                lookup_hmac_key: lookup_key,
                previous_lookup_hmac_key: None,
                confirm_keyring,
                session_keyring,
                config: config.clone(),
            };
            service.begin_magic_link_landing(command).await
        }
    })
    .await
    .expect("landing succeeds");

    assert_eq!(store.session_count().expect("sessions"), 0);
    assert!(
        landing
            .confirm_cookie
            .to_str()
            .expect("ascii")
            .starts_with("dd_auth_confirm=")
    );
    let confirm_cookie = cookie_value(&landing.confirm_cookie, "dd_auth_confirm");
    let confirmation = landing.outcome.confirmation_value().to_owned();

    // Confirmation (same-origin POST) consumes the link and mints the session.
    let confirm_request = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link/confirm")
        .header(ORIGIN, "https://example.test")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .header(COOKIE, format!("dd_auth_confirm={confirm_cookie}"))
        .body(Body::from(format!(
            r#"{{"confirmation":"{confirmation}"}}"#
        )))
        .expect("confirm request");
    let confirmed = magic_link_confirmation(confirm_request, &scanner, |command| {
        let (store, lookup_key, confirm_keyring, session_keyring, config) = (
            &store,
            &lookup_key,
            &confirm_keyring,
            &session_keyring,
            &config,
        );
        async move {
            let mut rng = OsRng;
            let mut service = MagicLinkFlowService {
                authentication: store,
                sessions: store,
                limiter: store,
                clock: &FlowClock,
                rng: &mut rng,
                lookup_hmac_key: lookup_key,
                previous_lookup_hmac_key: None,
                confirm_keyring,
                session_keyring,
                config: config.clone(),
            };
            service.confirm_magic_link_flow(command).await
        }
    })
    .await
    .expect("confirmation succeeds");

    assert_eq!(store.session_count().expect("sessions"), 1);
    assert!(
        confirmed
            .session_cookie
            .to_str()
            .expect("ascii")
            .starts_with("dd_session=")
    );
    assert!(
        confirmed
            .clear_confirm_cookie
            .to_str()
            .expect("ascii")
            .starts_with("dd_auth_confirm=;")
    );
}

#[test]
fn security_headers_keep_form_posts_same_origin_and_tokens_out_of_referer() {
    let mut headers = HeaderMap::new();
    apply_magic_link_security_headers(&mut headers);
    // `no-referrer` would make browsers send `Origin: null` on the
    // confirmation form POST, which `request_is_same_origin` rejects.
    // `strict-origin` sends only the origin, never the token-bearing path.
    assert_eq!(
        headers.get("referrer-policy").map(HeaderValue::as_bytes),
        Some(&b"strict-origin"[..])
    );
    assert_eq!(
        headers.get("cache-control").map(HeaderValue::as_bytes),
        Some(&b"no-store"[..])
    );
    assert_eq!(
        headers.get("x-frame-options").map(HeaderValue::as_bytes),
        Some(&b"DENY"[..])
    );
    let csp = headers
        .get("content-security-policy")
        .and_then(|value| value.to_str().ok())
        .expect("csp");
    assert!(csp.contains("form-action 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
}

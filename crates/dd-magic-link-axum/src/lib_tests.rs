//! Axum adapter tests.

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use dd_magic_link_service::{
    ConsumeMagicLinkOutcome, MagicLinkServiceError, RequestMagicLinkOutcome, SessionId, UserId,
};

use super::*;

fn request(content_type: &'static str, body: &'static str) -> Request {
    Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .expect("request builds")
}

async fn body_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("body reads");
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

#[test]
fn request_json_parses_to_service_command_without_rewriting_email() {
    let body = br#"{
        "email":"User@example.com",
        "locale":"hu",
        "terms_accepted":true,
        "privacy_accepted":true,
        "client_key":"client-1"
    }"#;

    let command = parse_magic_link_request_json(body, None).expect("command");

    assert_eq!(command.email().as_str(), "User@example.com");
    assert_eq!(command.locale(), EmailLocale::Hu);
    assert!(command.terms_accepted());
    assert!(command.privacy_accepted());
    assert_eq!(command.client_key().expect("client").as_str(), "client-1");
}

#[test]
fn request_json_rejects_bad_locale_and_missing_consent_is_left_to_service() {
    let bad_locale = br#"{"email":"user@example.com","locale":"de","terms_accepted":true,"privacy_accepted":true}"#;
    assert_eq!(
        parse_magic_link_request_json(bad_locale, None).unwrap_err(),
        MagicLinkHttpError::BadRequest
    );

    let missing_consent = br#"{"email":"user@example.com","locale":"en","terms_accepted":false,"privacy_accepted":true}"#;
    let command = parse_magic_link_request_json(missing_consent, None).expect("command");
    assert!(!command.terms_accepted());
}

#[test]
fn consume_body_parses_json_and_form_without_token_validation() {
    let json = parse_magic_link_consume_body(
        br#"{"token":"not-a-token","client_key":"client-1","country":"HU"}"#,
        true,
    )
    .expect("json");
    assert_eq!(json.token(), "not-a-token");
    assert_eq!(
        json.client_key(None)
            .expect("client")
            .expect("some")
            .as_str(),
        "client-1"
    );
    assert_eq!(json.country(None).as_deref(), Some("HU"));

    let form = parse_magic_link_consume_body(b"token=not-a-token&country=HU", false).expect("form");
    assert_eq!(form.token(), "not-a-token");
    assert_eq!(form.country(None).as_deref(), Some("HU"));
}

#[test]
fn cookie_helpers_default_to_secure_host_only_session_cookie() {
    let config = SessionCookieConfig::production();
    let set = session_set_cookie_header(&config, "v1.active.token").expect("set cookie");
    let set = set.to_str().expect("ascii");

    assert!(set.starts_with("dd_session=v1.active.token; Path=/; HttpOnly; Secure"));
    assert!(set.contains("SameSite=Lax"));
    assert!(set.contains("Max-Age=2592000"));
    assert!(!set.contains("Domain="));

    let clear = clear_session_cookie_header(&config).expect("clear cookie");
    let clear = clear.to_str().expect("ascii");
    assert!(clear.starts_with("dd_session=; Path=/; HttpOnly; Secure"));
    assert!(clear.contains("Max-Age=0"));
    assert!(clear.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
}

#[test]
fn cookie_config_rejects_unsafe_names_and_samesite_none_without_secure() {
    let bad_name = SessionCookieConfig::production().with_name("__Host-session");
    assert_eq!(
        session_set_cookie_header(&bad_name, "value").unwrap_err(),
        MagicLinkHttpError::BadRequest
    );

    let insecure_none = SessionCookieConfig::local_development().with_same_site(SameSite::None);
    assert_eq!(
        session_set_cookie_header(&insecure_none, "value").unwrap_err(),
        MagicLinkHttpError::BadRequest
    );
}

#[test]
fn redirect_target_is_same_origin_and_scrubbed() {
    assert!(SameOriginRedirect::parse("/app").is_ok());
    assert!(SameOriginRedirect::parse("/app?next=dashboard").is_ok());
    assert_eq!(
        SameOriginRedirect::parse("https://example.com/app").unwrap_err(),
        MagicLinkHttpError::BadRequest
    );
    assert_eq!(
        SameOriginRedirect::parse("//evil.example/app").unwrap_err(),
        MagicLinkHttpError::BadRequest
    );
    assert_eq!(
        SameOriginRedirect::parse("/app?token=mlv1.selector.verifier").unwrap_err(),
        MagicLinkHttpError::BadRequest
    );
}

#[test]
fn consume_success_sets_303_location_and_cookie() {
    let outcome = ConsumeMagicLinkOutcome {
        session_cookie: "v1.active.token".to_owned(),
        user_id: UserId::parse("usr_00000000000000000000000000000000").expect("user"),
        session_id: SessionId::parse(
            "sid_0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("session"),
        user_created: true,
        country: Some("HU".to_owned()),
    };
    let config = ConsumeSuccessConfig::new(SameOriginRedirect::parse("/done").expect("redirect"));

    let response = consume_success_response(&outcome, &config).expect("response");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(LOCATION).expect("location"), "/done");
    assert!(response.headers().get(SET_COOKIE).is_some());
}

#[test]
fn service_errors_map_to_stable_public_http_errors() {
    let cases = [
        (
            MagicLinkServiceError::BadRequest,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            MagicLinkServiceError::MagicLinkUnavailable,
            StatusCode::BAD_REQUEST,
            "magic_link_unavailable",
        ),
        (
            MagicLinkServiceError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
        (
            MagicLinkServiceError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
        ),
    ];

    for (service_error, status, code) in cases {
        let http_error = MagicLinkHttpError::from(service_error);
        assert_eq!(http_error.status(), status);
        assert_eq!(http_error.code(), code);
    }
}

#[test]
fn content_type_and_country_extractors_are_strict() {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("Application/JSON; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY),
        HeaderValue::from_static("HU"),
    );

    assert!(content_type_matches(&headers, APPLICATION_JSON));
    assert_eq!(viewer_country(&headers).as_deref(), Some("HU"));

    headers.insert(
        HeaderName::from_static(CLOUDFRONT_VIEWER_COUNTRY),
        HeaderValue::from_static("hu"),
    );
    assert_eq!(viewer_country(&headers), None);
}

#[tokio::test]
async fn request_handler_returns_generic_success() {
    let response = handle_magic_link_request_json(
        request(
            APPLICATION_JSON,
            r#"{"email":"user@example.com","locale":"en","terms_accepted":true,"privacy_accepted":true}"#,
        ),
        None,
        |command| {
            assert_eq!(command.email().as_str(), "user@example.com");
            Ok(RequestMagicLinkOutcome)
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn consume_handler_delegates_invalid_token_to_service() {
    let config = ConsumeSuccessConfig::new(SameOriginRedirect::parse("/done").expect("redirect"));
    let response = handle_magic_link_consume(
        request(FORM_URLENCODED, "token=bad-token"),
        Some(ClientKey::parse("client-1").expect("client")),
        &config,
        |token, client_key, country| {
            assert_eq!(token, "bad-token");
            assert_eq!(client_key.expect("client").as_str(), "client-1");
            assert_eq!(country, None);
            Err(MagicLinkServiceError::MagicLinkUnavailable)
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_text(response).await;
    assert!(body.contains("magic_link_unavailable"));
    assert!(!body.contains("bad-token"));
}

#[tokio::test]
async fn guard_rejects_wrong_type_and_oversized_content_length() {
    let wrong_type = guarded_body(
        request("text/plain", "{}"),
        &[APPLICATION_JSON],
        MAX_MAGIC_LINK_BODY_BYTES,
    )
    .await
    .unwrap_err();
    assert_eq!(wrong_type, MagicLinkHttpError::UnsupportedMediaType);

    let oversized = Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .header(
            "content-length",
            (MAX_MAGIC_LINK_BODY_BYTES + 1).to_string(),
        )
        .body(Body::empty())
        .expect("request builds");
    assert_eq!(
        guarded_body(oversized, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES)
            .await
            .unwrap_err(),
        MagicLinkHttpError::PayloadTooLarge
    );
}

#[tokio::test]
async fn landing_page_uses_security_headers_and_escapes_html() {
    let page = MagicLinkLandingPage {
        token: "mlv1.selector.verifier\"<".to_owned(),
        post_action: SameOriginRedirect::parse("/auth/magic-link/consume").expect("redirect"),
        account_label: Some("user<&>@example.com".to_owned()),
    };

    let response = magic_link_landing_response(&page).expect("landing");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("cache-control").expect("cache"),
        "no-store"
    );
    assert_eq!(
        response.headers().get("referrer-policy").expect("referrer"),
        "no-referrer"
    );
    assert_eq!(
        response.headers().get("x-frame-options").expect("xfo"),
        "DENY"
    );

    let text = body_text(response).await;
    assert!(text.contains("user&lt;&amp;&gt;@example.com"));
    assert!(text.contains("mlv1.selector.verifier&quot;&lt;"));
}

use axum::body::Body;
use axum::http::{HeaderValue, Method};

use super::*;

#[test]
fn request_json_regression_preserves_email_and_consent() {
    let body = br#"{
        "email":"User@example.com",
        "terms_accepted":true,
        "privacy_accepted":true
    }"#;
    let command = parse_magic_link_request_json(body).expect("command");
    assert_eq!(command.email().as_str(), "User@example.com");
    assert!(command.terms_accepted());
    assert!(command.privacy_accepted());
}

#[test]
fn request_negative_regressions_reject_unknown_fields_and_forward_false_consent() {
    // The library is language-agnostic: a locale (or any unknown field) is
    // rejected, so applications parse their own request shape and select the
    // email language in their own outbox.
    let with_locale = br#"{"email":"user@example.com","locale":"de","terms_accepted":true,"privacy_accepted":true}"#;
    assert_eq!(
        parse_magic_link_request_json(with_locale).unwrap_err(),
        MagicLinkHttpError::BadRequest
    );

    let false_consent =
        br#"{"email":"user@example.com","terms_accepted":false,"privacy_accepted":true}"#;
    let command = parse_magic_link_request_json(false_consent).expect("command");
    assert!(!command.terms_accepted());
    assert!(command.privacy_accepted());
}

#[test]
fn request_and_confirmation_dto_debug_are_redacted() {
    let request: MagicLinkRequestJson = serde_json::from_str(
        r#"{"email":"sensitive@example.test","terms_accepted":true,"privacy_accepted":true}"#,
    )
    .expect("request dto");
    let debug = format!("{request:?}");
    assert!(!debug.contains("sensitive@example.test"));

    let confirmation: MagicLinkConfirmationBody =
        serde_json::from_str(r#"{"confirmation":"confirmation-secret"}"#)
            .expect("confirmation dto");
    let debug = format!("{confirmation:?}");
    assert!(!debug.contains("confirmation-secret"));
    assert!(
        serde_json::from_str::<MagicLinkConfirmationBody>(
            r#"{"confirmation":"ok","token":"forbidden"}"#
        )
        .is_err()
    );
    // Country is never accepted from the body — it is a trusted-edge header
    // concern only, so a body-supplied country is an unknown field.
    assert!(
        serde_json::from_str::<MagicLinkConfirmationBody>(
            r#"{"confirmation":"ok","country":"HU"}"#
        )
        .is_err()
    );
}

#[test]
fn landing_query_parser_is_raw_exact_and_bounded() {
    assert!(extract_landing_token(Some("token=canonical")).is_ok());
    for query in [
        None,
        Some(""),
        Some("canonical"),
        Some("token="),
        Some("token=a&token=b"),
        Some("token=a&other=b"),
        Some("other=a"),
        Some("token=a%2Eb"),
        Some("token=a+b"),
        Some("token=a=b"),
    ] {
        if query == Some("token=a+b") {
            // Plus is not decoded and is delegated to the sole grammar authority.
            assert!(extract_landing_token(query).is_ok());
        } else {
            assert!(extract_landing_token(query).is_err(), "query {query:?}");
        }
    }
    // The raw-token length cap is owned by the service command, not this
    // extractor; only the outer query-size guard applies here.
    let over_query = "a".repeat(MAX_MAGIC_LINK_LANDING_QUERY_BYTES + 1);
    assert!(extract_landing_token(Some(&over_query)).is_err());
}

#[tokio::test]
async fn guarded_body_debug_redacts_all_body_bytes() {
    let secret_body = r#"{"email":"sensitive@example.test","opaque_secret":"body-secret","confirmation":"confirmation-secret"}"#;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(secret_body))
        .expect("request");
    let guarded = guarded_body(request, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES)
        .await
        .expect("guarded");
    let debug = format!("{guarded:?}");
    assert_eq!(debug, "GuardedBody(..)");
    for sentinel in [
        "sensitive@example.test",
        "body-secret",
        "confirmation-secret",
    ] {
        assert!(!debug.contains(sentinel));
    }
}

#[tokio::test]
async fn oversized_declared_content_length_is_rejected_before_body_read() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth")
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .header(CONTENT_LENGTH, (MAX_MAGIC_LINK_BODY_BYTES + 1).to_string())
        .body(Body::empty())
        .expect("request");
    assert_eq!(
        guarded_body(request, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES)
            .await
            .unwrap_err(),
        MagicLinkHttpError::PayloadTooLarge
    );
}

#[tokio::test]
async fn guarded_body_and_country_regressions_remain_strict() {
    let wrong = Request::builder()
        .method(Method::POST)
        .uri("/auth")
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from("{}"))
        .expect("request");
    assert_eq!(
        guarded_body(wrong, &[APPLICATION_JSON], MAX_MAGIC_LINK_BODY_BYTES)
            .await
            .unwrap_err(),
        MagicLinkHttpError::UnsupportedMediaType
    );

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

    // A configured non-CloudFront edge header works through the same
    // validation; the CloudFront helper ignores it.
    let cf_ipcountry = HeaderName::from_static("cf-ipcountry");
    let mut cloudflare_headers = HeaderMap::new();
    cloudflare_headers.insert(cf_ipcountry.clone(), HeaderValue::from_static("DE"));
    assert_eq!(
        viewer_country_from(&cloudflare_headers, &cf_ipcountry).as_deref(),
        Some("DE")
    );
    assert_eq!(viewer_country(&cloudflare_headers), None);
}

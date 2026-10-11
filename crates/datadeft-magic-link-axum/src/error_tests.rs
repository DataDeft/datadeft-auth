use axum::body::to_bytes;
use axum::http::header::CACHE_CONTROL;

use super::*;

#[test]
fn general_service_error_mapping_follows_the_response_contract() {
    let cases = [
        (MagicLinkServiceError::BadRequest, StatusCode::BAD_REQUEST),
        (
            MagicLinkServiceError::MagicLinkUnavailable,
            StatusCode::BAD_REQUEST,
        ),
        (
            MagicLinkServiceError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            MagicLinkServiceError::Internal,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ];
    for (service, status) in cases {
        assert_eq!(MagicLinkHttpError::from(service).status(), status);
    }
}

async fn parts(error: MagicLinkHttpError) -> (StatusCode, HeaderValue, Vec<u8>) {
    let response = error.into_response();
    let status = response.status();
    let cache = response
        .headers()
        .get(CACHE_CONTROL)
        .cloned()
        .expect("cache-control");
    let body = to_bytes(response.into_body(), 4096).await.expect("body");
    (status, cache, body.to_vec())
}

/// Shape errors are one generic 400; every fault is one constant 503. The
/// public response never tells the reasons apart; `reason()` does, internally.
#[tokio::test]
async fn shape_errors_and_faults_are_indistinguishable_from_outside() {
    let shape = [
        MagicLinkHttpError::BadRequest,
        MagicLinkHttpError::UnsupportedMediaType,
        MagicLinkHttpError::PayloadTooLarge,
        // An unusable link answers exactly like a malformed request.
        MagicLinkHttpError::MagicLinkUnavailable,
    ];
    let first = parts(shape[0]).await;
    assert_eq!(first.0, StatusCode::BAD_REQUEST);
    for error in &shape[1..] {
        assert_eq!(parts(*error).await, first);
    }

    let unavailable = parts(MagicLinkHttpError::Unavailable).await;
    assert_eq!(unavailable, parts(MagicLinkHttpError::Internal).await);
    assert_eq!(
        unavailable,
        parts(MagicLinkHttpError::OutboxUnavailable).await
    );
    assert_eq!(unavailable.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable.1, HeaderValue::from_static("no-store"));
    // Byte-identical to datadeft-pow-axum's 503 (pinned there too).
    assert_eq!(
        unavailable.2,
        br#"{"error":"unavailable","message":"The service is temporarily unavailable. Try again later."}"#
    );

    let mut reasons: Vec<&str> = [
        MagicLinkHttpError::BadRequest,
        MagicLinkHttpError::UnsupportedMediaType,
        MagicLinkHttpError::PayloadTooLarge,
        MagicLinkHttpError::MagicLinkUnavailable,
        MagicLinkHttpError::Unavailable,
        MagicLinkHttpError::OutboxUnavailable,
        MagicLinkHttpError::Internal,
    ]
    .iter()
    .map(|error| error.reason())
    .collect();
    reasons.sort_unstable();
    reasons.dedup();
    assert_eq!(reasons.len(), 7, "every reason is distinct internally");
}

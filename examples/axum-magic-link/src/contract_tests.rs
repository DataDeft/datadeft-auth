//! The public HTTP status contract (docs/security.md, "HTTP response
//! contract") as one table over every library refusal, across both Axum
//! crates. A change to any status, header, or body shows up here.

use axum::body::to_bytes;
use axum::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use datadeft_magic_link_axum::{MagicLinkHttpError, authenticate_session};
use datadeft_magic_link_service::{SessionValidationError, ValidatedSession};
use datadeft_pow_axum::{PowFlowError, ProofRejection};

use super::*;

struct Seen {
    status: StatusCode,
    challenge: Option<String>,
    cache: Option<String>,
    body: Vec<u8>,
}

async fn seen(response: Response) -> Seen {
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let challenge = header(WWW_AUTHENTICATE);
    let cache = header(CACHE_CONTROL);
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("body")
        .to_vec();
    Seen {
        status,
        challenge,
        cache,
        body,
    }
}

async fn session_rejection(error: Option<SessionValidationError>) -> Response {
    let state = build_state().expect("state");
    let mut headers = HeaderMap::new();
    if error.is_some() {
        headers.insert(
            "cookie",
            "dd_session=present".parse().expect("cookie header"),
        );
    }
    let result = authenticate_session(
        &headers,
        state.http_config.session_cookie(),
        move |_| async move {
            Err::<ValidatedSession, _>(error.unwrap_or(SessionValidationError::InvalidSession))
        },
    )
    .await;
    match result {
        Ok(_) => panic!("rejected"),
        Err(rejection) => rejection.into_response(),
    }
}

#[tokio::test]
async fn every_library_refusal_follows_the_contract() {
    // 401 + DD-PoW: solve, retry once.
    for response in [
        ProofRejection::ProofRequired.into_response(),
        ProofRejection::BudgetExhausted.into_response(),
        PowFlowError::Rejected.into_response(),
    ] {
        let seen = seen(response).await;
        assert_eq!(seen.status, StatusCode::UNAUTHORIZED);
        assert_eq!(seen.challenge.as_deref(), Some("DD-PoW"));
    }

    // 401 + DD-Session: sign in again.
    let seen_session = seen(session_rejection(None).await).await;
    assert_eq!(seen_session.status, StatusCode::UNAUTHORIZED);
    assert_eq!(seen_session.challenge.as_deref(), Some("DD-Session"));

    // 400, one generic body, for every shape error.
    let shape: Vec<Seen> = futures_seen([
        MagicLinkHttpError::BadRequest.into_response(),
        MagicLinkHttpError::UnsupportedMediaType.into_response(),
        MagicLinkHttpError::PayloadTooLarge.into_response(),
        MagicLinkHttpError::MagicLinkUnavailable.into_response(),
    ])
    .await;
    for seen in &shape {
        assert_eq!(seen.status, StatusCode::BAD_REQUEST);
        assert_eq!(seen.body, shape[0].body);
        assert_eq!(seen.challenge, None);
    }

    // 503, byte-identical across both crates and every reason.
    let unavailable: Vec<Seen> = futures_seen([
        ProofRejection::Unavailable.into_response(),
        PowFlowError::Internal.into_response(),
        MagicLinkHttpError::Unavailable.into_response(),
        MagicLinkHttpError::Internal.into_response(),
        session_rejection(Some(SessionValidationError::Unavailable)).await,
        session_rejection(Some(SessionValidationError::Internal)).await,
    ])
    .await;
    for seen in &unavailable {
        assert_eq!(seen.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(seen.challenge, None);
        assert_eq!(seen.cache.as_deref(), Some("no-store"));
        assert_eq!(seen.body, unavailable[0].body);
    }
    assert_eq!(
        unavailable[0].body,
        br#"{"error":"unavailable","message":"The service is temporarily unavailable. Try again later."}"#
    );
}

async fn futures_seen<const N: usize>(responses: [Response; N]) -> Vec<Seen> {
    let mut all = Vec::with_capacity(N);
    for response in responses {
        all.push(seen(response).await);
    }
    all
}

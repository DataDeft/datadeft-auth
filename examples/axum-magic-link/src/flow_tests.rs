//! End to end through the real router: PoW, link request, scanner-safe
//! landing, same-origin confirmation, and an authenticated page.

use axum::body::{Body, to_bytes};
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, SET_COOKIE};
use axum::http::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::*;

async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.expect("router")
}

async fn text(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

/// The `name=value` part of a `Set-Cookie` header, for the given cookie name.
fn cookie(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().to_owned())
        .find(|pair| pair.starts_with(&format!("{name}=")) && pair.len() > name.len() + 1)
}

/// Solve the PoW challenge the way the browser worker does.
fn solve(challenge: &serde_json::Value) -> serde_json::Value {
    let chg = challenge["chg"].as_str().expect("chg");
    let dif = challenge["dif"].as_u64().expect("dif") as usize;
    let prefix = "0".repeat(dif);
    let (non, sol) = (0u64..)
        .map(|nonce| {
            let digest = Sha256::digest(format!("{chg}{nonce}").as_bytes());
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            (nonce, hex)
        })
        .find(|(_, hex)| hex.starts_with(&prefix))
        .expect("solution");
    serde_json::json!({
        "chg": chg, "sol": sol, "non": non.to_string(),
        "tim": challenge["tim"], "tag": challenge["tag"],
    })
}

/// The hidden `confirmation` value of the landing page.
fn confirmation(page: &str) -> String {
    let marker = "name=\"confirmation\" value=\"";
    let start = page.find(marker).expect("confirmation field") + marker.len();
    page[start..].split('"').next().expect("value").to_owned()
}

fn confirm_request(confirm_cookie: &str, confirmation: &str, origin: &str) -> Request<Body> {
    Request::post("/auth/magic-link/consume")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(COOKIE, confirm_cookie)
        .header(ORIGIN, origin)
        .body(Body::from(format!("confirmation={confirmation}")))
        .expect("request")
}

#[tokio::test]
async fn sign_in_end_to_end_through_the_router() {
    let state = build_state().expect("state");
    let outbox = state.outbox.clone();
    let app = app(state);

    // Without a proof the request is 401 + DD-PoW.
    let request_link = |pow_cookie: Option<&str>| {
        let body = serde_json::json!({
            "email": "e2e@example.test", "terms_accepted": true, "privacy_accepted": true,
            "locale": "hu",
        });
        let mut request =
            Request::post("/auth/magic-link/request").header(CONTENT_TYPE, "application/json");
        if let Some(pow_cookie) = pow_cookie {
            request = request.header(COOKIE, pow_cookie);
        }
        request.body(Body::from(body.to_string())).expect("req")
    };
    let unproven = send(&app, request_link(None)).await;
    assert_eq!(unproven.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unproven
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("DD-PoW")
    );

    // Solve once; the validate route sets the dd_pow cookie.
    let challenge = send(
        &app,
        Request::post("/auth/pow/create")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge: serde_json::Value = serde_json::from_str(&text(challenge).await).expect("json");
    let validated = send(
        &app,
        Request::post("/auth/pow/validate")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(solve(&challenge).to_string()))
            .expect("req"),
    )
    .await;
    assert_eq!(validated.status(), StatusCode::NO_CONTENT);
    let pow_cookie = cookie(&validated, "dd_pow").expect("dd_pow cookie");

    let requested = send(&app, request_link(Some(&pow_cookie))).await;
    assert_eq!(requested.status(), StatusCode::OK);
    let email = outbox.recorded().expect("outbox").pop().expect("email");
    // The request's locale hint resolved against the app's allowlist.
    assert_eq!(
        email.locale.as_ref().map(|locale| locale.as_str()),
        Some("hu")
    );
    let token = email.token.as_secret_value().to_string();
    let landing_uri = format!("/auth/magic-link?token={token}");

    // A scanner fetches the link twice; neither fetch consumes it.
    for _ in 0..2 {
        let scan = send(
            &app,
            Request::get(&landing_uri).body(Body::empty()).expect("req"),
        )
        .await;
        assert_eq!(scan.status(), StatusCode::OK);
    }
    let landing = send(
        &app,
        Request::get(&landing_uri).body(Body::empty()).expect("req"),
    )
    .await;
    assert_eq!(landing.status(), StatusCode::OK);
    assert_eq!(
        landing
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let confirm_cookie = cookie(&landing, "dd_auth_confirm").expect("confirm cookie");
    let page = text(landing).await;
    assert!(
        page.contains("e2e@example.test"),
        "the page names the account"
    );
    assert!(!page.contains(&token), "the page never echoes the token");
    let confirmation = confirmation(&page);

    // A cross-site POST is refused and consumes nothing.
    let cross = send(
        &app,
        confirm_request(&confirm_cookie, &confirmation, "https://evil.example"),
    )
    .await;
    assert_ne!(cross.status(), StatusCode::SEE_OTHER);

    // The same-origin POST signs in.
    let confirmed = send(
        &app,
        confirm_request(&confirm_cookie, &confirmation, LOCAL_ORIGIN),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
    let location = confirmed
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location");
    assert!(
        !location.contains(&token) && !location.contains(&confirmation),
        "no secrets in Location"
    );
    let session = cookie(&confirmed, "dd_session").expect("session cookie");

    let me = send(
        &app,
        Request::get("/me")
            .header(COOKIE, &session)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(me.status(), StatusCode::OK);
    assert!(text(me).await.contains("e2e@example.test"));

    // The link is single use: replaying the confirmation fails.
    let replay = send(
        &app,
        confirm_request(&confirm_cookie, &confirmation, LOCAL_ORIGIN),
    )
    .await;
    assert_ne!(replay.status(), StatusCode::SEE_OTHER);

    // One solve buys five requests over its lifetime; the sixth is the
    // constant 503, whatever the reason.
    for _ in 1..5 {
        let again = send(&app, request_link(Some(&pow_cookie))).await;
        assert_eq!(again.status(), StatusCode::OK);
    }
    let exhausted = send(&app, request_link(Some(&pow_cookie))).await;
    assert_eq!(exhausted.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        text(exhausted).await,
        r#"{"error":"unavailable","message":"The service is temporarily unavailable. Try again later."}"#
    );
}

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

    // An email-provider failure is the constant 503 (reason
    // magic_link_outbox_unavailable, logged, never sent). Inject it with
    // FakeMagicLinkOutbox::set_next_error.
    outbox
        .set_next_error(datadeft_magic_link_service::DependencyError::Unavailable)
        .expect("inject");
    let failed = send(&app, request_link(Some(&pow_cookie))).await;
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(outbox.recorded().expect("outbox").is_empty());

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
        page.contains("e\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}@example.test"),
        "the page names the account, masked"
    );
    assert!(!page.contains("e2e@example.test"), "never the full address");
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

    // One solve buys five requests over its lifetime; the sixth asks for a
    // new solve (401 + DD-PoW), and a fresh solve buys a fresh budget. The
    // failed send above spent a unit too, so three more requests remain.
    for _ in 2..5 {
        let again = send(&app, request_link(Some(&pow_cookie))).await;
        assert_eq!(again.status(), StatusCode::OK);
    }
    let exhausted = send(&app, request_link(Some(&pow_cookie))).await;
    assert_eq!(exhausted.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        exhausted
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("DD-PoW")
    );
    let challenge = send(
        &app,
        Request::post("/auth/pow/create")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let challenge: serde_json::Value = serde_json::from_str(&text(challenge).await).expect("json");
    let revalidated = send(
        &app,
        Request::post("/auth/pow/validate")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(solve(&challenge).to_string()))
            .expect("req"),
    )
    .await;
    let fresh_cookie = cookie(&revalidated, "dd_pow").expect("fresh dd_pow cookie");
    let resumed = send(&app, request_link(Some(&fresh_cookie))).await;
    assert_eq!(resumed.status(), StatusCode::OK);
}

/// Redirect landing mode end to end: the link redirects to the static page
/// with no token in `Location`, the page reads the flow state (repeatably,
/// burning nothing), posts the confirmation, and the user is signed in.
#[tokio::test]
async fn redirect_mode_end_to_end_through_the_router() {
    use datadeft_magic_link_service::{
        MagicLinkRequestService, NormalizedEmail, RequestMagicLinkCommand,
    };
    use rand_core::OsRng;

    let state = build_state().expect("state");
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
        NormalizedEmail::from_normalized("static@example.test").expect("email"),
        true,
        true,
    ))
    .await
    .expect("request");
    let token = state
        .outbox
        .recorded()
        .expect("outbox")
        .pop()
        .expect("email")
        .token
        .as_secret_value()
        .to_string();
    let app = app(state);

    // A scanner follows the link twice: each time a 303 to the same page.
    let open = format!("/auth/magic-link/open?token={token}");
    let mut confirm_cookie = String::new();
    for _ in 0..2 {
        let landed = send(&app, Request::get(&open).body(Body::empty()).expect("req")).await;
        assert_eq!(landed.status(), StatusCode::SEE_OTHER);
        let location = landed
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("location");
        assert_eq!(location, "/login/confirm", "one target, no token");
        confirm_cookie = cookie(&landed, "dd_auth_confirm").expect("confirm cookie");
    }

    // The static page carries its own strict headers.
    let page = send(
        &app,
        Request::get("/login/confirm")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let csp = page
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("csp")
        .to_owned();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert!(!text(page).await.contains(&token));

    // The page reads the flow state; reading again burns nothing.
    let flow_state = || {
        Request::get("/auth/magic-link/flow-state")
            .header(COOKIE, &confirm_cookie)
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .expect("req")
    };
    let mut confirmation = String::new();
    for _ in 0..2 {
        let read = send(&app, flow_state()).await;
        assert_eq!(read.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&text(read).await).expect("json");
        assert_eq!(body["usable"], true);
        // Masked on the server: the full address never crosses the network.
        assert_eq!(
            body["account"],
            "s\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}@example.test"
        );
        confirmation = body["confirmation"]
            .as_str()
            .expect("confirmation")
            .to_owned();
    }
    // A cross-site read gets nothing.
    let cross = send(
        &app,
        Request::get("/auth/magic-link/flow-state")
            .header(COOKIE, &confirm_cookie)
            .header("sec-fetch-site", "cross-site")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let cross: serde_json::Value = serde_json::from_str(&text(cross).await).expect("json");
    assert_eq!(cross, serde_json::json!({ "usable": false }));

    // The page posts the confirmation same-origin, as JSON.
    let confirmed = send(
        &app,
        Request::post("/auth/magic-link/consume")
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, &confirm_cookie)
            .header(ORIGIN, LOCAL_ORIGIN)
            .body(Body::from(
                serde_json::json!({ "confirmation": confirmation }).to_string(),
            ))
            .expect("req"),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
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

    // The link is used: its flow state is no longer usable.
    let after: serde_json::Value =
        serde_json::from_str(&text(send(&app, flow_state()).await).await).expect("json");
    assert_eq!(after, serde_json::json!({ "usable": false }));
}

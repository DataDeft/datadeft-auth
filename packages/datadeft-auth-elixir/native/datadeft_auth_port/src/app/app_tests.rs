use super::*;

pub(crate) fn secret_document(verify_until_unix: u64) -> String {
    use base64::Engine;
    let key = |byte: u8| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
    serde_json::json!({
        "kid": "test-active",
        "mint_until_unix": 4_102_444_800_u64,
        "verify_until_unix": verify_until_unix,
        "magic_link_lookup_hmac_b64": key(1),
        "storage_hmac_b64": key(2),
        "session_cookie_root_b64": key(3),
        "magic_link_confirm_cookie_root_b64": key(4),
        "pow_challenge_secret_b64": key(5),
        "pow_proof_cookie_root_b64": key(6),
    })
    .to_string()
}

#[test]
fn the_test_secret_document_loads_and_requires_a_verify_window() {
    assert!(LoadedAuthSecrets::from_json(&secret_document(4_202_444_800), None).is_ok());
    // The loader requires the verify window to extend past the mint window;
    // the configuration error must fire at init, not at first use.
    assert!(LoadedAuthSecrets::from_json(&secret_document(4_102_444_800), None).is_err());
}

fn init_json(pow: Option<serde_json::Value>) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "mode": "fake",
        "service": { "terms_version": "t1", "privacy_version": "p1" },
        "email": {
            "link_base_url": "https://auth.test/auth/magic-link/landing?token=",
            "subject": "Sign in",
            "text": "Open {magic_link_url}"
        },
        "secrets": { "active_document": secret_document(4_202_444_800) }
    });
    if let Some(pow) = pow {
        payload["pow"] = pow;
    }
    payload
}

async fn initialized(pow: Option<serde_json::Value>) -> Result<ReadyApp, ErrorCode> {
    let payload: InitPayload = serde_json::from_value(init_json(pow)).expect("payload shape");
    ReadyApp::initialize(payload).await
}

#[tokio::test]
async fn a_subject_carrying_the_url_marker_is_refused_at_init() {
    // The rendered URL is a bearer secret and Subject headers are logged in
    // transit; the template validation must refuse the marker up front.
    let mut payload = init_json(None);
    payload["email"]["subject"] = serde_json::json!("Sign in: {magic_link_url}");
    let payload: InitPayload = serde_json::from_value(payload).expect("payload shape");
    assert!(matches!(
        ReadyApp::initialize(payload).await,
        Err(ErrorCode::Configuration)
    ));
}

/// Solve the way the shipped browser client does: decimal nonces into
/// `hex(SHA-256(chg + non))` until `dif` leading zero hex characters appear.
fn solve(chg: &str, dif: u8) -> (String, String) {
    use sha2::{Digest, Sha256};
    let target = "0".repeat(usize::from(dif));
    let mut nonce: u64 = 0;
    loop {
        let non = nonce.to_string();
        let sol = hex::encode(Sha256::digest(format!("{chg}{non}").as_bytes()));
        if sol.starts_with(&target) {
            return (sol, non);
        }
        nonce += 1;
    }
}

async fn admit(app: &ReadyApp, proof_cookie: &str) -> ResultBody {
    app.handle(AppCommand::PowAdmit(crate::protocol::PowAdmitPayload {
        proof_cookie: proof_cookie.to_owned(),
    }))
    .await
}

#[tokio::test]
async fn pow_flow_mints_verifies_and_admits_within_the_shared_lifetime_budget() {
    let app = initialized(Some(serde_json::json!({
        "difficulty": 1,
        "proof_budget_per_solve": 2
    })))
    .await
    .expect("initialized with pow");

    let ResultBody::PowChallenge { chg, dif, tim, tag } =
        app.handle(AppCommand::PowChallenge).await
    else {
        panic!("challenge expected");
    };
    assert_eq!(dif, 1);
    let (sol, non) = solve(&chg, dif);

    // A tampered solution collapses into the uniform refusal.
    let tampered = crate::protocol::PowVerifyPayload {
        chg: chg.clone(),
        sol: sol.replace(char::is_numeric, "f"),
        non: non.clone(),
        tim: tim.clone(),
        tag: tag.clone(),
    };
    let ResultBody::PowVerify {
        admitted: false,
        proof_cookie: None,
        mint_to_verify_ms: None,
    } = app.handle(AppCommand::PowVerify(tampered)).await
    else {
        panic!("tampered solution must be refused uniformly");
    };

    let ResultBody::PowVerify {
        admitted: true,
        proof_cookie: Some(cookie),
        ..
    } = app
        .handle(AppCommand::PowVerify(crate::protocol::PowVerifyPayload {
            chg,
            sol,
            non,
            tim,
            tag,
        }))
        .await
    else {
        panic!("valid solution must mint a proof cookie");
    };

    // One solve buys exactly its per-solve budget over the proof's lifetime.
    for _ in 0..2 {
        let ResultBody::PowAdmit { admitted: true } = admit(&app, &cookie).await else {
            panic!("budget must admit");
        };
    }
    let ResultBody::PowAdmit { admitted: false } = admit(&app, &cookie).await else {
        panic!("exhausted budget must refuse");
    };
    // A garbage cookie is the same uniform refusal, never an error detail.
    let ResultBody::PowAdmit { admitted: false } = admit(&app, "junk").await else {
        panic!("garbage cookie must be refused");
    };
}

#[tokio::test]
async fn pow_policy_is_validated_at_init_and_required_for_the_operations() {
    // Without the pow section every pow operation is a configuration error.
    let app = initialized(None).await.expect("initialized without pow");
    let ResultBody::Error {
        code: ErrorCode::Configuration,
    } = app.handle(AppCommand::PowChallenge).await
    else {
        panic!("pow_challenge without the gate must be a configuration error");
    };

    // Out-of-range policy values fail at init, before any work exists.
    for bad in [
        serde_json::json!({ "difficulty": 0, "proof_budget_per_solve": 2 }),
        serde_json::json!({ "difficulty": 65, "proof_budget_per_solve": 2 }),
        serde_json::json!({ "difficulty": 1, "proof_budget_per_solve": 0 }),
        serde_json::json!({ "difficulty": 1, "proof_budget_per_solve": 1001 }),
        serde_json::json!({ "difficulty": 1, "proof_budget_per_solve": 2, "challenge_max_age_secs": 0 }),
        serde_json::json!({ "difficulty": 1, "proof_budget_per_solve": 2, "challenge_max_age_secs": 601 }),
        serde_json::json!({ "difficulty": 1, "proof_budget_per_solve": 2, "proof_ttl_secs": 0 }),
        serde_json::json!({ "difficulty": 1, "proof_budget_per_solve": 2, "proof_ttl_secs": 86_401 }),
    ] {
        assert!(matches!(
            initialized(Some(bad)).await,
            Err(ErrorCode::Configuration)
        ));
    }
}

use super::*;

pub(crate) fn secret_document(verify_until_unix: u64) -> String {
    datadeft_magic_link_aws::test_support::auth_secret_document(
        "test-active",
        1,
        4_102_444_800,
        verify_until_unix,
    )
}

#[test]
fn the_test_secret_document_loads_and_requires_a_verify_window() {
    assert!(LoadedAuthSecrets::from_json(&secret_document(4_202_444_800), None).is_ok());
    // The loader requires the verify window to extend past the mint window;
    // the configuration error must fire at init, not at first use.
    assert!(LoadedAuthSecrets::from_json(&secret_document(4_102_444_800), None).is_err());
}

pub(super) fn init_json(pow: Option<serde_json::Value>) -> serde_json::Value {
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

use datadeft_pow_core::test_support::solve;

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
    let (non, sol) = solve(&chg, dif);

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

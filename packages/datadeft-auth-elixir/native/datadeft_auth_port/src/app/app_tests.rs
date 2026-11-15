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

#[tokio::test]
async fn invalid_aws_metadata_fails_initialization_before_credential_or_secret_io() {
    for field in ["table", "from_email", "region"] {
        let mut payload = init_json(None);
        payload["mode"] = serde_json::json!("aws");
        payload["aws"] = serde_json::json!({
            "region": "eu-central-1", "table": "test-auth",
            "from_email": "login@example.test"
        });
        payload["aws"][field] = serde_json::json!("");
        assert!(matches!(
            ReadyApp::initialize(serde_json::from_value(payload).expect("payload")).await,
            Err(ErrorCode::Configuration)
        ));
    }
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

fn localized_init_json() -> serde_json::Value {
    let mut payload = init_json(None);
    payload["service"]["default_locale"] = serde_json::json!("hu");
    payload["service"]["locales"] = serde_json::json!(["en"]);
    payload["locale_emails"] = serde_json::json!({
        "en": {
            "link_base_url": "https://auth.test/landing/en?token=",
            "subject": "Sign in (en)",
            "text": "Open {magic_link_url}"
        }
    });
    payload
}

#[tokio::test]
async fn locale_emails_must_match_the_configured_locales_exactly() {
    let mut empty = localized_init_json();
    empty["locale_emails"] = serde_json::json!({});
    let mut extra = localized_init_json();
    extra["locale_emails"]["de"] = extra["locale_emails"]["en"].clone();
    let mut without_locales = init_json(None);
    without_locales["locale_emails"] = localized_init_json()["locale_emails"].clone();
    let mut marked_subject = localized_init_json();
    marked_subject["locale_emails"]["en"]["subject"] = serde_json::json!("{magic_link_url}");
    for payload in [empty, extra, without_locales, marked_subject] {
        let payload: InitPayload = serde_json::from_value(payload).expect("payload shape");
        assert!(matches!(
            ReadyApp::initialize(payload).await,
            Err(ErrorCode::Configuration)
        ));
    }
}

#[test]
fn omitted_locale_emails_send_the_default_email_for_every_locale() {
    let mut json = localized_init_json();
    json.as_object_mut()
        .expect("object")
        .remove("locale_emails");
    let payload: InitPayload = serde_json::from_value(json).expect("payload");
    let emails =
        Emails::validate(payload.email, payload.locale_emails, &["en".to_owned()]).expect("emails");
    let en = LocaleAllowlist::new("hu", ["en"])
        .expect("locales")
        .resolve(Some("en"));
    assert_eq!(emails.for_locale(Some(&en)).subject, "Sign in");
}

#[test]
fn the_resolved_locale_selects_its_email() {
    let payload: InitPayload = serde_json::from_value(localized_init_json()).expect("payload");
    let emails =
        Emails::validate(payload.email, payload.locale_emails, &["en".to_owned()]).expect("emails");
    let locales = LocaleAllowlist::new("hu", ["en"]).expect("locales");
    let en = locales.resolve(Some("en-GB"));
    let hu = locales.resolve(Some("hu"));
    assert_eq!(emails.for_locale(Some(&en)).subject, "Sign in (en)");
    assert_eq!(emails.for_locale(Some(&hu)).subject, "Sign in");
    assert_eq!(emails.for_locale(None).subject, "Sign in");
}

#[tokio::test]
async fn a_request_link_locale_reaches_the_landing_url() {
    let app = ReadyApp::initialize(serde_json::from_value(localized_init_json()).expect("payload"))
        .await
        .expect("initialized");
    for (locale, base) in [
        (Some("en"), "https://auth.test/landing/en?token="),
        (None, "https://auth.test/auth/magic-link/landing?token="),
    ] {
        let email = format!("locale-{}@example.test", locale.unwrap_or("default"));
        app.handle(AppCommand::RequestLink(
            crate::protocol::RequestLinkPayload {
                email: email.clone(),
                terms_accepted: true,
                privacy_accepted: true,
                locale: locale.map(str::to_owned),
            },
        ))
        .await;
        let peek = crate::protocol::OutboxPeekPayload { email };
        let ResultBody::FakeLastMagicLink {
            magic_link_url: Some(url),
            ..
        } = app.handle(AppCommand::FakeLastMagicLink(peek)).await
        else {
            panic!("a recorded magic link expected");
        };
        assert!(url.starts_with(base), "{url}");
    }
}

#[test]
fn the_renderer_fills_the_resolved_locale_email() {
    let mut json = localized_init_json();
    json["locale_emails"]["en"]["html"] = serde_json::json!("<a href=\"{magic_link_url}\">en</a>");
    let payload: InitPayload = serde_json::from_value(json).expect("payload");
    let renderer = TemplateRenderer {
        emails: Arc::new(
            Emails::validate(payload.email, payload.locale_emails, &["en".to_owned()])
                .expect("emails"),
        ),
    };
    let locales = LocaleAllowlist::new("hu", ["en"]).expect("locales");
    let raw = "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    let email = |hint| MagicLinkEmail {
        email: datadeft_magic_link_service::NormalizedEmail::normalize("user@example.test")
            .expect("email"),
        token: datadeft_magic_link_core::MagicLinkToken::parse(raw).expect("token"),
        expires_at_unix: 1_600,
        locale: Some(locales.resolve(hint)),
    };

    let en = renderer.render(&email(Some("en"))).expect("rendered");
    let en_url = format!("https://auth.test/landing/en?token={raw}");
    assert_eq!(en.subject, "Sign in (en)");
    assert_eq!(en.text, format!("Open {en_url}"));
    assert_eq!(en.html, Some(format!("<a href=\"{en_url}\">en</a>")));

    let hu = renderer.render(&email(Some("hu"))).expect("rendered");
    let hu_url = format!("https://auth.test/auth/magic-link/landing?token={raw}");
    assert_eq!(hu.subject, "Sign in");
    assert_eq!(hu.text, format!("Open {hu_url}"));
    assert_eq!(hu.html, None);
}

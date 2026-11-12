//! Exercise the adapter handlers against real service state, without sleeping
//! or adding a production clock override. Seed sessions through the existing
//! service's injected clock, then validate/refresh/logout through the adapter.
use super::*;
use crate::protocol::SessionPayload;
use datadeft_magic_link_service::{
    BeginMagicLinkLandingCommand, ConfirmMagicLinkFlowCommand, MagicLinkRequestService,
    NormalizedEmail, RequestMagicLinkCommand,
};

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(self.0)
    }
}

async fn session_aged(age_secs: u64) -> (ReadyApp, String) {
    let mut payload = tests::init_json(None);
    payload["service"]["session_idle_secs"] = serde_json::json!(100);
    payload["service"]["session_absolute_secs"] = serde_json::json!(300);
    payload["service"]["enforce_country"] = serde_json::json!(true);
    let app = ReadyApp::initialize(serde_json::from_value(payload).expect("payload"))
        .await
        .expect("initialized");
    let ReadyApp::Fake(fake) = &app else {
        panic!("fake backend expected");
    };
    let clock = FixedClock(WallClock.now_unix().expect("clock") - age_secs);
    let mut rng = OsRng;
    MagicLinkRequestService {
        magic_links: &fake.store,
        limiter: &fake.store,
        outbox: &fake.outbox,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &fake.shared.lookup_hmac_key,
        config: &fake.shared.config,
    }
    .request_magic_link(RequestMagicLinkCommand::new(
        NormalizedEmail::normalize("session-fixture@example.test").expect("email"),
        true,
        true,
    ))
    .await
    .expect("requested");
    let message = fake
        .outbox
        .recorded()
        .expect("outbox")
        .pop()
        .expect("message");
    let mut flow = MagicLinkFlowService {
        authentication: &fake.store,
        sessions: &fake.store,
        limiter: &fake.store,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &fake.shared.lookup_hmac_key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &fake.shared.confirm_keyring,
        session_keyring: &fake.shared.session_keyring,
        config: &fake.shared.config,
    };
    let landing = flow
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(
            message.token.as_secret_value().as_str().to_owned(),
        ))
        .await
        .expect("landing");
    let outcome = flow
        .confirm_magic_link_flow(
            ConfirmMagicLinkFlowCommand::new(
                landing.confirm_cookie_value().to_owned(),
                landing.confirmation_value().to_owned(),
                Some("HU".to_owned()),
            )
            .expect("command"),
        )
        .await
        .expect("confirmed");
    let cookie = outcome.authentication().session_cookie_value().to_owned();
    (app, cookie)
}

async fn validate(app: &ReadyApp, cookie: &str, country: &str) -> ResultBody {
    app.handle(AppCommand::ValidateSession(SessionPayload {
        session_cookie: cookie.to_owned(),
        country: Some(country.to_owned()),
    }))
    .await
}

#[tokio::test]
async fn handler_forwards_refresh_only_when_due_and_preserves_country_and_revocation() {
    let (fresh, cookie) = session_aged(0).await;
    assert!(matches!(
        validate(&fresh, &cookie, "HU").await,
        ResultBody::ValidateSession {
            valid: true,
            refreshed_cookie: None,
            ..
        }
    ));
    let (app, cookie) = session_aged(60).await;
    let ResultBody::ValidateSession {
        valid: true,
        user_id: Some(user),
        refreshed_cookie: Some(refreshed),
    } = validate(&app, &cookie, "HU").await
    else {
        panic!("due session must forward refreshed cookie");
    };
    assert_ne!(refreshed, cookie);
    assert!(matches!(
        validate(&app, &refreshed, "HU").await,
        ResultBody::ValidateSession { valid: true, user_id: Some(same_user), .. }
            if same_user == user
    ));
    assert!(matches!(
        validate(&app, &refreshed, "DE").await,
        ResultBody::ValidateSession {
            valid: false,
            user_id: None,
            refreshed_cookie: None
        }
    ));
    assert!(matches!(
        app.handle(AppCommand::Logout(SessionPayload {
            session_cookie: refreshed.clone(),
            country: Some("HU".to_owned()),
        }))
        .await,
        ResultBody::Logout { revoked: true }
    ));
    for cookie in [&cookie, &refreshed] {
        assert!(matches!(
            validate(&app, cookie, "HU").await,
            ResultBody::ValidateSession {
                valid: false,
                user_id: None,
                refreshed_cookie: None
            }
        ));
    }
}

#[tokio::test]
async fn handler_never_refreshes_idle_or_absolute_expired_sessions() {
    // Both are safely beyond the default 60-second skew allowance.
    for age in [200, 400] {
        let (app, mut cookie) = session_aged(age).await;
        if age == 400 {
            // Keep activity fresh but preserve the original issue time, so
            // this case isolates absolute expiry from idle expiry.
            use datadeft_auth_token_core::cookie::{mint_bound_cookie, parse_bound_cookie};
            let ReadyApp::Fake(fake) = &app else {
                panic!("fake backend expected");
            };
            let now = WallClock.now_unix().expect("clock");
            let old = parse_bound_cookie::<SessionCookie>(
                &cookie,
                &fake.shared.session_keyring,
                now - age,
                fake.shared.config.session_max_age().expect("max age"),
            )
            .expect("cookie at creation");
            cookie = mint_bound_cookie::<SessionCookie, _>(
                old.body(),
                &fake.shared.session_keyring,
                &mut OsRng,
                u32::try_from(now).expect("timestamp"),
                old.iat(),
                now,
            )
            .expect("fresh activity, unchanged original issue time");
        }
        assert!(matches!(
            validate(&app, &cookie, "HU").await,
            ResultBody::ValidateSession {
                valid: false,
                user_id: None,
                refreshed_cookie: None
            }
        ));
    }
}

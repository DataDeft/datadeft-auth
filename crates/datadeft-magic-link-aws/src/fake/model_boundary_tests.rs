//! Deterministic boundary tests for the exact comparisons the model tests
//! depend on: the inclusive enable watermark, the idle/2 refresh threshold, the
//! stale-validation window, idle / absolute / skew edges, the admin "active"
//! edge, and the magic-link and flow-cookie expiry edges.

use datadeft_magic_link_service::{
    MagicLinkServiceError, SessionRepository, SessionValidationError, ValidatedSession,
};

use datadeft_auth_token_core::cookie::CLOCK_SKEW_TOLERANCE_SECS;

use super::model_support::*;

async fn validate_at(
    h: &mut Harness,
    at: u64,
    cookie: &str,
) -> Result<ValidatedSession, SessionValidationError> {
    h.clock.set(at);
    h.validate(cookie, None).await
}

/// Validate and refresh at `at`, returning the refreshed cookie if re-issued.
async fn refresh_at(h: &mut Harness, at: u64, cookie: &str) -> Option<String> {
    let validated = validate_at(h, at, cookie).await.expect("valid");
    h.refresh(&validated)
        .expect("refresh")
        .map(|value| value.as_secret_value().to_owned())
}

#[tokio::test]
async fn enable_watermark_accepts_a_login_in_the_enable_second() {
    let mut h = Harness::new(1);
    let old = h.login_at(T0, 0).await;
    let id = h.only_user();
    let store = h.store.clone();
    h.admin_with(&store)
        .disable_user(&id, &actor())
        .await
        .expect("disable");
    h.clock.set(T0 + 10);
    h.admin_with(&store)
        .enable_user(&id, &actor())
        .await
        .expect("enable");

    // The pre-disable session never comes back.
    assert_eq!(
        validate_at(&mut h, T0 + 10, &old).await.err(),
        Some(SessionValidationError::InvalidSession)
    );
    // A login in the enable's own second works (CeleraTax #12): the cutoff
    // is inclusive.
    let same_second = h.login_at(T0 + 10, 0).await;
    assert!(validate_at(&mut h, T0 + 10, &same_second).await.is_ok());
    // A session stamped one second before the watermark (an auth host whose
    // clock runs behind) is still refused.
    let store = h.store.clone();
    assert!(
        !store
            .is_session_owner_active(&id, T0 + 9)
            .await
            .expect("status")
    );
    assert!(
        store
            .is_session_owner_active(&id, T0 + 10)
            .await
            .expect("status")
    );
}

#[tokio::test]
async fn refresh_is_due_at_exactly_half_the_idle_lifetime() {
    let mut h = Harness::new(2);
    let cookie = h.login_at(T0, 0).await;
    assert!(
        refresh_at(&mut h, T0 + IDLE / 2 - 1, &cookie)
            .await
            .is_none()
    );
    assert!(refresh_at(&mut h, T0 + IDLE / 2, &cookie).await.is_some());
}

#[tokio::test]
async fn refresh_refuses_a_validation_older_than_the_skew_window() {
    let mut h = Harness::new(3);
    let cookie = h.login_at(T0, 0).await;
    let at = T0 + IDLE / 2;
    let validated = validate_at(&mut h, at, &cookie).await.expect("valid");
    h.clock.set(at + SKEW);
    assert!(h.refresh(&validated).expect("within the window").is_some());
    h.clock.set(at + SKEW + 1);
    assert_eq!(
        h.refresh(&validated).err(),
        Some(SessionValidationError::InvalidSession)
    );
    h.clock.set(at - 1);
    assert_eq!(
        h.refresh(&validated).err(),
        Some(SessionValidationError::InvalidSession)
    );
}

#[tokio::test]
async fn idle_bound_is_inclusive() {
    let mut h = Harness::new(4);
    let cookie = h.login_at(T0, 0).await;
    assert!(validate_at(&mut h, T0 + IDLE, &cookie).await.is_ok());
    assert_eq!(
        validate_at(&mut h, T0 + IDLE + 1, &cookie).await.err(),
        Some(SessionValidationError::InvalidSession)
    );
}

#[tokio::test]
async fn future_skew_bound_is_inclusive() {
    let mut h = Harness::new(5);
    let cookie = h.login_at(T0, 0).await;
    assert!(validate_at(&mut h, T0 - SKEW, &cookie).await.is_ok());
    assert_eq!(
        validate_at(&mut h, T0 - SKEW - 1, &cookie).await.err(),
        Some(SessionValidationError::InvalidSession)
    );
}

#[tokio::test]
async fn sliding_refresh_never_passes_the_absolute_lifetime() {
    let mut h = Harness::new(6);
    let mut cookie = h.login_at(T0, 0).await;
    // Keep the session active with a refresh every 301 seconds.
    let mut at = T0;
    while at + 301 <= T0 + ABSOLUTE - IDLE / 2 {
        at += 301;
        cookie = refresh_at(&mut h, at, &cookie).await.expect("due");
    }
    // The last refresh before the absolute bound is still issued...
    cookie = refresh_at(&mut h, T0 + ABSOLUTE - 1, &cookie)
        .await
        .expect("due");
    // ...validates at the bound itself, but is not re-issued there...
    assert!(refresh_at(&mut h, T0 + ABSOLUTE, &cookie).await.is_none());
    // ...and ends one second later, though its activity time is fresh.
    assert_eq!(
        validate_at(&mut h, T0 + ABSOLUTE + 1, &cookie).await.err(),
        Some(SessionValidationError::InvalidSession)
    );
}

/// `revoke_all_sessions` keeps a session in scope until the clock-skew
/// tolerance has passed after its expiry: an admin clock that runs ahead must
/// not skip a session a slower validating node still accepts.
#[tokio::test]
async fn revoke_all_covers_a_session_until_the_skew_tolerance_past_expiry() {
    let mut h = Harness::new(7);
    h.login_at(T0, 0).await;
    h.login_at(T0, 1).await;
    let ids: Vec<_> = {
        let inner = h.store.lock_inner().expect("lock");
        let mut users: Vec<_> = inner
            .user_profiles_by_id
            .values()
            .map(|user| (user.email.as_str().to_owned(), user.user_id.clone()))
            .collect();
        users.sort_by(|left, right| left.0.cmp(&right.0));
        users.into_iter().map(|(_, id)| id).collect()
    };
    let store = h.store.clone();
    h.clock.set(T0 + ABSOLUTE + CLOCK_SKEW_TOLERANCE_SECS);
    assert_eq!(
        h.admin_with(&store)
            .revoke_all_sessions(&ids[0], &actor())
            .await,
        Ok(1)
    );
    h.clock.set(T0 + ABSOLUTE + CLOCK_SKEW_TOLERANCE_SECS + 1);
    assert_eq!(
        h.admin_with(&store)
            .revoke_all_sessions(&ids[1], &actor())
            .await,
        Ok(0)
    );
}

fn consumed(h: &Harness) -> usize {
    let inner = h.store.lock_inner().expect("lock");
    inner
        .magic_links_by_selector_hmac
        .values()
        .filter(|record| record.consumed_at_unix.is_some())
        .count()
}

#[tokio::test]
async fn landing_is_refused_from_the_link_expiry_second() {
    let mut h = Harness::new(8);
    h.clock.set(T0);
    let token = h.request(&email(0)).await;
    h.clock.set(T0 + LINK_TTL - 1);
    assert!(h.land(&token).await.is_ok());
    h.clock.set(T0 + LINK_TTL);
    assert_eq!(
        h.land(&token).await.err().map(|error| error.public_error()),
        Some(MagicLinkServiceError::MagicLinkUnavailable)
    );
}

#[tokio::test]
async fn flow_cookie_lives_exactly_its_ttl_and_never_past_the_link() {
    let mut h = Harness::new(9);
    let store = h.store.clone();
    h.clock.set(T0);
    let token = h.request(&email(0)).await;
    let (cookie, confirmation) = h.land(&token).await.expect("land");
    // One second past the flow TTL: refused, link not burned.
    h.clock.set(T0 + FLOW_TTL + 1);
    assert!(
        h.confirm_with(&store, &cookie, &confirmation, None)
            .await
            .is_err()
    );
    assert_eq!(consumed(&h), 0);
    // A flow landed in the link's last seconds expires with the link: at the
    // link's expiry second the cookie still verifies, the link does not.
    h.clock.set(T0 + LINK_TTL - 30);
    let (cookie, confirmation) = h.land(&token).await.expect("late land");
    h.clock.set(T0 + LINK_TTL);
    assert!(
        h.confirm_with(&store, &cookie, &confirmation, None)
            .await
            .is_err()
    );
    assert_eq!(consumed(&h), 0);
    // At exactly the flow TTL a fresh flow confirms.
    h.clock.set(T0 + 1_000);
    let token = h.request(&email(0)).await;
    let (cookie, confirmation) = h.land(&token).await.expect("land");
    h.clock.set(T0 + 1_000 + FLOW_TTL);
    h.confirm_with(&store, &cookie, &confirmation, None)
        .await
        .expect("confirm at the TTL");
    assert_eq!(consumed(&h), 1);
}

/// Coordinator-requested reproduction. The login node's clock runs `SKEW`
/// seconds ahead of the admin/validating node (accepted by validation's
/// future-skew tolerance), so the session's `created_at` postdates the
/// admin clock. Disable's revocation of that session fails, then the user is
/// re-enabled within the skew window: the enable watermark (admin clock) is
/// earlier than `created_at`, so the pre-disable session validates again.
#[tokio::test]
async fn pre_disable_session_from_a_clock_ahead_node_stays_dead_after_enable() {
    use super::model_admin::{FailingAdmin, Fault};

    let mut h = Harness::new(10);
    // Login node clock: SKEW ahead of the admin/validating clock T0.
    let cookie = h.login_at(T0 + SKEW, 0).await;
    let id = h.only_user();
    h.clock.set(T0);
    assert!(
        h.validate(&cookie, None).await.is_ok(),
        "accepted within skew"
    );

    // Disable: call 0 sets disabled, call 1 lists, call 2 (the revoke) fails.
    let failing = FailingAdmin::new(&h.store, Fault::FailAt(2));
    let disable = h.admin_with(&failing).disable_user(&id, &actor()).await;
    assert_eq!(
        disable,
        Err(datadeft_magic_link_service::AdminError::Unavailable)
    );
    assert!(
        h.validate(&cookie, None).await.is_err(),
        "disabled user rejected"
    );

    // Re-enable 10 s later on the admin clock: watermark T0 + 10 < created_at.
    h.clock.set(T0 + 10);
    let store = h.store.clone();
    h.admin_with(&store)
        .enable_user(&id, &actor())
        .await
        .expect("enable");

    // Documented guarantee: enabling never restores a pre-disable session.
    assert_eq!(
        h.validate(&cookie, None).await.err(),
        Some(SessionValidationError::InvalidSession),
        "pre-disable session must not validate after re-enable"
    );
}

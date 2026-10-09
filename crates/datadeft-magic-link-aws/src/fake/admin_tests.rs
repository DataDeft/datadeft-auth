//! Admin queries, audited mutations, and their failure recovery on the fake store.

//! Fake store integration tests.

use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_core::{LookupHmacKey, NormalizedEmail};
use datadeft_magic_link_service::{SessionRepository, UserId};

use super::test_support::*;
use super::*;

// --- admin -----------------------------------------------------------------

use datadeft_magic_link_service::{
    AdminAction, AdminActor, AdminError, AuthAdminService, SessionStatus,
};

fn admin_actor() -> AdminActor {
    AdminActor::new("admin@example.test", Some("support ticket".to_owned())).expect("actor")
}

fn admin_service<'a>(
    store: &'a FakeDynamoDbAuthStore,
    rng: &'a mut CountingRng,
) -> AuthAdminService<'a, FakeDynamoDbAuthStore, FixedClock, CountingRng> {
    AuthAdminService {
        admin: store,
        clock: &FixedClock,
        rng,
    }
}

/// Log the default test user in twice: two sessions, one user.
async fn store_with_two_sessions() -> (FakeDynamoDbAuthStore, UserId) {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let first = login_with_keys(&store, &mut rng, &key, &key, None)
        .await
        .expect("first login");
    login_with_keys(&store, &mut rng, &key, &key, None)
        .await
        .expect("second login");
    (store, first.authentication().user_id().clone())
}

#[tokio::test]
async fn admin_queries_return_users_and_sessions() {
    let (store, user_id) = store_with_two_sessions().await;
    store.seed_user(user_record(false)).expect("second user");
    let mut rng = CountingRng::starting_at(50);
    let admin = admin_service(&store, &mut rng);

    let page = admin.list_users(None, 1).await.expect("page 1");
    assert_eq!(page.items.len(), 1);
    let rest = admin
        .list_users(page.next.as_ref(), 10)
        .await
        .expect("page 2");
    assert_eq!(rest.items.len(), 1);
    assert!(rest.next.is_none());

    let email = NormalizedEmail::parse("user@example.com").expect("email");
    let found = admin
        .find_user_by_email(&email)
        .await
        .expect("find")
        .expect("user exists");
    assert_eq!(found.user_id, user_id);
    assert!(!found.disabled);
    assert_eq!(
        admin
            .get_user(&user_id)
            .await
            .expect("get")
            .map(|user| user.email),
        Some(email)
    );

    let sessions = admin
        .list_sessions_for_user(&user_id)
        .await
        .expect("sessions");
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|(_, status)| *status == SessionStatus::Active)
    );
    for (session, _) in &sessions {
        assert!(session.handle.display_id().starts_with("sess_"));
        assert_eq!(session.user_id, user_id);
    }
    let active = admin.list_active_sessions(None, 10).await.expect("active");
    assert_eq!(active.items.len(), 2);
}

#[tokio::test]
async fn revoking_one_session_is_final_audited_and_owner_checked() {
    let (store, user_id) = store_with_two_sessions().await;
    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);
    let sessions = admin
        .list_sessions_for_user(&user_id)
        .await
        .expect("sessions");
    let handle = sessions[0].0.handle.clone();

    // Another user cannot be named as the owner.
    let stranger = UserId::parse("usr_ffffffffffffffffffffffffffffffff").expect("user id");
    assert_eq!(
        admin
            .revoke_session(&stranger, &handle, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::NotFound
    );

    admin
        .revoke_session(&user_id, &handle, &admin_actor())
        .await
        .expect("revoke");
    assert_eq!(
        admin
            .revoke_session(&user_id, &handle, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::AlreadyInState
    );

    let sessions = admin
        .list_sessions_for_user(&user_id)
        .await
        .expect("sessions");
    let (revoked, status) = sessions
        .iter()
        .find(|(session, _)| session.handle == handle)
        .expect("still listed: nothing is deleted");
    assert_eq!(*status, SessionStatus::Revoked);
    assert_eq!(revoked.revoked_by.as_deref(), Some("admin@example.test"));
    assert_eq!(
        admin
            .list_active_sessions(None, 10)
            .await
            .expect("active")
            .items
            .len(),
        1
    );

    let events = admin
        .list_admin_events(&user_id, None, 10)
        .await
        .expect("events");
    assert_eq!(events.items.len(), 1);
    let event = &events.items[0];
    assert_eq!(event.action, AdminAction::RevokeSession);
    assert_eq!(event.session.as_ref(), Some(&handle));
    assert_eq!(event.actor.reason(), Some("support ticket"));
    assert_eq!(event.at_unix, 1_000);
}

#[tokio::test]
async fn revoke_all_sessions_is_repeatable() {
    let (store, user_id) = store_with_two_sessions().await;
    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);

    assert_eq!(
        admin
            .revoke_all_sessions(&user_id, &admin_actor())
            .await
            .expect("revoke all"),
        2
    );
    assert_eq!(
        admin
            .revoke_all_sessions(&user_id, &admin_actor())
            .await
            .expect("again"),
        0
    );
    assert!(
        admin
            .list_active_sessions(None, 10)
            .await
            .expect("active")
            .items
            .is_empty()
    );
    // One audited event per revoked session.
    assert_eq!(
        admin
            .list_admin_events(&user_id, None, 10)
            .await
            .expect("events")
            .items
            .len(),
        2
    );
}

#[tokio::test]
async fn disabling_a_user_blocks_login_and_every_session_until_enabled() {
    let (store, user_id) = store_with_two_sessions().await;
    let key = LookupHmacKey::new([0x42; 32]);
    let mut login_rng = CountingRng::starting_at(100);
    let mut rng = CountingRng::starting_at(50);

    {
        let mut admin = admin_service(&store, &mut rng);
        assert_eq!(
            admin
                .disable_user(&user_id, &admin_actor())
                .await
                .expect("disable"),
            2
        );
        // Repeating a disable is safe: it completes revocation (none left).
        assert_eq!(
            admin
                .disable_user(&user_id, &admin_actor())
                .await
                .expect("repeat"),
            0
        );
        let user = admin.get_user(&user_id).await.expect("get").expect("user");
        assert!(user.disabled);
        assert_eq!(user.disabled_at_unix, Some(1_000));
        assert_eq!(user.disabled_by.as_deref(), Some("admin@example.test"));
    }
    assert!(
        !store
            .is_session_owner_active(&user_id, 1_000)
            .await
            .expect("status")
    );
    assert!(
        login_with_keys(&store, &mut login_rng, &key, &key, None)
            .await
            .is_err(),
        "a disabled user cannot log in"
    );

    {
        let mut admin = admin_service(&store, &mut rng);
        admin
            .enable_user(&user_id, &admin_actor())
            .await
            .expect("enable");
        assert_eq!(
            admin
                .enable_user(&user_id, &admin_actor())
                .await
                .unwrap_err(),
            AdminError::AlreadyInState
        );
        let user = admin.get_user(&user_id).await.expect("get").expect("user");
        assert!(!user.disabled);
        assert_eq!(user.disabled_by, None);
        // Revocation is final: enabling does not restore old sessions.
        assert!(
            admin
                .list_sessions_for_user(&user_id)
                .await
                .expect("sessions")
                .iter()
                .all(|(_, status)| *status == SessionStatus::Revoked)
        );

        let events = admin
            .list_admin_events(&user_id, None, 10)
            .await
            .expect("events");
        // All four happened within the same second (FixedClock), where the
        // order follows the random event id, as in DynamoDB. Check the set.
        let mut actions: Vec<&str> = events
            .items
            .iter()
            .map(|event| event.action.as_str())
            .collect();
        actions.sort_unstable();
        assert_eq!(
            actions,
            [
                "disable_user",
                "enable_user",
                "revoke_session",
                "revoke_session"
            ]
        );
    }
    // Sessions created after the re-enable are accepted.
    assert!(
        store
            .is_session_owner_active(&user_id, 1_001)
            .await
            .expect("status")
    );
    login_with_keys(&store, &mut login_rng, &key, &key, None)
        .await
        .expect("an enabled user can log in again");
}

#[tokio::test]
async fn admin_mutations_on_unknown_users_report_not_found() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);
    let unknown = UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id");
    assert_eq!(
        admin
            .disable_user(&unknown, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::NotFound
    );
    assert_eq!(
        admin
            .enable_user(&unknown, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::NotFound
    );
    assert_eq!(
        admin
            .revoke_all_sessions(&unknown, &admin_actor())
            .await
            .expect("nothing to revoke"),
        0
    );
}

/// The state a disable leaves behind when revoking then fails: disabled,
/// sessions still unrevoked.
async fn disable_without_revoking(store: &FakeDynamoDbAuthStore, user_id: &UserId) {
    use datadeft_magic_link_service::{AdminEvent, AdminEventId, AuthAdminRepository};
    store
        .set_user_disabled_audited(&AdminEvent {
            event_id: AdminEventId::parse("evt_000102030405060708090a0b0c0d0e0f").expect("id"),
            at_unix: 1_500,
            action: AdminAction::DisableUser,
            user_id: user_id.clone(),
            session: None,
            actor: admin_actor(),
        })
        .await
        .expect("disable");
}

#[tokio::test]
async fn retried_disable_finishes_revoking_after_a_partial_failure() {
    let (store, user_id) = store_with_two_sessions().await;
    disable_without_revoking(&store, &user_id).await;

    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);
    // The retry must not stop at "already disabled".
    assert_eq!(
        admin
            .disable_user(&user_id, &admin_actor())
            .await
            .expect("retry"),
        2
    );
    assert!(
        admin
            .list_sessions_for_user(&user_id)
            .await
            .expect("sessions")
            .iter()
            .all(|(_, status)| *status == SessionStatus::Revoked)
    );
}

#[tokio::test]
async fn enabling_never_restores_sessions_from_before_the_disable() {
    let (store, user_id) = store_with_two_sessions().await;
    // Sessions were created at 1_000. Disable without revoking them, as a
    // partial failure would, then enable later at 2_000.
    disable_without_revoking(&store, &user_id).await;
    let mut rng = CountingRng::starting_at(50);
    let mut admin = AuthAdminService {
        admin: &store,
        clock: &At(2_000),
        rng: &mut rng,
    };
    admin
        .enable_user(&user_id, &admin_actor())
        .await
        .expect("enable");

    // Unrevoked, yet rejected: they predate the re-enable watermark.
    assert!(
        !store
            .is_session_owner_active(&user_id, 1_000)
            .await
            .expect("status")
    );
    // Sessions from after the re-enable work. The watermark is strict: a
    // session from the enable's own second does not count as "after".
    assert!(
        !store
            .is_session_owner_active(&user_id, 2_000)
            .await
            .expect("status")
    );
    assert!(
        store
            .is_session_owner_active(&user_id, 2_001)
            .await
            .expect("status")
    );
}

#[tokio::test]
async fn index_rows_without_a_session_row_are_skipped() {
    let (store, user_id) = store_with_two_sessions().await;
    // Simulate a legacy TTL deleting one session row but not its index row.
    {
        let mut inner = store.inner.lock().expect("lock");
        let orphan = inner
            .sessions_by_hmac
            .keys()
            .next()
            .cloned()
            .expect("a session");
        inner.sessions_by_hmac.remove(&orphan);
    }
    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);
    assert_eq!(
        admin
            .list_sessions_for_user(&user_id)
            .await
            .expect("listing still works")
            .len(),
        1
    );
    assert_eq!(
        admin
            .disable_user(&user_id, &admin_actor())
            .await
            .expect("disable"),
        1
    );
}

#[tokio::test]
async fn revoke_all_leaves_expired_sessions_alone() {
    let (store, user_id) = store_with_two_sessions().await;
    // Both sessions (created at 1_000) have expired by this far-future time.
    let mut rng = CountingRng::starting_at(50);
    let mut admin = AuthAdminService {
        admin: &store,
        clock: &At(1_000 + 400 * 24 * 60 * 60),
        rng: &mut rng,
    };
    assert_eq!(
        admin
            .revoke_all_sessions(&user_id, &admin_actor())
            .await
            .expect("revoke all"),
        0
    );
    // Nothing to audit: expired sessions were already over.
    assert!(
        admin
            .list_admin_events(&user_id, None, 10)
            .await
            .expect("events")
            .items
            .is_empty()
    );
}

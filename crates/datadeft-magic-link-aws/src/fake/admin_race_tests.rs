//! Two admin workflows on one user, interleaved deterministically: an
//! `enable_user` whose final write is delayed (a slow or retried request)
//! lands after another admin has enabled, the user has logged in again, and a
//! third admin has disabled the user again.

use std::sync::Arc;

use datadeft_magic_link_service::{
    AdminAction, AdminError, AdminEvent, AuthAdminRepository, AuthAdminService, DependencyError,
    NormalizedEmail, Page, PageCursor, SessionSummary, UserId, UserSummary,
};
use tokio::sync::Notify;

use super::model_admin::{FailingAdmin, Fault};
use super::model_support::*;
use super::*;

/// Delegates to the store, but holds the enable write until released.
struct GatedEnable {
    store: FakeDynamoDbAuthStore,
    reached: Arc<Notify>,
    release: Arc<Notify>,
}

impl AuthAdminRepository for GatedEnable {
    async fn list_users(
        &self,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<UserSummary>, DependencyError> {
        self.store.list_users(cursor, limit).await
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<UserSummary>, DependencyError> {
        self.store.get_user(user_id).await
    }

    async fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserSummary>, DependencyError> {
        self.store.find_user_by_email(email).await
    }

    async fn list_sessions_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<SessionSummary>, DependencyError> {
        self.store.list_sessions_for_user(user_id).await
    }

    async fn list_active_sessions(
        &self,
        now_unix: u64,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<SessionSummary>, DependencyError> {
        self.store
            .list_active_sessions(now_unix, cursor, limit)
            .await
    }

    async fn revoke_session_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        self.store.revoke_session_audited(event).await
    }

    async fn set_user_disabled_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        if event.action == AdminAction::EnableUser {
            self.reached.notify_one();
            self.release.notified().await;
        }
        self.store.set_user_disabled_audited(event).await
    }

    async fn list_admin_events(
        &self,
        user_id: &UserId,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<AdminEvent>, DependencyError> {
        self.store.list_admin_events(user_id, cursor, limit).await
    }
}

async fn login_at(h: &mut Harness, at: u64) -> String {
    h.clock.set(at);
    let outcome = h.login(&email(0), None).await.expect("login");
    outcome.authentication().session_cookie_value().to_owned()
}

fn only_user(h: &Harness) -> UserId {
    h.store
        .lock_inner()
        .expect("lock")
        .user_profiles_by_id
        .values()
        .next()
        .expect("user")
        .user_id
        .clone()
}

/// Accepted tradeoff ADM-F1 (docs/security.md): concurrent admin actions on
/// one user are last-write-wins. X's enable observed an earlier disabled
/// period; its delayed write lands after Y's enable, a login (S1), and Z's
/// disable whose revocation of S1 failed. The write succeeds, Z's disable is
/// undone, and S1 validates again. The user record shows the real state; the
/// audit log lists X's enable before Z's disable. If this test starts failing,
/// the behaviour changed: update the docs with it.
#[tokio::test]
async fn concurrent_admin_actions_are_last_write_wins() {
    let mut h = Harness::new(41);
    login_at(&mut h, T0).await;
    let id = only_user(&h);
    let store = h.store.clone();
    h.clock.set(T0 + 1);
    h.admin_with(&store)
        .disable_user(&id, &actor())
        .await
        .expect("first disable");

    let gated = GatedEnable {
        store: store.clone(),
        reached: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    };
    let x_clock = ManualClock::new(T0 + 10);
    let mut x_rng = SplitMixRng::new(7);
    let mut x_admin = AuthAdminService {
        admin: &gated,
        clock: &x_clock,
        rng: &mut x_rng,
    };

    let x_actor = actor();
    let (x_result, s1) = tokio::join!(x_admin.enable_user(&id, &x_actor), async {
        gated.reached.notified().await;
        // Y enables; the user logs in again (S1).
        h.clock.set(T0 + 20);
        h.admin_with(&store)
            .enable_user(&id, &actor())
            .await
            .expect("Y enable");
        let s1 = login_at(&mut h, T0 + 30).await;
        // Z disables; the revocation of S1 fails (call 2 is the revoke).
        h.clock.set(T0 + 40);
        let failing = FailingAdmin::new(&store, Fault::FailAt(2));
        assert_eq!(
            h.admin_with(&failing).disable_user(&id, &actor()).await,
            Err(AdminError::Unavailable)
        );
        assert!(h.validate(&s1, None).await.is_err(), "Z's disable holds");
        gated.release.notify_one();
        s1
    });

    // X's delayed enable lands and wins.
    assert_eq!(x_result, Ok(()));
    let user = store.get_user(&id).await.expect("get").expect("user");
    assert!(!user.disabled, "the user record shows the real state");
    h.clock.set(T0 + 50);
    assert!(h.validate(&s1, None).await.is_ok(), "S1 is live again");

    // The audit log lists events by their prepared time: X's enable (T0+10)
    // sorts below Z's disable (T0+40) although it was applied last.
    let events = store
        .list_admin_events(&id, None, 100)
        .await
        .expect("events")
        .items;
    let toggles: Vec<(AdminAction, u64)> = events
        .iter()
        .filter(|event| event.action != AdminAction::RevokeSession)
        .map(|event| (event.action, event.at_unix))
        .collect();
    assert_eq!(
        toggles,
        vec![
            (AdminAction::DisableUser, T0 + 40),
            (AdminAction::EnableUser, T0 + 20),
            (AdminAction::EnableUser, T0 + 10),
            (AdminAction::DisableUser, T0 + 1),
        ]
    );
}

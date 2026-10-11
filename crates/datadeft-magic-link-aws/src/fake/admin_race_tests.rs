//! Two admin workflows on one user, interleaved deterministically: an
//! `enable_user` whose final write is delayed (a slow or retried request)
//! lands after another admin has enabled, the user has logged in again, and a
//! third admin has disabled the user again (ADM-F1, fixed in 0.5.0).

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

    async fn set_user_disabled_audited(
        &self,
        event: &AdminEvent,
        expected_version: Option<u64>,
    ) -> Result<(), DependencyError> {
        if event.action == AdminAction::EnableUser {
            self.reached.notify_one();
            self.release.notified().await;
        }
        self.store
            .set_user_disabled_audited(event, expected_version)
            .await
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

/// ADM-F1 (docs/security.md): X's enable observed an earlier disabled period;
/// its delayed write lands after Y's enable, a login (S1), and Z's disable
/// whose revocation of S1 failed. Admin writes are conditional on the
/// version they read, so X's write fails with `Conflict`: Z's disable holds,
/// S1 stays rejected, and the audit log has no enable from X. (Under 0.4 the
/// write succeeded and silently undid Z's disable.)
#[tokio::test]
async fn a_stale_admin_write_conflicts_instead_of_undoing_a_later_one() {
    let mut h = Harness::new(41);
    h.login_at(T0, 0).await;
    let id = h.only_user();
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
        let s1 = h.login_at(T0 + 30, 0).await;
        // Z disables; the revocation of S1 fails (calls: write, list, then
        // the revoke).
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

    // X's delayed enable lost the race and wrote nothing.
    assert_eq!(x_result, Err(AdminError::Conflict));
    let user = store.get_user(&id).await.expect("get").expect("user");
    assert!(user.disabled, "Z's disable holds");
    h.clock.set(T0 + 50);
    assert!(h.validate(&s1, None).await.is_err(), "S1 stays rejected");

    // The audit log has every applied toggle and nothing from X.
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
            (AdminAction::DisableUser, T0 + 1),
        ]
    );
}

/// The race the security review found: X's enable reads the disabled user and
/// is still revoking when Y disables the (already disabled) user and is told
/// it succeeded. Y's disable writes a version bump even though the flag does
/// not change, so X's delayed enable conflicts and the user stays disabled.
#[tokio::test]
async fn a_disable_of_a_disabled_user_still_fences_a_slow_enable() {
    let mut h = Harness::new(43);
    h.login_at(T0, 0).await;
    let id = h.only_user();
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
    let mut x_rng = SplitMixRng::new(9);
    let mut x_admin = AuthAdminService {
        admin: &gated,
        clock: &x_clock,
        rng: &mut x_rng,
    };
    let x_actor = actor();
    let (x_result, ()) = tokio::join!(x_admin.enable_user(&id, &x_actor), async {
        gated.reached.notified().await;
        h.clock.set(T0 + 20);
        assert_eq!(
            h.admin_with(&store).disable_user(&id, &actor()).await,
            Ok(0),
            "Y's disable reports success"
        );
        gated.release.notify_one();
    });

    assert_eq!(x_result, Err(AdminError::Conflict));
    let user = store.get_user(&id).await.expect("get").expect("user");
    assert!(user.disabled, "Y's disable holds");
    assert_eq!(
        user.disabled_at_unix,
        Some(T0 + 1),
        "the first disable's time is kept"
    );
}

/// Delegates to the store; on the first disable write, another admin's
/// disable lands first, so this one's version is stale.
struct RacingDisable {
    store: FakeDynamoDbAuthStore,
    raced: std::sync::atomic::AtomicBool,
}

impl AuthAdminRepository for RacingDisable {
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

    async fn set_user_disabled_audited(
        &self,
        event: &AdminEvent,
        expected_version: Option<u64>,
    ) -> Result<(), DependencyError> {
        if event.action == AdminAction::DisableUser
            && !self.raced.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let mut other = event.clone();
            other.event_id = datadeft_magic_link_service::AdminEventId::parse(
                "evt-0f0e0d0c0b0a09080706050403020100",
            )
            .expect("id");
            self.store
                .set_user_disabled_audited(&other, expected_version)
                .await?;
        }
        self.store
            .set_user_disabled_audited(event, expected_version)
            .await
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

/// A disable never loses a version race: another admin's disable landing
/// between this one's call and its write does not stop it, and both bump the
/// version (so an enable that read before either is fenced).
#[tokio::test]
async fn a_disable_that_loses_a_version_race_writes_again() {
    let mut h = Harness::new(47);
    h.login_at(T0, 0).await;
    let id = h.only_user();
    let store = h.store.clone();
    let before = store.get_user(&id).await.expect("get").expect("user");
    let racing = RacingDisable {
        store: store.clone(),
        raced: std::sync::atomic::AtomicBool::new(false),
    };
    h.clock.set(T0 + 1);
    assert!(
        h.admin_with(&racing)
            .disable_user(&id, &actor())
            .await
            .is_ok()
    );
    let after = store.get_user(&id).await.expect("get").expect("user");
    assert!(after.disabled);
    // The other admin's write and this call's own retried write.
    assert_eq!(after.admin_version, before.admin_version + 2);
}

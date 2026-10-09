//! Fault injection for the admin repository in the model tests.
//!
//! `FailingAdmin` counts every `AuthAdminRepository` call of one service
//! operation and fails the chosen one, either before it reaches the store
//! (`FailAt`: nothing applied) or after (`AckLostAt`: applied, but the caller
//! sees `Unavailable`, like a lost transaction acknowledgement). The reference
//! model replays the same call sequence through [`Budget`].

use core::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};

use datadeft_magic_link_service::{
    AdminEvent, AuthAdminRepository, DependencyError, NormalizedEmail, Page, PageCursor,
    SessionSummary, UserId, UserSummary,
};

use super::*;

/// Which repository call of one admin operation fails, and how.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fault {
    None,
    /// Fail call `n` (0-based) before it reaches storage.
    FailAt(u8),
    /// Apply call `n`, then report `Unavailable`.
    AckLostAt(u8),
}

/// What happens to one repository call under a [`Fault`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fate {
    Normal,
    Fail,
    AckLost,
}

impl Fault {
    fn fate(self, call: u8) -> Fate {
        match self {
            Fault::FailAt(at) if at == call => Fate::Fail,
            Fault::AckLostAt(at) if at == call => Fate::AckLost,
            _ => Fate::Normal,
        }
    }
}

/// The model's replay of the repository call counter.
pub(super) struct Budget {
    next: u8,
    fault: Fault,
}

impl Budget {
    pub(super) fn new(fault: Fault) -> Self {
        Self { next: 0, fault }
    }

    pub(super) fn call(&mut self) -> Fate {
        let fate = self.fault.fate(self.next);
        self.next = self.next.saturating_add(1);
        fate
    }
}

/// An admin repository over the fake store that fails one chosen call.
pub(super) struct FailingAdmin {
    store: FakeDynamoDbAuthStore,
    calls: AtomicU8,
    fault: Fault,
}

impl FailingAdmin {
    pub(super) fn new(store: &FakeDynamoDbAuthStore, fault: Fault) -> Self {
        Self {
            store: store.clone(),
            calls: AtomicU8::new(0),
            fault,
        }
    }

    fn fate(&self) -> Fate {
        self.fault.fate(self.calls.fetch_add(1, Ordering::SeqCst))
    }

    /// Run `call` under this call's fate.
    async fn guarded<T>(
        &self,
        call: impl Future<Output = Result<T, DependencyError>>,
    ) -> Result<T, DependencyError> {
        match self.fate() {
            Fate::Normal => call.await,
            Fate::Fail => Err(DependencyError::Unavailable),
            Fate::AckLost => {
                let _applied = call.await;
                Err(DependencyError::Unavailable)
            }
        }
    }
}

impl AuthAdminRepository for FailingAdmin {
    async fn list_users(
        &self,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<UserSummary>, DependencyError> {
        self.guarded(self.store.list_users(cursor, limit)).await
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<UserSummary>, DependencyError> {
        self.guarded(self.store.get_user(user_id)).await
    }

    async fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserSummary>, DependencyError> {
        self.guarded(self.store.find_user_by_email(email)).await
    }

    async fn list_sessions_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<SessionSummary>, DependencyError> {
        self.guarded(self.store.list_sessions_for_user(user_id))
            .await
    }

    async fn list_active_sessions(
        &self,
        now_unix: u64,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<SessionSummary>, DependencyError> {
        self.guarded(self.store.list_active_sessions(now_unix, cursor, limit))
            .await
    }

    async fn revoke_session_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        self.guarded(self.store.revoke_session_audited(event)).await
    }

    async fn set_user_disabled_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        self.guarded(self.store.set_user_disabled_audited(event))
            .await
    }

    async fn list_admin_events(
        &self,
        user_id: &UserId,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<AdminEvent>, DependencyError> {
        self.guarded(self.store.list_admin_events(user_id, cursor, limit))
            .await
    }
}

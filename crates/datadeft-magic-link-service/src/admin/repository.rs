//! The storage trait behind the admin service.

use core::future::Future;

use datadeft_magic_link_core::NormalizedEmail;

use crate::error::DependencyError;
use crate::types::UserId;

use super::types::*;

/// Storage for admin queries and audited mutations.
///
/// Every mutation writes the change and its [`AdminEvent`] atomically: both or
/// neither. Mutations report a missing target and a target already in the
/// requested state as `DependencyError::ConditionalWriteFailed`; the service
/// tells them apart with a read.
pub trait AuthAdminRepository {
    /// Users in storage order. `limit` is already clamped by the service.
    fn list_users(
        &self,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Page<UserSummary>, DependencyError>> + Send;

    fn get_user(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<Option<UserSummary>, DependencyError>> + Send;

    fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> impl Future<Output = Result<Option<UserSummary>, DependencyError>> + Send;

    /// Every session the user ever had, active or not, newest first.
    fn list_sessions_for_user(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<Vec<SessionSummary>, DependencyError>> + Send;

    /// Sessions that are neither revoked nor expired at `now_unix`.
    fn list_active_sessions(
        &self,
        now_unix: u64,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Page<SessionSummary>, DependencyError>> + Send;

    /// Revoke the session at `event.session` if it belongs to `event.user_id`
    /// and is not revoked yet, recording `event` atomically with it.
    fn revoke_session_audited(
        &self,
        event: &AdminEvent,
    ) -> impl Future<Output = Result<(), DependencyError>> + Send;

    /// Set the user's disabled flag (`DisableUser` / `EnableUser`) if it is
    /// not already in that state, recording `event` atomically with it.
    fn set_user_disabled_audited(
        &self,
        event: &AdminEvent,
    ) -> impl Future<Output = Result<(), DependencyError>> + Send;

    /// The user's audit events, newest first.
    fn list_admin_events(
        &self,
        user_id: &UserId,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Page<AdminEvent>, DependencyError>> + Send;
}

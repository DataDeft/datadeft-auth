//! The storage trait behind the admin service.

use core::future::Future;

use datadeft_magic_link_core::NormalizedEmail;

use crate::error::DependencyError;
use crate::types::UserId;

use super::types::{AdminEvent, Page, PageCursor, SessionSummary, UserSummary};

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

    /// Apply `event` and bump the user's `admin_version`, recording `event`
    /// atomically with it.
    ///
    /// - `DisableUser` (`expected_version: None`) is unconditional apart from
    ///   the user existing: disabling is the safe direction, and its version
    ///   bump fences any enable that read the user earlier. Re-disabling keeps
    ///   the first disable's time and admin.
    /// - `EnableUser` (`expected_version: Some(v)`) requires the user to be
    ///   disabled **and** still at version `v`.
    ///
    /// Any failed condition is `DependencyError::ConditionalWriteFailed`.
    fn set_user_disabled_audited(
        &self,
        event: &AdminEvent,
        expected_version: Option<u64>,
    ) -> impl Future<Output = Result<(), DependencyError>> + Send;

    /// The user's audit events, newest first.
    fn list_admin_events(
        &self,
        user_id: &UserId,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Page<AdminEvent>, DependencyError>> + Send;
}

//! AuthAdminService: admin queries and audited mutations.

use datadeft_magic_link_core::NormalizedEmail;
use rand_core::{CryptoRng, RngCore};

use crate::error::DependencyError;
use crate::traits::Clock;
use crate::types::UserId;

use super::repository::AuthAdminRepository;
use super::types::*;
use super::*;

/// Admin queries and audited mutations over an [`AuthAdminRepository`].
///
/// Construct with a struct literal. The clock timestamps audit events and
/// classifies sessions; the CSPRNG generates audit event ids.
pub struct AuthAdminService<'a, Repository, ServiceClock, Rng: ?Sized> {
    pub admin: &'a Repository,
    pub clock: &'a ServiceClock,
    pub rng: &'a mut Rng,
}

impl<Repository, ServiceClock, Rng> AuthAdminService<'_, Repository, ServiceClock, Rng>
where
    Repository: AuthAdminRepository,
    ServiceClock: Clock,
    Rng: RngCore + CryptoRng + ?Sized,
{
    /// One page of users. `limit` is clamped to `1..=MAX_ADMIN_PAGE_SIZE`.
    pub async fn list_users(
        &self,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<UserSummary>, AdminError> {
        self.admin
            .list_users(cursor, clamp_limit(limit))
            .await
            .map_err(map_admin_dependency_error)
    }

    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<UserSummary>, AdminError> {
        self.admin
            .get_user(user_id)
            .await
            .map_err(map_admin_dependency_error)
    }

    pub async fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserSummary>, AdminError> {
        self.admin
            .find_user_by_email(email)
            .await
            .map_err(map_admin_dependency_error)
    }

    /// Every session of the user, newest first, with each one's status now.
    pub async fn list_sessions_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<(SessionSummary, SessionStatus)>, AdminError> {
        let now_unix = self.now()?;
        let sessions = self
            .admin
            .list_sessions_for_user(user_id)
            .await
            .map_err(map_admin_dependency_error)?;
        Ok(sessions
            .into_iter()
            .map(|session| {
                let status = session.status(now_unix);
                (session, status)
            })
            .collect())
    }

    /// One page of currently active sessions across all users.
    pub async fn list_active_sessions(
        &self,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<SessionSummary>, AdminError> {
        let now_unix = self.now()?;
        self.admin
            .list_active_sessions(now_unix, cursor, clamp_limit(limit))
            .await
            .map_err(map_admin_dependency_error)
    }

    /// The user's audit trail, newest first.
    pub async fn list_admin_events(
        &self,
        user_id: &UserId,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<AdminEvent>, AdminError> {
        self.admin
            .list_admin_events(user_id, cursor, clamp_limit(limit))
            .await
            .map_err(map_admin_dependency_error)
    }

    /// End one session. Final: a revoked session cannot be restored.
    ///
    /// `user_id` must own the session (the UI got the handle from
    /// [`Self::list_sessions_for_user`]), so the audit event names the right
    /// user. Returns [`AdminError::NotFound`] if it does not, and
    /// [`AdminError::AlreadyInState`] if the session is already revoked.
    pub async fn revoke_session(
        &mut self,
        user_id: &UserId,
        handle: &SessionHandle,
        actor: &AdminActor,
    ) -> Result<(), AdminError> {
        let event = self.event(AdminAction::RevokeSession, user_id, Some(handle), actor)?;
        match self.admin.revoke_session_audited(&event).await {
            Ok(()) => Ok(()),
            Err(DependencyError::ConditionalWriteFailed) => {
                let sessions = self
                    .admin
                    .list_sessions_for_user(user_id)
                    .await
                    .map_err(map_admin_dependency_error)?;
                match sessions.iter().find(|session| session.handle == *handle) {
                    Some(session) if session.revoked_at_unix.is_some() => {
                        Err(AdminError::AlreadyInState)
                    }
                    _ => Err(AdminError::NotFound),
                }
            }
            Err(error) => Err(map_admin_dependency_error(error)),
        }
    }

    /// End every session of the user that is not revoked yet ("log out
    /// everywhere"). Each revocation is audited on its own. Returns how many
    /// sessions this call revoked; a second call returns 0.
    ///
    /// Not atomic across sessions: on an error, call it again to finish. A
    /// session created while it runs can be missed, which is why
    /// [`Self::disable_user`] disables first: a disabled user's sessions are
    /// rejected on every request regardless of revocation.
    pub async fn revoke_all_sessions(
        &mut self,
        user_id: &UserId,
        actor: &AdminActor,
    ) -> Result<u64, AdminError> {
        let sessions = self
            .admin
            .list_sessions_for_user(user_id)
            .await
            .map_err(map_admin_dependency_error)?;
        let mut revoked = 0u64;
        for session in sessions
            .iter()
            .filter(|session| session.revoked_at_unix.is_none())
        {
            let event = self.event(
                AdminAction::RevokeSession,
                user_id,
                Some(&session.handle),
                actor,
            )?;
            match self.admin.revoke_session_audited(&event).await {
                Ok(()) => revoked = revoked.saturating_add(1),
                // Revoked concurrently: the goal is reached, keep going.
                Err(DependencyError::ConditionalWriteFailed) => {}
                Err(error) => return Err(map_admin_dependency_error(error)),
            }
        }
        Ok(revoked)
    }

    /// Disable the user: login is blocked and every session is rejected from
    /// the next request on. Then revoke all sessions, so the audit trail shows
    /// each one ending. Returns how many sessions this call revoked.
    ///
    /// Safe to retry. On an error the user may already be disabled (their
    /// sessions are rejected regardless); calling again finishes revoking.
    /// Calling it for an already-disabled user just completes revocation.
    pub async fn disable_user(
        &mut self,
        user_id: &UserId,
        actor: &AdminActor,
    ) -> Result<u64, AdminError> {
        match self
            .set_disabled(AdminAction::DisableUser, user_id, actor)
            .await
        {
            Ok(()) | Err(AdminError::AlreadyInState) => {}
            Err(error) => return Err(error),
        }
        self.revoke_all_sessions(user_id, actor).await
    }

    /// Enable a disabled user. No session from before this moment works
    /// again, even one whose revocation failed: enabling stamps a
    /// `sessions_valid_after` watermark that session validation enforces. The
    /// user logs in again.
    pub async fn enable_user(
        &mut self,
        user_id: &UserId,
        actor: &AdminActor,
    ) -> Result<(), AdminError> {
        self.set_disabled(AdminAction::EnableUser, user_id, actor)
            .await
    }

    async fn set_disabled(
        &mut self,
        action: AdminAction,
        user_id: &UserId,
        actor: &AdminActor,
    ) -> Result<(), AdminError> {
        let event = self.event(action, user_id, None, actor)?;
        match self.admin.set_user_disabled_audited(&event).await {
            Ok(()) => Ok(()),
            Err(DependencyError::ConditionalWriteFailed) => {
                match self
                    .admin
                    .get_user(user_id)
                    .await
                    .map_err(map_admin_dependency_error)?
                {
                    Some(_) => Err(AdminError::AlreadyInState),
                    None => Err(AdminError::NotFound),
                }
            }
            Err(error) => Err(map_admin_dependency_error(error)),
        }
    }

    fn event(
        &mut self,
        action: AdminAction,
        user_id: &UserId,
        session: Option<&SessionHandle>,
        actor: &AdminActor,
    ) -> Result<AdminEvent, AdminError> {
        let mut bytes = [0u8; ADMIN_EVENT_ID_BYTES];
        self.rng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| AdminError::Unavailable)?;
        let event_id =
            AdminEventId::parse(&format!("{ADMIN_EVENT_ID_PREFIX}{}", hex::encode(bytes)))?;
        Ok(AdminEvent {
            event_id,
            at_unix: self.now()?,
            action,
            user_id: user_id.clone(),
            session: session.cloned(),
            actor: actor.clone(),
        })
    }

    fn now(&self) -> Result<u64, AdminError> {
        self.clock.now_unix().map_err(map_admin_dependency_error)
    }
}

pub(super) fn clamp_limit(limit: u32) -> u32 {
    limit.clamp(1, MAX_ADMIN_PAGE_SIZE)
}

fn map_admin_dependency_error(error: DependencyError) -> AdminError {
    match error {
        DependencyError::Unavailable | DependencyError::RateLimited => AdminError::Unavailable,
        DependencyError::ConditionalWriteFailed | DependencyError::Internal => AdminError::Internal,
    }
}

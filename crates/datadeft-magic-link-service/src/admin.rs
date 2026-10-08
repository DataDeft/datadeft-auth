//! Admin queries and mutations for account and session management.
//!
//! Consuming projects build their own admin UI and endpoints on top of
//! [`AuthAdminService`]. The library provides the data and the mutations; who
//! counts as an admin is the application's decision.
//!
//! Nothing is deleted. Revoking a session and disabling a user are status
//! changes, and every mutation appends an [`AdminEvent`] in the same atomic
//! write as the change itself, so the audit trail cannot miss an action.
//! Ending a session is final; users can be disabled and enabled again.

use core::fmt;
use core::future::Future;

use datadeft_magic_link_core::NormalizedEmail;
use rand_core::{CryptoRng, RngCore};

use crate::error::DependencyError;
use crate::traits::Clock;
use crate::types::UserId;

/// Longest accepted [`AdminActor`] id, in bytes.
pub const MAX_ADMIN_ACTOR_ID_BYTES: usize = 128;
/// Longest accepted [`AdminActor`] reason, in bytes.
pub const MAX_ADMIN_REASON_BYTES: usize = 512;
/// Largest page any admin listing returns.
pub const MAX_ADMIN_PAGE_SIZE: u32 = 100;
/// Longest accepted [`PageCursor`], in bytes.
pub const MAX_PAGE_CURSOR_BYTES: usize = 1024;

const SESSION_HANDLE_PREFIX: &str = "sih_";
const SESSION_HANDLE_HEX_LEN: usize = 64;
const SESSION_DISPLAY_HEX_LEN: usize = 8;
const ADMIN_EVENT_ID_PREFIX: &str = "evt_";
const ADMIN_EVENT_ID_BYTES: usize = 16;

/// Public failure classes for admin operations. No variant carries data.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AdminError {
    /// An input (actor, handle, cursor, page size) failed validation.
    InvalidInput,
    /// The user or session does not exist, or the session belongs to a
    /// different user.
    NotFound,
    /// The target is already in the requested state: the session is already
    /// revoked, or the user is already disabled / enabled.
    AlreadyInState,
    /// A dependency is temporarily unavailable. Callers may retry.
    Unavailable,
    /// Storage returned an inconsistent record, or an invariant broke.
    Internal,
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid admin input",
            Self::NotFound => "not found",
            Self::AlreadyInState => "already in the requested state",
            Self::Unavailable => "admin operation unavailable",
            Self::Internal => "internal admin error",
        })
    }
}

impl std::error::Error for AdminError {}

/// The admin performing a mutation, recorded in the audit trail.
///
/// `id` is the application's identifier for the admin (an email, a user id,
/// an SSO subject). `reason` is optional free text. Both are length-capped and
/// may not contain control characters, so they are safe to store and display.
#[derive(Clone, Eq, PartialEq)]
pub struct AdminActor {
    id: String,
    reason: Option<String>,
}

impl AdminActor {
    /// Validate an actor: `id` non-empty and at most
    /// [`MAX_ADMIN_ACTOR_ID_BYTES`], `reason` at most [`MAX_ADMIN_REASON_BYTES`],
    /// neither containing control characters.
    pub fn new(id: impl Into<String>, reason: Option<String>) -> Result<Self, AdminError> {
        let id = id.into();
        if id.is_empty() || id.len() > MAX_ADMIN_ACTOR_ID_BYTES || has_control(&id) {
            return Err(AdminError::InvalidInput);
        }
        if let Some(reason) = &reason
            && (reason.len() > MAX_ADMIN_REASON_BYTES || has_control(reason))
        {
            return Err(AdminError::InvalidInput);
        }
        Ok(Self { id, reason })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl fmt::Debug for AdminActor {
    // The reason is free text that may mention people; keep it out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminActor")
            .field("id", &self.id)
            .field("reason", &self.reason.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Opaque handle for one stored session: the keyed hash its record is stored
/// under. The raw session id is never stored, so admin calls address
/// sessions by this handle. It cannot be reversed or used to authenticate.
///
/// Pass the full handle back to mutations; show [`SessionHandle::display_id`]
/// in UIs.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SessionHandle(String);

impl SessionHandle {
    /// Parse a handle: `sih_` followed by 64 lowercase hex characters. Use it
    /// on values the admin UI posts back, and in storage adapters.
    pub fn parse(value: &str) -> Result<Self, AdminError> {
        let hex = value
            .strip_prefix(SESSION_HANDLE_PREFIX)
            .ok_or(AdminError::InvalidInput)?;
        if hex.len() != SESSION_HANDLE_HEX_LEN
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AdminError::InvalidInput);
        }
        Ok(Self(value.to_owned()))
    }

    /// The full handle, for round-tripping through the UI and storage.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Short label for display, e.g. `sess_3f9a1c2e`. Never use it to address
    /// a session; mutations take the full handle.
    #[must_use]
    pub fn display_id(&self) -> String {
        let hex = &self.0[SESSION_HANDLE_PREFIX.len()..];
        format!("sess_{}", &hex[..SESSION_DISPLAY_HEX_LEN])
    }
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionHandle({})", self.display_id())
    }
}

/// Unique id of one audit event, generated from the CSPRNG.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct AdminEventId(String);

impl AdminEventId {
    /// Parse an event id: `evt_` followed by 32 lowercase hex characters.
    pub fn parse(value: &str) -> Result<Self, AdminError> {
        let hex = value
            .strip_prefix(ADMIN_EVENT_ID_PREFIX)
            .ok_or(AdminError::InvalidInput)?;
        if hex.len() != ADMIN_EVENT_ID_BYTES * 2
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AdminError::InvalidInput);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdminEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AdminEventId({})", self.0)
    }
}

/// Opaque pagination cursor produced by a storage adapter. The UI passes it
/// back unchanged to fetch the next page.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor(String);

impl PageCursor {
    /// Wrap an adapter-produced cursor, or parse one the UI posted back:
    /// non-empty, at most [`MAX_PAGE_CURSOR_BYTES`], URL-safe base64 alphabet.
    pub fn parse(value: &str) -> Result<Self, AdminError> {
        if value.is_empty()
            || value.len() > MAX_PAGE_CURSOR_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(AdminError::InvalidInput);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PageCursor(..)")
    }
}

/// One page of results and the cursor for the next page, if any.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<PageCursor>,
}

/// A user as an admin sees it.
#[derive(Debug, Clone)]
pub struct UserSummary {
    pub user_id: UserId,
    pub email: NormalizedEmail,
    pub disabled: bool,
    /// When the user was last disabled, while disabled.
    pub disabled_at_unix: Option<u64>,
    /// The admin who last disabled the user, while disabled.
    pub disabled_by: Option<String>,
    pub terms_version: Option<String>,
    pub privacy_version: Option<String>,
    pub consented_at_unix: Option<u64>,
}

/// Lifecycle state of a session at a given time.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionStatus {
    Active,
    Expired,
    Revoked,
}

/// A stored session as an admin sees it.
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub handle: SessionHandle,
    pub user_id: UserId,
    pub email: NormalizedEmail,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
    /// The admin who revoked the session, when an admin did.
    pub revoked_by: Option<String>,
}

impl SessionSummary {
    /// The session's state at `now_unix`. Revocation wins over expiry.
    #[must_use]
    pub fn status(&self, now_unix: u64) -> SessionStatus {
        if self.revoked_at_unix.is_some() {
            SessionStatus::Revoked
        } else if self.expires_at_unix < now_unix {
            SessionStatus::Expired
        } else {
            SessionStatus::Active
        }
    }
}

/// Kind of admin mutation recorded in the audit trail.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AdminAction {
    RevokeSession,
    DisableUser,
    EnableUser,
}

impl AdminAction {
    /// Stable storage name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevokeSession => "revoke_session",
            Self::DisableUser => "disable_user",
            Self::EnableUser => "enable_user",
        }
    }

    /// Parse a stored name.
    pub fn parse(value: &str) -> Result<Self, AdminError> {
        match value {
            "revoke_session" => Ok(Self::RevokeSession),
            "disable_user" => Ok(Self::DisableUser),
            "enable_user" => Ok(Self::EnableUser),
            _ => Err(AdminError::InvalidInput),
        }
    }
}

/// One append-only audit record of an admin mutation.
#[derive(Debug, Clone)]
pub struct AdminEvent {
    pub event_id: AdminEventId,
    pub at_unix: u64,
    pub action: AdminAction,
    /// The user the action applied to.
    pub user_id: UserId,
    /// The session, for [`AdminAction::RevokeSession`].
    pub session: Option<SessionHandle>,
    pub actor: AdminActor,
}

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
    /// each one ending. Returns how many sessions were revoked.
    pub async fn disable_user(
        &mut self,
        user_id: &UserId,
        actor: &AdminActor,
    ) -> Result<u64, AdminError> {
        self.set_disabled(AdminAction::DisableUser, user_id, actor)
            .await?;
        self.revoke_all_sessions(user_id, actor).await
    }

    /// Enable a disabled user. Revoked sessions stay revoked; the user logs
    /// in again.
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

fn clamp_limit(limit: u32) -> u32 {
    limit.clamp(1, MAX_ADMIN_PAGE_SIZE)
}

fn map_admin_dependency_error(error: DependencyError) -> AdminError {
    match error {
        DependencyError::Unavailable | DependencyError::RateLimited => AdminError::Unavailable,
        DependencyError::ConditionalWriteFailed | DependencyError::Internal => AdminError::Internal,
    }
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;

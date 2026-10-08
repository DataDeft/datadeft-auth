//! Admin value types: errors, actor, session handle, cursor, summaries, and audit events.

use core::fmt;

use datadeft_magic_link_core::NormalizedEmail;

use crate::types::UserId;

use super::*;

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

    /// Rebuild an actor read back from storage. Stored history stays readable
    /// even if the input limits are tightened later; only new actors from
    /// [`AdminActor::new`] are validated.
    #[must_use]
    pub fn from_stored(id: String, reason: Option<String>) -> Self {
        Self { id, reason }
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

/// Control characters plus invisible and direction-changing ones that would
/// let an actor id or reason look different from what is stored.
pub(super) fn has_control(value: &str) -> bool {
    value.chars().any(|ch| {
        ch.is_control()
            || matches!(
                ch,
                '\u{00AD}'
                    | '\u{061C}'
                    | '\u{180E}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{2028}'..='\u{202E}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{FEFF}'
            )
    })
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

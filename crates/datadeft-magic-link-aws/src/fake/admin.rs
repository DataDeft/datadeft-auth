//! The fake admin repository: listings, audited mutations, and offset pagination.

use datadeft_magic_link_service::{
    AdminAction, AdminEvent, AuthAdminRepository, Page, PageCursor, SessionHandle, SessionSummary,
    UserSummary,
};
use datadeft_magic_link_service::{DependencyError, NormalizedEmail, UserId, UserRecord};

use crate::hmac_key::EMAIL_LOOKUP_HMAC_PREFIX;

use super::*;

impl FakeDynamoDbInner {
    fn user_summary(&self, profile: &UserRecord) -> UserSummary {
        let meta = self
            .disabled_meta
            .get(profile.user_id.as_str())
            .cloned()
            .unwrap_or_default();
        UserSummary {
            user_id: profile.user_id.clone(),
            email: profile.email.clone(),
            disabled: profile.disabled,
            disabled_at_unix: meta.at_unix,
            disabled_by: meta.by,
            terms_version: profile.terms_version.clone(),
            privacy_version: profile.privacy_version.clone(),
            consented_at_unix: profile.consented_at_unix,
        }
    }

    fn session_summary(
        session_hmac: &str,
        stored: &StoredSession,
    ) -> Result<SessionSummary, DependencyError> {
        Ok(SessionSummary {
            handle: SessionHandle::parse(session_hmac).map_err(|_| DependencyError::Internal)?,
            user_id: stored.record.user_id.clone(),
            email: stored.record.email.clone(),
            created_at_unix: stored.record.created_at_unix,
            expires_at_unix: stored.expires_at_unix,
            revoked_at_unix: stored.record.revoked_at_unix,
            revoked_by: stored.revoked_by.clone(),
        })
    }
}

/// Offset pagination for the fake: cursors are `o<offset>`.
fn fake_page<T>(
    items: Vec<T>,
    cursor: Option<&PageCursor>,
    limit: u32,
) -> Result<Page<T>, DependencyError> {
    let offset = match cursor {
        None => 0,
        Some(cursor) => cursor
            .as_str()
            .strip_prefix('o')
            .and_then(|digits| digits.parse::<usize>().ok())
            .ok_or(DependencyError::Internal)?,
    };
    let limit = usize::try_from(limit).map_err(|_| DependencyError::Internal)?;
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(offset).take(limit).collect();
    let end = offset.saturating_add(page.len());
    let next = if end < total {
        Some(PageCursor::parse(&format!("o{end}")).map_err(|_| DependencyError::Internal)?)
    } else {
        None
    };
    Ok(Page { items: page, next })
}

impl AuthAdminRepository for FakeDynamoDbAuthStore {
    async fn list_users(
        &self,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<UserSummary>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let mut users: Vec<UserSummary> = inner
            .user_profiles_by_id
            .values()
            .map(|profile| inner.user_summary(profile))
            .collect();
        users.sort_by(|left, right| left.user_id.as_str().cmp(right.user_id.as_str()));
        fake_page(users, cursor, limit)
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<UserSummary>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        Ok(inner
            .user_profiles_by_id
            .get(user_id.as_str())
            .map(|profile| inner.user_summary(profile)))
    }

    async fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserSummary>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let (email_hmac, _) =
            self.resolve_hmac(EMAIL_LOOKUP_HMAC_PREFIX, email.as_str(), |hmac| {
                inner.user_id_by_email_hmac.contains_key(hmac)
            })?;
        let Some(user_id) = inner.user_id_by_email_hmac.get(&email_hmac) else {
            return Ok(None);
        };
        Ok(inner
            .user_profiles_by_id
            .get(user_id.as_str())
            .map(|profile| inner.user_summary(profile)))
    }

    async fn list_sessions_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<SessionSummary>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let mut sessions = Vec::new();
        for entry in inner
            .user_session_index
            .get(user_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            // The index sort key is `SESSION#<created>#<session hmac>`.
            let session_hmac = entry
                .sk
                .rsplit('#')
                .next()
                .ok_or(DependencyError::Internal)?;
            // Mirror DynamoDB: an index row can outlive its session row (rows
            // written with a legacy TTL expire independently). Skip it.
            let Some(stored) = inner.sessions_by_hmac.get(session_hmac) else {
                continue;
            };
            sessions.push(FakeDynamoDbInner::session_summary(session_hmac, stored)?);
        }
        sessions.sort_by_key(|session| core::cmp::Reverse(session.created_at_unix));
        Ok(sessions)
    }

    async fn list_active_sessions(
        &self,
        now_unix: u64,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<SessionSummary>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let mut sessions = Vec::new();
        for (session_hmac, stored) in &inner.sessions_by_hmac {
            if stored.record.revoked_at_unix.is_none() && stored.expires_at_unix >= now_unix {
                sessions.push(FakeDynamoDbInner::session_summary(session_hmac, stored)?);
            }
        }
        sessions.sort_by(|left, right| left.handle.as_str().cmp(right.handle.as_str()));
        fake_page(sessions, cursor, limit)
    }

    async fn revoke_session_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        let handle = event.session.as_ref().ok_or(DependencyError::Internal)?;
        if event.action != AdminAction::RevokeSession {
            return Err(DependencyError::Internal);
        }
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let stored = inner
            .sessions_by_hmac
            .get_mut(handle.as_str())
            .ok_or(DependencyError::ConditionalWriteFailed)?;
        // Same conditions as the DynamoDB transaction: owned by the event's
        // user and not revoked yet.
        if stored.record.user_id != event.user_id || stored.record.revoked_at_unix.is_some() {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        stored.record.revoked_at_unix = Some(event.at_unix);
        stored.revoked_by = Some(event.actor.id().to_owned());
        inner.admin_events.push(event.clone());
        Ok(())
    }

    async fn set_user_disabled_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        let disable = match event.action {
            AdminAction::DisableUser => true,
            AdminAction::EnableUser => false,
            AdminAction::RevokeSession => return Err(DependencyError::Internal),
        };
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let profile = inner
            .user_profiles_by_id
            .get_mut(event.user_id.as_str())
            .ok_or(DependencyError::ConditionalWriteFailed)?;
        if profile.disabled == disable {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        profile.disabled = disable;
        let meta = if disable {
            DisabledMeta {
                at_unix: Some(event.at_unix),
                by: Some(event.actor.id().to_owned()),
            }
        } else {
            DisabledMeta::default()
        };
        if !disable {
            inner
                .sessions_valid_after
                .insert(event.user_id.as_str().to_owned(), event.at_unix);
        }
        inner
            .disabled_meta
            .insert(event.user_id.as_str().to_owned(), meta);
        inner.admin_events.push(event.clone());
        Ok(())
    }

    async fn list_admin_events(
        &self,
        user_id: &UserId,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<AdminEvent>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        // Same order as the DynamoDB sort key `EVENT#<at>#<event id>`, newest
        // first: within one second the order follows the random event id.
        let mut events: Vec<AdminEvent> = inner
            .admin_events
            .iter()
            .filter(|event| event.user_id == *user_id)
            .cloned()
            .collect();
        events.sort_by(|left, right| {
            (right.at_unix, right.event_id.as_str()).cmp(&(left.at_unix, left.event_id.as_str()))
        });
        fake_page(events, cursor, limit)
    }
}

//! In-memory fake DynamoDB-style auth store.
//!
//! This fake mirrors the storage-shape security properties of the AWS adapter:
//! magic-link selectors, sessions, users-by-email, and rate-limit keys are all
//! keyed by derived lookup material rather than raw bearer values where the
//! service contract permits it.

mod admin;
mod authentication;

use core::fmt;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};

use datadeft_magic_link_service::AdminEvent;
use datadeft_magic_link_service::{
    CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, DependencyError, LookupHmac,
    MagicLinkRecord, MagicLinkRepository, NormalizedEmail, RateLimitDecision, RateLimitKey,
    RateLimiter, SessionId, SessionRecord, SessionRepository, UserId, UserRecord,
};

use crate::error::AwsAdapterError;
use crate::hmac_key::{
    EMAIL_LOOKUP_HMAC_PREFIX, RATE_LOOKUP_HMAC_PREFIX, SESSION_LOOKUP_HMAC_PREFIX, StorageHmacKey,
    StorageHmacKeys,
};
use crate::window::fixed_window_index;

/// Fake mirror of the DynamoDB user-session index item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSessionIndexEntry {
    pub sk: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

/// In-memory fake store for service tests/examples.
#[derive(Clone)]
pub struct FakeDynamoDbAuthStore {
    inner: Arc<Mutex<FakeDynamoDbInner>>,
    storage_hmac_keys: Arc<StorageHmacKeys>,
}

/// Session record plus the expiry the DynamoDB item would carry as TTL.
struct StoredSession {
    record: SessionRecord,
    expires_at_unix: u64,
    /// The admin who revoked the session, when an admin did.
    revoked_by: Option<String>,
}

/// Admin metadata kept beside a user profile while it is disabled.
#[derive(Clone, Default)]
struct DisabledMeta {
    at_unix: Option<u64>,
    by: Option<String>,
}

#[derive(Default)]
struct FakeDynamoDbInner {
    magic_links_by_selector_hmac: HashMap<String, MagicLinkRecord>,
    user_profiles_by_id: HashMap<String, UserRecord>,
    user_id_by_email_hmac: HashMap<String, UserId>,
    sessions_by_hmac: HashMap<String, StoredSession>,
    user_session_index: HashMap<String, Vec<UserSessionIndexEntry>>,
    authentication_attempts: HashMap<String, CommitMagicLinkAuthentication>,
    rate_counters: HashMap<String, u32>,
    disabled_meta: HashMap<String, DisabledMeta>,
    /// Per user: sessions created before this time are not valid (set on
    /// re-enable).
    sessions_valid_after: HashMap<String, u64>,
    admin_events: Vec<AdminEvent>,
    next_error: Option<AwsAdapterError>,
    #[cfg(test)]
    fail_next_authentication_pre_commit: bool,
    #[cfg(test)]
    disable_user_before_next_commit: Option<String>,
}

impl FakeDynamoDbAuthStore {
    #[must_use]
    pub fn new(storage_hmac_key: StorageHmacKey) -> Self {
        Self {
            inner: Arc::default(),
            storage_hmac_keys: Arc::new(StorageHmacKeys::new(storage_hmac_key, None)),
        }
    }

    /// A store over the same data with different storage keys. Models a
    /// rotation (`previous: Some(old_key)`), dropping the previous key after
    /// it (`None`), or a key change without fallback.
    #[must_use]
    pub fn sharing_data_with_keys(
        &self,
        current: StorageHmacKey,
        previous: Option<StorageHmacKey>,
    ) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            storage_hmac_keys: Arc::new(StorageHmacKeys::new(current, previous)),
        }
    }

    /// Rewrite every email lookup under the current storage key, mirroring
    /// [`crate::DynamoDbAuthStore::rekey_email_lookups`]. Returns the number of
    /// lookups written.
    pub fn rekey_email_lookups(&self) -> Result<usize, DependencyError> {
        let mut inner = self.lock_inner()?;
        let profiles: Vec<(String, UserId)> = inner
            .user_profiles_by_id
            .values()
            .map(|profile| Ok((self.email_hmac(&profile.email)?, profile.user_id.clone())))
            .collect::<Result<_, DependencyError>>()?;
        let mut written = 0usize;
        for (email_hmac, user_id) in profiles {
            if let Entry::Vacant(entry) = inner.user_id_by_email_hmac.entry(email_hmac) {
                entry.insert(user_id);
                written = written.saturating_add(1);
            }
        }
        Ok(written)
    }

    pub fn set_next_error(&self, error: AwsAdapterError) -> Result<(), DependencyError> {
        self.lock_inner()?.next_error = Some(error);
        Ok(())
    }

    pub fn magic_link_count(&self) -> Result<usize, DependencyError> {
        Ok(self.lock_inner()?.magic_links_by_selector_hmac.len())
    }

    pub fn user_count(&self) -> Result<usize, DependencyError> {
        Ok(self.lock_inner()?.user_profiles_by_id.len())
    }

    pub fn session_count(&self) -> Result<usize, DependencyError> {
        Ok(self.lock_inner()?.sessions_by_hmac.len())
    }

    pub fn session_storage_keys(&self) -> Result<Vec<String>, DependencyError> {
        let mut keys = self
            .lock_inner()?
            .sessions_by_hmac
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        Ok(keys)
    }

    pub fn magic_link_record(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkRecord>, DependencyError> {
        Ok(self
            .lock_inner()?
            .magic_links_by_selector_hmac
            .get(selector_lookup_hmac.as_storage_value())
            .cloned())
    }

    pub fn user_session_index_entries(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<UserSessionIndexEntry>, DependencyError> {
        Ok(self
            .lock_inner()?
            .user_session_index
            .get(user_id.as_str())
            .cloned()
            .unwrap_or_default())
    }

    fn hmac(&self, prefix: &str, value: &str) -> Result<String, DependencyError> {
        self.storage_hmac_keys
            .current()
            .hmac(prefix, value)
            .map_err(DependencyError::from)
    }

    fn email_hmac(&self, email: &NormalizedEmail) -> Result<String, DependencyError> {
        self.hmac(EMAIL_LOOKUP_HMAC_PREFIX, email.as_str())
    }

    fn session_hmac(&self, session_id: &SessionId) -> Result<String, DependencyError> {
        self.hmac(SESSION_LOOKUP_HMAC_PREFIX, session_id.as_str())
    }

    fn rate_hmac(&self, key: &RateLimitKey) -> Result<String, DependencyError> {
        self.hmac(RATE_LOOKUP_HMAC_PREFIX, key.as_str())
    }

    /// The HMAC of `value` under the current key, or under the previous key
    /// when only that one is `present`. Mirrors the real store's
    /// `get_with_key_fallback`; the flag reports a previous-key hit.
    fn resolve_hmac(
        &self,
        prefix: &str,
        value: &str,
        present: impl Fn(&str) -> bool,
    ) -> Result<(String, bool), DependencyError> {
        let current = self.hmac(prefix, value)?;
        if !present(&current)
            && let Some(previous) = self.storage_hmac_keys.previous()
        {
            let previous = previous.hmac(prefix, value)?;
            if present(&previous) {
                return Ok((previous, true));
            }
        }
        Ok((current, false))
    }

    fn authentication_error(error: AwsAdapterError) -> CommitMagicLinkAuthenticationError {
        match error {
            AwsAdapterError::DependencyUnavailable | AwsAdapterError::RateLimited => {
                CommitMagicLinkAuthenticationError::DependencyUnavailable
            }
            AwsAdapterError::Internal => CommitMagicLinkAuthenticationError::Internal,
            AwsAdapterError::ConditionalWriteFailed => {
                CommitMagicLinkAuthenticationError::DependencyUnavailable
            }
        }
    }

    #[cfg(test)]
    fn fail_next_authentication_pre_commit(&self) -> Result<(), DependencyError> {
        self.lock_inner()?.fail_next_authentication_pre_commit = true;
        Ok(())
    }

    #[cfg(test)]
    fn seed_user(&self, user: UserRecord) -> Result<(), DependencyError> {
        let email_hmac = self.email_hmac(&user.email)?;
        let mut inner = self.lock_inner()?;
        if inner.user_id_by_email_hmac.contains_key(&email_hmac)
            || inner
                .user_profiles_by_id
                .contains_key(user.user_id.as_str())
        {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        inner
            .user_id_by_email_hmac
            .insert(email_hmac, user.user_id.clone());
        inner
            .user_profiles_by_id
            .insert(user.user_id.as_str().to_owned(), user);
        Ok(())
    }

    #[cfg(test)]
    fn seed_session(
        &self,
        session: SessionRecord,
        expires_at_unix: u64,
    ) -> Result<(), DependencyError> {
        let session_hmac = self.session_hmac(&session.session_id)?;
        let mut inner = self.lock_inner()?;
        if inner.sessions_by_hmac.contains_key(&session_hmac) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        inner.sessions_by_hmac.insert(
            session_hmac,
            StoredSession {
                record: session,
                expires_at_unix,
                revoked_by: None,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    fn disable_user_before_next_commit(&self, user_id: &UserId) -> Result<(), DependencyError> {
        self.lock_inner()?.disable_user_before_next_commit = Some(user_id.as_str().to_owned());
        Ok(())
    }

    fn take_next_error(inner: &mut FakeDynamoDbInner) -> Result<(), DependencyError> {
        if let Some(error) = inner.next_error.take() {
            Err(DependencyError::from(error))
        } else {
            Ok(())
        }
    }

    fn lock_inner(&self) -> Result<std::sync::MutexGuard<'_, FakeDynamoDbInner>, DependencyError> {
        self.inner.lock().map_err(|_| DependencyError::Internal)
    }
}

impl fmt::Debug for FakeDynamoDbAuthStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FakeDynamoDbAuthStore(..)")
    }
}

impl MagicLinkRepository for FakeDynamoDbAuthStore {
    async fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> Result<(), DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let key = record.selector_lookup_hmac.as_storage_value().to_owned();
        if inner.magic_links_by_selector_hmac.contains_key(&key) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        inner.magic_links_by_selector_hmac.insert(key, record);
        Ok(())
    }
}

impl SessionRepository for FakeDynamoDbAuthStore {
    async fn find_session(
        &self,
        session_id: &SessionId,
        now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let (session_hmac, _) =
            self.resolve_hmac(SESSION_LOOKUP_HMAC_PREFIX, session_id.as_str(), |hmac| {
                inner.sessions_by_hmac.contains_key(hmac)
            })?;
        Ok(inner
            .sessions_by_hmac
            .get(&session_hmac)
            .filter(|stored| {
                stored.expires_at_unix >= now_unix && stored.record.revoked_at_unix.is_none()
            })
            .map(|stored| stored.record.clone()))
    }

    async fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let (session_hmac, _) =
            self.resolve_hmac(SESSION_LOOKUP_HMAC_PREFIX, session_id.as_str(), |hmac| {
                inner.sessions_by_hmac.contains_key(hmac)
            })?;
        let session = &mut inner
            .sessions_by_hmac
            .get_mut(&session_hmac)
            .ok_or(DependencyError::ConditionalWriteFailed)?
            .record;
        if session.revoked_at_unix.is_some() {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        session.revoked_at_unix = Some(revoked_at_unix);
        Ok(())
    }

    async fn is_session_owner_active(
        &self,
        user_id: &UserId,
        session_created_at_unix: u64,
    ) -> Result<bool, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let enabled = inner
            .user_profiles_by_id
            .get(user_id.as_str())
            .is_some_and(|profile| profile.user_id == *user_id && !profile.disabled);
        let fresh_enough = inner
            .sessions_valid_after
            .get(user_id.as_str())
            .is_none_or(|valid_after| session_created_at_unix > *valid_after);
        Ok(enabled && fresh_enough)
    }
}

impl RateLimiter for FakeDynamoDbAuthStore {
    async fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window_secs: u64,
        now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        let window_index = fixed_window_index(now_unix, window_secs);
        let rate_hmac = self.rate_hmac(key)?;
        let rate_hmac = format!("{rate_hmac}:{window_index}");
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let counter = inner.rate_counters.entry(rate_hmac).or_default();
        if *counter >= limit {
            return Ok(RateLimitDecision::Denied);
        }
        *counter += 1;
        Ok(RateLimitDecision::Allowed)
    }
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod admin_tests;
#[cfg(test)]
mod aggregate_tests;
#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod rotation_tests;

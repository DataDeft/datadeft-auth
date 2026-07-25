//! In-memory fake DynamoDB-style auth store.
//!
//! This fake mirrors the storage-shape security properties of the AWS adapter:
//! magic-link selectors, sessions, users-by-email, and rate-limit keys are all
//! keyed by derived lookup material rather than raw bearer values where the
//! service contract permits it.

use core::fmt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dd_magic_link_core::{LookupHmac, NormalizedEmail, VerifierHash};
use dd_magic_link_service::{
    ConsumeMagicLinkError, ConsumedMagicLink, DependencyError, MagicLinkRecord,
    MagicLinkRepository, RateLimitDecision, RateLimitKey, RateLimiter, SessionId, SessionRecord,
    SessionRepository, UserId, UserRecord, UserRepository,
};

use crate::error::AwsAdapterError;
use crate::hmac_key::{SESSION_LOOKUP_HMAC_PREFIX, StorageHmacKey};

/// Fake mirror of the DynamoDB user-session index item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSessionIndexEntry {
    pub sk: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

/// In-memory fake store for service tests/examples.
#[derive(Clone, Default)]
pub struct FakeDynamoDbAuthStore {
    inner: Arc<Mutex<FakeDynamoDbInner>>,
    storage_hmac_key: Arc<StorageHmacKey>,
}

#[derive(Default)]
struct FakeDynamoDbInner {
    magic_links_by_selector_hmac: HashMap<String, MagicLinkRecord>,
    user_profiles_by_id: HashMap<String, UserRecord>,
    user_id_by_email_hmac: HashMap<String, UserId>,
    sessions_by_hmac: HashMap<String, SessionRecord>,
    user_session_index: HashMap<String, Vec<UserSessionIndexEntry>>,
    rate_counters: HashMap<String, u32>,
    next_error: Option<AwsAdapterError>,
}

impl FakeDynamoDbAuthStore {
    #[must_use]
    pub fn new(storage_hmac_key: StorageHmacKey) -> Self {
        Self {
            inner: Arc::default(),
            storage_hmac_key: Arc::new(storage_hmac_key),
        }
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

    fn email_hmac(&self, email: &NormalizedEmail) -> Result<String, DependencyError> {
        self.storage_hmac_key
            .hmac("emh", email.as_str())
            .map_err(DependencyError::from)
    }

    fn session_hmac(&self, session_id: &SessionId) -> Result<String, DependencyError> {
        self.storage_hmac_key
            .hmac(SESSION_LOOKUP_HMAC_PREFIX, session_id.as_str())
            .map_err(DependencyError::from)
    }

    fn rate_hmac(&self, key: &RateLimitKey) -> Result<String, DependencyError> {
        self.storage_hmac_key
            .hmac("rlh", key.as_str())
            .map_err(DependencyError::from)
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
    fn put_magic_link_if_absent(&self, record: MagicLinkRecord) -> Result<(), DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let key = record.selector_lookup_hmac.as_storage_value().to_owned();
        if inner.magic_links_by_selector_hmac.contains_key(&key) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        inner.magic_links_by_selector_hmac.insert(key, record);
        Ok(())
    }

    fn consume_magic_link(
        &self,
        selector_lookup_hmac: &LookupHmac,
        verifier_hash: &VerifierHash,
        now_unix: u64,
    ) -> Result<ConsumedMagicLink, ConsumeMagicLinkError> {
        let mut inner = self
            .lock_inner()
            .map_err(|_| ConsumeMagicLinkError::Internal)?;
        if let Some(error) = inner.next_error.take() {
            return Err(ConsumeMagicLinkError::from(error));
        }
        let Some(record) = inner
            .magic_links_by_selector_hmac
            .get_mut(selector_lookup_hmac.as_storage_value())
        else {
            return Err(ConsumeMagicLinkError::Unavailable);
        };
        if record.consumed_at_unix.is_some()
            || record.expires_at_unix < now_unix
            || !record
                .verifier_hash
                .matches_hash_constant_time(verifier_hash)
        {
            return Err(ConsumeMagicLinkError::Unavailable);
        }
        record.consumed_at_unix = Some(now_unix);
        Ok(ConsumedMagicLink {
            email: record.email.clone(),
            user_id: record.user_id.clone(),
            terms_version: record.terms_version.clone(),
            privacy_version: record.privacy_version.clone(),
            consented_at_unix: record.consented_at_unix,
        })
    }
}

impl UserRepository for FakeDynamoDbAuthStore {
    fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        let email_hmac = self.email_hmac(email)?;
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let Some(user_id) = inner.user_id_by_email_hmac.get(&email_hmac) else {
            return Ok(None);
        };
        Ok(inner.user_profiles_by_id.get(user_id.as_str()).cloned())
    }

    fn put_user_if_absent(&self, user: UserRecord) -> Result<(), DependencyError> {
        let email_hmac = self.email_hmac(&user.email)?;
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
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
}

impl SessionRepository for FakeDynamoDbAuthStore {
    fn put_session_if_absent(&self, session: SessionRecord) -> Result<(), DependencyError> {
        let session_hmac = self.session_hmac(&session.session_id)?;
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        if inner.sessions_by_hmac.contains_key(&session_hmac) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        let expires_at_unix = session.created_at_unix.saturating_add(30 * 24 * 60 * 60);
        inner
            .user_session_index
            .entry(session.user_id.as_str().to_owned())
            .or_default()
            .push(UserSessionIndexEntry {
                sk: format!("SESSION#{}#{session_hmac}", session.created_at_unix),
                created_at_unix: session.created_at_unix,
                expires_at_unix,
            });
        inner.sessions_by_hmac.insert(session_hmac, session);
        Ok(())
    }

    fn find_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        let session_hmac = self.session_hmac(session_id)?;
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        Ok(inner.sessions_by_hmac.get(&session_hmac).cloned())
    }

    fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        let session_hmac = self.session_hmac(session_id)?;
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let session = inner
            .sessions_by_hmac
            .get_mut(&session_hmac)
            .ok_or(DependencyError::ConditionalWriteFailed)?;
        if session.revoked_at_unix.is_some() {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        session.revoked_at_unix = Some(revoked_at_unix);
        Ok(())
    }
}

impl RateLimiter for FakeDynamoDbAuthStore {
    fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        limit: u32,
        _window_secs: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        let rate_hmac = self.rate_hmac(key)?;
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
#[path = "fake_tests.rs"]
mod tests;

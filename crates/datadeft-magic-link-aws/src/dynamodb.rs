//! Optional DynamoDB-backed service trait implementations.

mod admin;
mod admin_items;
mod authentication;
mod items;
mod rotation;
mod sessions;

use core::fmt;
use std::collections::HashMap;

use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::types::{AttributeValue, Put, TransactWriteItem, Update};
use datadeft_magic_link_service::{
    DependencyError, LookupHmac, MagicLinkRecord, MagicLinkRepository, NormalizedEmail,
    RateLimitKey, SessionId, UserId,
};

use crate::error::{
    AwsAdapterError, map_get_item_error, map_put_item_error, map_scan_error, map_update_item_error,
};
use crate::hmac_key::{
    EMAIL_LOOKUP_HMAC_PREFIX, RATE_LOOKUP_HMAC_PREFIX, SESSION_LOOKUP_HMAC_PREFIX, StorageHmacKey,
    StorageHmacKeys,
};
use crate::window::fixed_window_index;

use self::items::*;

/// Default TTL grace applied to spent auth artifacts: 24 hours past their
/// logical expiry. DynamoDB TTL deletion is asynchronous and best-effort, so
/// the grace keeps a row queryable slightly past expiry. The grace is garbage
/// collection, not a validity window (record fields gate validity).
pub const DEFAULT_CLEANUP_GRACE_SECS: u64 = 24 * 60 * 60;

/// DynamoDB single-table auth store.
pub struct DynamoDbAuthStore {
    client: DynamoDbClient,
    table_name: String,
    storage_hmac_keys: StorageHmacKeys,
    cleanup_grace_secs: u64,
}

impl DynamoDbAuthStore {
    #[must_use]
    pub fn new(
        client: DynamoDbClient,
        table_name: String,
        storage_hmac_key: StorageHmacKey,
    ) -> Self {
        Self {
            client,
            table_name,
            storage_hmac_keys: StorageHmacKeys::new(storage_hmac_key, None),
            cleanup_grace_secs: DEFAULT_CLEANUP_GRACE_SECS,
        }
    }

    /// Previous storage HMAC key during a rotation window. Session and email
    /// lookups that miss under the current key retry under this one, and a
    /// user found that way gets an email lookup row under the current key.
    /// Run [`Self::rekey_email_lookups`] before dropping the previous key, so
    /// users who did not log in during the window are not stranded.
    #[must_use]
    pub fn with_previous_storage_hmac_key(mut self, previous: StorageHmacKey) -> Self {
        self.storage_hmac_keys.set_previous(previous);
        self
    }

    /// Override the retention grace (seconds past logical expiry) applied to
    /// the DynamoDB TTL of spent magic-link challenge and rate-counter rows.
    /// This is a data-retention/minimization policy, not a security control.
    #[must_use]
    pub fn with_cleanup_grace_secs(mut self, cleanup_grace_secs: u64) -> Self {
        self.cleanup_grace_secs = cleanup_grace_secs;
        self
    }

    fn hmac(&self, prefix: &str, value: &str) -> Result<String, AwsAdapterError> {
        self.storage_hmac_keys.current().hmac(prefix, value)
    }

    fn pk_magic_link(selector_lookup_hmac: &LookupHmac) -> String {
        format!("ML#{}", selector_lookup_hmac.as_storage_value())
    }

    fn pk_session_from_hmac(session_hmac: &str) -> String {
        format!("SESSION#{session_hmac}")
    }

    fn session_hmac(&self, session_id: &SessionId) -> Result<String, AwsAdapterError> {
        self.hmac(SESSION_LOOKUP_HMAC_PREFIX, session_id.as_str())
    }

    fn pk_session_under(
        key: &StorageHmacKey,
        session_id: &SessionId,
    ) -> Result<String, AwsAdapterError> {
        Ok(Self::pk_session_from_hmac(
            &key.hmac(SESSION_LOOKUP_HMAC_PREFIX, session_id.as_str())?,
        ))
    }

    fn pk_user_email_under(
        key: &StorageHmacKey,
        email: &NormalizedEmail,
    ) -> Result<String, AwsAdapterError> {
        Ok(format!(
            "USER#{}",
            key.hmac(EMAIL_LOOKUP_HMAC_PREFIX, email.as_str())?
        ))
    }

    fn pk_user_email(&self, email: &NormalizedEmail) -> Result<String, AwsAdapterError> {
        Self::pk_user_email_under(self.storage_hmac_keys.current(), email)
    }

    fn pk_user_id(user_id: &UserId) -> String {
        format!("USERID#{}", user_id.as_str())
    }

    fn pk_rate(
        &self,
        key: &RateLimitKey,
        window_secs: u64,
        now_unix: u64,
    ) -> Result<String, AwsAdapterError> {
        let window_index = fixed_window_index(now_unix, window_secs);
        let storage_key = format!("{}:{window_index}", key.as_str());
        Ok(format!(
            "RL#{}",
            self.hmac(RATE_LOOKUP_HMAC_PREFIX, &storage_key)?
        ))
    }
}

impl fmt::Debug for DynamoDbAuthStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DynamoDbAuthStore(..)")
    }
}

impl MagicLinkRepository for DynamoDbAuthStore {
    async fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> Result<(), DependencyError> {
        let pk = Self::pk_magic_link(&record.selector_lookup_hmac);
        let ttl = record
            .expires_at_unix
            .saturating_add(self.cleanup_grace_secs);
        async {
            self.client
                .put_item()
                .table_name(&self.table_name)
                .item("pk", av_s(pk))
                .item("sk", av_s("CHALLENGE"))
                .item("entity_type", av_s("magic_link"))
                .item("email_normalized", av_s(record.email.as_str()))
                .item(
                    "verifier_hash",
                    av_s(record.verifier_hash.as_storage_value()),
                )
                .item("expires_at_unix", av_n(record.expires_at_unix))
                .item("terms_version", av_s(record.terms_version.clone()))
                .item("privacy_version", av_s(record.privacy_version.clone()))
                .item("consented_at_unix", av_n(record.consented_at_unix))
                .item("ttl", av_n(ttl))
                .condition_expression("attribute_not_exists(pk)")
                .send()
                .await
                .map_err(map_put_item_error)?;
            Ok::<(), AwsAdapterError>(())
        }
        .await
        .map_err(DependencyError::from)
    }
}

#[cfg(test)]
mod store_tests;

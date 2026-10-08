//! Sessions and the rate limiter: lookup, revocation, owner status, fixed-window counters.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use datadeft_magic_link_service::{
    DependencyError, NormalizedEmail, RateLimitDecision, RateLimitKey, RateLimiter, SessionId,
    SessionRecord, SessionRepository, UserId,
};

use crate::error::{AwsAdapterError, map_get_item_error, map_update_item_error};
use crate::window::fixed_window_index;

use super::items::*;
use super::*;

impl DynamoDbAuthStore {
    pub(super) async fn revoke_session_item(
        &self,
        pk: String,
        revoked_at_unix: u64,
    ) -> Result<(), AwsAdapterError> {
        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("pk", av_s(pk))
            .key("sk", av_s("SESSION"))
            .update_expression("SET revoked_at_unix = :now")
            .condition_expression("attribute_exists(pk) AND attribute_not_exists(revoked_at_unix)")
            .expression_attribute_values(":now", av_n(revoked_at_unix))
            .send()
            .await
            .map_err(map_update_item_error)?;
        Ok(())
    }

    pub(super) fn item_to_session(
        session_id: &SessionId,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<SessionRecord, AwsAdapterError> {
        Ok(SessionRecord {
            session_id: session_id.clone(),
            user_id: UserId::parse(required_s(item, "user_id")?)
                .map_err(|_| AwsAdapterError::Internal)?,
            email: NormalizedEmail::parse(required_s(item, "email_normalized")?)
                .map_err(|_| AwsAdapterError::Internal)?,
            created_at_unix: required_u64(item, "created_at_unix")?,
            revoked_at_unix: optional_u64(item, "revoked_at_unix")?,
        })
    }
}

impl SessionRepository for DynamoDbAuthStore {
    async fn find_session(
        &self,
        session_id: &SessionId,
        now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        async {
            let (output, _) = self
                .get_with_key_fallback("SESSION", |key| Self::pk_session_under(key, session_id))
                .await?;
            let Some(item) = output.item() else {
                return Ok(None);
            };
            if optional_s(item, "entity_type") != Some("session")
                || optional_u64(item, "revoked_at_unix")?.is_some()
                || required_u64(item, "expires_at_unix")? < now_unix
            {
                return Ok(None);
            }
            Self::item_to_session(session_id, item).map(Some)
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        async {
            let keys = &self.storage_hmac_keys;
            let revoked = self
                .revoke_session_item(
                    Self::pk_session_under(keys.current(), session_id)?,
                    revoked_at_unix,
                )
                .await;
            match (revoked, keys.previous()) {
                // Rotation window: the session may be stored under the
                // previous key. A second conditional failure is reported.
                (Err(AwsAdapterError::ConditionalWriteFailed), Some(previous)) => {
                    self.revoke_session_item(
                        Self::pk_session_under(previous, session_id)?,
                        revoked_at_unix,
                    )
                    .await
                }
                (result, _) => result,
            }
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn is_session_owner_active(
        &self,
        user_id: &UserId,
        session_created_at_unix: u64,
    ) -> Result<bool, DependencyError> {
        async {
            let output = self
                .authentication_get_item(Self::pk_user_id(user_id), "PROFILE")
                .send()
                .await
                .map_err(map_get_item_error)?;
            // Fail closed: only an intact, enabled profile for this id counts.
            let Some(item) = output.item() else {
                return Ok::<bool, AwsAdapterError>(false);
            };
            // Sessions from before a re-enable stay invalid (watermark).
            let fresh_enough = optional_u64(item, "sessions_valid_after_unix")?
                .is_none_or(|valid_after| session_created_at_unix >= valid_after);
            Ok(optional_s(item, "entity_type") == Some("user_profile")
                && optional_s(item, "user_id") == Some(user_id.as_str())
                && matches!(item.get("disabled"), Some(AttributeValue::Bool(false)))
                && fresh_enough)
        }
        .await
        .map_err(DependencyError::from)
    }
}

impl RateLimiter for DynamoDbAuthStore {
    async fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window_secs: u64,
        now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        let pk = self
            .pk_rate(key, window_secs, now_unix)
            .map_err(DependencyError::from)?;
        let window_start_unix = fixed_window_start(now_unix, window_secs);
        let window_expires_unix = window_start_unix.saturating_add(window_secs);
        let ttl = window_expires_unix.saturating_add(self.cleanup_grace_secs);
        async {
            let result = self
                .client
                .update_item()
                .table_name(&self.table_name)
                .key("pk", av_s(pk))
                .key("sk", av_s("COUNTER"))
                .update_expression("SET #entity_type = if_not_exists(#entity_type, :entity), #window_start = if_not_exists(#window_start, :window_start), #window_expires = if_not_exists(#window_expires, :window_expires), #ttl = if_not_exists(#ttl, :ttl) ADD #count :one")
                .condition_expression("attribute_not_exists(#count) OR #count < :limit")
                .expression_attribute_names("#entity_type", "entity_type")
                .expression_attribute_names("#window_start", "window_start_unix")
                .expression_attribute_names("#window_expires", "window_expires_unix")
                .expression_attribute_names("#ttl", "ttl")
                .expression_attribute_names("#count", "count")
                .expression_attribute_values(":entity", av_s("rate_counter"))
                .expression_attribute_values(":window_start", av_n(window_start_unix))
                .expression_attribute_values(":window_expires", av_n(window_expires_unix))
                .expression_attribute_values(":ttl", av_n(ttl))
                .expression_attribute_values(":one", av_n(1))
                .expression_attribute_values(":limit", av_n(limit))
                .send()
                .await;
            match result {
                Ok(_) => Ok(RateLimitDecision::Allowed),
                Err(error) => match map_update_item_error(error) {
                    AwsAdapterError::ConditionalWriteFailed => Ok(RateLimitDecision::Denied),
                    other => Err(other),
                },
            }
        }
        .await
        .map_err(DependencyError::from)
    }
}

pub(super) fn fixed_window_start(now_unix: u64, window_secs: u64) -> u64 {
    fixed_window_index(now_unix, window_secs).saturating_mul(window_secs)
}

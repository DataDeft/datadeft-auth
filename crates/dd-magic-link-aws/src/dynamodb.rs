//! Optional DynamoDB-backed service trait implementations.

use core::fmt;
use std::collections::HashMap;
use std::sync::Arc;

use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::types::{AttributeValue, Put, ReturnValue, TransactWriteItem};
use dd_magic_link_core::{LookupHmac, NormalizedEmail, VerifierHash};
use dd_magic_link_service::{
    ConsumeMagicLinkError, ConsumedMagicLink, DependencyError, MagicLinkRecord,
    MagicLinkRepository, RateLimitDecision, RateLimitKey, RateLimiter, SessionId, SessionRecord,
    SessionRepository, UserId, UserRecord, UserRepository,
};
use tokio::runtime::Handle;

use crate::error::{AwsAdapterError, map_sdk_error};
use crate::hmac_key::{SESSION_LOOKUP_HMAC_PREFIX, StorageHmacKey};

/// DynamoDB single-table auth store.
pub struct DynamoDbAuthStore {
    client: DynamoDbClient,
    table_name: String,
    storage_hmac_key: Arc<StorageHmacKey>,
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
            storage_hmac_key: Arc::new(storage_hmac_key),
        }
    }

    fn block_on<T, F>(&self, future: F) -> Result<T, AwsAdapterError>
    where
        F: core::future::Future<Output = Result<T, AwsAdapterError>>,
    {
        tokio::task::block_in_place(|| Handle::current().block_on(future))
    }

    fn hmac(&self, prefix: &str, value: &str) -> Result<String, AwsAdapterError> {
        self.storage_hmac_key.hmac(prefix, value)
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

    fn pk_session(&self, session_id: &SessionId) -> Result<String, AwsAdapterError> {
        Ok(Self::pk_session_from_hmac(&self.session_hmac(session_id)?))
    }

    fn pk_user_email(&self, email: &NormalizedEmail) -> Result<String, AwsAdapterError> {
        Ok(format!("USER#{}", self.hmac("emh", email.as_str())?))
    }

    fn pk_user_id(user_id: &UserId) -> String {
        format!("USERID#{}", user_id.as_str())
    }

    fn pk_rate(&self, key: &RateLimitKey) -> Result<String, AwsAdapterError> {
        Ok(format!("RL#{}", self.hmac("rlh", key.as_str())?))
    }

    fn item_to_user(item: &HashMap<String, AttributeValue>) -> Result<UserRecord, AwsAdapterError> {
        Ok(UserRecord {
            user_id: UserId::parse(required_s(item, "user_id")?)
                .map_err(|_| AwsAdapterError::Internal)?,
            email: NormalizedEmail::parse(required_s(item, "email_normalized")?)
                .map_err(|_| AwsAdapterError::Internal)?,
            disabled: optional_bool(item, "disabled").unwrap_or(false),
            terms_version: optional_s(item, "terms_version").map(str::to_owned),
            privacy_version: optional_s(item, "privacy_version").map(str::to_owned),
            consented_at_unix: optional_u64(item, "consented_at_unix")?,
        })
    }

    fn item_to_consumed(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<ConsumedMagicLink, AwsAdapterError> {
        Ok(ConsumedMagicLink {
            email: NormalizedEmail::parse(required_s(item, "email_normalized")?)
                .map_err(|_| AwsAdapterError::Internal)?,
            user_id: optional_s(item, "user_id")
                .map(|value| UserId::parse(value).map_err(|_| AwsAdapterError::Internal))
                .transpose()?,
            terms_version: required_s(item, "terms_version")?.to_owned(),
            privacy_version: required_s(item, "privacy_version")?.to_owned(),
            consented_at_unix: required_u64(item, "consented_at_unix")?,
        })
    }

    fn item_to_session(
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

impl fmt::Debug for DynamoDbAuthStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DynamoDbAuthStore(..)")
    }
}

impl MagicLinkRepository for DynamoDbAuthStore {
    fn put_magic_link_if_absent(&self, record: MagicLinkRecord) -> Result<(), DependencyError> {
        let pk = Self::pk_magic_link(&record.selector_lookup_hmac);
        let ttl = record.expires_at_unix.saturating_add(24 * 60 * 60);
        self.block_on(async {
            let mut request = self
                .client
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
                .condition_expression("attribute_not_exists(pk)");
            if let Some(user_id) = &record.user_id {
                request = request.item("user_id", av_s(user_id.as_str()));
            }
            request
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            Ok(())
        })
        .map_err(DependencyError::from)
    }

    fn consume_magic_link(
        &self,
        selector_lookup_hmac: &LookupHmac,
        verifier_hash: &VerifierHash,
        now_unix: u64,
    ) -> Result<ConsumedMagicLink, ConsumeMagicLinkError> {
        let pk = Self::pk_magic_link(selector_lookup_hmac);
        self.block_on(async {
            let output = self
                .client
                .update_item()
                .table_name(&self.table_name)
                .key("pk", av_s(pk))
                .key("sk", av_s("CHALLENGE"))
                .update_expression("SET consumed_at_unix = :now")
                .condition_expression("attribute_exists(pk) AND attribute_not_exists(consumed_at_unix) AND expires_at_unix >= :now AND verifier_hash = :vh AND attribute_exists(terms_version) AND attribute_exists(privacy_version) AND attribute_exists(consented_at_unix)")
                .expression_attribute_values(":now", av_n(now_unix))
                .expression_attribute_values(":vh", av_s(verifier_hash.as_storage_value()))
                .return_values(ReturnValue::AllNew)
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            let item = output.attributes().ok_or(AwsAdapterError::Internal)?;
            Self::item_to_consumed(item)
        })
        .map_err(ConsumeMagicLinkError::from)
    }
}

impl UserRepository for DynamoDbAuthStore {
    fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        let pk = self.pk_user_email(email).map_err(DependencyError::from)?;
        self.block_on(async {
            let output = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key("pk", av_s(pk))
                .key("sk", av_s("PROFILE"))
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            let Some(item) = output.item() else {
                return Ok(None);
            };
            if optional_s(item, "entity_type") != Some("user_email_lookup") {
                return Err(AwsAdapterError::Internal);
            }
            let user_id = UserId::parse(required_s(item, "user_id")?)
                .map_err(|_| AwsAdapterError::Internal)?;
            let user_output = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key("pk", av_s(Self::pk_user_id(&user_id)))
                .key("sk", av_s("PROFILE"))
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            user_output.item().map(Self::item_to_user).transpose()
        })
        .map_err(DependencyError::from)
    }

    fn put_user_if_absent(&self, user: UserRecord) -> Result<(), DependencyError> {
        let email_pk = self
            .pk_user_email(&user.email)
            .map_err(DependencyError::from)?;
        let user_pk = Self::pk_user_id(&user.user_id);
        self.block_on(async {
            let mut profile_put = Put::builder()
                .table_name(&self.table_name)
                .item("pk", av_s(user_pk))
                .item("sk", av_s("PROFILE"))
                .item("entity_type", av_s("user_profile"))
                .item("user_id", av_s(user.user_id.as_str()))
                .item("email_normalized", av_s(user.email.as_str()))
                .item("disabled", av_bool(user.disabled));
            if let Some(terms_version) = &user.terms_version {
                profile_put = profile_put.item("terms_version", av_s(terms_version.clone()));
            }
            if let Some(privacy_version) = &user.privacy_version {
                profile_put = profile_put.item("privacy_version", av_s(privacy_version.clone()));
            }
            if let Some(consented_at_unix) = user.consented_at_unix {
                profile_put = profile_put.item("consented_at_unix", av_n(consented_at_unix));
            }
            let profile_put = profile_put
                .condition_expression("attribute_not_exists(pk)")
                .build()
                .map_err(|_| AwsAdapterError::Internal)?;
            let email_lookup_put = Put::builder()
                .table_name(&self.table_name)
                .item("pk", av_s(email_pk))
                .item("sk", av_s("PROFILE"))
                .item("entity_type", av_s("user_email_lookup"))
                .item("user_id", av_s(user.user_id.as_str()))
                .item("email_normalized", av_s(user.email.as_str()))
                .condition_expression("attribute_not_exists(pk)")
                .build()
                .map_err(|_| AwsAdapterError::Internal)?;
            self.client
                .transact_write_items()
                .transact_items(TransactWriteItem::builder().put(profile_put).build())
                .transact_items(TransactWriteItem::builder().put(email_lookup_put).build())
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            Ok(())
        })
        .map_err(DependencyError::from)
    }
}

impl SessionRepository for DynamoDbAuthStore {
    fn put_session_if_absent(&self, session: SessionRecord) -> Result<(), DependencyError> {
        let session_hmac = self
            .session_hmac(&session.session_id)
            .map_err(DependencyError::from)?;
        let pk = Self::pk_session_from_hmac(&session_hmac);
        let user_pk = format!("USER#{}", session.user_id.as_str());
        let expires_at_unix = session.created_at_unix.saturating_add(30 * 24 * 60 * 60);
        self.block_on(async {
            let session_put = Put::builder()
                .table_name(&self.table_name)
                .item("pk", av_s(pk))
                .item("sk", av_s("SESSION"))
                .item("entity_type", av_s("session"))
                .item("user_id", av_s(session.user_id.as_str()))
                .item("email_normalized", av_s(session.email.as_str()))
                .item("created_at_unix", av_n(session.created_at_unix))
                .item("ttl", av_n(expires_at_unix))
                .condition_expression("attribute_not_exists(pk)")
                .build()
                .map_err(|_| AwsAdapterError::Internal)?;
            let index_put = Put::builder()
                .table_name(&self.table_name)
                .item("pk", av_s(user_pk))
                .item(
                    "sk",
                    av_s(format!(
                        "SESSION#{}#{session_hmac}",
                        session.created_at_unix
                    )),
                )
                .item("entity_type", av_s("user_session_index"))
                .item("created_at_unix", av_n(session.created_at_unix))
                .item("expires_at_unix", av_n(expires_at_unix))
                .item("ttl", av_n(expires_at_unix))
                .condition_expression("attribute_not_exists(pk)")
                .build()
                .map_err(|_| AwsAdapterError::Internal)?;
            self.client
                .transact_write_items()
                .transact_items(TransactWriteItem::builder().put(session_put).build())
                .transact_items(TransactWriteItem::builder().put(index_put).build())
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            Ok(())
        })
        .map_err(DependencyError::from)
    }

    fn find_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        let pk = self.pk_session(session_id).map_err(DependencyError::from)?;
        self.block_on(async {
            let output = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key("pk", av_s(pk))
                .key("sk", av_s("SESSION"))
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            output
                .item()
                .map(|item| Self::item_to_session(session_id, item))
                .transpose()
        })
        .map_err(DependencyError::from)
    }

    fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        let pk = self.pk_session(session_id).map_err(DependencyError::from)?;
        self.block_on(async {
            self.client
                .update_item()
                .table_name(&self.table_name)
                .key("pk", av_s(pk))
                .key("sk", av_s("SESSION"))
                .update_expression("SET revoked_at_unix = :now")
                .condition_expression(
                    "attribute_exists(pk) AND attribute_not_exists(revoked_at_unix)",
                )
                .expression_attribute_values(":now", av_n(revoked_at_unix))
                .send()
                .await
                .map_err(|err| map_sdk_error(&format!("{err:?}")))?;
            Ok(())
        })
        .map_err(DependencyError::from)
    }
}

impl RateLimiter for DynamoDbAuthStore {
    fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window_secs: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        let pk = self.pk_rate(key).map_err(DependencyError::from)?;
        let ttl = unix_now_secs().saturating_add(window_secs);
        self.block_on(async {
            let result = self
                .client
                .update_item()
                .table_name(&self.table_name)
                .key("pk", av_s(pk))
                .key("sk", av_s("COUNTER"))
                .update_expression("SET #entity_type = if_not_exists(#entity_type, :entity), #ttl = :ttl ADD #count :one")
                .condition_expression("attribute_not_exists(#count) OR #count < :limit")
                .expression_attribute_names("#entity_type", "entity_type")
                .expression_attribute_names("#ttl", "ttl")
                .expression_attribute_names("#count", "count")
                .expression_attribute_values(":entity", av_s("rate_counter"))
                .expression_attribute_values(":ttl", av_n(ttl))
                .expression_attribute_values(":one", av_n(1))
                .expression_attribute_values(":limit", av_n(limit))
                .return_values(ReturnValue::AllNew)
                .send()
                .await;
            match result {
                Ok(_) => Ok(RateLimitDecision::Allowed),
                Err(error) => match map_sdk_error(&format!("{error:?}")) {
                    AwsAdapterError::ConditionalWriteFailed => Ok(RateLimitDecision::Denied),
                    other => Err(other),
                },
            }
        })
        .map_err(DependencyError::from)
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn av_s(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}

fn av_n(value: impl ToString) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

fn av_bool(value: bool) -> AttributeValue {
    AttributeValue::Bool(value)
}

fn required_s<'a>(
    item: &'a HashMap<String, AttributeValue>,
    key: &str,
) -> Result<&'a str, AwsAdapterError> {
    optional_s(item, key).ok_or(AwsAdapterError::Internal)
}

fn optional_s<'a>(item: &'a HashMap<String, AttributeValue>, key: &str) -> Option<&'a str> {
    item.get(key)
        .and_then(|value| value.as_s().ok().map(String::as_str))
}

fn required_u64(item: &HashMap<String, AttributeValue>, key: &str) -> Result<u64, AwsAdapterError> {
    optional_u64(item, key)?.ok_or(AwsAdapterError::Internal)
}

fn optional_u64(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<u64>, AwsAdapterError> {
    item.get(key)
        .map(|value| {
            value
                .as_n()
                .map_err(|_| AwsAdapterError::Internal)?
                .parse::<u64>()
                .map_err(|_| AwsAdapterError::Internal)
        })
        .transpose()
}

fn optional_bool(item: &HashMap<String, AttributeValue>, key: &str) -> Option<bool> {
    item.get(key)
        .and_then(|value| value.as_bool().ok().copied())
}

//! Optional DynamoDB-backed service trait implementations.

use core::fmt;
use std::collections::HashMap;

use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::operation::get_item::GetItemOutput;
use aws_sdk_dynamodb::operation::get_item::builders::GetItemFluentBuilder;
use aws_sdk_dynamodb::operation::transact_write_items::builders::TransactWriteItemsFluentBuilder;
use aws_sdk_dynamodb::types::{AttributeValue, ConditionCheck, Put, TransactWriteItem, Update};
use datadeft_magic_link_service::{
    CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, DependencyError, LookupHmac,
    MagicLinkAuthenticationCandidate, MagicLinkAuthenticationRepository,
    MagicLinkAuthenticationUser, MagicLinkRecord, MagicLinkRepository, NormalizedEmail,
    RateLimitDecision, RateLimitKey, RateLimiter, SessionId, SessionRecord, SessionRepository,
    UserId, UserRecord, VerifierHash,
};

use crate::error::{
    AwsAdapterError, map_authentication_transact_write_items_error, map_get_item_error,
    map_put_item_error, map_scan_error, map_update_item_error,
};
use crate::hmac_key::{
    EMAIL_LOOKUP_HMAC_PREFIX, RATE_LOOKUP_HMAC_PREFIX, SESSION_LOOKUP_HMAC_PREFIX, StorageHmacKey,
    StorageHmacKeys,
};
use crate::window::fixed_window_index;

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

    /// Write an email lookup row under the current storage key for every user
    /// profile that lacks one. Idempotent; safe to run repeatedly and while
    /// serving traffic. Needs `dynamodb:Scan` on the table. Returns the number
    /// of rows written.
    pub async fn rekey_email_lookups(&self) -> Result<u64, AwsAdapterError> {
        let mut written = 0u64;
        let mut start_key: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .client
                .scan()
                .table_name(&self.table_name)
                .filter_expression("entity_type = :user_profile")
                .projection_expression("user_id, email_normalized")
                .expression_attribute_values(":user_profile", av_s("user_profile"))
                .set_exclusive_start_key(start_key.take())
                .send()
                .await
                .map_err(map_scan_error)?;
            for item in output.items() {
                let email = NormalizedEmail::parse(required_s(item, "email_normalized")?)
                    .map_err(|_| AwsAdapterError::Internal)?;
                let user_id = UserId::parse(required_s(item, "user_id")?)
                    .map_err(|_| AwsAdapterError::Internal)?;
                if self.put_email_lookup_if_absent(&email, &user_id).await? {
                    written = written.saturating_add(1);
                }
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => return Ok(written),
            }
        }
    }

    /// Conditionally write the current-key email lookup row. Returns `true`
    /// when written, `false` when one already existed.
    async fn put_email_lookup_if_absent(
        &self,
        email: &NormalizedEmail,
        user_id: &UserId,
    ) -> Result<bool, AwsAdapterError> {
        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(self.email_lookup_item(email, user_id)?))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
            .map_err(map_put_item_error);
        match result {
            Ok(_) => Ok(true),
            Err(AwsAdapterError::ConditionalWriteFailed) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// The email lookup row, shared by user creation and lookup migration so
    /// the commit's condition check and both writers agree on its shape.
    fn email_lookup_item(
        &self,
        email: &NormalizedEmail,
        user_id: &UserId,
    ) -> Result<HashMap<String, AttributeValue>, AwsAdapterError> {
        Ok(HashMap::from([
            ("pk".to_owned(), av_s(self.pk_user_email(email)?)),
            ("sk".to_owned(), av_s("PROFILE")),
            ("entity_type".to_owned(), av_s("user_email_lookup")),
            ("user_id".to_owned(), av_s(user_id.as_str())),
            ("email_normalized".to_owned(), av_s(email.as_str())),
        ]))
    }

    /// Consistent read of `(pk, sk)` under the current storage key, retried
    /// under the previous key on a miss. Returns the output and whether it
    /// came from the previous key. The previous HMAC is only computed on a
    /// miss, so the hot path pays nothing outside a rotation.
    async fn get_with_key_fallback(
        &self,
        sk: &str,
        pk_for: impl Fn(&StorageHmacKey) -> Result<String, AwsAdapterError>,
    ) -> Result<(GetItemOutput, bool), AwsAdapterError> {
        let output = self
            .authentication_get_item(pk_for(self.storage_hmac_keys.current())?, sk)
            .send()
            .await
            .map_err(map_get_item_error)?;
        if output.item().is_none()
            && let Some(previous) = self.storage_hmac_keys.previous()
        {
            let fallback = self
                .authentication_get_item(pk_for(previous)?, sk)
                .send()
                .await
                .map_err(map_get_item_error)?;
            if fallback.item().is_some() {
                return Ok((fallback, true));
            }
        }
        Ok((output, false))
    }

    async fn revoke_session_item(
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

    fn item_to_authentication_candidate(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<MagicLinkAuthenticationCandidate, AwsAdapterError> {
        if required_s(item, "entity_type")? != "magic_link" {
            return Err(AwsAdapterError::Internal);
        }
        Ok(MagicLinkAuthenticationCandidate {
            verifier_hash: VerifierHash::parse_storage_value(required_s(item, "verifier_hash")?)
                .map_err(|_| AwsAdapterError::Internal)?,
            email: NormalizedEmail::parse(required_s(item, "email_normalized")?)
                .map_err(|_| AwsAdapterError::Internal)?,
            expires_at_unix: required_u64(item, "expires_at_unix")?,
            consumed_at_unix: optional_u64(item, "consumed_at_unix")?,
            terms_version: required_s(item, "terms_version")?.to_owned(),
            privacy_version: required_s(item, "privacy_version")?.to_owned(),
            consented_at_unix: required_u64(item, "consented_at_unix")?,
        })
    }

    fn item_to_authentication_user(
        item: &HashMap<String, AttributeValue>,
        expected_user_id: &UserId,
        expected_email: &NormalizedEmail,
    ) -> Result<UserRecord, AwsAdapterError> {
        if required_s(item, "entity_type")? != "user_profile" {
            return Err(AwsAdapterError::Internal);
        }
        let user_id =
            UserId::parse(required_s(item, "user_id")?).map_err(|_| AwsAdapterError::Internal)?;
        let email = NormalizedEmail::parse(required_s(item, "email_normalized")?)
            .map_err(|_| AwsAdapterError::Internal)?;
        if user_id != *expected_user_id || email != *expected_email {
            return Err(AwsAdapterError::Internal);
        }
        Ok(UserRecord {
            user_id,
            email,
            disabled: required_bool(item, "disabled")?,
            terms_version: optional_s_strict(item, "terms_version")?.map(str::to_owned),
            privacy_version: optional_s_strict(item, "privacy_version")?.map(str::to_owned),
            consented_at_unix: optional_u64(item, "consented_at_unix")?,
        })
    }

    fn authentication_get_item(&self, pk: String, sk: &str) -> GetItemFluentBuilder {
        self.client
            .get_item()
            .table_name(&self.table_name)
            .key("pk", av_s(pk))
            .key("sk", av_s(sk))
            .consistent_read(true)
    }

    fn build_authentication_transaction(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<Vec<TransactWriteItem>, AwsAdapterError> {
        if command.session_expires_at_unix < command.now_unix {
            return Err(AwsAdapterError::Internal);
        }
        let user_id = match &command.user {
            MagicLinkAuthenticationUser::Existing { user_id }
            | MagicLinkAuthenticationUser::Create { user_id } => user_id,
        };
        let challenge_update = Update::builder()
            .table_name(&self.table_name)
            .key(
                "pk",
                av_s(Self::pk_magic_link(
                    &command.magic_link.selector_lookup_hmac,
                )),
            )
            .key("sk", av_s("CHALLENGE"))
            .update_expression("SET consumed_at_unix = :now")
            .condition_expression("entity_type = :magic_link AND attribute_not_exists(consumed_at_unix) AND expires_at_unix = :expected_expiry AND expires_at_unix >= :now AND email_normalized = :expected_email AND terms_version = :expected_terms AND privacy_version = :expected_privacy AND consented_at_unix = :expected_consent AND consented_at_unix > :zero")
            .expression_attribute_values(":magic_link", av_s("magic_link"))
            .expression_attribute_values(":expected_expiry", av_n(command.magic_link.expires_at_unix))
            .expression_attribute_values(":now", av_n(command.now_unix))
            .expression_attribute_values(":expected_email", av_s(command.magic_link.email.as_str()))
            .expression_attribute_values(":expected_terms", av_s(command.magic_link.terms_version.clone()))
            .expression_attribute_values(":expected_privacy", av_s(command.magic_link.privacy_version.clone()))
            .expression_attribute_values(":expected_consent", av_n(command.magic_link.consented_at_unix))
            .expression_attribute_values(":zero", av_n(0))
            .build()
            .map_err(|_| AwsAdapterError::Internal)?;
        let mut actions = vec![
            TransactWriteItem::builder()
                .update(challenge_update)
                .build(),
        ];

        match &command.user {
            MagicLinkAuthenticationUser::Existing { .. } => {
                let email_check = ConditionCheck::builder()
                    .table_name(&self.table_name)
                    .key("pk", av_s(self.pk_user_email(&command.magic_link.email)?))
                    .key("sk", av_s("PROFILE"))
                    .condition_expression("entity_type = :email_lookup AND email_normalized = :expected_email AND user_id = :expected_user")
                    .expression_attribute_values(":email_lookup", av_s("user_email_lookup"))
                    .expression_attribute_values(":expected_email", av_s(command.magic_link.email.as_str()))
                    .expression_attribute_values(":expected_user", av_s(user_id.as_str()))
                    .build()
                    .map_err(|_| AwsAdapterError::Internal)?;
                let profile_check = ConditionCheck::builder()
                    .table_name(&self.table_name)
                    .key("pk", av_s(Self::pk_user_id(user_id)))
                    .key("sk", av_s("PROFILE"))
                    .condition_expression("entity_type = :user_profile AND user_id = :expected_user AND email_normalized = :expected_email AND disabled = :false")
                    .expression_attribute_values(":user_profile", av_s("user_profile"))
                    .expression_attribute_values(":expected_user", av_s(user_id.as_str()))
                    .expression_attribute_values(":expected_email", av_s(command.magic_link.email.as_str()))
                    .expression_attribute_values(":false", av_bool(false))
                    .build()
                    .map_err(|_| AwsAdapterError::Internal)?;
                actions.push(
                    TransactWriteItem::builder()
                        .condition_check(email_check)
                        .build(),
                );
                actions.push(
                    TransactWriteItem::builder()
                        .condition_check(profile_check)
                        .build(),
                );
            }
            MagicLinkAuthenticationUser::Create { .. } => {
                let profile_put = Put::builder()
                    .table_name(&self.table_name)
                    .item("pk", av_s(Self::pk_user_id(user_id)))
                    .item("sk", av_s("PROFILE"))
                    .item("entity_type", av_s("user_profile"))
                    .item("user_id", av_s(user_id.as_str()))
                    .item("email_normalized", av_s(command.magic_link.email.as_str()))
                    .item("disabled", av_bool(false))
                    .item(
                        "terms_version",
                        av_s(command.magic_link.terms_version.clone()),
                    )
                    .item(
                        "privacy_version",
                        av_s(command.magic_link.privacy_version.clone()),
                    )
                    .item(
                        "consented_at_unix",
                        av_n(command.magic_link.consented_at_unix),
                    )
                    .condition_expression("attribute_not_exists(pk)")
                    .build()
                    .map_err(|_| AwsAdapterError::Internal)?;
                let email_put = Put::builder()
                    .table_name(&self.table_name)
                    .set_item(Some(
                        self.email_lookup_item(&command.magic_link.email, user_id)?,
                    ))
                    .condition_expression("attribute_not_exists(pk)")
                    .build()
                    .map_err(|_| AwsAdapterError::Internal)?;
                actions.push(TransactWriteItem::builder().put(profile_put).build());
                actions.push(TransactWriteItem::builder().put(email_put).build());
            }
        }

        let session_hmac = self.session_hmac(&command.session_id)?;
        let session_put = Put::builder()
            .table_name(&self.table_name)
            .item("pk", av_s(Self::pk_session_from_hmac(&session_hmac)))
            .item("sk", av_s("SESSION"))
            .item("entity_type", av_s("session"))
            .item("user_id", av_s(user_id.as_str()))
            .item("email_normalized", av_s(command.magic_link.email.as_str()))
            .item("created_at_unix", av_n(command.now_unix))
            .item("expires_at_unix", av_n(command.session_expires_at_unix))
            // No `ttl`: session rows are kept for the audit trail. Validity is
            // `expires_at_unix` / `revoked_at_unix`, checked on every read.
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|_| AwsAdapterError::Internal)?;
        let index_put = Put::builder()
            .table_name(&self.table_name)
            .item("pk", av_s(format!("USER#{}", user_id.as_str())))
            .item(
                "sk",
                av_s(format!("SESSION#{}#{session_hmac}", command.now_unix)),
            )
            .item("entity_type", av_s("user_session_index"))
            .item("created_at_unix", av_n(command.now_unix))
            .item("expires_at_unix", av_n(command.session_expires_at_unix))
            // No `ttl`: session rows are kept for the audit trail. Validity is
            // `expires_at_unix` / `revoked_at_unix`, checked on every read.
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|_| AwsAdapterError::Internal)?;
        actions.push(TransactWriteItem::builder().put(session_put).build());
        actions.push(TransactWriteItem::builder().put(index_put).build());
        Ok(actions)
    }

    fn authentication_transaction_request(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<TransactWriteItemsFluentBuilder, AwsAdapterError> {
        Ok(self
            .client
            .transact_write_items()
            .set_transact_items(Some(self.build_authentication_transaction(command)?))
            .client_request_token(command.attempt_id.as_str()))
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

impl MagicLinkAuthenticationRepository for DynamoDbAuthStore {
    async fn find_magic_link_for_authentication(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        let pk = Self::pk_magic_link(selector_lookup_hmac);
        async {
            let output = self
                .authentication_get_item(pk, "CHALLENGE")
                .send()
                .await
                .map_err(map_get_item_error)?;
            output
                .item()
                .map(Self::item_to_authentication_candidate)
                .transpose()
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        async {
            let (output, migrate) = self
                .get_with_key_fallback("PROFILE", |key| Self::pk_user_email_under(key, email))
                .await?;
            let Some(item) = output.item() else {
                return Ok(None);
            };
            if required_s(item, "entity_type")? != "user_email_lookup"
                || NormalizedEmail::parse(required_s(item, "email_normalized")?)
                    .map_err(|_| AwsAdapterError::Internal)?
                    != *email
            {
                return Err(AwsAdapterError::Internal);
            }
            let user_id = UserId::parse(required_s(item, "user_id")?)
                .map_err(|_| AwsAdapterError::Internal)?;
            let profile_output = self
                .authentication_get_item(Self::pk_user_id(&user_id), "PROFILE")
                .send()
                .await
                .map_err(map_get_item_error)?;
            let profile = profile_output.item().ok_or(AwsAdapterError::Internal)?;
            let user = Self::item_to_authentication_user(profile, &user_id, email)?;
            if migrate {
                // Found under the previous storage key: write the current-key
                // lookup row the commit's condition check reads.
                self.put_email_lookup_if_absent(email, &user_id).await?;
            }
            Ok(Some(user))
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        self.authentication_transaction_request(command)
            .map_err(|_| CommitMagicLinkAuthenticationError::Internal)?
            .send()
            .await
            .map_err(map_authentication_transact_write_items_error)?;
        Ok(())
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

    async fn is_user_active(&self, user_id: &UserId) -> Result<bool, DependencyError> {
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
            Ok(optional_s(item, "entity_type") == Some("user_profile")
                && optional_s(item, "user_id") == Some(user_id.as_str())
                && matches!(item.get("disabled"), Some(AttributeValue::Bool(false))))
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

fn fixed_window_start(now_unix: u64, window_secs: u64) -> u64 {
    fixed_window_index(now_unix, window_secs).saturating_mul(window_secs)
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

fn optional_s_strict<'a>(
    item: &'a HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<&'a str>, AwsAdapterError> {
    item.get(key)
        .map(|value| {
            value
                .as_s()
                .map(String::as_str)
                .map_err(|_| AwsAdapterError::Internal)
        })
        .transpose()
}

fn required_bool(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<bool, AwsAdapterError> {
    item.get(key)
        .ok_or(AwsAdapterError::Internal)?
        .as_bool()
        .copied()
        .map_err(|_| AwsAdapterError::Internal)
}

#[cfg(test)]
#[path = "dynamodb_tests.rs"]
mod tests;

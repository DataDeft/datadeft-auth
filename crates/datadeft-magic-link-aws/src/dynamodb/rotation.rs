//! Storage-key rotation: previous-key read fallback, email-lookup rows, and re-keying.

use std::collections::HashMap;

use aws_sdk_dynamodb::operation::get_item::GetItemOutput;
use aws_sdk_dynamodb::types::AttributeValue;
use datadeft_magic_link_service::{NormalizedEmail, UserId};

use crate::error::{AwsAdapterError, map_get_item_error, map_put_item_error, map_scan_error};
use crate::hmac_key::StorageHmacKey;

use super::items::{av_s, required_s};
use super::*;

impl DynamoDbAuthStore {
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
    pub(super) async fn put_email_lookup_if_absent(
        &self,
        email: &NormalizedEmail,
        user_id: &UserId,
    ) -> Result<bool, AwsAdapterError> {
        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(Self::email_lookup_item(
                self.storage_hmac_keys.current(),
                email,
                user_id,
            )?))
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

    /// The email lookup row under `key`, shared by user creation and lookup
    /// migration so the commit's condition check and every writer agree on
    /// its shape.
    pub(super) fn email_lookup_item(
        key: &StorageHmacKey,
        email: &NormalizedEmail,
        user_id: &UserId,
    ) -> Result<HashMap<String, AttributeValue>, AwsAdapterError> {
        Ok(HashMap::from([
            (
                "pk".to_owned(),
                av_s(Self::pk_user_email_under(key, email)?),
            ),
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
    pub(super) async fn get_with_key_fallback(
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
}

//! The magic-link authentication repository: candidate reads and the atomic commit transaction.

use std::collections::HashMap;

use aws_sdk_dynamodb::operation::get_item::builders::GetItemFluentBuilder;
use aws_sdk_dynamodb::operation::transact_write_items::builders::TransactWriteItemsFluentBuilder;
use aws_sdk_dynamodb::types::{AttributeValue, ConditionCheck, Put, TransactWriteItem, Update};
use datadeft_magic_link_service::{
    CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, DependencyError, LookupHmac,
    MagicLinkAuthenticationCandidate, MagicLinkAuthenticationRepository,
    MagicLinkAuthenticationUser, NormalizedEmail, UserId, UserRecord, VerifierHash,
};

use crate::error::{
    AwsAdapterError, map_authentication_transact_write_items_error, map_get_item_error,
};

use super::items::*;
use super::*;

impl DynamoDbAuthStore {
    pub(super) fn item_to_authentication_candidate(
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

    pub(super) fn item_to_authentication_user(
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

    pub(super) fn authentication_get_item(&self, pk: String, sk: &str) -> GetItemFluentBuilder {
        self.client
            .get_item()
            .table_name(&self.table_name)
            .key("pk", av_s(pk))
            .key("sk", av_s(sk))
            .consistent_read(true)
    }

    pub(super) fn build_authentication_transaction(
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

    pub(super) fn authentication_transaction_request(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<TransactWriteItemsFluentBuilder, AwsAdapterError> {
        Ok(self
            .client
            .transact_write_items()
            .set_transact_items(Some(self.build_authentication_transaction(command)?))
            .client_request_token(command.attempt_id.as_str()))
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

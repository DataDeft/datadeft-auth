//! [`AuthAdminRepository`] for [`DynamoDbAuthStore`].
//!
//! Item layout (single table, `pk` / `sk`):
//!
//! - user profile: `USERID#<user id>` / `PROFILE`; disabling adds
//!   `disabled_at_unix` and `disabled_by`, enabling removes them;
//! - session: `SESSION#<session hmac>` / `SESSION`; revoking adds
//!   `revoked_at_unix` and `revoked_by`;
//! - per-user session index: `USER#<user id>` / `SESSION#<created>#<hmac>`;
//! - audit event: `AUDIT#<user id>` / `EVENT#<at, 20 digits>#<event id>`.
//!
//! Every mutation is one `TransactWriteItems`: the conditional change plus the
//! audit event put, so both happen or neither does. Nothing is deleted.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use datadeft_magic_link_service::{
    AdminAction, AdminActor, AdminEvent, AdminEventId, AuthAdminRepository, Page, PageCursor,
    SessionHandle, SessionSummary, UserSummary,
};

use super::*;
use crate::error::{map_admin_transact_write_items_error, map_query_error};

const AUDIT_PK_PREFIX: &str = "AUDIT#";
const AUDIT_SK_PREFIX: &str = "EVENT#";
const SESSION_PK_PREFIX: &str = "SESSION#";
const INDEX_SK_PREFIX: &str = "SESSION#";

impl DynamoDbAuthStore {
    fn pk_audit(user_id: &UserId) -> String {
        format!("{AUDIT_PK_PREFIX}{}", user_id.as_str())
    }

    fn pk_user_sessions(user_id: &UserId) -> String {
        format!("USER#{}", user_id.as_str())
    }

    /// Append-only audit event put; never overwrites an existing event.
    pub(crate) fn audit_event_put(&self, event: &AdminEvent) -> Result<Put, AwsAdapterError> {
        let mut builder = Put::builder()
            .table_name(&self.table_name)
            .item("pk", av_s(Self::pk_audit(&event.user_id)))
            .item(
                "sk",
                av_s(format!(
                    "{AUDIT_SK_PREFIX}{:020}#{}",
                    event.at_unix,
                    event.event_id.as_str()
                )),
            )
            .item("entity_type", av_s("admin_event"))
            .item("event_id", av_s(event.event_id.as_str()))
            .item("at_unix", av_n(event.at_unix))
            .item("action", av_s(event.action.as_str()))
            .item("user_id", av_s(event.user_id.as_str()))
            .item("actor_id", av_s(event.actor.id()));
        if let Some(session) = &event.session {
            builder = builder.item("session_handle", av_s(session.as_str()));
        }
        if let Some(reason) = event.actor.reason() {
            builder = builder.item("actor_reason", av_s(reason));
        }
        builder
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|_| AwsAdapterError::Internal)
    }

    /// Revoke the event's session if the event's user owns it and it is not
    /// revoked yet, plus the audit event.
    pub(crate) fn revoke_session_transaction(
        &self,
        event: &AdminEvent,
    ) -> Result<Vec<TransactWriteItem>, AwsAdapterError> {
        if event.action != AdminAction::RevokeSession {
            return Err(AwsAdapterError::Internal);
        }
        let handle = event.session.as_ref().ok_or(AwsAdapterError::Internal)?;
        let update = Update::builder()
            .table_name(&self.table_name)
            .key("pk", av_s(Self::pk_session_from_hmac(handle.as_str())))
            .key("sk", av_s("SESSION"))
            .update_expression("SET revoked_at_unix = :at, revoked_by = :actor")
            .condition_expression(
                "entity_type = :session AND user_id = :user AND attribute_not_exists(revoked_at_unix)",
            )
            .expression_attribute_values(":at", av_n(event.at_unix))
            .expression_attribute_values(":actor", av_s(event.actor.id()))
            .expression_attribute_values(":session", av_s("session"))
            .expression_attribute_values(":user", av_s(event.user_id.as_str()))
            .build()
            .map_err(|_| AwsAdapterError::Internal)?;
        Ok(vec![
            TransactWriteItem::builder().update(update).build(),
            TransactWriteItem::builder()
                .put(self.audit_event_put(event)?)
                .build(),
        ])
    }

    /// Flip the user's disabled flag if it is not already in the target
    /// state, plus the audit event.
    pub(crate) fn set_user_disabled_transaction(
        &self,
        event: &AdminEvent,
    ) -> Result<Vec<TransactWriteItem>, AwsAdapterError> {
        let builder = Update::builder()
            .table_name(&self.table_name)
            .key("pk", av_s(Self::pk_user_id(&event.user_id)))
            .key("sk", av_s("PROFILE"))
            .condition_expression(
                "entity_type = :profile AND user_id = :user AND disabled = :current",
            )
            .expression_attribute_values(":profile", av_s("user_profile"))
            .expression_attribute_values(":user", av_s(event.user_id.as_str()));
        let builder = match event.action {
            AdminAction::DisableUser => builder
                .update_expression(
                    "SET disabled = :target, disabled_at_unix = :at, disabled_by = :actor",
                )
                .expression_attribute_values(":current", av_bool(false))
                .expression_attribute_values(":target", av_bool(true))
                .expression_attribute_values(":at", av_n(event.at_unix))
                .expression_attribute_values(":actor", av_s(event.actor.id())),
            AdminAction::EnableUser => builder
                .update_expression("SET disabled = :target REMOVE disabled_at_unix, disabled_by")
                .expression_attribute_values(":current", av_bool(true))
                .expression_attribute_values(":target", av_bool(false)),
            AdminAction::RevokeSession => return Err(AwsAdapterError::Internal),
        };
        let update = builder.build().map_err(|_| AwsAdapterError::Internal)?;
        Ok(vec![
            TransactWriteItem::builder().update(update).build(),
            TransactWriteItem::builder()
                .put(self.audit_event_put(event)?)
                .build(),
        ])
    }

    async fn transact(&self, items: Vec<TransactWriteItem>) -> Result<(), AwsAdapterError> {
        self.client
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
            .map_err(map_admin_transact_write_items_error)?;
        Ok(())
    }

    async fn get_user_summary(
        &self,
        user_id: &UserId,
    ) -> Result<Option<UserSummary>, AwsAdapterError> {
        let output = self
            .authentication_get_item(Self::pk_user_id(user_id), "PROFILE")
            .send()
            .await
            .map_err(map_get_item_error)?;
        let Some(item) = output.item() else {
            return Ok(None);
        };
        let summary = item_to_user_summary(item)?;
        if summary.user_id != *user_id {
            return Err(AwsAdapterError::Internal);
        }
        Ok(Some(summary))
    }
}

/// Encode a `LastEvaluatedKey` (`pk` / `sk`) as an opaque cursor.
pub(crate) fn encode_cursor(
    key: Option<&HashMap<String, AttributeValue>>,
) -> Result<Option<PageCursor>, AwsAdapterError> {
    let Some(key) = key.filter(|key| !key.is_empty()) else {
        return Ok(None);
    };
    let pk = required_s(key, "pk")?;
    let sk = required_s(key, "sk")?;
    if pk.contains('\n') || sk.contains('\n') {
        return Err(AwsAdapterError::Internal);
    }
    PageCursor::parse(&URL_SAFE_NO_PAD.encode(format!("{pk}\n{sk}")))
        .map(Some)
        .map_err(|_| AwsAdapterError::Internal)
}

/// Decode a cursor into an `ExclusiveStartKey`. For a query, `expected_pk`
/// pins the partition, so a cursor from one user's listing cannot be replayed
/// against another's.
pub(crate) fn decode_cursor(
    cursor: Option<&PageCursor>,
    expected_pk: Option<&str>,
) -> Result<Option<HashMap<String, AttributeValue>>, AwsAdapterError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| AwsAdapterError::Internal)?;
    let text = String::from_utf8(bytes).map_err(|_| AwsAdapterError::Internal)?;
    let (pk, sk) = text.split_once('\n').ok_or(AwsAdapterError::Internal)?;
    if pk.is_empty() || sk.is_empty() || sk.contains('\n') {
        return Err(AwsAdapterError::Internal);
    }
    if expected_pk.is_some_and(|expected| expected != pk) {
        return Err(AwsAdapterError::Internal);
    }
    Ok(Some(HashMap::from([
        ("pk".to_owned(), av_s(pk)),
        ("sk".to_owned(), av_s(sk)),
    ])))
}

pub(crate) fn item_to_user_summary(
    item: &HashMap<String, AttributeValue>,
) -> Result<UserSummary, AwsAdapterError> {
    if required_s(item, "entity_type")? != "user_profile" {
        return Err(AwsAdapterError::Internal);
    }
    Ok(UserSummary {
        user_id: UserId::parse(required_s(item, "user_id")?)
            .map_err(|_| AwsAdapterError::Internal)?,
        email: NormalizedEmail::parse(required_s(item, "email_normalized")?)
            .map_err(|_| AwsAdapterError::Internal)?,
        disabled: required_bool(item, "disabled")?,
        disabled_at_unix: optional_u64(item, "disabled_at_unix")?,
        disabled_by: optional_s_strict(item, "disabled_by")?.map(str::to_owned),
        terms_version: optional_s_strict(item, "terms_version")?.map(str::to_owned),
        privacy_version: optional_s_strict(item, "privacy_version")?.map(str::to_owned),
        consented_at_unix: optional_u64(item, "consented_at_unix")?,
    })
}

pub(crate) fn item_to_session_summary(
    item: &HashMap<String, AttributeValue>,
) -> Result<SessionSummary, AwsAdapterError> {
    if required_s(item, "entity_type")? != "session" {
        return Err(AwsAdapterError::Internal);
    }
    let session_hmac = required_s(item, "pk")?
        .strip_prefix(SESSION_PK_PREFIX)
        .ok_or(AwsAdapterError::Internal)?;
    Ok(SessionSummary {
        handle: SessionHandle::parse(session_hmac).map_err(|_| AwsAdapterError::Internal)?,
        user_id: UserId::parse(required_s(item, "user_id")?)
            .map_err(|_| AwsAdapterError::Internal)?,
        email: NormalizedEmail::parse(required_s(item, "email_normalized")?)
            .map_err(|_| AwsAdapterError::Internal)?,
        created_at_unix: required_u64(item, "created_at_unix")?,
        expires_at_unix: required_u64(item, "expires_at_unix")?,
        revoked_at_unix: optional_u64(item, "revoked_at_unix")?,
        revoked_by: optional_s_strict(item, "revoked_by")?.map(str::to_owned),
    })
}

pub(crate) fn item_to_admin_event(
    item: &HashMap<String, AttributeValue>,
) -> Result<AdminEvent, AwsAdapterError> {
    if required_s(item, "entity_type")? != "admin_event" {
        return Err(AwsAdapterError::Internal);
    }
    let session = optional_s_strict(item, "session_handle")?
        .map(SessionHandle::parse)
        .transpose()
        .map_err(|_| AwsAdapterError::Internal)?;
    let actor = AdminActor::new(
        required_s(item, "actor_id")?,
        optional_s_strict(item, "actor_reason")?.map(str::to_owned),
    )
    .map_err(|_| AwsAdapterError::Internal)?;
    Ok(AdminEvent {
        event_id: AdminEventId::parse(required_s(item, "event_id")?)
            .map_err(|_| AwsAdapterError::Internal)?,
        at_unix: required_u64(item, "at_unix")?,
        action: AdminAction::parse(required_s(item, "action")?)
            .map_err(|_| AwsAdapterError::Internal)?,
        user_id: UserId::parse(required_s(item, "user_id")?)
            .map_err(|_| AwsAdapterError::Internal)?,
        session,
        actor,
    })
}

fn page_limit(limit: u32) -> Result<i32, AwsAdapterError> {
    i32::try_from(limit).map_err(|_| AwsAdapterError::Internal)
}

impl AuthAdminRepository for DynamoDbAuthStore {
    async fn list_users(
        &self,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<UserSummary>, DependencyError> {
        async {
            // A filtered scan may return fewer than `limit` items while more
            // remain; callers continue while `next` is set.
            let output = self
                .client
                .scan()
                .table_name(&self.table_name)
                .filter_expression("entity_type = :profile")
                .expression_attribute_values(":profile", av_s("user_profile"))
                .limit(page_limit(limit)?)
                .set_exclusive_start_key(decode_cursor(cursor, None)?)
                .send()
                .await
                .map_err(map_scan_error)?;
            Ok::<_, AwsAdapterError>(Page {
                items: output
                    .items()
                    .iter()
                    .map(item_to_user_summary)
                    .collect::<Result<_, _>>()?,
                next: encode_cursor(output.last_evaluated_key())?,
            })
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<UserSummary>, DependencyError> {
        self.get_user_summary(user_id)
            .await
            .map_err(DependencyError::from)
    }

    async fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserSummary>, DependencyError> {
        async {
            let (output, _) = self
                .get_with_key_fallback("PROFILE", |key| Self::pk_user_email_under(key, email))
                .await?;
            let Some(item) = output.item() else {
                return Ok(None);
            };
            if required_s(item, "entity_type")? != "user_email_lookup" {
                return Err(AwsAdapterError::Internal);
            }
            let user_id = UserId::parse(required_s(item, "user_id")?)
                .map_err(|_| AwsAdapterError::Internal)?;
            let summary = self.get_user_summary(&user_id).await?;
            if summary.as_ref().is_some_and(|user| user.email != *email) {
                return Err(AwsAdapterError::Internal);
            }
            Ok(summary)
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn list_sessions_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<SessionSummary>, DependencyError> {
        async {
            let mut sessions = Vec::new();
            let mut start_key = None;
            loop {
                let output = self
                    .client
                    .query()
                    .table_name(&self.table_name)
                    .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                    .expression_attribute_values(":pk", av_s(Self::pk_user_sessions(user_id)))
                    .expression_attribute_values(":prefix", av_s(INDEX_SK_PREFIX))
                    .consistent_read(true)
                    .scan_index_forward(false)
                    .set_exclusive_start_key(start_key.take())
                    .send()
                    .await
                    .map_err(map_query_error)?;
                for entry in output.items() {
                    // Index sort key: `SESSION#<created>#<session hmac>`.
                    let session_hmac = required_s(entry, "sk")?
                        .rsplit('#')
                        .next()
                        .ok_or(AwsAdapterError::Internal)?;
                    let session = self
                        .authentication_get_item(
                            Self::pk_session_from_hmac(session_hmac),
                            "SESSION",
                        )
                        .send()
                        .await
                        .map_err(map_get_item_error)?;
                    let item = session.item().ok_or(AwsAdapterError::Internal)?;
                    let summary = item_to_session_summary(item)?;
                    if summary.user_id != *user_id {
                        return Err(AwsAdapterError::Internal);
                    }
                    sessions.push(summary);
                }
                match output.last_evaluated_key() {
                    Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                    _ => return Ok(sessions),
                }
            }
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn list_active_sessions(
        &self,
        now_unix: u64,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<SessionSummary>, DependencyError> {
        async {
            let output = self
                .client
                .scan()
                .table_name(&self.table_name)
                .filter_expression(
                    "entity_type = :session AND expires_at_unix >= :now AND attribute_not_exists(revoked_at_unix)",
                )
                .expression_attribute_values(":session", av_s("session"))
                .expression_attribute_values(":now", av_n(now_unix))
                .limit(page_limit(limit)?)
                .set_exclusive_start_key(decode_cursor(cursor, None)?)
                .send()
                .await
                .map_err(map_scan_error)?;
            Ok::<_, AwsAdapterError>(Page {
                items: output
                    .items()
                    .iter()
                    .map(item_to_session_summary)
                    .collect::<Result<_, _>>()?,
                next: encode_cursor(output.last_evaluated_key())?,
            })
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn revoke_session_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        async { self.transact(self.revoke_session_transaction(event)?).await }
            .await
            .map_err(DependencyError::from)
    }

    async fn set_user_disabled_audited(&self, event: &AdminEvent) -> Result<(), DependencyError> {
        async {
            self.transact(self.set_user_disabled_transaction(event)?)
                .await
        }
        .await
        .map_err(DependencyError::from)
    }

    async fn list_admin_events(
        &self,
        user_id: &UserId,
        cursor: Option<&PageCursor>,
        limit: u32,
    ) -> Result<Page<AdminEvent>, DependencyError> {
        async {
            let pk = Self::pk_audit(user_id);
            let output = self
                .client
                .query()
                .table_name(&self.table_name)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":pk", av_s(pk.clone()))
                .expression_attribute_values(":prefix", av_s(AUDIT_SK_PREFIX))
                .consistent_read(true)
                .scan_index_forward(false)
                .limit(page_limit(limit)?)
                .set_exclusive_start_key(decode_cursor(cursor, Some(&pk))?)
                .send()
                .await
                .map_err(map_query_error)?;
            Ok::<_, AwsAdapterError>(Page {
                items: output
                    .items()
                    .iter()
                    .map(item_to_admin_event)
                    .collect::<Result<_, _>>()?,
                next: encode_cursor(output.last_evaluated_key())?,
            })
        }
        .await
        .map_err(DependencyError::from)
    }
}

#[cfg(test)]
#[path = "dynamodb_admin_tests.rs"]
mod tests;

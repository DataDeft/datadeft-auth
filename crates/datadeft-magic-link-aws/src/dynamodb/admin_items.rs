//! Admin item parsers and opaque pagination cursors for the DynamoDB store.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use datadeft_magic_link_service::{
    AdminAction, AdminActor, AdminEvent, AdminEventId, PageCursor, SessionHandle, SessionSummary,
    UserSummary,
};

use super::*;

pub(crate) const SESSION_PK_PREFIX: &str = "SESSION#";

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
    // Stored history stays readable even if input limits tighten later.
    let actor = AdminActor::from_stored(
        required_s(item, "actor_id")?.to_owned(),
        optional_s_strict(item, "actor_reason")?.map(str::to_owned),
    );
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

pub(crate) fn page_limit(limit: u32) -> Result<i32, AwsAdapterError> {
    i32::try_from(limit).map_err(|_| AwsAdapterError::Internal)
}

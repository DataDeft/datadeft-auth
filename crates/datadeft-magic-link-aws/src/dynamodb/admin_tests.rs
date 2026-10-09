//! Request-shape tests for the DynamoDB admin implementation. They build the
//! requests without sending them, so they run without AWS.

use aws_sdk_dynamodb::config::{Credentials, Region};

use datadeft_magic_link_service::{
    AdminAction, AdminActor, AdminEvent, AdminEventId, PageCursor, SessionHandle,
};

use super::items::av_bool;
use super::*;

const USER_ID: &str = "usr_000102030405060708090a0b0c0d0e0f";
const HANDLE: &str = "sih_3f9a1c2e00000000000000000000000000000000000000000000000000000001";
const EVENT_ID: &str = "evt_000102030405060708090a0b0c0d0e0f";

fn store() -> DynamoDbAuthStore {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(Region::new("test-region-1"))
        .credentials_provider(Credentials::new(
            "test-access-key",
            "test-secret-key",
            None,
            None,
            "unit-test",
        ))
        .build();
    DynamoDbAuthStore::new(
        DynamoDbClient::from_conf(config),
        "auth".to_owned(),
        StorageHmacKey::new([0x24; 32]),
    )
}

fn event(action: AdminAction, session: Option<&str>) -> AdminEvent {
    AdminEvent {
        event_id: AdminEventId::parse(EVENT_ID).expect("event id"),
        at_unix: 1_234,
        action,
        user_id: UserId::parse(USER_ID).expect("user id"),
        session: session.map(|handle| SessionHandle::parse(handle).expect("handle")),
        actor: AdminActor::new("admin@example.test", Some("ticket 7".to_owned())).expect("actor"),
    }
}

fn attribute<'a>(
    values: Option<&'a HashMap<String, AttributeValue>>,
    name: &str,
) -> Option<&'a AttributeValue> {
    values.and_then(|values| values.get(name))
}

#[test]
fn revoke_transaction_is_owner_checked_final_and_audited() {
    let items = store()
        .revoke_session_transaction(&event(AdminAction::RevokeSession, Some(HANDLE)))
        .expect("transaction");
    assert_eq!(items.len(), 2);

    let update = items[0].update().expect("update");
    assert_eq!(
        update.key().get("pk"),
        Some(&av_s(format!("SESSION#{HANDLE}")))
    );
    let condition = update.condition_expression().expect("condition");
    assert!(condition.contains("user_id = :user"));
    assert!(condition.contains("attribute_not_exists(revoked_at_unix)"));
    let values = update.expression_attribute_values();
    assert_eq!(attribute(values, ":user"), Some(&av_s(USER_ID)));
    assert_eq!(attribute(values, ":at"), Some(&av_n(1_234)));
    assert_eq!(
        attribute(values, ":actor"),
        Some(&av_s("admin@example.test"))
    );

    let audit = items[1].put().expect("audit put");
    assert_eq!(
        audit.condition_expression(),
        Some("attribute_not_exists(pk)")
    );
    let item = audit.item();
    assert_eq!(item.get("pk"), Some(&av_s(format!("AUDIT#{USER_ID}"))));
    assert_eq!(
        item.get("sk"),
        Some(&av_s(format!("EVENT#00000000000000001234#{EVENT_ID}")))
    );
    assert_eq!(item.get("action"), Some(&av_s("revoke_session")));
    assert_eq!(item.get("session_handle"), Some(&av_s(HANDLE)));
    assert_eq!(item.get("actor_reason"), Some(&av_s("ticket 7")));
    // Nothing in the transaction deletes or expires data.
    assert!(items.iter().all(|item| item.delete().is_none()));
    assert!(item.get("ttl").is_none());
}

#[test]
fn disable_and_enable_transactions_require_the_opposite_state() {
    let store = store();
    let disable = store
        .set_user_disabled_transaction(&event(AdminAction::DisableUser, None))
        .expect("disable");
    let update = disable[0].update().expect("update");
    assert_eq!(
        update.key().get("pk"),
        Some(&av_s(format!("USERID#{USER_ID}")))
    );
    assert!(
        update
            .condition_expression()
            .expect("condition")
            .contains("disabled = :current")
    );
    let values = update.expression_attribute_values();
    assert_eq!(attribute(values, ":current"), Some(&av_bool(false)));
    assert_eq!(attribute(values, ":target"), Some(&av_bool(true)));
    assert!(update.update_expression().contains("disabled_by = :actor"));
    assert_eq!(
        disable[1].put().expect("audit").item().get("action"),
        Some(&av_s("disable_user"))
    );

    let enable = store
        .set_user_disabled_transaction(&event(AdminAction::EnableUser, None))
        .expect("enable");
    let update = enable[0].update().expect("update");
    let values = update.expression_attribute_values();
    assert_eq!(attribute(values, ":current"), Some(&av_bool(true)));
    assert_eq!(attribute(values, ":target"), Some(&av_bool(false)));
    assert!(
        update
            .update_expression()
            .contains("REMOVE disabled_at_unix, disabled_by")
    );
    // Re-enabling stamps the watermark that keeps older sessions invalid.
    assert!(
        update
            .update_expression()
            .contains("sessions_valid_after_unix = :at")
    );
    assert_eq!(attribute(values, ":at"), Some(&av_n(1_234)));
}

#[test]
fn mismatched_actions_are_rejected() {
    let store = store();
    assert!(
        store
            .revoke_session_transaction(&event(AdminAction::DisableUser, Some(HANDLE)))
            .is_err()
    );
    assert!(
        store
            .revoke_session_transaction(&event(AdminAction::RevokeSession, None))
            .is_err()
    );
    assert!(
        store
            .set_user_disabled_transaction(&event(AdminAction::RevokeSession, Some(HANDLE)))
            .is_err()
    );
}

#[test]
fn cursors_round_trip_and_stay_pinned_to_their_partition() {
    let key = HashMap::from([
        ("pk".to_owned(), av_s(format!("AUDIT#{USER_ID}"))),
        ("sk".to_owned(), av_s("EVENT#00000000000000001234#evt_x")),
    ]);
    let cursor = encode_cursor(Some(&key)).expect("encode").expect("cursor");
    assert_eq!(
        decode_cursor(Some(&cursor), Some(&format!("AUDIT#{USER_ID}"))).expect("decode"),
        Some(key)
    );
    // The same cursor cannot page another user's audit trail.
    assert!(decode_cursor(Some(&cursor), Some("AUDIT#usr_other")).is_err());
    assert_eq!(encode_cursor(None).expect("none"), None);
    assert_eq!(encode_cursor(Some(&HashMap::new())).expect("empty"), None);
    for garbage in ["bm8tbmV3bGluZQ", "____"] {
        let cursor = PageCursor::parse(garbage).expect("charset ok");
        assert!(decode_cursor(Some(&cursor), None).is_err());
    }
}

#[test]
fn stored_items_parse_into_admin_types() {
    let store = store();
    let event = event(AdminAction::RevokeSession, Some(HANDLE));
    let audit_item = store.audit_event_put(&event).expect("put").item().clone();
    let parsed = item_to_admin_event(&audit_item).expect("event parses");
    assert_eq!(parsed.event_id, event.event_id);
    assert_eq!(parsed.action, AdminAction::RevokeSession);
    assert_eq!(parsed.session, event.session);
    assert_eq!(parsed.actor.reason(), Some("ticket 7"));

    let profile = HashMap::from([
        ("entity_type".to_owned(), av_s("user_profile")),
        ("user_id".to_owned(), av_s(USER_ID)),
        ("email_normalized".to_owned(), av_s("user@example.test")),
        ("disabled".to_owned(), av_bool(true)),
        ("disabled_at_unix".to_owned(), av_n(1_234)),
        ("disabled_by".to_owned(), av_s("admin@example.test")),
    ]);
    let user = item_to_user_summary(&profile).expect("user parses");
    assert!(user.disabled);
    assert_eq!(user.disabled_by.as_deref(), Some("admin@example.test"));

    let session = HashMap::from([
        ("pk".to_owned(), av_s(format!("SESSION#{HANDLE}"))),
        ("entity_type".to_owned(), av_s("session")),
        ("user_id".to_owned(), av_s(USER_ID)),
        ("email_normalized".to_owned(), av_s("user@example.test")),
        ("created_at_unix".to_owned(), av_n(100)),
        ("expires_at_unix".to_owned(), av_n(200)),
    ]);
    let summary = item_to_session_summary(&session).expect("session parses");
    assert_eq!(summary.handle.as_str(), HANDLE);
    assert_eq!(summary.revoked_at_unix, None);

    // Wrong entity types never parse as the wrong thing.
    assert!(item_to_user_summary(&session).is_err());
    assert!(item_to_session_summary(&profile).is_err());
}

//! DynamoDB authentication transaction and storage parser tests.

use aws_sdk_dynamodb::config::{Credentials, Region};
use datadeft_magic_link_core::{
    LookupHmacKey, MagicLinkSelector, NormalizedEmail, selector_lookup_hmac,
};
use datadeft_magic_link_service::{
    AuthenticationAttemptId, CommitMagicLinkAuthentication, MagicLinkAuthenticationExpectation,
    MagicLinkAuthenticationUser, SessionId, UserId,
};

use super::items::av_bool;
use super::*;

const USER_ID: &str = "usr_000102030405060708090a0b0c0d0e0f";
const SESSION_ID: &str = "sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ATTEMPT_ID: &str = "aid_000102030405060708090a0b0c0d0e0f";
const VERIFIER_HASH: &str = "mlv_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

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
        .endpoint_url("http://127.0.0.1:9")
        .build();
    DynamoDbAuthStore::new(
        DynamoDbClient::from_conf(config),
        "test-auth-table".to_owned(),
        StorageHmacKey::new([0x31; 32]),
    )
}

fn command(user: MagicLinkAuthenticationUser) -> CommitMagicLinkAuthentication {
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let selector = MagicLinkSelector::parse("000102030405060708090a0b0c0d0e0f").expect("selector");
    CommitMagicLinkAuthentication {
        magic_link: MagicLinkAuthenticationExpectation {
            selector_lookup_hmac: selector_lookup_hmac(&lookup_key, &selector)
                .expect("selector lookup hmac"),
            email: NormalizedEmail::parse("atomic@example.test").expect("email"),
            expires_at_unix: 2_000,
            terms_version: "terms-v1".to_owned(),
            privacy_version: "privacy-v1".to_owned(),
            consented_at_unix: 900,
        },
        now_unix: 1_000,
        attempt_id: AuthenticationAttemptId::parse(ATTEMPT_ID).expect("attempt id"),
        user,
        session_id: SessionId::parse(SESSION_ID).expect("session id"),
        session_expires_at_unix: 3_000,
    }
}

fn user_id() -> UserId {
    UserId::parse(USER_ID).expect("user id")
}

fn item_with_candidate() -> HashMap<String, AttributeValue> {
    HashMap::from([
        ("entity_type".to_owned(), av_s("magic_link")),
        ("verifier_hash".to_owned(), av_s(VERIFIER_HASH)),
        ("email_normalized".to_owned(), av_s("atomic@example.test")),
        ("expires_at_unix".to_owned(), av_n(2_000)),
        ("terms_version".to_owned(), av_s("terms-v1")),
        ("privacy_version".to_owned(), av_s("privacy-v1")),
        ("consented_at_unix".to_owned(), av_n(900)),
    ])
}

fn item_with_user(disabled: AttributeValue) -> HashMap<String, AttributeValue> {
    HashMap::from([
        ("entity_type".to_owned(), av_s("user_profile")),
        ("user_id".to_owned(), av_s(USER_ID)),
        ("email_normalized".to_owned(), av_s("atomic@example.test")),
        ("disabled".to_owned(), disabled),
    ])
}

#[test]
fn authentication_candidate_parser_requires_canonical_verifier_hash() {
    let candidate = DynamoDbAuthStore::item_to_authentication_candidate(&item_with_candidate())
        .expect("candidate");
    assert_eq!(candidate.verifier_hash.as_storage_value(), VERIFIER_HASH);

    for malformed in [
        "mlv_000102030405060708090A0B0C0D0E0F101112131415161718191a1b1c1d1e1f",
        "bad_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "mlv_short",
    ] {
        let mut item = item_with_candidate();
        item.insert("verifier_hash".to_owned(), av_s(malformed));
        assert_eq!(
            DynamoDbAuthStore::item_to_authentication_candidate(&item).err(),
            Some(AwsAdapterError::Internal)
        );
    }
}

#[test]
fn authentication_user_parser_requires_boolean_disabled_and_exact_linkage() {
    let email = NormalizedEmail::parse("atomic@example.test").expect("email");
    assert!(
        !DynamoDbAuthStore::item_to_authentication_user(
            &item_with_user(av_bool(false)),
            &user_id(),
            &email,
        )
        .expect("enabled user")
        .disabled
    );

    for malformed in [
        item_with_user(av_s("false")),
        {
            let mut item = item_with_user(av_bool(false));
            item.remove("disabled");
            item
        },
        {
            let mut item = item_with_user(av_bool(false));
            item.insert(
                "user_id".to_owned(),
                av_s("usr_101112131415161718191a1b1c1d1e1f"),
            );
            item
        },
        {
            let mut item = item_with_user(av_bool(false));
            item.insert("email_normalized".to_owned(), av_s("other@example.test"));
            item
        },
    ] {
        assert_eq!(
            DynamoDbAuthStore::item_to_authentication_user(&malformed, &user_id(), &email),
            Err(AwsAdapterError::Internal)
        );
    }
}

#[test]
fn authentication_read_builders_are_strongly_consistent() {
    let store = store();
    for request in [
        store.authentication_get_item("ML#test".to_owned(), "CHALLENGE"),
        store.authentication_get_item("USER#test".to_owned(), "PROFILE"),
        store.authentication_get_item("USERID#test".to_owned(), "PROFILE"),
    ] {
        assert_eq!(request.as_input().get_consistent_read(), &Some(true));
    }
}

#[test]
fn session_read_builder_is_strongly_consistent() {
    // Session reads share the consistent-read builder with authentication.
    let request = store().authentication_get_item("SESSION#test".to_owned(), "SESSION");

    assert_eq!(request.as_input().get_consistent_read(), &Some(true));
}

#[test]
fn authentication_request_uses_attempt_id_as_client_request_token() {
    let store = store();
    let command = command(MagicLinkAuthenticationUser::Create { user_id: user_id() });
    let (request, _) = store
        .authentication_transaction_request(&command)
        .expect("request");
    assert_eq!(
        request.as_input().get_client_request_token().as_deref(),
        Some(ATTEMPT_ID)
    );
    assert_eq!(
        request
            .as_input()
            .get_transact_items()
            .as_ref()
            .map(Vec::len),
        Some(5)
    );
}

#[test]
fn existing_authentication_transaction_has_exact_order_and_bound_conditions() {
    let store = store();
    let command = command(MagicLinkAuthenticationUser::Existing { user_id: user_id() });
    let actions = store
        .build_authentication_transaction(&command)
        .expect("transaction");
    assert_eq!(actions.len(), 5);
    assert!(actions[0].update().is_some());
    assert!(actions[1].condition_check().is_some());
    assert!(actions[2].condition_check().is_some());
    assert!(actions[3].put().is_some());
    assert!(actions[4].put().is_some());

    let challenge = actions[0].update().expect("challenge update");
    let condition = challenge.condition_expression().expect("condition");
    for required in [
        "entity_type = :magic_link",
        "attribute_not_exists(consumed_at_unix)",
        "expires_at_unix = :expected_expiry",
        "expires_at_unix >= :now",
        "email_normalized = :expected_email",
        "terms_version = :expected_terms",
        "privacy_version = :expected_privacy",
        "consented_at_unix = :expected_consent",
        "consented_at_unix > :zero",
    ] {
        assert!(condition.contains(required), "missing condition {required}");
    }
    assert_eq!(challenge.update_expression(), "SET consumed_at_unix = :now");
    let values = challenge
        .expression_attribute_values()
        .expect("challenge values");
    assert!(!values.contains_key(":vh"));
    assert!(!values.values().any(|value| {
        value
            .as_s()
            .is_ok_and(|value| value == VERIFIER_HASH || value.starts_with("mlv1."))
    }));

    let email_condition = actions[1]
        .condition_check()
        .expect("email check")
        .condition_expression();
    assert!(email_condition.contains("entity_type = :email_lookup"));
    assert!(email_condition.contains("user_id = :expected_user"));
    let profile_condition = actions[2]
        .condition_check()
        .expect("profile check")
        .condition_expression();
    assert!(profile_condition.contains("disabled = :false"));
    assert!(!profile_condition.contains("terms_version"));
    assert!(!profile_condition.contains("privacy_version"));
    assert_eq!(command.attempt_id.as_str(), ATTEMPT_ID);
}

#[test]
fn create_authentication_transaction_derives_all_items_and_validity_expiry() {
    let store = store();
    let command = command(MagicLinkAuthenticationUser::Create { user_id: user_id() });
    let actions = store
        .build_authentication_transaction(&command)
        .expect("transaction");
    assert_eq!(actions.len(), 5);
    assert!(actions[0].update().is_some());
    assert!(actions[1].put().is_some());
    assert!(actions[2].put().is_some());
    assert!(actions[3].put().is_some());
    assert!(actions[4].put().is_some());

    let profile = actions[1].put().expect("profile put").item();
    assert_eq!(profile.get("disabled"), Some(&av_bool(false)));
    assert_eq!(profile.get("terms_version"), Some(&av_s("terms-v1")));
    assert_eq!(profile.get("privacy_version"), Some(&av_s("privacy-v1")));
    assert_eq!(profile.get("consented_at_unix"), Some(&av_n(900)));
    let session = actions[3].put().expect("session put").item();
    assert_eq!(
        session.get("created_at_unix"),
        Some(&av_n(command.now_unix))
    );
    assert_eq!(
        session.get("expires_at_unix"),
        Some(&av_n(command.session_expires_at_unix))
    );
    // Kept for the audit trail: no TTL deletion.
    assert_eq!(session.get("ttl"), None);
    let index = actions[4].put().expect("index put").item();
    assert_eq!(
        index.get("expires_at_unix"),
        Some(&av_n(command.session_expires_at_unix))
    );
    assert_eq!(index.get("ttl"), None);
    for action in &actions {
        if let Some(put) = action.put() {
            assert!(!put.item().values().any(|value| {
                value
                    .as_s()
                    .is_ok_and(|value| value == VERIFIER_HASH || value.starts_with("mlv1."))
            }));
        }
    }
}

#[test]
fn authentication_transaction_rejects_expiry_before_creation_time() {
    let store = store();
    let mut command = command(MagicLinkAuthenticationUser::Create { user_id: user_id() });
    command.session_expires_at_unix = command.now_unix - 1;
    assert_eq!(
        store.build_authentication_transaction(&command),
        Err(AwsAdapterError::Internal)
    );
}

#[test]
fn cleanup_grace_defaults_and_is_configurable() {
    assert_eq!(store().cleanup_grace_secs, DEFAULT_CLEANUP_GRACE_SECS);
    assert_eq!(DEFAULT_CLEANUP_GRACE_SECS, 24 * 60 * 60);
    let tuned = store().with_cleanup_grace_secs(0);
    assert_eq!(tuned.cleanup_grace_secs, 0);
}

/// The action count the error classifier receives matches the transaction:
/// five actions, or six for a create while a previous storage key is set.
#[test]
fn authentication_request_reports_its_action_count() {
    let create = command(MagicLinkAuthenticationUser::Create { user_id: user_id() });
    let existing = command(MagicLinkAuthenticationUser::Existing { user_id: user_id() });
    let plain = store();
    let rotating = store().with_previous_storage_hmac_key(StorageHmacKey::new([0x32; 32]));
    for (store, command, expected) in [
        (&plain, &create, 5),
        (&plain, &existing, 5),
        (&rotating, &create, 6),
        (&rotating, &existing, 5),
    ] {
        let (request, count) = store
            .authentication_transaction_request(command)
            .expect("request");
        assert_eq!(count, expected);
        assert_eq!(
            request
                .as_input()
                .get_transact_items()
                .as_ref()
                .map(Vec::len),
            Some(expected)
        );
    }
}

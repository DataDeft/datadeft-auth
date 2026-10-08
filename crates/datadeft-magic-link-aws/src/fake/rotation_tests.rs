//! Lookup- and storage-key rotation on the fake store.

//! Fake store integration tests.

use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_core::{LookupHmacKey, NormalizedEmail};
use datadeft_magic_link_service::{MagicLinkAuthenticationRepository, SessionRepository, UserId};

use super::test_support::*;
use super::*;

#[tokio::test]
async fn lookup_key_rotation_keeps_in_flight_links_usable() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let mut rng = CountingRng::starting_at(0);
    let old_key = LookupHmacKey::new([0x42; 32]);
    let new_key = LookupHmacKey::new([0x43; 32]);

    // A link minted under the old key fails once the key changes...
    assert!(
        login_with_keys(&store, &mut rng, &old_key, &new_key, None)
            .await
            .is_err()
    );
    // ...and succeeds when the old key is configured as previous.
    login_with_keys(&store, &mut rng, &old_key, &new_key, Some(&old_key))
        .await
        .expect("in-flight link confirms during rotation");
    // New links use the new key and need no fallback.
    login_with_keys(&store, &mut rng, &new_key, &new_key, Some(&old_key))
        .await
        .expect("new link confirms");
    assert_eq!(store.user_count().expect("users"), 1);
}

#[tokio::test]
async fn storage_key_rotation_keeps_users_and_sessions() {
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let before = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let first = login_with_keys(&before, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("first login");
    let session_id = first.authentication().session_id().clone();

    let after = before.sharing_data_with_keys(
        StorageHmacKey::new([0x25; 32]),
        Some(StorageHmacKey::new([0x24; 32])),
    );

    // The pre-rotation session is still found and can be revoked.
    assert!(
        after
            .find_session(&session_id, 1_000)
            .await
            .expect("find")
            .is_some()
    );

    // Logging in again finds the same account instead of creating a second.
    login_with_keys(&after, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("second login");
    assert_eq!(after.user_count().expect("users"), 1);

    after
        .revoke_session(&session_id, 1_000)
        .await
        .expect("revoke");
    assert!(
        after
            .find_session(&session_id, 1_000)
            .await
            .expect("find")
            .is_none()
    );

    // Login migrated the lookup, so the store works without the old key.
    let without_previous = after.sharing_data_with_keys(StorageHmacKey::new([0x25; 32]), None);
    let email = NormalizedEmail::parse("user@example.com").expect("email");
    assert!(
        without_previous
            .find_user_for_authentication(&email)
            .await
            .expect("find")
            .is_some()
    );
}

#[tokio::test]
async fn rekey_migrates_users_who_did_not_log_in_during_rotation() {
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let before = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    login_with_keys(&before, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("login");

    let after = before.sharing_data_with_keys(
        StorageHmacKey::new([0x25; 32]),
        Some(StorageHmacKey::new([0x24; 32])),
    );
    assert_eq!(after.rekey_email_lookups().expect("rekey"), 1);
    assert_eq!(after.rekey_email_lookups().expect("rekey is idempotent"), 0);

    // With the previous key dropped, the account is still found.
    let dropped = after.sharing_data_with_keys(StorageHmacKey::new([0x25; 32]), None);
    login_with_keys(&dropped, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("login after previous key dropped");
    assert_eq!(dropped.user_count().expect("users"), 1);
}

#[tokio::test]
async fn storage_key_change_without_previous_key_splits_accounts() {
    // The failure mode the previous-key fallback prevents.
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let before = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    login_with_keys(&before, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("first login");
    let unrotated = before.sharing_data_with_keys(StorageHmacKey::new([0x25; 32]), None);
    login_with_keys(&unrotated, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("second login");
    assert_eq!(unrotated.user_count().expect("users"), 2);
}

#[tokio::test]
async fn fake_user_status_fails_closed_for_unknown_users() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let unknown = UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id");
    assert!(
        !store
            .is_session_owner_active(&unknown, 0)
            .await
            .expect("status")
    );
}

//! Storage lookup HMAC pin tests.
//!
//! These vectors pin the exact keyed-lookup framing
//! (`domain || 0x00 || prefix || 0x00 || value` → `{prefix}_{hex}`) and the
//! `magic-link-aws-storage-v1` domain string. Changing either silently
//! re-keys every stored partition key, so any refactor of the mechanism must
//! keep these values byte-identical.

use super::*;

#[test]
fn storage_hmac_vectors_are_pinned() {
    let key = StorageHmacKey::new([0x11; STORAGE_HMAC_KEY_BYTES]);

    let vectors = [
        key.hmac(SESSION_LOOKUP_HMAC_PREFIX, "sid_000102030405060708090a0b")
            .expect("session hmac"),
        key.hmac(EMAIL_LOOKUP_HMAC_PREFIX, "user@example.com")
            .expect("email hmac"),
        key.hmac(RATE_LOOKUP_HMAC_PREFIX, "req:email:user@example.com:0")
            .expect("rate hmac"),
    ];
    assert_eq!(
        vectors,
        [
            "sih_87e7f48488fa0a349a177fc19ab47a99cce9e36171c10270856df31f7ed52807",
            "emh_48f078f217f580d763c2edf13fec18bf2ffc3490100ecc51450090f196a23bf5",
            "rlh_1bd9b30bdc96ac134e8e1ee7f593eddcd0144cb506c22d176cf22e4245464574",
        ]
    );
}

/// Repository-only vectors are supplied at runtime, so packaged crate tests do
/// not depend on files outside the crate. No production API or Rust logic added.
#[test]
#[ignore = "repository vectors: mise run compatibility-test"]
fn shared_storage_and_email_vectors() {
    use datadeft_magic_link_service::NormalizedEmail;
    let directory = std::path::PathBuf::from(
        std::env::var("DD_AUTH_COMPATIBILITY_DIR").expect("compatibility fixture directory"),
    );
    let storage =
        std::fs::read_to_string(directory.join("storage_hmac.tsv")).expect("storage vectors");
    let mut count = 0;
    for line in storage.lines().filter(|line| !line.starts_with('#')) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 4);
        let key = StorageHmacKey::from_slice(&hex::decode(columns[0]).expect("key hex"))
            .expect("synthetic key");
        let prefix =
            String::from_utf8(hex::decode(columns[1]).expect("prefix hex")).expect("prefix");
        let value = String::from_utf8(hex::decode(columns[2]).expect("value hex")).expect("value");
        assert_eq!(key.hmac(&prefix, &value).expect("hmac"), columns[3]);
        count += 1;
    }
    assert!(count >= 6);

    let emails = std::fs::read_to_string(directory.join("email.tsv")).expect("email vectors");
    let mut count = 0;
    for line in emails.lines().filter(|line| !line.starts_with('#')) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 3);
        let input = String::from_utf8(hex::decode(columns[0]).expect("input hex")).expect("input");
        match columns[1] {
            "-" => assert!(NormalizedEmail::normalize(&input).is_err()),
            expected => {
                let expected = String::from_utf8(hex::decode(expected).expect("expected hex"))
                    .expect("expected");
                assert_eq!(
                    NormalizedEmail::normalize(&input)
                        .expect("normalize")
                        .as_str(),
                    expected
                );
            }
        }
        let stored = NormalizedEmail::from_normalized(&input);
        assert_eq!(stored.is_ok(), columns[2] == "true");
        if let Ok(stored) = stored {
            assert_eq!(stored.as_str(), input);
        }
        count += 1;
    }
    assert!(count >= 50);
}

#[test]
fn storage_hmac_key_debug_is_redacted() {
    let key = StorageHmacKey::new([0x2A; STORAGE_HMAC_KEY_BYTES]);
    let debug = format!("{key:?}");
    assert_eq!(debug, "StorageHmacKey(..)");
    assert!(!debug.contains("2a"));
}

#[test]
fn a_previous_key_equal_to_the_current_one_is_dropped() {
    let same = StorageHmacKeys::new(
        StorageHmacKey::new([0x11; STORAGE_HMAC_KEY_BYTES]),
        Some(StorageHmacKey::new([0x11; STORAGE_HMAC_KEY_BYTES])),
    );
    assert!(same.previous().is_none());
    assert_eq!(same.all().count(), 1);

    let rotated = StorageHmacKeys::new(
        StorageHmacKey::new([0x11; STORAGE_HMAC_KEY_BYTES]),
        Some(StorageHmacKey::new([0x22; STORAGE_HMAC_KEY_BYTES])),
    );
    assert!(rotated.previous().is_some());
    assert_eq!(rotated.all().count(), 2);
}

#[cfg(feature = "aws")]
#[test]
fn setting_a_previous_key_equal_to_the_current_one_is_a_no_op() {
    let mut keys = StorageHmacKeys::new(StorageHmacKey::new([0x11; STORAGE_HMAC_KEY_BYTES]), None);
    keys.set_previous(StorageHmacKey::new([0x11; STORAGE_HMAC_KEY_BYTES]));
    assert!(keys.previous().is_none());
    keys.set_previous(StorageHmacKey::new([0x22; STORAGE_HMAC_KEY_BYTES]));
    assert!(keys.previous().is_some());
}

#[test]
fn lifetime_counter_ids_do_not_depend_on_the_storage_key_and_are_pinned() {
    let key = datadeft_magic_link_service::RateLimitKey::parse("pow:budget:abc").expect("key");
    let id = lifetime_counter_id(&key);
    // Pinned: a change would orphan every live budget counter. Computed
    // outside Rust: sha256(domain || 0x00 || key).
    assert_eq!(
        id,
        "lt_952cdd8fe2cbc9ac3c77dfe0e178850e9d4bc329ab5d930e918c71f29c469c8a"
    );
    let other = datadeft_magic_link_service::RateLimitKey::parse("pow:budget:abd").expect("key");
    assert_ne!(id, lifetime_counter_id(&other));
}

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

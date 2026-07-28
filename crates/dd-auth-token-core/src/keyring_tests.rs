//! Key material tests.

use super::*;

/// Local purposes so machinery tests do not depend on any product key policy.
#[derive(Debug)]
enum TestCookieA {}

impl KeyPurpose for TestCookieA {
    const HKDF_INFO: &'static [u8] = b"auth/test-a-v1";
    const TOKEN_TYPE: &'static str = "test-a-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 600;
}

#[derive(Debug)]
enum TestCookieB {}

impl KeyPurpose for TestCookieB {
    const HKDF_INFO: &'static [u8] = b"auth/test-b-v1";
    const TOKEN_TYPE: &'static str = "test-b-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 600;
}

fn kid(value: &str) -> KeyId {
    KeyId::parse(value).expect("kid parses")
}

#[test]
fn root_secret_debug_does_not_contain_key_bytes() {
    let secret = RootSecret::new([0x2A; KEY_BYTES]);
    let debug = format!("{secret:?}");

    assert_eq!(debug, "RootSecret(..)");
    assert!(!debug.contains("2a"), "hex key bytes must not appear");
    assert!(!debug.contains("42"), "decimal key bytes must not appear");
    assert!(!debug.contains('*'), "ASCII key bytes must not appear");
    assert!(!debug.contains('['), "raw array debug must not appear");
}

#[test]
fn branca_key_debug_does_not_contain_key_bytes() {
    let key = BrancaKey::<()>::new([0x2A; KEY_BYTES]);
    let debug = format!("{key:?}");

    assert_eq!(debug, "BrancaKey(..)");
    assert!(!debug.contains("2a"), "hex key bytes must not appear");
    assert!(!debug.contains("42"), "decimal key bytes must not appear");
    assert!(!debug.contains('*'), "ASCII key bytes must not appear");
    assert!(!debug.contains('['), "raw array debug must not appear");
}

#[test]
fn root_secret_derives_deterministic_kid_and_purpose_separated_keys() {
    let root = RootSecret::new([0x11; KEY_BYTES]);

    let a_k1 = root
        .derive_key::<TestCookieA>(&kid("k1"))
        .expect("derive purpose A");
    let a_k1_again = root
        .derive_key::<TestCookieA>(&kid("k1"))
        .expect("derive purpose A again");
    let a_k2 = root
        .derive_key::<TestCookieA>(&kid("k2"))
        .expect("derive purpose A kid2");
    let b_k1 = root
        .derive_key::<TestCookieB>(&kid("k1"))
        .expect("derive purpose B");

    assert_eq!(
        a_k1.as_bytes(),
        a_k1_again.as_bytes(),
        "same root+purpose+kid is deterministic"
    );
    assert_ne!(
        a_k1.as_bytes(),
        a_k2.as_bytes(),
        "different kid separates keys (rotation is cryptographic, not a label)"
    );
    assert_ne!(
        a_k1.as_bytes(),
        b_k1.as_bytes(),
        "different purpose info separates keys"
    );
    assert_ne!(
        a_k1.as_bytes(),
        root.as_bytes(),
        "derived key is not raw root material"
    );
}

#[test]
fn hkdf_vector_is_pinned() {
    // HKDF-SHA256 with salt=None, IKM=[0x11; 32], L=32,
    // info = HKDF_INFO || 0x00 || kid. This vector pins the exact info framing
    // (purpose + kid) and output length; changing the framing invalidates every
    // token minted under previously derived keys. Downstream crates that own a
    // purpose pin their own product vectors on top of this one.
    let root = RootSecret::new([0x11; KEY_BYTES]);
    let derived = root
        .derive_key::<TestCookieA>(&kid("test-active"))
        .expect("derive test key");

    assert_eq!(
        hex::encode(derived.as_bytes()),
        "4776cde807f361cd1fa77404521c54941e4404750be9e9abdbc694d8df562ad9"
    );
}

#[test]
fn typed_keyring_mints_with_active_and_verifies_with_previous() {
    let root = RootSecret::new([0x33; KEY_BYTES]);
    let active = root
        .derive_key::<TestCookieA>(&kid("test-active"))
        .expect("active key");
    let previous = root
        .derive_key::<TestCookieA>(&kid("test-prev"))
        .expect("previous key");

    let ring = KeyRing::<TestCookieA>::new(vec![
        KeySlot::active_with_windows(
            kid("test-active"),
            active,
            10,
            10 + TestCookieA::MAX_ABSOLUTE_AGE_SECS,
        ),
        KeySlot::verify_only(kid("test-prev"), previous, 100),
    ])
    .expect("ring builds");

    assert_eq!(
        ring.minting_key_at(10)
            .expect("mint at boundary")
            .kid()
            .as_str(),
        "test-active"
    );
    assert_eq!(
        ring.verification_key_at(&kid("test-prev"), 100)
            .expect("previous verifies at boundary")
            .status(),
        KeyStatus::VerifyOnly
    );
    assert_eq!(ring.minting_key_at(11).unwrap_err(), TokenError::KeyExpired);
    assert_eq!(
        ring.verification_key_at(&kid("test-prev"), 101)
            .unwrap_err(),
        TokenError::KeyExpired
    );
}

#[test]
fn keyring_rejects_duplicate_or_missing_active_keys() {
    let root = RootSecret::new([0x44; KEY_BYTES]);
    let active_dup = root
        .derive_key::<TestCookieA>(&kid("test-active"))
        .expect("active key");
    let previous_dup = root
        .derive_key::<TestCookieA>(&kid("test-active"))
        .expect("previous key");
    let previous_only = root
        .derive_key::<TestCookieA>(&kid("test-old"))
        .expect("previous key");

    let dup = KeyRing::<TestCookieA>::new(vec![
        KeySlot::active(kid("test-active"), active_dup),
        KeySlot::verify_only(kid("test-active"), previous_dup, u64::MAX),
    ])
    .unwrap_err();
    assert_eq!(dup, TokenError::KeyringMisconfigured);

    let no_active = KeyRing::<TestCookieA>::new(vec![KeySlot::verify_only(
        kid("test-old"),
        previous_only,
        u64::MAX,
    )])
    .unwrap_err();
    assert_eq!(no_active, TokenError::KeyringMisconfigured);
}

#[test]
fn keyring_rejects_active_verify_window_shorter_than_absolute_lifetime() {
    let root = RootSecret::new([0x46; KEY_BYTES]);
    let key = root
        .derive_key::<TestCookieA>(&kid("test-active"))
        .expect("active key");

    let err = KeyRing::<TestCookieA>::new(vec![KeySlot::active_with_windows(
        kid("test-active"),
        key,
        100,
        100 + TestCookieA::MAX_ABSOLUTE_AGE_SECS - 1,
    )])
    .unwrap_err();

    assert_eq!(err, TokenError::KeyringMisconfigured);
}

#[test]
fn keyring_rejects_active_mint_window_after_verify_window() {
    let root = RootSecret::new([0x45; KEY_BYTES]);
    let key = root
        .derive_key::<TestCookieA>(&kid("test-active"))
        .expect("active key");

    let err = KeyRing::<TestCookieA>::new(vec![KeySlot::active_with_windows(
        kid("test-active"),
        key,
        100,
        50,
    )])
    .unwrap_err();

    assert_eq!(err, TokenError::KeyringMisconfigured);
}

#[test]
fn key_id_debug_redacts_attacker_input() {
    let id = kid("attacker-controlled");
    let debug = format!("{id:?}");
    assert_eq!(debug, "KeyId(..)");
    assert!(!debug.contains("attacker-controlled"));
}

#[test]
fn retired_keys_are_absent_and_return_unknown_key() {
    // There is intentionally no KeyStatus::Retired. Once a key should no
    // longer verify, remove the slot; holding retired material in memory is
    // needless liability.
    let root = RootSecret::new([0x55; KEY_BYTES]);
    let active = root
        .derive_key::<TestCookieA>(&kid("test-active"))
        .expect("active key");
    let ring = KeyRing::<TestCookieA>::new(vec![KeySlot::active(kid("test-active"), active)])
        .expect("ring builds");

    assert_eq!(
        ring.verification_key_at(&kid("removed-old-key"), 0)
            .unwrap_err(),
        TokenError::UnknownKey
    );
}

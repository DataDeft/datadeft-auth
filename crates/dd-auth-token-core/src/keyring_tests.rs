//! Key material tests.

use super::*;

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

    let session_a = root
        .derive_key::<SessionCookie>(&kid("k1"))
        .expect("derive session");
    let session_a2 = root
        .derive_key::<SessionCookie>(&kid("k1"))
        .expect("derive session again");
    let session_k2 = root
        .derive_key::<SessionCookie>(&kid("k2"))
        .expect("derive session kid2");
    let pow = root
        .derive_key::<PowCookie>(&kid("k1"))
        .expect("derive pow");
    let flow = root
        .derive_key::<MagicLinkFlowCookie>(&kid("k1"))
        .expect("derive flow");

    assert_eq!(
        session_a.as_bytes(),
        session_a2.as_bytes(),
        "same root+purpose+kid is deterministic"
    );
    assert_ne!(
        session_a.as_bytes(),
        session_k2.as_bytes(),
        "different kid separates keys (rotation is cryptographic, not a label)"
    );
    assert_ne!(
        session_a.as_bytes(),
        pow.as_bytes(),
        "different purpose info separates keys"
    );
    assert_ne!(
        session_a.as_bytes(),
        flow.as_bytes(),
        "flow and session purposes must use independent keys"
    );
    assert_ne!(
        pow.as_bytes(),
        flow.as_bytes(),
        "flow and PoW purposes must use independent keys"
    );
    assert_ne!(
        session_a.as_bytes(),
        root.as_bytes(),
        "derived key is not raw root material"
    );
}

#[test]
fn hkdf_info_strings_are_versioned_constants() {
    assert_eq!(HKDF_INFO_SESSION_COOKIE_V1, b"auth/session-v1");
    assert_eq!(HKDF_INFO_POW_COOKIE_V1, b"auth/pow-v1");
    assert_eq!(
        HKDF_INFO_MAGIC_LINK_FLOW_COOKIE_V1,
        b"auth/magic-link-flow-v1"
    );
    assert_eq!(SessionCookie::HKDF_INFO, HKDF_INFO_SESSION_COOKIE_V1);
    assert_eq!(PowCookie::HKDF_INFO, HKDF_INFO_POW_COOKIE_V1);
    assert_eq!(
        MagicLinkFlowCookie::HKDF_INFO,
        HKDF_INFO_MAGIC_LINK_FLOW_COOKIE_V1
    );
    assert_eq!(TOKEN_TYPE_SESSION_COOKIE_V1, "session-v1");
    assert_eq!(TOKEN_TYPE_POW_COOKIE_V1, "pow-v1");
    assert_eq!(TOKEN_TYPE_MAGIC_LINK_FLOW_COOKIE_V1, "ml-flow-v1");
    assert_eq!(SessionCookie::TOKEN_TYPE, TOKEN_TYPE_SESSION_COOKIE_V1);
    assert_eq!(PowCookie::TOKEN_TYPE, TOKEN_TYPE_POW_COOKIE_V1);
    assert_eq!(
        MagicLinkFlowCookie::TOKEN_TYPE,
        TOKEN_TYPE_MAGIC_LINK_FLOW_COOKIE_V1
    );
    assert_eq!(SessionCookie::MAX_BODY_BYTES, 128);
    assert_eq!(PowCookie::MAX_BODY_BYTES, 128);
    assert_eq!(MagicLinkFlowCookie::MAX_BODY_BYTES, 256);
    assert_eq!(SessionCookie::MAX_ABSOLUTE_AGE_SECS, 30 * 24 * 60 * 60);
    assert_eq!(PowCookie::MAX_ABSOLUTE_AGE_SECS, 10 * 60);
    assert_eq!(MagicLinkFlowCookie::MAX_ABSOLUTE_AGE_SECS, 5 * 60);
}

#[test]
fn hkdf_vectors_are_pinned() {
    // HKDF-SHA256 with salt=None, IKM=[0x11; 32], L=32,
    // info = HKDF_INFO || 0x00 || kid. These vectors pin the exact info framing
    // (purpose + kid) and output length; changing any of them invalidates every
    // token minted under the previous derived key.
    let root = RootSecret::new([0x11; KEY_BYTES]);
    let session = root
        .derive_key::<SessionCookie>(&kid("session-active"))
        .expect("derive session");
    let pow = root
        .derive_key::<PowCookie>(&kid("pow-active"))
        .expect("derive pow");
    let flow = root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-active"))
        .expect("derive flow");

    assert_eq!(
        hex::encode(session.as_bytes()),
        "eda74d6ba28134ffe9c380e3a14729aa1fa4474dfbf63014a8b82e0325e4b10b"
    );
    assert_eq!(
        hex::encode(pow.as_bytes()),
        "4aa0804a52c9437f12e0087883a0f0aa8ef319bea122d3402399f0b3d60d96f6"
    );
    assert_eq!(
        hex::encode(flow.as_bytes()),
        "beb04add958a76123ba0d68f4a0294fae6afaaa918652871e78c45db00ab4746"
    );
}

fn kid(value: &str) -> KeyId {
    KeyId::parse(value).expect("kid parses")
}

#[test]
fn typed_keyring_mints_with_active_and_verifies_with_previous() {
    let root = RootSecret::new([0x33; KEY_BYTES]);
    let active = root
        .derive_key::<SessionCookie>(&kid("session-active"))
        .expect("active key");
    let previous = root
        .derive_key::<SessionCookie>(&kid("session-prev"))
        .expect("previous key");

    let ring = KeyRing::<SessionCookie>::new(
        kid("session-active"),
        vec![
            KeySlot::active_with_windows(
                kid("session-active"),
                active,
                10,
                10 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
            ),
            KeySlot::verify_only(kid("session-prev"), previous, 100),
        ],
    )
    .expect("ring builds");

    assert_eq!(
        ring.minting_key_at(10)
            .expect("mint at boundary")
            .kid()
            .as_str(),
        "session-active"
    );
    assert_eq!(
        ring.verification_key_at(&kid("session-prev"), 100)
            .expect("previous verifies at boundary")
            .status(),
        KeyStatus::VerifyOnly
    );
    assert_eq!(ring.minting_key_at(11).unwrap_err(), TokenError::KeyExpired);
    assert_eq!(
        ring.verification_key_at(&kid("session-prev"), 101)
            .unwrap_err(),
        TokenError::KeyExpired
    );
}

#[test]
fn keyring_rejects_duplicate_or_missing_active_keys() {
    let root = RootSecret::new([0x44; KEY_BYTES]);
    let active_dup = root
        .derive_key::<PowCookie>(&kid("pow-active"))
        .expect("active key");
    let previous_dup = root
        .derive_key::<PowCookie>(&kid("pow-active"))
        .expect("previous key");
    let previous_only = root
        .derive_key::<PowCookie>(&kid("pow-old"))
        .expect("previous key");

    let dup = KeyRing::<PowCookie>::new(
        kid("pow-active"),
        vec![
            KeySlot::active(kid("pow-active"), active_dup),
            KeySlot::verify_only(kid("pow-active"), previous_dup, u64::MAX),
        ],
    )
    .unwrap_err();
    assert_eq!(dup, TokenError::KeyringMisconfigured);

    let no_active = KeyRing::<PowCookie>::new(
        kid("pow-active"),
        vec![KeySlot::verify_only(
            kid("pow-old"),
            previous_only,
            u64::MAX,
        )],
    )
    .unwrap_err();
    assert_eq!(no_active, TokenError::KeyringMisconfigured);
}

#[test]
fn keyring_rejects_active_verify_window_shorter_than_absolute_lifetime() {
    let root = RootSecret::new([0x46; KEY_BYTES]);
    let key = root
        .derive_key::<SessionCookie>(&kid("session-active"))
        .expect("active key");

    let err = KeyRing::<SessionCookie>::new(
        kid("session-active"),
        vec![KeySlot::active_with_windows(
            kid("session-active"),
            key,
            100,
            100 + SessionCookie::MAX_ABSOLUTE_AGE_SECS - 1,
        )],
    )
    .unwrap_err();

    assert_eq!(err, TokenError::KeyringMisconfigured);
}

#[test]
fn keyring_rejects_active_mint_window_after_verify_window() {
    let root = RootSecret::new([0x45; KEY_BYTES]);
    let key = root
        .derive_key::<SessionCookie>(&kid("session-active"))
        .expect("active key");

    let err = KeyRing::<SessionCookie>::new(
        kid("session-active"),
        vec![KeySlot::active_with_windows(
            kid("session-active"),
            key,
            100,
            50,
        )],
    )
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
        .derive_key::<SessionCookie>(&kid("session-active"))
        .expect("active key");
    let ring = KeyRing::<SessionCookie>::new(
        kid("session-active"),
        vec![KeySlot::active(kid("session-active"), active)],
    )
    .expect("ring builds");

    assert_eq!(
        ring.verification_key_at(&kid("removed-old-key"), 0)
            .unwrap_err(),
        TokenError::UnknownKey
    );
}

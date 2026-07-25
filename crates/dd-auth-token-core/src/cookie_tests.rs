//! Cookie wrapper tests.

use super::*;
use crate::branca::{self, encode_with_nonce};
use crate::keyring::{KeyRing, KeySlot, RootSecret, SessionCookie};

fn ring_and_value() -> (KeyRing<SessionCookie>, String) {
    let root = RootSecret::new([0x66; crate::keyring::KEY_BYTES]);
    let key = root.derive_key::<SessionCookie>().expect("derive key");
    let token = encode_with_nonce(
        b"payload",
        key.as_bytes(),
        &[0x77; branca::NONCE_BYTES],
        123,
    )
    .expect("token");
    let ring = KeyRing::<SessionCookie>::new(
        crate::keyring::KeyId::parse("active").expect("kid"),
        vec![KeySlot::active(
            crate::keyring::KeyId::parse("active").expect("kid"),
            key,
        )],
    )
    .expect("ring");
    (ring, format!("v1.active.{token}"))
}

#[test]
fn wrapper_validates_kid_before_lookup() {
    for bad in [
        "v1..token",
        "v1.bad*kid.token",
        "v1.has.dot.token.more",
        &format!("v1.{}.token", "x".repeat(65)),
    ] {
        assert_eq!(
            parse_cookie_wrapper(bad).unwrap_err(),
            TokenError::InvalidToken
        );
    }
}

#[test]
fn wrapper_debug_redacts_kid_and_token() {
    let parts = parse_cookie_wrapper("v1.attacker-token-id.abc123").expect("parts");
    let debug = format!("{parts:?}");
    assert!(debug.contains("KeyId(..)"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("attacker-token-id"));
    assert!(!debug.contains("abc123"));
}

#[test]
fn cookie_validation_maps_malformed_unknown_and_bad_mac_to_invalid_token() {
    let (ring, value) = ring_and_value();

    let (_, verified) = decrypt_wrapped_token(&value, &ring, 0).expect("valid");
    assert_eq!(verified.payload, b"payload");

    assert_eq!(
        decrypt_wrapped_token("not-a-cookie", &ring, 0).unwrap_err(),
        TokenError::InvalidToken
    );

    let unknown = value.replacen("active", "missing", 1);
    assert_eq!(
        decrypt_wrapped_token(&unknown, &ring, 0).unwrap_err(),
        TokenError::InvalidToken
    );

    let mut bad_mac = value.clone().into_bytes();
    let last = bad_mac.len() - 1;
    bad_mac[last] = if bad_mac[last] == b'0' { b'1' } else { b'0' };
    let bad_mac = String::from_utf8(bad_mac).expect("utf8");
    assert_eq!(
        decrypt_wrapped_token(&bad_mac, &ring, 0).unwrap_err(),
        TokenError::InvalidToken
    );
}

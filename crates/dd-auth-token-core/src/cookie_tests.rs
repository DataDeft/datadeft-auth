//! Cookie wrapper tests.

use super::*;
use crate::branca::{self, encode_with_nonce};
use crate::keyring::{KeyId, KeyRing, KeySlot, PowCookie, RootSecret, SessionCookie};
use rand_core::{CryptoRng, RngCore};

struct FixedNonceRng([u8; branca::NONCE_BYTES]);

impl RngCore for FixedNonceRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(dest.len(), self.0.len());
        dest.copy_from_slice(&self.0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedNonceRng {}

fn kid(value: &str) -> KeyId {
    KeyId::parse(value).expect("kid parses")
}

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

#[test]
fn bound_cookie_round_trips_body_and_binds_kid() {
    let root = RootSecret::new([0x88; crate::keyring::KEY_BYTES]);
    let key = root.derive_key::<SessionCookie>().expect("derive key");
    let ring =
        KeyRing::<SessionCookie>::new(kid("active"), vec![KeySlot::active(kid("active"), key)])
            .expect("ring");
    let mut rng = FixedNonceRng([0x99; branca::NONCE_BYTES]);

    let value = mint_bound_cookie::<SessionCookie, _>(b"session-body", &ring, &mut rng, 456, 0)
        .expect("mint");
    assert!(value.starts_with("v1.active."));

    let verified = parse_bound_cookie::<SessionCookie>(&value, &ring, 0).expect("parse");
    assert_eq!(verified.kid().as_str(), "active");
    assert_eq!(verified.timestamp(), 456);
    assert_eq!(verified.body(), b"session-body");
    assert_eq!(verified.jti().as_bytes(), &[0x99; branca::NONCE_BYTES]);

    let debug = format!("{verified:?}");
    assert!(!debug.contains("session-body"));
    assert!(!debug.contains("active"));
}

#[test]
fn encrypted_typ_must_match_expected_purpose() {
    let root = RootSecret::new([0x89; crate::keyring::KEY_BYTES]);
    let key = root.derive_key::<SessionCookie>().expect("derive key");
    let token = encode_with_nonce(
        &serde_json::to_vec(&BoundCookiePayload {
            v: 1,
            typ: PowCookie::TOKEN_TYPE.to_owned(),
            kid: "active".to_owned(),
            body: b"body".to_vec(),
        })
        .expect("json"),
        key.as_bytes(),
        &[0x9A; branca::NONCE_BYTES],
        1,
    )
    .expect("token");
    let ring =
        KeyRing::<SessionCookie>::new(kid("active"), vec![KeySlot::active(kid("active"), key)])
            .expect("ring");

    assert_eq!(
        parse_bound_cookie::<SessionCookie>(&format!("v1.active.{token}"), &ring, 0).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn encrypted_kid_must_match_wrapper_kid() {
    let root = RootSecret::new([0x8A; crate::keyring::KEY_BYTES]);
    let key = root.derive_key::<SessionCookie>().expect("derive key");
    let token = encode_with_nonce(
        &serde_json::to_vec(&BoundCookiePayload {
            v: 1,
            typ: SessionCookie::TOKEN_TYPE.to_owned(),
            kid: "inner-other".to_owned(),
            body: b"body".to_vec(),
        })
        .expect("json"),
        key.as_bytes(),
        &[0x9B; branca::NONCE_BYTES],
        1,
    )
    .expect("token");
    let ring =
        KeyRing::<SessionCookie>::new(kid("outer"), vec![KeySlot::active(kid("outer"), key)])
            .expect("ring");

    assert_eq!(
        parse_bound_cookie::<SessionCookie>(&format!("v1.outer.{token}"), &ring, 0).unwrap_err(),
        TokenError::InvalidToken
    );
}

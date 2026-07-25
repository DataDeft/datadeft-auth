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

fn session_ring(root_byte: u8, kid_str: &str) -> KeyRing<SessionCookie> {
    let root = RootSecret::new([root_byte; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<SessionCookie>(&kid(kid_str))
        .expect("derive key");
    KeyRing::<SessionCookie>::new(kid(kid_str), vec![KeySlot::active(kid(kid_str), key)])
        .expect("ring")
}

/// A raw (non-bound) branca token wrapped as `v1.active.{token}`, timestamp 123.
fn ring_and_value() -> (KeyRing<SessionCookie>, String) {
    let root = RootSecret::new([0x66; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<SessionCookie>(&kid("active"))
        .expect("derive key");
    let token = encode_with_nonce(b"payload", key.as_bytes(), &[0x77; branca::NONCE_BYTES], 123)
        .expect("token");
    let ring = KeyRing::<SessionCookie>::new(kid("active"), vec![KeySlot::active(kid("active"), key)])
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
    let now = 123;
    let max_age = 1_000_000;

    let (_, verified) = decrypt_wrapped_token(&value, &ring, now, max_age).expect("valid");
    assert_eq!(verified.payload, b"payload");

    assert_eq!(
        decrypt_wrapped_token("not-a-cookie", &ring, now, max_age).unwrap_err(),
        TokenError::InvalidToken
    );

    let unknown = value.replacen("active", "missing", 1);
    assert_eq!(
        decrypt_wrapped_token(&unknown, &ring, now, max_age).unwrap_err(),
        TokenError::InvalidToken
    );

    let mut bad_mac = value.clone().into_bytes();
    let last = bad_mac.len() - 1;
    bad_mac[last] = if bad_mac[last] == b'0' { b'1' } else { b'0' };
    let bad_mac = String::from_utf8(bad_mac).expect("utf8");
    assert_eq!(
        decrypt_wrapped_token(&bad_mac, &ring, now, max_age).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn decrypt_wrapped_token_enforces_freshness_and_skew() {
    let (ring, value) = ring_and_value(); // timestamp 123

    // Stale: now far past timestamp, tight max_age.
    assert_eq!(
        decrypt_wrapped_token(&value, &ring, 10_000, 60).unwrap_err(),
        TokenError::InvalidToken
    );
    // Future-dated beyond skew tolerance: now well before the timestamp.
    assert_eq!(
        decrypt_wrapped_token(&value, &ring, 0, 1_000_000).unwrap_err(),
        TokenError::InvalidToken
    );
    // Fresh: now == timestamp.
    assert!(decrypt_wrapped_token(&value, &ring, 123, 60).is_ok());
    // Within skew tolerance ahead: timestamp 123, now 100 (< skew).
    assert!(decrypt_wrapped_token(&value, &ring, 100, 1_000_000).is_ok());
}

#[test]
fn bound_cookie_round_trips_body_binds_kid_and_iat() {
    let ring = session_ring(0x88, "active");
    let mut rng = FixedNonceRng([0x99; branca::NONCE_BYTES]);

    let value = mint_bound_cookie::<SessionCookie, _>(b"session-body", &ring, &mut rng, 456, 456, 456)
        .expect("mint");
    assert!(value.starts_with("v1.active."));

    let verified =
        parse_bound_cookie::<SessionCookie>(&value, &ring, 456, MaxAge::fixed(1_000_000)).expect("parse");
    assert_eq!(verified.kid().as_str(), "active");
    assert_eq!(verified.timestamp(), 456);
    assert_eq!(verified.iat(), 456);
    assert_eq!(verified.body(), b"session-body");
    assert_eq!(verified.jti().as_bytes(), &[0x99; branca::NONCE_BYTES]);

    let debug = format!("{verified:?}");
    assert!(!debug.contains("session-body"));
    assert!(!debug.contains("active"));
}

#[test]
fn bound_cookie_enforces_idle_absolute_and_skew() {
    let ring = session_ring(0x8B, "active");
    let mint = |ts: u32, iat: u32| {
        let mut rng = FixedNonceRng([0x99; branca::NONCE_BYTES]);
        mint_bound_cookie::<SessionCookie, _>(b"body", &ring, &mut rng, ts, iat, u64::from(ts))
            .expect("mint")
    };
    let bounds = MaxAge::new(3_600, 86_400);

    // Fresh within both bounds.
    let fresh = mint(1_000, 1_000);
    assert!(parse_bound_cookie::<SessionCookie>(&fresh, &ring, 1_100, bounds).is_ok());

    // Idle exceeded: last activity 1_000, now 5_000 (> 3_600 idle bound).
    assert_eq!(
        parse_bound_cookie::<SessionCookie>(&fresh, &ring, 5_000, bounds).unwrap_err(),
        TokenError::InvalidToken
    );

    // Absolute exceeded on a sliding re-mint: iat 1_000, last activity 100_000.
    let slid = mint(100_000, 1_000);
    assert_eq!(
        parse_bound_cookie::<SessionCookie>(&slid, &ring, 100_050, bounds).unwrap_err(),
        TokenError::InvalidToken // now - iat = 99_050 > 86_400
    );

    // Future-dated beyond skew tolerance (rewound minting clock).
    let future = mint(10_000, 10_000);
    assert_eq!(
        parse_bound_cookie::<SessionCookie>(&future, &ring, 9_900, bounds).unwrap_err(),
        TokenError::InvalidToken
    );

    // iat that postdates the activity timestamp is rejected as malformed.
    let mut rng = FixedNonceRng([0x99; branca::NONCE_BYTES]);
    assert_eq!(
        mint_bound_cookie::<SessionCookie, _>(b"body", &ring, &mut rng, 1_000, 2_000, 1_000)
            .unwrap_err(),
        TokenError::Internal
    );
}

#[test]
fn encrypted_typ_must_match_expected_purpose() {
    let root = RootSecret::new([0x89; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<SessionCookie>(&kid("active"))
        .expect("derive key");
    // Craft a payload whose bound typ is a *different* purpose.
    let payload = encode_bound_payload(PowCookie::TOKEN_TYPE, "active", 1, b"body").expect("payload");
    let token = encode_with_nonce(&payload, key.as_bytes(), &[0x9A; branca::NONCE_BYTES], 1)
        .expect("token");
    let ring = KeyRing::<SessionCookie>::new(kid("active"), vec![KeySlot::active(kid("active"), key)])
        .expect("ring");

    assert_eq!(
        parse_bound_cookie::<SessionCookie>(&format!("v1.active.{token}"), &ring, 1, MaxAge::fixed(1_000_000))
            .unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn encrypted_kid_must_match_wrapper_kid() {
    let root = RootSecret::new([0x8A; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<SessionCookie>(&kid("outer"))
        .expect("derive key");
    // Craft a payload whose bound kid differs from the outer wrapper kid.
    let payload =
        encode_bound_payload(SessionCookie::TOKEN_TYPE, "inner-other", 1, b"body").expect("payload");
    let token = encode_with_nonce(&payload, key.as_bytes(), &[0x9B; branca::NONCE_BYTES], 1)
        .expect("token");
    let ring = KeyRing::<SessionCookie>::new(kid("outer"), vec![KeySlot::active(kid("outer"), key)])
        .expect("ring");

    assert_eq!(
        parse_bound_cookie::<SessionCookie>(&format!("v1.outer.{token}"), &ring, 1, MaxAge::fixed(1_000_000))
            .unwrap_err(),
        TokenError::InvalidToken
    );
}

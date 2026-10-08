//! Cookie wrapper tests.

use super::*;
use crate::branca::{self, encode_with_nonce};
use crate::keyring::{KeyId, KeyRing, KeySlot, RootSecret};
use crate::test_support::FixedBytesRng;

/// Local purpose so wrapper tests do not depend on any product key policy.
#[derive(Debug)]
enum TestCookie {}

impl KeyPurpose for TestCookie {
    const HKDF_INFO: &'static [u8] = b"auth/test-v1";
    const TOKEN_TYPE: &'static str = "test-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 30 * 24 * 60 * 60;
}

fn kid(value: &str) -> KeyId {
    KeyId::parse(value).expect("kid parses")
}

fn test_ring(root_byte: u8, kid_str: &str) -> KeyRing<TestCookie> {
    let root = RootSecret::new([root_byte; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<TestCookie>(&kid(kid_str))
        .expect("derive key");
    KeyRing::<TestCookie>::new(vec![KeySlot::active(kid(kid_str), key)]).expect("ring")
}

/// A raw (non-bound) branca token wrapped as `v1.active.{token}`, timestamp 123.
fn ring_and_value() -> (KeyRing<TestCookie>, String) {
    let root = RootSecret::new([0x66; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<TestCookie>(&kid("active"))
        .expect("derive key");
    let token = encode_with_nonce(
        b"payload",
        key.as_bytes(),
        &[0x77; branca::NONCE_BYTES],
        123,
    )
    .expect("token");
    let ring = KeyRing::<TestCookie>::new(vec![KeySlot::active(kid("active"), key)]).expect("ring");
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

    let (_, verified) =
        decrypt_wrapped_token(&value, &ring, now, max_age, CLOCK_SKEW_TOLERANCE_SECS)
            .expect("valid");
    assert_eq!(verified.payload(), b"payload");

    assert_eq!(
        decrypt_wrapped_token(
            "not-a-cookie",
            &ring,
            now,
            max_age,
            CLOCK_SKEW_TOLERANCE_SECS
        )
        .unwrap_err(),
        TokenError::InvalidToken
    );

    let unknown = value.replacen("active", "missing", 1);
    assert_eq!(
        decrypt_wrapped_token(&unknown, &ring, now, max_age, CLOCK_SKEW_TOLERANCE_SECS)
            .unwrap_err(),
        TokenError::InvalidToken
    );

    let mut bad_mac = value.clone().into_bytes();
    let last = bad_mac.len() - 1;
    bad_mac[last] = if bad_mac[last] == b'0' { b'1' } else { b'0' };
    let bad_mac = String::from_utf8(bad_mac).expect("utf8");
    assert_eq!(
        decrypt_wrapped_token(&bad_mac, &ring, now, max_age, CLOCK_SKEW_TOLERANCE_SECS)
            .unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn decrypt_wrapped_token_enforces_freshness_and_skew() {
    let (ring, value) = ring_and_value(); // timestamp 123

    // Stale: now far past timestamp, tight max_age.
    assert_eq!(
        decrypt_wrapped_token(&value, &ring, 10_000, 60, CLOCK_SKEW_TOLERANCE_SECS).unwrap_err(),
        TokenError::InvalidToken
    );
    // Future-dated beyond skew tolerance: now well before the timestamp.
    assert_eq!(
        decrypt_wrapped_token(&value, &ring, 0, 1_000_000, CLOCK_SKEW_TOLERANCE_SECS).unwrap_err(),
        TokenError::InvalidToken
    );
    // Fresh: now == timestamp.
    assert!(decrypt_wrapped_token(&value, &ring, 123, 60, CLOCK_SKEW_TOLERANCE_SECS).is_ok());
    // Within skew tolerance ahead: timestamp 123, now 100 (< skew).
    assert!(
        decrypt_wrapped_token(&value, &ring, 100, 1_000_000, CLOCK_SKEW_TOLERANCE_SECS).is_ok()
    );
}

#[test]
fn bound_cookie_round_trips_body_binds_kid_and_iat() {
    let ring = test_ring(0x88, "active");
    let mut rng = FixedBytesRng([0x99; branca::NONCE_BYTES]);

    let value = mint_bound_cookie::<TestCookie, _>(b"session-body", &ring, &mut rng, 456, 456, 456)
        .expect("mint");
    assert!(value.starts_with("v1.active."));

    let verified = parse_bound_cookie::<TestCookie>(&value, &ring, 456, MaxAge::fixed(1_000_000))
        .expect("parse");
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
    let ring = test_ring(0x8B, "active");
    let mint = |ts: u32, iat: u32| {
        let mut rng = FixedBytesRng([0x99; branca::NONCE_BYTES]);
        mint_bound_cookie::<TestCookie, _>(b"body", &ring, &mut rng, ts, iat, u64::from(ts))
            .expect("mint")
    };
    let bounds = MaxAge::new(3_600, 86_400);

    // Fresh within both bounds.
    let fresh = mint(1_000, 1_000);
    assert!(parse_bound_cookie::<TestCookie>(&fresh, &ring, 1_100, bounds).is_ok());

    // Idle exceeded: last activity 1_000, now 5_000 (> 3_600 idle bound).
    assert_eq!(
        parse_bound_cookie::<TestCookie>(&fresh, &ring, 5_000, bounds).unwrap_err(),
        TokenError::InvalidToken
    );

    // Absolute exceeded on a sliding re-mint: iat 1_000, last activity 100_000.
    let slid = mint(100_000, 1_000);
    assert_eq!(
        parse_bound_cookie::<TestCookie>(&slid, &ring, 100_050, bounds).unwrap_err(),
        TokenError::InvalidToken // now - iat = 99_050 > 86_400
    );

    // Future-dated beyond skew tolerance (rewound minting clock).
    let future = mint(10_000, 10_000);
    assert_eq!(
        parse_bound_cookie::<TestCookie>(&future, &ring, 9_900, bounds).unwrap_err(),
        TokenError::InvalidToken
    );

    // iat that postdates the activity timestamp is rejected as malformed.
    let mut rng = FixedBytesRng([0x99; branca::NONCE_BYTES]);
    assert_eq!(
        mint_bound_cookie::<TestCookie, _>(b"body", &ring, &mut rng, 1_000, 2_000, 1_000)
            .unwrap_err(),
        TokenError::InvalidTimestamp
    );
}

#[test]
fn mint_rejects_timestamps_outside_skew_tolerance() {
    let ring = test_ring(0x8C, "active");
    let mut rng = FixedBytesRng([0xAB; branca::NONCE_BYTES]);

    assert_eq!(
        mint_bound_cookie::<TestCookie, _>(b"body", &ring, &mut rng, 1_000, 1_000, 1_061)
            .unwrap_err(),
        TokenError::InvalidTimestamp
    );

    let mut rng = FixedBytesRng([0xAC; branca::NONCE_BYTES]);
    assert_eq!(
        mint_bound_cookie::<TestCookie, _>(b"body", &ring, &mut rng, 1_000, 1_000, 939)
            .unwrap_err(),
        TokenError::InvalidTimestamp
    );
}

#[test]
fn configured_clock_skew_checks_idle_and_first_issue_times_at_the_boundary() {
    let ring = test_ring(0x8C, "active");

    // Cover a first mint and a sliding refresh with an earlier first-issue time.
    for iat in [1_000, 1_030] {
        let mut rng = FixedBytesRng([0xB0; branca::NONCE_BYTES]);
        let value = mint_bound_cookie::<TestCookie, _>(b"body", &ring, &mut rng, 1_030, iat, 1_030)
            .expect("mint");
        let verified =
            parse_bound_cookie_with_clock_skew(&value, &ring, 1_000, MaxAge::fixed(60), 30)
                .expect("exactly 30 seconds ahead is accepted");
        assert_eq!(verified.timestamp(), 1_030);
        assert_eq!(verified.iat(), iat);
        assert_eq!(
            parse_bound_cookie_with_clock_skew(&value, &ring, 999, MaxAge::fixed(60), 30)
                .unwrap_err(),
            TokenError::InvalidToken
        );
    }
}

#[test]
fn configured_mint_clock_skew_is_inclusive_in_both_directions() {
    let ring = test_ring(0x8C, "active");

    for now in [970, 1_000, 1_030] {
        let mut rng = FixedBytesRng([0xB1; branca::NONCE_BYTES]);
        assert!(
            mint_bound_cookie_with_clock_skew(b"body", &ring, &mut rng, 1_000, 1_000, now, 30)
                .is_ok()
        );
    }
    for now in [969, 1_031] {
        let mut rng = FixedBytesRng([0xB2; branca::NONCE_BYTES]);
        assert_eq!(
            mint_bound_cookie_with_clock_skew(b"body", &ring, &mut rng, 1_000, 1_000, now, 30)
                .unwrap_err(),
            TokenError::InvalidTimestamp
        );
    }
    let mut rng = FixedBytesRng([0xB3; branca::NONCE_BYTES]);
    assert_eq!(
        mint_bound_cookie_with_clock_skew(b"body", &ring, &mut rng, 1_000, 1_001, 1_000, 30)
            .unwrap_err(),
        TokenError::InvalidTimestamp
    );
}

#[test]
fn zero_clock_skew_requires_exact_mint_time_and_rejects_future_cookies() {
    let ring = test_ring(0x8C, "active");
    let mut rng = FixedBytesRng([0xB4; branca::NONCE_BYTES]);
    let value = mint_bound_cookie_with_clock_skew(b"body", &ring, &mut rng, 1_000, 1_000, 1_000, 0)
        .expect("matching mint clock");

    for now in [1_000, 1_001] {
        assert!(
            parse_bound_cookie_with_clock_skew(&value, &ring, now, MaxAge::fixed(60), 0).is_ok()
        );
    }
    assert_eq!(
        parse_bound_cookie_with_clock_skew(&value, &ring, 999, MaxAge::fixed(60), 0).unwrap_err(),
        TokenError::InvalidToken
    );
    for now in [999, 1_001] {
        let mut rng = FixedBytesRng([0xB5; branca::NONCE_BYTES]);
        assert_eq!(
            mint_bound_cookie_with_clock_skew(b"body", &ring, &mut rng, 1_000, 1_000, now, 0)
                .unwrap_err(),
            TokenError::InvalidTimestamp
        );
    }
}

#[test]
fn default_clock_skew_remains_sixty_seconds() {
    assert_eq!(CLOCK_SKEW_TOLERANCE_SECS, 60);
    let ring = test_ring(0x8C, "active");
    let mut rng = FixedBytesRng([0xB6; branca::NONCE_BYTES]);
    let value = mint_bound_cookie(b"body", &ring, &mut rng, 1_000, 1_000, 940)
        .expect("mint 60 seconds ahead");
    assert!(parse_bound_cookie(&value, &ring, 940, MaxAge::fixed(60)).is_ok());
    assert_eq!(
        parse_bound_cookie(&value, &ring, 939, MaxAge::fixed(60)).unwrap_err(),
        TokenError::InvalidToken
    );
    let mut rng = FixedBytesRng([0xB7; branca::NONCE_BYTES]);
    assert!(mint_bound_cookie(b"body", &ring, &mut rng, 1_000, 1_000, 1_060).is_ok());
}

#[test]
fn configured_clock_skew_never_extends_idle_or_absolute_expiry() {
    let ring = test_ring(0x8C, "active");
    let mut rng = FixedBytesRng([0xB8; branca::NONCE_BYTES]);
    let value = mint_bound_cookie(b"body", &ring, &mut rng, 1_000, 1_000, 1_000).expect("mint");

    for bounds in [MaxAge::new(30, 60), MaxAge::new(60, 30)] {
        for skew in [0, 30, 60, MAX_CLOCK_SKEW_SECS] {
            assert!(parse_bound_cookie_with_clock_skew(&value, &ring, 1_030, bounds, skew).is_ok());
            assert_eq!(
                parse_bound_cookie_with_clock_skew(&value, &ring, 1_031, bounds, skew).unwrap_err(),
                TokenError::InvalidToken
            );
        }
    }
}

#[test]
fn clock_skew_above_the_cap_is_rejected_as_misconfiguration() {
    let ring = test_ring(0x8C, "active");
    let mut rng = FixedBytesRng([0xB9; branca::NONCE_BYTES]);
    for skew in [MAX_CLOCK_SKEW_SECS + 1, u64::MAX] {
        assert_eq!(
            mint_bound_cookie_with_clock_skew(b"body", &ring, &mut rng, 1_000, 1_000, 1_000, skew)
                .unwrap_err(),
            TokenError::InvalidTimestamp
        );
    }
    let value = mint_bound_cookie(b"body", &ring, &mut rng, 1_000, 1_000, 1_000).expect("mint");
    for skew in [MAX_CLOCK_SKEW_SECS + 1, u64::MAX] {
        // Distinct from InvalidToken, so operators see the misconfiguration.
        assert_eq!(
            parse_bound_cookie_with_clock_skew(&value, &ring, 1_000, MaxAge::fixed(60), skew)
                .unwrap_err(),
            TokenError::InvalidTimestamp
        );
    }
}

#[test]
fn capped_clock_skew_is_overflow_safe_at_extreme_times() {
    let ring = test_ring(0x8C, "active");
    let mut rng = FixedBytesRng([0xBA; branca::NONCE_BYTES]);
    let value = mint_bound_cookie_with_clock_skew(
        b"body",
        &ring,
        &mut rng,
        u32::MAX,
        u32::MAX,
        u64::from(u32::MAX),
        MAX_CLOCK_SKEW_SECS,
    )
    .expect("mint at the u32 timestamp ceiling");
    let longest = MaxAge::fixed(TestCookie::MAX_ABSOLUTE_AGE_SECS);
    assert!(
        parse_bound_cookie_with_clock_skew(
            &value,
            &ring,
            u64::from(u32::MAX),
            longest,
            MAX_CLOCK_SKEW_SECS,
        )
        .is_ok()
    );
    // At the far end of the clock the cookie is expired, not an overflow.
    assert_eq!(
        parse_bound_cookie_with_clock_skew(&value, &ring, u64::MAX, longest, MAX_CLOCK_SKEW_SECS)
            .unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        mint_bound_cookie_with_clock_skew(
            b"body",
            &ring,
            &mut rng,
            u32::MAX,
            u32::MAX,
            u64::MAX,
            MAX_CLOCK_SKEW_SECS,
        )
        .unwrap_err(),
        // The mint timestamp is far behind `now`; the capped skew cannot
        // bridge it, and the comparison saturates instead of overflowing.
        TokenError::InvalidTimestamp
    );
}

#[test]
fn mint_preserves_keyring_errors_instead_of_funneling_to_invalid_token() {
    let root = RootSecret::new([0x8D; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<TestCookie>(&kid("active"))
        .expect("derive key");
    let ring = KeyRing::<TestCookie>::new(vec![KeySlot::active_with_windows(
        kid("active"),
        key,
        10,
        10 + TestCookie::MAX_ABSOLUTE_AGE_SECS,
    )])
    .expect("ring");
    let mut rng = FixedBytesRng([0xAD; branca::NONCE_BYTES]);

    assert_eq!(
        mint_bound_cookie::<TestCookie, _>(b"body", &ring, &mut rng, 11, 11, 11).unwrap_err(),
        TokenError::KeyExpired
    );
}

#[test]
fn body_cap_helper_accounts_for_framing() {
    let id = kid("active");
    let cap = max_body_bytes::<TestCookie>(&id);
    assert_eq!(
        cap,
        TestCookie::MAX_BODY_BYTES
            - (1 + 4 + 1 + TestCookie::TOKEN_TYPE.len() + 1 + id.as_str().len())
    );

    let ring = test_ring(0x8E, "active");
    let mut rng = FixedBytesRng([0xAE; branca::NONCE_BYTES]);
    let ok_body = vec![0x42; cap];
    let value = mint_bound_cookie::<TestCookie, _>(&ok_body, &ring, &mut rng, 1, 1, 1)
        .expect("max-size body mints");
    let parsed = parse_bound_cookie::<TestCookie>(&value, &ring, 1, MaxAge::fixed(60))
        .expect("max-size body parses");
    assert_eq!(parsed.body(), ok_body);

    let mut rng = FixedBytesRng([0xAF; branca::NONCE_BYTES]);
    let too_big = vec![0x42; cap + 1];
    assert_eq!(
        mint_bound_cookie::<TestCookie, _>(&too_big, &ring, &mut rng, 1, 1, 1).unwrap_err(),
        TokenError::PayloadTooLarge
    );
}

#[test]
fn cookie_edge_rejects_oversized_token_before_decode() {
    let ring = test_ring(0x8F, "active");
    let oversized = format!("v1.active.{}", "1".repeat(branca::MAX_TOKEN_BYTES + 1));

    assert_eq!(
        decrypt_wrapped_token::<TestCookie>(&oversized, &ring, 1, 60, CLOCK_SKEW_TOLERANCE_SECS)
            .unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn encrypted_typ_must_match_expected_purpose() {
    let root = RootSecret::new([0x89; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<TestCookie>(&kid("active"))
        .expect("derive key");
    // Craft a payload whose bound typ is a *different* purpose.
    let payload =
        encode_bound_payload::<TestCookie>("other-typ-v1", "active", 1, b"body").expect("payload");
    let token = encode_with_nonce(&payload, key.as_bytes(), &[0x9A; branca::NONCE_BYTES], 1)
        .expect("token");
    let ring = KeyRing::<TestCookie>::new(vec![KeySlot::active(kid("active"), key)]).expect("ring");

    assert_eq!(
        parse_bound_cookie::<TestCookie>(
            &format!("v1.active.{token}"),
            &ring,
            1,
            MaxAge::fixed(1_000_000)
        )
        .unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn encrypted_kid_must_match_wrapper_kid() {
    let root = RootSecret::new([0x8A; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<TestCookie>(&kid("outer"))
        .expect("derive key");
    // Craft a payload whose bound kid differs from the outer wrapper kid.
    let payload =
        encode_bound_payload::<TestCookie>(TestCookie::TOKEN_TYPE, "inner-other", 1, b"body")
            .expect("payload");
    let token = encode_with_nonce(&payload, key.as_bytes(), &[0x9B; branca::NONCE_BYTES], 1)
        .expect("token");
    let ring = KeyRing::<TestCookie>::new(vec![KeySlot::active(kid("outer"), key)]).expect("ring");

    assert_eq!(
        parse_bound_cookie::<TestCookie>(
            &format!("v1.outer.{token}"),
            &ring,
            1,
            MaxAge::fixed(1_000_000)
        )
        .unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn max_age_beyond_the_purpose_lifetime_is_rejected_as_misconfiguration() {
    let ring = test_ring(0x8C, "active");
    let mut rng = FixedBytesRng([0xBB; branca::NONCE_BYTES]);
    let value = mint_bound_cookie(b"body", &ring, &mut rng, 1_000, 1_000, 1_000).expect("mint");
    let longest = TestCookie::MAX_ABSOLUTE_AGE_SECS;
    assert!(parse_bound_cookie(&value, &ring, 1_000, MaxAge::fixed(longest)).is_ok());
    for bounds in [
        MaxAge::fixed(longest + 1),
        MaxAge::new(longest + 1, 60),
        MaxAge::new(60, longest + 1),
        MaxAge::fixed(u64::MAX),
    ] {
        // Distinct from InvalidToken, so a typo does not silently widen or
        // break validation.
        assert_eq!(
            parse_bound_cookie(&value, &ring, 1_000, bounds).unwrap_err(),
            TokenError::InvalidTimestamp
        );
    }
}

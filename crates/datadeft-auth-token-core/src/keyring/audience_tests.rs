use super::*;
use crate::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use crate::keyring::{KeyId, KeyStatus, RootSecret};
use crate::test_support::{
    CountingRng, TestCookieA, TestCookieB, test_active_slot_with_windows, test_keyring_with_windows,
};

fn ring<P: KeyPurpose>() -> KeyRing<P> {
    test_keyring_with_windows(0x11, "test-active", 1000, 10000)
}

fn scoped<P: KeyPurpose>(name: &str) -> KeyRing<P> {
    KeyRing::new_with_audience(
        vec![test_active_slot_with_windows(
            0x11,
            "test-active",
            1000,
            10000,
        )],
        &Audience::parse(name).expect("audience"),
    )
    .expect("scope")
}

#[test]
fn audience_validation_is_bounded_exact_and_redacted() {
    for invalid in ["", " api", "api ", "api\0", "api\r\n", "api?x", "é"] {
        assert_eq!(
            Audience::parse(invalid).unwrap_err(),
            TokenError::KeyringMisconfigured
        );
    }
    assert!(Audience::parse(&"a".repeat(128)).is_ok());
    assert!(Audience::parse(&"a".repeat(129)).is_err());
    let audience = Audience::parse("https://app.example.invalid/api-v1_2").expect("identifier");
    assert_eq!(audience.as_str(), "https://app.example.invalid/api-v1_2");
    assert_eq!(format!("{audience:?}"), "Audience(..)");
    assert_ne!(
        Audience::parse("API").expect("upper"),
        Audience::parse("api").expect("lower")
    );
}

#[test]
fn audience_hkdf_vector_and_separation_are_pinned() {
    let api = scoped::<TestCookieA>("api");
    // Independently calculated with Python stdlib HMAC/HKDF: input key is the
    // existing purpose/kid vector 4776cd..., and each info field has a u64 BE length.
    assert_eq!(
        hex::encode(api.active().key().as_bytes()),
        "c7b97dd06260e236fa5f5807b8093c64829c955ad4d7cd5cb159724bcce6babb"
    );
    assert_eq!(
        api.active().key().as_bytes(),
        scoped::<TestCookieA>("api").active().key().as_bytes()
    );
    for other in [
        ring::<TestCookieA>(),
        scoped::<TestCookieA>("admin"),
        scoped::<TestCookieA>("API"),
        KeyRing::new_with_audience(
            vec![test_active_slot_with_windows::<TestCookieA>(
                0x11,
                "different-kid",
                1000,
                10000,
            )],
            &Audience::parse("api").expect("audience"),
        )
        .expect("scope"),
    ] {
        assert_ne!(
            api.active().key().as_bytes(),
            other.active().key().as_bytes()
        );
    }
    assert_ne!(
        api.active().key().as_bytes(),
        scoped::<TestCookieB>("api").active().key().as_bytes()
    );
}

#[test]
fn scoped_unscoped_and_cross_audience_cookies_have_no_verification_fallback() {
    let rings = [
        ring::<TestCookieA>(),
        scoped::<TestCookieA>("api"),
        scoped::<TestCookieA>("admin"),
    ];
    for (issuer, mint_ring) in rings.iter().enumerate() {
        let token = mint_bound_cookie(
            b"fixture",
            mint_ring,
            &mut CountingRng::starting_at(0),
            100,
            100,
            100,
        )
        .expect("mint");
        for (verifier, verify_ring) in rings.iter().enumerate() {
            let result = parse_bound_cookie(&token, verify_ring, 101, MaxAge::fixed(600));
            if issuer == verifier {
                assert_eq!(result.expect("same scope").body(), b"fixture");
            } else {
                assert_eq!(result.unwrap_err(), TokenError::InvalidToken);
            }
        }
    }
}

#[test]
fn scoping_preserves_previous_slot_windows_and_mint_status() {
    let audience = Audience::parse("api").expect("audience");
    let old_id = KeyId::parse("old").expect("kid");
    let new_id = KeyId::parse("new").expect("kid");
    let old_root = RootSecret::new([0x22; 32]);
    let old = KeyRing::new_with_audience(
        vec![test_active_slot_with_windows::<TestCookieA>(
            0x22, "old", 1000, 10000,
        )],
        &audience,
    )
    .expect("old scope");
    let token = mint_bound_cookie(
        b"fixture",
        &old,
        &mut CountingRng::starting_at(0),
        100,
        100,
        100,
    )
    .expect("mint old");
    let rotated = KeyRing::new_with_audience(
        vec![
            KeySlot::active_with_windows(
                new_id.clone(),
                RootSecret::new([0x33; 32])
                    .derive_key::<TestCookieA>(&new_id)
                    .expect("new key"),
                1000,
                10000,
            ),
            KeySlot::verify_only(
                old_id.clone(),
                old_root
                    .derive_key::<TestCookieA>(&old_id)
                    .expect("old key"),
                500,
            ),
        ],
        &audience,
    )
    .expect("scoped rotation");
    assert_eq!(rotated.minting_key_at(1000).expect("active").kid(), &new_id);
    assert_eq!(
        rotated.minting_key_at(1001).unwrap_err(),
        TokenError::KeyExpired
    );
    assert_eq!(
        rotated
            .verification_key_at(&old_id, 500)
            .expect("previous")
            .status(),
        KeyStatus::VerifyOnly
    );
    assert_eq!(
        parse_bound_cookie(&token, &rotated, 500, MaxAge::fixed(600))
            .expect("old scoped cookie")
            .body(),
        b"fixture"
    );
    assert_eq!(
        parse_bound_cookie(&token, &rotated, 501, MaxAge::fixed(600)).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn audience_construction_enforces_the_same_ring_invariants() {
    let audience = Audience::parse("api").expect("audience");
    let previous_kid = KeyId::parse("twin").expect("kid");
    let previous_key = RootSecret::new([0x22; 32])
        .derive_key::<TestCookieA>(&previous_kid)
        .expect("previous key");
    let previous_only_kid = KeyId::parse("previous").expect("kid");
    let previous_only_key = RootSecret::new([0x22; 32])
        .derive_key::<TestCookieA>(&previous_only_kid)
        .expect("previous-only key");
    for (case, keys) in [
        ("empty", Vec::new()),
        (
            "duplicate kid with exactly one active slot",
            vec![
                test_active_slot_with_windows(0x11, "twin", 1000, 10000),
                KeySlot::verify_only(previous_kid, previous_key, 10000),
            ],
        ),
        (
            "two distinct active slots",
            vec![
                test_active_slot_with_windows(0x11, "first", 1000, 10000),
                test_active_slot_with_windows(0x22, "second", 1000, 10000),
            ],
        ),
        (
            "no active slot",
            vec![KeySlot::verify_only(
                previous_only_kid,
                previous_only_key,
                10000,
            )],
        ),
        (
            "verification shorter than absolute lifetime",
            vec![test_active_slot_with_windows(0x11, "active", 1000, 1599)],
        ),
        (
            "minting after verification expires",
            vec![test_active_slot_with_windows(0x11, "active", 1000, 999)],
        ),
        (
            "absolute lifetime arithmetic overflow",
            vec![test_active_slot_with_windows(
                0x11,
                "active",
                u64::MAX,
                u64::MAX,
            )],
        ),
    ] {
        assert_eq!(
            KeyRing::new_with_audience(keys, &audience).unwrap_err(),
            TokenError::KeyringMisconfigured,
            "{case}"
        );
    }
}

#[test]
fn scoped_cookies_still_reject_tamper_and_expiry() {
    let ring = scoped::<TestCookieA>("api");
    let token = mint_bound_cookie(
        b"fixture",
        &ring,
        &mut CountingRng::starting_at(0),
        100,
        100,
        100,
    )
    .expect("mint");
    assert_eq!(
        parse_bound_cookie(&token, &ring, 701, MaxAge::fixed(600)).unwrap_err(),
        TokenError::InvalidToken
    );
    let mut tampered = token.into_bytes();
    let last = tampered.last_mut().expect("nonempty cookie");
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("ascii");
    assert_eq!(
        parse_bound_cookie(&tampered, &ring, 101, MaxAge::fixed(600)).unwrap_err(),
        TokenError::InvalidToken
    );
}

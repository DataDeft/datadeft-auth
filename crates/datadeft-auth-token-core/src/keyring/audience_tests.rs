use super::*;
use crate::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use crate::keyring::{KeyId, KeyStatus, RootSecret};
use crate::test_support::{CountingRng, test_keyring_with_windows};

#[derive(Debug)]
enum CookieA {}
impl KeyPurpose for CookieA {
    const HKDF_INFO: &'static [u8] = b"auth/test-a-v1";
    const TOKEN_TYPE: &'static str = "test-a-v1";
    const MAX_BODY_BYTES: usize = 128;
    const LARGEST_BODY_BYTES: usize = 0;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 600;
}

#[derive(Debug)]
enum CookieB {}
impl KeyPurpose for CookieB {
    const HKDF_INFO: &'static [u8] = b"auth/test-b-v1";
    const TOKEN_TYPE: &'static str = "test-b-v1";
    const MAX_BODY_BYTES: usize = 128;
    const LARGEST_BODY_BYTES: usize = 0;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 600;
}

fn ring<P: KeyPurpose>() -> KeyRing<P> {
    test_keyring_with_windows(0x11, "test-active", 1000, 10000)
}

fn scoped<P: KeyPurpose>(name: &str) -> KeyRing<P> {
    ring()
        .with_audience(&Audience::parse(name).expect("audience"))
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
    let api = scoped::<CookieA>("api");
    // Independently calculated with Python stdlib HMAC/HKDF: input key is the
    // existing purpose/kid vector 4776cd..., and each info field has a u64 BE length.
    assert_eq!(
        hex::encode(api.active().key().as_bytes()),
        "c7b97dd06260e236fa5f5807b8093c64829c955ad4d7cd5cb159724bcce6babb"
    );
    assert_eq!(
        api.active().key().as_bytes(),
        scoped::<CookieA>("api").active().key().as_bytes()
    );
    for other in [
        ring::<CookieA>(),
        scoped::<CookieA>("admin"),
        scoped::<CookieA>("API"),
        test_keyring_with_windows::<CookieA>(0x11, "different-kid", 1000, 10000)
            .with_audience(&Audience::parse("api").expect("audience"))
            .expect("scope"),
    ] {
        assert_ne!(
            api.active().key().as_bytes(),
            other.active().key().as_bytes()
        );
    }
    assert_ne!(
        api.active().key().as_bytes(),
        scoped::<CookieB>("api").active().key().as_bytes()
    );
}

#[test]
fn scoped_unscoped_and_cross_audience_cookies_have_no_verification_fallback() {
    let rings = [
        ring::<CookieA>(),
        scoped::<CookieA>("api"),
        scoped::<CookieA>("admin"),
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
    let old = test_keyring_with_windows::<CookieA>(0x22, "old", 1000, 10000)
        .with_audience(&audience)
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
    let rotated = KeyRing::new(vec![
        KeySlot::active_with_windows(
            new_id.clone(),
            RootSecret::new([0x33; 32])
                .derive_key::<CookieA>(&new_id)
                .expect("new key"),
            1000,
            10000,
        ),
        KeySlot::verify_only(
            old_id.clone(),
            old_root.derive_key::<CookieA>(&old_id).expect("old key"),
            500,
        ),
    ])
    .expect("rotation")
    .with_audience(&audience)
    .expect("scope rotation");
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
    assert_eq!(
        rotated.with_audience(&audience).unwrap_err(),
        TokenError::KeyringMisconfigured
    );
}

#[test]
fn scoped_cookies_still_reject_tamper_and_expiry() {
    let ring = scoped::<CookieA>("api");
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

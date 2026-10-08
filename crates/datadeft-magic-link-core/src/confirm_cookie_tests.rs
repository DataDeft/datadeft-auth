//! Magic-link confirm-cookie tests.

use datadeft_auth_token_core::branca;
use datadeft_auth_token_core::cookie::{max_body_bytes, mint_bound_cookie};
use datadeft_auth_token_core::keyring::{KEY_BYTES, KeyId, KeyRing, KeySlot, RootSecret};
use datadeft_auth_token_core::test_support::{FailOnCallRng, PerCallRng, test_keyring};
use zeroize::Zeroize;

use super::*;

/// Local non-confirm purpose proving cross-purpose cookies are rejected.
#[derive(Debug)]
enum OtherCookie {}

impl KeyPurpose for OtherCookie {
    const HKDF_INFO: &'static [u8] = b"auth/test-other-v1";
    const TOKEN_TYPE: &'static str = "test-other-v1";
    const MAX_BODY_BYTES: usize = 128;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 600;
}

fn kid(value: &str) -> KeyId {
    KeyId::parse(value).expect("kid parses")
}

fn confirm_ring(root_byte: u8, kid_value: &str) -> KeyRing<MagicLinkConfirmCookie> {
    test_keyring::<MagicLinkConfirmCookie>(root_byte, kid_value)
}

fn bindings(expires_at_unix: u32) -> MagicLinkConfirmBindings {
    MagicLinkConfirmBindings::new(
        ConfirmSelectorBinding::new([0x11; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
        ConfirmVerifierBinding::new([0x22; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
        ConfirmAccountBinding::new([0x33; MAGIC_LINK_CONFIRM_BINDING_BYTES]),
        expires_at_unix,
    )
}

fn mint_confirm(
    ring: &KeyRing<MagicLinkConfirmCookie>,
    now_unix: u64,
    expires_at_unix: u32,
) -> MintedMagicLinkConfirm {
    let mut rng = PerCallRng::starting_at(0xa0);
    mint_magic_link_confirm(bindings(expires_at_unix), ring, &mut rng, now_unix)
        .expect("confirm mints")
}

#[test]
fn confirm_purpose_constants_are_pinned() {
    assert_eq!(
        HKDF_INFO_MAGIC_LINK_CONFIRM_COOKIE_V1,
        b"auth/magic-link-confirm-v1"
    );
    assert_eq!(
        MagicLinkConfirmCookie::HKDF_INFO,
        HKDF_INFO_MAGIC_LINK_CONFIRM_COOKIE_V1
    );
    assert_eq!(TOKEN_TYPE_MAGIC_LINK_CONFIRM_COOKIE_V1, "ml-confirm-v1");
    assert_eq!(
        MagicLinkConfirmCookie::TOKEN_TYPE,
        TOKEN_TYPE_MAGIC_LINK_CONFIRM_COOKIE_V1
    );
    assert_eq!(MagicLinkConfirmCookie::MAX_BODY_BYTES, 256);
    assert_eq!(MagicLinkConfirmCookie::MAX_ABSOLUTE_AGE_SECS, 5 * 60);
}

#[test]
fn confirm_hkdf_vector_is_pinned() {
    // HKDF-SHA256 with salt=None, IKM=[0x11; 32], L=32,
    // info = HKDF_INFO || 0x00 || kid. This vector pins the exact info framing.
    // Changing it invalidates every confirm cookie minted under the previous key.
    let root = RootSecret::new([0x11; KEY_BYTES]);
    let confirm = root
        .derive_key::<MagicLinkConfirmCookie>(&kid("confirm-active"))
        .expect("derive confirm");

    assert_eq!(
        hex::encode(confirm.as_test_bytes()),
        "64423584c5e2c5dc0648d1bec4443bc4e1d019cbaea681b5e84ced9b3cb0c313"
    );
}

#[test]
fn canonical_confirm_body_vector_is_pinned() {
    let confirmation = MagicLinkConfirmNonce([0xaa; MAGIC_LINK_CONFIRM_NONCE_BYTES]);

    let body = encode_confirm_body(&bindings(1_000), &confirmation);
    let expected = hex::decode(concat!(
        "01",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "000003e8"
    ))
    .expect("vector hex");
    assert_eq!(body, expected);
    assert_eq!(body.len(), CONFIRM_BODY_BYTES);
}

#[test]
fn confirm_round_trips() {
    let ring = confirm_ring(0x71, "confirm-active");
    let minted = mint_confirm(&ring, 1_000, 1_300);
    assert_eq!(
        minted.confirmation().as_value(),
        "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
    );
    let verified = verify_magic_link_confirm(
        minted.cookie().as_secret_value(),
        minted.confirmation().as_value(),
        &ring,
        1_000,
        MAGIC_LINK_CONFIRM_MAX_AGE_SECS,
    )
    .expect("confirm verifies");

    assert!(
        verified
            .selector()
            .matches_constant_time(&ConfirmSelectorBinding::new(
                [0x11; MAGIC_LINK_CONFIRM_BINDING_BYTES]
            ))
    );
    assert!(
        verified
            .verifier()
            .matches_constant_time(&ConfirmVerifierBinding::new(
                [0x22; MAGIC_LINK_CONFIRM_BINDING_BYTES]
            ))
    );
    assert!(
        verified
            .account()
            .matches_constant_time(&ConfirmAccountBinding::new(
                [0x33; MAGIC_LINK_CONFIRM_BINDING_BYTES]
            ))
    );
    assert_eq!(verified.expires_at_unix(), 1_300);
}

#[test]
fn binding_comparisons_are_explicit_and_constant_time() {
    let selector = ConfirmSelectorBinding::new([0x10; MAGIC_LINK_CONFIRM_BINDING_BYTES]);
    assert!(selector.matches_constant_time(&ConfirmSelectorBinding::new(
        [0x10; MAGIC_LINK_CONFIRM_BINDING_BYTES]
    )));
    assert!(
        !selector.matches_constant_time(&ConfirmSelectorBinding::new(
            [0x11; MAGIC_LINK_CONFIRM_BINDING_BYTES]
        ))
    );

    let verifier = ConfirmVerifierBinding::new([0x20; MAGIC_LINK_CONFIRM_BINDING_BYTES]);
    assert!(verifier.matches_constant_time(&ConfirmVerifierBinding::new(
        [0x20; MAGIC_LINK_CONFIRM_BINDING_BYTES]
    )));
    assert!(
        !verifier.matches_constant_time(&ConfirmVerifierBinding::new(
            [0x21; MAGIC_LINK_CONFIRM_BINDING_BYTES]
        ))
    );
}

#[test]
fn confirmation_is_canonical_and_must_match() {
    let ring = confirm_ring(0x72, "confirm-active");
    let minted = mint_confirm(&ring, 1_000, 1_300);
    let cookie = minted.cookie().as_secret_value();
    let confirmation = minted.confirmation().as_value();

    assert_eq!(confirmation.len(), CONFIRMATION_HEX_BYTES);
    assert!(
        confirmation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    );
    assert!(verify_magic_link_confirm(cookie, confirmation, &ring, 1_000, 300).is_ok());
    assert_eq!(
        verify_magic_link_confirm(
            cookie,
            &confirmation.to_ascii_uppercase(),
            &ring,
            1_000,
            300
        )
        .unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        verify_magic_link_confirm(cookie, &confirmation[..63], &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
    let wrong = "b0".repeat(MAGIC_LINK_CONFIRM_NONCE_BYTES);
    assert_eq!(
        verify_magic_link_confirm(cookie, &wrong, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn confirm_enforces_explicit_and_caller_freshness_boundaries() {
    let ring = confirm_ring(0x73, "confirm-active");
    let minted = mint_confirm(&ring, 1_000, 1_300);
    let cookie = minted.cookie().as_secret_value();
    let confirmation = minted.confirmation().as_value();

    assert!(verify_magic_link_confirm(cookie, confirmation, &ring, 1_300, 300).is_ok());
    assert_eq!(
        verify_magic_link_confirm(cookie, confirmation, &ring, 1_301, 300).unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        verify_magic_link_confirm(cookie, confirmation, &ring, 1_001, 100).unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        verify_magic_link_confirm(cookie, confirmation, &ring, 1_000, 0).unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        verify_magic_link_confirm(cookie, confirmation, &ring, 1_000, 301).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn mint_enforces_explicit_expiry_and_u32_time_bounds() {
    let ring = confirm_ring(0x74, "confirm-active");

    let mut rng = PerCallRng::starting_at(0xa0);
    assert_eq!(
        mint_magic_link_confirm(bindings(999), &ring, &mut rng, 1_000).unwrap_err(),
        TokenError::InvalidTimestamp
    );
    let mut rng = PerCallRng::starting_at(0xa0);
    assert_eq!(
        mint_magic_link_confirm(bindings(1_301), &ring, &mut rng, 1_000).unwrap_err(),
        TokenError::InvalidTimestamp
    );
    let mut rng = PerCallRng::starting_at(0xa0);
    assert!(mint_magic_link_confirm(bindings(1_000), &ring, &mut rng, 1_000).is_ok());
    let mut rng = PerCallRng::starting_at(0xa0);
    assert_eq!(
        mint_magic_link_confirm(bindings(u32::MAX), &ring, &mut rng, u64::from(u32::MAX) + 1,)
            .unwrap_err(),
        TokenError::InvalidTimestamp
    );
}

#[test]
fn future_dated_confirm_cookie_beyond_skew_fails_generically() {
    let ring = confirm_ring(0x7a, "confirm-active");
    let confirmation_nonce = MagicLinkConfirmNonce([0xa0; MAGIC_LINK_CONFIRM_NONCE_BYTES]);
    let mut body = encode_confirm_body(&bindings(1_100), &confirmation_nonce);
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_bound_cookie::<MagicLinkConfirmCookie, _>(&body, &ring, &mut rng, 1_100, 1_100, 1_100)
            .expect("future fixture mints");
    body.zeroize();
    let confirmation = "a0".repeat(MAGIC_LINK_CONFIRM_NONCE_BYTES);

    assert_eq!(
        verify_magic_link_confirm(&cookie, &confirmation, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn tampered_cookie_and_unknown_key_fail_generically() {
    let ring = confirm_ring(0x75, "confirm-active");
    let minted = mint_confirm(&ring, 1_000, 1_300);
    let confirmation = minted.confirmation().as_value();
    let mut tampered = minted.cookie().as_secret_value().as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).expect("cookie is ascii");
    assert_eq!(
        verify_magic_link_confirm(&tampered, confirmation, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );

    let unknown =
        minted
            .cookie()
            .as_secret_value()
            .replacen("confirm-active", "confirm-missing", 1);
    assert_eq!(
        verify_magic_link_confirm(&unknown, confirmation, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn malformed_and_old_flow_bodies_are_rejected() {
    let confirmation = MagicLinkConfirmNonce([0xaa; MAGIC_LINK_CONFIRM_NONCE_BYTES]);
    let valid = encode_confirm_body(&bindings(1_300), &confirmation);

    let mut bad_version = valid.clone();
    bad_version[0] = 2;
    let mut trailing = valid.clone();
    trailing.push(0);
    let truncated = &valid[..valid.len() - 1];

    let binding_end = 1 + (3 * MAGIC_LINK_CONFIRM_BINDING_BYTES);
    let mut old_134_body = valid[..binding_end].to_vec();
    old_134_body.push(0);
    old_134_body.extend_from_slice(&valid[binding_end..]);
    let mut old_166_body = valid[..binding_end].to_vec();
    old_166_body.push(1);
    old_166_body.extend_from_slice(&[0x44; MAGIC_LINK_CONFIRM_BINDING_BYTES]);
    old_166_body.extend_from_slice(&valid[binding_end..]);
    assert_eq!(old_134_body.len(), 134);
    assert_eq!(old_166_body.len(), 166);

    for malformed in [
        &bad_version[..],
        &trailing[..],
        truncated,
        &old_134_body,
        &old_166_body,
    ] {
        assert!(matches!(
            decode_confirm_body(malformed),
            Err(TokenError::InvalidToken)
        ));
    }
}

#[test]
fn old_authenticated_body_shapes_fail_generically() {
    let ring = confirm_ring(0x76, "confirm-active");
    let confirmation_nonce = MagicLinkConfirmNonce([0xaa; MAGIC_LINK_CONFIRM_NONCE_BYTES]);
    let valid = encode_confirm_body(&bindings(1_300), &confirmation_nonce);
    let binding_end = 1 + (3 * MAGIC_LINK_CONFIRM_BINDING_BYTES);

    let mut old_134_body = valid[..binding_end].to_vec();
    old_134_body.push(0);
    old_134_body.extend_from_slice(&valid[binding_end..]);
    let mut old_166_body = valid[..binding_end].to_vec();
    old_166_body.push(1);
    old_166_body.extend_from_slice(&[0x44; MAGIC_LINK_CONFIRM_BINDING_BYTES]);
    old_166_body.extend_from_slice(&valid[binding_end..]);
    let confirmation = "aa".repeat(MAGIC_LINK_CONFIRM_NONCE_BYTES);

    for old_body in [&old_134_body, &old_166_body] {
        let mut rng = PerCallRng::starting_at(0xa0);
        let cookie = mint_bound_cookie::<MagicLinkConfirmCookie, _>(
            old_body, &ring, &mut rng, 1_000, 1_000, 1_000,
        )
        .expect("low-level cookie mints");
        assert_eq!(
            verify_magic_link_confirm(&cookie, &confirmation, &ring, 1_000, 300).unwrap_err(),
            TokenError::InvalidToken
        );
    }
}

#[test]
fn confirm_purpose_rejects_other_purpose_cookie_and_has_tight_size_cap() {
    let confirm_ring = confirm_ring(0x77, "confirm-active");
    let other_ring = test_keyring::<OtherCookie>(0x77, "other-active");
    let mut rng = PerCallRng::starting_at(0xa0);
    let other_cookie = mint_bound_cookie::<OtherCookie, _>(
        b"other-body",
        &other_ring,
        &mut rng,
        1_000,
        1_000,
        1_000,
    )
    .expect("other cookie mints");
    let confirmation = "a0".repeat(MAGIC_LINK_CONFIRM_NONCE_BYTES);
    assert_eq!(
        verify_magic_link_confirm(&other_cookie, &confirmation, &confirm_ring, 1_000, 300)
            .unwrap_err(),
        TokenError::InvalidToken
    );

    let maximum_kid = kid(&"k".repeat(64));
    assert!(max_body_bytes::<MagicLinkConfirmCookie>(&maximum_kid) >= CONFIRM_BODY_BYTES);
    assert_eq!(MagicLinkConfirmCookie::MAX_BODY_BYTES, 256);
}

#[test]
fn confirm_cookie_verifies_across_active_to_verify_only_rotation() {
    let old_root = RootSecret::new([0x81; KEY_BYTES]);
    let old_key = old_root
        .derive_key::<MagicLinkConfirmCookie>(&kid("confirm-old"))
        .expect("derive old active");
    let old_ring = KeyRing::new(vec![KeySlot::active_with_windows(
        kid("confirm-old"),
        old_key,
        1_000,
        1_300,
    )])
    .expect("old ring");
    let minted = mint_confirm(&old_ring, 1_000, 1_300);

    let new_root = RootSecret::new([0x82; KEY_BYTES]);
    let new_key = new_root
        .derive_key::<MagicLinkConfirmCookie>(&kid("confirm-new"))
        .expect("derive new active");
    let old_key = old_root
        .derive_key::<MagicLinkConfirmCookie>(&kid("confirm-old"))
        .expect("derive old verify key");
    let rotated_ring = KeyRing::new(vec![
        KeySlot::active_with_windows(kid("confirm-new"), new_key, 1_300, 1_600),
        KeySlot::verify_only(kid("confirm-old"), old_key, 1_300),
    ])
    .expect("rotated ring");

    assert!(
        verify_magic_link_confirm(
            minted.cookie().as_secret_value(),
            minted.confirmation().as_value(),
            &rotated_ring,
            1_100,
            300,
        )
        .is_ok()
    );
    assert_eq!(
        verify_magic_link_confirm(
            minted.cookie().as_secret_value(),
            minted.confirmation().as_value(),
            &rotated_ring,
            1_301,
            300,
        )
        .unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn entropy_failures_propagate_from_both_nonce_draws() {
    let ring = confirm_ring(0x78, "confirm-active");

    let mut confirmation_failure = FailOnCallRng::failing_on(0);
    assert_eq!(
        mint_magic_link_confirm(bindings(1_300), &ring, &mut confirmation_failure, 1_000,)
            .unwrap_err(),
        TokenError::EntropyUnavailable
    );

    let mut branca_failure = FailOnCallRng::failing_on(1);
    assert_eq!(
        mint_magic_link_confirm(bindings(1_300), &ring, &mut branca_failure, 1_000,).unwrap_err(),
        TokenError::EntropyUnavailable
    );
}

#[test]
fn sensitive_debug_output_is_fully_redacted() {
    let ring = confirm_ring(0x79, "confirm-active");
    let input = bindings(1_300);
    assert_eq!(format!("{input:?}"), "MagicLinkConfirmBindings(..)");
    let minted = {
        let mut rng = PerCallRng::starting_at(0xa0);
        mint_magic_link_confirm(input, &ring, &mut rng, 1_000).expect("confirm mints")
    };
    let cookie_value = minted.cookie().as_secret_value().to_owned();
    let confirmation_value = minted.confirmation().as_value().to_owned();
    let minted_debug = format!("{minted:?}");
    let cookie_debug = format!("{:?}", minted.cookie());
    let confirmation_debug = format!("{:?}", minted.confirmation());

    assert_eq!(minted_debug, "MintedMagicLinkConfirm(..)");
    assert_eq!(cookie_debug, "MagicLinkConfirmCookieValue(..)");
    assert_eq!(confirmation_debug, "MagicLinkConfirmationValue(..)");
    assert!(!minted_debug.contains(&cookie_value));
    assert!(!minted_debug.contains(&confirmation_value));

    let verified = verify_magic_link_confirm(&cookie_value, &confirmation_value, &ring, 1_000, 300)
        .expect("confirm verifies");
    assert_eq!(format!("{verified:?}"), "VerifiedMagicLinkConfirm(..)");
    assert_eq!(
        format!("{:?}", verified.selector()),
        "ConfirmSelectorBinding(..)"
    );
    assert_eq!(
        format!("{:?}", verified.verifier()),
        "ConfirmVerifierBinding(..)"
    );
    assert_eq!(
        format!("{:?}", verified.account()),
        "ConfirmAccountBinding(..)"
    );
}

#[test]
fn cookie_token_size_is_bounded_by_confirm_body_cap() {
    let maximum_kid = kid(&"m".repeat(64));
    let maximum_body = max_body_bytes::<MagicLinkConfirmCookie>(&maximum_kid);
    let maximum_token = branca::max_token_chars_for_payload(
        1 + 4 + 1 + MagicLinkConfirmCookie::TOKEN_TYPE.len() + 1 + 64 + maximum_body,
    );
    assert!(maximum_body >= CONFIRM_BODY_BYTES);
    assert!(maximum_token < branca::MAX_TOKEN_BYTES);
}

/// Entropy table in docs/security.md: the confirm nonce needs at least 128
/// bits ("256 when cheap"). Each mint draws a fresh one.
#[test]
fn confirm_nonce_meets_entropy_minimum_and_is_fresh_per_mint() {
    const { assert!(MAGIC_LINK_CONFIRM_NONCE_BYTES * 8 >= 256) };
    let ring = confirm_ring(0x71, "confirm-active");
    let first = mint_confirm(&ring, 1_000, 1_300);
    assert_eq!(
        first.confirmation().as_value().len(),
        MAGIC_LINK_CONFIRM_NONCE_BYTES * 2
    );
    let mut rng = PerCallRng::starting_at(0xb0);
    let second =
        mint_magic_link_confirm(bindings(1_300), &ring, &mut rng, 1_000).expect("second mint");
    assert_ne!(
        first.confirmation().as_value(),
        second.confirmation().as_value()
    );
}

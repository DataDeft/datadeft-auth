//! Magic-link flow-cookie tests.

use dd_auth_token_core::branca;
use dd_auth_token_core::cookie::{max_body_bytes, mint_bound_cookie};
use dd_auth_token_core::keyring::{KEY_BYTES, KeyId, KeyRing, KeySlot, RootSecret};
use dd_auth_token_core::test_support::{FailOnCallRng, PerCallRng, test_keyring};
use zeroize::Zeroize;

use super::*;

/// Local non-flow purpose proving cross-purpose cookies are rejected.
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

fn flow_ring(root_byte: u8, kid_value: &str) -> KeyRing<MagicLinkFlowCookie> {
    test_keyring::<MagicLinkFlowCookie>(root_byte, kid_value)
}

fn bindings(expires_at_unix: u32) -> MagicLinkFlowBindings {
    MagicLinkFlowBindings::new(
        FlowSelectorBinding::new([0x11; MAGIC_LINK_FLOW_BINDING_BYTES]),
        FlowVerifierBinding::new([0x22; MAGIC_LINK_FLOW_BINDING_BYTES]),
        FlowAccountBinding::new([0x33; MAGIC_LINK_FLOW_BINDING_BYTES]),
        expires_at_unix,
    )
}

fn mint_flow(
    ring: &KeyRing<MagicLinkFlowCookie>,
    now_unix: u64,
    expires_at_unix: u32,
) -> MintedMagicLinkFlow {
    let mut rng = PerCallRng::starting_at(0xa0);
    mint_magic_link_flow(bindings(expires_at_unix), ring, &mut rng, now_unix).expect("flow mints")
}

#[test]
fn flow_purpose_constants_are_pinned() {
    assert_eq!(
        HKDF_INFO_MAGIC_LINK_FLOW_COOKIE_V1,
        b"auth/magic-link-flow-v1"
    );
    assert_eq!(
        MagicLinkFlowCookie::HKDF_INFO,
        HKDF_INFO_MAGIC_LINK_FLOW_COOKIE_V1
    );
    assert_eq!(TOKEN_TYPE_MAGIC_LINK_FLOW_COOKIE_V1, "ml-flow-v1");
    assert_eq!(
        MagicLinkFlowCookie::TOKEN_TYPE,
        TOKEN_TYPE_MAGIC_LINK_FLOW_COOKIE_V1
    );
    assert_eq!(MagicLinkFlowCookie::MAX_BODY_BYTES, 256);
    assert_eq!(MagicLinkFlowCookie::MAX_ABSOLUTE_AGE_SECS, 5 * 60);
}

#[test]
fn flow_hkdf_vector_is_pinned() {
    // HKDF-SHA256 with salt=None, IKM=[0x11; 32], L=32,
    // info = HKDF_INFO || 0x00 || kid. This vector pins the exact info framing;
    // changing it invalidates every flow cookie minted under the previous key.
    let root = RootSecret::new([0x11; KEY_BYTES]);
    let flow = root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-active"))
        .expect("derive flow");

    assert_eq!(
        hex::encode(flow.as_test_bytes()),
        "beb04add958a76123ba0d68f4a0294fae6afaaa918652871e78c45db00ab4746"
    );
}

#[test]
fn canonical_flow_body_vector_is_pinned() {
    let confirmation = MagicLinkFlowNonce([0xaa; MAGIC_LINK_FLOW_NONCE_BYTES]);

    let body = encode_flow_body(&bindings(1_000), &confirmation);
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
    assert_eq!(body.len(), FLOW_BODY_BYTES);
}

#[test]
fn flow_round_trips() {
    let ring = flow_ring(0x71, "flow-active");
    let minted = mint_flow(&ring, 1_000, 1_300);
    assert_eq!(
        minted.confirmation().as_value(),
        "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
    );
    let verified = verify_magic_link_flow(
        minted.cookie().as_secret_value(),
        minted.confirmation().as_value(),
        &ring,
        1_000,
        MAGIC_LINK_FLOW_MAX_AGE_SECS,
    )
    .expect("flow verifies");

    assert!(
        verified
            .selector()
            .matches_constant_time(&FlowSelectorBinding::new(
                [0x11; MAGIC_LINK_FLOW_BINDING_BYTES]
            ))
    );
    assert!(
        verified
            .verifier()
            .matches_constant_time(&FlowVerifierBinding::new(
                [0x22; MAGIC_LINK_FLOW_BINDING_BYTES]
            ))
    );
    assert!(
        verified
            .account()
            .matches_constant_time(&FlowAccountBinding::new(
                [0x33; MAGIC_LINK_FLOW_BINDING_BYTES]
            ))
    );
    assert_eq!(verified.expires_at_unix(), 1_300);
}

#[test]
fn binding_comparisons_are_explicit_and_constant_time() {
    let selector = FlowSelectorBinding::new([0x10; MAGIC_LINK_FLOW_BINDING_BYTES]);
    assert!(selector.matches_constant_time(&FlowSelectorBinding::new(
        [0x10; MAGIC_LINK_FLOW_BINDING_BYTES]
    )));
    assert!(!selector.matches_constant_time(&FlowSelectorBinding::new(
        [0x11; MAGIC_LINK_FLOW_BINDING_BYTES]
    )));

    let verifier = FlowVerifierBinding::new([0x20; MAGIC_LINK_FLOW_BINDING_BYTES]);
    assert!(verifier.matches_constant_time(&FlowVerifierBinding::new(
        [0x20; MAGIC_LINK_FLOW_BINDING_BYTES]
    )));
    assert!(!verifier.matches_constant_time(&FlowVerifierBinding::new(
        [0x21; MAGIC_LINK_FLOW_BINDING_BYTES]
    )));
}

#[test]
fn confirmation_is_canonical_and_must_match() {
    let ring = flow_ring(0x72, "flow-active");
    let minted = mint_flow(&ring, 1_000, 1_300);
    let cookie = minted.cookie().as_secret_value();
    let confirmation = minted.confirmation().as_value();

    assert_eq!(confirmation.len(), CONFIRMATION_HEX_BYTES);
    assert!(
        confirmation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    );
    assert!(verify_magic_link_flow(cookie, confirmation, &ring, 1_000, 300).is_ok());
    assert_eq!(
        verify_magic_link_flow(
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
        verify_magic_link_flow(cookie, &confirmation[..63], &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
    let wrong = "b0".repeat(MAGIC_LINK_FLOW_NONCE_BYTES);
    assert_eq!(
        verify_magic_link_flow(cookie, &wrong, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn flow_enforces_explicit_and_caller_freshness_boundaries() {
    let ring = flow_ring(0x73, "flow-active");
    let minted = mint_flow(&ring, 1_000, 1_300);
    let cookie = minted.cookie().as_secret_value();
    let confirmation = minted.confirmation().as_value();

    assert!(verify_magic_link_flow(cookie, confirmation, &ring, 1_300, 300).is_ok());
    assert_eq!(
        verify_magic_link_flow(cookie, confirmation, &ring, 1_301, 300).unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        verify_magic_link_flow(cookie, confirmation, &ring, 1_001, 100).unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        verify_magic_link_flow(cookie, confirmation, &ring, 1_000, 0).unwrap_err(),
        TokenError::InvalidToken
    );
    assert_eq!(
        verify_magic_link_flow(cookie, confirmation, &ring, 1_000, 301).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn mint_enforces_explicit_expiry_and_u32_time_bounds() {
    let ring = flow_ring(0x74, "flow-active");

    let mut rng = PerCallRng::starting_at(0xa0);
    assert_eq!(
        mint_magic_link_flow(bindings(999), &ring, &mut rng, 1_000).unwrap_err(),
        TokenError::InvalidTimestamp
    );
    let mut rng = PerCallRng::starting_at(0xa0);
    assert_eq!(
        mint_magic_link_flow(bindings(1_301), &ring, &mut rng, 1_000).unwrap_err(),
        TokenError::InvalidTimestamp
    );
    let mut rng = PerCallRng::starting_at(0xa0);
    assert!(mint_magic_link_flow(bindings(1_000), &ring, &mut rng, 1_000).is_ok());
    let mut rng = PerCallRng::starting_at(0xa0);
    assert_eq!(
        mint_magic_link_flow(bindings(u32::MAX), &ring, &mut rng, u64::from(u32::MAX) + 1,)
            .unwrap_err(),
        TokenError::InvalidTimestamp
    );
}

#[test]
fn future_dated_flow_cookie_beyond_skew_fails_generically() {
    let ring = flow_ring(0x7a, "flow-active");
    let confirmation_nonce = MagicLinkFlowNonce([0xa0; MAGIC_LINK_FLOW_NONCE_BYTES]);
    let mut body = encode_flow_body(&bindings(1_100), &confirmation_nonce);
    let mut rng = PerCallRng::starting_at(0xa0);
    let cookie =
        mint_bound_cookie::<MagicLinkFlowCookie, _>(&body, &ring, &mut rng, 1_100, 1_100, 1_100)
            .expect("future fixture mints");
    body.zeroize();
    let confirmation = "a0".repeat(MAGIC_LINK_FLOW_NONCE_BYTES);

    assert_eq!(
        verify_magic_link_flow(&cookie, &confirmation, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn tampered_cookie_and_unknown_key_fail_generically() {
    let ring = flow_ring(0x75, "flow-active");
    let minted = mint_flow(&ring, 1_000, 1_300);
    let confirmation = minted.confirmation().as_value();
    let mut tampered = minted.cookie().as_secret_value().as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).expect("cookie is ascii");
    assert_eq!(
        verify_magic_link_flow(&tampered, confirmation, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );

    let unknown = minted
        .cookie()
        .as_secret_value()
        .replacen("flow-active", "flow-missing", 1);
    assert_eq!(
        verify_magic_link_flow(&unknown, confirmation, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn malformed_and_old_flow_bodies_are_rejected() {
    let confirmation = MagicLinkFlowNonce([0xaa; MAGIC_LINK_FLOW_NONCE_BYTES]);
    let valid = encode_flow_body(&bindings(1_300), &confirmation);

    let mut bad_version = valid.clone();
    bad_version[0] = 2;
    let mut trailing = valid.clone();
    trailing.push(0);
    let truncated = &valid[..valid.len() - 1];

    let binding_end = 1 + (3 * MAGIC_LINK_FLOW_BINDING_BYTES);
    let mut old_134_body = valid[..binding_end].to_vec();
    old_134_body.push(0);
    old_134_body.extend_from_slice(&valid[binding_end..]);
    let mut old_166_body = valid[..binding_end].to_vec();
    old_166_body.push(1);
    old_166_body.extend_from_slice(&[0x44; MAGIC_LINK_FLOW_BINDING_BYTES]);
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
            decode_flow_body(malformed),
            Err(TokenError::InvalidToken)
        ));
    }
}

#[test]
fn old_authenticated_body_shapes_fail_generically() {
    let ring = flow_ring(0x76, "flow-active");
    let confirmation_nonce = MagicLinkFlowNonce([0xaa; MAGIC_LINK_FLOW_NONCE_BYTES]);
    let valid = encode_flow_body(&bindings(1_300), &confirmation_nonce);
    let binding_end = 1 + (3 * MAGIC_LINK_FLOW_BINDING_BYTES);

    let mut old_134_body = valid[..binding_end].to_vec();
    old_134_body.push(0);
    old_134_body.extend_from_slice(&valid[binding_end..]);
    let mut old_166_body = valid[..binding_end].to_vec();
    old_166_body.push(1);
    old_166_body.extend_from_slice(&[0x44; MAGIC_LINK_FLOW_BINDING_BYTES]);
    old_166_body.extend_from_slice(&valid[binding_end..]);
    let confirmation = "aa".repeat(MAGIC_LINK_FLOW_NONCE_BYTES);

    for old_body in [&old_134_body, &old_166_body] {
        let mut rng = PerCallRng::starting_at(0xa0);
        let cookie = mint_bound_cookie::<MagicLinkFlowCookie, _>(
            old_body, &ring, &mut rng, 1_000, 1_000, 1_000,
        )
        .expect("low-level cookie mints");
        assert_eq!(
            verify_magic_link_flow(&cookie, &confirmation, &ring, 1_000, 300).unwrap_err(),
            TokenError::InvalidToken
        );
    }
}

#[test]
fn flow_purpose_rejects_other_purpose_cookie_and_has_tight_size_cap() {
    let flow_ring = flow_ring(0x77, "flow-active");
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
    let confirmation = "a0".repeat(MAGIC_LINK_FLOW_NONCE_BYTES);
    assert_eq!(
        verify_magic_link_flow(&other_cookie, &confirmation, &flow_ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );

    let maximum_kid = kid(&"k".repeat(64));
    assert!(max_body_bytes::<MagicLinkFlowCookie>(&maximum_kid) >= FLOW_BODY_BYTES);
    assert_eq!(MagicLinkFlowCookie::MAX_BODY_BYTES, 256);
}

#[test]
fn flow_cookie_verifies_across_active_to_verify_only_rotation() {
    let old_root = RootSecret::new([0x81; KEY_BYTES]);
    let old_key = old_root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-old"))
        .expect("derive old active");
    let old_ring = KeyRing::new(vec![KeySlot::active_with_windows(
        kid("flow-old"),
        old_key,
        1_000,
        1_300,
    )])
    .expect("old ring");
    let minted = mint_flow(&old_ring, 1_000, 1_300);

    let new_root = RootSecret::new([0x82; KEY_BYTES]);
    let new_key = new_root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-new"))
        .expect("derive new active");
    let old_key = old_root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-old"))
        .expect("derive old verify key");
    let rotated_ring = KeyRing::new(vec![
        KeySlot::active_with_windows(kid("flow-new"), new_key, 1_300, 1_600),
        KeySlot::verify_only(kid("flow-old"), old_key, 1_300),
    ])
    .expect("rotated ring");

    assert!(
        verify_magic_link_flow(
            minted.cookie().as_secret_value(),
            minted.confirmation().as_value(),
            &rotated_ring,
            1_100,
            300,
        )
        .is_ok()
    );
    assert_eq!(
        verify_magic_link_flow(
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
    let ring = flow_ring(0x78, "flow-active");

    let mut confirmation_failure = FailOnCallRng::failing_on(0);
    assert_eq!(
        mint_magic_link_flow(bindings(1_300), &ring, &mut confirmation_failure, 1_000,)
            .unwrap_err(),
        TokenError::EntropyUnavailable
    );

    let mut branca_failure = FailOnCallRng::failing_on(1);
    assert_eq!(
        mint_magic_link_flow(bindings(1_300), &ring, &mut branca_failure, 1_000,).unwrap_err(),
        TokenError::EntropyUnavailable
    );
}

#[test]
fn sensitive_debug_output_is_fully_redacted() {
    let ring = flow_ring(0x79, "flow-active");
    let input = bindings(1_300);
    assert_eq!(format!("{input:?}"), "MagicLinkFlowBindings(..)");
    let minted = {
        let mut rng = PerCallRng::starting_at(0xa0);
        mint_magic_link_flow(input, &ring, &mut rng, 1_000).expect("flow mints")
    };
    let cookie_value = minted.cookie().as_secret_value().to_owned();
    let confirmation_value = minted.confirmation().as_value().to_owned();
    let minted_debug = format!("{minted:?}");
    let cookie_debug = format!("{:?}", minted.cookie());
    let confirmation_debug = format!("{:?}", minted.confirmation());

    assert_eq!(minted_debug, "MintedMagicLinkFlow(..)");
    assert_eq!(cookie_debug, "MagicLinkFlowCookieValue(..)");
    assert_eq!(confirmation_debug, "MagicLinkFlowConfirmation(..)");
    assert!(!minted_debug.contains(&cookie_value));
    assert!(!minted_debug.contains(&confirmation_value));

    let verified = verify_magic_link_flow(&cookie_value, &confirmation_value, &ring, 1_000, 300)
        .expect("flow verifies");
    assert_eq!(format!("{verified:?}"), "VerifiedMagicLinkFlow(..)");
    assert_eq!(
        format!("{:?}", verified.selector()),
        "FlowSelectorBinding(..)"
    );
    assert_eq!(
        format!("{:?}", verified.verifier()),
        "FlowVerifierBinding(..)"
    );
    assert_eq!(
        format!("{:?}", verified.account()),
        "FlowAccountBinding(..)"
    );
}

#[test]
fn cookie_token_size_is_bounded_by_flow_body_cap() {
    let maximum_kid = kid(&"m".repeat(64));
    let maximum_body = max_body_bytes::<MagicLinkFlowCookie>(&maximum_kid);
    let maximum_token = branca::max_token_chars_for_payload(
        1 + 4 + 1 + MagicLinkFlowCookie::TOKEN_TYPE.len() + 1 + 64 + maximum_body,
    );
    assert!(maximum_body >= FLOW_BODY_BYTES);
    assert!(maximum_token < branca::MAX_TOKEN_BYTES);
}

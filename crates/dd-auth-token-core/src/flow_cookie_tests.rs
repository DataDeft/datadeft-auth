//! Magic-link flow-cookie tests.

use core::num::NonZeroU32;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::*;
use crate::branca;
use crate::cookie::{max_body_bytes, mint_bound_cookie};
use crate::keyring::{KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret, SessionCookie};

struct PatternRng {
    calls: u8,
}

impl PatternRng {
    fn new() -> Self {
        Self { calls: 0 }
    }
}

impl RngCore for PatternRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).expect("pattern rng fills");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let value = 0xa0_u8.wrapping_add(self.calls);
        dest.fill(value);
        self.calls = self.calls.wrapping_add(1);
        Ok(())
    }
}

impl CryptoRng for PatternRng {}

struct FailOnCallRng {
    calls: usize,
    fail_on: usize,
}

impl RngCore for FailOnCallRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = self.try_fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let call = self.calls;
        self.calls += 1;
        if call == self.fail_on {
            let code = NonZeroU32::new(rand_core::Error::CUSTOM_START)
                .expect("rand_core custom error code is non-zero");
            return Err(rand_core::Error::from(code));
        }
        dest.fill(0x5a);
        Ok(())
    }
}

impl CryptoRng for FailOnCallRng {}

fn kid(value: &str) -> KeyId {
    KeyId::parse(value).expect("kid parses")
}

fn flow_ring(root_byte: u8, kid_value: &str) -> KeyRing<MagicLinkFlowCookie> {
    let root = RootSecret::new([root_byte; crate::keyring::KEY_BYTES]);
    let key = root
        .derive_key::<MagicLinkFlowCookie>(&kid(kid_value))
        .expect("derive flow key");
    KeyRing::new(kid(kid_value), vec![KeySlot::active(kid(kid_value), key)]).expect("flow ring")
}

fn bindings(client: bool, expires_at_unix: u32) -> MagicLinkFlowBindings {
    MagicLinkFlowBindings::new(
        FlowSelectorBinding::new([0x11; MAGIC_LINK_FLOW_BINDING_BYTES]),
        FlowVerifierBinding::new([0x22; MAGIC_LINK_FLOW_BINDING_BYTES]),
        FlowAccountBinding::new([0x33; MAGIC_LINK_FLOW_BINDING_BYTES]),
        client.then(|| FlowClientBinding::new([0x44; MAGIC_LINK_FLOW_BINDING_BYTES])),
        expires_at_unix,
    )
}

fn mint_flow(
    ring: &KeyRing<MagicLinkFlowCookie>,
    client: bool,
    now_unix: u64,
    expires_at_unix: u32,
) -> MintedMagicLinkFlow {
    let mut rng = PatternRng::new();
    mint_magic_link_flow(bindings(client, expires_at_unix), ring, &mut rng, now_unix)
        .expect("flow mints")
}

#[test]
fn canonical_flow_body_vectors_are_pinned() {
    let confirmation = MagicLinkFlowNonce([0xaa; MAGIC_LINK_FLOW_NONCE_BYTES]);

    let without_client = encode_flow_body(&bindings(false, 1_000), &confirmation);
    let expected_without = hex::decode(concat!(
        "01",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "00",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "000003e8"
    ))
    .expect("vector hex");
    assert_eq!(without_client, expected_without);
    assert_eq!(without_client.len(), BODY_WITHOUT_CLIENT_BYTES);

    let with_client = encode_flow_body(&bindings(true, 1_000), &confirmation);
    let expected_with = hex::decode(concat!(
        "01",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "01",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "000003e8"
    ))
    .expect("vector hex");
    assert_eq!(with_client, expected_with);
    assert_eq!(with_client.len(), BODY_WITH_CLIENT_BYTES);
}

#[test]
fn flow_round_trips_with_and_without_client_binding() {
    let ring = flow_ring(0x71, "flow-active");

    for has_client in [false, true] {
        let minted = mint_flow(&ring, has_client, 1_000, 1_300);
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
        assert_eq!(verified.client().is_some(), has_client);
        if let Some(client) = verified.client() {
            assert!(client.matches_constant_time(&FlowClientBinding::new(
                [0x44; MAGIC_LINK_FLOW_BINDING_BYTES]
            )));
        }
        assert_eq!(verified.expires_at_unix(), 1_300);
    }
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
    let minted = mint_flow(&ring, true, 1_000, 1_300);
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
    let minted = mint_flow(&ring, false, 1_000, 1_300);
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

    let mut rng = PatternRng::new();
    assert_eq!(
        mint_magic_link_flow(bindings(false, 999), &ring, &mut rng, 1_000).unwrap_err(),
        TokenError::InvalidTimestamp
    );
    let mut rng = PatternRng::new();
    assert_eq!(
        mint_magic_link_flow(bindings(false, 1_301), &ring, &mut rng, 1_000).unwrap_err(),
        TokenError::InvalidTimestamp
    );
    let mut rng = PatternRng::new();
    assert!(mint_magic_link_flow(bindings(false, 1_000), &ring, &mut rng, 1_000).is_ok());
    let mut rng = PatternRng::new();
    assert_eq!(
        mint_magic_link_flow(
            bindings(false, u32::MAX),
            &ring,
            &mut rng,
            u64::from(u32::MAX) + 1,
        )
        .unwrap_err(),
        TokenError::InvalidTimestamp
    );
}

#[test]
fn future_dated_flow_cookie_beyond_skew_fails_generically() {
    let ring = flow_ring(0x7a, "flow-active");
    let confirmation_nonce = MagicLinkFlowNonce([0xa0; MAGIC_LINK_FLOW_NONCE_BYTES]);
    let mut body = encode_flow_body(&bindings(false, 1_100), &confirmation_nonce);
    let mut rng = PatternRng::new();
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
    let minted = mint_flow(&ring, true, 1_000, 1_300);
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
fn malformed_flow_bodies_are_rejected_without_trailing_data() {
    let confirmation = MagicLinkFlowNonce([0xaa; MAGIC_LINK_FLOW_NONCE_BYTES]);
    let valid = encode_flow_body(&bindings(false, 1_300), &confirmation);

    let mut bad_version = valid.clone();
    bad_version[0] = 2;
    let mut bad_flag = valid.clone();
    bad_flag[CLIENT_FLAG_OFFSET] = 2;
    let mut trailing = valid.clone();
    trailing.push(0);
    let truncated = &valid[..valid.len() - 1];

    for malformed in [&bad_version[..], &bad_flag[..], &trailing[..], truncated] {
        assert!(matches!(
            decode_flow_body(malformed),
            Err(TokenError::InvalidToken)
        ));
    }
}

#[test]
fn malformed_authenticated_body_is_a_generic_verification_failure() {
    let ring = flow_ring(0x76, "flow-active");
    let mut rng = PatternRng::new();
    let malformed = vec![FLOW_BODY_V1; BODY_WITHOUT_CLIENT_BYTES - 1];
    let cookie = mint_bound_cookie::<MagicLinkFlowCookie, _>(
        &malformed, &ring, &mut rng, 1_000, 1_000, 1_000,
    )
    .expect("low-level cookie mints");
    let confirmation = "a0".repeat(MAGIC_LINK_FLOW_NONCE_BYTES);

    assert_eq!(
        verify_magic_link_flow(&cookie, &confirmation, &ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );
}

#[test]
fn flow_purpose_rejects_session_cookie_and_has_tight_size_cap() {
    let flow_ring = flow_ring(0x77, "flow-active");
    let session_root = RootSecret::new([0x77; crate::keyring::KEY_BYTES]);
    let session_key = session_root
        .derive_key::<SessionCookie>(&kid("session-active"))
        .expect("derive session key");
    let session_ring = KeyRing::new(
        kid("session-active"),
        vec![KeySlot::active(kid("session-active"), session_key)],
    )
    .expect("session ring");
    let mut rng = PatternRng::new();
    let session_cookie = mint_bound_cookie::<SessionCookie, _>(
        b"session",
        &session_ring,
        &mut rng,
        1_000,
        1_000,
        1_000,
    )
    .expect("session cookie mints");
    let confirmation = "a0".repeat(MAGIC_LINK_FLOW_NONCE_BYTES);
    assert_eq!(
        verify_magic_link_flow(&session_cookie, &confirmation, &flow_ring, 1_000, 300).unwrap_err(),
        TokenError::InvalidToken
    );

    let maximum_kid = kid(&"k".repeat(64));
    assert!(max_body_bytes::<MagicLinkFlowCookie>(&maximum_kid) >= BODY_WITH_CLIENT_BYTES);
    assert_eq!(MagicLinkFlowCookie::MAX_BODY_BYTES, 256);
}

#[test]
fn flow_cookie_verifies_across_active_to_verify_only_rotation() {
    let old_root = RootSecret::new([0x81; crate::keyring::KEY_BYTES]);
    let old_key = old_root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-old"))
        .expect("derive old active");
    let old_ring = KeyRing::new(
        kid("flow-old"),
        vec![KeySlot::active_with_windows(
            kid("flow-old"),
            old_key,
            1_000,
            1_300,
        )],
    )
    .expect("old ring");
    let minted = mint_flow(&old_ring, false, 1_000, 1_300);

    let new_root = RootSecret::new([0x82; crate::keyring::KEY_BYTES]);
    let new_key = new_root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-new"))
        .expect("derive new active");
    let old_key = old_root
        .derive_key::<MagicLinkFlowCookie>(&kid("flow-old"))
        .expect("derive old verify key");
    let rotated_ring = KeyRing::new(
        kid("flow-new"),
        vec![
            KeySlot::active_with_windows(kid("flow-new"), new_key, 1_300, 1_600),
            KeySlot::verify_only(kid("flow-old"), old_key, 1_300),
        ],
    )
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

    let mut confirmation_failure = FailOnCallRng {
        calls: 0,
        fail_on: 0,
    };
    assert_eq!(
        mint_magic_link_flow(
            bindings(false, 1_300),
            &ring,
            &mut confirmation_failure,
            1_000,
        )
        .unwrap_err(),
        TokenError::EntropyUnavailable
    );

    let mut branca_failure = FailOnCallRng {
        calls: 0,
        fail_on: 1,
    };
    assert_eq!(
        mint_magic_link_flow(bindings(false, 1_300), &ring, &mut branca_failure, 1_000,)
            .unwrap_err(),
        TokenError::EntropyUnavailable
    );
}

#[test]
fn sensitive_debug_output_is_fully_redacted() {
    let ring = flow_ring(0x79, "flow-active");
    let input = bindings(true, 1_300);
    assert_eq!(format!("{input:?}"), "MagicLinkFlowBindings(..)");
    let minted = {
        let mut rng = PatternRng::new();
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
    assert_eq!(
        format!("{:?}", verified.client().expect("client exists")),
        "FlowClientBinding(..)"
    );
}

#[test]
fn cookie_token_size_is_bounded_by_flow_body_cap() {
    let maximum_kid = kid(&"m".repeat(64));
    let maximum_body = max_body_bytes::<MagicLinkFlowCookie>(&maximum_kid);
    let maximum_token = branca::max_token_chars_for_payload(
        1 + 4 + 1 + MagicLinkFlowCookie::TOKEN_TYPE.len() + 1 + 64 + maximum_body,
    );
    assert!(maximum_body >= BODY_WITH_CLIENT_BYTES);
    assert!(maximum_token < branca::MAX_TOKEN_BYTES);
}

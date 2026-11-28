//! Test-only cross-language cookie fixture exchange; no production API changes.

use datadeft_auth_token_core::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring};
use datadeft_magic_link_core::{
    ConfirmAccountBinding, ConfirmSelectorBinding, ConfirmVerifierBinding,
    MagicLinkConfirmBindings, mint_magic_link_confirm, verify_magic_link_confirm,
};
use datadeft_magic_link_service::{
    MagicLinkConfirmCookie, SessionCookie, SessionId, decode_session_cookie_body,
    encode_session_cookie_body,
};

const NOW: u32 = 1_700_000_000;
const SID: &str = "sid-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
#[ignore = "fixture exchange driven by mise run compatibility-test"]
fn elixir_cookie_parity() {
    let dir =
        std::path::PathBuf::from(std::env::var_os("DD_AUTH_COOKIE_FIXTURES").expect("fixture dir"));
    let input = std::fs::read_to_string(dir.join("elixir.tsv")).expect("Elixir fixtures");
    let mut fields = input.trim_end_matches('\n').split('\t');
    let (session_value, confirm_value, nonce) = (
        fields.next().expect("session fixture"),
        fields.next().expect("confirm fixture"),
        fields.next().expect("nonce fixture"),
    );
    assert!(fields.next().is_none());
    let session_ring = test_keyring::<SessionCookie>(0x45, "session-active");
    let confirm_ring = test_keyring::<MagicLinkConfirmCookie>(0x11, "confirm-active");
    let now = u64::from(NOW);
    let session = parse_bound_cookie(session_value, &session_ring, now, MaxAge::fixed(60))
        .expect("Rust opens Elixir session cookie");
    let parsed = decode_session_cookie_body(session.body()).expect("session body");
    let sid = SessionId::parse(SID).expect("synthetic session id");
    assert_eq!(parsed.session_id, sid);
    assert_eq!(parsed.country.as_deref(), Some("HU"));
    assert_eq!(session.iat(), NOW - 5);
    assert_eq!(session.timestamp(), NOW);
    let confirm = verify_magic_link_confirm(confirm_value, nonce, &confirm_ring, now, 300)
        .expect("Rust opens Elixir confirm cookie");
    let selector = ConfirmSelectorBinding::new([0x11; 32]);
    let verifier = ConfirmVerifierBinding::new([0x22; 32]);
    let account = ConfirmAccountBinding::new([0x33; 32]);
    assert!(confirm.selector().matches_constant_time(&selector));
    assert!(confirm.verifier().matches_constant_time(&verifier));
    assert!(confirm.account().matches_constant_time(&account));
    assert_eq!(confirm.expires_at_unix(), NOW + 100);

    let body = encode_session_cookie_body(&sid, Some("HU")).expect("encode session body");
    let mut rng = PerCallRng::starting_at(0xA0);
    let session = mint_bound_cookie(&body, &session_ring, &mut rng, NOW, NOW - 5, now)
        .expect("Rust session fixture");
    let bindings = MagicLinkConfirmBindings::new(selector, verifier, account, NOW + 100);
    let confirm = mint_magic_link_confirm(bindings, &confirm_ring, &mut rng, now)
        .expect("Rust confirm fixture");
    std::fs::write(
        dir.join("rust.tsv"),
        format!(
            "{session}\t{}\t{}\n",
            confirm.cookie().as_secret_value(),
            confirm.confirmation().as_value()
        ),
    )
    .expect("write synthetic fixtures");
}

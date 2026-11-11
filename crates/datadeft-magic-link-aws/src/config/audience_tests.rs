use datadeft_auth_token_core::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_service::{
    Audience, KeyRing, MagicLinkConfirmCookie, SessionCookie, TokenError,
};

use super::*;

fn loaded(scope: Option<&str>, rotate: bool) -> LoadedAuthSecrets {
    let active = secret_json("active", 0x10, 1000, 4_000_000);
    let previous = secret_json("previous", 0x20, 1000, 4_000_000);
    let secrets = LoadedAuthSecrets::from_json(&active, rotate.then_some(previous.as_str()))
        .expect("loaded fixtures");
    match scope {
        Some(scope) => secrets
            .with_audience(&Audience::parse(scope).expect("audience"))
            .expect("bound"),
        None => secrets,
    }
}

fn assert_isolation<P: KeyPurpose>(select: fn(&LoadedAuthSecrets) -> &KeyRing<P>) {
    let secrets = [
        loaded(None, true),
        loaded(Some("api"), true),
        loaded(Some("admin"), true),
    ];
    for (issuer, source) in secrets.iter().enumerate() {
        let cookie = mint_bound_cookie(
            b"fixture",
            select(source),
            &mut CountingRng::starting_at(0),
            1000,
            1000,
            1000,
        )
        .expect("mint");
        for (verifier, target) in secrets.iter().enumerate() {
            let result = parse_bound_cookie(&cookie, select(target), 1001, MaxAge::fixed(60));
            if issuer == verifier {
                assert_eq!(result.expect("same audience").body(), b"fixture");
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    datadeft_auth_token_core::TokenError::InvalidToken
                );
            }
        }
    }
}

#[test]
fn startup_binding_isolates_both_real_cookie_purposes_with_no_fallback() {
    assert_isolation::<SessionCookie>(|loaded| &loaded.session_keyring);
    assert_isolation::<MagicLinkConfirmCookie>(|loaded| &loaded.confirm_keyring);
}

fn assert_rotation<P: KeyPurpose>(select: fn(&LoadedAuthSecrets) -> &KeyRing<P>) {
    let previous = secret_json("previous", 0x20, 1000, 4_000_000);
    let old = LoadedAuthSecrets::from_json(&previous, None)
        .expect("old")
        .with_audience(&Audience::parse("api").expect("audience"))
        .expect("scope");
    let cookie = mint_bound_cookie(
        b"fixture",
        select(&old),
        &mut CountingRng::starting_at(0),
        1000,
        1000,
        1000,
    )
    .expect("mint old");
    let api = loaded(Some("api"), true);
    let previous_kid = KeyId::parse("previous").expect("kid");
    assert_eq!(
        select(&api)
            .verification_key_at(&previous_kid, 1001)
            .expect("previous")
            .status(),
        KeyStatus::VerifyOnly
    );
    assert_eq!(
        select(&api)
            .minting_key_at(1000)
            .expect("active")
            .kid()
            .as_str(),
        "active"
    );
    assert_eq!(
        parse_bound_cookie(&cookie, select(&api), 1001, MaxAge::fixed(60))
            .expect("rotation works")
            .body(),
        b"fixture"
    );
    let admin = loaded(Some("admin"), true);
    assert!(parse_bound_cookie(&cookie, select(&admin), 1001, MaxAge::fixed(60)).is_err());
}

#[test]
fn startup_binding_scopes_previous_session_and_confirm_slots_too() {
    assert_rotation::<SessionCookie>(|loaded| &loaded.session_keyring);
    assert_rotation::<MagicLinkConfirmCookie>(|loaded| &loaded.confirm_keyring);
}

#[test]
fn startup_binding_rejects_rebinding_without_changing_independent_pow_material() {
    let unbound = loaded(None, true);
    let proof_before = unbound
        .pow_proof_keyring::<ProofLikePurpose>()
        .expect("proof");
    let bound = unbound
        .with_audience(&Audience::parse("api").expect("audience"))
        .expect("bound");
    let proof_after = bound
        .pow_proof_keyring::<ProofLikePurpose>()
        .expect("proof");
    assert_eq!(
        proof_before.active().key().as_test_bytes(),
        proof_after.active().key().as_test_bytes()
    );
    assert_eq!(bound.pow_challenge_secret.as_bytes(), &[0x14; 32]);
    assert_eq!(
        bound
            .previous_pow_challenge_secret
            .as_ref()
            .expect("previous")
            .as_bytes(),
        &[0x24; 32]
    );
    assert!(bound.previous_lookup_hmac_key.is_some());
    assert!(bound.previous_storage_hmac_key.is_some());
    // Rebinding keeps its typed core signal instead of collapsing to an
    // opaque adapter-internal failure.
    assert_eq!(
        bound
            .with_audience(&Audience::parse("admin").expect("audience"))
            .unwrap_err(),
        TokenError::KeyringMisconfigured
    );
}

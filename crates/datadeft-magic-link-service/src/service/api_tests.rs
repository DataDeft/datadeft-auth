//! Public API properties: Send futures, revocation delegation, redaction, entropy.

//! Service orchestration tests.

use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_core::selector_lookup_hmac;

use super::test_support::*;
use super::*;

/// Locks the `Send` policy from `crate::traits`: the service's composed call
/// future must stay `Send` so it can run on multi-threaded executors (Axum's
/// default Tokio runtime). This fails to compile if the service ever holds a
/// non-`Send` value across an await, independent of the per-trait bounds.
#[test]
fn service_call_futures_are_send() {
    fn assert_send<T: Send>(_: &T) {}

    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = CountingRng::starting_at(0);
    let key = lookup_key();
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config: config(),
    };
    assert_send(
        &service.begin_magic_link_landing(BeginMagicLinkLandingCommand::new(
            "mlv1.deadbeef.token".to_owned(),
        )),
    );
}

#[tokio::test]
async fn revoke_session_still_delegates_to_the_session_repository() {
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut rng = CountingRng::starting_at(0);
    let service = MagicLinkFlowService {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config: config(),
    };
    let session_id =
        SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("session id");
    service
        .revoke_session(&session_id)
        .await
        .expect("revoke session");
    assert_eq!(repository.revoked.borrow().as_slice(), &[session_id]);
}

#[test]
fn authentication_commands_and_success_outcomes_redact_sensitive_values() {
    let key = lookup_key();
    let candidate = candidate();
    let selector = selector_lookup_hmac(&key, token(VERIFIER).selector()).expect("selector hmac");
    let command = CommitMagicLinkAuthentication {
        magic_link: authentication_expectation(&selector, &candidate),
        now_unix: NOW,
        attempt_id: AuthenticationAttemptId::parse("aid_000102030405060708090a0b0c0d0e0f")
            .expect("attempt id"),
        user: MagicLinkAuthenticationUser::Existing {
            user_id: UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id"),
        },
        session_id: SessionId::parse(
            "sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("session id"),
        session_expires_at_unix: NOW + 300,
    };
    let debug = format!("{command:?}");
    assert!(!debug.contains("account@example.test"));
    assert!(!debug.contains(command.attempt_id.as_str()));
    assert!(!debug.contains(command.session_id.as_str()));
    assert!(!debug.contains(selector.as_storage_value()));
}

/// Entropy table in docs/security.md: session IDs need 256 bits, drawn
/// fresh for every session.
#[test]
fn session_ids_carry_256_bits_of_fresh_entropy() {
    let mut rng = CountingRng::starting_at(1);
    let first = generate_session_id(&mut rng).expect("session id");
    let second = generate_session_id(&mut rng).expect("session id");
    let hex = first.as_str().strip_prefix("sid_").expect("sid prefix");
    assert_eq!(hex.len() * 4, 256);
    assert!(hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(first.as_str(), second.as_str());
}

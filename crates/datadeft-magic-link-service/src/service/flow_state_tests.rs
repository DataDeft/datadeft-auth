//! The redirect landing mode's read-only flow-state step (CeleraTax #2).

use datadeft_auth_token_core::test_support::CountingRng;

use crate::types::ReadMagicLinkFlowStateCommand;

use super::test_support::*;
use super::*;

async fn read_state(
    repository: &FakeRepository,
    limiter: &AllowLimiter,
    clock: &FixedClock,
    confirm_cookie: &str,
) -> Result<crate::types::MagicLinkFlowState, MagicLinkFlowError> {
    let key = lookup_key();
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut rng = CountingRng::starting_at(200);
    MagicLinkFlowService {
        authentication: repository,
        sessions: repository,
        limiter,
        clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config: config(),
    }
    .read_magic_link_flow_state(ReadMagicLinkFlowStateCommand::new(
        confirm_cookie.to_owned(),
    ))
    .await
}

async fn landed(repository: &FakeRepository) -> (String, String) {
    *repository.candidate.borrow_mut() = Some(candidate());
    let mut rng = CountingRng::starting_at(0);
    let landing = begin_flow(
        repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        config(),
    )
    .await
    .expect("landing");
    (
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
    )
}

#[tokio::test]
async fn the_cookie_alone_yields_account_and_confirmation_repeatably() {
    let repository = FakeRepository::default();
    let (cookie, confirmation) = landed(&repository).await;

    for _ in 0..3 {
        let state = read_state(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW + 10),
            &cookie,
        )
        .await
        .expect("flow state");
        assert_eq!(
            state.account_identity().as_str(),
            "a\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}@example.test"
        );
        assert_eq!(state.confirmation_value(), confirmation);
        assert_eq!(format!("{state:?}"), "MagicLinkFlowState(..)");
    }
    // Reading never writes: nothing was committed, no session exists.
    assert!(repository.commands.borrow().is_empty());
    assert!(repository.sessions.borrow().is_empty());

    // The full redirect-mode round trip: landing, flow-state, then the same
    // confirmation POST as the server-rendered mode.
    let mut rng = CountingRng::starting_at(50);
    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW + 20),
        &mut rng,
        cookie,
        confirmation,
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect("confirmation");
    assert!(outcome.authentication().user_created());
}

#[tokio::test]
async fn every_unusable_state_is_the_same_generic_error() {
    let repository = FakeRepository::default();
    let (cookie, _) = landed(&repository).await;
    let unavailable = Err(MagicLinkServiceError::MagicLinkUnavailable);
    let public =
        |result: Result<_, MagicLinkFlowError>| result.map(|_| ()).map_err(|e| e.public_error());

    // Missing, malformed, or forged cookie.
    for bad in [
        "",
        "v1.flow-active.AAAA",
        &cookie.replacen("flow-active", "flow-other", 1),
    ] {
        let result = read_state(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            bad,
        )
        .await;
        assert_eq!(public(result), unavailable, "{bad:?}");
    }
    // Past the flow lifetime.
    let late = read_state(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW + config().magic_link_flow_ttl_secs + 1),
        &cookie,
    )
    .await;
    assert_eq!(public(late), unavailable);
    // Throttled per selector, like the landing.
    let limiter = AllowLimiter::default();
    limiter.deny_prefix("magic-link:landing:selector:");
    let throttled = read_state(&repository, &limiter, &FixedClock::at(NOW), &cookie).await;
    assert_eq!(public(throttled), unavailable);
    // The link was consumed meanwhile.
    if let Some(candidate) = repository.candidate.borrow_mut().as_mut() {
        candidate.consumed_at_unix = Some(NOW + 1);
    }
    let consumed = read_state(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW + 2),
        &cookie,
    )
    .await;
    assert_eq!(public(consumed), unavailable);
    // The link now belongs to another account than the cookie names.
    if let Some(candidate) = repository.candidate.borrow_mut().as_mut() {
        candidate.consumed_at_unix = None;
        candidate.email =
            datadeft_magic_link_core::NormalizedEmail::from_normalized("other@example.test")
                .expect("email");
    }
    let other = read_state(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW + 2),
        &cookie,
    )
    .await;
    assert_eq!(public(other), unavailable);
}

#[tokio::test]
async fn a_store_outage_is_unavailable_not_unusable() {
    let repository = FakeRepository::default();
    let (cookie, _) = landed(&repository).await;
    let limiter = AllowLimiter::default();
    limiter.fail_next(crate::DependencyError::Unavailable);
    let result = read_state(&repository, &limiter, &FixedClock::at(NOW), &cookie).await;
    assert_eq!(
        result.map(|_| ()).map_err(|error| error.public_error()),
        Err(MagicLinkServiceError::Unavailable)
    );
}

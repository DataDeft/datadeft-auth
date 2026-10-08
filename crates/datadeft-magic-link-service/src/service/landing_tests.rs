//! Scanner-safe landing: bounds, dummy work, limits, ordering, failures.

//! Service orchestration tests.

use datadeft_auth_token_core::test_support::CountingRng;

use crate::TemporaryAuthStateAction;
use crate::types::MAX_RAW_MAGIC_LINK_TOKEN_BYTES;

use super::test_support::*;
use super::*;

#[tokio::test]
async fn valid_landing_is_bounded_non_mutating_and_caps_expiry_to_record() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = CountingRng::starting_at(0);
    let outcome = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        config(),
    )
    .await
    .expect("valid landing");

    assert_eq!(clock.calls.get(), 1);
    assert_eq!(repository.candidate_reads.get(), 1);
    assert_eq!(repository.user_reads.get(), 0);
    assert!(repository.commands.borrow().is_empty());
    assert!(repository.sessions.borrow().is_empty());
    assert_eq!(verifier_comparison_count(), 1);
    assert_eq!(limiter.calls.get(), 1);
    assert!(limiter.checked.borrow()[0].starts_with("magic-link:landing:selector:"));
    assert_eq!(rng.calls(), 2);
    assert_eq!(outcome.cookie_max_age_secs(), 100);
    assert_eq!(outcome.account_identity().as_str(), "account@example.test");
    let debug = format!("{outcome:?}");
    assert!(!debug.contains(outcome.confirm_cookie_value()));
    assert!(!debug.contains(outcome.confirmation_value()));
    assert!(!debug.contains("account@example.test"));
}

#[tokio::test]
async fn landing_selector_miss_does_one_dummy_read_and_creates_no_flow_state() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = CountingRng::starting_at(0);
    let error = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        config(),
    )
    .await
    .expect_err("selector miss");

    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
    assert_eq!(clock.calls.get(), 1);
    assert_eq!(limiter.calls.get(), 1);
    assert!(limiter.checked.borrow()[0].starts_with("magic-link:landing:selector:"));
    assert_eq!(repository.candidate_reads.get(), 1);
    assert_eq!(verifier_comparison_count(), 1);
    assert_eq!(repository.user_reads.get(), 0);
    assert!(repository.commands.borrow().is_empty());
    assert!(repository.sessions.borrow().is_empty());
    assert_eq!(rng.calls(), 0);
}

#[tokio::test]
async fn landing_uses_configured_expiry_cap_and_rejects_expiry_at_now() {
    let repository = FakeRepository::default();
    let mut value = candidate();
    value.expires_at_unix = NOW + 250;
    *repository.candidate.borrow_mut() = Some(value);
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = CountingRng::starting_at(0);
    let mut policy = config();
    policy.magic_link_flow_ttl_secs = 30;
    let outcome = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        policy,
    )
    .await
    .expect("landing");
    assert_eq!(outcome.cookie_max_age_secs(), 30);

    let repository = FakeRepository::default();
    let mut value = candidate();
    value.expires_at_unix = NOW;
    *repository.candidate.borrow_mut() = Some(value);
    let error = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut CountingRng::starting_at(0),
        token(VERIFIER).as_secret_value().to_string(),
        config(),
    )
    .await
    .expect_err("expiry at current second is invalid");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
}

#[tokio::test]
async fn confirmation_accepts_authenticated_expiry_then_rejects_post_expiry() {
    for (elapsed, succeeds) in [(30_u64, true), (31_u64, false)] {
        let repository = FakeRepository::default();
        let mut value = candidate();
        value.expires_at_unix = NOW + 100;
        *repository.candidate.borrow_mut() = Some(value);
        let mut policy = config();
        policy.magic_link_flow_ttl_secs = 30;
        let mut rng = CountingRng::starting_at(0);
        let landing = begin_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            &mut rng,
            token(VERIFIER).as_secret_value().to_string(),
            policy.clone(),
        )
        .await
        .expect("landing");
        assert_eq!(landing.cookie_max_age_secs(), 30);

        let result = confirm_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW + elapsed),
            &mut rng,
            landing.confirm_cookie_value().to_owned(),
            landing.confirmation_value().to_owned(),
            Some("HU".to_owned()),
            policy,
        )
        .await;
        if succeeds {
            result.expect("authenticated expiry is inclusive in flow core");
            assert_eq!(repository.commands.borrow().len(), 1);
            assert_eq!(repository.sessions.borrow().len(), 1);
        } else {
            let error = result.expect_err("post-expiry confirmation");
            assert_eq!(
                error.public_error(),
                MagicLinkServiceError::MagicLinkUnavailable
            );
            assert_eq!(
                error.temporary_state_action(),
                TemporaryAuthStateAction::Clear
            );
            assert!(repository.commands.borrow().is_empty());
            assert!(repository.sessions.borrow().is_empty());
            assert!(
                repository
                    .candidate
                    .borrow()
                    .as_ref()
                    .is_some_and(|candidate| candidate.consumed_at_unix.is_none())
            );
        }
    }

    // Flow-core expiry is inclusive. If the same instant is also the backing
    // candidate expiry, the service's stricter candidate rule still rejects.
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let mut rng = CountingRng::starting_at(0);
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        config(),
    )
    .await
    .expect("candidate-capped landing");
    assert_eq!(landing.cookie_max_age_secs(), 100);
    let error = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW + 100),
        &mut rng,
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect_err("candidate expiry instant is invalid");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
    assert!(repository.commands.borrow().is_empty());
    assert!(repository.sessions.borrow().is_empty());
    assert!(
        repository
            .candidate
            .borrow()
            .as_ref()
            .is_some_and(|candidate| candidate.consumed_at_unix.is_none())
    );
}

#[tokio::test]
async fn malformed_and_oversized_landing_are_generic_and_do_no_limiter_or_repository_work() {
    for raw_token in [
        "malformed".to_owned(),
        "x".repeat(MAX_RAW_MAGIC_LINK_TOKEN_BYTES + 1),
    ] {
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        let limiter = AllowLimiter::default();
        let clock = FixedClock::at(NOW);
        let mut rng = CountingRng::starting_at(0);
        let error = begin_flow(&repository, &limiter, &clock, &mut rng, raw_token, config())
            .await
            .expect_err("invalid landing");
        assert_eq!(
            error.public_error(),
            MagicLinkServiceError::MagicLinkUnavailable
        );
        assert_eq!(
            error.temporary_state_action(),
            TemporaryAuthStateAction::Clear
        );
        assert_eq!(clock.calls.get(), 1);
        assert_eq!(limiter.calls.get(), 0);
        assert!(limiter.checked.borrow().is_empty());
        assert_eq!(repository.candidate_reads.get(), 0);
        assert_eq!(rng.calls(), 0);
    }
}

#[tokio::test]
async fn landing_selector_limit_is_generic_and_precedes_repository_work() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    limiter.deny_prefix("magic-link:landing:selector:");
    let error = begin_flow(
        &repository,
        &limiter,
        &FixedClock::at(NOW),
        &mut CountingRng::starting_at(0),
        token(VERIFIER).as_secret_value().to_string(),
        config(),
    )
    .await
    .expect_err("landing denial");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(limiter.calls.get(), 1);
    assert_eq!(repository.candidate_reads.get(), 0);
}

#[tokio::test]
async fn landing_invalid_config_precedes_clock_limiter_repository_and_entropy() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = CountingRng::starting_at(0);
    let mut policy = config();
    policy.magic_link_flow_ttl_secs = 0;
    let error = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        policy,
    )
    .await
    .expect_err("invalid configuration");
    assert_eq!(error.public_error(), MagicLinkServiceError::Internal);
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
    assert_eq!(clock.calls.get(), 0);
    assert_eq!(limiter.calls.get(), 0);
    assert_eq!(repository.candidate_reads.get(), 0);
    assert_eq!(rng.calls(), 0);
}

#[tokio::test]
async fn landing_dependency_and_entropy_failures_preserve_temporary_state() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    limiter.fail_next(DependencyError::Unavailable);
    let error = begin_flow(
        &repository,
        &limiter,
        &FixedClock::at(NOW),
        &mut CountingRng::starting_at(0),
        token(VERIFIER).as_secret_value().to_string(),
        config(),
    )
    .await
    .expect_err("limiter unavailable");
    assert_eq!(error.public_error(), MagicLinkServiceError::Unavailable);
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Preserve
    );

    for fail_at in [1, 2] {
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        let error = begin_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            &mut CountingRng::failing_at(fail_at),
            token(VERIFIER).as_secret_value().to_string(),
            config(),
        )
        .await
        .expect_err("flow entropy unavailable");
        assert_eq!(error.public_error(), MagicLinkServiceError::Unavailable);
        assert_eq!(
            error.temporary_state_action(),
            TemporaryAuthStateAction::Preserve
        );
        assert!(repository.commands.borrow().is_empty());
    }
}

//! Confirmation and the atomic commit: binding checks, replay, retries, limits.

//! Service orchestration tests.

use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_core::{
    LookupHmacKey, NormalizedEmail, selector_lookup_hmac, verifier_hash,
};

use crate::TemporaryAuthStateAction;
use crate::traits::MagicLinkAuthenticationRepository;
use crate::types::SessionRecord;

use super::test_support::*;
use super::*;

#[tokio::test]
async fn scanner_confirmation_atomically_authenticates_and_replay_clears() {
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
    .expect("landing");
    let cookie = landing.confirm_cookie_value().to_owned();
    let confirmation = landing.confirmation_value().to_owned();

    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        cookie.clone(),
        confirmation.clone(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect("confirmation");
    assert!(outcome.authentication().user_created());
    assert_eq!(outcome.authentication().country(), Some("HU"));
    assert!(
        outcome
            .authentication()
            .session_cookie_value()
            .starts_with("v1.active.")
    );
    assert_eq!(repository.sessions.borrow().len(), 1);
    assert_eq!(repository.commands.borrow().len(), 1);
    assert!(
        repository
            .candidate
            .borrow()
            .as_ref()
            .is_some_and(|value| value.consumed_at_unix == Some(NOW))
    );

    let replay = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        cookie,
        confirmation,
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect_err("replay");
    assert_eq!(
        replay.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(
        replay.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
    assert_eq!(repository.sessions.borrow().len(), 1);
}

#[tokio::test]
async fn confirmation_rejects_cookie_nonce_verifier_account_and_stale_mismatches() {
    for case in 0..8 {
        reset_verifier_comparison_count();
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
        .expect("landing");
        let mut cookie = landing.confirm_cookie_value().to_owned();
        let mut confirmation = landing.confirmation_value().to_owned();
        let mut confirm_now = NOW;
        match case {
            0 => cookie.push('x'),
            1 => confirmation.replace_range(0..1, "f"),
            2 => confirm_now = NOW + 101,
            3 => {
                let mut value = repository.candidate.borrow().clone().expect("candidate");
                value.verifier_hash =
                    verifier_hash(&lookup_key(), token(OTHER_VERIFIER).verifier())
                        .expect("other verifier");
                *repository.candidate.borrow_mut() = Some(value);
            }
            4 => {
                repository
                    .candidate
                    .borrow_mut()
                    .as_mut()
                    .expect("candidate")
                    .email = NormalizedEmail::parse("other@example.test").expect("email");
            }
            5 => {
                repository
                    .candidate
                    .borrow_mut()
                    .as_mut()
                    .expect("candidate")
                    .terms_version = "stale".to_owned();
            }
            6 => {
                repository
                    .candidate
                    .borrow_mut()
                    .as_mut()
                    .expect("candidate")
                    .privacy_version = "stale".to_owned();
            }
            _ => {
                repository
                    .candidate
                    .borrow_mut()
                    .as_mut()
                    .expect("candidate")
                    .consented_at_unix = 0;
            }
        }
        let error = confirm_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(confirm_now),
            &mut rng,
            cookie,
            confirmation,
            Some("HU".to_owned()),
            config(),
        )
        .await
        .expect_err("mismatched confirmation");
        assert_eq!(
            error.public_error(),
            MagicLinkServiceError::MagicLinkUnavailable,
            "case {case}"
        );
        assert_eq!(
            error.temporary_state_action(),
            TemporaryAuthStateAction::Clear
        );
        assert!(repository.commands.borrow().is_empty());
        assert!(repository.sessions.borrow().is_empty());
        if matches!(case, 3..=7) {
            assert_eq!(
                verifier_comparison_count(),
                2,
                "landing plus confirm case {case}"
            );
        }
    }
}

#[tokio::test]
async fn scanner_confirmation_disabled_user_is_generic_and_does_not_burn_link() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    *repository.user.borrow_mut() =
        Some(existing_user("usr_000102030405060708090a0b0c0d0e0f", true));
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
    .expect("landing");
    let error = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect_err("disabled user");

    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
    assert_eq!(repository.user_reads.get(), 1);
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
async fn scanner_confirmation_dependency_preserves_and_internal_clears() {
    for (commit_error, expected_public, expected_action, expected_commits) in [
        (
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
            MagicLinkServiceError::Unavailable,
            TemporaryAuthStateAction::Preserve,
            3,
        ),
        (
            CommitMagicLinkAuthenticationError::Internal,
            MagicLinkServiceError::Internal,
            TemporaryAuthStateAction::Clear,
            1,
        ),
    ] {
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        for _ in 0..expected_commits {
            repository
                .commit_results
                .borrow_mut()
                .push_back(commit_error);
        }
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
        .expect("landing");
        let error = confirm_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            &mut rng,
            landing.confirm_cookie_value().to_owned(),
            landing.confirmation_value().to_owned(),
            Some("HU".to_owned()),
            config(),
        )
        .await
        .expect_err("commit error");

        assert_eq!(error.public_error(), expected_public);
        assert_eq!(error.temporary_state_action(), expected_action);
        assert_eq!(repository.commands.borrow().len(), expected_commits);
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

#[tokio::test]
async fn confirmation_selector_miss_performs_one_dummy_comparison() {
    reset_verifier_comparison_count();
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
    .expect("landing");
    *repository.candidate.borrow_mut() = None;
    let error = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect_err("selector miss");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(verifier_comparison_count(), 2);
    assert_eq!(repository.candidate_reads.get(), 2);
    assert_eq!(repository.user_reads.get(), 0);
    assert!(repository.commands.borrow().is_empty());
}

#[tokio::test]
async fn scanner_confirmation_preserves_exact_retry_and_replan_behavior() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository
        .commit_results
        .borrow_mut()
        .push_back(CommitMagicLinkAuthenticationError::UserConflict);
    repository.install_winner_on_user_conflict.set(true);
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
    .expect("landing");
    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect("confirmation replan");
    assert!(!outcome.authentication().user_created());
    assert_eq!(repository.commands.borrow().len(), 2);
    assert_eq!(repository.candidate_reads.get(), 3);
    assert_eq!(repository.user_reads.get(), 2);
    assert_eq!(verifier_comparison_count(), 3);
    let commands = repository.commands.borrow();
    assert_eq!(commands[0].session_id, commands[1].session_id);
    assert_ne!(commands[0].attempt_id, commands[1].attempt_id);
}

#[tokio::test]
async fn scanner_confirmation_retries_ambiguous_commit_without_replanning() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository.apply_then_unavailable_once.set(true);
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
    .expect("landing");
    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect("exact retry");
    let commands = repository.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0], commands[1]);
    assert_eq!(repository.candidate_reads.get(), 2);
    assert_eq!(repository.user_reads.get(), 1);
    assert_eq!(repository.sessions.borrow().len(), 1);
    assert_eq!(
        repository.sessions.borrow()[0].session_id,
        *outcome.authentication().session_id()
    );
}

#[tokio::test]
async fn scanner_confirmation_replans_session_conflict_with_fresh_cookie_and_attempt() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository
        .commit_results
        .borrow_mut()
        .push_back(CommitMagicLinkAuthenticationError::SessionConflict);
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
    .expect("landing");
    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect("session replan");
    let commands = repository.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert_ne!(commands[0].session_id, commands[1].session_id);
    assert_ne!(commands[0].attempt_id, commands[1].attempt_id);
    assert_eq!(
        &commands[1].session_id,
        outcome.authentication().session_id()
    );
    assert_eq!(repository.candidate_reads.get(), 2);
    assert_eq!(repository.user_reads.get(), 1);
}

#[tokio::test]
async fn natural_create_user_session_collision_is_fully_atomic() {
    let repository = FakeRepository::default();
    let initial_candidate = candidate();
    *repository.candidate.borrow_mut() = Some(initial_candidate.clone());
    let colliding_id =
        SessionId::parse("sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("session id");
    let existing_session = SessionRecord {
        session_id: colliding_id.clone(),
        user_id: UserId::parse("usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").expect("user id"),
        email: NormalizedEmail::parse("existing@example.test").expect("email"),
        created_at_unix: NOW - 10,
        revoked_at_unix: None,
    };
    repository
        .sessions
        .borrow_mut()
        .push(existing_session.clone());
    let command = create_commit_command(colliding_id);

    assert_eq!(
        repository
            .commit_magic_link_authentication(&command)
            .await
            .unwrap_err(),
        CommitMagicLinkAuthenticationError::SessionConflict
    );
    // The candidate has no `==` (it holds a verifier hash); compare fields.
    let candidate = repository.candidate.borrow();
    let candidate = candidate.as_ref().expect("candidate kept");
    assert!(
        candidate
            .verifier_hash
            .matches_hash_constant_time(&initial_candidate.verifier_hash)
    );
    assert_eq!(candidate.email, initial_candidate.email);
    assert_eq!(candidate.expires_at_unix, initial_candidate.expires_at_unix);
    assert_eq!(
        candidate.consumed_at_unix,
        initial_candidate.consumed_at_unix
    );
    assert_eq!(candidate.terms_version, initial_candidate.terms_version);
    assert_eq!(candidate.privacy_version, initial_candidate.privacy_version);
    assert_eq!(
        candidate.consented_at_unix,
        initial_candidate.consented_at_unix
    );
    assert!(repository.user.borrow().is_none());
    assert_eq!(repository.sessions.borrow().as_slice(), &[existing_session]);
    assert!(repository.successful_command.borrow().is_none());
}

#[tokio::test]
async fn fake_authentication_reads_require_exact_selector_and_email_arguments() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    *repository.user.borrow_mut() =
        Some(existing_user("usr_000102030405060708090a0b0c0d0e0f", false));
    let wrong_selector =
        selector_lookup_hmac(&LookupHmacKey::new([0x99; 32]), token(VERIFIER).selector())
            .expect("wrong selector lookup");
    assert!(
        repository
            .find_magic_link_for_authentication(&wrong_selector)
            .await
            .expect("lookup")
            .is_none()
    );
    let wrong_email = NormalizedEmail::parse("wrong@example.test").expect("email");
    assert!(
        repository
            .find_user_for_authentication(&wrong_email)
            .await
            .expect("lookup")
            .is_none()
    );
    assert_eq!(
        repository.candidate_lookup_keys.borrow().as_slice(),
        &[wrong_selector]
    );
    assert_eq!(
        repository.user_lookup_emails.borrow().as_slice(),
        &[wrong_email]
    );
}

#[tokio::test]
async fn scanner_confirmation_malformed_and_selector_limits_are_generic_and_non_mutating() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let malformed_limiter = AllowLimiter::default();
    let malformed = confirm_flow(
        &repository,
        &malformed_limiter,
        &FixedClock::at(NOW),
        &mut CountingRng::starting_at(0),
        "malformed-confirm-cookie".to_owned(),
        "malformed-confirmation".to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect_err("malformed confirmation");
    assert_eq!(
        malformed.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(malformed_limiter.calls.get(), 0);
    assert!(malformed_limiter.checked.borrow().is_empty());
    assert_eq!(repository.candidate_reads.get(), 0);

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
    .expect("landing");
    let selector_limiter = AllowLimiter::default();
    selector_limiter.deny_prefix("magic-link:consume:selector:");
    let limited = confirm_flow(
        &repository,
        &selector_limiter,
        &FixedClock::at(NOW),
        &mut rng,
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect_err("selector limited confirmation");
    assert_eq!(
        limited.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(repository.candidate_reads.get(), 1);
    assert!(repository.commands.borrow().is_empty());
}

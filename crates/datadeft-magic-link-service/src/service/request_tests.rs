//! Magic-link requests: put-only storage, rate limits, dependency errors.

//! Service orchestration tests.

use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_core::NormalizedEmail;

use crate::types::RequestMagicLinkCommand;

use super::test_support::*;
use super::*;

#[tokio::test]
async fn request_side_repository_remains_put_only_and_stores_no_user_id() {
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let mut rng = CountingRng::starting_at(0);
    let mut service = MagicLinkRequestService {
        magic_links: &repository,
        limiter: &limiter,
        outbox: &outbox,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        config: config(),
    };
    service
        .request_magic_link(RequestMagicLinkCommand::new(
            NormalizedEmail::parse("account@example.test").expect("email"),
            true,
            true,
        ))
        .await
        .expect("request");
    assert_eq!(repository.request_records.borrow().len(), 1);
    assert_eq!(outbox.messages.borrow().len(), 1);
}

#[tokio::test]
async fn request_rate_limit_denials_are_generic_and_suppress_side_effects() {
    for denied_prefix in [
        "magic-link:request:email:short:",
        "magic-link:outbox:email:hourly:",
    ] {
        let repository = FakeRepository::default();
        let limiter = AllowLimiter::default();
        limiter.deny_prefix(denied_prefix);
        let outbox = FakeOutbox::default();
        let result = request(
            &repository,
            &limiter,
            &outbox,
            &mut CountingRng::starting_at(0),
            config(),
        )
        .await;
        assert_eq!(result, Ok(RequestMagicLinkOutcome));
        assert!(repository.request_records.borrow().is_empty());
        assert!(outbox.messages.borrow().is_empty());
    }
}

#[tokio::test]
async fn limiter_and_outbox_dependency_errors_remain_generic() {
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    limiter.fail_next(DependencyError::Unavailable);
    let outbox = FakeOutbox::default();
    let result = request(
        &repository,
        &limiter,
        &outbox,
        &mut CountingRng::starting_at(0),
        config(),
    )
    .await;
    assert_eq!(result.unwrap_err(), MagicLinkServiceError::Unavailable);
    assert!(repository.request_records.borrow().is_empty());
    assert!(outbox.messages.borrow().is_empty());

    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let outbox = FakeOutbox::default();
    outbox.fail_next(DependencyError::Unavailable);
    let result = request(
        &repository,
        &limiter,
        &outbox,
        &mut CountingRng::starting_at(0),
        config(),
    )
    .await;
    assert_eq!(result.unwrap_err(), MagicLinkServiceError::Unavailable);
    assert_eq!(repository.request_records.borrow().len(), 1);
    assert!(outbox.messages.borrow().is_empty());
}

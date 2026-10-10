//! Magic-link requests: put-only storage, rate limits, dependency errors.

//! Service orchestration tests.

use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_core::NormalizedEmail;

use crate::types::{RequestMagicLinkCommand, RequestMagicLinkOutcome, RequestThrottle};

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
    let outcome = service
        .request_magic_link(RequestMagicLinkCommand::new(
            NormalizedEmail::from_normalized("account@example.test").expect("email"),
            true,
            true,
        ))
        .await
        .expect("request");
    assert_eq!(outcome, RequestMagicLinkOutcome::Sent);
    assert_eq!(outcome.reason(), "magic_link_request_sent");
    assert_eq!(repository.request_records.borrow().len(), 1);
    assert_eq!(outbox.messages.borrow().len(), 1);
}

#[tokio::test]
async fn request_rate_limit_denials_are_generic_and_suppress_side_effects() {
    for (denied_prefix, throttle) in [
        (
            "magic-link:request:email:short:",
            RequestThrottle::EmailShortWindow,
        ),
        (
            "magic-link:request:email:daily:",
            RequestThrottle::EmailDaily,
        ),
        (
            "magic-link:outbox:email:hourly:",
            RequestThrottle::OutboxHourly,
        ),
        (
            "magic-link:outbox:email:daily:",
            RequestThrottle::OutboxDaily,
        ),
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
        // Internal only: the public response is the same generic 200.
        assert_eq!(result, Ok(RequestMagicLinkOutcome::Throttled(throttle)));
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

/// CeleraTax #5: the request's locale hint resolves against the configured
/// allowlist, reaches the outbox renderer, and is never stored.
#[tokio::test]
async fn locale_hint_reaches_the_outbox_resolved_and_is_never_stored() {
    async fn request(
        locales: Option<crate::LocaleAllowlist>,
        hint: Option<&str>,
    ) -> (Vec<String>, MagicLinkEmail) {
        let repository = FakeRepository::default();
        let outbox = FakeOutbox::default();
        let key = lookup_key();
        let mut rng = CountingRng::starting_at(0);
        let mut config = config();
        config.locales = locales;
        let mut command = RequestMagicLinkCommand::new(
            NormalizedEmail::from_normalized("account@example.test").expect("email"),
            true,
            true,
        );
        if let Some(hint) = hint {
            command = command.with_locale_hint(hint);
        }
        MagicLinkRequestService {
            magic_links: &repository,
            limiter: &AllowLimiter::default(),
            outbox: &outbox,
            clock: &FixedClock::at(NOW),
            rng: &mut rng,
            lookup_hmac_key: &key,
            config,
        }
        .request_magic_link(command)
        .await
        .expect("request");
        // Every stored field: a locale would have to show up here.
        let record = repository.request_records.borrow()[0].clone();
        let stored = vec![
            record.selector_lookup_hmac.as_storage_value().to_owned(),
            record.email.as_str().to_owned(),
            record.verifier_hash.as_storage_value().to_owned(),
            record.expires_at_unix.to_string(),
            format!("{:?}", record.consumed_at_unix),
            record.terms_version,
            record.privacy_version,
            record.consented_at_unix.to_string(),
        ];
        let email = outbox.messages.borrow()[0].clone();
        (stored, email)
    }
    let locales = || Some(crate::LocaleAllowlist::new("en", ["hu"]).expect("allowlist"));

    let (with_hu, email_hu) = request(locales(), Some("hu-HU")).await;
    assert_eq!(
        email_hu.locale.as_ref().map(crate::Locale::as_str),
        Some("hu")
    );
    let (with_free_text, email_default) = request(locales(), Some("<b>")).await;
    assert_eq!(
        email_default.locale.as_ref().map(crate::Locale::as_str),
        Some("en")
    );
    let (unconfigured, email_none) = request(None, Some("hu")).await;
    assert_eq!(email_none.locale, None);

    // The stored record is the same with or without a locale.
    assert_eq!(with_hu, with_free_text);
    assert_eq!(with_hu, unconfigured);
}

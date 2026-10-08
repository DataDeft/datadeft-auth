//! End-to-end request and scanner flows, races, and the limiter on the fake store.

//! Fake store integration tests.

use std::sync::Arc;

use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_core::{LookupHmacKey, NormalizedEmail, selector_lookup_hmac};
use datadeft_magic_link_service::{
    MagicLinkRequestService, MagicLinkServiceConfig, MagicLinkServiceError, RateLimitDecision,
    RateLimitKey, RateLimiter, SessionRepository, TemporaryAuthStateAction, UserId, UserRecord,
};
use tokio::sync::Barrier;

use super::test_support::*;
use super::*;

#[tokio::test]
async fn fake_store_round_trips_request_and_scanner_flow_without_raw_session_storage() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let mut rng = CountingRng::starting_at(0);
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");

    {
        let mut request = MagicLinkRequestService {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        };
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }

    let email = outbox.recorded().expect("recorded").remove(0);
    let selector_lookup = selector_lookup_hmac(&lookup_key, email.token.selector()).expect("hmac");
    assert!(
        store
            .magic_link_record(&selector_lookup)
            .expect("record")
            .is_some()
    );

    let flow = begin_flow(
        &store,
        &store,
        &store,
        &mut rng,
        email.token.as_secret_value().to_string(),
        config.clone(),
    )
    .await
    .expect("landing");

    assert_eq!(store.user_count().expect("user count after landing"), 0);
    assert_eq!(
        store.session_count().expect("session count after landing"),
        0
    );
    assert_eq!(
        store
            .magic_link_record(&selector_lookup)
            .expect("challenge after landing")
            .expect("stored challenge after landing")
            .consumed_at_unix,
        None
    );

    let outcome = confirm_flow(&store, &store, &store, &mut rng, flow, config)
        .await
        .expect("confirmation");
    let authentication = outcome.authentication();

    assert_eq!(store.user_count().expect("user count"), 1);
    assert_eq!(store.session_count().expect("session count"), 1);
    assert!(
        store
            .find_session(authentication.session_id(), 1_000)
            .await
            .expect("find")
            .is_some()
    );

    let storage_keys = store.session_storage_keys().expect("storage keys");
    assert_eq!(storage_keys.len(), 1);
    assert!(storage_keys[0].starts_with("sih_"));
    assert!(!storage_keys[0].contains(authentication.session_id().as_str()));
}

#[tokio::test]
async fn fake_scanner_confirmation_rejects_second_use() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let mut rng = CountingRng::starting_at(0);
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");

    {
        let mut request = MagicLinkRequestService {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        };
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }
    let token = outbox.recorded().expect("recorded")[0]
        .token
        .as_secret_value();
    let flow = begin_flow(
        &store,
        &store,
        &store,
        &mut rng,
        token.to_string(),
        config.clone(),
    )
    .await
    .expect("landing");

    confirm_flow(
        &store,
        &store,
        &store,
        &mut rng,
        flow.clone(),
        config.clone(),
    )
    .await
    .expect("first confirmation");
    let error = confirm_flow(&store, &store, &store, &mut rng, flow, config)
        .await
        .expect_err("replayed confirmation");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(store.session_count().expect("sessions"), 1);
}

// Multi-threaded so the racing confirmations really run in parallel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_fake_end_to_end_confirmation_race_has_one_session_and_generic_losers() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    let mut request_rng = CountingRng::starting_at(0);
    {
        let mut request = MagicLinkRequestService {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut request_rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        };
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }
    let sent = outbox.recorded().expect("recorded").remove(0);
    let selector_lookup =
        selector_lookup_hmac(&lookup_key, sent.token.selector()).expect("selector hmac");
    let flow = begin_flow(
        &store,
        &store,
        &AllowAllLimiter,
        &mut request_rng,
        sent.token.as_secret_value().to_string(),
        config.clone(),
    )
    .await
    .expect("landing");

    assert_eq!(store.user_count().expect("users after landing"), 0);
    assert_eq!(store.session_count().expect("sessions after landing"), 0);
    assert_eq!(
        store
            .magic_link_record(&selector_lookup)
            .expect("challenge after landing")
            .expect("stored challenge after landing")
            .consumed_at_unix,
        None
    );

    let commit_barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for start in 1_u8..=16 {
        let task_store = store.clone();
        let task_authentication = CommitBarrierAuthenticationRepository {
            store: task_store.clone(),
            barrier: Arc::clone(&commit_barrier),
        };
        let task_flow = flow.clone();
        let task_config = config.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = CountingRng::starting_at(start);
            confirm_flow(
                &task_authentication,
                &task_store,
                &AllowAllLimiter,
                &mut rng,
                task_flow,
                task_config,
            )
            .await
        }));
    }

    let mut successes = 0;
    let mut generic_losers = 0;
    for task in tasks {
        match task.await.expect("confirmation task") {
            Ok(_) => successes += 1,
            Err(error) if error.public_error() == MagicLinkServiceError::MagicLinkUnavailable => {
                assert_eq!(
                    error.temporary_state_action(),
                    TemporaryAuthStateAction::Clear
                );
                generic_losers += 1;
            }
            Err(other) => panic!("unexpected scrubbed confirmation error: {other}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(generic_losers, 15);
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(store.session_count().expect("sessions"), 1);
}

#[tokio::test]
async fn disable_between_landing_read_and_confirmation_commit_does_not_burn_link() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    let mut rng = CountingRng::starting_at(0);
    {
        let mut request = MagicLinkRequestService {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        };
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }
    let sent = outbox.recorded().expect("recorded").remove(0);
    let selector_lookup =
        selector_lookup_hmac(&lookup_key, sent.token.selector()).expect("selector hmac");
    let user_id = UserId::parse(USER_ID).expect("user id");
    store
        .seed_user(UserRecord {
            user_id: user_id.clone(),
            email: NormalizedEmail::parse("user@example.com").expect("email"),
            disabled: false,
            terms_version: Some("old-terms".to_owned()),
            privacy_version: Some("old-privacy".to_owned()),
            consented_at_unix: Some(100),
        })
        .expect("seed user");

    let flow = begin_flow(
        &store,
        &store,
        &store,
        &mut rng,
        sent.token.as_secret_value().to_string(),
        config.clone(),
    )
    .await
    .expect("landing");
    assert_eq!(store.user_count().expect("users after landing"), 1);
    assert_eq!(store.session_count().expect("sessions after landing"), 0);
    assert_eq!(
        store
            .magic_link_record(&selector_lookup)
            .expect("challenge after landing")
            .expect("stored challenge after landing")
            .consumed_at_unix,
        None
    );

    store
        .disable_user_before_next_commit(&user_id)
        .expect("install disable hook");
    let error = confirm_flow(&store, &store, &store, &mut rng, flow, config)
        .await
        .expect_err("disabled-at-commit confirmation");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
    assert_eq!(store.session_count().expect("sessions"), 0);
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(
        store
            .magic_link_record(&selector_lookup)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        None
    );
}

#[tokio::test]
async fn fake_limiter_uses_fixed_windows_from_service_clock() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let key = RateLimitKey::parse("magic-link:test:bucket").expect("rate key");

    assert_eq!(
        store
            .check_rate_limit(&key, 1, 60, 119)
            .await
            .expect("first hit"),
        RateLimitDecision::Allowed
    );
    assert_eq!(
        store
            .check_rate_limit(&key, 1, 60, 119)
            .await
            .expect("second same window"),
        RateLimitDecision::Denied
    );
    assert_eq!(
        store
            .check_rate_limit(&key, 1, 60, 120)
            .await
            .expect("new window"),
        RateLimitDecision::Allowed
    );
}

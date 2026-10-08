//! Fake store integration tests.

use std::sync::Arc;

use datadeft_auth_token_core::keyring::{KeyPurpose, KeyRing};
use datadeft_auth_token_core::test_support::{CountingRng, test_keyring_with_windows};
use datadeft_magic_link_core::{
    LookupHmac, LookupHmacKey, MagicLinkConfirmCookie, MagicLinkToken, NormalizedEmail,
    selector_lookup_hmac, verifier_hash,
};
use datadeft_magic_link_service::{
    AuthenticationAttemptId, BeginMagicLinkLandingCommand, Clock, CommitMagicLinkAuthentication,
    CommitMagicLinkAuthenticationError, ConfirmMagicLinkFlowCommand, ConfirmMagicLinkFlowOutcome,
    DependencyError, MagicLinkAuthenticationCandidate, MagicLinkAuthenticationExpectation,
    MagicLinkAuthenticationRepository, MagicLinkAuthenticationUser, MagicLinkFlowError,
    MagicLinkFlowService, MagicLinkRecord, MagicLinkRepository, MagicLinkRequestService,
    MagicLinkServiceConfig, MagicLinkServiceError, RateLimitDecision, RateLimitKey, RateLimiter,
    RequestMagicLinkCommand, SessionCookie, SessionId, SessionRecord, SessionRepository,
    TemporaryAuthStateAction, UserId, UserRecord,
};
use tokio::sync::Barrier;

use super::*;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(1_000)
    }
}

#[derive(Clone)]
struct CommitBarrierAuthenticationRepository {
    store: FakeDynamoDbAuthStore,
    barrier: Arc<Barrier>,
}

impl MagicLinkAuthenticationRepository for CommitBarrierAuthenticationRepository {
    async fn find_magic_link_for_authentication(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        self.store
            .find_magic_link_for_authentication(selector_lookup_hmac)
            .await
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        self.store.find_user_for_authentication(email).await
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        self.barrier.wait().await;
        self.store.commit_magic_link_authentication(command).await
    }
}

struct AllowAllLimiter;

impl RateLimiter for AllowAllLimiter {
    async fn check_rate_limit(
        &self,
        _key: &RateLimitKey,
        _limit: u32,
        _window_secs: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        Ok(RateLimitDecision::Allowed)
    }
}

fn session_keyring() -> KeyRing<SessionCookie> {
    test_keyring_with_windows(
        0x11,
        "active",
        10_000,
        10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
    )
}

fn confirm_keyring() -> KeyRing<MagicLinkConfirmCookie> {
    test_keyring_with_windows(0x22, "flow-active", 10_000, 10_300)
}

#[derive(Clone)]
struct TestFlowState {
    cookie: String,
    confirmation: String,
}

async fn begin_flow<Authentication, Sessions, Limiter>(
    authentication: &Authentication,
    sessions: &Sessions,
    limiter: &Limiter,
    rng: &mut CountingRng,
    raw_token: String,
    config: MagicLinkServiceConfig,
) -> Result<TestFlowState, MagicLinkFlowError>
where
    Authentication: MagicLinkAuthenticationRepository,
    Sessions: SessionRepository,
    Limiter: RateLimiter,
{
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService {
        authentication,
        sessions,
        limiter,
        clock: &FixedClock,
        rng,
        lookup_hmac_key: &lookup_key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config,
    };
    let landing = service
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(raw_token))
        .await?;
    Ok(TestFlowState {
        cookie: landing.confirm_cookie_value().to_owned(),
        confirmation: landing.confirmation_value().to_owned(),
    })
}

async fn confirm_flow<Authentication, Sessions, Limiter>(
    authentication: &Authentication,
    sessions: &Sessions,
    limiter: &Limiter,
    rng: &mut CountingRng,
    flow: TestFlowState,
    config: MagicLinkServiceConfig,
) -> Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError>
where
    Authentication: MagicLinkAuthenticationRepository,
    Sessions: SessionRepository,
    Limiter: RateLimiter,
{
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService {
        authentication,
        sessions,
        limiter,
        clock: &FixedClock,
        rng,
        lookup_hmac_key: &lookup_key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config,
    };
    let command = ConfirmMagicLinkFlowCommand::new(flow.cookie, flow.confirmation, None)?;
    service.confirm_magic_link_flow(command).await
}

fn command() -> RequestMagicLinkCommand {
    RequestMagicLinkCommand::new(
        NormalizedEmail::parse("user@example.com").expect("email"),
        true,
        true,
    )
}

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

const USER_ID: &str = "usr_000102030405060708090a0b0c0d0e0f";
const SESSION_ID: &str = "sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const OTHER_SESSION_ID: &str =
    "sid_101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const ATTEMPT_ID: &str = "aid_000102030405060708090a0b0c0d0e0f";
const OTHER_ATTEMPT_ID: &str = "aid_101112131415161718191a1b1c1d1e1f";

fn authentication_fixture(
    branch: MagicLinkAuthenticationUser,
    attempt_id: &str,
    session_id: &str,
) -> (
    FakeDynamoDbAuthStore,
    MagicLinkRecord,
    CommitMagicLinkAuthentication,
) {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x35; 32]));
    let lookup_key = LookupHmacKey::new([0x46; 32]);
    let token = MagicLinkToken::generate(&mut CountingRng::starting_at(0)).expect("token");
    let selector_lookup_hmac =
        selector_lookup_hmac(&lookup_key, token.selector()).expect("selector hmac");
    let record = MagicLinkRecord {
        selector_lookup_hmac: selector_lookup_hmac.clone(),
        email: NormalizedEmail::parse("atomic@example.test").expect("email"),
        verifier_hash: verifier_hash(&lookup_key, token.verifier()).expect("verifier hash"),
        expires_at_unix: 2_000,
        consumed_at_unix: None,
        terms_version: "terms-v1".to_owned(),
        privacy_version: "privacy-v1".to_owned(),
        consented_at_unix: 900,
    };
    let command = CommitMagicLinkAuthentication {
        magic_link: MagicLinkAuthenticationExpectation {
            selector_lookup_hmac,
            email: record.email.clone(),
            expires_at_unix: record.expires_at_unix,
            terms_version: record.terms_version.clone(),
            privacy_version: record.privacy_version.clone(),
            consented_at_unix: record.consented_at_unix,
        },
        now_unix: 1_000,
        attempt_id: AuthenticationAttemptId::parse(attempt_id).expect("attempt id"),
        user: branch,
        session_id: SessionId::parse(session_id).expect("session id"),
        session_expires_at_unix: 3_000,
    };
    (store, record, command)
}

async fn seed_challenge(store: &FakeDynamoDbAuthStore, record: MagicLinkRecord) {
    store
        .put_magic_link_if_absent(record)
        .await
        .expect("seed challenge");
}

fn user_record(disabled: bool) -> UserRecord {
    UserRecord {
        user_id: UserId::parse(USER_ID).expect("user id"),
        email: NormalizedEmail::parse("atomic@example.test").expect("email"),
        disabled,
        terms_version: Some("old-terms".to_owned()),
        privacy_version: Some("old-privacy".to_owned()),
        consented_at_unix: Some(100),
    }
}

#[tokio::test]
async fn aggregate_existing_user_commit_is_atomic_and_preserves_consent() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Existing {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store.seed_user(user_record(false)).expect("seed user");

    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("commit");

    let stored_user = store
        .find_user_for_authentication(&command.magic_link.email)
        .await
        .expect("find user")
        .expect("stored user");
    assert_eq!(stored_user.terms_version.as_deref(), Some("old-terms"));
    assert_eq!(stored_user.consented_at_unix, Some(100));
    assert_eq!(store.session_count().expect("sessions"), 1);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        Some(command.now_unix)
    );
    assert!(
        store
            .find_session(&command.session_id, command.session_expires_at_unix)
            .await
            .expect("find at expiry")
            .is_some()
    );
    assert!(
        store
            .find_session(&command.session_id, command.session_expires_at_unix + 1,)
            .await
            .expect("find after expiry")
            .is_none()
    );
}

#[tokio::test]
async fn aggregate_create_commit_derives_enabled_user_and_session() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;

    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("commit");

    let user = store
        .find_user_for_authentication(&command.magic_link.email)
        .await
        .expect("find user")
        .expect("created user");
    assert_eq!(user.user_id, user_id);
    assert!(!user.disabled);
    assert_eq!(user.terms_version.as_deref(), Some("terms-v1"));
    assert_eq!(user.privacy_version.as_deref(), Some("privacy-v1"));
    assert_eq!(user.consented_at_unix, Some(900));
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(store.session_count().expect("sessions"), 1);
    assert_eq!(
        store
            .user_session_index_entries(&user.user_id)
            .expect("index")[0]
            .expires_at_unix,
        command.session_expires_at_unix
    );
}

#[tokio::test]
async fn aggregate_rejects_stale_challenge_states_without_mutation() {
    for state in [
        "consumed",
        "expired",
        "consent",
        "zero-consent",
        "terms",
        "privacy",
    ] {
        let user_id = UserId::parse(USER_ID).expect("user id");
        let (store, mut record, mut command) = authentication_fixture(
            MagicLinkAuthenticationUser::Create { user_id },
            ATTEMPT_ID,
            SESSION_ID,
        );
        match state {
            "consumed" => record.consumed_at_unix = Some(999),
            "expired" => command.now_unix = 2_001,
            "consent" => command.magic_link.consented_at_unix += 1,
            "zero-consent" => {
                record.consented_at_unix = 0;
                command.magic_link.consented_at_unix = 0;
            }
            "terms" => command.magic_link.terms_version = "terms-v2".to_owned(),
            "privacy" => command.magic_link.privacy_version = "privacy-v2".to_owned(),
            _ => unreachable!("fixed test state"),
        }
        seed_challenge(&store, record).await;
        assert_eq!(
            store.commit_magic_link_authentication(&command).await,
            Err(CommitMagicLinkAuthenticationError::Rejected),
            "state {state}"
        );
        assert_eq!(store.user_count().expect("users"), 0);
        assert_eq!(store.session_count().expect("sessions"), 0);
    }
}

#[tokio::test]
async fn aggregate_disabled_user_and_user_conflicts_do_not_burn_link() {
    for disabled in [true, false] {
        let planned_id = if disabled {
            UserId::parse(USER_ID).expect("user id")
        } else {
            UserId::parse("usr_101112131415161718191a1b1c1d1e1f").expect("other user id")
        };
        let (store, record, command) = authentication_fixture(
            MagicLinkAuthenticationUser::Existing {
                user_id: planned_id,
            },
            ATTEMPT_ID,
            SESSION_ID,
        );
        seed_challenge(&store, record).await;
        store.seed_user(user_record(disabled)).expect("seed user");
        assert_eq!(
            store.commit_magic_link_authentication(&command).await,
            Err(CommitMagicLinkAuthenticationError::UserConflict)
        );
        assert_eq!(store.session_count().expect("sessions"), 0);
        assert_eq!(
            store
                .magic_link_record(&command.magic_link.selector_lookup_hmac)
                .expect("challenge")
                .expect("stored challenge")
                .consumed_at_unix,
            None
        );
    }
}

#[tokio::test]
async fn aggregate_session_conflict_is_atomic() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store
        .seed_session(
            SessionRecord {
                session_id: command.session_id.clone(),
                user_id,
                email: command.magic_link.email.clone(),
                created_at_unix: 500,
                revoked_at_unix: None,
            },
            command.session_expires_at_unix,
        )
        .expect("seed session collision");
    assert_eq!(
        store.commit_magic_link_authentication(&command).await,
        Err(CommitMagicLinkAuthenticationError::SessionConflict)
    );
    assert_eq!(store.user_count().expect("users"), 0);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        None
    );
}

#[tokio::test]
async fn aggregate_next_error_mapping_is_scrubbed_and_has_no_partial_mutation() {
    for (adapter_error, expected) in [
        (
            AwsAdapterError::ConditionalWriteFailed,
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
        ),
        (
            AwsAdapterError::RateLimited,
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
        ),
        (
            AwsAdapterError::DependencyUnavailable,
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
        ),
        (
            AwsAdapterError::Internal,
            CommitMagicLinkAuthenticationError::Internal,
        ),
    ] {
        let (store, record, command) = authentication_fixture(
            MagicLinkAuthenticationUser::Create {
                user_id: UserId::parse(USER_ID).expect("user id"),
            },
            ATTEMPT_ID,
            SESSION_ID,
        );
        seed_challenge(&store, record).await;
        store.set_next_error(adapter_error).expect("inject error");

        assert_eq!(
            store.commit_magic_link_authentication(&command).await,
            Err(expected)
        );
        assert_eq!(store.user_count().expect("users"), 0);
        assert_eq!(store.session_count().expect("sessions"), 0);
        assert_eq!(
            store
                .magic_link_record(&command.magic_link.selector_lookup_hmac)
                .expect("challenge")
                .expect("stored challenge")
                .consumed_at_unix,
            None
        );
    }
}

#[tokio::test]
async fn aggregate_pre_commit_dependency_failure_has_no_authentication_mutation() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store
        .fail_next_authentication_pre_commit()
        .expect("inject pre-commit failure");

    assert_eq!(
        store.commit_magic_link_authentication(&command).await,
        Err(CommitMagicLinkAuthenticationError::DependencyUnavailable)
    );
    assert_eq!(store.user_count().expect("users"), 0);
    assert_eq!(store.session_count().expect("sessions"), 0);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        None
    );
}

#[tokio::test]
async fn aggregate_rejects_session_expiry_before_now_without_mutation() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, mut command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    command.session_expires_at_unix = command.now_unix - 1;

    assert_eq!(
        store.commit_magic_link_authentication(&command).await,
        Err(CommitMagicLinkAuthenticationError::Internal)
    );
    assert_eq!(store.user_count().expect("users"), 0);
    assert_eq!(store.session_count().expect("sessions"), 0);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        None
    );
}

#[tokio::test]
async fn aggregate_attempt_id_is_exact_payload_idempotency_key() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("first commit");
    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("exact retry");
    assert_eq!(store.session_count().expect("sessions"), 1);

    let mut changed = command.clone();
    changed.session_expires_at_unix += 1;
    assert_eq!(
        store.commit_magic_link_authentication(&changed).await,
        Err(CommitMagicLinkAuthenticationError::Internal)
    );
}

// Multi-threaded so the racing confirmations really run in parallel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aggregate_replay_race_has_exactly_one_commit() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, base_command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;

    let mut tasks = Vec::new();
    for index in 0_u128..16 {
        let task_store = store.clone();
        let mut task_command = base_command.clone();
        task_command.attempt_id =
            AuthenticationAttemptId::parse(&format!("aid_{index:032x}")).expect("race attempt id");
        task_command.session_id =
            SessionId::parse(&format!("sid_{index:064x}")).expect("race session id");
        tasks.push(tokio::spawn(async move {
            task_store
                .commit_magic_link_authentication(&task_command)
                .await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("race task"));
    }
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| { **result == Err(CommitMagicLinkAuthenticationError::Rejected) })
            .count(),
        15
    );
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(store.session_count().expect("sessions"), 1);

    let mut replay = base_command;
    replay.attempt_id = AuthenticationAttemptId::parse(OTHER_ATTEMPT_ID).expect("replay attempt");
    replay.session_id = SessionId::parse(OTHER_SESSION_ID).expect("replay session");
    assert_eq!(
        store.commit_magic_link_authentication(&replay).await,
        Err(CommitMagicLinkAuthenticationError::Rejected)
    );
}

#[tokio::test]
async fn aggregate_reads_candidates_and_scrubs_store_debug() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record.clone()).await;
    let candidate = store
        .find_magic_link_for_authentication(&command.magic_link.selector_lookup_hmac)
        .await
        .expect("candidate")
        .expect("stored candidate");
    assert_eq!(candidate.email, record.email);
    assert!(
        candidate
            .verifier_hash
            .matches_hash_constant_time(&record.verifier_hash)
    );
    assert_eq!(format!("{store:?}"), "FakeDynamoDbAuthStore(..)");
}

// --- key rotation ----------------------------------------------------------

/// Request a link signed with `request_key`, then land and confirm it with a
/// flow service that uses `flow_key` and the optional previous key. Rate
/// limits are not under test here, so the limiter allows everything.
async fn login_with_keys(
    store: &FakeDynamoDbAuthStore,
    rng: &mut CountingRng,
    request_key: &LookupHmacKey,
    flow_key: &LookupHmacKey,
    previous_key: Option<&LookupHmacKey>,
) -> Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError> {
    let outbox = crate::FakeMagicLinkOutbox::default();
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    MagicLinkRequestService {
        magic_links: store,
        limiter: &AllowAllLimiter,
        outbox: &outbox,
        clock: &FixedClock,
        rng: &mut *rng,
        lookup_hmac_key: request_key,
        config: config.clone(),
    }
    .request_magic_link(command())
    .await
    .expect("request");
    let email = outbox.recorded().expect("recorded").remove(0);
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService {
        authentication: store,
        sessions: store,
        limiter: &AllowAllLimiter,
        clock: &FixedClock,
        rng,
        lookup_hmac_key: flow_key,
        previous_lookup_hmac_key: previous_key,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config,
    };
    let landing = service
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(
            email.token.as_secret_value().to_string(),
        ))
        .await?;
    let command = ConfirmMagicLinkFlowCommand::new(
        landing.confirm_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        None,
    )?;
    service.confirm_magic_link_flow(command).await
}

#[tokio::test]
async fn lookup_key_rotation_keeps_in_flight_links_usable() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let mut rng = CountingRng::starting_at(0);
    let old_key = LookupHmacKey::new([0x42; 32]);
    let new_key = LookupHmacKey::new([0x43; 32]);

    // A link minted under the old key fails once the key changes...
    assert!(
        login_with_keys(&store, &mut rng, &old_key, &new_key, None)
            .await
            .is_err()
    );
    // ...and succeeds when the old key is configured as previous.
    login_with_keys(&store, &mut rng, &old_key, &new_key, Some(&old_key))
        .await
        .expect("in-flight link confirms during rotation");
    // New links use the new key and need no fallback.
    login_with_keys(&store, &mut rng, &new_key, &new_key, Some(&old_key))
        .await
        .expect("new link confirms");
    assert_eq!(store.user_count().expect("users"), 1);
}

#[tokio::test]
async fn storage_key_rotation_keeps_users_and_sessions() {
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let before = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let first = login_with_keys(&before, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("first login");
    let session_id = first.authentication().session_id().clone();

    let after = before.sharing_data_with_keys(
        StorageHmacKey::new([0x25; 32]),
        Some(StorageHmacKey::new([0x24; 32])),
    );

    // The pre-rotation session is still found and can be revoked.
    assert!(
        after
            .find_session(&session_id, 1_000)
            .await
            .expect("find")
            .is_some()
    );

    // Logging in again finds the same account instead of creating a second.
    login_with_keys(&after, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("second login");
    assert_eq!(after.user_count().expect("users"), 1);

    after
        .revoke_session(&session_id, 1_000)
        .await
        .expect("revoke");
    assert!(
        after
            .find_session(&session_id, 1_000)
            .await
            .expect("find")
            .is_none()
    );

    // Login migrated the lookup, so the store works without the old key.
    let without_previous = after.sharing_data_with_keys(StorageHmacKey::new([0x25; 32]), None);
    let email = NormalizedEmail::parse("user@example.com").expect("email");
    assert!(
        without_previous
            .find_user_for_authentication(&email)
            .await
            .expect("find")
            .is_some()
    );
}

#[tokio::test]
async fn rekey_migrates_users_who_did_not_log_in_during_rotation() {
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let before = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    login_with_keys(&before, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("login");

    let after = before.sharing_data_with_keys(
        StorageHmacKey::new([0x25; 32]),
        Some(StorageHmacKey::new([0x24; 32])),
    );
    assert_eq!(after.rekey_email_lookups().expect("rekey"), 1);
    assert_eq!(after.rekey_email_lookups().expect("rekey is idempotent"), 0);

    // With the previous key dropped, the account is still found.
    let dropped = after.sharing_data_with_keys(StorageHmacKey::new([0x25; 32]), None);
    login_with_keys(&dropped, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("login after previous key dropped");
    assert_eq!(dropped.user_count().expect("users"), 1);
}

#[tokio::test]
async fn storage_key_change_without_previous_key_splits_accounts() {
    // The failure mode the previous-key fallback prevents.
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let before = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    login_with_keys(&before, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("first login");
    let unrotated = before.sharing_data_with_keys(StorageHmacKey::new([0x25; 32]), None);
    login_with_keys(&unrotated, &mut rng, &lookup_key, &lookup_key, None)
        .await
        .expect("second login");
    assert_eq!(unrotated.user_count().expect("users"), 2);
}

#[tokio::test]
async fn fake_user_status_fails_closed_for_unknown_users() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let unknown = UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id");
    assert!(!store.is_user_active(&unknown).await.expect("status"));
}

// --- admin -----------------------------------------------------------------

use datadeft_magic_link_service::{
    AdminAction, AdminActor, AdminError, AuthAdminService, SessionStatus,
};

fn admin_actor() -> AdminActor {
    AdminActor::new("admin@example.test", Some("support ticket".to_owned())).expect("actor")
}

fn admin_service<'a>(
    store: &'a FakeDynamoDbAuthStore,
    rng: &'a mut CountingRng,
) -> AuthAdminService<'a, FakeDynamoDbAuthStore, FixedClock, CountingRng> {
    AuthAdminService {
        admin: store,
        clock: &FixedClock,
        rng,
    }
}

/// Log the default test user in twice: two sessions, one user.
async fn store_with_two_sessions() -> (FakeDynamoDbAuthStore, UserId) {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let key = LookupHmacKey::new([0x42; 32]);
    let mut rng = CountingRng::starting_at(0);
    let first = login_with_keys(&store, &mut rng, &key, &key, None)
        .await
        .expect("first login");
    login_with_keys(&store, &mut rng, &key, &key, None)
        .await
        .expect("second login");
    (store, first.authentication().user_id().clone())
}

#[tokio::test]
async fn admin_queries_return_users_and_sessions() {
    let (store, user_id) = store_with_two_sessions().await;
    store.seed_user(user_record(false)).expect("second user");
    let mut rng = CountingRng::starting_at(50);
    let admin = admin_service(&store, &mut rng);

    let page = admin.list_users(None, 1).await.expect("page 1");
    assert_eq!(page.items.len(), 1);
    let rest = admin
        .list_users(page.next.as_ref(), 10)
        .await
        .expect("page 2");
    assert_eq!(rest.items.len(), 1);
    assert!(rest.next.is_none());

    let email = NormalizedEmail::parse("user@example.com").expect("email");
    let found = admin
        .find_user_by_email(&email)
        .await
        .expect("find")
        .expect("user exists");
    assert_eq!(found.user_id, user_id);
    assert!(!found.disabled);
    assert_eq!(
        admin
            .get_user(&user_id)
            .await
            .expect("get")
            .map(|user| user.email),
        Some(email)
    );

    let sessions = admin
        .list_sessions_for_user(&user_id)
        .await
        .expect("sessions");
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|(_, status)| *status == SessionStatus::Active)
    );
    for (session, _) in &sessions {
        assert!(session.handle.display_id().starts_with("sess_"));
        assert_eq!(session.user_id, user_id);
    }
    let active = admin.list_active_sessions(None, 10).await.expect("active");
    assert_eq!(active.items.len(), 2);
}

#[tokio::test]
async fn revoking_one_session_is_final_audited_and_owner_checked() {
    let (store, user_id) = store_with_two_sessions().await;
    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);
    let sessions = admin
        .list_sessions_for_user(&user_id)
        .await
        .expect("sessions");
    let handle = sessions[0].0.handle.clone();

    // Another user cannot be named as the owner.
    let stranger = UserId::parse("usr_ffffffffffffffffffffffffffffffff").expect("user id");
    assert_eq!(
        admin
            .revoke_session(&stranger, &handle, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::NotFound
    );

    admin
        .revoke_session(&user_id, &handle, &admin_actor())
        .await
        .expect("revoke");
    assert_eq!(
        admin
            .revoke_session(&user_id, &handle, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::AlreadyInState
    );

    let sessions = admin
        .list_sessions_for_user(&user_id)
        .await
        .expect("sessions");
    let (revoked, status) = sessions
        .iter()
        .find(|(session, _)| session.handle == handle)
        .expect("still listed: nothing is deleted");
    assert_eq!(*status, SessionStatus::Revoked);
    assert_eq!(revoked.revoked_by.as_deref(), Some("admin@example.test"));
    assert_eq!(
        admin
            .list_active_sessions(None, 10)
            .await
            .expect("active")
            .items
            .len(),
        1
    );

    let events = admin
        .list_admin_events(&user_id, None, 10)
        .await
        .expect("events");
    assert_eq!(events.items.len(), 1);
    let event = &events.items[0];
    assert_eq!(event.action, AdminAction::RevokeSession);
    assert_eq!(event.session.as_ref(), Some(&handle));
    assert_eq!(event.actor.reason(), Some("support ticket"));
    assert_eq!(event.at_unix, 1_000);
}

#[tokio::test]
async fn revoke_all_sessions_is_repeatable() {
    let (store, user_id) = store_with_two_sessions().await;
    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);

    assert_eq!(
        admin
            .revoke_all_sessions(&user_id, &admin_actor())
            .await
            .expect("revoke all"),
        2
    );
    assert_eq!(
        admin
            .revoke_all_sessions(&user_id, &admin_actor())
            .await
            .expect("again"),
        0
    );
    assert!(
        admin
            .list_active_sessions(None, 10)
            .await
            .expect("active")
            .items
            .is_empty()
    );
    // One audited event per revoked session.
    assert_eq!(
        admin
            .list_admin_events(&user_id, None, 10)
            .await
            .expect("events")
            .items
            .len(),
        2
    );
}

#[tokio::test]
async fn disabling_a_user_blocks_login_and_every_session_until_enabled() {
    let (store, user_id) = store_with_two_sessions().await;
    let key = LookupHmacKey::new([0x42; 32]);
    let mut login_rng = CountingRng::starting_at(100);
    let mut rng = CountingRng::starting_at(50);

    {
        let mut admin = admin_service(&store, &mut rng);
        assert_eq!(
            admin
                .disable_user(&user_id, &admin_actor())
                .await
                .expect("disable"),
            2
        );
        assert_eq!(
            admin
                .disable_user(&user_id, &admin_actor())
                .await
                .unwrap_err(),
            AdminError::AlreadyInState
        );
        let user = admin.get_user(&user_id).await.expect("get").expect("user");
        assert!(user.disabled);
        assert_eq!(user.disabled_at_unix, Some(1_000));
        assert_eq!(user.disabled_by.as_deref(), Some("admin@example.test"));
    }
    assert!(!store.is_user_active(&user_id).await.expect("status"));
    assert!(
        login_with_keys(&store, &mut login_rng, &key, &key, None)
            .await
            .is_err(),
        "a disabled user cannot log in"
    );

    {
        let mut admin = admin_service(&store, &mut rng);
        admin
            .enable_user(&user_id, &admin_actor())
            .await
            .expect("enable");
        assert_eq!(
            admin
                .enable_user(&user_id, &admin_actor())
                .await
                .unwrap_err(),
            AdminError::AlreadyInState
        );
        let user = admin.get_user(&user_id).await.expect("get").expect("user");
        assert!(!user.disabled);
        assert_eq!(user.disabled_by, None);
        // Revocation is final: enabling does not restore old sessions.
        assert!(
            admin
                .list_sessions_for_user(&user_id)
                .await
                .expect("sessions")
                .iter()
                .all(|(_, status)| *status == SessionStatus::Revoked)
        );

        let events = admin
            .list_admin_events(&user_id, None, 10)
            .await
            .expect("events");
        let actions: Vec<AdminAction> = events.items.iter().map(|event| event.action).collect();
        assert_eq!(
            actions,
            [
                AdminAction::EnableUser,
                AdminAction::RevokeSession,
                AdminAction::RevokeSession,
                AdminAction::DisableUser,
            ],
            "newest first"
        );
    }
    assert!(store.is_user_active(&user_id).await.expect("status"));
    login_with_keys(&store, &mut login_rng, &key, &key, None)
        .await
        .expect("an enabled user can log in again");
}

#[tokio::test]
async fn admin_mutations_on_unknown_users_report_not_found() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let mut rng = CountingRng::starting_at(50);
    let mut admin = admin_service(&store, &mut rng);
    let unknown = UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id");
    assert_eq!(
        admin
            .disable_user(&unknown, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::NotFound
    );
    assert_eq!(
        admin
            .enable_user(&unknown, &admin_actor())
            .await
            .unwrap_err(),
        AdminError::NotFound
    );
    assert_eq!(
        admin
            .revoke_all_sessions(&unknown, &admin_actor())
            .await
            .expect("nothing to revoke"),
        0
    );
}

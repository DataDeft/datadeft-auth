//! Fake store integration tests.

use std::sync::Arc;

use dd_auth_token_core::keyring::{KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret, SessionCookie};
use dd_magic_link_core::{
    LookupHmac, LookupHmacKey, MagicLinkToken, NormalizedEmail, selector_lookup_hmac, verifier_hash,
};
use dd_magic_link_service::{
    AuthenticationAttemptId, ClientKey, Clock, CommitMagicLinkAuthentication,
    CommitMagicLinkAuthenticationError, DependencyError, EmailLocale,
    MagicLinkAuthenticationCandidate, MagicLinkAuthenticationExpectation,
    MagicLinkAuthenticationRepository, MagicLinkAuthenticationUser, MagicLinkConsumeService,
    MagicLinkConsumeServiceInputs, MagicLinkRecord, MagicLinkRepository, MagicLinkRequestService,
    MagicLinkRequestServiceInputs, MagicLinkServiceConfig, MagicLinkServiceError,
    RateLimitDecision, RateLimitKey, RateLimiter, RequestMagicLinkCommand, SessionId,
    SessionRecord, SessionRepository, UserId, UserRecord,
};
use rand_core::{CryptoRng, RngCore};
use tokio::sync::Barrier;

use super::*;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(1_000)
    }
}

struct CounterRng {
    next: u8,
}

impl CounterRng {
    fn new() -> Self {
        Self { next: 0 }
    }
}

impl RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CounterRng {}

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
    let kid = KeyId::parse("active").expect("kid");
    let root = RootSecret::new([0x11; 32]);
    let key = root.derive_key::<SessionCookie>(&kid).expect("derive key");
    KeyRing::new(
        kid.clone(),
        vec![KeySlot::active_with_windows(
            kid,
            key,
            10_000,
            10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
        )],
    )
    .expect("keyring")
}

fn command() -> RequestMagicLinkCommand {
    RequestMagicLinkCommand::new(
        NormalizedEmail::parse("user@example.com").expect("email"),
        EmailLocale::En,
        true,
        true,
        Some(ClientKey::parse("client-1").expect("client key")),
    )
}

#[tokio::test]
async fn fake_store_round_trips_request_and_consume_without_raw_session_storage() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let mut rng = CounterRng::new();
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let session_keyring = session_keyring();
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");

    {
        let mut request = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        });
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

    let outcome = {
        let mut consume = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
            authentication: &store,
            sessions: &store,
            limiter: &store,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            session_keyring: &session_keyring,
            config,
        });
        consume
            .consume_magic_link_token(&email.token.as_secret_value(), None, None)
            .await
            .expect("consume")
    };

    assert_eq!(store.user_count().expect("user count"), 1);
    assert_eq!(store.session_count().expect("session count"), 1);
    assert!(
        store
            .find_session(&outcome.session_id, 1_000)
            .await
            .expect("find")
            .is_some()
    );

    let storage_keys = store.session_storage_keys().expect("storage keys");
    assert_eq!(storage_keys.len(), 1);
    assert!(storage_keys[0].starts_with("sih_"));
    assert!(!storage_keys[0].contains(outcome.session_id.as_str()));
}

#[tokio::test]
async fn fake_consume_rejects_second_use() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let mut rng = CounterRng::new();
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let session_keyring = session_keyring();
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");

    {
        let mut request = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        });
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }
    let token = outbox.recorded().expect("recorded")[0]
        .token
        .as_secret_value();

    let mut consume = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &store,
        sessions: &store,
        limiter: &store,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config,
    });
    consume
        .consume_magic_link_token(&token, None, None)
        .await
        .expect("first consume");
    assert!(
        consume
            .consume_magic_link_token(&token, None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn shared_fake_end_to_end_consume_race_has_one_session_and_generic_losers() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    let mut request_rng = CounterRng::new();
    {
        let mut request = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut request_rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        });
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }
    let token = outbox.recorded().expect("recorded")[0]
        .token
        .as_secret_value();

    let commit_barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for start in 1_u8..=16 {
        let task_store = store.clone();
        let task_authentication = CommitBarrierAuthenticationRepository {
            store: task_store.clone(),
            barrier: Arc::clone(&commit_barrier),
        };
        let task_token = token.clone();
        let task_config = config.clone();
        tasks.push(tokio::spawn(async move {
            let clock = FixedClock;
            let lookup_key = LookupHmacKey::new([0x42; 32]);
            let session_keyring = session_keyring();
            let mut rng = CounterRng { next: start };
            let limiter = AllowAllLimiter;
            let mut consume = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
                authentication: &task_authentication,
                sessions: &task_store,
                limiter: &limiter,
                clock: &clock,
                rng: &mut rng,
                lookup_hmac_key: &lookup_key,
                session_keyring: &session_keyring,
                config: task_config,
            });
            consume
                .consume_magic_link_token(&task_token, None, None)
                .await
        }));
    }

    let mut successes = 0;
    let mut generic_losers = 0;
    for task in tasks {
        match task.await.expect("consume task") {
            Ok(_) => successes += 1,
            Err(MagicLinkServiceError::MagicLinkUnavailable) => generic_losers += 1,
            Err(other) => panic!("unexpected scrubbed consume error: {other}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(generic_losers, 15);
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(store.session_count().expect("sessions"), 1);
}

#[tokio::test]
async fn concurrent_disable_between_read_and_commit_does_not_burn_link() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let session_keyring = session_keyring();
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    let mut rng = CounterRng::new();
    {
        let mut request = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        });
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }
    let token = outbox.recorded().expect("recorded")[0]
        .token
        .as_secret_value();
    let selector_lookup = selector_lookup_hmac(
        &lookup_key,
        outbox.recorded().expect("recorded")[0].token.selector(),
    )
    .expect("selector hmac");
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
    store
        .disable_user_before_next_commit(&user_id)
        .expect("install disable hook");

    let mut consume = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &store,
        sessions: &store,
        limiter: &store,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config,
    });
    assert_eq!(
        consume
            .consume_magic_link_token(&token, None, None)
            .await
            .unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
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
    let token = MagicLinkToken::generate(&mut CounterRng::new()).expect("token");
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

#[tokio::test]
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
    assert_eq!(candidate.verifier_hash, record.verifier_hash);
    assert_eq!(format!("{store:?}"), "FakeDynamoDbAuthStore(..)");
}

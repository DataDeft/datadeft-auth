//! Shared fixtures for the fake store's test modules.

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
    MagicLinkServiceConfig, RateLimitDecision, RateLimitKey, RateLimiter, RequestMagicLinkCommand,
    SessionCookie, SessionId, SessionRepository, UserId, UserRecord,
};
use tokio::sync::Barrier;

use super::*;

pub(super) struct FixedClock;

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(1_000)
    }
}

#[derive(Clone)]
pub(super) struct CommitBarrierAuthenticationRepository {
    pub(super) store: FakeDynamoDbAuthStore,
    pub(super) barrier: Arc<Barrier>,
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

pub(super) struct AllowAllLimiter;

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

pub(super) fn session_keyring() -> KeyRing<SessionCookie> {
    test_keyring_with_windows(
        0x11,
        "active",
        10_000,
        10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
    )
}

pub(super) fn confirm_keyring() -> KeyRing<MagicLinkConfirmCookie> {
    test_keyring_with_windows(0x22, "flow-active", 10_000, 10_300)
}

#[derive(Clone)]
pub(super) struct TestFlowState {
    pub(super) cookie: String,
    pub(super) confirmation: String,
}

pub(super) async fn begin_flow<Authentication, Sessions, Limiter>(
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

pub(super) async fn confirm_flow<Authentication, Sessions, Limiter>(
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

pub(super) fn command() -> RequestMagicLinkCommand {
    RequestMagicLinkCommand::new(
        NormalizedEmail::parse("user@example.com").expect("email"),
        true,
        true,
    )
}

pub(super) const USER_ID: &str = "usr_000102030405060708090a0b0c0d0e0f";
pub(super) const SESSION_ID: &str =
    "sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub(super) const OTHER_SESSION_ID: &str =
    "sid_101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
pub(super) const ATTEMPT_ID: &str = "aid_000102030405060708090a0b0c0d0e0f";
pub(super) const OTHER_ATTEMPT_ID: &str = "aid_101112131415161718191a1b1c1d1e1f";

pub(super) fn authentication_fixture(
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

pub(super) async fn seed_challenge(store: &FakeDynamoDbAuthStore, record: MagicLinkRecord) {
    store
        .put_magic_link_if_absent(record)
        .await
        .expect("seed challenge");
}

pub(super) fn user_record(disabled: bool) -> UserRecord {
    UserRecord {
        user_id: UserId::parse(USER_ID).expect("user id"),
        email: NormalizedEmail::parse("atomic@example.test").expect("email"),
        disabled,
        terms_version: Some("old-terms".to_owned()),
        privacy_version: Some("old-privacy".to_owned()),
        consented_at_unix: Some(100),
    }
}

// --- key rotation ----------------------------------------------------------

/// Request a link signed with `request_key`, then land and confirm it with a
/// flow service that uses `flow_key` and the optional previous key. Rate
/// limits are not under test here, so the limiter allows everything.
pub(super) async fn login_with_keys(
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

/// A clock pinned to one instant, for calls at a time other than [`FixedClock`].
pub(super) struct At(pub(super) u64);

impl Clock for At {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(self.0)
    }
}

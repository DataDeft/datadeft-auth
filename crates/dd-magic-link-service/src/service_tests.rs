//! Service orchestration tests.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::num::NonZeroU32;

use dd_auth_token_core::keyring::{
    KeyId, KeyPurpose, KeyRing, KeySlot, MagicLinkFlowCookie, RootSecret, SessionCookie,
};
use dd_magic_link_core::{
    LookupHmac, LookupHmacKey, MagicLinkToken, NormalizedEmail, selector_lookup_hmac, verifier_hash,
};
use rand_core::{CryptoRng, RngCore};

use super::*;
use crate::TemporaryAuthStateAction;
use crate::config::MagicLinkServiceConfig;
use crate::traits::{
    Clock, MagicLinkAuthenticationRepository, MagicLinkOutbox, MagicLinkRepository,
    SessionRepository,
};
use crate::types::{
    EmailLocale, MAX_RAW_MAGIC_LINK_TOKEN_BYTES, RequestMagicLinkCommand, SessionRecord,
};

const NOW: u64 = 1_000;
const SELECTOR: &str = "000102030405060708090a0b0c0d0e0f";
const VERIFIER: &str = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const OTHER_VERIFIER: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct TestRng {
    next: u8,
    calls: usize,
    fail_at: Option<usize>,
}

impl TestRng {
    fn working() -> Self {
        Self {
            next: 0,
            calls: 0,
            fail_at: None,
        }
    }

    fn failing_at(call: usize) -> Self {
        Self {
            next: 0,
            calls: 0,
            fail_at: Some(call),
        }
    }

    fn fill_pattern(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.calls += 1;
        self.fill_pattern(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.calls += 1;
        if self.fail_at == Some(self.calls) {
            return Err(rand_core::Error::from(
                NonZeroU32::new(1).expect("nonzero error code"),
            ));
        }
        self.fill_pattern(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

struct FixedClock {
    now: u64,
    calls: Cell<usize>,
}

impl FixedClock {
    fn at(now: u64) -> Self {
        Self {
            now,
            calls: Cell::new(0),
        }
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.now)
    }
}

#[derive(Default)]
struct AllowLimiter {
    calls: Cell<usize>,
    checked: RefCell<Vec<String>>,
    denied_prefixes: RefCell<Vec<String>>,
    next_error: Cell<Option<DependencyError>>,
}

impl AllowLimiter {
    fn deny_prefix(&self, prefix: &str) {
        self.denied_prefixes.borrow_mut().push(prefix.to_owned());
    }

    fn fail_next(&self, error: DependencyError) {
        self.next_error.set(Some(error));
    }
}

impl RateLimiter for AllowLimiter {
    async fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        _limit: u32,
        _window_secs: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        self.calls.set(self.calls.get() + 1);
        self.checked.borrow_mut().push(key.as_str().to_owned());
        if let Some(error) = self.next_error.take() {
            return Err(error);
        }
        if self
            .denied_prefixes
            .borrow()
            .iter()
            .any(|prefix| key.as_str().starts_with(prefix))
        {
            Ok(RateLimitDecision::Denied)
        } else {
            Ok(RateLimitDecision::Allowed)
        }
    }
}

#[derive(Default)]
struct FakeRepository {
    candidate: RefCell<Option<MagicLinkAuthenticationCandidate>>,
    user: RefCell<Option<UserRecord>>,
    commands: RefCell<Vec<CommitMagicLinkAuthentication>>,
    commit_results: RefCell<VecDeque<CommitMagicLinkAuthenticationError>>,
    successful_command: RefCell<Option<CommitMagicLinkAuthentication>>,
    apply_then_unavailable_once: Cell<bool>,
    sessions: RefCell<Vec<SessionRecord>>,
    request_records: RefCell<Vec<MagicLinkRecord>>,
    candidate_reads: Cell<usize>,
    candidate_lookup_keys: RefCell<Vec<LookupHmac>>,
    user_reads: Cell<usize>,
    user_lookup_emails: RefCell<Vec<NormalizedEmail>>,
    revoked: RefCell<Vec<SessionId>>,
    install_winner_on_user_conflict: Cell<bool>,
}

impl MagicLinkRepository for FakeRepository {
    async fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> Result<(), DependencyError> {
        self.request_records.borrow_mut().push(record);
        Ok(())
    }
}

impl MagicLinkAuthenticationRepository for FakeRepository {
    async fn find_magic_link_for_authentication(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        self.candidate_reads.set(self.candidate_reads.get() + 1);
        self.candidate_lookup_keys
            .borrow_mut()
            .push(selector_lookup_hmac.clone());
        if selector_lookup_hmac != &expected_selector_lookup() {
            return Ok(None);
        }
        Ok(self.candidate.borrow().clone())
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        self.user_reads.set(self.user_reads.get() + 1);
        self.user_lookup_emails.borrow_mut().push(email.clone());
        if !self
            .candidate
            .borrow()
            .as_ref()
            .is_some_and(|candidate| candidate.email == *email)
        {
            return Ok(None);
        }
        Ok(self.user.borrow().clone())
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        self.commands.borrow_mut().push(command.clone());

        if let Some(successful) = self.successful_command.borrow().as_ref() {
            if successful.attempt_id == command.attempt_id {
                return if successful == command {
                    Ok(())
                } else {
                    Err(CommitMagicLinkAuthenticationError::Internal)
                };
            }
        }

        if let Some(error) = self.commit_results.borrow_mut().pop_front() {
            if error == CommitMagicLinkAuthenticationError::UserConflict
                && self.install_winner_on_user_conflict.replace(false)
            {
                *self.user.borrow_mut() =
                    Some(existing_user("usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false));
            }
            return Err(error);
        }

        let candidate = self
            .candidate
            .borrow()
            .clone()
            .ok_or(CommitMagicLinkAuthenticationError::Rejected)?;
        if candidate.consumed_at_unix.is_some()
            || candidate.email != command.magic_link.email
            || candidate.expires_at_unix != command.magic_link.expires_at_unix
            || candidate.terms_version != command.magic_link.terms_version
            || candidate.privacy_version != command.magic_link.privacy_version
            || candidate.consented_at_unix != command.magic_link.consented_at_unix
            || candidate.expires_at_unix < command.now_unix
            || candidate.consented_at_unix == 0
        {
            return Err(CommitMagicLinkAuthenticationError::Rejected);
        }

        let (user_id, created_user) = match &command.user {
            MagicLinkAuthenticationUser::Existing { user_id } => {
                let users = self.user.borrow();
                let user = users
                    .as_ref()
                    .ok_or(CommitMagicLinkAuthenticationError::UserConflict)?;
                if user.user_id != *user_id || user.email != candidate.email || user.disabled {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                (user_id.clone(), None)
            }
            MagicLinkAuthenticationUser::Create { user_id } => {
                if self.user.borrow().is_some() {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                (
                    user_id.clone(),
                    Some(UserRecord {
                        user_id: user_id.clone(),
                        email: candidate.email.clone(),
                        disabled: false,
                        terms_version: Some(candidate.terms_version.clone()),
                        privacy_version: Some(candidate.privacy_version.clone()),
                        consented_at_unix: Some(candidate.consented_at_unix),
                    }),
                )
            }
        };

        if self
            .sessions
            .borrow()
            .iter()
            .any(|session| session.session_id == command.session_id)
        {
            return Err(CommitMagicLinkAuthenticationError::SessionConflict);
        }
        let session = SessionRecord {
            session_id: command.session_id.clone(),
            user_id,
            email: candidate.email,
            created_at_unix: command.now_unix,
            revoked_at_unix: None,
        };

        // Apply only after every condition above has succeeded.
        if let Some(user) = created_user {
            *self.user.borrow_mut() = Some(user);
        }
        self.candidate
            .borrow_mut()
            .as_mut()
            .ok_or(CommitMagicLinkAuthenticationError::Internal)?
            .consumed_at_unix = Some(command.now_unix);
        self.sessions.borrow_mut().push(session);
        *self.successful_command.borrow_mut() = Some(command.clone());

        if self.apply_then_unavailable_once.replace(false) {
            Err(CommitMagicLinkAuthenticationError::DependencyUnavailable)
        } else {
            Ok(())
        }
    }
}

impl SessionRepository for FakeRepository {
    async fn find_session(
        &self,
        session_id: &SessionId,
        _now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        Ok(self
            .sessions
            .borrow()
            .iter()
            .find(|session| &session.session_id == session_id)
            .cloned())
    }

    async fn revoke_session(
        &self,
        session_id: &SessionId,
        _revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        self.revoked.borrow_mut().push(session_id.clone());
        Ok(())
    }
}

#[derive(Default)]
struct FakeOutbox {
    messages: RefCell<Vec<MagicLinkEmail>>,
    next_error: Cell<Option<DependencyError>>,
}

impl FakeOutbox {
    fn fail_next(&self, error: DependencyError) {
        self.next_error.set(Some(error));
    }
}

impl MagicLinkOutbox for FakeOutbox {
    async fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError> {
        if let Some(error) = self.next_error.take() {
            return Err(error);
        }
        self.messages.borrow_mut().push(email);
        Ok(())
    }
}

fn lookup_key() -> LookupHmacKey {
    LookupHmacKey::new([0x42; 32])
}

fn expected_selector_lookup() -> LookupHmac {
    selector_lookup_hmac(&lookup_key(), token(VERIFIER).selector()).expect("selector lookup")
}

fn session_keyring_with_mint_until(mint_until_unix: u64) -> KeyRing<SessionCookie> {
    let kid = KeyId::parse("active").expect("key id");
    let root = RootSecret::new([0x11; 32]);
    let key = root
        .derive_key::<SessionCookie>(&kid)
        .expect("derive session key");
    KeyRing::new(
        kid.clone(),
        vec![KeySlot::active_with_windows(
            kid,
            key,
            mint_until_unix,
            mint_until_unix + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
        )],
    )
    .expect("session keyring")
}

fn session_keyring() -> KeyRing<SessionCookie> {
    session_keyring_with_mint_until(20_000)
}

fn flow_keyring() -> KeyRing<MagicLinkFlowCookie> {
    let kid = KeyId::parse("flow-active").expect("key id");
    let root = RootSecret::new([0x33; 32]);
    let key = root
        .derive_key::<MagicLinkFlowCookie>(&kid)
        .expect("derive flow key");
    KeyRing::new(
        kid.clone(),
        vec![KeySlot::active_with_windows(kid, key, 20_000, 20_300)],
    )
    .expect("flow keyring")
}

fn config() -> MagicLinkServiceConfig {
    let mut config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    config.session_idle_secs = 100;
    config.session_absolute_secs = 300;
    config.enforce_country = true;
    config
}

fn token(verifier: &str) -> MagicLinkToken {
    MagicLinkToken::parse(&format!("mlv1.{SELECTOR}.{verifier}")).expect("test token")
}

fn candidate() -> MagicLinkAuthenticationCandidate {
    let key = lookup_key();
    let token = token(VERIFIER);
    MagicLinkAuthenticationCandidate {
        verifier_hash: verifier_hash(&key, token.verifier()).expect("verifier hash"),
        email: NormalizedEmail::parse("account@example.test").expect("email"),
        expires_at_unix: NOW + 100,
        consumed_at_unix: None,
        terms_version: "terms-v1".to_owned(),
        privacy_version: "privacy-v1".to_owned(),
        consented_at_unix: NOW - 1,
    }
}

fn existing_user(id: &str, disabled: bool) -> UserRecord {
    UserRecord {
        user_id: UserId::parse(id).expect("user id"),
        email: NormalizedEmail::parse("account@example.test").expect("email"),
        disabled,
        terms_version: Some("old-terms".to_owned()),
        privacy_version: Some("old-privacy".to_owned()),
        consented_at_unix: Some(7),
    }
}

fn create_commit_command(session_id: SessionId) -> CommitMagicLinkAuthentication {
    let candidate = candidate();
    CommitMagicLinkAuthentication {
        magic_link: authentication_expectation(&expected_selector_lookup(), &candidate),
        now_unix: NOW,
        attempt_id: AuthenticationAttemptId::parse("aid_000102030405060708090a0b0c0d0e0f")
            .expect("attempt id"),
        user: MagicLinkAuthenticationUser::Create {
            user_id: UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id"),
        },
        session_id,
        session_expires_at_unix: NOW + 300,
    }
}

async fn consume(
    repository: &FakeRepository,
    rng: &mut TestRng,
    presented_token: MagicLinkToken,
    config: MagicLinkServiceConfig,
) -> Result<ConsumeMagicLinkOutcome, MagicLinkServiceError> {
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let keyring = session_keyring();
    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: repository,
        sessions: repository,
        limiter: &limiter,
        clock: &clock,
        rng,
        lookup_hmac_key: &key,
        session_keyring: &keyring,
        config,
    });
    service
        .consume_magic_link(ConsumeMagicLinkCommand::new(
            presented_token,
            Some(ClientKey::parse("client-1").expect("client key")),
            Some("HU".to_owned()),
        )?)
        .await
}

async fn begin_flow(
    repository: &FakeRepository,
    limiter: &AllowLimiter,
    clock: &FixedClock,
    rng: &mut TestRng,
    raw_token: String,
    client_key: Option<ClientKey>,
    config: MagicLinkServiceConfig,
) -> Result<BeginMagicLinkLandingOutcome, MagicLinkFlowError> {
    let key = lookup_key();
    let flow_keyring = flow_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService::new(MagicLinkFlowServiceInputs {
        authentication: repository,
        sessions: repository,
        limiter,
        clock,
        rng,
        lookup_hmac_key: &key,
        flow_keyring: &flow_keyring,
        session_keyring: &session_keyring,
        config,
    });
    service
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(raw_token, client_key))
        .await
}

#[allow(clippy::too_many_arguments)]
async fn confirm_flow(
    repository: &FakeRepository,
    limiter: &AllowLimiter,
    clock: &FixedClock,
    rng: &mut TestRng,
    flow_cookie: String,
    confirmation: String,
    client_key: Option<ClientKey>,
    country: Option<String>,
    config: MagicLinkServiceConfig,
) -> Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError> {
    let key = lookup_key();
    let flow_keyring = flow_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService::new(MagicLinkFlowServiceInputs {
        authentication: repository,
        sessions: repository,
        limiter,
        clock,
        rng,
        lookup_hmac_key: &key,
        flow_keyring: &flow_keyring,
        session_keyring: &session_keyring,
        config,
    });
    let command = ConfirmMagicLinkFlowCommand::new(flow_cookie, confirmation, client_key, country)?;
    service.confirm_magic_link_flow(command).await
}

async fn request(
    repository: &FakeRepository,
    limiter: &AllowLimiter,
    outbox: &FakeOutbox,
    rng: &mut TestRng,
    config: MagicLinkServiceConfig,
) -> Result<RequestMagicLinkOutcome, MagicLinkServiceError> {
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
        magic_links: repository,
        limiter,
        outbox,
        clock: &clock,
        rng,
        lookup_hmac_key: &key,
        config,
    });
    service
        .request_magic_link(RequestMagicLinkCommand::new(
            NormalizedEmail::parse("account@example.test").expect("email"),
            EmailLocale::En,
            true,
            true,
            Some(ClientKey::parse("client-1").expect("client key")),
        ))
        .await
}

#[tokio::test]
async fn valid_landing_is_bounded_non_mutating_and_caps_expiry_to_record() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = TestRng::working();
    let outcome = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        Some(ClientKey::parse("client-1").expect("client key")),
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
    assert_eq!(limiter.calls.get(), 2);
    assert!(limiter.checked.borrow()[0].starts_with("magic-link:landing:client:"));
    assert!(limiter.checked.borrow()[1].starts_with("magic-link:landing:selector:"));
    assert_eq!(rng.calls, 2);
    assert_eq!(outcome.cookie_max_age_secs(), 100);
    assert_eq!(outcome.account_identity().as_str(), "account@example.test");
    let debug = format!("{outcome:?}");
    assert!(!debug.contains(outcome.flow_cookie_value()));
    assert!(!debug.contains(outcome.confirmation_value()));
    assert!(!debug.contains("account@example.test"));
}

#[tokio::test]
async fn landing_selector_miss_does_one_dummy_read_and_creates_no_flow_state() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = TestRng::working();
    let error = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
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
    assert_eq!(rng.calls, 0);
}

#[tokio::test]
async fn landing_uses_configured_expiry_cap_and_rejects_expiry_at_now() {
    let repository = FakeRepository::default();
    let mut value = candidate();
    value.expires_at_unix = NOW + 250;
    *repository.candidate.borrow_mut() = Some(value);
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = TestRng::working();
    let mut policy = config();
    policy.magic_link_flow_ttl_secs = 30;
    let outcome = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
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
        &mut TestRng::working(),
        token(VERIFIER).as_secret_value().to_string(),
        None,
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
        let mut rng = TestRng::working();
        let landing = begin_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            &mut rng,
            token(VERIFIER).as_secret_value().to_string(),
            None,
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
            landing.flow_cookie_value().to_owned(),
            landing.confirmation_value().to_owned(),
            None,
            Some("HU".to_owned()),
            policy,
        )
        .await;
        if succeeds {
            let outcome = result.expect("authenticated expiry is inclusive in flow core");
            assert_eq!(
                outcome.temporary_state_action(),
                TemporaryAuthStateAction::Clear
            );
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
    let mut rng = TestRng::working();
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
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
        landing.flow_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        None,
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
async fn malformed_and_oversized_landing_have_identical_client_only_work() {
    for raw_token in [
        "malformed".to_owned(),
        "x".repeat(MAX_RAW_MAGIC_LINK_TOKEN_BYTES + 1),
    ] {
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        let limiter = AllowLimiter::default();
        limiter.deny_prefix("magic-link:landing:client:");
        let clock = FixedClock::at(NOW);
        let mut rng = TestRng::working();
        let error = begin_flow(
            &repository,
            &limiter,
            &clock,
            &mut rng,
            raw_token,
            Some(ClientKey::parse("client-1").expect("client key")),
            config(),
        )
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
        assert_eq!(limiter.calls.get(), 1);
        assert!(limiter.checked.borrow()[0].starts_with("magic-link:landing:client:"));
        assert_eq!(repository.candidate_reads.get(), 0);
        assert_eq!(rng.calls, 0);
    }

    let error = begin_flow(
        &FakeRepository::default(),
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut TestRng::working(),
        "malformed".to_owned(),
        None,
        config(),
    )
    .await
    .expect_err("malformed without client");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
}

#[tokio::test]
async fn landing_runs_both_buckets_even_when_the_first_denies() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    limiter.deny_prefix("magic-link:landing:client:");
    let error = begin_flow(
        &repository,
        &limiter,
        &FixedClock::at(NOW),
        &mut TestRng::working(),
        token(VERIFIER).as_secret_value().to_string(),
        Some(ClientKey::parse("client-1").expect("client key")),
        config(),
    )
    .await
    .expect_err("landing denial");
    assert_eq!(
        error.public_error(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(limiter.calls.get(), 2);
    assert_eq!(repository.candidate_reads.get(), 0);
}

#[tokio::test]
async fn landing_invalid_config_precedes_clock_limiter_repository_and_entropy() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let mut rng = TestRng::working();
    let mut policy = config();
    policy.magic_link_flow_ttl_secs = 0;
    let error = begin_flow(
        &repository,
        &limiter,
        &clock,
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        Some(ClientKey::parse("client-1").expect("client key")),
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
    assert_eq!(rng.calls, 0);
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
        &mut TestRng::working(),
        "malformed".to_owned(),
        Some(ClientKey::parse("client-1").expect("client key")),
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
            &mut TestRng::failing_at(fail_at),
            token(VERIFIER).as_secret_value().to_string(),
            None,
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

#[tokio::test]
async fn scanner_confirmation_atomically_authenticates_and_replay_clears() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let mut rng = TestRng::working();
    let client = ClientKey::parse("client-1").expect("client key");
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        Some(client.clone()),
        config(),
    )
    .await
    .expect("landing");
    let cookie = landing.flow_cookie_value().to_owned();
    let confirmation = landing.confirmation_value().to_owned();

    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        cookie.clone(),
        confirmation.clone(),
        Some(client.clone()),
        Some("HU".to_owned()),
        config(),
    )
    .await
    .expect("confirmation");
    assert_eq!(
        outcome.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
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
        Some(client),
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
async fn confirmation_rejects_cookie_nonce_client_verifier_account_and_stale_mismatches() {
    for case in 0..10 {
        reset_verifier_comparison_count();
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        let mut rng = TestRng::working();
        let client = ClientKey::parse("client-1").expect("client key");
        let landing = begin_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            &mut rng,
            token(VERIFIER).as_secret_value().to_string(),
            Some(client.clone()),
            config(),
        )
        .await
        .expect("landing");
        let mut cookie = landing.flow_cookie_value().to_owned();
        let mut confirmation = landing.confirmation_value().to_owned();
        let mut submitted_client = Some(client);
        let mut confirm_now = NOW;
        match case {
            0 => cookie.push('x'),
            1 => confirmation.replace_range(0..1, "f"),
            2 => submitted_client = None,
            3 => {
                submitted_client = Some(ClientKey::parse("client-2").expect("client key"));
            }
            4 => confirm_now = NOW + 101,
            5 => {
                let mut value = repository.candidate.borrow().clone().expect("candidate");
                value.verifier_hash =
                    verifier_hash(&lookup_key(), token(OTHER_VERIFIER).verifier())
                        .expect("other verifier");
                *repository.candidate.borrow_mut() = Some(value);
            }
            6 => {
                repository
                    .candidate
                    .borrow_mut()
                    .as_mut()
                    .expect("candidate")
                    .email = NormalizedEmail::parse("other@example.test").expect("email");
            }
            7 => {
                repository
                    .candidate
                    .borrow_mut()
                    .as_mut()
                    .expect("candidate")
                    .terms_version = "stale".to_owned();
            }
            8 => {
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
            submitted_client,
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
        if matches!(case, 5..=9) {
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
    let mut rng = TestRng::working();
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
        config(),
    )
    .await
    .expect("landing");
    let error = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.flow_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        None,
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
        let mut rng = TestRng::working();
        let landing = begin_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            &mut rng,
            token(VERIFIER).as_secret_value().to_string(),
            None,
            config(),
        )
        .await
        .expect("landing");
        let error = confirm_flow(
            &repository,
            &AllowLimiter::default(),
            &FixedClock::at(NOW),
            &mut rng,
            landing.flow_cookie_value().to_owned(),
            landing.confirmation_value().to_owned(),
            None,
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
    let mut rng = TestRng::working();
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
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
        landing.flow_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        None,
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
    let mut rng = TestRng::working();
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
        config(),
    )
    .await
    .expect("landing");
    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.flow_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        None,
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
    let mut rng = TestRng::working();
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
        config(),
    )
    .await
    .expect("landing");
    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.flow_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        None,
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
    let mut rng = TestRng::working();
    let landing = begin_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        token(VERIFIER).as_secret_value().to_string(),
        None,
        config(),
    )
    .await
    .expect("landing");
    let outcome = confirm_flow(
        &repository,
        &AllowLimiter::default(),
        &FixedClock::at(NOW),
        &mut rng,
        landing.flow_cookie_value().to_owned(),
        landing.confirmation_value().to_owned(),
        None,
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
async fn selector_miss_performs_one_dummy_comparison_and_no_other_authentication_work() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    let result = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await;

    assert_eq!(
        result.unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(verifier_comparison_count(), 1);
    assert_eq!(repository.candidate_reads.get(), 1);
    assert_eq!(repository.user_reads.get(), 0);
    assert!(repository.commands.borrow().is_empty());
}

#[tokio::test]
async fn wrong_verifier_is_compared_locally_once_and_never_committed() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());

    let result = consume(
        &repository,
        &mut TestRng::working(),
        token(OTHER_VERIFIER),
        config(),
    )
    .await;
    assert_eq!(
        result.unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(verifier_comparison_count(), 1);
    assert!(repository.commands.borrow().is_empty());
    assert!(
        repository
            .candidate
            .borrow()
            .as_ref()
            .is_some_and(|c| c.consumed_at_unix.is_none())
    );
}

#[tokio::test]
async fn stale_candidate_states_are_generic_and_do_not_mutate() {
    for stale in 0..5 {
        let repository = FakeRepository::default();
        let mut value = candidate();
        match stale {
            0 => value.consumed_at_unix = Some(NOW - 1),
            1 => value.expires_at_unix = NOW - 1,
            2 => value.terms_version = "stale".to_owned(),
            3 => value.privacy_version = "stale".to_owned(),
            _ => value.consented_at_unix = 0,
        }
        *repository.candidate.borrow_mut() = Some(value.clone());
        let result = consume(
            &repository,
            &mut TestRng::working(),
            token(VERIFIER),
            config(),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            MagicLinkServiceError::MagicLinkUnavailable
        );
        assert!(repository.commands.borrow().is_empty());
        assert_eq!(repository.candidate.borrow().as_ref(), Some(&value));
    }
}

#[tokio::test]
async fn disabled_or_malformed_existing_identity_does_not_burn_link() {
    for user in [
        existing_user("usr_000102030405060708090a0b0c0d0e0f", true),
        UserRecord {
            email: NormalizedEmail::parse("other@example.test").expect("other email"),
            ..existing_user("usr_000102030405060708090a0b0c0d0e0f", false)
        },
    ] {
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        *repository.user.borrow_mut() = Some(user);
        let result = consume(
            &repository,
            &mut TestRng::working(),
            token(VERIFIER),
            config(),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            MagicLinkServiceError::MagicLinkUnavailable
        );
        assert!(repository.commands.borrow().is_empty());
        assert!(
            repository
                .candidate
                .borrow()
                .as_ref()
                .is_some_and(|c| c.consumed_at_unix.is_none())
        );
    }
}

#[tokio::test]
async fn entropy_or_cookie_mint_entropy_failure_happens_before_commit() {
    for failure_call in [1, 2, 3, 4] {
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        let result = consume(
            &repository,
            &mut TestRng::failing_at(failure_call),
            token(VERIFIER),
            config(),
        )
        .await;
        assert_eq!(result.unwrap_err(), MagicLinkServiceError::Unavailable);
        assert!(repository.commands.borrow().is_empty());
        assert!(
            repository
                .candidate
                .borrow()
                .as_ref()
                .is_some_and(|c| c.consumed_at_unix.is_none())
        );
    }
}

#[tokio::test]
async fn checked_session_expiry_overflow_fails_before_commit() {
    let repository = FakeRepository::default();
    let mut value = candidate();
    value.expires_at_unix = u64::MAX;
    *repository.candidate.borrow_mut() = Some(value);
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(u64::MAX);
    let key = lookup_key();
    let keyring = session_keyring();
    let mut rng = TestRng::working();
    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        session_keyring: &keyring,
        config: config(),
    });
    let result = service
        .consume_magic_link(
            ConsumeMagicLinkCommand::new(token(VERIFIER), None, Some("HU".to_owned()))
                .expect("command"),
        )
        .await;

    assert_eq!(result.unwrap_err(), MagicLinkServiceError::Internal);
    assert!(repository.commands.borrow().is_empty());
    assert!(repository.user.borrow().is_none());
}

#[tokio::test]
async fn expired_cookie_key_fails_before_commit_without_burning_link() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let keyring = session_keyring_with_mint_until(NOW - 1);
    let mut rng = TestRng::working();
    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        session_keyring: &keyring,
        config: config(),
    });
    let result = service
        .consume_magic_link(
            ConsumeMagicLinkCommand::new(token(VERIFIER), None, Some("HU".to_owned()))
                .expect("command"),
        )
        .await;

    assert_eq!(result.unwrap_err(), MagicLinkServiceError::Unavailable);
    assert!(repository.commands.borrow().is_empty());
    assert!(
        repository
            .candidate
            .borrow()
            .as_ref()
            .is_some_and(|candidate| candidate.consumed_at_unix.is_none())
    );
}

#[tokio::test]
async fn new_user_success_atomically_returns_matching_session_and_complete_cookie() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let outcome = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await
    .expect("consume");

    assert!(outcome.user_created);
    assert!(outcome.session_cookie.starts_with("v1.active."));
    assert_eq!(outcome.country.as_deref(), Some("HU"));
    assert_eq!(repository.commands.borrow().len(), 1);
    assert_eq!(
        repository.sessions.borrow()[0].session_id,
        outcome.session_id
    );
    let user = repository.user.borrow();
    let user = user.as_ref().expect("created user");
    assert_eq!(user.terms_version.as_deref(), Some("terms-v1"));
    assert_eq!(user.privacy_version.as_deref(), Some("privacy-v1"));
    assert_eq!(user.consented_at_unix, Some(NOW - 1));
}

#[tokio::test]
async fn existing_user_success_preserves_stored_consent() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let existing = existing_user("usr_000102030405060708090a0b0c0d0e0f", false);
    *repository.user.borrow_mut() = Some(existing.clone());

    let outcome = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await
    .expect("consume");
    assert!(!outcome.user_created);
    assert_eq!(outcome.user_id, existing.user_id);
    assert_eq!(repository.user.borrow().as_ref(), Some(&existing));
}

#[tokio::test]
async fn user_conflict_rereads_and_replans_through_winner_with_fresh_attempt() {
    reset_verifier_comparison_count();
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository
        .commit_results
        .borrow_mut()
        .push_back(CommitMagicLinkAuthenticationError::UserConflict);
    repository.install_winner_on_user_conflict.set(true);

    let outcome = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await
    .expect("replanned consume");
    assert!(!outcome.user_created);
    assert_eq!(repository.candidate_reads.get(), 2);
    assert_eq!(repository.user_reads.get(), 2);
    assert_eq!(verifier_comparison_count(), 2);
    let commands = repository.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert!(matches!(
        commands[0].user,
        MagicLinkAuthenticationUser::Create { .. }
    ));
    assert!(matches!(
        commands[1].user,
        MagicLinkAuthenticationUser::Existing { .. }
    ));
    assert_eq!(commands[0].session_id, commands[1].session_id);
    assert_ne!(commands[0].attempt_id, commands[1].attempt_id);
}

#[tokio::test]
async fn session_conflict_replans_session_cookie_and_attempt() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository
        .commit_results
        .borrow_mut()
        .push_back(CommitMagicLinkAuthenticationError::SessionConflict);

    let outcome = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await
    .expect("replanned consume");
    assert_eq!(repository.candidate_reads.get(), 1);
    assert_eq!(repository.user_reads.get(), 1);
    let commands = repository.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert_ne!(commands[0].session_id, commands[1].session_id);
    assert_ne!(commands[0].attempt_id, commands[1].attempt_id);
    assert_eq!(outcome.session_id, commands[1].session_id);
}

#[tokio::test]
async fn conflicts_are_bounded_to_two_total_replans() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository.commit_results.borrow_mut().extend([
        CommitMagicLinkAuthenticationError::SessionConflict,
        CommitMagicLinkAuthenticationError::SessionConflict,
        CommitMagicLinkAuthenticationError::SessionConflict,
    ]);

    let result = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await;
    assert_eq!(result.unwrap_err(), MagicLinkServiceError::Unavailable);
    assert_eq!(repository.commands.borrow().len(), 3);
    assert!(repository.sessions.borrow().is_empty());
    assert!(
        repository
            .candidate
            .borrow()
            .as_ref()
            .is_some_and(|c| c.consumed_at_unix.is_none())
    );
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
    assert_eq!(
        repository.candidate.borrow().as_ref(),
        Some(&initial_candidate)
    );
    assert!(repository.user.borrow().is_none());
    assert_eq!(repository.sessions.borrow().as_slice(), &[existing_session]);
    assert!(repository.successful_command.borrow().is_none());
}

#[tokio::test]
async fn ambiguous_success_exact_retry_is_idempotent_and_changed_payload_is_internal() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository.apply_then_unavailable_once.set(true);
    let mut rng = TestRng::working();

    let outcome = consume(&repository, &mut rng, token(VERIFIER), config())
        .await
        .expect("exact retry recovers success");
    assert_eq!(repository.candidate_reads.get(), 1);
    assert_eq!(repository.user_reads.get(), 1);
    assert_eq!(repository.sessions.borrow().len(), 1);
    assert_eq!(
        repository.sessions.borrow()[0].session_id,
        outcome.session_id
    );
    let successful_command = {
        let commands = repository.commands.borrow();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], commands[1]);
        commands[0].clone()
    };
    assert_eq!(
        repository.successful_command.borrow().as_ref(),
        Some(&successful_command)
    );
    let mut changed = successful_command;
    changed.session_expires_at_unix += 1;

    assert_eq!(
        repository
            .commit_magic_link_authentication(&changed)
            .await
            .unwrap_err(),
        CommitMagicLinkAuthenticationError::Internal
    );
    assert_eq!(repository.sessions.borrow().len(), 1);
    assert_eq!(
        repository.sessions.borrow()[0].session_id,
        outcome.session_id
    );
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
async fn dependency_retry_uses_exact_same_command_and_attempt_three_times() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    repository.commit_results.borrow_mut().extend([
        CommitMagicLinkAuthenticationError::DependencyUnavailable,
        CommitMagicLinkAuthenticationError::DependencyUnavailable,
        CommitMagicLinkAuthenticationError::DependencyUnavailable,
    ]);

    let result = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await;
    assert_eq!(result.unwrap_err(), MagicLinkServiceError::Unavailable);
    assert_eq!(repository.candidate_reads.get(), 1);
    assert_eq!(repository.user_reads.get(), 1);
    let commands = repository.commands.borrow();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0], commands[1]);
    assert_eq!(commands[1], commands[2]);
}

#[tokio::test]
async fn sequential_replay_returns_generic_failure_without_second_session() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await
    .expect("first consume");
    let replay = consume(
        &repository,
        &mut TestRng::working(),
        token(VERIFIER),
        config(),
    )
    .await;
    assert_eq!(
        replay.unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(repository.sessions.borrow().len(), 1);
    assert_eq!(repository.commands.borrow().len(), 1);
}

#[tokio::test]
async fn commit_errors_map_to_generic_public_classes() {
    for (error, expected, expected_calls) in [
        (
            CommitMagicLinkAuthenticationError::Rejected,
            MagicLinkServiceError::MagicLinkUnavailable,
            1,
        ),
        (
            CommitMagicLinkAuthenticationError::Internal,
            MagicLinkServiceError::Internal,
            1,
        ),
        (
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
            MagicLinkServiceError::Unavailable,
            3,
        ),
    ] {
        let repository = FakeRepository::default();
        *repository.candidate.borrow_mut() = Some(candidate());
        for _ in 0..expected_calls {
            repository.commit_results.borrow_mut().push_back(error);
        }
        let result = consume(
            &repository,
            &mut TestRng::working(),
            token(VERIFIER),
            config(),
        )
        .await;
        assert_eq!(result.unwrap_err(), expected);
        assert_eq!(repository.commands.borrow().len(), expected_calls);
    }
}

#[tokio::test]
async fn invalid_config_and_country_precede_clock_and_repository_work() {
    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let keyring = session_keyring();
    let mut rng = TestRng::working();
    let mut invalid = config();
    invalid.session_absolute_secs = 0;
    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        session_keyring: &keyring,
        config: invalid,
    });
    let command = ConsumeMagicLinkCommand::new(token(VERIFIER), None, None).expect("command");
    assert_eq!(
        service.consume_magic_link(command).await.unwrap_err(),
        MagicLinkServiceError::Internal
    );
    assert_eq!(clock.calls.get(), 0);
    assert_eq!(repository.candidate_reads.get(), 0);
}

#[tokio::test]
async fn request_side_repository_remains_put_only_and_stores_no_user_id() {
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let mut rng = TestRng::working();
    let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
        magic_links: &repository,
        limiter: &limiter,
        outbox: &outbox,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        config: config(),
    });
    service
        .request_magic_link(RequestMagicLinkCommand::new(
            NormalizedEmail::parse("account@example.test").expect("email"),
            EmailLocale::En,
            true,
            true,
            None,
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
            &mut TestRng::working(),
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
        &mut TestRng::working(),
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
        &mut TestRng::working(),
        config(),
    )
    .await;
    assert_eq!(result.unwrap_err(), MagicLinkServiceError::Unavailable);
    assert_eq!(repository.request_records.borrow().len(), 1);
    assert!(outbox.messages.borrow().is_empty());
}

#[tokio::test]
async fn malformed_and_limited_consume_paths_are_generic_and_do_not_read_authentication() {
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    limiter.deny_prefix("magic-link:consume:malformed:");
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let keyring = session_keyring();
    let mut rng = TestRng::working();
    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        session_keyring: &keyring,
        config: config(),
    });
    let result = service
        .consume_magic_link_token(
            "malformed",
            Some(ClientKey::parse("client-1").expect("client key")),
            Some("HU".to_owned()),
        )
        .await;
    assert_eq!(
        result.unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(repository.candidate_reads.get(), 0);

    let repository = FakeRepository::default();
    *repository.candidate.borrow_mut() = Some(candidate());
    let limiter = AllowLimiter::default();
    limiter.deny_prefix("magic-link:consume:selector:");
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let keyring = session_keyring();
    let mut rng = TestRng::working();
    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        session_keyring: &keyring,
        config: config(),
    });
    let result = service
        .consume_magic_link_token(
            token(VERIFIER).as_secret_value().as_ref(),
            Some(ClientKey::parse("client-1").expect("client key")),
            Some("HU".to_owned()),
        )
        .await;
    assert_eq!(
        result.unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(repository.candidate_reads.get(), 0);
    assert!(repository.commands.borrow().is_empty());
}

#[tokio::test]
async fn revoke_session_still_delegates_to_the_session_repository() {
    let repository = FakeRepository::default();
    let limiter = AllowLimiter::default();
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let keyring = session_keyring();
    let mut rng = TestRng::working();
    let service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &key,
        session_keyring: &keyring,
        config: config(),
    });
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

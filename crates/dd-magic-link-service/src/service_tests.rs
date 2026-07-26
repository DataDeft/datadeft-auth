//! Service orchestration tests.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use dd_auth_token_core::keyring::{KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret, SessionCookie};
use dd_magic_link_core::{LookupHmac, LookupHmacKey, NormalizedEmail, VerifierHash};
use rand_core::{CryptoRng, RngCore};

use super::*;
use crate::config::MagicLinkServiceConfig;
use crate::session::validate_session;
use crate::traits::{Clock, MagicLinkOutbox, MagicLinkRepository, SessionRepository};
use crate::traits::{RateLimiter, UserRepository};
use crate::types::{EmailLocale, RequestMagicLinkCommand, UserRecord};

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

struct FixedClock {
    now: u64,
}

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(self.now)
    }
}

#[derive(Clone)]
struct StoredMagicLink {
    record: MagicLinkRecord,
}

#[derive(Default)]
struct FakeRepo {
    magic_links: RefCell<HashMap<String, StoredMagicLink>>,
    users: RefCell<Vec<UserRecord>>,
    sessions: RefCell<Vec<SessionRecord>>,
    revoked_sessions: RefCell<Vec<String>>,
    fail_next_session_write: Cell<bool>,
}

impl MagicLinkRepository for FakeRepo {
    async fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> Result<(), DependencyError> {
        let key = record.selector_lookup_hmac.as_storage_value().to_owned();
        let mut records = self.magic_links.borrow_mut();
        if records.contains_key(&key) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        records.insert(key, StoredMagicLink { record });
        Ok(())
    }

    async fn consume_magic_link(
        &self,
        selector_lookup_hmac: &LookupHmac,
        verifier_hash: &VerifierHash,
        now_unix: u64,
    ) -> Result<ConsumedMagicLink, ConsumeMagicLinkError> {
        let mut records = self.magic_links.borrow_mut();
        let Some(stored) = records.get_mut(selector_lookup_hmac.as_storage_value()) else {
            return Err(ConsumeMagicLinkError::Unavailable);
        };
        if stored.record.consumed_at_unix.is_some()
            || stored.record.expires_at_unix < now_unix
            || !stored
                .record
                .verifier_hash
                .matches_hash_constant_time(verifier_hash)
        {
            return Err(ConsumeMagicLinkError::Unavailable);
        }

        stored.record.consumed_at_unix = Some(now_unix);
        Ok(ConsumedMagicLink {
            email: stored.record.email.clone(),
            user_id: stored.record.user_id.clone(),
            terms_version: stored.record.terms_version.clone(),
            privacy_version: stored.record.privacy_version.clone(),
            consented_at_unix: stored.record.consented_at_unix,
        })
    }
}

impl UserRepository for FakeRepo {
    async fn find_user_by_email(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|user| &user.email == email)
            .cloned())
    }

    async fn put_user_if_absent(&self, user: UserRecord) -> Result<(), DependencyError> {
        let mut users = self.users.borrow_mut();
        if users.iter().any(|existing| existing.email == user.email) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        users.push(user);
        Ok(())
    }
}

impl SessionRepository for FakeRepo {
    async fn put_session_if_absent(&self, session: SessionRecord) -> Result<(), DependencyError> {
        if self.fail_next_session_write.replace(false) {
            return Err(DependencyError::Unavailable);
        }
        let mut sessions = self.sessions.borrow_mut();
        if sessions
            .iter()
            .any(|existing| existing.session_id == session.session_id)
        {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        sessions.push(session);
        Ok(())
    }

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
        self.revoked_sessions
            .borrow_mut()
            .push(session_id.as_str().to_owned());
        Ok(())
    }
}

#[derive(Default)]
struct FakeLimiter {
    denied_prefixes: RefCell<Vec<String>>,
    checked: RefCell<Vec<String>>,
}

impl FakeLimiter {
    fn deny_prefix(&self, prefix: &str) {
        self.denied_prefixes.borrow_mut().push(prefix.to_owned());
    }
}

impl RateLimiter for FakeLimiter {
    async fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        _limit: u32,
        _window_secs: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        self.checked.borrow_mut().push(key.as_str().to_owned());
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
struct FakeOutbox {
    emails: RefCell<Vec<MagicLinkEmail>>,
}

impl MagicLinkOutbox for FakeOutbox {
    async fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError> {
        self.emails.borrow_mut().push(email);
        Ok(())
    }
}

fn lookup_key() -> LookupHmacKey {
    LookupHmacKey::new([0x42; 32])
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

fn config() -> MagicLinkServiceConfig {
    let mut config = MagicLinkServiceConfig::new("terms-2026-01-01", "privacy-2026-01-01");
    config.enforce_country = true;
    config
}

fn request_command() -> RequestMagicLinkCommand {
    RequestMagicLinkCommand::new(
        NormalizedEmail::parse("user@example.com").expect("email"),
        EmailLocale::En,
        true,
        true,
        Some(ClientKey::parse("client-1").expect("client")),
    )
}

#[tokio::test]
async fn request_rejects_invalid_config_before_command_or_dependencies() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let mut rng = CounterRng::new();
    let mut invalid_config = config();
    invalid_config.magic_link_ttl_secs = 0;
    let command = RequestMagicLinkCommand::new(
        NormalizedEmail::parse("user@example.com").expect("email"),
        EmailLocale::En,
        false,
        false,
        Some(ClientKey::parse("client-1").expect("client")),
    );

    let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
        magic_links: &repo,
        limiter: &limiter,
        outbox: &outbox,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        config: invalid_config,
    });

    assert_eq!(
        service.request_magic_link(command).await.unwrap_err(),
        MagicLinkServiceError::Internal
    );
    assert!(repo.magic_links.borrow().is_empty());
    assert!(limiter.checked.borrow().is_empty());
    assert!(outbox.emails.borrow().is_empty());
}

#[tokio::test]
async fn consume_entrypoints_reject_invalid_config_before_token_or_country_work() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let token = MagicLinkToken::generate(&mut rng).expect("token");
    let command = ConsumeMagicLinkCommand::new(token, None, None).expect("command");
    let mut invalid_config = config();
    invalid_config.magic_link_ttl_secs = 0;
    invalid_config.enforce_country = true;

    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: invalid_config.clone(),
    });
    assert_eq!(
        service.consume_magic_link(command).await.unwrap_err(),
        MagicLinkServiceError::Internal
    );
    assert!(limiter.checked.borrow().is_empty());
    assert!(repo.magic_links.borrow().is_empty());

    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: invalid_config,
    });
    assert_eq!(
        service
            .consume_magic_link_token("not-a-token", None, None)
            .await
            .unwrap_err(),
        MagicLinkServiceError::Internal
    );
    assert!(limiter.checked.borrow().is_empty());
}

#[tokio::test]
async fn revocation_is_not_blocked_by_unrelated_invalid_config() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let mut invalid_config = config();
    invalid_config.magic_link_ttl_secs = 0;
    let session_id =
        SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("session id");

    let service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: invalid_config,
    });

    service
        .revoke_session(&session_id)
        .await
        .expect("revocation remains available");
    assert_eq!(
        repo.revoked_sessions.borrow().as_slice(),
        &[session_id.as_str()]
    );
}

#[tokio::test]
async fn request_flow_stores_hmac_material_and_enqueues_redacted_token() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let mut rng = CounterRng::new();

    let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
        magic_links: &repo,
        limiter: &limiter,
        outbox: &outbox,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        config: config(),
    });

    assert_eq!(
        service
            .request_magic_link(request_command())
            .await
            .expect("request"),
        RequestMagicLinkOutcome
    );

    let emails = outbox.emails.borrow();
    assert_eq!(emails.len(), 1);
    let token = emails[0].token.as_secret_value();
    assert!(token.starts_with("mlv1."));
    assert!(!format!("{:?}", emails[0]).contains(token.as_str()));

    let records = repo.magic_links.borrow();
    assert_eq!(records.len(), 1);
    let record = records.values().next().expect("record");
    assert!(
        record
            .record
            .selector_lookup_hmac
            .as_storage_value()
            .starts_with("mlh_")
    );
    assert!(
        record
            .record
            .verifier_hash
            .as_storage_value()
            .starts_with("mlv_")
    );
    assert_eq!(record.record.expires_at_unix, 1_600);
    assert!(
        !record
            .record
            .selector_lookup_hmac
            .as_storage_value()
            .contains(emails[0].token.selector().as_lookup_value())
    );
    assert!(!format!("{:?}", record.record).contains("user@example.com"));
    assert!(!format!("{:?}", record.record).contains(emails[0].token.verifier().as_secret_value()));
}

#[tokio::test]
async fn consume_flow_burns_token_creates_user_session_and_cookie() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let cfg = config();

    {
        let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &repo,
            limiter: &limiter,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: cfg.clone(),
        });
        service
            .request_magic_link(request_command())
            .await
            .expect("request");
    }

    let token = outbox.emails.borrow()[0].token.as_secret_value();
    let outcome = {
        let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
            magic_links: &repo,
            users: &repo,
            sessions: &repo,
            limiter: &limiter,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            session_keyring: &session_keyring,
            config: cfg.clone(),
        });
        service
            .consume_magic_link_token(
                &token,
                Some(ClientKey::parse("client-1").expect("client")),
                Some("HU".to_owned()),
            )
            .await
            .expect("consume")
    };

    assert!(outcome.session_cookie.starts_with("v1.active."));
    assert_eq!(repo.users.borrow().len(), 1);
    assert_eq!(repo.sessions.borrow().len(), 1);
    assert_eq!(repo.sessions.borrow()[0].session_id, outcome.session_id);
    assert_eq!(outcome.country.as_deref(), Some("HU"));

    let validated = validate_session(
        &outcome.session_cookie,
        &session_keyring,
        &repo,
        &clock,
        &cfg,
    )
    .await
    .expect("session validates");
    assert_eq!(validated.session().session_id, outcome.session_id);
    assert_eq!(validated.country(), Some("HU"));
}

#[tokio::test]
async fn consumed_token_cannot_create_second_session() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let cfg = config();

    {
        let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &repo,
            limiter: &limiter,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: cfg.clone(),
        });
        service
            .request_magic_link(request_command())
            .await
            .expect("request");
    }
    let token = outbox.emails.borrow()[0].token.as_secret_value();

    for expected in [Ok(()), Err(MagicLinkServiceError::MagicLinkUnavailable)] {
        let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
            magic_links: &repo,
            users: &repo,
            sessions: &repo,
            limiter: &limiter,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            session_keyring: &session_keyring,
            config: cfg.clone(),
        });
        let result = service
            .consume_magic_link_token(&token, None, Some("HU".to_owned()))
            .await
            .map(|_| ());
        assert_eq!(result, expected);
    }
    assert_eq!(repo.sessions.borrow().len(), 1);
}

#[tokio::test]
async fn wrong_verifier_is_generic_and_creates_no_session() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let cfg = config();

    {
        let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &repo,
            limiter: &limiter,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: cfg.clone(),
        });
        service
            .request_magic_link(request_command())
            .await
            .expect("request");
    }
    let mut token = outbox.emails.borrow()[0].token.as_secret_value();
    let last = token.pop().expect("last char");
    token.push(if last == '0' { '1' } else { '0' });

    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: cfg,
    });
    assert_eq!(
        service
            .consume_magic_link_token(&token, None, Some("HU".to_owned()))
            .await
            .unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(repo.sessions.borrow().len(), 0);
}

#[tokio::test]
async fn request_rate_limit_is_generic_and_suppresses_storage_and_email() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    limiter.deny_prefix("magic-link:request:email:short:");
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let mut rng = CounterRng::new();

    let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
        magic_links: &repo,
        limiter: &limiter,
        outbox: &outbox,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        config: config(),
    });

    assert_eq!(
        service
            .request_magic_link(request_command())
            .await
            .expect("generic accepted"),
        RequestMagicLinkOutcome
    );
    assert_eq!(repo.magic_links.borrow().len(), 0);
    assert_eq!(outbox.emails.borrow().len(), 0);
}

#[tokio::test]
async fn malformed_consume_is_client_limited_and_generic() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();

    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: config(),
    });

    assert_eq!(
        service
            .consume_magic_link_token(
                "not-a-token",
                Some(ClientKey::parse("client-1").expect("client")),
                Some("HU".to_owned()),
            )
            .await
            .unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert!(
        limiter
            .checked
            .borrow()
            .iter()
            .any(|key| key.starts_with("magic-link:consume:malformed:client-1"))
    );
}

#[tokio::test]
async fn expired_token_is_generic_and_creates_no_user_or_session() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let cfg = config();

    {
        let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &repo,
            limiter: &limiter,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: cfg.clone(),
        });
        service
            .request_magic_link(request_command())
            .await
            .expect("request");
    }
    let token = outbox.emails.borrow()[0].token.as_secret_value();
    repo.magic_links
        .borrow_mut()
        .values_mut()
        .next()
        .expect("record")
        .record
        .expires_at_unix = 999;

    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: cfg,
    });

    assert_eq!(
        service
            .consume_magic_link_token(&token, None, Some("HU".to_owned()))
            .await
            .unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(repo.users.borrow().len(), 0);
    assert_eq!(repo.sessions.borrow().len(), 0);
    assert!(
        repo.magic_links
            .borrow()
            .values()
            .next()
            .expect("record")
            .record
            .consumed_at_unix
            .is_none()
    );
}

#[tokio::test]
async fn disabled_user_is_generic_and_gets_no_session_after_token_burn() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let cfg = config();
    let email = NormalizedEmail::parse("user@example.com").expect("email");

    repo.users.borrow_mut().push(UserRecord {
        user_id: UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id"),
        email: email.clone(),
        disabled: true,
        terms_version: Some(cfg.terms_version.clone()),
        privacy_version: Some(cfg.privacy_version.clone()),
        consented_at_unix: Some(1_000),
    });

    {
        let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &repo,
            limiter: &limiter,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: cfg.clone(),
        });
        service
            .request_magic_link(request_command())
            .await
            .expect("request");
    }
    let token = outbox.emails.borrow()[0].token.as_secret_value();

    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: cfg,
    });

    assert_eq!(
        service
            .consume_magic_link_token(&token, None, Some("HU".to_owned()))
            .await
            .unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
    assert_eq!(repo.sessions.borrow().len(), 0);
    assert!(
        repo.magic_links
            .borrow()
            .values()
            .next()
            .expect("record")
            .record
            .consumed_at_unix
            .is_some()
    );
}

#[tokio::test]
async fn session_write_failure_after_consume_burns_token() {
    let repo = FakeRepo::default();
    let limiter = FakeLimiter::default();
    let outbox = FakeOutbox::default();
    let clock = FixedClock { now: 1_000 };
    let lookup_key = lookup_key();
    let session_keyring = session_keyring();
    let mut rng = CounterRng::new();
    let cfg = config();

    {
        let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &repo,
            limiter: &limiter,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: cfg.clone(),
        });
        service
            .request_magic_link(request_command())
            .await
            .expect("request");
    }
    let token = outbox.emails.borrow()[0].token.as_secret_value();
    repo.fail_next_session_write.set(true);

    {
        let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
            magic_links: &repo,
            users: &repo,
            sessions: &repo,
            limiter: &limiter,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            session_keyring: &session_keyring,
            config: cfg.clone(),
        });
        assert_eq!(
            service
                .consume_magic_link_token(&token, None, Some("HU".to_owned()))
                .await
                .unwrap_err(),
            MagicLinkServiceError::Unavailable
        );
    }

    assert_eq!(repo.sessions.borrow().len(), 0);
    assert!(
        repo.magic_links
            .borrow()
            .values()
            .next()
            .expect("record")
            .record
            .consumed_at_unix
            .is_some()
    );

    let mut service = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &repo,
        users: &repo,
        sessions: &repo,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config: cfg,
    });
    assert_eq!(
        service
            .consume_magic_link_token(&token, None, Some("HU".to_owned()))
            .await
            .unwrap_err(),
        MagicLinkServiceError::MagicLinkUnavailable
    );
}

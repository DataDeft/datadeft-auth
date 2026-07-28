//! Complete session-validation tests.

use std::cell::{Cell, RefCell};

use dd_auth_token_core::cookie::mint_bound_cookie;
use dd_auth_token_core::keyring::{KeyPurpose, KeyRing};
use dd_auth_token_core::test_support::{PerCallRng, test_keyring_with_windows};
use dd_magic_link_core::NormalizedEmail;

use super::*;
use crate::session_body::encode_session_cookie_body;
use crate::types::{SessionId, UserId};

struct TestClock {
    result: Result<u64, DependencyError>,
    calls: Cell<usize>,
}

impl TestClock {
    fn at(now_unix: u64) -> Self {
        Self {
            result: Ok(now_unix),
            calls: Cell::new(0),
        }
    }

    fn failing(error: DependencyError) -> Self {
        Self {
            result: Err(error),
            calls: Cell::new(0),
        }
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        self.calls.set(self.calls.get() + 1);
        self.result
    }
}

#[derive(Default)]
struct TestSessions {
    record: RefCell<Option<SessionRecord>>,
    storage_expires_at_unix: Cell<Option<u64>>,
    next_error: Cell<Option<DependencyError>>,
    return_mismatched_record: Cell<bool>,
    find_calls: Cell<usize>,
    revoke_calls: Cell<usize>,
}

impl TestSessions {
    fn with_record(record: SessionRecord) -> Self {
        Self {
            record: RefCell::new(Some(record)),
            ..Self::default()
        }
    }
}

impl SessionRepository for TestSessions {
    async fn find_session(
        &self,
        session_id: &SessionId,
        now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        self.find_calls.set(self.find_calls.get() + 1);
        if let Some(error) = self.next_error.take() {
            return Err(error);
        }
        if self
            .storage_expires_at_unix
            .get()
            .is_some_and(|expires_at| expires_at < now_unix)
        {
            return Ok(None);
        }
        let record = self.record.borrow().clone();
        if !self.return_mismatched_record.get()
            && record
                .as_ref()
                .is_some_and(|record| &record.session_id != session_id)
        {
            return Ok(None);
        }
        Ok(record)
    }

    async fn revoke_session(
        &self,
        _session_id: &SessionId,
        _revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        self.revoke_calls.set(self.revoke_calls.get() + 1);
        Ok(())
    }
}

fn keyring() -> KeyRing<SessionCookie> {
    test_keyring_with_windows(
        0x51,
        "session-active",
        10_000,
        10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
    )
}

fn session_id() -> SessionId {
    SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("session id")
}

fn other_session_id() -> SessionId {
    SessionId::parse("sid_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .expect("other session id")
}

fn record(created_at_unix: u64) -> SessionRecord {
    SessionRecord {
        session_id: session_id(),
        user_id: UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id"),
        email: NormalizedEmail::parse("session-user@example.com").expect("email"),
        created_at_unix,
        revoked_at_unix: None,
    }
}

fn config() -> MagicLinkServiceConfig {
    let mut config = MagicLinkServiceConfig::new("terms-test", "privacy-test");
    config.session_idle_secs = 100;
    config.session_absolute_secs = 300;
    config
}

fn cookie(
    keyring: &KeyRing<SessionCookie>,
    timestamp: u32,
    iat: u32,
    country: Option<&str>,
) -> String {
    let body = encode_session_cookie_body(&session_id(), country).expect("encode session body");
    raw_cookie(keyring, timestamp, iat, &body)
}

fn raw_cookie(keyring: &KeyRing<SessionCookie>, timestamp: u32, iat: u32, body: &[u8]) -> String {
    let mut rng = PerCallRng::starting_at(0x61);
    mint_bound_cookie::<SessionCookie, _>(
        body,
        keyring,
        &mut rng,
        timestamp,
        iat,
        u64::from(timestamp),
    )
    .expect("mint session cookie")
}

#[tokio::test]
async fn valid_session_resolves_once_without_writes_or_refresh() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 900, 800, Some("HU"));
    let sessions = TestSessions::with_record(record(800));
    let clock = TestClock::at(900);

    let validated = validate_session(&cookie, &keyring, &sessions, &clock, &config())
        .await
        .expect("session validates");

    assert_eq!(validated.session().session_id, session_id());
    assert_eq!(validated.country(), Some("HU"));
    assert_eq!(clock.calls.get(), 1);
    assert_eq!(sessions.find_calls.get(), 1);
    assert_eq!(sessions.revoke_calls.get(), 0);
}

#[tokio::test]
async fn invalid_cookie_or_authenticated_body_never_reaches_repository() {
    let keyring = keyring();
    let sessions = TestSessions::with_record(record(800));
    let clock = TestClock::at(900);

    let valid = cookie(&keyring, 900, 800, None);
    let unknown_key = valid.replacen("session-active", "session-missing", 1);
    let mut tampered = valid.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).expect("cookie is ascii");
    let invalid_body = raw_cookie(&keyring, 900, 800, b"not-a-session-body");

    for invalid in ["not-a-cookie", &unknown_key, &tampered, &invalid_body] {
        assert_eq!(
            validate_session(invalid, &keyring, &sessions, &clock, &config())
                .await
                .unwrap_err(),
            SessionValidationError::InvalidSession
        );
    }
    assert_eq!(sessions.find_calls.get(), 0);
}

#[tokio::test]
async fn idle_and_absolute_cookie_boundaries_are_inclusive_then_expire() {
    let keyring = keyring();
    let config = config();

    let idle_cookie = cookie(&keyring, 900, 800, None);
    let idle_sessions = TestSessions::with_record(record(800));
    assert!(
        validate_session(
            &idle_cookie,
            &keyring,
            &idle_sessions,
            &TestClock::at(1_000),
            &config,
        )
        .await
        .is_ok()
    );
    assert_eq!(
        validate_session(
            &idle_cookie,
            &keyring,
            &idle_sessions,
            &TestClock::at(1_001),
            &config,
        )
        .await
        .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let absolute_cookie = cookie(&keyring, 990, 700, None);
    let absolute_sessions = TestSessions::with_record(record(700));
    assert!(
        validate_session(
            &absolute_cookie,
            &keyring,
            &absolute_sessions,
            &TestClock::at(1_000),
            &config,
        )
        .await
        .is_ok()
    );
    assert_eq!(
        validate_session(
            &absolute_cookie,
            &keyring,
            &absolute_sessions,
            &TestClock::at(1_001),
            &config,
        )
        .await
        .unwrap_err(),
        SessionValidationError::InvalidSession
    );
    assert_eq!(absolute_sessions.find_calls.get(), 1);
}

#[tokio::test]
async fn future_dated_cookie_beyond_skew_is_invalid_without_lookup() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 1_100, 1_100, None);
    let sessions = TestSessions::with_record(record(900));

    assert_eq!(
        validate_session(
            &cookie,
            &keyring,
            &sessions,
            &TestClock::at(1_000),
            &config(),
        )
        .await
        .unwrap_err(),
        SessionValidationError::InvalidSession
    );
    assert_eq!(sessions.find_calls.get(), 0);
}

#[tokio::test]
async fn repository_absence_revocation_and_expiry_are_generic() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 990, 800, None);
    let clock = TestClock::at(1_000);
    let config = config();

    let missing = TestSessions::default();
    assert_eq!(
        validate_session(&cookie, &keyring, &missing, &clock, &config)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let mut revoked_record = record(800);
    revoked_record.revoked_at_unix = Some(999);
    let revoked = TestSessions::with_record(revoked_record);
    assert_eq!(
        validate_session(&cookie, &keyring, &revoked, &clock, &config)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let storage_expired = TestSessions::with_record(record(800));
    storage_expired.storage_expires_at_unix.set(Some(999));
    assert_eq!(
        validate_session(&cookie, &keyring, &storage_expired, &clock, &config)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    assert_eq!(missing.find_calls.get(), 1);
    assert_eq!(revoked.find_calls.get(), 1);
    assert_eq!(storage_expired.find_calls.get(), 1);
}

#[tokio::test]
async fn mismatched_repository_record_is_rejected() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 990, 800, None);
    let mut mismatched = record(800);
    mismatched.session_id = other_session_id();
    let sessions = TestSessions::with_record(mismatched);
    sessions.return_mismatched_record.set(true);

    assert_eq!(
        validate_session(
            &cookie,
            &keyring,
            &sessions,
            &TestClock::at(1_000),
            &config(),
        )
        .await
        .unwrap_err(),
        SessionValidationError::InvalidSession
    );
    assert_eq!(sessions.find_calls.get(), 1);
}

#[tokio::test]
async fn repository_creation_skew_and_service_expiry_boundaries_are_enforced() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 990, 700, None);
    let clock = TestClock::at(1_000);
    let config = config();

    let within_skew = TestSessions::with_record(record(
        1_000 + dd_auth_token_core::cookie::CLOCK_SKEW_TOLERANCE_SECS,
    ));
    assert!(
        validate_session(&cookie, &keyring, &within_skew, &clock, &config)
            .await
            .is_ok()
    );

    for invalid_record in [
        record(1_000 + dd_auth_token_core::cookie::CLOCK_SKEW_TOLERANCE_SECS + 1),
        record(699),
    ] {
        let sessions = TestSessions::with_record(invalid_record);
        assert_eq!(
            validate_session(&cookie, &keyring, &sessions, &clock, &config)
                .await
                .unwrap_err(),
            SessionValidationError::InvalidSession
        );
        assert_eq!(sessions.find_calls.get(), 1);
    }
}

#[tokio::test]
async fn dependency_errors_keep_unavailable_and_internal_distinct() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 990, 800, None);
    let clock = TestClock::at(1_000);

    for (dependency, expected) in [
        (
            DependencyError::Unavailable,
            SessionValidationError::Unavailable,
        ),
        (
            DependencyError::RateLimited,
            SessionValidationError::Unavailable,
        ),
        (
            DependencyError::ConditionalWriteFailed,
            SessionValidationError::Internal,
        ),
        (DependencyError::Internal, SessionValidationError::Internal),
    ] {
        let sessions = TestSessions::with_record(record(800));
        sessions.next_error.set(Some(dependency));
        assert_eq!(
            validate_session(&cookie, &keyring, &sessions, &clock, &config())
                .await
                .unwrap_err(),
            expected
        );
        assert_eq!(sessions.find_calls.get(), 1);
    }
}

#[tokio::test]
async fn unrelated_invalid_pre_auth_config_does_not_disable_session_validation() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 900, 800, None);
    let sessions = TestSessions::with_record(record(800));
    let mut config = config();
    config.magic_link_ttl_secs = 0;
    config.rate_limits.request_email_short_limit = 0;

    assert!(
        validate_session(&cookie, &keyring, &sessions, &TestClock::at(900), &config,)
            .await
            .is_ok()
    );
    assert_eq!(sessions.find_calls.get(), 1);
}

#[tokio::test]
async fn configuration_clock_and_cookie_error_precedence_is_deterministic() {
    let keyring = keyring();
    let sessions = TestSessions::with_record(record(800));
    sessions.next_error.set(Some(DependencyError::Internal));
    let clock = TestClock::failing(DependencyError::Unavailable);
    let mut invalid_config = config();
    invalid_config.session_idle_secs = 0;

    assert_eq!(
        validate_session("not-a-cookie", &keyring, &sessions, &clock, &invalid_config)
            .await
            .unwrap_err(),
        SessionValidationError::Internal
    );
    assert_eq!(clock.calls.get(), 0);
    assert_eq!(sessions.find_calls.get(), 0);

    assert_eq!(
        validate_session("not-a-cookie", &keyring, &sessions, &clock, &config())
            .await
            .unwrap_err(),
        SessionValidationError::Unavailable
    );
    assert_eq!(clock.calls.get(), 1);
    assert_eq!(sessions.find_calls.get(), 0);

    let working_clock = TestClock::at(1_000);
    assert_eq!(
        validate_session(
            "not-a-cookie",
            &keyring,
            &sessions,
            &working_clock,
            &config(),
        )
        .await
        .unwrap_err(),
        SessionValidationError::InvalidSession
    );
    assert_eq!(sessions.find_calls.get(), 0);
}

#[tokio::test]
async fn result_and_errors_redact_session_cookie_and_account_data() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 900, 800, Some("HU"));
    let sessions = TestSessions::with_record(record(800));
    let validated = validate_session(&cookie, &keyring, &sessions, &TestClock::at(900), &config())
        .await
        .expect("session validates");

    let debug = format!("{validated:?}");
    assert_eq!(debug, "ValidatedSession(..)");
    assert!(!debug.contains("session-user@example.com"));
    assert!(!debug.contains(session_id().as_str()));
    assert!(!debug.contains(&cookie));

    for error in [
        SessionValidationError::InvalidSession,
        SessionValidationError::Unavailable,
        SessionValidationError::Internal,
    ] {
        let display = error.to_string();
        assert!(!display.contains(&cookie));
        assert!(!display.contains("session-user@example.com"));
        assert!(!display.contains(session_id().as_str()));
    }
}

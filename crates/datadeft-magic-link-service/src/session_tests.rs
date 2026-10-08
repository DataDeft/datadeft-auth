//! Complete session-validation tests.

use crate::test_shared::Shared;

use datadeft_auth_token_core::cookie::mint_bound_cookie;
use datadeft_auth_token_core::keyring::{KeyPurpose, KeyRing};
use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring_with_windows};
use datadeft_magic_link_core::NormalizedEmail;

use super::*;
use crate::session_body::encode_session_cookie_body;
use crate::types::{SessionId, UserId};

struct TestClock {
    result: Result<u64, DependencyError>,
    calls: Shared<usize>,
}

impl TestClock {
    fn at(now_unix: u64) -> Self {
        Self {
            result: Ok(now_unix),
            calls: Shared::new(0),
        }
    }

    fn failing(error: DependencyError) -> Self {
        Self {
            result: Err(error),
            calls: Shared::new(0),
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
    record: Shared<Option<SessionRecord>>,
    storage_expires_at_unix: Shared<Option<u64>>,
    next_error: Shared<Option<DependencyError>>,
    return_mismatched_record: Shared<bool>,
    find_calls: Shared<usize>,
    revoke_calls: Shared<usize>,
    user_disabled: Shared<bool>,
    user_check_error: Shared<Option<DependencyError>>,
    user_checks: Shared<usize>,
}

impl TestSessions {
    fn with_record(record: SessionRecord) -> Self {
        Self {
            record: Shared::new(Some(record)),
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

    async fn is_user_active(&self, _user_id: &UserId) -> Result<bool, DependencyError> {
        self.user_checks.set(self.user_checks.get() + 1);
        if let Some(error) = self.user_check_error.take() {
            return Err(error);
        }
        Ok(!self.user_disabled.get())
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

    let validated = validate_session(&cookie, Some("HU"), &keyring, &sessions, &clock, &config())
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
            validate_session(invalid, None, &keyring, &sessions, &clock, &config())
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
        validate_session(&cookie, None, &keyring, &missing, &clock, &config)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let mut revoked_record = record(800);
    revoked_record.revoked_at_unix = Some(999);
    let revoked = TestSessions::with_record(revoked_record);
    assert_eq!(
        validate_session(&cookie, None, &keyring, &revoked, &clock, &config)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let storage_expired = TestSessions::with_record(record(800));
    storage_expired.storage_expires_at_unix.set(Some(999));
    assert_eq!(
        validate_session(&cookie, None, &keyring, &storage_expired, &clock, &config)
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
            None,
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
        1_000 + datadeft_auth_token_core::cookie::CLOCK_SKEW_TOLERANCE_SECS,
    ));
    assert!(
        validate_session(&cookie, None, &keyring, &within_skew, &clock, &config)
            .await
            .is_ok()
    );

    for invalid_record in [
        record(1_000 + datadeft_auth_token_core::cookie::CLOCK_SKEW_TOLERANCE_SECS + 1),
        record(699),
    ] {
        let sessions = TestSessions::with_record(invalid_record);
        assert_eq!(
            validate_session(&cookie, None, &keyring, &sessions, &clock, &config)
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
            validate_session(&cookie, None, &keyring, &sessions, &clock, &config())
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
        validate_session(
            &cookie,
            None,
            &keyring,
            &sessions,
            &TestClock::at(900),
            &config,
        )
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
        validate_session(
            "not-a-cookie",
            None,
            &keyring,
            &sessions,
            &clock,
            &invalid_config
        )
        .await
        .unwrap_err(),
        SessionValidationError::Internal
    );
    assert_eq!(clock.calls.get(), 0);
    assert_eq!(sessions.find_calls.get(), 0);

    assert_eq!(
        validate_session("not-a-cookie", None, &keyring, &sessions, &clock, &config())
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
            None,
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
    let validated = validate_session(
        &cookie,
        Some("HU"),
        &keyring,
        &sessions,
        &TestClock::at(900),
        &config(),
    )
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

#[tokio::test]
async fn country_locked_sessions_require_the_same_trusted_country() {
    let keyring = keyring();
    let sessions = TestSessions::with_record(record(800));
    let clock = TestClock::at(900);
    let config = config();

    // Locked session: same trusted country validates.
    let locked = cookie(&keyring, 900, 800, Some("HU"));
    assert!(
        validate_session(&locked, Some("HU"), &keyring, &sessions, &clock, &config)
            .await
            .is_ok()
    );
    // Different country is invalid.
    assert_eq!(
        validate_session(&locked, Some("DE"), &keyring, &sessions, &clock, &config)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );
    // A locked session with no current signal fails closed.
    assert_eq!(
        validate_session(&locked, None, &keyring, &sessions, &clock, &config)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    // Unlocked sessions ignore the request country entirely.
    let unlocked = cookie(&keyring, 900, 800, None);
    assert!(
        validate_session(&unlocked, Some("DE"), &keyring, &sessions, &clock, &config)
            .await
            .is_ok()
    );
    assert!(
        validate_session(&unlocked, None, &keyring, &sessions, &clock, &config)
            .await
            .is_ok()
    );

    // Country mismatches are rejected before any repository lookup: only the
    // three successful validations above reached the repository.
    assert_eq!(sessions.find_calls.get(), 3);
}

/// Keyring after a session-key rotation: a new active key plus the previous
/// key kept verify-only until `verify_until_unix`.
fn rotated_keyring(verify_until_unix: u64) -> KeyRing<SessionCookie> {
    use datadeft_auth_token_core::keyring::{KeyId, KeySlot, RootSecret};
    let new_kid = KeyId::parse("session-new").expect("kid");
    let old_kid = KeyId::parse("session-active").expect("kid");
    let new_key = RootSecret::new([0x52; 32])
        .derive_key::<SessionCookie>(&new_kid)
        .expect("new key");
    let old_key = RootSecret::new([0x51; 32])
        .derive_key::<SessionCookie>(&old_kid)
        .expect("old key");
    KeyRing::new(vec![
        KeySlot::active_with_windows(
            new_kid,
            new_key,
            10_000,
            10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
        ),
        KeySlot::verify_only(old_kid, old_key, verify_until_unix),
    ])
    .expect("rotated keyring")
}

#[tokio::test]
async fn session_minted_before_rotation_validates_with_verify_only_key() {
    let cookie = cookie(&keyring(), 900, 800, None);
    let sessions = TestSessions::with_record(record(800));
    let clock = TestClock::at(900);

    validate_session(
        &cookie,
        None,
        &rotated_keyring(1_000),
        &sessions,
        &clock,
        &config(),
    )
    .await
    .expect("pre-rotation session still validates");
    assert_eq!(sessions.find_calls.get(), 1);
}

#[tokio::test]
async fn session_under_retired_or_unknown_key_is_rejected_before_lookup() {
    let cookie = cookie(&keyring(), 900, 800, None);
    let sessions = TestSessions::with_record(record(800));
    let clock = TestClock::at(900);

    // Verify-only window already closed: the old key is retired.
    assert!(
        validate_session(
            &cookie,
            None,
            &rotated_keyring(899),
            &sessions,
            &clock,
            &config()
        )
        .await
        .is_err()
    );
    // Old key removed entirely: unknown kid.
    let unknown = test_keyring_with_windows::<SessionCookie>(
        0x52,
        "session-new",
        10_000,
        10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
    );
    assert!(
        validate_session(&cookie, None, &unknown, &sessions, &clock, &config())
            .await
            .is_err()
    );
    assert_eq!(sessions.find_calls.get(), 0);
}

// --- explicit refresh ------------------------------------------------------
// Fixtures: idle 100 s, absolute 300 s; cookies issued at iat 800.

async fn validated_at(
    cookie: &str,
    country: Option<&str>,
    keyring: &KeyRing<SessionCookie>,
    sessions: &TestSessions,
    now_unix: u64,
) -> Result<ValidatedSession, SessionValidationError> {
    validate_session(
        cookie,
        country,
        keyring,
        sessions,
        &TestClock::at(now_unix),
        &config(),
    )
    .await
}

/// Refresh in the same request: the clock reads the validation's instant.
fn refresh(validated: &ValidatedSession, keyring: &KeyRing<SessionCookie>) -> Option<String> {
    let mut rng = PerCallRng::starting_at(0x71);
    let clock = TestClock::at(validated.validated_at_unix);
    refresh_session_cookie(validated, keyring, &mut rng, &clock, &config())
        .expect("refresh")
        .map(|cookie| cookie.as_secret_value().to_owned())
}

#[tokio::test]
async fn refresh_waits_until_half_the_idle_lifetime_has_passed() {
    let keyring = keyring();
    let original = cookie(&keyring, 900, 800, None);
    let sessions = TestSessions::with_record(record(800));

    let early = validated_at(&original, None, &keyring, &sessions, 949)
        .await
        .expect("valid");
    assert!(refresh(&early, &keyring).is_none());
    let due = validated_at(&original, None, &keyring, &sessions, 950)
        .await
        .expect("valid");
    assert!(refresh(&due, &keyring).is_some());
}

#[tokio::test]
async fn refreshed_cookie_keeps_identity_and_extends_only_idle_time() {
    let keyring = keyring();
    let original = cookie(&keyring, 900, 800, Some("HU"));
    let sessions = TestSessions::with_record(record(800));
    let validated = validated_at(&original, Some("HU"), &keyring, &sessions, 960)
        .await
        .expect("valid");
    let refreshed = refresh(&validated, &keyring).expect("due");

    let parsed = parse_bound_cookie::<SessionCookie>(
        &refreshed,
        &keyring,
        960,
        config().session_max_age().expect("max age"),
    )
    .expect("refreshed cookie parses");
    assert_eq!(parsed.iat(), 800, "first-issue time is preserved");
    assert_eq!(parsed.timestamp(), 960, "activity time moves to now");
    let body = decode_session_cookie_body(parsed.body()).expect("body");
    assert_eq!(body.session_id, session_id());
    assert_eq!(body.country.as_deref(), Some("HU"));

    // The original cookie is idle-expired at 1_050; the refreshed one is not.
    assert!(
        validated_at(&original, Some("HU"), &keyring, &sessions, 1_050)
            .await
            .is_err()
    );
    validated_at(&refreshed, Some("HU"), &keyring, &sessions, 1_050)
        .await
        .expect("refreshed cookie is valid");
    // The country lock carries over.
    assert!(
        validated_at(&refreshed, Some("DE"), &keyring, &sessions, 1_050)
            .await
            .is_err()
    );
    // Refresh never touches the repository; only the validations read it.
    assert_eq!(sessions.revoke_calls.get(), 0);
}

#[tokio::test]
async fn refresh_can_never_extend_the_absolute_lifetime() {
    let keyring = keyring();
    let sessions = TestSessions::with_record(record(800));
    // Keep refreshing as often as allowed; the session still ends at
    // iat + absolute = 1_100.
    let mut current = cookie(&keyring, 800, 800, None);
    let mut now = 800;
    let mut last_valid = 800;
    while now < 1_200 {
        now += 50;
        let Ok(validated) = validated_at(&current, None, &keyring, &sessions, now).await else {
            break;
        };
        last_valid = now;
        if let Some(next) = refresh(&validated, &keyring) {
            current = next;
        }
    }
    assert!(
        last_valid <= 1_100,
        "session outlived its absolute lifetime"
    );
    assert!(
        validated_at(&current, None, &keyring, &sessions, 1_101)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cookie_at_the_absolute_limit_is_not_reissued() {
    let keyring = keyring();
    let sessions = TestSessions::with_record(record(800));
    let original = cookie(&keyring, 1_050, 800, None);
    let validated = validated_at(&original, None, &keyring, &sessions, 1_100)
        .await
        .expect("valid at the inclusive boundary");
    assert!(refresh(&validated, &keyring).is_none());
}

#[tokio::test]
async fn revocation_after_refresh_still_ends_the_session() {
    let keyring = keyring();
    let original = cookie(&keyring, 900, 800, None);
    let sessions = TestSessions::with_record(record(800));
    let validated = validated_at(&original, None, &keyring, &sessions, 960)
        .await
        .expect("valid");
    let refreshed = refresh(&validated, &keyring).expect("due");

    sessions
        .record
        .borrow_mut()
        .as_mut()
        .expect("record")
        .revoked_at_unix = Some(965);
    assert_eq!(
        validated_at(&refreshed, None, &keyring, &sessions, 970)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );
}

#[tokio::test]
async fn refresh_reissues_under_the_current_active_key() {
    let old = keyring();
    let original = cookie(&old, 900, 800, None);
    let sessions = TestSessions::with_record(record(800));
    let rotated = rotated_keyring(10_000);
    let validated = validated_at(&original, None, &rotated, &sessions, 960)
        .await
        .expect("pre-rotation cookie validates with the verify-only key");
    let refreshed = refresh(&validated, &rotated).expect("due");
    assert!(refreshed.starts_with("v1.session-new."));
}

#[test]
fn refreshed_cookie_debug_is_redacted() {
    let cookie = RefreshedSessionCookie("v1.kid.secret".to_owned());
    assert_eq!(format!("{cookie:?}"), "RefreshedSessionCookie(..)");
}

#[tokio::test]
async fn stale_validation_cannot_be_refreshed() {
    let keyring = keyring();
    let original = cookie(&keyring, 900, 800, None);
    let sessions = TestSessions::with_record(record(800));
    let validated = validated_at(&original, None, &keyring, &sessions, 960)
        .await
        .expect("valid");
    let mut rng = PerCallRng::starting_at(0x71);

    // Within the skew tolerance of the validation it still counts as fresh.
    assert!(
        refresh_session_cookie(
            &validated,
            &keyring,
            &mut rng,
            &TestClock::at(1_020),
            &config()
        )
        .expect("fresh enough")
        .is_some()
    );
    // Kept around and refreshed later, or with a clock that went backwards:
    // refused, so the caller must validate (and see any revocation) again.
    for later in [1_021, 959] {
        assert_eq!(
            refresh_session_cookie(
                &validated,
                &keyring,
                &mut rng,
                &TestClock::at(later),
                &config()
            )
            .unwrap_err(),
            SessionValidationError::InvalidSession
        );
    }
}

// --- disabled users --------------------------------------------------------

#[tokio::test]
async fn disabled_user_cannot_use_a_valid_session() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 900, 800, None);
    let sessions = TestSessions::with_record(record(800));

    validated_at(&cookie, None, &keyring, &sessions, 900)
        .await
        .expect("active user validates");
    sessions.user_disabled.set(true);
    assert_eq!(
        validated_at(&cookie, None, &keyring, &sessions, 900)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );
    // Checked on every validation, not cached.
    assert_eq!(sessions.user_checks.get(), 2);
}

#[tokio::test]
async fn user_status_lookup_failures_never_count_as_active() {
    let keyring = keyring();
    let cookie = cookie(&keyring, 900, 800, None);
    for (error, expected) in [
        (
            DependencyError::Unavailable,
            SessionValidationError::Unavailable,
        ),
        (DependencyError::Internal, SessionValidationError::Internal),
    ] {
        let sessions = TestSessions::with_record(record(800));
        sessions.user_check_error.set(Some(error));
        assert_eq!(
            validated_at(&cookie, None, &keyring, &sessions, 900)
                .await
                .unwrap_err(),
            expected
        );
    }
}

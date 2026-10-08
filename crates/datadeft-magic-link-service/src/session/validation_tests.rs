//! Session validation: freshness, repository checks, errors, country lock, key rotation, disabled users.

//! Complete session-validation tests.

use datadeft_auth_token_core::keyring::KeyPurpose;
use datadeft_auth_token_core::test_support::test_keyring_with_windows;

use super::test_support::*;
use super::*;

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

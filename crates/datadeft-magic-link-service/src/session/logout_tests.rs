//! Logout cookie validation: revocation eligibility is not session admission.

use super::test_support::*;
use super::*;

async fn for_logout(
    cookie: &str,
    sessions: &TestSessions,
) -> Result<SessionRecord, SessionValidationError> {
    validate_session_for_logout(cookie, &keyring(), sessions, &TestClock::at(900), &config()).await
}

#[tokio::test]
async fn logout_validation_skips_country_but_preserves_integrity_and_absolute_expiry() {
    let keyring = keyring();
    let locked = cookie(&keyring, 900, 800, Some("HU"));

    // A country-locked session can be ended from anywhere, with no signal.
    let sessions = TestSessions::with_record(record(800));
    let session = for_logout(&locked, &sessions)
        .await
        .expect("an authentic session is revocable");
    assert_eq!(session.session_id, session_id());
    assert_eq!(sessions.revoke_calls.get(), 0, "validation never writes");

    // Integrity and absolute freshness checks still apply.
    let mut tampered = locked.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).expect("cookie is ascii");
    assert_eq!(
        for_logout(&tampered, &sessions).await.unwrap_err(),
        SessionValidationError::InvalidSession
    );
    let much_later = TestClock::at(900 + 365 * 24 * 60 * 60);
    assert_eq!(
        validate_session_for_logout(&locked, &keyring, &sessions, &much_later, &config())
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession,
        "a cookie past its absolute lifetime is not revocable"
    );
    // A retired key (verify-only window closed at 899) is not revocable either.
    assert_eq!(
        validate_session_for_logout(
            &locked,
            &rotated_keyring(899),
            &sessions,
            &TestClock::at(900),
            &config()
        )
        .await
        .unwrap_err(),
        SessionValidationError::InvalidSession
    );
    // Nor is a cookie dated beyond the clock-skew tolerance.
    assert_eq!(
        for_logout(&cookie(&keyring, 1_100, 1_100, Some("HU")), &sessions)
            .await
            .unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let mut revoked_record = record(800);
    revoked_record.revoked_at_unix = Some(850);
    let revoked = TestSessions::with_record(revoked_record);
    assert_eq!(
        for_logout(&locked, &revoked).await.unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let disabled = TestSessions::with_record(record(800));
    disabled.user_disabled.set(true);
    assert_eq!(
        for_logout(&locked, &disabled).await.unwrap_err(),
        SessionValidationError::InvalidSession
    );

    let missing = TestSessions::default();
    assert_eq!(
        for_logout(&locked, &missing).await.unwrap_err(),
        SessionValidationError::InvalidSession
    );
}

#[tokio::test]
async fn logout_accepts_an_idle_expired_cookie_but_never_admits_or_refreshes_it() {
    let keyring = keyring();
    let old = cookie(&keyring, 700, 700, Some("HU"));
    let sessions = TestSessions::with_record(record(700));
    assert!(matches!(
        validated_at(&old, Some("HU"), &keyring, &sessions, 900).await,
        Err(SessionValidationError::InvalidSession)
    ));
    assert_eq!(
        for_logout(&old, &sessions)
            .await
            .expect("revocable")
            .session_id,
        session_id()
    );
    assert_eq!(sessions.revoke_calls.get(), 0);

    // Fresh activity cannot rescue a cookie beyond the original absolute TTL.
    let expired = cookie(&keyring, 850, 500, Some("HU"));
    assert!(matches!(
        for_logout(&expired, &sessions).await,
        Err(SessionValidationError::InvalidSession)
    ));
}

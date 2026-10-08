//! Explicit session refresh: threshold, preserved identity, absolute limit, revocation, rotation, staleness.

//! Complete session-validation tests.

use datadeft_auth_token_core::test_support::PerCallRng;

use super::test_support::*;
use super::*;

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

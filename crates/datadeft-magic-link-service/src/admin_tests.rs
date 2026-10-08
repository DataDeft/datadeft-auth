//! Admin type tests. Storage-backed behaviour is tested against the fake store
//! in `datadeft-magic-link-aws`.

use super::*;

const HANDLE: &str = "sih_3f9a1c2e00000000000000000000000000000000000000000000000000000001";

#[test]
fn session_handle_accepts_only_the_stored_hash_shape() {
    let handle = SessionHandle::parse(HANDLE).expect("valid handle");
    assert_eq!(handle.as_str(), HANDLE);
    for bad in [
        "",
        "sih_",
        "sih_3f9a1c2e",
        "SIH_3f9a1c2e00000000000000000000000000000000000000000000000000000001",
        "sih_3F9A1C2E00000000000000000000000000000000000000000000000000000001",
        "sih_3f9a1c2e000000000000000000000000000000000000000000000000000000010",
        "sih_3f9a1c2e0000000000000000000000000000000000000000000000000000000g",
        "emh_3f9a1c2e00000000000000000000000000000000000000000000000000000001",
        "sih_3f9a1c2e00000000000000000000000000000000000000000000000000000001\n",
    ] {
        assert_eq!(
            SessionHandle::parse(bad).unwrap_err(),
            AdminError::InvalidInput,
            "{bad:?}"
        );
    }
}

#[test]
fn session_handle_display_id_is_a_short_label() {
    let handle = SessionHandle::parse(HANDLE).expect("valid handle");
    assert_eq!(handle.display_id(), "sess_3f9a1c2e");
    assert_eq!(format!("{handle:?}"), "SessionHandle(sess_3f9a1c2e)");
    // The short label is not a valid handle, so it can never address a session.
    assert!(SessionHandle::parse(&handle.display_id()).is_err());
}

#[test]
fn admin_actor_is_validated_and_its_reason_is_redacted() {
    let actor =
        AdminActor::new("admin@example.test", Some("ticket 42".to_owned())).expect("valid actor");
    assert_eq!(actor.id(), "admin@example.test");
    assert_eq!(actor.reason(), Some("ticket 42"));
    assert!(!format!("{actor:?}").contains("ticket"));

    assert!(AdminActor::new("ops", None).is_ok());
    for (id, reason) in [
        (String::new(), None),
        ("a".repeat(MAX_ADMIN_ACTOR_ID_BYTES + 1), None),
        ("admin\nX-Injected: 1".to_owned(), None),
        (
            "admin".to_owned(),
            Some("r".repeat(MAX_ADMIN_REASON_BYTES + 1)),
        ),
        ("admin".to_owned(), Some("line\rbreak".to_owned())),
    ] {
        assert_eq!(
            AdminActor::new(id, reason).unwrap_err(),
            AdminError::InvalidInput
        );
    }
}

#[test]
fn page_cursor_accepts_only_url_safe_base64() {
    assert!(PageCursor::parse("abc-_XYZ019").is_ok());
    for bad in [
        String::new(),
        "a".repeat(MAX_PAGE_CURSOR_BYTES + 1),
        "abc+/=".to_owned(),
        "abc def".to_owned(),
    ] {
        assert_eq!(
            PageCursor::parse(&bad).unwrap_err(),
            AdminError::InvalidInput
        );
    }
}

#[test]
fn admin_event_id_and_action_round_trip() {
    let id = "evt_000102030405060708090a0b0c0d0e0f";
    assert_eq!(AdminEventId::parse(id).expect("id").as_str(), id);
    assert!(AdminEventId::parse("evt_00").is_err());
    for action in [
        AdminAction::RevokeSession,
        AdminAction::DisableUser,
        AdminAction::EnableUser,
    ] {
        assert_eq!(AdminAction::parse(action.as_str()), Ok(action));
    }
    assert!(AdminAction::parse("delete_user").is_err());
}

#[test]
fn session_status_prefers_revocation_over_expiry() {
    let session = SessionSummary {
        handle: SessionHandle::parse(HANDLE).expect("handle"),
        user_id: UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id"),
        email: NormalizedEmail::parse("user@example.test").expect("email"),
        created_at_unix: 100,
        expires_at_unix: 200,
        revoked_at_unix: None,
        revoked_by: None,
    };
    assert_eq!(session.status(200), SessionStatus::Active);
    assert_eq!(session.status(201), SessionStatus::Expired);
    let revoked = SessionSummary {
        revoked_at_unix: Some(150),
        ..session
    };
    assert_eq!(revoked.status(160), SessionStatus::Revoked);
    assert_eq!(revoked.status(500), SessionStatus::Revoked);
}

#[test]
fn page_limits_are_clamped() {
    assert_eq!(clamp_limit(0), 1);
    assert_eq!(clamp_limit(25), 25);
    assert_eq!(clamp_limit(u32::MAX), MAX_ADMIN_PAGE_SIZE);
}

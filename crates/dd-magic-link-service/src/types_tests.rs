//! Service type tests.

use super::*;

#[test]
fn ids_and_keys_are_validated_and_redacted() {
    let user = UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id");
    let session =
        SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("session id");
    let client = ClientKey::parse("client-key_123").expect("client key");

    assert_eq!(format!("{user:?}"), "UserId(..)");
    assert_eq!(format!("{session:?}"), "SessionId(..)");
    assert_eq!(format!("{client:?}"), "ClientKey(..)");
}

#[test]
fn invalid_ids_and_keys_are_rejected() {
    assert_eq!(
        UserId::parse("user_000102030405060708090a0b0c0d0e0f").unwrap_err(),
        MagicLinkServiceError::Internal
    );
    assert_eq!(
        SessionId::parse("sid_short").unwrap_err(),
        MagicLinkServiceError::Internal
    );
    assert_eq!(
        ClientKey::parse("bad key with spaces").unwrap_err(),
        MagicLinkServiceError::BadRequest
    );
}

#[test]
fn country_shape_is_strict() {
    assert!(validate_country("HU").is_ok());
    assert_eq!(
        validate_country("hu").unwrap_err(),
        MagicLinkServiceError::BadRequest
    );
    assert_eq!(
        validate_country("HUN").unwrap_err(),
        MagicLinkServiceError::BadRequest
    );
}

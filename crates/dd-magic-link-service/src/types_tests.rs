//! Service type tests.

use dd_magic_link_core::{
    LookupHmacKey, MagicLinkSelector, NormalizedEmail, VerifierHash, selector_lookup_hmac,
};

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

#[test]
fn authentication_attempt_id_grammar_is_strict_and_debug_is_redacted() {
    let canonical = "aid_000102030405060708090a0b0c0d0e0f";
    let attempt_id = AuthenticationAttemptId::parse(canonical).expect("canonical attempt id");

    assert_eq!(attempt_id.as_str(), canonical);
    assert_eq!(format!("{attempt_id:?}"), "AuthenticationAttemptId(..)");

    for malformed in [
        "000102030405060708090a0b0c0d0e0f",
        "aid_000102030405060708090a0b0c0d0e0",
        "aid_000102030405060708090a0b0c0d0e0f0",
        "aid_000102030405060708090A0B0C0D0E0F",
        "aid_000102030405060708090a0b0c0d0e0g",
        "aid__000102030405060708090a0b0c0d0e0f",
    ] {
        assert_eq!(
            AuthenticationAttemptId::parse(malformed).unwrap_err(),
            MagicLinkServiceError::Internal,
            "malformed attempt id should fail: {malformed}"
        );
    }
}

#[test]
fn authentication_dto_debug_redacts_identity_and_secret_derived_values() {
    let email_value = "account@example.test";
    let user_id_value = "usr_000102030405060708090a0b0c0d0e0f";
    let session_id_value = "sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let attempt_id_value = "aid_101112131415161718191a1b1c1d1e1f";
    let verifier_hash_value =
        "mlv_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let email = NormalizedEmail::parse(email_value).expect("normalized email");
    let user_id = UserId::parse(user_id_value).expect("user id");
    let session_id = SessionId::parse(session_id_value).expect("session id");
    let attempt_id =
        AuthenticationAttemptId::parse(attempt_id_value).expect("authentication attempt id");
    let verifier_hash =
        VerifierHash::parse_storage_value(verifier_hash_value).expect("verifier hash");
    let lookup_key = LookupHmacKey::new([7_u8; 32]);
    let selector =
        MagicLinkSelector::parse("000102030405060708090a0b0c0d0e0f").expect("magic-link selector");
    let selector_lookup_hmac =
        selector_lookup_hmac(&lookup_key, &selector).expect("selector lookup hmac");
    let selector_lookup_value = selector_lookup_hmac.as_storage_value().to_owned();

    let candidate = MagicLinkAuthenticationCandidate {
        verifier_hash,
        email: email.clone(),
        expires_at_unix: 2_000,
        consumed_at_unix: None,
        terms_version: "terms-v1".to_owned(),
        privacy_version: "privacy-v1".to_owned(),
        consented_at_unix: 1_000,
    };
    let expectation = MagicLinkAuthenticationExpectation {
        selector_lookup_hmac,
        email: email.clone(),
        expires_at_unix: candidate.expires_at_unix,
        terms_version: candidate.terms_version.clone(),
        privacy_version: candidate.privacy_version.clone(),
        consented_at_unix: candidate.consented_at_unix,
    };
    let create_user = MagicLinkAuthenticationUser::Create {
        user_id: user_id.clone(),
    };
    let existing_user = MagicLinkAuthenticationUser::Existing { user_id };
    let command = CommitMagicLinkAuthentication {
        magic_link: expectation.clone(),
        now_unix: 1_500,
        attempt_id,
        user: create_user.clone(),
        session_id,
        session_expires_at_unix: 3_000,
    };

    let debug_values = [
        format!("{candidate:?}"),
        format!("{expectation:?}"),
        format!("{create_user:?}"),
        format!("{existing_user:?}"),
        format!("{command:?}"),
    ];
    for debug_value in debug_values {
        for sensitive_value in [
            email_value,
            user_id_value,
            session_id_value,
            attempt_id_value,
            verifier_hash_value,
            selector_lookup_value.as_str(),
        ] {
            assert!(
                !debug_value.contains(sensitive_value),
                "debug output exposed sensitive value: {debug_value}"
            );
        }
    }
}

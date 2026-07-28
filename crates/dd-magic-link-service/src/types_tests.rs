//! Service type tests.

use dd_magic_link_core::{
    LookupHmacKey, MagicLinkSelector, NormalizedEmail, VerifierHash, selector_lookup_hmac,
};

use super::*;
use crate::error::TemporaryAuthStateAction;

#[test]
fn ids_are_validated_and_redacted() {
    let user = UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id");
    let session =
        SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("session id");

    assert_eq!(format!("{user:?}"), "UserId(..)");
    assert_eq!(format!("{session:?}"), "SessionId(..)");
}

#[test]
fn invalid_ids_are_rejected() {
    assert_eq!(
        UserId::parse("user_000102030405060708090a0b0c0d0e0f").unwrap_err(),
        MagicLinkServiceError::Internal
    );
    assert_eq!(
        SessionId::parse("sid_short").unwrap_err(),
        MagicLinkServiceError::Internal
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
fn scanner_commands_are_bounded_and_debug_redacts_all_sensitive_fields() {
    let bounded_value = "malformed-secret-sentinel".to_owned();
    let bounded = BeginMagicLinkLandingCommand::new(bounded_value.clone());
    assert_eq!(bounded.raw_token(), Some(bounded_value.as_str()));
    let bounded_debug = format!("{bounded:?}");
    assert_eq!(bounded_debug, "BeginMagicLinkLandingCommand(..)");
    assert!(!bounded_debug.contains(&bounded_value));

    let oversized_value = "x".repeat(MAX_RAW_MAGIC_LINK_TOKEN_BYTES + 1);
    let oversized = BeginMagicLinkLandingCommand::new(oversized_value.clone());
    assert_eq!(oversized.raw_token(), None);
    assert!(!format!("{oversized:?}").contains(&oversized_value));

    let confirm = ConfirmMagicLinkFlowCommand::new(
        "cookie-secret-sentinel".to_owned(),
        "confirmation-secret-sentinel".to_owned(),
        Some("HU".to_owned()),
    )
    .expect("confirmation command");
    let confirm_debug = format!("{confirm:?}");
    assert_eq!(confirm_debug, "ConfirmMagicLinkFlowCommand(..)");
    for secret in ["cookie-secret-sentinel", "confirmation-secret-sentinel"] {
        assert!(!confirm_debug.contains(secret));
    }
}

#[test]
fn account_identity_is_exact_and_redacted() {
    let email = NormalizedEmail::parse("Exact.Account+tag@example.test").expect("email");
    let identity = MagicLinkAccountIdentity::from_normalized_email(&email);
    assert_eq!(identity.as_str(), "Exact.Account+tag@example.test");
    assert_eq!(format!("{identity:?}"), "MagicLinkAccountIdentity(..)");
}

#[test]
fn flow_error_action_is_structurally_clear_except_for_unavailable() {
    for public_error in [
        MagicLinkServiceError::BadRequest,
        MagicLinkServiceError::MagicLinkUnavailable,
        MagicLinkServiceError::Internal,
    ] {
        let error = MagicLinkFlowError::from_public_error(public_error);
        assert_eq!(error.public_error(), public_error);
        assert_eq!(
            error.temporary_state_action(),
            TemporaryAuthStateAction::Clear
        );
    }
    let unavailable = MagicLinkFlowError::from_public_error(MagicLinkServiceError::Unavailable);
    assert_eq!(
        unavailable.temporary_state_action(),
        TemporaryAuthStateAction::Preserve
    );
}

#[test]
fn confirmation_country_validation_maps_to_clear_bad_request() {
    let error = ConfirmMagicLinkFlowCommand::new(
        "cookie".to_owned(),
        "confirmation".to_owned(),
        Some("hu".to_owned()),
    )
    .expect_err("invalid country");
    assert_eq!(error.public_error(), MagicLinkServiceError::BadRequest);
    assert_eq!(
        error.temporary_state_action(),
        TemporaryAuthStateAction::Clear
    );
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

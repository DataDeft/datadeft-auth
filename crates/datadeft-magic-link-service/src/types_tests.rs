//! Service type tests.

use datadeft_magic_link_core::{
    LookupHmacKey, MagicLinkSelector, NormalizedEmail, VerifierHash, selector_lookup_hmac,
};

use super::*;
use crate::error::TemporaryAuthStateAction;
use crate::error::{MagicLinkFlowError, MagicLinkServiceError};

#[test]
fn ids_are_validated_and_redacted() {
    let user = UserId::parse("usr-000102030405060708090a0b0c0d0e0f").expect("user id");
    let session =
        SessionId::parse("sid-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
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

/// CeleraTax #1: ids use `<tag>-<hex>`. The 0.4 underscore form is refused,
/// not migrated.
#[test]
fn ids_accept_only_the_hyphen_form() {
    let user = format!("usr-{}", "0a".repeat(16));
    let session = format!("sid-{}", "0a".repeat(32));
    let attempt = format!("aid-{}", "0a".repeat(16));
    assert_eq!(UserId::parse(&user).expect("user").as_str(), user);
    assert_eq!(
        SessionId::parse(&session).expect("session").as_str(),
        session
    );
    assert_eq!(
        AuthenticationAttemptId::parse(&attempt)
            .expect("attempt")
            .as_str(),
        attempt
    );
    assert!(UserId::parse(&user.replace('-', "_")).is_err());
    assert!(SessionId::parse(&session.replace('-', "_")).is_err());
    assert!(AuthenticationAttemptId::parse(&attempt.replace('-', "_")).is_err());
    assert_eq!(
        format!("{:?}", UserId::parse(&user).expect("user")),
        "UserId(..)"
    );
    assert_eq!(
        format!("{:?}", SessionId::parse(&session).expect("session")),
        "SessionId(..)"
    );
}

#[test]
fn authentication_attempt_id_grammar_is_strict_and_debug_is_redacted() {
    let canonical = "aid-000102030405060708090a0b0c0d0e0f";
    let attempt_id = AuthenticationAttemptId::parse(canonical).expect("canonical attempt id");

    assert_eq!(attempt_id.as_str(), canonical);
    assert_eq!(format!("{attempt_id:?}"), "AuthenticationAttemptId(..)");

    for malformed in [
        "000102030405060708090a0b0c0d0e0f",
        "aid-000102030405060708090a0b0c0d0e0",
        "aid-000102030405060708090a0b0c0d0e0f0",
        "aid-000102030405060708090A0B0C0D0E0F",
        "aid-000102030405060708090a0b0c0d0e0g",
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
fn account_identity_is_masked_by_default_and_redacted() {
    let email = NormalizedEmail::from_normalized("exact.account+tag@example.test").expect("email");
    assert_eq!(AccountDisplay::default(), AccountDisplay::Masked);
    let masked = MagicLinkAccountIdentity::new(&email, AccountDisplay::Masked);
    assert_eq!(
        masked.as_str(),
        "e\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}@example.test"
    );
    // The mask has a fixed length: a short and a long local part look alike.
    let short = NormalizedEmail::from_normalized("e@example.test").expect("email");
    assert_eq!(
        MagicLinkAccountIdentity::new(&short, AccountDisplay::Masked).as_str(),
        masked.as_str()
    );
    let full = MagicLinkAccountIdentity::new(&email, AccountDisplay::Full);
    assert_eq!(full.as_str(), "exact.account+tag@example.test");
    assert_eq!(format!("{masked:?}"), "MagicLinkAccountIdentity(..)");
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
    let user_id_value = "usr-000102030405060708090a0b0c0d0e0f";
    let session_id_value = "sid-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let attempt_id_value = "aid-101112131415161718191a1b1c1d1e1f";
    let verifier_hash_value =
        "mlv_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let email = NormalizedEmail::from_normalized(email_value).expect("normalized email");
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

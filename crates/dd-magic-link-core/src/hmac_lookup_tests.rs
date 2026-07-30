//! HMAC lookup tests.

use super::*;
use crate::confirm_cookie::MAGIC_LINK_CONFIRM_BINDING_BYTES;
use crate::email::NormalizedEmail;
use crate::magic_link::{MagicLinkSelector, MagicLinkVerifier};

fn key() -> LookupHmacKey {
    LookupHmacKey::new([0x42; HMAC_KEY_BYTES])
}

fn binding_bytes(encoded: &str) -> [u8; MAGIC_LINK_CONFIRM_BINDING_BYTES] {
    let bytes = hex::decode(encoded).expect("binding vector is valid hex");
    bytes.try_into().expect("binding vector is 32 bytes")
}

#[test]
fn hmac_outputs_are_prefixed_and_pinned() {
    let email = NormalizedEmail::parse("user@example.com").expect("email");
    let selector = MagicLinkSelector::parse("000102030405060708090a0b0c0d0e0f").expect("selector");
    let verifier = MagicLinkVerifier::parse(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    )
    .expect("verifier");

    assert_eq!(
        email_lookup_hmac(&key(), &email)
            .expect("email hmac")
            .as_storage_value(),
        "emh_7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8"
    );
    assert_eq!(
        selector_lookup_hmac(&key(), &selector)
            .expect("selector hmac")
            .as_storage_value(),
        "mlh_42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21"
    );
    assert_eq!(
        verifier_hash(&key(), &verifier)
            .expect("verifier hmac")
            .as_storage_value(),
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae"
    );
}

#[test]
fn verifier_hash_storage_value_round_trips_canonical_vector() {
    let verifier = MagicLinkVerifier::parse(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    )
    .expect("verifier");
    let generated = verifier_hash(&key(), &verifier).expect("verifier hash");
    let stored = "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae";

    let parsed = VerifierHash::parse_storage_value(stored).expect("canonical storage value");

    assert_eq!(parsed.as_storage_value(), stored);
    assert_eq!(parsed, generated);
    assert!(parsed.matches_hash_constant_time(&generated));
}

#[test]
fn verifier_hash_storage_parser_rejects_malformed_and_noncanonical_values() {
    let malformed = [
        "",
        "mlv_",
        "mlh_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae",
        "MLV_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae",
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbada",
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae0",
        "mlv_Ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae",
        "mlv_ge00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae",
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae\n",
    ];

    for value in malformed {
        assert_eq!(
            VerifierHash::parse_storage_value(value),
            Err(MagicLinkError::InvalidToken),
            "accepted malformed verifier hash storage value"
        );
    }
}

#[test]
fn verifier_hash_matches_in_constant_time_api() {
    let verifier = MagicLinkVerifier::parse(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    )
    .expect("verifier");
    let hash = verifier_hash(&key(), &verifier).expect("hash");
    let other = MagicLinkVerifier::parse(
        "111112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    )
    .expect("other verifier");

    assert!(
        hash.matches_verifier_constant_time(&key(), &verifier)
            .expect("compare")
    );
    assert!(
        !hash
            .matches_verifier_constant_time(&key(), &other)
            .expect("compare")
    );
    assert!(hash.matches_hash_constant_time(&verifier_hash(&key(), &verifier).expect("hash")));
}

#[test]
fn debug_output_redacts_hmac_material() {
    let key = key();
    let email = NormalizedEmail::parse("user@example.com").expect("email");
    let hmac = email_lookup_hmac(&key, &email).expect("email hmac");

    assert_eq!(format!("{key:?}"), "LookupHmacKey(..)");
    let verifier_hash = VerifierHash::parse_storage_value(
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae",
    )
    .expect("verifier hash");

    assert_eq!(format!("{hmac:?}"), "LookupHmac(..)");
    assert!(!format!("{hmac:?}").contains(hmac.as_storage_value()));
    assert_eq!(format!("{verifier_hash:?}"), "VerifierHash(..)");
    assert!(!format!("{verifier_hash:?}").contains(verifier_hash.as_storage_value()));
}

#[test]
fn key_from_slice_rejects_wrong_length() {
    assert_eq!(
        LookupHmacKey::from_slice(b"short").unwrap_err(),
        MagicLinkError::BadKeyLength
    );
}

#[test]
fn confirm_binding_vectors_are_pinned() {
    let selector_lookup = LookupHmac(
        "mlh_42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21".to_owned(),
    );
    let verifier = VerifierHash(
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae".to_owned(),
    );
    let account_lookup = LookupHmac(
        "emh_7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8".to_owned(),
    );

    assert!(
        confirm_selector_binding(&selector_lookup)
            .expect("selector binding")
            .matches_constant_time(&ConfirmSelectorBinding::new(binding_bytes(
                "42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21",
            )))
    );
    assert!(
        confirm_verifier_binding(&verifier)
            .expect("verifier binding")
            .matches_constant_time(&ConfirmVerifierBinding::new(binding_bytes(
                "ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae",
            )))
    );
    assert!(
        confirm_account_binding(&account_lookup)
            .expect("account binding")
            .matches_constant_time(&ConfirmAccountBinding::new(binding_bytes(
                "7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8",
            )))
    );
}

#[test]
fn selector_and_verifier_confirm_bindings_round_trip_canonically() {
    let selector =
        MagicLinkSelector::parse("000102030405060708090a0b0c0d0e0f").expect("selector vector");
    let verifier = MagicLinkVerifier::parse(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    )
    .expect("verifier vector");
    let selector_lookup = selector_lookup_hmac(&key(), &selector).expect("selector lookup");
    let verifier_lookup = verifier_hash(&key(), &verifier).expect("verifier hash");

    let reconstructed_selector = selector_lookup_hmac_from_confirm_binding(
        &confirm_selector_binding(&selector_lookup).expect("selector binding"),
    );
    let reconstructed_verifier = verifier_hash_from_confirm_binding(
        &confirm_verifier_binding(&verifier_lookup).expect("verifier binding"),
    );

    assert_eq!(
        reconstructed_selector.as_storage_value(),
        selector_lookup.as_storage_value()
    );
    assert_eq!(
        reconstructed_verifier.as_storage_value(),
        verifier_lookup.as_storage_value()
    );
}

#[test]
fn confirm_binding_conversions_reject_domain_confusion_and_noncanonical_values() {
    let digest = "42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21";
    let malformed = [
        format!("mlv_{digest}"),
        format!("emh_{digest}"),
        format!("MLH_{digest}"),
        format!("mlh_{}", &digest[..63]),
        format!("mlh_{digest}0"),
        format!("mlh_{}G", &digest[..63]),
        format!("mlh_{}A", &digest[..63]),
        format!("mlh_{digest}\n"),
    ];
    for value in malformed {
        assert_eq!(
            confirm_selector_binding(&LookupHmac(value)).unwrap_err(),
            MagicLinkError::InvalidToken
        );
    }

    assert_eq!(
        confirm_verifier_binding(&VerifierHash(format!("mlh_{digest}"))).unwrap_err(),
        MagicLinkError::InvalidToken
    );
    assert_eq!(
        confirm_account_binding(&LookupHmac(format!("mlh_{digest}"))).unwrap_err(),
        MagicLinkError::InvalidToken
    );
}

#[test]
fn all_confirm_binding_types_match_only_in_constant_time_api() {
    let selector = confirm_selector_binding(&LookupHmac(
        "mlh_42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21".to_owned(),
    ))
    .expect("selector");
    let verifier = confirm_verifier_binding(&VerifierHash(
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae".to_owned(),
    ))
    .expect("verifier");
    let account = confirm_account_binding(&LookupHmac(
        "emh_7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8".to_owned(),
    ))
    .expect("account");

    assert!(
        selector.matches_constant_time(&ConfirmSelectorBinding::new(binding_bytes(
            "42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21",
        )))
    );
    assert!(!selector.matches_constant_time(&ConfirmSelectorBinding::new([0; 32])));
    assert!(
        verifier.matches_constant_time(&ConfirmVerifierBinding::new(binding_bytes(
            "ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae",
        )))
    );
    assert!(!verifier.matches_constant_time(&ConfirmVerifierBinding::new([0; 32])));
    assert!(
        account.matches_constant_time(&ConfirmAccountBinding::new(binding_bytes(
            "7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8",
        )))
    );
    assert!(!account.matches_constant_time(&ConfirmAccountBinding::new([0; 32])));
}

#[test]
fn confirm_binding_debug_output_is_redacted() {
    let selector = confirm_selector_binding(&LookupHmac(
        "mlh_42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21".to_owned(),
    ))
    .expect("selector");
    let verifier = confirm_verifier_binding(&VerifierHash(
        "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae".to_owned(),
    ))
    .expect("verifier");
    let account = confirm_account_binding(&LookupHmac(
        "emh_7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8".to_owned(),
    ))
    .expect("account");

    assert_eq!(format!("{selector:?}"), "ConfirmSelectorBinding(..)");
    assert_eq!(format!("{verifier:?}"), "ConfirmVerifierBinding(..)");
    assert_eq!(format!("{account:?}"), "ConfirmAccountBinding(..)");
}

//! HMAC lookup tests.

use super::*;
use crate::email::NormalizedEmail;
use crate::magic_link::{MagicLinkSelector, MagicLinkVerifier};

fn key() -> LookupHmacKey {
    LookupHmacKey::new([0x42; HMAC_KEY_BYTES])
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
    assert_eq!(format!("{hmac:?}"), "LookupHmac(..)");
    assert!(!format!("{hmac:?}").contains(hmac.as_storage_value()));
}

#[test]
fn key_from_slice_rejects_wrong_length() {
    assert_eq!(
        LookupHmacKey::from_slice(b"short").unwrap_err(),
        MagicLinkError::BadKeyLength
    );
}

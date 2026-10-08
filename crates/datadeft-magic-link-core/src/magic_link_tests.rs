//! Magic-link token tests.

use datadeft_auth_token_core::test_support::CountingRng;

use super::*;

#[test]
fn generated_token_uses_selector_and_verifier_entropy_sizes() {
    let mut rng = CountingRng::starting_at(0);
    let token = MagicLinkToken::generate(&mut rng).expect("generate token");

    assert_eq!(token.selector().as_lookup_value().len(), SELECTOR_HEX_LEN);
    assert_eq!(token.verifier().as_secret_value().len(), VERIFIER_HEX_LEN);
    assert_eq!(
        token.as_secret_value().as_str(),
        "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
    );
}

#[test]
fn parses_current_token_shape() {
    let raw = "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    let token = MagicLinkToken::parse(raw).expect("token parses");

    assert_eq!(token.as_secret_value().as_str(), raw);
    assert_eq!(
        token.selector().as_lookup_value(),
        &raw[5..5 + SELECTOR_HEX_LEN]
    );
}

#[test]
fn malformed_tokens_are_rejected_without_branch_detail() {
    for value in [
        "missing-separator",
        "short.short",
        "000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        "v1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        "mlv2.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f.extra",
        "mlv1.000102030405060708090a0b0c0d0e0F.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        "mlv1.000102030405060708090a0b0c0d0e0g.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2g",
        // Non-canonical: uppercase hex in the verifier and in the prefix.
        "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2F",
        "MLV1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    ] {
        assert_eq!(
            MagicLinkToken::parse(value).unwrap_err(),
            MagicLinkError::InvalidToken
        );
    }
}

#[test]
fn debug_output_redacts_token_parts() {
    let raw = "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    let token = MagicLinkToken::parse(raw).expect("token parses");
    let debug = format!("{token:?}");

    assert_eq!(debug, "MagicLinkToken(..)");
    assert!(!debug.contains(token.selector().as_lookup_value()));
    assert!(!debug.contains(token.verifier().as_secret_value()));
    assert_eq!(format!("{:?}", token.selector()), "MagicLinkSelector(..)");
    assert_eq!(format!("{:?}", token.verifier()), "MagicLinkVerifier(..)");
}

#[test]
fn token_marker_predicate_tracks_the_wire_grammar() {
    // A rendered token must always trip the marker: this is the property the
    // redirect-target guard in the HTTP layer depends on across version bumps.
    let raw = "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    let token = MagicLinkToken::parse(raw).expect("token parses");
    assert!(contains_magic_link_token_marker(
        token.as_secret_value().as_str()
    ));

    // Embedded anywhere, including mid-path and after other text.
    assert!(contains_magic_link_token_marker("/signed-in?t=mlv1.a.b"));
    assert!(contains_magic_link_token_marker("xmlv1.y"));

    // The bare prefix without its separator is not a token shape, and other
    // versions/spellings do not match this guard.
    assert!(!contains_magic_link_token_marker("mlv1"));
    assert!(!contains_magic_link_token_marker("/mlv1x/path"));
    assert!(!contains_magic_link_token_marker("/plain/path"));
    assert!(!contains_magic_link_token_marker(""));
}

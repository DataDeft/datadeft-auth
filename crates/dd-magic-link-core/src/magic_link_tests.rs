//! Magic-link token tests.

use super::*;
use rand_core::{CryptoRng, RngCore};

struct FixedRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl FixedRng {
    fn new() -> Self {
        let bytes = (0u8..48).collect();
        Self { bytes, offset: 0 }
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.offset + dest.len();
        dest.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

#[test]
fn generated_token_uses_selector_and_verifier_entropy_sizes() {
    let mut rng = FixedRng::new();
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

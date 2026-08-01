//! `encode_with_nonce` is a nonce-reuse footgun and must be reachable only with
//! the `test-support` feature (or the crate's own tests).
//!
//! This whole file compiles to nothing unless `test-support` is enabled, so it
//! proves the symbol *exists and works* under the feature. The CI "public API
//! guard" job proves the complementary half: that the symbol is gated and the
//! crate builds without it: since Rust cannot assert a symbol's *absence* from
//! within a normal test.

#![cfg(feature = "test-support")]

use dd_auth_token_core::branca;

#[test]
fn encode_with_nonce_is_available_under_test_support() {
    let key = [0x11u8; branca::KEY_BYTES];
    let nonce = [0x22u8; branca::NONCE_BYTES];
    let token = branca::encode_with_nonce(b"payload", &key, &nonce, 1).expect("encode");
    let verified = branca::decode(&token, &key).expect("decode");
    assert_eq!(verified.payload, b"payload");
    assert_eq!(verified.nonce, nonce);
}

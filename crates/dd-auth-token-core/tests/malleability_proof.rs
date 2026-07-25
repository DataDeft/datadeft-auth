//! Regression test for base62 token malleability.
//!
//! base62 is a big-integer codec, so `"0"+token`, `"00"+token`, … all decode to
//! the same blob. Before the canonicality gate in `branca::decode`, every such
//! spelling authenticated identically — one token had unboundedly many valid
//! strings (malleability, not forgery: the AEAD payload is unchanged). This test
//! pins the fix: only the canonical spelling authenticates.

use dd_auth_token_core::branca;
use proptest::prelude::*;

#[test]
fn zero_prefixed_tokens_are_rejected() {
    let key = b"supersecretkeyyoushouldnotcommit";
    let nonce = [7u8; branca::NONCE_BYTES];
    let token = branca::encode(b"Hello world!", key, &nonce, 123_206_400).expect("encode");

    // Baseline: the canonical token authenticates.
    assert!(branca::decode(&token, key).is_ok());

    // Non-canonical spellings must all be rejected.
    for k in 1..=6 {
        let forged = format!("{}{}", "0".repeat(k), token);
        assert_ne!(forged, token, "spelling is genuinely different (k={k})");
        assert!(
            branca::decode(&forged, key).is_err(),
            "non-canonical token (k={k}) must be rejected: {forged}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// PROPERTY: for any token and any run of `k >= 1` leading zeros, the
    /// canonical token authenticates to exactly its minted fields and every
    /// zero-prefixed spelling is rejected.
    #[test]
    fn any_leading_zero_run_is_rejected(
        payload in prop::collection::vec(any::<u8>(), 0..64),
        nonce in prop::array::uniform24(any::<u8>()),
        timestamp in any::<u32>(),
        k in 1usize..40,
    ) {
        let key = [0x11u8; branca::KEY_BYTES];
        let token = branca::encode(&payload, &key, &nonce, timestamp).unwrap();

        // Canonical token authenticates to the minted fields; Jti tracks the nonce.
        let v = branca::decode(&token, &key).unwrap();
        prop_assert_eq!(v.timestamp, timestamp);
        prop_assert_eq!(&v.payload, &payload);
        prop_assert_eq!(v.nonce, nonce);
        let jti = v.jti();
        prop_assert_eq!(jti.as_bytes(), &nonce);

        // Every zero-prefixed spelling is rejected.
        let forged = format!("{}{}", "0".repeat(k), token);
        prop_assert!(branca::decode(&forged, &key).is_err());
    }
}

//! Regression test for base62 token malleability.
//!
//! base62 is a big-integer codec, so `"0"+token`, `"00"+token`, … all decode to
//! the same blob. Before the canonicality gate in `branca::decode`, every such
//! spelling authenticated identically: one token had unboundedly many valid
//! strings (malleability, not forgery: the AEAD payload is unchanged). This test
//! pins the fix: only the canonical spelling authenticates.

use datadeft_auth_token_core::branca;
use proptest::prelude::*;
use rand_core::{CryptoRng, RngCore};

struct FixedNonceRng([u8; branca::NONCE_BYTES]);

impl RngCore for FixedNonceRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(
            dest.len(),
            self.0.len(),
            "Branca requests exactly one nonce"
        );
        dest.copy_from_slice(&self.0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedNonceRng {}

fn encode_with_fixed_nonce(
    payload: &[u8],
    key: &[u8],
    nonce: [u8; branca::NONCE_BYTES],
    timestamp: u32,
) -> String {
    let mut rng = FixedNonceRng(nonce);
    branca::encode(payload, key, &mut rng, timestamp).expect("encode")
}

#[test]
fn zero_prefixed_tokens_are_rejected() {
    let key = b"supersecretkeyyoushouldnotcommit";
    let nonce = [7u8; branca::NONCE_BYTES];
    let token = encode_with_fixed_nonce(b"Hello world!", key, nonce, 123_206_400);

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
        let token = encode_with_fixed_nonce(&payload, &key, nonce, timestamp);

        // The canonical token authenticates to the minted fields. Jti tracks the nonce.
        let v = branca::decode(&token, &key).unwrap();
        prop_assert_eq!(v.timestamp(), timestamp);
        prop_assert_eq!(v.payload(), payload.as_slice());
        prop_assert_eq!(v.nonce(), &nonce);
        let jti = v.jti();
        prop_assert_eq!(jti.as_bytes(), &nonce);

        // Every zero-prefixed spelling is rejected.
        let forged = format!("{}{}", "0".repeat(k), token);
        prop_assert!(branca::decode(&forged, &key).is_err());
    }

    /// PROPERTY: inserting `\n` or `\r` at any position is rejected. These
    /// were the second malleable spelling family: the codec used to strip
    /// them, so `"ab\nc"` decoded identically to `"abc"` and only the
    /// re-encode backstop rejected it. The codec now rejects non-alphabet
    /// bytes outright, which this pins.
    #[test]
    fn any_newline_insertion_is_rejected(
        payload in prop::collection::vec(any::<u8>(), 0..64),
        nonce in prop::array::uniform24(any::<u8>()),
        timestamp in any::<u32>(),
        position in any::<prop::sample::Index>(),
        newline in prop::sample::select(vec![b'\n', b'\r']),
    ) {
        let key = [0x11u8; branca::KEY_BYTES];
        let token = encode_with_fixed_nonce(&payload, &key, nonce, timestamp);

        let mut forged = token.clone().into_bytes();
        forged.insert(position.index(forged.len() + 1), newline);
        let forged = String::from_utf8(forged).expect("ascii plus newline");
        prop_assert_ne!(&forged, &token);
        prop_assert!(branca::decode(&forged, &key).is_err());
    }
}

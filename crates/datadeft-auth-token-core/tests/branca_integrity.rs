//! Branca + base62 security properties through the public API only.
//!
//! - Integrity: any bit flip in the decoded blob, any truncation, extension,
//!   or prefix of the token string is rejected.
//! - Canonicality: every accepted string is the unique spelling of its blob,
//!   and the base62 codec's two integer-codec quirks (leading `'0'` digits,
//!   leading `0x00` bytes) are characterized exactly.
//! - Totality: decoders never panic on arbitrary input (non-ASCII, NUL, huge).
//! - Entropy: a real OS RNG never repeats a nonce across many mints, a fixed
//!   RNG reproduces the official golden vector through `encode`, and a failing
//!   RNG yields `EntropyUnavailable` instead of a token.
//!
//! Labeling: a non-canonical spelling that authenticates is *malleability*
//! (same payload, new string), not forgery. A bit flip that authenticates
//! would be forgery. Both are asserted absent here.

use datadeft_auth_token_core::TokenError;
use datadeft_auth_token_core::base62;
use datadeft_auth_token_core::branca;
use proptest::prelude::*;
use rand_core::{CryptoRng, OsRng, RngCore};

const ALPHABET: &[u8; 62] = base62::ENCODE_STD;
const KEY: [u8; branca::KEY_BYTES] = [0x11; branca::KEY_BYTES];

/// Returns the same fixed nonce on every draw.
struct FixedNonceRng([u8; branca::NONCE_BYTES]);

impl RngCore for FixedNonceRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(dest.len(), branca::NONCE_BYTES, "one Branca nonce draw");
        dest.copy_from_slice(&self.0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedNonceRng {}

/// Every draw fails: models an exhausted or broken entropy source.
struct BrokenRng;

impl RngCore for BrokenRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Err(rand_core::Error::from(
            core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).expect("nonzero"),
        ))
    }
}

impl CryptoRng for BrokenRng {}

fn mint(payload: &[u8], nonce: [u8; branca::NONCE_BYTES], timestamp: u32) -> String {
    branca::encode(payload, &KEY, &mut FixedNonceRng(nonce), timestamp).expect("encode")
}

// --- Golden / entropy ------------------------------------------------------

/// Official Branca vector #0 (`tests/fixtures/branca_test.json`), reproduced
/// through the public RNG-driven `encode`, not the gated fixed-nonce helper.
/// Fails if the wire format, header layout, AAD binding, or base62 alphabet
/// ever changes.
#[test]
fn deterministic_rng_reproduces_official_golden_vector() {
    let key = b"supersecretkeyyoushouldnotcommit";
    let mut nonce = [0u8; branca::NONCE_BYTES];
    for pair in nonce.chunks_mut(2) {
        pair.copy_from_slice(&[0xbe, 0xef]);
    }
    let token = branca::encode(b"Hello world!", key, &mut FixedNonceRng(nonce), 0).expect("encode");
    assert_eq!(
        token,
        "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"
    );
    let verified = branca::decode(&token, key).expect("decode");
    assert_eq!(verified.nonce(), &nonce);
    assert_eq!(verified.timestamp(), 0);
}

#[test]
fn failing_rng_yields_entropy_unavailable_not_a_weak_token() {
    assert_eq!(
        branca::encode(b"payload", &KEY, &mut BrokenRng, 1).unwrap_err(),
        TokenError::EntropyUnavailable
    );
}

/// Sanity check of the production RNG wiring, not of RNG quality: 192-bit
/// nonces from the OS CSPRNG never collide across 4096 mints, so every token
/// and every `Jti` is distinct.
#[test]
fn os_rng_mints_never_repeat_a_nonce() {
    let mut nonces = std::collections::HashSet::new();
    let mut tokens = std::collections::HashSet::new();
    for _ in 0..4096 {
        let token = branca::encode(b"same payload", &KEY, &mut OsRng, 1_000).expect("encode");
        let verified = branca::decode(&token, &KEY).expect("decode");
        assert!(nonces.insert(*verified.jti().as_bytes()), "nonce repeated");
        assert!(tokens.insert(token), "token repeated");
    }
}

// --- Time ------------------------------------------------------------------

#[test]
fn timestamp_extremes_round_trip_as_authenticated_header() {
    // 0, the signed 32-bit rollover (2038), one past it, and the unsigned max
    // (2106). The timestamp is AAD, so it must come back bit-exact.
    for timestamp in [
        0,
        i32::MAX as u32,
        (i32::MAX as u32) + 1,
        u32::MAX - 1,
        u32::MAX,
    ] {
        let token = mint(b"t", [0x42; branca::NONCE_BYTES], timestamp);
        let verified = branca::decode(&token, &KEY).expect("decode");
        assert_eq!(verified.timestamp(), timestamp);
    }
}

// --- Totality --------------------------------------------------------------

#[test]
fn huge_inputs_are_rejected_cheaply_without_panicking() {
    let huge = "z".repeat(8 * 1024 * 1024);
    assert_eq!(
        branca::decode(&huge, &KEY).unwrap_err(),
        TokenError::PayloadTooLarge
    );
    // Just under the string cap, but the decoded blob exceeds the blob cap.
    let near_cap = "z".repeat(branca::MAX_TOKEN_BYTES);
    assert!(branca::decode(&near_cap, &KEY).is_err());
    // Embedded NUL and multi-byte UTF-8 fail as bad base62, not a panic.
    for input in ["\0", "abc\0def", "\u{feff}abc", "ß", "😀😀", ""] {
        assert!(branca::decode(input, &KEY).is_err(), "{input:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Totality: arbitrary Unicode (including NUL and control chars) never
    /// panics either decoder. `branca::decode` has a `debug_assert` that an
    /// accepted string is canonical, so a non-canonical acceptance would panic
    /// here in a debug build.
    #[test]
    fn decoders_are_total_on_arbitrary_strings(input in "\\PC{0,300}|[\\x00-\\x7f]{0,300}") {
        let _ = base62::decode(&input);
        let _ = branca::decode(&input, &KEY);
    }

    /// Totality: arbitrary alphabet-only strings, which pass the charset gate
    /// and reach the radix conversion, length/version gates, and AEAD.
    #[test]
    fn branca_decode_is_total_on_alphabet_strings(input in "[0-9A-Za-z]{0,1500}") {
        let _ = branca::decode(&input, &KEY);
    }

    /// Codec characterization (non-canonicality is exactly leading '0'):
    /// for any alphabet string, `encode(decode(s))` is `s` with its leading
    /// '0' digits removed. Nothing else is ever rewritten.
    #[test]
    fn base62_reencode_strips_only_leading_zero_digits(s in "[0-9A-Za-z]{0,200}") {
        let decoded = base62::decode(&s).expect("alphabet decodes");
        prop_assert_eq!(base62::encode(&decoded), s.trim_start_matches('0'));
    }

    /// Codec characterization (leading 0x00 loss is exactly leading zeros):
    /// `decode(encode(b))` is `b` with its leading 0x00 bytes removed.
    #[test]
    fn base62_round_trip_drops_only_leading_zero_bytes(
        zeros in 0usize..4,
        rest in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut bytes = vec![0u8; zeros];
        bytes.extend_from_slice(&rest);
        let expected: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
        prop_assert_eq!(base62::decode(&base62::encode(&bytes)).expect("decodes"), expected);
    }

    /// Integrity at the blob level: flipping ANY single bit of the decoded
    /// Branca blob (version, timestamp, nonce, ciphertext, or tag) and
    /// re-encoding canonically never authenticates.
    #[test]
    fn any_single_blob_bit_flip_is_rejected(
        payload in prop::collection::vec(any::<u8>(), 0..48),
        nonce in prop::array::uniform24(any::<u8>()),
        timestamp in any::<u32>(),
        bit in any::<prop::sample::Index>(),
    ) {
        let token = mint(&payload, nonce, timestamp);
        let mut blob = base62::decode(&token).expect("own token decodes");
        let bit = bit.index(blob.len() * 8);
        blob[bit / 8] ^= 1 << (bit % 8);
        let tampered = base62::encode(&blob);
        prop_assert!(branca::decode(&tampered, &KEY).is_err(), "bit {} accepted", bit);
    }

    /// Integrity at the string level: every strict prefix (truncation), any
    /// appended alphabet suffix (extension), and any prepended non-'0' digit
    /// is rejected. Prepended '0' runs are covered by `malleability_proof.rs`.
    #[test]
    fn truncation_extension_and_prefixing_are_rejected(
        payload in prop::collection::vec(any::<u8>(), 0..48),
        nonce in prop::array::uniform24(any::<u8>()),
        timestamp in any::<u32>(),
        cut in any::<prop::sample::Index>(),
        suffix in "[0-9A-Za-z]{1,8}",
        prefix in "[1-9A-Za-z]",
    ) {
        let token = mint(&payload, nonce, timestamp);
        let truncated = &token[..cut.index(token.len())];
        prop_assert!(branca::decode(truncated, &KEY).is_err());
        let extended = format!("{token}{suffix}");
        prop_assert!(branca::decode(&extended, &KEY).is_err());
        let prefixed = format!("{prefix}{token}");
        prop_assert!(branca::decode(&prefixed, &KEY).is_err());
    }

    /// Canonicality: apply a random edit (substitute, insert, delete, swap
    /// case, prepend zeros) to a valid token. If the edited string still
    /// authenticates, it MUST be byte-identical to the original: there is no
    /// second spelling of an accepted token.
    #[test]
    fn no_second_spelling_authenticates(
        payload in prop::collection::vec(any::<u8>(), 0..32),
        nonce in prop::array::uniform24(any::<u8>()),
        timestamp in any::<u32>(),
        edit in 0usize..5,
        pos in any::<prop::sample::Index>(),
        ch in prop::sample::select(ALPHABET.to_vec()),
        zeros in 1usize..4,
    ) {
        let token = mint(&payload, nonce, timestamp);
        let mut bytes = token.clone().into_bytes();
        let i = pos.index(bytes.len());
        match edit {
            0 => bytes[i] = ch,
            1 => bytes.insert(i, ch),
            2 => {
                bytes.remove(i);
            }
            3 => bytes[i] = if bytes[i].is_ascii_lowercase() {
                bytes[i].to_ascii_uppercase()
            } else {
                bytes[i].to_ascii_lowercase()
            },
            _ => {
                let mut prefixed = vec![b'0'; zeros];
                prefixed.extend_from_slice(&bytes);
                bytes = prefixed;
            }
        }
        let edited = String::from_utf8(bytes).expect("ascii");
        if let Ok(verified) = branca::decode(&edited, &KEY) {
            prop_assert_eq!(&edited, &token);
            prop_assert_eq!(verified.payload(), payload.as_slice());
        }
        // Every accepted string re-encodes to itself.
        if branca::decode(&edited, &KEY).is_ok() {
            let blob = base62::decode(&edited).expect("accepted implies base62");
            prop_assert_eq!(base62::encode(&blob), edited);
        }
    }
}

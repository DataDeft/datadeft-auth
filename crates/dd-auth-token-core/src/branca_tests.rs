//! `branca` tests: official spec vectors (encoding + decoding), round trips,
//! TTL-free determinism, and a single-character tamper property.

use super::*;
use proptest::prelude::*;
use serde::Deserialize;
use std::fs;

const FIXTURE: &str = "tests/fixtures/branca_test.json";

#[derive(Debug, Deserialize)]
struct TestFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: u32,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "testType")]
    test_type: String,
    tests: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVector {
    #[allow(dead_code)]
    id: u32,
    #[allow(dead_code)]
    comment: String,
    key: String,
    nonce: Option<String>,
    timestamp: u32,
    token: String,
    msg: String,
    is_valid: bool,
}

fn hex_dec(s: &str) -> Vec<u8> {
    if s.is_empty() {
        Vec::new()
    } else {
        hex::decode(s).expect("fixture hex parses")
    }
}

/** Official Branca test vectors (25 cases across encoding + decoding). This is
 * the authoritative cross-implementation golden: the crate must reproduce the
 * exact token bytes for a known (key, nonce, timestamp, message), and reject
 * every invalid vector.
 */
fn load_fixture() -> TestFile {
    let json = fs::read_to_string(FIXTURE).expect("branca_test.json fixture exists");
    serde_json::from_str(&json).expect("fixture parses")
}

#[test]
fn official_vectors_encode_decode_and_reject() {
    let tests = load_fixture();
    let mut run = 0usize;

    for group in &tests.test_groups {
        for t in &group.tests {
            let key = hex_dec(&t.key);
            let msg = hex_dec(&t.msg);

            if group.test_type == "encoding" {
                let nonce_bytes = hex_dec(t.nonce.as_deref().expect("encoding vector has nonce"));
                let nonce: [u8; NONCE_BYTES] = nonce_bytes
                    .as_slice()
                    .try_into()
                    .expect("fixture nonce is 24 bytes");
                let result = encode_with_nonce(&msg, &key, &nonce, t.timestamp);

                if t.is_valid {
                    let token = result.expect("valid encoding vector should encode");
                    assert_eq!(token, t.token, "token mismatch: {}", t.comment);
                    // Our own token must round-trip.
                    let v = decode(&token, &key).expect("self round-trip");
                    assert_eq!(v.timestamp, t.timestamp);
                    assert_eq!(v.payload, msg);
                } else {
                    assert!(result.is_err(), "should fail: {}", t.comment);
                }
            } else if group.test_type == "decoding" {
                let result = decode(&t.token, &key);
                if t.is_valid {
                    let v = result.expect("valid decoding vector should decode");
                    assert_eq!(v.timestamp, t.timestamp, "timestamp: {}", t.comment);
                    assert_eq!(v.payload, msg, "message: {}", t.comment);
                } else {
                    assert!(result.is_err(), "should fail: {}", t.comment);
                }
            }
            run += 1;
        }
    }

    assert_eq!(
        run, tests.number_of_tests as usize,
        "ran all official vectors"
    );
}

#[test]
fn deterministic_encode_with_fixed_nonce_round_trips() {
    let key = b"supersecretkeyyoushouldnotcommit";
    let nonce = [0u8; NONCE_BYTES];
    let ts = 123_206_400;

    for msg in [b"".as_slice(), b"Hello world!", b"Test", &[0x80]] {
        let token = encode_with_nonce(msg, key, &nonce, ts).expect("encode");
        let v = decode(&token, key).expect("decode");
        assert_eq!(v.timestamp, ts);
        assert_eq!(v.payload, msg);
        assert_eq!(v.nonce, nonce);
        assert_eq!(v.jti().as_bytes(), &nonce);
    }
}

#[test]
fn decode_rejects_wrong_key_version_and_short_key() {
    let key = b"supersecretkeyyoushouldnotcommit";
    let nonce = [0u8; NONCE_BYTES];
    let token = encode_with_nonce(b"Hello world!", key, &nonce, 0).expect("encode");

    // Wrong key → tag mismatch (coarse DecryptFailed).
    let wrong = b"supersecretkeyyoushouldnotcommi.";
    assert_eq!(
        decode(&token, wrong).unwrap_err(),
        TokenError::DecryptFailed
    );

    // Short key is rejected before any crypto.
    assert_eq!(
        decode(&token, b"short").unwrap_err(),
        TokenError::BadKeyLength
    );
    // Tampered version byte (flip the first base62 char deterministically) →
    // either InvalidTokenVersion or InvalidBase62, never Ok.
    let mut bad = token.into_bytes();
    bad[0] = if bad[0] == b'0' { b'1' } else { b'0' };
    assert!(decode(String::from_utf8(bad).unwrap().as_str(), key).is_err());
}

#[test]
fn payload_and_token_size_guards_fire() {
    let key = [0u8; KEY_BYTES];
    let nonce = [0u8; NONCE_BYTES];
    // Payload over 1 KiB is rejected.
    let big = vec![0u8; MAX_PAYLOAD_BYTES + 1];
    assert_eq!(
        encode_with_nonce(&big, &key, &nonce, 0).unwrap_err(),
        TokenError::PayloadTooLarge
    );
    // Oversized token string is rejected pre-decode.
    let huge = "0".repeat(MAX_TOKEN_BYTES + 1);
    assert_eq!(
        decode(&huge, &key).unwrap_err(),
        TokenError::PayloadTooLarge
    );
}

#[test]
fn max_token_bytes_covers_max_blob() {
    let worst_case = vec![0xFF; MAX_TOKEN_BLOB_BYTES];
    let encoded = crate::base62::encode(&worst_case);
    assert!(
        encoded.len() <= MAX_TOKEN_BYTES,
        "max token bound too small: {} > {}",
        encoded.len(),
        MAX_TOKEN_BYTES
    );
    assert_eq!(
        MAX_TOKEN_BYTES,
        max_token_chars_for_payload(MAX_PAYLOAD_BYTES)
    );
}

#[test]
fn non_canonical_zero_prefixed_tokens_are_rejected() {
    let key = [0x11u8; KEY_BYTES];
    let nonce = [0x22u8; NONCE_BYTES];
    let token = encode_with_nonce(b"Hello world!", &key, &nonce, 123_206_400).expect("encode");

    // The canonical token decodes.
    let v = decode(&token, &key).expect("canonical token decodes");
    let jti = v.jti();

    // Every zero-prefixed spelling decodes to the same bytes at the base62 layer
    // but must be rejected as non-canonical by branca::decode.
    for k in 1..=4 {
        let forged = format!("{}{}", "0".repeat(k), token);
        assert_ne!(forged, token);
        assert_eq!(
            decode(&forged, &key).unwrap_err(),
            TokenError::InvalidBase62,
            "zero-prefixed (k={k}) token must be rejected"
        );
    }

    // A different token (different nonce) yields a different Jti; keying
    // revocation on Jti is stable across spellings and unique across tokens.
    let other = encode_with_nonce(b"Hello world!", &key, &[0x23u8; NONCE_BYTES], 123_206_400)
        .expect("encode");
    assert_ne!(decode(&other, &key).unwrap().jti(), jti);
}

#[test]
fn empty_and_non_utf8_payloads_round_trip() {
    let key = [0xAB; KEY_BYTES];
    let nonce = [0xCD; NONCE_BYTES];
    for msg in [b"".as_slice(), &[0x80, 0x81, 0x82]] {
        let token = encode_with_nonce(msg, &key, &nonce, 9_999).expect("encode");
        let got = decode(&token, &key).expect("decode");
        assert_eq!(got.payload, msg);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// PROPERTY (round trip): for any 32-byte key, 24-byte nonce, timestamp,
    /// and payload, encode -> decode returns exactly (timestamp, payload). The
    /// timestamp is authenticated AAD, not incidental metadata.
    #[test]
    fn prop_branca_round_trip(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        payload in prop::collection::vec(any::<u8>(), 0..256),
        timestamp in any::<u32>(),
    ) {
        let token = encode_with_nonce(&payload, &key, &nonce, timestamp).unwrap();
        let v = decode(&token, &key).unwrap();
        prop_assert_eq!(v.timestamp, timestamp);
        prop_assert_eq!(&v.payload, &payload);
        prop_assert_eq!(v.nonce, nonce);
    }

    /// PROPERTY (single-character tamper): replacing any ONE character of a
    /// token with a DIFFERENT base62 character never decodes. Poly1305
    /// authenticates the version/timestamp/nonce header (as AAD) and the
    /// ciphertext alike, and shorter/malformed decodes die on the length /
    /// version gates first.
    #[test]
    fn prop_branca_single_char_tamper_rejected(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        payload in prop::collection::vec(any::<u8>(), 0..64),
        timestamp in any::<u32>(),
        pos in any::<prop::sample::Index>(),
        alphabet_idx in 0usize..62,
    ) {
        let token = encode_with_nonce(&payload, &key, &nonce, timestamp).unwrap();
        let mut bytes = token.into_bytes();
        let i = pos.index(bytes.len());
        let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut replacement = alphabet[alphabet_idx];
        if replacement == bytes[i] {
            replacement = alphabet[(alphabet_idx + 1) % 62];
        }
        bytes[i] = replacement;
        let tampered = String::from_utf8(bytes).unwrap();
        prop_assert!(decode(&tampered, &key).is_err());
    }
}

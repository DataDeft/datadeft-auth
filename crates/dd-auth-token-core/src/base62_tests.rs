//! `base62` tests: Go-parity golden vectors, custom-alphabet parity, newline
//! tolerance, error cases, and a round-trip property.

use super::*;
use proptest::prelude::*;

/// `(source, target)` vectors matching the reference Go base62 implementation
/// (and the upstream `base62` crate). Pinned so a refactor cannot silently
/// change the wire alphabet.
const SAMPLES_STD: &[(&[u8], &str)] = &[
    (b"", ""),
    (b"f", "1e"),
    (b"fo", "6ox"),
    (b"foo", "SAPP"),
    (b"foob", "1sIyuo"),
    (b"fooba", "7kENWa1"),
    (b"foobar", "VytN8Wjy"),
    (b"su", "7gj"),
    (b"sur", "VkRe"),
    (b"sure", "275mAn"),
    (b"sure.", "8jHquZ4"),
    (b"asure.", "UQPPAab8"),
    (b"easure.", "26h8PlupSA"),
    (b"leasure.", "9IzLUOIY2fe"),
    (b"=", "z"),
    (b">", "10"),
    (b"?", "11"),
    (b"11", "3H7"),
    (b"111", "DWfh"),
    (b"1111", "tquAL"),
    (b"11111", "3icRuhV"),
    (b"111111", "FMElG7cn"),
    (b"Hello, World!", "1wJfrzvdbtXUOlUjUf"),
    ("你好，世界！".as_bytes(), "1ugmIChyMAcCbDRpROpAtpXdp"),
    ("こんにちは".as_bytes(), "1fyB0pNlcVqP3tfXZ1FmB"),
    ("안녕하십니까".as_bytes(), "1yl6dfHPaO9hroEXU9qFioFhM"),
];

/// A custom alphabet that is a permutation of the standard one, with its own
/// independent golden vectors (also Go-parity). Proves `new()` honors the
/// supplied alphabet, not a hardcoded one.
const SAMPLES_CUSTOM: &[(&[u8], &str)] = &[
    (b"", ""),
    (b"f", "Bo"),
    (b"foobar", "f83XIgt8"),
    (b"Hello, World!", "B6Tp195nl3heYvetep"),
];

fn custom_alphabet() -> &'static str {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
}

#[test]
fn std_encodes_match_golden_vectors() {
    let enc = Encoding::std();
    for &(src, target) in SAMPLES_STD {
        assert_eq!(enc.encode_to_string(src), target, "encode {src:?}");
    }
}

#[test]
fn std_decodes_match_golden_vectors() {
    let enc = Encoding::std();
    for &(src, target) in SAMPLES_STD {
        assert_eq!(enc.decode_str(target).unwrap(), src, "decode {target}");
    }
}

#[test]
fn custom_alphabet_encodes_and_decodes() {
    let enc = Encoding::new(custom_alphabet()).expect("custom alphabet parses");
    for &(src, target) in SAMPLES_CUSTOM {
        assert_eq!(enc.encode_to_string(src), target, "custom encode {src:?}");
        assert_eq!(
            enc.decode_str(target).unwrap(),
            src,
            "custom decode {target}"
        );
    }
}

#[test]
fn decode_tolerates_embedded_newlines() {
    let enc = Encoding::std();
    assert_eq!(enc.decode(b"FMEl\nG7cn").unwrap(), b"111111");
    assert_eq!(enc.decode(b"FMEl\rG7cn").unwrap(), b"111111");
    assert_eq!(enc.decode(b"\n\r\n\r").unwrap(), Vec::<u8>::new());
}

#[test]
fn decode_rejects_invalid_bytes_with_position() {
    let enc = Encoding::std();
    // '@' is not in the base62 alphabet.
    let err = enc.decode(b"ABC@123").unwrap_err();
    assert_eq!(
        err,
        Base62Error::InvalidByte {
            byte: b'@',
            position: 3
        }
    );
    // Non-alphabet unicode fails too.
    assert!(enc.decode_str("哈哈").is_err());
}

#[test]
fn new_rejects_malformed_alphabets() {
    assert!(Encoding::new("ABC").is_err(), "wrong length");
    // Newline in alphabet.
    let mut bad = ENCODE_STD.to_vec();
    bad[0] = b'\n';
    assert!(Encoding::new(std::str::from_utf8(&bad).unwrap()).is_err());
    // Duplicate byte in alphabet.
    let mut dup = ENCODE_STD.to_vec();
    dup[5] = dup[0]; // two '0's
    assert!(Encoding::new(std::str::from_utf8(&dup).unwrap()).is_err());
    // Non-ASCII alphabets are rejected even when their UTF-8 byte length is 62.
    assert_eq!("é".repeat(31).len(), 62);
    assert!(Encoding::new(&"é".repeat(31)).is_err());
}

#[test]
fn shared_static_matches_fresh_encoding() {
    // The lazy STD_ENCODING must be byte-identical to a freshly built one.
    let fresh = Encoding::std();
    for input in [
        &b""[..],
        b"f",
        b"foobar",
        b"\xba\x00\x01\x02\x03",
        b"Hello, World!",
    ] {
        assert_eq!(encode(input), fresh.encode_to_string(input));
        assert_eq!(decode(&encode(input)).unwrap(), input.to_vec());
    }
}

#[test]
fn integer_codec_limitations_are_pinned() {
    // Documented limitation: base62 is a big-INTEGER codec, not a byte-string
    // codec. These behaviors are intentional and relied upon by branca's
    // canonicality gate; pin them so a refactor cannot silently change them.
    let enc = Encoding::std();

    // 1. A leading 0x00 byte is dropped on a round trip.
    let round = enc
        .decode_str(&enc.encode_to_string(&[0x00, 0x01, 0x02]))
        .unwrap();
    assert_eq!(round, vec![0x01, 0x02], "leading 0x00 is not preserved");

    // 2. Decoding is non-canonical: leading '0' digits decode to the same bytes.
    let base = enc.decode_str("FMElG7cn").unwrap();
    assert_eq!(enc.decode_str("0FMElG7cn").unwrap(), base);
    assert_eq!(enc.decode_str("000FMElG7cn").unwrap(), base);
}

#[test]
fn empty_input_round_trips() {
    let enc = Encoding::std();
    assert_eq!(enc.encode(&[]), Vec::<u8>::new());
    assert_eq!(enc.decode(&[]).unwrap(), Vec::<u8>::new());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// PROPERTY (round trip): `decode(encode(bytes)) == bytes` for any input
    /// whose first byte is nonzero. Base62 here is a big-number encoding, so a
    /// LEADING 0x00 byte carries no digit weight and is dropped on the round
    /// trip. This crate only ever encodes Branca tokens, whose first byte is
    /// the fixed 0xBA version, so that domain restriction matches real usage.
    #[test]
    fn prop_base62_round_trip(
        first in 1u8..=255,
        rest in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut bytes = vec![first];
        bytes.extend_from_slice(&rest);
        let encoded = encode(&bytes);
        prop_assert_eq!(decode(&encoded).unwrap(), bytes);
    }
}

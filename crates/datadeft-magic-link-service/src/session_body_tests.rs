//! Session cookie purpose and body tests.

use datadeft_auth_token_core::keyring::{KEY_BYTES, KeyId, RootSecret};

use super::*;

#[test]
fn session_purpose_constants_are_pinned() {
    assert_eq!(HKDF_INFO_SESSION_COOKIE_V1, b"auth/session-v1");
    assert_eq!(SessionCookie::HKDF_INFO, HKDF_INFO_SESSION_COOKIE_V1);
    assert_eq!(TOKEN_TYPE_SESSION_COOKIE_V1, "session-v1");
    assert_eq!(SessionCookie::TOKEN_TYPE, TOKEN_TYPE_SESSION_COOKIE_V1);
    assert_eq!(SessionCookie::MAX_BODY_BYTES, 128);
    assert_eq!(SessionCookie::MAX_ABSOLUTE_AGE_SECS, 30 * 24 * 60 * 60);
}

#[test]
fn session_hkdf_vector_is_pinned() {
    // HKDF-SHA256 with salt=None, IKM=[0x11; 32], L=32,
    // info = HKDF_INFO || 0x00 || kid. This vector pins the exact info framing.
    // Changing it invalidates every session cookie minted under the previous key.
    let root = RootSecret::new([0x11; KEY_BYTES]);
    let session = root
        .derive_key::<SessionCookie>(&KeyId::parse("session-active").expect("kid parses"))
        .expect("derive session");

    assert_eq!(
        hex::encode(session.as_test_bytes()),
        "eda74d6ba28134ffe9c380e3a14729aa1fa4474dfbf63014a8b82e0325e4b10b"
    );
}

#[test]
fn session_cookie_body_round_trips() {
    let sid =
        SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("sid");
    let encoded = encode_session_cookie_body(&sid, Some("HU")).expect("encode");
    let decoded = decode_session_cookie_body(&encoded).expect("decode");

    assert_eq!(decoded.session_id, sid);
    assert_eq!(decoded.country.as_deref(), Some("HU"));
}

#[test]
fn malformed_session_cookie_body_is_rejected_with_session_vocabulary() {
    for body in [b"".as_slice(), &[2, 0, 0], &[1, 4, b's', b'i', b'd']] {
        let error = decode_session_cookie_body(body).unwrap_err();
        assert_eq!(error, SessionBodyError::Invalid);
        assert_eq!(error.to_string(), "invalid session cookie body");
        assert!(!error.to_string().contains("magic link"));
    }
}

#[test]
fn invalid_country_shape_in_session_cookie_body_is_rejected() {
    let sid = b"sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let mut encoded = Vec::new();
    encoded.push(1);
    encoded.push(u8::try_from(sid.len()).expect("sid length fits"));
    encoded.extend_from_slice(sid);
    encoded.push(2);
    encoded.extend_from_slice(b"hu");
    assert_eq!(
        decode_session_cookie_body(&encoded).unwrap_err(),
        SessionBodyError::Invalid
    );
}

#[test]
fn encoding_invalid_country_shape_is_rejected() {
    let sid =
        SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("sid");

    assert_eq!(
        encode_session_cookie_body(&sid, Some("hu")).unwrap_err(),
        MagicLinkServiceError::BadRequest
    );
}

// --- Canonical framing, tamper, and purpose-separation properties ------------
//
// This crate has no proptest dev-dependency, so the properties below are
// checked exhaustively over every byte position and every byte value, which
// is stronger than sampling for bodies this small.

use datadeft_auth_token_core::branca;
use datadeft_auth_token_core::cookie::{MaxAge, mint_bound_cookie, parse_bound_cookie};
use datadeft_auth_token_core::keyring::{KeyPurpose, KeyRing};
use datadeft_auth_token_core::test_support::{FixedBytesRng, test_keyring};
use datadeft_magic_link_core::MagicLinkConfirmCookie;

const SID: &str = "sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn sid_from_seed(seed: u8) -> SessionId {
    let hex: String = (0..32u8)
        .map(|i| {
            format!(
                "{:02x}",
                seed.wrapping_mul(31).wrapping_add(i.wrapping_mul(seed | 1))
            )
        })
        .collect();
    SessionId::parse(&format!("sid_{hex}")).expect("generated sid")
}

fn reencodes(body: &SessionCookieBody) -> Vec<u8> {
    encode_session_cookie_body(&body.session_id, body.country.as_deref()).expect("re-encode")
}

#[test]
fn session_body_round_trips_for_many_ids_and_countries() {
    for seed in 0..=u8::MAX {
        let sid = sid_from_seed(seed);
        for country in [None, Some("HU"), Some("US"), Some("ZZ")] {
            let encoded = encode_session_cookie_body(&sid, country).expect("encode");
            let decoded = decode_session_cookie_body(&encoded).expect("decode");
            assert_eq!(decoded.session_id, sid);
            assert_eq!(decoded.country.as_deref(), country);
            assert_eq!(
                reencodes(&decoded),
                encoded,
                "decode then encode is identity"
            );
        }
    }
}

#[test]
fn session_body_golden_bytes_are_pinned() {
    let sid = SessionId::parse(SID).expect("sid");
    let mut expected = vec![1u8, 68];
    expected.extend_from_slice(SID.as_bytes());
    expected.extend_from_slice(&[2, b'H', b'U']);
    assert_eq!(
        encode_session_cookie_body(&sid, Some("HU")).expect("encode"),
        expected
    );
    let mut no_country = vec![1u8, 68];
    no_country.extend_from_slice(SID.as_bytes());
    no_country.push(0);
    assert_eq!(
        encode_session_cookie_body(&sid, None).expect("encode"),
        no_country
    );
}

/// Every single-byte substitution at every position: the result is either
/// rejected or decodes to a body whose canonical encoding is exactly the
/// mutated bytes. So no accepted body has a second byte spelling, and no
/// mutation decodes back to the original session.
#[test]
fn every_single_byte_substitution_is_rejected_or_canonical() {
    let sid = SessionId::parse(SID).expect("sid");
    for country in [None, Some("HU")] {
        let original = encode_session_cookie_body(&sid, country).expect("encode");
        for position in 0..original.len() {
            for value in 0..=u8::MAX {
                if original[position] == value {
                    continue;
                }
                let mut mutated = original.clone();
                mutated[position] = value;
                if let Ok(decoded) = decode_session_cookie_body(&mutated) {
                    assert_eq!(reencodes(&decoded), mutated, "pos {position} value {value}");
                    assert!(
                        decoded.session_id != sid || decoded.country.as_deref() != country,
                        "mutation decoded to the original body"
                    );
                }
            }
        }
    }
}

#[test]
fn version_byte_length_prefixes_truncation_and_extension_are_strict() {
    let sid = SessionId::parse(SID).expect("sid");
    for country in [None, Some("HU")] {
        let original = encode_session_cookie_body(&sid, country).expect("encode");
        let country_len_at = 2 + SID.len();
        for value in 0..=u8::MAX {
            // Version byte: only 1 is accepted.
            let mut v = original.clone();
            v[0] = value;
            assert_eq!(
                decode_session_cookie_body(&v).is_ok(),
                value == 1,
                "version {value}"
            );
            // Session-id length prefix: only the true length is accepted.
            let mut s = original.clone();
            s[1] = value;
            assert_eq!(
                decode_session_cookie_body(&s).is_ok(),
                usize::from(value) == SID.len(),
                "sid_len {value}"
            );
            // Country length prefix: only the true length is accepted.
            let mut c = original.clone();
            c[country_len_at] = value;
            let true_len = country.map_or(0, str::len);
            assert_eq!(
                decode_session_cookie_body(&c).is_ok(),
                usize::from(value) == true_len,
                "country_len {value}"
            );
            // Any one trailing byte.
            let mut extended = original.clone();
            extended.push(value);
            assert_eq!(
                decode_session_cookie_body(&extended).unwrap_err(),
                SessionBodyError::Invalid
            );
        }
        for len in 0..original.len() {
            assert_eq!(
                decode_session_cookie_body(&original[..len]).unwrap_err(),
                SessionBodyError::Invalid,
                "truncated to {len}"
            );
        }
    }
}

/// Mirror of the PoW proof purpose (pow-core is not a dependency here; its
/// constants are pinned in `datadeft-pow-core`).
#[derive(Debug)]
enum MirrorPowProof {}

impl KeyPurpose for MirrorPowProof {
    const HKDF_INFO: &'static [u8] = b"auth/pow-proof-v1";
    const TOKEN_TYPE: &'static str = "pow-proof-v1";
    const MAX_BODY_BYTES: usize = 65;
    const MAX_ABSOLUTE_AGE_SECS: u64 = 24 * 60 * 60;
}

const COOKIE_NOW: u64 = 1_700_000_000;

fn mint_with<P: KeyPurpose>(ring: &KeyRing<P>, body: &[u8]) -> String {
    let mut rng = FixedBytesRng([0x6d; branca::NONCE_BYTES]);
    let ts = u32::try_from(COOKIE_NOW).expect("fits");
    mint_bound_cookie::<P, _>(body, ring, &mut rng, ts, ts, COOKIE_NOW).expect("mint")
}

#[test]
fn every_product_purpose_has_a_distinct_hkdf_info_and_typ() {
    let infos: [&[u8]; 3] = [
        SessionCookie::HKDF_INFO,
        MagicLinkConfirmCookie::HKDF_INFO,
        MirrorPowProof::HKDF_INFO,
    ];
    let typs = [
        SessionCookie::TOKEN_TYPE,
        MagicLinkConfirmCookie::TOKEN_TYPE,
        MirrorPowProof::TOKEN_TYPE,
    ];
    for i in 0..3 {
        assert!(!infos[i].contains(&0));
        for j in i + 1..3 {
            assert_ne!(infos[i], infos[j]);
            assert_ne!(typs[i], typs[j]);
        }
    }
}

/// Real session and confirm purposes (plus the PoW mirror) under the same
/// root byte and kid: a cookie of one purpose never verifies as another.
#[test]
fn session_cookie_never_crosses_purposes() {
    let body =
        encode_session_cookie_body(&SessionId::parse(SID).expect("sid"), None).expect("encode");
    let session = test_keyring::<SessionCookie>(0x44, "shared-kid");
    let confirm = test_keyring::<MagicLinkConfirmCookie>(0x44, "shared-kid");
    let pow = test_keyring::<MirrorPowProof>(0x44, "shared-kid");
    let session_value = mint_with(&session, &body);
    let confirm_value = mint_with(&confirm, &body);
    let pow_value = mint_with(&pow, &body[..30]);
    let fixed = MaxAge::fixed(60);

    assert!(parse_bound_cookie(&session_value, &session, COOKIE_NOW, fixed).is_ok());
    assert!(parse_bound_cookie(&session_value, &confirm, COOKIE_NOW, fixed).is_err());
    assert!(parse_bound_cookie(&session_value, &pow, COOKIE_NOW, fixed).is_err());
    assert!(parse_bound_cookie(&confirm_value, &session, COOKIE_NOW, fixed).is_err());
    assert!(parse_bound_cookie(&pow_value, &session, COOKIE_NOW, fixed).is_err());
}

#[test]
fn session_cookie_golden_value_and_single_edits_are_rejected() {
    let ring = test_keyring::<SessionCookie>(0x45, "session-active");
    let body = encode_session_cookie_body(&SessionId::parse(SID).expect("sid"), Some("HU"))
        .expect("encode");
    let value = mint_with(&ring, &body);
    assert_eq!(
        value,
        "v1.session-active.1cvR6OEpuO38jsjYKybSqZiPuQpoAJRIqyuPinjG9yOzapVUJAzYsNBITbuG43wc89HecbOAt66OVagxgUfGOfr22JOiTg7MDJlKdhngAxiV9sIUoOuLpqhQKKNA3XUNNIQDhfpaEEUrkf65HYIU0QQZ04qgW6kOx6pzSxpolAxdwova4XbG0yzeiu5Zmp3VA6jqdNQDV"
    );
    let fixed = MaxAge::fixed(60);
    let parsed = parse_bound_cookie(&value, &ring, COOKIE_NOW, fixed).expect("parse");
    assert_eq!(parsed.body(), body.as_slice());

    // Every position, every replacement in "0z." that differs from it.
    let bytes = value.as_bytes();
    for position in 0..bytes.len() {
        for &replacement in b"0z." {
            if bytes[position] == replacement {
                continue;
            }
            let mut edited = bytes.to_vec();
            edited[position] = replacement;
            let edited = String::from_utf8(edited).expect("ascii");
            assert!(
                parse_bound_cookie(&edited, &ring, COOKIE_NOW, fixed).is_err(),
                "edit at {position}"
            );
        }
    }
}

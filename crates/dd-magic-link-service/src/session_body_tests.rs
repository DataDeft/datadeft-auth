//! Session cookie purpose and body tests.

use dd_auth_token_core::keyring::{KEY_BYTES, KeyId, RootSecret};

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

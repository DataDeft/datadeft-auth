use axum::http::HeaderValue;

use super::*;

#[test]
fn cookie_parser_matrix_is_strict_on_target_and_skips_foreign_pairs() {
    let cases = [
        ("other=ok; target=value", Ok("value")),
        ("target=value; other=ok", Ok("value")),
        (" target=value ", Ok("value")),
        ("target=", Err(CookieParseError::Malformed)),
        ("target=\"value\"", Err(CookieParseError::Malformed)),
        ("target=one; target=two", Err(CookieParseError::Duplicate)),
        ("target=one=two", Ok("one=two")),
        ("other=base64==; target=value", Ok("value")),
        // Foreign cookies that break RFC 6265 are skipped, never fatal.
        ("other; target=value", Ok("value")),
        ("other=has space; target=value", Ok("value")),
        ("target=value;", Ok("value")),
        (
            "CookieConsent={stamp:'x',necessary:true}; target=value",
            Ok("value"),
        ),
        ("=nameless; target=value", Ok("value")),
        ("target=value; ;; other", Ok("value")),
        // The target itself stays strict.
        ("other=ok;", Err(CookieParseError::Missing)),
        ("target=has space", Err(CookieParseError::Malformed)),
        ("target=a,b", Err(CookieParseError::Malformed)),
        (
            "target=ok; target=has space",
            Err(CookieParseError::Duplicate),
        ),
        ("Target=value", Err(CookieParseError::Missing)),
        ("target =value", Err(CookieParseError::Missing)),
    ];
    for (raw, expected) in cases {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(raw).expect("header"));
        let actual = extract_target_cookie(&headers, "target");
        match expected {
            Ok(value) => assert_eq!(actual.expect(raw), value),
            Err(error) => assert_eq!(actual.unwrap_err(), error, "{raw}"),
        }
    }

    let mut duplicate_fields = HeaderMap::new();
    duplicate_fields.append(COOKIE, HeaderValue::from_static("target=one"));
    duplicate_fields.append(COOKIE, HeaderValue::from_static("target=two"));
    assert_eq!(
        extract_target_cookie(&duplicate_fields, "target").unwrap_err(),
        CookieParseError::Duplicate
    );

    let mut too_many = HeaderMap::new();
    for _ in 0..=MAX_COOKIE_HEADER_FIELDS {
        too_many.append(COOKIE, HeaderValue::from_static("other=ok"));
    }
    assert_eq!(
        extract_target_cookie(&too_many, "target").unwrap_err(),
        CookieParseError::Oversized
    );

    let mut oversized = HeaderMap::new();
    oversized.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "target={}",
            "a".repeat(MAX_SELECTED_COOKIE_VALUE_BYTES + 1)
        ))
        .expect("header"),
    );
    assert_eq!(
        extract_target_cookie(&oversized, "target").unwrap_err(),
        CookieParseError::Oversized
    );
}

#[test]
fn non_ascii_foreign_cookie_does_not_block_target() {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_bytes("pref=caf\u{e9}; target=value".as_bytes()).expect("header"),
    );
    assert_eq!(
        extract_target_cookie(&headers, "target").expect("target"),
        "value"
    );
}

#[test]
fn http2_style_one_field_per_cookie_is_accepted() {
    let mut headers = HeaderMap::new();
    for index in 0..20 {
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!("other{index}=ok")).expect("header"),
        );
    }
    headers.append(COOKIE, HeaderValue::from_static("target=value"));
    assert_eq!(
        extract_target_cookie(&headers, "target").expect("target"),
        "value"
    );
}

#[test]
fn aggregate_cookie_bytes_stay_capped() {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "other={}; target=value",
            "a".repeat(MAX_COOKIE_HEADER_BYTES)
        ))
        .expect("header"),
    );
    assert_eq!(
        extract_target_cookie(&headers, "target").unwrap_err(),
        CookieParseError::Oversized
    );
}

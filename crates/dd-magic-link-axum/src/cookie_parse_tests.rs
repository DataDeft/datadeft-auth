use axum::http::HeaderValue;

use super::*;

#[test]
fn cookie_parser_matrix_rejects_ambiguity_and_malformed_unrelated_pairs() {
    let cases = [
        ("other=ok; target=value", Ok("value")),
        ("target=value; other=ok", Ok("value")),
        (" target=value ", Ok("value")),
        ("target=", Err(CookieParseError::Malformed)),
        ("target=\"value\"", Err(CookieParseError::Malformed)),
        ("target=one; target=two", Err(CookieParseError::Duplicate)),
        ("target=one=two", Ok("one=two")),
        ("other=base64==; target=value", Ok("value")),
        ("other; target=value", Err(CookieParseError::Malformed)),
        (
            "other=has space; target=value",
            Err(CookieParseError::Malformed),
        ),
        ("other=ok;", Err(CookieParseError::Malformed)),
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

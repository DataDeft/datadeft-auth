//! The Axum wiring of the shared selector: every `Cookie` field is read. The
//! parsing matrix lives with the selector in datadeft-auth-token-core.

use axum::http::HeaderValue;

use super::*;

#[test]
fn every_cookie_field_is_read_and_duplicates_span_fields() {
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

    headers.append(COOKIE, HeaderValue::from_static("target=two"));
    assert_eq!(
        extract_target_cookie(&headers, "target").unwrap_err(),
        CookieHeaderError::Duplicate
    );
}

#[test]
fn no_cookie_header_is_missing() {
    assert_eq!(
        extract_target_cookie(&HeaderMap::new(), "target").unwrap_err(),
        CookieHeaderError::Missing
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

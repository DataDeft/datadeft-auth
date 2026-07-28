use axum::http::HeaderName;

use super::*;

#[test]
fn same_origin_redirect_is_fully_prevalidated_for_location() {
    for value in [
        "/done",
        "/auth/complete?fixed=dashboard",
        "/path%20segment?value=%2F",
    ] {
        let redirect = SameOriginRedirect::parse(value).expect(value);
        assert_eq!(redirect.as_str(), value);
        assert_eq!(redirect.location_header(), value);
    }
    for value in [
        "",
        "done",
        "//evil.test/path",
        "https://evil.test/path",
        "http:relative",
        "/path with space",
        "/path\tvalue",
        "/path\\value",
        "/path%",
        "/path%2",
        "/path%GG",
        "/mlv1.selector.verifier",
        "/café",
    ] {
        assert!(
            SameOriginRedirect::parse(value).is_err(),
            "redirect {value:?}"
        );
    }
}

#[test]
fn origin_parser_accepts_only_narrow_canonical_grammar() {
    for origin in [
        "https://example.test",
        "http://localhost",
        "https://example.test:8443",
        "http://127.0.0.1:8080",
        "https://0.0.0.0",
    ] {
        let parsed = SameOriginPostConfig::parse(origin).expect(origin);
        assert_eq!(parsed.expected_origin(), origin);
    }
    for origin in [
        "HTTPS://example.test",
        "ftp://example.test",
        "https://Example.test",
        "https://example.test/",
        "https://example.test/path",
        "https://example.test?x",
        "https://example.test#x",
        "https://user@example.test",
        "https://[::1]",
        "https://example%2etest",
        "https://example.test,https://other.test",
        "https://example.test:443",
        "http://example.test:80",
        "https://example.test:0443",
        "https://example.test:0",
        "https://example.test:65536",
        "https://127.00.0.1",
        "https://127.0.0",
        "https://256.0.0.1",
        "https://example.test.",
        "https://-example.test",
        "https://example-.test",
        "https://exa_mple.test",
        " https://example.test",
    ] {
        assert!(
            SameOriginPostConfig::parse(origin).is_err(),
            "origin {origin}"
        );
    }
}

#[test]
fn request_origin_enforcement_requires_exact_unique_headers() {
    let config = SameOriginPostConfig::parse("https://example.test:8443").expect("origin");
    let mut headers = HeaderMap::new();
    headers.insert(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    assert!(request_is_same_origin(&headers, &config));
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    assert!(request_is_same_origin(&headers, &config));

    for value in [
        "https://example.test",
        "null",
        "https://example.test:8443, https://other.test",
    ] {
        let mut rejected = HeaderMap::new();
        rejected.insert(ORIGIN, HeaderValue::from_str(value).expect("header"));
        assert!(!request_is_same_origin(&rejected, &config));
    }
    for fetch in ["same-site", "cross-site", "none", "Same-Origin"] {
        let mut rejected = HeaderMap::new();
        rejected.insert(
            ORIGIN,
            HeaderValue::from_static("https://example.test:8443"),
        );
        rejected.insert(
            HeaderName::from_static("sec-fetch-site"),
            HeaderValue::from_str(fetch).expect("header"),
        );
        assert!(!request_is_same_origin(&rejected, &config));
    }

    let mut duplicate_origin = HeaderMap::new();
    duplicate_origin.append(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    duplicate_origin.append(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    assert!(!request_is_same_origin(&duplicate_origin, &config));

    let mut duplicate_fetch = HeaderMap::new();
    duplicate_fetch.insert(
        ORIGIN,
        HeaderValue::from_static("https://example.test:8443"),
    );
    duplicate_fetch.append(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    duplicate_fetch.append(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    assert!(!request_is_same_origin(&duplicate_fetch, &config));
}

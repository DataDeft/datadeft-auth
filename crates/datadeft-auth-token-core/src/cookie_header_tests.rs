//! Strict cookie selection: target strictness, foreign-pair tolerance, caps.

use super::*;

fn one(raw: &str, name: &str) -> Result<String, CookieHeaderError> {
    select_cookie([raw.as_bytes()], name).map(str::to_owned)
}

#[test]
fn the_target_is_strict_and_foreign_pairs_are_skipped() {
    let cases = [
        ("other=ok; target=value", Ok("value")),
        ("target=value; other=ok", Ok("value")),
        (" target=value ", Ok("value")),
        ("\ttarget=value\t", Ok("value")),
        ("target=", Err(CookieHeaderError::Malformed)),
        ("target=\"value\"", Err(CookieHeaderError::Malformed)),
        ("target=one; target=two", Err(CookieHeaderError::Duplicate)),
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
        ("", Err(CookieHeaderError::Missing)),
        ("   ", Err(CookieHeaderError::Missing)),
        // The target itself stays strict.
        ("other=ok;", Err(CookieHeaderError::Missing)),
        ("target=has space", Err(CookieHeaderError::Malformed)),
        ("target=a,b", Err(CookieHeaderError::Malformed)),
        ("target=a\\b", Err(CookieHeaderError::Malformed)),
        (
            "target=ok; target=has space",
            Err(CookieHeaderError::Duplicate),
        ),
        ("Target=value", Err(CookieHeaderError::Missing)),
        ("target =value", Err(CookieHeaderError::Missing)),
    ];
    for (raw, expected) in cases {
        assert_eq!(one(raw, "target"), expected.map(str::to_owned), "{raw:?}");
    }
}

#[test]
fn non_ascii_foreign_bytes_do_not_block_the_target() {
    let raw = "pref=caf\u{e9}; target=value".as_bytes();
    assert_eq!(select_cookie([raw], "target"), Ok("value"));
    let raw: &[u8] = b"pref=\xff\xfe; target=value";
    assert_eq!(select_cookie([raw], "target"), Ok("value"));
}

#[test]
fn a_non_utf8_target_is_malformed() {
    let raw: &[u8] = b"target=\xff";
    assert_eq!(
        select_cookie([raw], "target"),
        Err(CookieHeaderError::Malformed)
    );
}

#[test]
fn one_field_per_cookie_is_accepted_and_duplicates_span_fields() {
    let fields: Vec<String> = (0..20).map(|index| format!("other{index}=ok")).collect();
    let mut all: Vec<&[u8]> = fields.iter().map(|field| field.as_bytes()).collect();
    all.push(b"target=value");
    assert_eq!(select_cookie(all.clone(), "target"), Ok("value"));
    all.push(b"target=again");
    assert_eq!(
        select_cookie(all, "target"),
        Err(CookieHeaderError::Duplicate)
    );
}

#[test]
fn field_count_aggregate_bytes_and_value_size_are_capped() {
    let too_many = vec![b"other=ok".as_slice(); MAX_COOKIE_HEADER_FIELDS + 1];
    assert_eq!(
        select_cookie(too_many, "target"),
        Err(CookieHeaderError::Oversized)
    );
    let at_limit = vec![b"other=ok".as_slice(); MAX_COOKIE_HEADER_FIELDS];
    assert_eq!(
        select_cookie(at_limit, "target"),
        Err(CookieHeaderError::Missing)
    );

    let aggregate = format!(
        "other={}; target=value",
        "a".repeat(MAX_COOKIE_HEADER_BYTES)
    );
    assert_eq!(one(&aggregate, "target"), Err(CookieHeaderError::Oversized));

    let largest = format!("target={}", "a".repeat(MAX_COOKIE_VALUE_BYTES));
    assert_eq!(
        one(&largest, "target").map(|value| value.len()),
        Ok(MAX_COOKIE_VALUE_BYTES)
    );
    let oversized = format!("target={}", "a".repeat(MAX_COOKIE_VALUE_BYTES + 1));
    assert_eq!(one(&oversized, "target"), Err(CookieHeaderError::Oversized));
}

#[test]
fn errors_carry_no_cookie_bytes() {
    for error in [
        CookieHeaderError::Missing,
        CookieHeaderError::Malformed,
        CookieHeaderError::Duplicate,
        CookieHeaderError::Oversized,
    ] {
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("target"), "{shown}");
    }
}

#[test]
fn cookie_octet_matches_rfc_6265() {
    for byte in 0u8..=255 {
        let expected = (0x21..=0x7e).contains(&byte) && !matches!(byte, b'"' | b',' | b';' | b'\\');
        assert_eq!(is_cookie_octet(byte), expected, "{byte:#04x}");
    }
}

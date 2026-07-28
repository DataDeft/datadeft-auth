//! Strict, bounded parsing of incoming `Cookie` headers with unambiguous
//! selection of a single target cookie.

use axum::http::HeaderMap;
use axum::http::header::COOKIE;

const MAX_COOKIE_HEADER_FIELDS: usize = 8;
const MAX_COOKIE_HEADER_BYTES: usize = 8192;
pub(crate) const MAX_SELECTED_COOKIE_VALUE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CookieParseError {
    Missing,
    Malformed,
    Duplicate,
    Oversized,
}

pub(crate) fn extract_target_cookie(
    headers: &HeaderMap,
    target_name: &str,
) -> Result<String, CookieParseError> {
    let mut field_count = 0usize;
    let mut aggregate = 0usize;
    let mut selected: Option<String> = None;
    for field in headers.get_all(COOKIE).iter() {
        field_count = field_count
            .checked_add(1)
            .ok_or(CookieParseError::Oversized)?;
        if field_count > MAX_COOKIE_HEADER_FIELDS {
            return Err(CookieParseError::Oversized);
        }
        let bytes = field.as_bytes();
        aggregate = aggregate
            .checked_add(bytes.len())
            .ok_or(CookieParseError::Oversized)?;
        if aggregate > MAX_COOKIE_HEADER_BYTES || !bytes.is_ascii() {
            return Err(CookieParseError::Oversized);
        }
        for raw_pair in bytes.split(|byte| *byte == b';') {
            let pair = trim_cookie_pair(raw_pair);
            if pair.is_empty() {
                return Err(CookieParseError::Malformed);
            }
            let Some(equals) = pair.iter().position(|byte| *byte == b'=') else {
                return Err(CookieParseError::Malformed);
            };
            let name = &pair[..equals];
            let value = &pair[equals + 1..];
            if !is_cookie_pair_name(name) || !value.iter().copied().all(is_cookie_octet) {
                return Err(CookieParseError::Malformed);
            }
            if name == target_name.as_bytes() {
                if selected.is_some() {
                    return Err(CookieParseError::Duplicate);
                }
                if value.is_empty()
                    || value.len() > MAX_SELECTED_COOKIE_VALUE_BYTES
                    || value.first() == Some(&b'"')
                {
                    return Err(if value.len() > MAX_SELECTED_COOKIE_VALUE_BYTES {
                        CookieParseError::Oversized
                    } else {
                        CookieParseError::Malformed
                    });
                }
                let value = core::str::from_utf8(value)
                    .map_err(|_| CookieParseError::Malformed)?
                    .to_owned();
                selected = Some(value);
            }
        }
    }
    selected.ok_or(CookieParseError::Missing)
}

fn trim_cookie_pair(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_cookie_pair_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().copied().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

pub(crate) fn is_cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

#[cfg(test)]
#[path = "cookie_parse_tests.rs"]
mod tests;

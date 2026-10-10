//! Strict selection of one cookie from incoming `Cookie` header fields.
//!
//! Only the target cookie is validated strictly: it must occur exactly once,
//! hold a non-empty, unquoted RFC 6265 `cookie-octet` value, and fit
//! [`MAX_COOKIE_VALUE_BYTES`]. Other cookies on the host (consent banners,
//! analytics) often break RFC 6265: commas, spaces, non-ASCII bytes, or no
//! name. They are skipped, never parsed, so one foreign cookie cannot lock a
//! user out. The field count and aggregate size are capped either way.
//!
//! Pure and IO-free: callers pass the raw field bytes, for example
//! `headers.get_all(COOKIE).iter().map(HeaderValue::as_bytes)` in Axum.

use core::fmt;

/// Most `Cookie` fields read. HTTP/2 clients may send one field per cookie.
pub const MAX_COOKIE_HEADER_FIELDS: usize = 128;
/// Most bytes read across all `Cookie` fields.
pub const MAX_COOKIE_HEADER_BYTES: usize = 8192;
/// Largest accepted value of the selected cookie.
pub const MAX_COOKIE_VALUE_BYTES: usize = 4096;

/// Why the target cookie could not be selected. Carries no cookie bytes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CookieHeaderError {
    /// No pair with the target name.
    Missing,
    /// The target pair is empty, quoted, or holds bytes outside
    /// `cookie-octet`.
    Malformed,
    /// The target name occurs more than once, across all fields.
    Duplicate,
    /// Too many fields, too many bytes, or an oversized target value.
    Oversized,
}

impl fmt::Display for CookieHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "cookie missing",
            Self::Malformed => "cookie malformed",
            Self::Duplicate => "cookie duplicated",
            Self::Oversized => "cookie header oversized",
        })
    }
}

impl std::error::Error for CookieHeaderError {}

/// Select the value of the one cookie named `name` from the `Cookie` header
/// fields. The name is matched exactly (case-sensitive).
pub fn select_cookie<'a, I>(fields: I, name: &str) -> Result<&'a str, CookieHeaderError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut field_count = 0usize;
    let mut aggregate = 0usize;
    let mut selected: Option<&'a str> = None;
    for bytes in fields {
        field_count = field_count
            .checked_add(1)
            .ok_or(CookieHeaderError::Oversized)?;
        if field_count > MAX_COOKIE_HEADER_FIELDS {
            return Err(CookieHeaderError::Oversized);
        }
        aggregate = aggregate
            .checked_add(bytes.len())
            .ok_or(CookieHeaderError::Oversized)?;
        if aggregate > MAX_COOKIE_HEADER_BYTES {
            return Err(CookieHeaderError::Oversized);
        }
        for raw_pair in bytes.split(|byte| *byte == b';') {
            let pair = trim_cookie_pair(raw_pair);
            // Foreign pairs with no `=` (or empty segments from a trailing
            // `;`) cannot be the target cookie: skip them.
            let Some(equals) = pair.iter().position(|byte| *byte == b'=') else {
                continue;
            };
            let (pair_name, rest) = pair.split_at(equals);
            let value = rest.get(1..).unwrap_or_default();
            if pair_name != name.as_bytes() {
                continue;
            }
            if selected.is_some() {
                return Err(CookieHeaderError::Duplicate);
            }
            if !is_cookie_name(pair_name) || !value.iter().copied().all(is_cookie_octet) {
                return Err(CookieHeaderError::Malformed);
            }
            if value.len() > MAX_COOKIE_VALUE_BYTES {
                return Err(CookieHeaderError::Oversized);
            }
            if value.is_empty() || value.first() == Some(&b'"') {
                return Err(CookieHeaderError::Malformed);
            }
            selected = Some(core::str::from_utf8(value).map_err(|_| CookieHeaderError::Malformed)?);
        }
    }
    selected.ok_or(CookieHeaderError::Missing)
}

/// RFC 6265 `cookie-octet`: printable ASCII except space, `"`, `,`, `;` and
/// `\`.
#[must_use]
pub fn is_cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

fn trim_cookie_pair(value: &[u8]) -> &[u8] {
    let is_space = |byte: &u8| matches!(byte, b' ' | b'\t');
    let start = value.iter().position(|byte| !is_space(byte));
    let end = value.iter().rposition(|byte| !is_space(byte));
    match (start, end) {
        (Some(start), Some(end)) => value.get(start..=end).unwrap_or_default(),
        _ => &[],
    }
}

/// RFC 7230 `token`, the RFC 6265 cookie-name grammar.
fn is_cookie_name(value: &[u8]) -> bool {
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

#[cfg(test)]
#[path = "cookie_header_tests.rs"]
mod tests;

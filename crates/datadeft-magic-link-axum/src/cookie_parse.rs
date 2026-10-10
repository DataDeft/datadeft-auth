//! Incoming `Cookie` headers: the shared strict selector
//! ([`datadeft_magic_link_service::cookie_header`]) applied to an Axum
//! `HeaderMap`.

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use datadeft_magic_link_service::cookie_header::{CookieHeaderError, select_cookie};

pub(crate) use datadeft_magic_link_service::cookie_header::{
    MAX_COOKIE_VALUE_BYTES as MAX_SELECTED_COOKIE_VALUE_BYTES, is_cookie_octet,
};

/// The one cookie named `target_name`, owned so callers can zeroize it.
pub(crate) fn extract_target_cookie(
    headers: &HeaderMap,
    target_name: &str,
) -> Result<String, CookieHeaderError> {
    select_cookie(
        headers.get_all(COOKIE).iter().map(HeaderValue::as_bytes),
        target_name,
    )
    .map(str::to_owned)
}

#[cfg(test)]
#[path = "cookie_parse_tests.rs"]
mod tests;

//! Small helpers: same-origin check, clocks, and HTML escaping.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use axum::http::header::ORIGIN;
use datadeft_magic_link_service::DependencyError;
use datadeft_pow_core::UnixMillis;

use super::*;

pub(super) fn is_same_origin_post(headers: &HeaderMap) -> bool {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return false;
    };
    origins.next().is_none() && origin.as_bytes() == LOCAL_ORIGIN.as_bytes()
}

pub(super) fn current_unix() -> Result<u64, DependencyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DependencyError::Internal)
}

pub(super) fn current_unix_millis() -> Result<UnixMillis, DependencyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .map(UnixMillis::from_millis)
        .ok_or(DependencyError::Internal)
}

pub(super) fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

//! Same-origin policy: validated same-origin redirect targets, the narrow
//! canonical Origin grammar, and request-time same-origin enforcement.

use core::fmt;

use axum::http::header::ORIGIN;
use axum::http::{HeaderMap, HeaderValue};
use dd_magic_link_service::contains_magic_link_token_marker;

use crate::error::MagicLinkHttpError;
use crate::handlers::SEC_FETCH_SITE;

/// Setup-validated same-origin redirect target.
///
/// Only canonical ASCII relative request targets with an absolute path are
/// accepted. The `Location` header is constructed during setup, before any
/// authentication transaction can commit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SameOriginRedirect {
    value: String,
    location: HeaderValue,
}

impl SameOriginRedirect {
    pub fn parse(value: impl Into<String>) -> Result<Self, MagicLinkHttpError> {
        let value = value.into();
        if !is_safe_same_origin_path(&value) {
            return Err(MagicLinkHttpError::BadRequest);
        }
        let uri = value
            .parse::<axum::http::Uri>()
            .map_err(|_| MagicLinkHttpError::BadRequest)?;
        if uri.scheme().is_some()
            || uri.authority().is_some()
            || uri
                .path_and_query()
                .is_none_or(|path_and_query| path_and_query.as_str() != value)
        {
            return Err(MagicLinkHttpError::BadRequest);
        }
        let location = HeaderValue::from_str(&value).map_err(|_| MagicLinkHttpError::BadRequest)?;
        Ok(Self { value, location })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub(crate) fn location_header(&self) -> HeaderValue {
        self.location.clone()
    }
}

/// Typed setup failures for the deliberately narrow Origin grammar.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OriginConfigError {
    InvalidScheme,
    InvalidAuthority,
    InvalidHost,
    InvalidPort,
    NonCanonical,
    InvalidHeaderValue,
}

impl fmt::Display for OriginConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidScheme => "invalid origin scheme",
            Self::InvalidAuthority => "invalid origin authority",
            Self::InvalidHost => "invalid origin host",
            Self::InvalidPort => "invalid origin port",
            Self::NonCanonical => "origin is not canonical",
            Self::InvalidHeaderValue => "origin is not a valid header value",
        })
    }
}

impl std::error::Error for OriginConfigError {}

/// Exact same-origin POST policy using a deliberately narrow canonical grammar.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SameOriginPostConfig {
    expected_origin: HeaderValue,
}

impl SameOriginPostConfig {
    pub fn parse(value: &str) -> Result<Self, OriginConfigError> {
        validate_origin(value)?;
        let expected_origin =
            HeaderValue::from_str(value).map_err(|_| OriginConfigError::InvalidHeaderValue)?;
        Ok(Self { expected_origin })
    }

    #[must_use]
    pub fn expected_origin(&self) -> &HeaderValue {
        &self.expected_origin
    }
}

pub(crate) fn request_is_same_origin(headers: &HeaderMap, config: &SameOriginPostConfig) -> bool {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return false;
    };
    if origins.next().is_some() || origin != config.expected_origin() {
        return false;
    }
    let mut fetch_values = headers.get_all(SEC_FETCH_SITE).iter();
    let Some(fetch) = fetch_values.next() else {
        return true;
    };
    fetch_values.next().is_none() && fetch.as_bytes() == b"same-origin"
}

fn validate_origin(value: &str) -> Result<(), OriginConfigError> {
    if value.is_empty()
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(OriginConfigError::InvalidAuthority);
    }
    let (scheme, authority) = value
        .split_once("://")
        .ok_or(OriginConfigError::InvalidScheme)?;
    if scheme != "http" && scheme != "https" {
        return Err(OriginConfigError::InvalidScheme);
    }
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'/' | b'?' | b'#' | b',' | b'%' | b'@' | b'[' | b']' | b'\\'
                )
        })
    {
        return Err(OriginConfigError::InvalidAuthority);
    }
    let colon_count = authority.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return Err(OriginConfigError::InvalidAuthority);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    validate_origin_host(host)?;
    if let Some(port) = port {
        validate_origin_port(scheme, port)?;
    }
    Ok(())
}

fn validate_origin_host(host: &str) -> Result<(), OriginConfigError> {
    if host.is_empty() || host.len() > 253 || host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(OriginConfigError::InvalidHost);
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        let octets: Vec<&str> = host.split('.').collect();
        if octets.len() != 4 {
            return Err(OriginConfigError::InvalidHost);
        }
        for octet in octets {
            if octet.is_empty()
                || (octet.len() > 1 && octet.starts_with('0'))
                || octet.parse::<u8>().is_err()
            {
                return Err(OriginConfigError::NonCanonical);
            }
        }
        return Ok(());
    }
    if host.ends_with('.') {
        return Err(OriginConfigError::NonCanonical);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(OriginConfigError::InvalidHost);
        }
    }
    Ok(())
}

fn validate_origin_port(scheme: &str, port: &str) -> Result<(), OriginConfigError> {
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || (port.len() > 1 && port.starts_with('0'))
    {
        return Err(OriginConfigError::InvalidPort);
    }
    let parsed = port
        .parse::<u16>()
        .map_err(|_| OriginConfigError::InvalidPort)?;
    if parsed == 0 {
        return Err(OriginConfigError::InvalidPort);
    }
    if (scheme == "http" && parsed == 80) || (scheme == "https" && parsed == 443) {
        return Err(OriginConfigError::NonCanonical);
    }
    if parsed.to_string() != port {
        return Err(OriginConfigError::NonCanonical);
    }
    Ok(())
}

fn is_safe_same_origin_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 2048
        && value.is_ascii()
        && !value.contains('\\')
        && !contains_magic_link_token_marker(value)
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && has_well_formed_percent_encoding(value)
}

fn has_well_formed_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(first) = bytes.get(index + 1) else {
                return false;
            };
            let Some(second) = bytes.get(index + 2) else {
                return false;
            };
            if !first.is_ascii_hexdigit() || !second.is_ascii_hexdigit() {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

#[cfg(test)]
#[path = "origin_tests.rs"]
mod tests;

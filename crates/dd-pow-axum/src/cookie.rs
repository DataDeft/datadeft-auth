//! Outgoing `Set-Cookie` policy for the `dd_pow` proof cookie: a validated
//! host-only cookie configuration plus set/clear header construction.
//!
//! Self-contained on purpose — PoW admission is independent of the magic-link
//! flow, so this crate does not depend on the magic-link integration. The
//! cookie grammar (lower-snake name, absolute path, RFC 6265 cookie-octet
//! value) matches the rest of the workspace.

use core::fmt;

use axum::http::HeaderValue;
use dd_pow_core::{DEFAULT_POW_PROOF_TTL_SECS, POW_PROOF_MAX_AGE_SECS};

/// Conservative default proof-cookie name.
pub const DEFAULT_POW_PROOF_COOKIE_NAME: &str = "dd_pow";
/// Proof cookies gate the whole app, so they default to the root path.
pub const DEFAULT_POW_PROOF_COOKIE_PATH: &str = "/";

const COOKIE_EPOCH: &str = "Thu, 01 Jan 1970 00:00:00 GMT";
const MAX_COOKIE_VALUE_BYTES: usize = 4096;

/// SameSite policy for cookie helper output.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SameSite {
    Lax,
    Strict,
    None,
}

impl SameSite {
    fn as_cookie_value(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

/// Typed proof-cookie setup failures.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PowCookieConfigError {
    InvalidName,
    InvalidPath,
    InvalidTtl,
    SameSiteNoneRequiresSecure,
}

impl fmt::Display for PowCookieConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "invalid cookie name",
            Self::InvalidPath => "invalid cookie path",
            Self::InvalidTtl => "proof-cookie TTL must be in 1..=POW_PROOF_MAX_AGE_SECS",
            Self::SameSiteNoneRequiresSecure => "SameSite=None requires Secure",
        })
    }
}

impl std::error::Error for PowCookieConfigError {}

/// Validated host-only `dd_pow` proof-cookie policy.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PowProofCookieConfig {
    name: String,
    path: String,
    secure: bool,
    same_site: SameSite,
    ttl_secs: u64,
    clear_header: HeaderValue,
}

impl PowProofCookieConfig {
    /// Validated production policy (`Secure`, Lax) with a caller-chosen name,
    /// path, and lifetime.
    pub fn production(
        name: impl Into<String>,
        path: impl Into<String>,
        ttl_secs: u64,
    ) -> Result<Self, PowCookieConfigError> {
        Self::build(name.into(), path.into(), true, ttl_secs)
    }

    /// Validated local-HTTP policy (no `Secure`) for development over plain
    /// HTTP.
    pub fn local_development(
        name: impl Into<String>,
        path: impl Into<String>,
        ttl_secs: u64,
    ) -> Result<Self, PowCookieConfigError> {
        Self::build(name.into(), path.into(), false, ttl_secs)
    }

    /// Default production policy (`dd_pow`, `/`, Secure, 3 h).
    #[must_use]
    pub fn production_defaults() -> Self {
        Self::production(
            DEFAULT_POW_PROOF_COOKIE_NAME,
            DEFAULT_POW_PROOF_COOKIE_PATH,
            DEFAULT_POW_PROOF_TTL_SECS,
        )
        .expect("default proof-cookie policy is valid")
    }

    /// Default local-HTTP policy (no `Secure`).
    #[must_use]
    pub fn local_development_defaults() -> Self {
        Self::local_development(
            DEFAULT_POW_PROOF_COOKIE_NAME,
            DEFAULT_POW_PROOF_COOKIE_PATH,
            DEFAULT_POW_PROOF_TTL_SECS,
        )
        .expect("default proof-cookie policy is valid")
    }

    fn build(
        name: String,
        path: String,
        secure: bool,
        ttl_secs: u64,
    ) -> Result<Self, PowCookieConfigError> {
        if !is_lower_snake_cookie_name(&name) {
            return Err(PowCookieConfigError::InvalidName);
        }
        if !is_valid_cookie_path(&path) {
            return Err(PowCookieConfigError::InvalidPath);
        }
        if ttl_secs == 0 || ttl_secs > POW_PROOF_MAX_AGE_SECS {
            return Err(PowCookieConfigError::InvalidTtl);
        }
        let same_site = SameSite::Lax;
        let clear_header = build_clear_cookie_header(&name, &path, secure, same_site)?;
        Ok(Self {
            name,
            path,
            secure,
            same_site,
            ttl_secs,
            clear_header,
        })
    }

    pub fn with_same_site(mut self, same_site: SameSite) -> Result<Self, PowCookieConfigError> {
        if same_site == SameSite::None && !self.secure {
            return Err(PowCookieConfigError::SameSiteNoneRequiresSecure);
        }
        self.same_site = same_site;
        self.clear_header =
            build_clear_cookie_header(&self.name, &self.path, self.secure, self.same_site)?;
        Ok(self)
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn secure(&self) -> bool {
        self.secure
    }

    #[must_use]
    pub fn same_site(&self) -> SameSite {
        self.same_site
    }

    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Build the `Set-Cookie` header carrying an encrypted proof-cookie value.
    /// `Max-Age` is the configured lifetime. Fails closed if the opaque value
    /// is not a legal cookie-octet string.
    pub fn set_header(&self, value: &str) -> Result<HeaderValue, PowCookieError> {
        if !is_valid_cookie_value(value) {
            return Err(PowCookieError);
        }
        cookie_header(
            &self.name,
            value,
            &self.path,
            self.secure,
            self.same_site,
            Some(self.ttl_secs),
            false,
        )
        .map_err(|_| PowCookieError)
    }

    /// The byte-for-byte attribute-parity clear header, precomputed at
    /// construction time. Set it to expire the proof cookie on logout or a
    /// terminal failure.
    #[must_use]
    pub fn clear_header(&self) -> HeaderValue {
        self.clear_header.clone()
    }
}

/// The proof-cookie value or header could not be encoded (non-ASCII / bad
/// octet). Only reachable on an internal minting fault, never on client input.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PowCookieError;

impl fmt::Display for PowCookieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("proof cookie could not be encoded")
    }
}

impl std::error::Error for PowCookieError {}

fn is_lower_snake_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
}

fn is_valid_cookie_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 128
        && !value.contains(['?', '#', '%', '\\', ',', ';'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn is_valid_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COOKIE_VALUE_BYTES
        && value.bytes().all(is_cookie_octet)
        && !value.starts_with('"')
}

/// RFC 6265 `cookie-octet`.
fn is_cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

fn build_clear_cookie_header(
    name: &str,
    path: &str,
    secure: bool,
    same_site: SameSite,
) -> Result<HeaderValue, PowCookieConfigError> {
    cookie_header(name, "", path, secure, same_site, Some(0), true)
        .map_err(|_| PowCookieConfigError::InvalidName)
}

fn cookie_header(
    name: &str,
    value: &str,
    path: &str,
    secure: bool,
    same_site: SameSite,
    max_age: Option<u64>,
    clear: bool,
) -> Result<HeaderValue, PowCookieError> {
    let secure = if secure { "; Secure" } else { "" };
    let max_age = max_age.map_or_else(String::new, |age| format!("; Max-Age={age}"));
    let expires = if clear {
        format!("; Expires={COOKIE_EPOCH}")
    } else {
        String::new()
    };
    let header = format!(
        "{name}={value}; Path={path}; HttpOnly{secure}; SameSite={}{max_age}{expires}",
        same_site.as_cookie_value(),
    );
    HeaderValue::from_str(&header).map_err(|_| PowCookieError)
}

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;

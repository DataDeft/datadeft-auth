//! Outgoing `Set-Cookie` policy: validated session and confirm cookie
//! configurations plus set/clear header construction.

use core::fmt;

use axum::http::HeaderValue;
use datadeft_magic_link_service::{
    KeyPurpose, MagicLinkConfigError, MagicLinkConfirmCookie, MagicLinkServiceConfig,
};

use crate::cookie_parse::{MAX_SELECTED_COOKIE_VALUE_BYTES, is_cookie_octet};
use crate::error::MagicLinkHttpError;

/// Conservative default primary session cookie name.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "dd_session";
/// Primary session cookies are app-wide by default.
pub const DEFAULT_SESSION_COOKIE_PATH: &str = "/";

const DEFAULT_CONFIRM_COOKIE_NAME: &str = "dd_auth_confirm";
const DEFAULT_CONFIRM_COOKIE_PATH: &str = "/auth";
const COOKIE_EPOCH: &str = "Thu, 01 Jan 1970 00:00:00 GMT";

/// Precomputed clear headers for the default cookie shapes, so the infallible
/// `*_defaults()` constructors need no fallible header build. Each must stay
/// byte-for-byte in lockstep with [`cookie_header`] output: pinned by the
/// `precomputed_clear_headers_match_freshly_built_ones` test.
const DEFAULT_CONFIRM_CLEAR_HEADER: &str = "dd_auth_confirm=; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
const DEFAULT_CONFIRM_CLEAR_HEADER_INSECURE: &str = "dd_auth_confirm=; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
const DEFAULT_SESSION_CLEAR_HEADER: &str = "dd_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
const DEFAULT_SESSION_CLEAR_HEADER_INSECURE: &str =
    "dd_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";

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

/// Typed cookie setup failures.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CookieConfigError {
    InvalidName,
    InvalidPath,
    SameSiteNoneRequiresSecure,
}

impl fmt::Display for CookieConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "invalid cookie name",
            Self::InvalidPath => "invalid cookie path",
            Self::SameSiteNoneRequiresSecure => "SameSite=None requires Secure",
        })
    }
}

impl std::error::Error for CookieConfigError {}

/// Validated host-only confirm cookie policy.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfirmCookieConfig {
    name: String,
    path: String,
    secure: bool,
    same_site: SameSite,
    clear_header: HeaderValue,
}

impl ConfirmCookieConfig {
    pub fn production(
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, CookieConfigError> {
        Self::build(name.into(), path.into(), true)
    }

    pub fn local_development(
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, CookieConfigError> {
        Self::build(name.into(), path.into(), false)
    }

    fn build(name: String, path: String, secure: bool) -> Result<Self, CookieConfigError> {
        validate_cookie_name(&name)?;
        validate_cookie_path(&path)?;
        let same_site = SameSite::Lax;
        let clear_header = build_clear_cookie_header(&name, &path, secure, same_site)?;
        Ok(Self {
            name,
            path,
            secure,
            same_site,
            clear_header,
        })
    }

    /// Default production confirm-cookie policy (`dd_auth_confirm`, `/auth`, Secure).
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            name: DEFAULT_CONFIRM_COOKIE_NAME.to_owned(),
            path: DEFAULT_CONFIRM_COOKIE_PATH.to_owned(),
            secure: true,
            same_site: SameSite::Lax,
            clear_header: HeaderValue::from_static(DEFAULT_CONFIRM_CLEAR_HEADER),
        }
    }

    /// Default local-HTTP confirm-cookie policy (no `Secure` attribute).
    #[must_use]
    pub fn local_development_defaults() -> Self {
        let mut defaults = Self::production_defaults();
        defaults.secure = false;
        defaults.clear_header = HeaderValue::from_static(DEFAULT_CONFIRM_CLEAR_HEADER_INSECURE);
        defaults
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
}

/// Validated host-only primary session cookie configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionCookieConfig {
    name: String,
    path: String,
    max_age_secs: u64,
    secure: bool,
    same_site: SameSite,
    clear_header: HeaderValue,
}

impl SessionCookieConfig {
    /// Build production cookie policy from validated service session policy.
    pub fn production(policy: &MagicLinkServiceConfig) -> Result<Self, MagicLinkConfigError> {
        let max_age = policy.session_max_age()?;
        Ok(Self {
            name: DEFAULT_SESSION_COOKIE_NAME.to_owned(),
            path: DEFAULT_SESSION_COOKIE_PATH.to_owned(),
            max_age_secs: max_age.idle_secs,
            secure: true,
            same_site: SameSite::Lax,
            clear_header: HeaderValue::from_static(DEFAULT_SESSION_CLEAR_HEADER),
        })
    }

    /// Build explicit local-HTTP cookie policy from validated service policy.
    pub fn local_development(
        policy: &MagicLinkServiceConfig,
    ) -> Result<Self, MagicLinkConfigError> {
        let mut config = Self::production(policy)?;
        config.secure = false;
        config.clear_header = HeaderValue::from_static(DEFAULT_SESSION_CLEAR_HEADER_INSECURE);
        Ok(config)
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self, CookieConfigError> {
        let name = name.into();
        validate_cookie_name(&name)?;
        self.name = name;
        self.rebuild_clear_header()?;
        Ok(self)
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Result<Self, CookieConfigError> {
        let path = path.into();
        validate_cookie_path(&path)?;
        self.path = path;
        self.rebuild_clear_header()?;
        Ok(self)
    }

    pub fn with_same_site(mut self, same_site: SameSite) -> Result<Self, CookieConfigError> {
        if same_site == SameSite::None && !self.secure {
            return Err(CookieConfigError::SameSiteNoneRequiresSecure);
        }
        self.same_site = same_site;
        self.rebuild_clear_header()?;
        Ok(self)
    }

    fn rebuild_clear_header(&mut self) -> Result<(), CookieConfigError> {
        self.clear_header =
            build_clear_cookie_header(&self.name, &self.path, self.secure, self.same_site)?;
        Ok(())
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
    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    #[must_use]
    pub fn secure(&self) -> bool {
        self.secure
    }

    #[must_use]
    pub fn same_site(&self) -> SameSite {
        self.same_site
    }
}

/// Create a host-only session `Set-Cookie` value.
pub fn session_set_cookie_header(
    config: &SessionCookieConfig,
    token: &str,
) -> Result<HeaderValue, MagicLinkHttpError> {
    if !is_valid_cookie_value(token) {
        return Err(MagicLinkHttpError::Internal);
    }
    cookie_header(
        config.name(),
        token,
        config.path(),
        config.secure(),
        config.same_site(),
        Some(config.max_age_secs()),
        false,
    )
}

/// The byte-for-byte attribute-parity session clear header.
///
/// Precomputed when the config is constructed. This is a cheap refcounted
/// clone, not a per-response format-and-parse.
#[must_use]
pub fn clear_session_cookie_header(config: &SessionCookieConfig) -> HeaderValue {
    config.clear_header.clone()
}

/// Create a confirm-cookie set header with a lifetime in
/// `1..=`[`MagicLinkConfirmCookie::MAX_ABSOLUTE_AGE_SECS`] (the confirm-cookie cap
/// owned by the service layer).
pub fn set_confirm_cookie_header(
    config: &ConfirmCookieConfig,
    value: &str,
    max_age_secs: u64,
) -> Result<HeaderValue, MagicLinkHttpError> {
    if max_age_secs == 0
        || max_age_secs > MagicLinkConfirmCookie::MAX_ABSOLUTE_AGE_SECS
        || !is_valid_cookie_value(value)
    {
        return Err(MagicLinkHttpError::Internal);
    }
    cookie_header(
        config.name(),
        value,
        config.path(),
        config.secure(),
        config.same_site(),
        Some(max_age_secs),
        false,
    )
}

/// The byte-for-byte attribute-parity confirm-cookie clear header.
///
/// Precomputed when the config is constructed. This is a cheap refcounted
/// clone, not a per-response format-and-parse.
#[must_use]
pub fn clear_confirm_cookie_header(config: &ConfirmCookieConfig) -> HeaderValue {
    config.clear_header.clone()
}

fn validate_cookie_name(value: &str) -> Result<(), CookieConfigError> {
    if is_lower_snake_cookie_name(value) {
        Ok(())
    } else {
        Err(CookieConfigError::InvalidName)
    }
}

fn validate_cookie_path(value: &str) -> Result<(), CookieConfigError> {
    if is_valid_cookie_path(value) {
        Ok(())
    } else {
        Err(CookieConfigError::InvalidPath)
    }
}

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
        && value.len() <= MAX_SELECTED_COOKIE_VALUE_BYTES
        && value.bytes().all(is_cookie_octet)
        && !value.starts_with('"')
}

/// Build the byte-for-byte clear header for a validated cookie shape. Runs at
/// config-construction time only. Responses clone the stored value.
fn build_clear_cookie_header(
    name: &str,
    path: &str,
    secure: bool,
    same_site: SameSite,
) -> Result<HeaderValue, CookieConfigError> {
    // A validated name/path always forms a legal header value, so this error
    // path is unreachable. It maps to the fallible inputs rather than panicking.
    cookie_header(name, "", path, secure, same_site, Some(0), true)
        .map_err(|_| CookieConfigError::InvalidName)
}

fn cookie_header(
    name: &str,
    value: &str,
    path: &str,
    secure: bool,
    same_site: SameSite,
    max_age: Option<u64>,
    clear: bool,
) -> Result<HeaderValue, MagicLinkHttpError> {
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
    HeaderValue::from_str(&header).map_err(|_| MagicLinkHttpError::Internal)
}

pub(crate) fn cookie_path_covers(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path == request_path {
        return true;
    }
    let Some(remainder) = request_path.strip_prefix(cookie_path) else {
        return false;
    };
    cookie_path.ends_with('/') || remainder.starts_with('/')
}

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;

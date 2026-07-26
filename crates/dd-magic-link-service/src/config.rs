//! Service configuration.

use core::fmt;

use dd_auth_token_core::cookie::MaxAge;
use dd_auth_token_core::keyring::{KeyPurpose, SessionCookie};

use crate::types::{
    DEFAULT_MAGIC_LINK_TTL_SECS, DEFAULT_SESSION_ABSOLUTE_SECS, DEFAULT_SESSION_IDLE_SECS,
};

/// Invalid magic-link service policy.
///
/// Variants never carry configured values, consent versions, or identifiers.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MagicLinkConfigError {
    /// Magic-link bearer lifetime was zero.
    ZeroMagicLinkTtl,
    /// Session idle lifetime was zero.
    ZeroSessionIdleTtl,
    /// Session absolute lifetime was zero.
    ZeroSessionAbsoluteTtl,
    /// Session idle lifetime exceeded the absolute lifetime.
    SessionIdleExceedsAbsolute,
    /// Session absolute lifetime exceeded the session-cookie purpose cap.
    SessionAbsoluteExceedsCookieCap,
    /// At least one rate-limit threshold was zero.
    ZeroRateLimit,
    /// At least one rate-limit window was zero.
    ZeroRateLimitWindow,
}

impl fmt::Display for MagicLinkConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMagicLinkTtl => f.write_str("magic-link lifetime must be non-zero"),
            Self::ZeroSessionIdleTtl => f.write_str("session idle lifetime must be non-zero"),
            Self::ZeroSessionAbsoluteTtl => {
                f.write_str("session absolute lifetime must be non-zero")
            }
            Self::SessionIdleExceedsAbsolute => {
                f.write_str("session idle lifetime exceeds absolute lifetime")
            }
            Self::SessionAbsoluteExceedsCookieCap => {
                f.write_str("session absolute lifetime exceeds cookie cap")
            }
            Self::ZeroRateLimit => f.write_str("rate-limit threshold must be non-zero"),
            Self::ZeroRateLimitWindow => f.write_str("rate-limit window must be non-zero"),
        }
    }
}

impl std::error::Error for MagicLinkConfigError {}

/// Default v1 rate-limit thresholds and windows.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RateLimitConfig {
    pub request_email_short_limit: u32,
    pub request_email_short_window_secs: u64,
    pub request_email_daily_limit: u32,
    pub request_email_daily_window_secs: u64,
    pub request_client_short_limit: u32,
    pub request_client_short_window_secs: u64,
    pub request_client_hourly_limit: u32,
    pub request_client_hourly_window_secs: u64,
    pub outbox_email_hourly_limit: u32,
    pub outbox_email_hourly_window_secs: u64,
    pub outbox_email_daily_limit: u32,
    pub outbox_email_daily_window_secs: u64,
    pub consume_selector_limit: u32,
    pub consume_client_short_limit: u32,
    pub consume_client_short_window_secs: u64,
    pub consume_client_hourly_limit: u32,
    pub consume_client_hourly_window_secs: u64,
    pub malformed_consume_client_limit: u32,
    pub malformed_consume_client_window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            request_email_short_limit: 3,
            request_email_short_window_secs: 15 * 60,
            request_email_daily_limit: 10,
            request_email_daily_window_secs: 24 * 60 * 60,
            request_client_short_limit: 10,
            request_client_short_window_secs: 10 * 60,
            request_client_hourly_limit: 50,
            request_client_hourly_window_secs: 60 * 60,
            outbox_email_hourly_limit: 3,
            outbox_email_hourly_window_secs: 60 * 60,
            outbox_email_daily_limit: 10,
            outbox_email_daily_window_secs: 24 * 60 * 60,
            consume_selector_limit: 5,
            consume_client_short_limit: 20,
            consume_client_short_window_secs: 10 * 60,
            consume_client_hourly_limit: 100,
            consume_client_hourly_window_secs: 60 * 60,
            malformed_consume_client_limit: 20,
            malformed_consume_client_window_secs: 10 * 60,
        }
    }
}

/// Magic-link service configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MagicLinkServiceConfig {
    pub terms_version: String,
    pub privacy_version: String,
    pub magic_link_ttl_secs: u64,
    pub session_idle_secs: u64,
    pub session_absolute_secs: u64,
    pub enforce_country: bool,
    pub rate_limits: RateLimitConfig,
}

impl MagicLinkServiceConfig {
    #[must_use]
    pub fn new(terms_version: impl Into<String>, privacy_version: impl Into<String>) -> Self {
        Self {
            terms_version: terms_version.into(),
            privacy_version: privacy_version.into(),
            magic_link_ttl_secs: DEFAULT_MAGIC_LINK_TTL_SECS,
            session_idle_secs: DEFAULT_SESSION_IDLE_SECS,
            session_absolute_secs: DEFAULT_SESSION_ABSOLUTE_SECS,
            enforce_country: false,
            rate_limits: RateLimitConfig::default(),
        }
    }

    /// Validate authentication lifetimes and every limiter threshold/window.
    ///
    /// Service operations call this before processing attacker-controlled input.
    /// Applications may also call it during setup to fail before serving traffic.
    pub fn validate(&self) -> Result<(), MagicLinkConfigError> {
        if self.magic_link_ttl_secs == 0 {
            return Err(MagicLinkConfigError::ZeroMagicLinkTtl);
        }
        self.session_max_age()?;
        self.rate_limits.validate()
    }

    /// Validate only incoming-session lifetime policy and return its cookie bounds.
    ///
    /// Existing-session authentication and HTTP cookie configuration use this
    /// narrower policy so unrelated pre-auth or limiter configuration cannot
    /// disable otherwise valid sessions.
    pub fn session_max_age(&self) -> Result<MaxAge, MagicLinkConfigError> {
        if self.session_idle_secs == 0 {
            return Err(MagicLinkConfigError::ZeroSessionIdleTtl);
        }
        if self.session_absolute_secs == 0 {
            return Err(MagicLinkConfigError::ZeroSessionAbsoluteTtl);
        }
        if self.session_idle_secs > self.session_absolute_secs {
            return Err(MagicLinkConfigError::SessionIdleExceedsAbsolute);
        }
        if self.session_absolute_secs > SessionCookie::MAX_ABSOLUTE_AGE_SECS {
            return Err(MagicLinkConfigError::SessionAbsoluteExceedsCookieCap);
        }
        Ok(MaxAge::new(
            self.session_idle_secs,
            self.session_absolute_secs,
        ))
    }
}

impl RateLimitConfig {
    fn validate(&self) -> Result<(), MagicLinkConfigError> {
        let limits = [
            self.request_email_short_limit,
            self.request_email_daily_limit,
            self.request_client_short_limit,
            self.request_client_hourly_limit,
            self.outbox_email_hourly_limit,
            self.outbox_email_daily_limit,
            self.consume_selector_limit,
            self.consume_client_short_limit,
            self.consume_client_hourly_limit,
            self.malformed_consume_client_limit,
        ];
        if limits.contains(&0) {
            return Err(MagicLinkConfigError::ZeroRateLimit);
        }

        let windows = [
            self.request_email_short_window_secs,
            self.request_email_daily_window_secs,
            self.request_client_short_window_secs,
            self.request_client_hourly_window_secs,
            self.outbox_email_hourly_window_secs,
            self.outbox_email_daily_window_secs,
            self.consume_client_short_window_secs,
            self.consume_client_hourly_window_secs,
            self.malformed_consume_client_window_secs,
        ];
        if windows.contains(&0) {
            return Err(MagicLinkConfigError::ZeroRateLimitWindow);
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

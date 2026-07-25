//! Service configuration.

use crate::types::{
    DEFAULT_MAGIC_LINK_TTL_SECS, DEFAULT_SESSION_ABSOLUTE_SECS, DEFAULT_SESSION_IDLE_SECS,
};

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
}

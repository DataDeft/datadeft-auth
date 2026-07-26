//! Service configuration tests.

use super::*;

type RateLimitMutation = fn(&mut RateLimitConfig);

fn config() -> MagicLinkServiceConfig {
    MagicLinkServiceConfig::new("terms-sentinel", "privacy-sentinel")
}

#[test]
fn default_policy_validates_and_uses_cookie_absolute_cap() {
    let config = config();

    assert_eq!(
        config.session_absolute_secs,
        SessionCookie::MAX_ABSOLUTE_AGE_SECS
    );
    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn zero_ttls_are_rejected_individually() {
    let mut magic_link = config();
    magic_link.magic_link_ttl_secs = 0;
    assert_eq!(
        magic_link.validate(),
        Err(MagicLinkConfigError::ZeroMagicLinkTtl)
    );

    let mut idle = config();
    idle.session_idle_secs = 0;
    assert_eq!(
        idle.validate(),
        Err(MagicLinkConfigError::ZeroSessionIdleTtl)
    );

    let mut absolute = config();
    absolute.session_absolute_secs = 0;
    assert_eq!(
        absolute.validate(),
        Err(MagicLinkConfigError::ZeroSessionAbsoluteTtl)
    );
}

#[test]
fn session_lifetime_order_and_cap_boundaries_are_validated() {
    let mut equal = config();
    equal.session_idle_secs = 60;
    equal.session_absolute_secs = 60;
    assert_eq!(equal.validate(), Ok(()));

    let mut reversed = config();
    reversed.session_idle_secs = 61;
    reversed.session_absolute_secs = 60;
    assert_eq!(
        reversed.validate(),
        Err(MagicLinkConfigError::SessionIdleExceedsAbsolute)
    );

    let mut at_cap = config();
    at_cap.session_absolute_secs = SessionCookie::MAX_ABSOLUTE_AGE_SECS;
    assert_eq!(at_cap.validate(), Ok(()));

    let mut above_cap = config();
    above_cap.session_absolute_secs = SessionCookie::MAX_ABSOLUTE_AGE_SECS + 1;
    assert_eq!(
        above_cap.validate(),
        Err(MagicLinkConfigError::SessionAbsoluteExceedsCookieCap)
    );
}

#[test]
fn every_rate_limit_threshold_rejects_zero() {
    let cases: &[(&str, RateLimitMutation)] = &[
        ("request_email_short_limit", |limits| {
            limits.request_email_short_limit = 0;
        }),
        ("request_email_daily_limit", |limits| {
            limits.request_email_daily_limit = 0;
        }),
        ("request_client_short_limit", |limits| {
            limits.request_client_short_limit = 0;
        }),
        ("request_client_hourly_limit", |limits| {
            limits.request_client_hourly_limit = 0;
        }),
        ("outbox_email_hourly_limit", |limits| {
            limits.outbox_email_hourly_limit = 0;
        }),
        ("outbox_email_daily_limit", |limits| {
            limits.outbox_email_daily_limit = 0;
        }),
        ("consume_selector_limit", |limits| {
            limits.consume_selector_limit = 0;
        }),
        ("consume_client_short_limit", |limits| {
            limits.consume_client_short_limit = 0;
        }),
        ("consume_client_hourly_limit", |limits| {
            limits.consume_client_hourly_limit = 0;
        }),
        ("malformed_consume_client_limit", |limits| {
            limits.malformed_consume_client_limit = 0;
        }),
    ];

    for (name, mutate) in cases {
        let mut config = config();
        mutate(&mut config.rate_limits);
        assert_eq!(
            config.validate(),
            Err(MagicLinkConfigError::ZeroRateLimit),
            "{name}"
        );
    }
}

#[test]
fn every_rate_limit_window_rejects_zero() {
    let cases: &[(&str, RateLimitMutation)] = &[
        ("request_email_short_window_secs", |limits| {
            limits.request_email_short_window_secs = 0;
        }),
        ("request_email_daily_window_secs", |limits| {
            limits.request_email_daily_window_secs = 0;
        }),
        ("request_client_short_window_secs", |limits| {
            limits.request_client_short_window_secs = 0;
        }),
        ("request_client_hourly_window_secs", |limits| {
            limits.request_client_hourly_window_secs = 0;
        }),
        ("outbox_email_hourly_window_secs", |limits| {
            limits.outbox_email_hourly_window_secs = 0;
        }),
        ("outbox_email_daily_window_secs", |limits| {
            limits.outbox_email_daily_window_secs = 0;
        }),
        ("consume_client_short_window_secs", |limits| {
            limits.consume_client_short_window_secs = 0;
        }),
        ("consume_client_hourly_window_secs", |limits| {
            limits.consume_client_hourly_window_secs = 0;
        }),
        ("malformed_consume_client_window_secs", |limits| {
            limits.malformed_consume_client_window_secs = 0;
        }),
    ];

    for (name, mutate) in cases {
        let mut config = config();
        mutate(&mut config.rate_limits);
        assert_eq!(
            config.validate(),
            Err(MagicLinkConfigError::ZeroRateLimitWindow),
            "{name}"
        );
    }
}

#[test]
fn config_errors_do_not_expose_version_values() {
    let mut config = config();
    config.magic_link_ttl_secs = 0;
    let error = config.validate().expect_err("invalid config");
    let debug = format!("{error:?}");
    let display = error.to_string();

    for sentinel in ["terms-sentinel", "privacy-sentinel"] {
        assert!(!debug.contains(sentinel));
        assert!(!display.contains(sentinel));
    }
}

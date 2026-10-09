//! Rate-limit checks for the request, landing, and consume paths.

use futures_util::future::join_all;

use crate::config::MagicLinkServiceConfig;
use crate::error::MagicLinkServiceError;
use crate::traits::{RateLimitDecision, RateLimiter};
use crate::types::RateLimitKey;

use super::*;

pub(super) async fn landing_limits_deny<Limiter: RateLimiter>(
    limiter: &Limiter,
    config: &MagicLinkServiceConfig,
    selector_lookup: &str,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let checks = [(
        format!("magic-link:landing:selector:{selector_lookup}"),
        config.rate_limits.landing_selector_limit,
        config.rate_limits.landing_selector_window_secs,
    )];
    any_limit_denied(limiter, checks, now_unix).await
}

/// Request-path limits: the request and outbox email buckets, checked as one
/// concurrent batch. With a network-backed limiter each check is a round
/// trip, so sequential awaits would serialize four of them per request.
pub(super) async fn request_and_outbox_limits_deny<Limiter: RateLimiter>(
    limiter: &Limiter,
    config: &MagicLinkServiceConfig,
    email_lookup: &str,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let limits = &config.rate_limits;
    let checks = [
        (
            format!("magic-link:request:email:short:{email_lookup}"),
            limits.request_email_short_limit,
            limits.request_email_short_window_secs,
        ),
        (
            format!("magic-link:request:email:daily:{email_lookup}"),
            limits.request_email_daily_limit,
            limits.request_email_daily_window_secs,
        ),
        (
            format!("magic-link:outbox:email:hourly:{email_lookup}"),
            limits.outbox_email_hourly_limit,
            limits.outbox_email_hourly_window_secs,
        ),
        (
            format!("magic-link:outbox:email:daily:{email_lookup}"),
            limits.outbox_email_daily_limit,
            limits.outbox_email_daily_window_secs,
        ),
    ];
    any_limit_denied(limiter, checks, now_unix).await
}

pub(super) async fn consume_limits_deny<Limiter: RateLimiter>(
    limiter: &Limiter,
    config: &MagicLinkServiceConfig,
    selector_lookup: &str,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let checks = [(
        format!("magic-link:consume:selector:{selector_lookup}"),
        config.rate_limits.consume_selector_limit,
        config.magic_link_ttl_secs,
    )];
    any_limit_denied(limiter, checks, now_unix).await
}

/// Run every `(key, limit, window_secs)` check concurrently. Report whether
/// any bucket denied.
///
/// Concurrency is an accounting choice as well as a latency one. The limiter
/// consults every bucket (and advances its counter) even when another bucket
/// denies, where the previous sequential form stopped at the first denial. A
/// denied request therefore still consumes quota in every bucket, which only
/// tightens limiting. A dependency error takes precedence over a denial.
/// Limiter state is unknown, so the request fails closed as unavailable.
async fn any_limit_denied<Limiter: RateLimiter>(
    limiter: &Limiter,
    checks: impl IntoIterator<Item = (String, u32, u64)>,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let checks: Vec<(RateLimitKey, u32, u64)> = checks
        .into_iter()
        .map(|(key, limit, window_secs)| {
            (RateLimitKey::from_service_built(key), limit, window_secs)
        })
        .collect();
    let decisions = join_all(checks.iter().map(|(key, limit, window_secs)| {
        limiter.check_rate_limit(key, *limit, *window_secs, now_unix)
    }))
    .await;

    let mut denied = false;
    for decision in decisions {
        denied |= decision.map_err(map_dependency_error)? == RateLimitDecision::Denied;
    }
    Ok(denied)
}

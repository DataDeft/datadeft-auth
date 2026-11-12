//! Cost of handing `MagicLinkServiceConfig` to a per-request service value.
//!
//! Two measurements: the config clone alone, and one full deterministic
//! `request_magic_link` pass (in-bench fakes, fixed clock, counting RNG, no
//! IO) including the service-struct construction exactly as HTTP callers
//! build it per request.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use datadeft_auth_token_core::test_support::CountingRng;
use datadeft_magic_link_service::{
    Clock, DependencyError, LocaleAllowlist, LookupHmacKey, MagicLinkEmail, MagicLinkOutbox,
    MagicLinkRecord, MagicLinkRepository, MagicLinkRequestService, MagicLinkServiceConfig,
    NormalizedEmail, RateLimitDecision, RateLimitKey, RateLimiter, RequestMagicLinkCommand,
    RequestMagicLinkOutcome,
};

const NOW: u64 = 1_000;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(NOW)
    }
}

struct AllowAllLimiter;

impl RateLimiter for AllowAllLimiter {
    async fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        _limit: u32,
        _window_secs: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        black_box(key.as_str());
        Ok(RateLimitDecision::Allowed)
    }

    async fn check_lifetime_limit(
        &self,
        key: &RateLimitKey,
        _limit: u32,
        _expires_at_unix: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        black_box(key.as_str());
        Ok(RateLimitDecision::Allowed)
    }
}

struct DropRepository;

impl MagicLinkRepository for DropRepository {
    async fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> Result<(), DependencyError> {
        black_box(&record);
        Ok(())
    }
}

struct DropOutbox;

impl MagicLinkOutbox for DropOutbox {
    async fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError> {
        black_box(&email);
        Ok(())
    }
}

/// A production-shaped config: versioned consent strings, a locale allowlist,
/// and the default rate limits.
fn realistic_config() -> MagicLinkServiceConfig {
    let mut config = MagicLinkServiceConfig::new("terms-2025-11-01", "privacy-2025-11-01");
    config.locales =
        Some(LocaleAllowlist::new("en", ["de", "fr", "nl", "hu"]).expect("bench locale allowlist"));
    config
}

fn bench_config_clone(c: &mut Criterion) {
    let config = realistic_config();
    c.bench_function("magic_link_service_config_clone", |b| {
        b.iter(|| black_box(black_box(&config).clone()));
    });
}

fn bench_request_path(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let config = realistic_config();
    let magic_links = DropRepository;
    let limiter = AllowAllLimiter;
    let outbox = DropOutbox;
    let clock = FixedClock;
    let lookup_hmac_key = LookupHmacKey::new([0x42; 32]);
    let email = NormalizedEmail::from_normalized("account@example.test").expect("bench email");
    let mut rng = CountingRng::starting_at(0);
    c.bench_function("request_magic_link_per_request_service", |b| {
        b.iter(|| {
            // Per-request construction exactly as the HTTP adapters do it.
            let mut service = MagicLinkRequestService {
                magic_links: &magic_links,
                limiter: &limiter,
                outbox: &outbox,
                clock: &clock,
                rng: &mut rng,
                lookup_hmac_key: &lookup_hmac_key,
                config: &config,
            };
            let command =
                RequestMagicLinkCommand::new(email.clone(), true, true).with_locale_hint("de");
            let outcome = runtime
                .block_on(service.request_magic_link(command))
                .expect("bench request");
            assert!(matches!(outcome, RequestMagicLinkOutcome::Sent));
            black_box(outcome)
        });
    });
}

criterion_group!(benches, bench_config_clone, bench_request_path);
criterion_main!(benches);

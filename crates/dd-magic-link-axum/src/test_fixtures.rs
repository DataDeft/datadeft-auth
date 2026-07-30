//! Shared fixtures for the per-module test suites: service policy, scanner
//! config, request/response helpers, and fake service dependencies.

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use dd_auth_token_core::keyring::{KeyPurpose, KeyRing};
use dd_auth_token_core::test_support::{CountingRng, test_keyring_with_windows};
use dd_magic_link_core::{LookupHmac, LookupHmacKey, MagicLinkConfirmCookie, NormalizedEmail};
use dd_magic_link_service::{
    BeginMagicLinkLandingCommand, Clock, CommitMagicLinkAuthentication,
    CommitMagicLinkAuthenticationError, DependencyError, MagicLinkAuthenticationCandidate,
    MagicLinkAuthenticationRepository, MagicLinkFlowError, MagicLinkFlowService,
    MagicLinkServiceConfig, RateLimitDecision, RateLimitKey, RateLimiter, SessionCookie, SessionId,
    SessionRecord, SessionRepository, UserRecord,
};

use crate::{
    ConfirmCookieConfig, MagicLinkScannerFlowConfig, SameOriginPostConfig, SameOriginRedirect,
    SessionCookieConfig,
};

pub(crate) fn policy() -> MagicLinkServiceConfig {
    MagicLinkServiceConfig::new("terms-v1", "privacy-v1")
}

pub(crate) fn scanner_config() -> MagicLinkScannerFlowConfig {
    MagicLinkScannerFlowConfig::new(
        SameOriginRedirect::parse("/auth/magic-link/confirm").expect("post action"),
        SameOriginPostConfig::parse("https://example.test").expect("origin"),
        SessionCookieConfig::production(&policy()).expect("session policy"),
        ConfirmCookieConfig::production_defaults(),
    )
    .expect("scanner config")
}

pub(crate) fn post_request(content_type: &'static str, body: impl Into<Body>) -> Request {
    Request::builder()
        .method(Method::POST)
        .uri("/auth/magic-link/confirm")
        .header(CONTENT_TYPE, content_type)
        .header(ORIGIN, "https://example.test")
        .header(COOKIE, "dd_auth_confirm=confirm-cookie")
        .body(body.into())
        .expect("request builds")
}

pub(crate) async fn response_parts(response: Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads")
        .to_vec();
    (status, headers, body)
}

#[derive(Clone, Copy)]
pub(crate) enum FixtureFlowError {
    MagicLinkUnavailable,
    Unavailable,
    Internal,
}

pub(crate) struct FixtureRepository;

impl MagicLinkAuthenticationRepository for FixtureRepository {
    async fn find_magic_link_for_authentication(
        &self,
        _selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        Ok(None)
    }

    async fn find_user_for_authentication(
        &self,
        _email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        Ok(None)
    }

    async fn commit_magic_link_authentication(
        &self,
        _command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        Err(CommitMagicLinkAuthenticationError::Internal)
    }
}

impl SessionRepository for FixtureRepository {
    async fn find_session(
        &self,
        _session_id: &SessionId,
        _now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        Ok(None)
    }

    async fn revoke_session(
        &self,
        _session_id: &SessionId,
        _revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        Ok(())
    }
}

pub(crate) struct FixtureLimiter;

impl RateLimiter for FixtureLimiter {
    async fn check_rate_limit(
        &self,
        _key: &RateLimitKey,
        _limit: u32,
        _window_secs: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        Ok(RateLimitDecision::Allowed)
    }
}

pub(crate) struct FixtureClock {
    pub(crate) error: Option<DependencyError>,
}

impl Clock for FixtureClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        self.error.map_or(Ok(1_000), Err)
    }
}

pub(crate) fn fixture_keyring<P: KeyPurpose>() -> KeyRing<P> {
    test_keyring_with_windows(0x42, "fixture-active", 20_000, 3_000_000)
}

pub(crate) async fn fixture_flow_error(kind: FixtureFlowError) -> MagicLinkFlowError {
    let repository = FixtureRepository;
    let limiter = FixtureLimiter;
    let clock = FixtureClock {
        error: matches!(kind, FixtureFlowError::Unavailable)
            .then_some(DependencyError::Unavailable),
    };
    let mut rng = CountingRng::starting_at(0);
    let lookup_key = LookupHmacKey::new([0x24; 32]);
    let confirm_keyring = fixture_keyring::<MagicLinkConfirmCookie>();
    let session_keyring = fixture_keyring::<SessionCookie>();
    let mut service_config = policy();
    if matches!(kind, FixtureFlowError::Internal) {
        service_config.magic_link_flow_ttl_secs = 0;
    }
    let mut service = MagicLinkFlowService {
        authentication: &repository,
        sessions: &repository,
        limiter: &limiter,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config: service_config,
    };
    service
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new("malformed".to_owned()))
        .await
        .expect_err("fixture flow error")
}

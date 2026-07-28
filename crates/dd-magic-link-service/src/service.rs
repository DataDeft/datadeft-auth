//! Request and scanner-safe authentication orchestration.
//!
//! Request-source, network, global, malformed-input, and external-proof admission
//! controls are intentionally outside this service. Magic-link owns only its
//! email/selector limiter domains, user/session transaction, outbox, clock, and
//! randomness policy.

use dd_auth_token_core::cookie::mint_bound_cookie;
use dd_auth_token_core::keyring::KeyRing;
use dd_magic_link_core::flow_cookie::{
    MagicLinkFlowBindings, MagicLinkFlowCookie, VerifiedMagicLinkFlow, mint_magic_link_flow,
    verify_magic_link_flow,
};
use dd_magic_link_core::{
    LookupHmac, LookupHmacKey, MagicLinkToken, VerifierHash, email_lookup_hmac,
    flow_account_binding, flow_selector_binding, flow_verifier_binding, selector_lookup_hmac,
    selector_lookup_hmac_from_flow_binding, verifier_hash, verifier_hash_from_flow_binding,
};
use futures_util::future::join_all;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::config::MagicLinkServiceConfig;
use crate::error::{
    CommitMagicLinkAuthenticationError, DependencyError, MagicLinkFlowError, MagicLinkServiceError,
};
use crate::session_body::encode_session_cookie_body;
use crate::traits::{
    Clock, MagicLinkAuthenticationRepository, MagicLinkOutbox, MagicLinkRepository,
    RateLimitDecision, RateLimiter, SessionRepository,
};
use crate::types::{
    AuthenticationAttemptId, BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome,
    CommitMagicLinkAuthentication, ConfirmMagicLinkFlowCommand, ConfirmMagicLinkFlowOutcome,
    MagicLinkAccountIdentity, MagicLinkAuthenticationCandidate, MagicLinkAuthenticationExpectation,
    MagicLinkAuthenticationOutcome, MagicLinkAuthenticationUser, MagicLinkEmail, MagicLinkRecord,
    RateLimitKey, RequestMagicLinkCommand, RequestMagicLinkOutcome, SessionCookie, SessionId,
    UserId, UserRecord, validate_country,
};

/// Request-flow-only service. It does not require user/session repositories or a
/// session-cookie keyring. Construct with a struct literal; every field is a
/// required dependency.
pub struct MagicLinkRequestService<'a, MagicLinks, Limiter, Outbox, ServiceClock, Rng> {
    pub magic_links: &'a MagicLinks,
    pub limiter: &'a Limiter,
    pub outbox: &'a Outbox,
    pub clock: &'a ServiceClock,
    pub rng: &'a mut Rng,
    pub lookup_hmac_key: &'a LookupHmacKey,
    pub config: MagicLinkServiceConfig,
}

impl<MagicLinks, Limiter, Outbox, ServiceClock, Rng>
    MagicLinkRequestService<'_, MagicLinks, Limiter, Outbox, ServiceClock, Rng>
where
    MagicLinks: MagicLinkRepository,
    Limiter: RateLimiter,
    Outbox: MagicLinkOutbox,
    ServiceClock: Clock,
    Rng: RngCore + CryptoRng,
{
    /// Request a magic link. Throttled request/outbox paths return the same
    /// generic accepted outcome as a send so callers cannot enumerate accounts
    /// or throttling policy from the public response.
    pub async fn request_magic_link(
        &mut self,
        command: RequestMagicLinkCommand,
    ) -> Result<RequestMagicLinkOutcome, MagicLinkServiceError> {
        validate_config(&self.config)?;
        if !command.terms_accepted() || !command.privacy_accepted() {
            return Err(MagicLinkServiceError::BadRequest);
        }

        let now_unix = self.clock.now_unix()?;
        let expires_at_unix = now_unix
            .checked_add(self.config.magic_link_ttl_secs)
            .ok_or(MagicLinkServiceError::Internal)?;
        let email_lookup = email_lookup_hmac(self.lookup_hmac_key, command.email())?;

        if request_and_outbox_limits_deny(
            self.limiter,
            &self.config,
            email_lookup.as_storage_value(),
            now_unix,
        )
        .await?
        {
            return Ok(RequestMagicLinkOutcome);
        }

        let token = MagicLinkToken::generate(self.rng)?;
        let selector_lookup = selector_lookup_hmac(self.lookup_hmac_key, token.selector())?;
        let verifier_hash = verifier_hash(self.lookup_hmac_key, token.verifier())?;

        let record = MagicLinkRecord {
            selector_lookup_hmac: selector_lookup,
            email: command.email().clone(),
            verifier_hash,
            expires_at_unix,
            consumed_at_unix: None,
            terms_version: self.config.terms_version.clone(),
            privacy_version: self.config.privacy_version.clone(),
            consented_at_unix: now_unix,
        };

        self.magic_links
            .put_magic_link_if_absent(record)
            .await
            .map_err(map_dependency_error)?;
        self.outbox
            .enqueue_magic_link(MagicLinkEmail {
                email: command.email().clone(),
                token,
                expires_at_unix,
            })
            .await
            .map_err(map_dependency_error)?;

        Ok(RequestMagicLinkOutcome)
    }
}

/// Canonical scanner-safe landing, confirmation, and revocation service.
/// Construct with a struct literal; every field is a required dependency.
pub struct MagicLinkFlowService<'a, Authentication, Sessions, Limiter, ServiceClock, Rng> {
    pub authentication: &'a Authentication,
    pub sessions: &'a Sessions,
    pub limiter: &'a Limiter,
    pub clock: &'a ServiceClock,
    pub rng: &'a mut Rng,
    pub lookup_hmac_key: &'a LookupHmacKey,
    pub flow_keyring: &'a KeyRing<MagicLinkFlowCookie>,
    pub session_keyring: &'a KeyRing<SessionCookie>,
    pub config: MagicLinkServiceConfig,
}

impl<Authentication, Sessions, Limiter, ServiceClock, Rng>
    MagicLinkFlowService<'_, Authentication, Sessions, Limiter, ServiceClock, Rng>
where
    Authentication: MagicLinkAuthenticationRepository,
    Sessions: SessionRepository,
    Limiter: RateLimiter,
    ServiceClock: Clock,
    Rng: RngCore + CryptoRng,
{
    /// Validate a landing token without consuming it or creating user/session state.
    pub async fn begin_magic_link_landing(
        &mut self,
        command: BeginMagicLinkLandingCommand,
    ) -> Result<BeginMagicLinkLandingOutcome, MagicLinkFlowError> {
        validate_config(&self.config).map_err(MagicLinkFlowError::from_public_error)?;
        let now_unix = self
            .clock
            .now_unix()
            .map_err(map_dependency_error)
            .map_err(MagicLinkFlowError::from_public_error)?;

        let raw_token = match command.raw_token() {
            Some(raw_token) => raw_token,
            None => return Err(flow_error(MagicLinkServiceError::MagicLinkUnavailable)),
        };
        let token = match MagicLinkToken::parse(raw_token) {
            Ok(token) => token,
            Err(_) => return Err(flow_error(MagicLinkServiceError::MagicLinkUnavailable)),
        };

        let selector_lookup = selector_lookup_hmac(self.lookup_hmac_key, token.selector())
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        if landing_limits_deny(
            self.limiter,
            &self.config,
            selector_lookup.as_storage_value(),
            now_unix,
        )
        .await
        .map_err(MagicLinkFlowError::from_public_error)?
        {
            return Err(flow_error(MagicLinkServiceError::MagicLinkUnavailable));
        }

        let presented_verifier_hash = verifier_hash(self.lookup_hmac_key, token.verifier())
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let candidate = self
            .authentication
            .find_magic_link_for_authentication(&selector_lookup)
            .await
            .map_err(map_dependency_error)
            .map_err(MagicLinkFlowError::from_public_error)?;
        let candidate =
            validate_scanner_candidate(&self.config, candidate, &presented_verifier_hash, now_unix)
                .map_err(MagicLinkFlowError::from_public_error)?;

        let email_lookup = email_lookup_hmac(self.lookup_hmac_key, &candidate.email)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let selector_binding = flow_selector_binding(&selector_lookup)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let verifier_binding = flow_verifier_binding(&presented_verifier_hash)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let account_binding = flow_account_binding(&email_lookup)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;

        let configured_expiry = now_unix
            .checked_add(self.config.magic_link_flow_ttl_secs)
            .ok_or_else(|| flow_error(MagicLinkServiceError::Internal))?;
        let flow_expiry = candidate.expires_at_unix.min(configured_expiry);
        if flow_expiry <= now_unix {
            return Err(flow_error(MagicLinkServiceError::MagicLinkUnavailable));
        }
        let flow_expiry_u32 =
            u32::try_from(flow_expiry).map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let cookie_max_age_secs = flow_expiry
            .checked_sub(now_unix)
            .ok_or_else(|| flow_error(MagicLinkServiceError::Internal))?;
        let account_identity = MagicLinkAccountIdentity::from_normalized_email(&candidate.email);
        let flow = mint_magic_link_flow(
            MagicLinkFlowBindings::new(
                selector_binding,
                verifier_binding,
                account_binding,
                flow_expiry_u32,
            ),
            self.flow_keyring,
            self.rng,
            now_unix,
        )
        .map_err(MagicLinkServiceError::from)
        .map_err(MagicLinkFlowError::from_public_error)?;

        Ok(BeginMagicLinkLandingOutcome {
            flow,
            account_identity,
            cookie_max_age_secs,
        })
    }

    /// Confirm authenticated scanner-flow state and atomically authenticate.
    pub async fn confirm_magic_link_flow(
        &mut self,
        command: ConfirmMagicLinkFlowCommand,
    ) -> Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError> {
        validate_config(&self.config).map_err(MagicLinkFlowError::from_public_error)?;
        let now_unix = self
            .clock
            .now_unix()
            .map_err(map_dependency_error)
            .map_err(MagicLinkFlowError::from_public_error)?;
        let country = mint_country(&self.config, command.request_country())
            .map_err(MagicLinkFlowError::from_public_error)?;

        let verified = verify_magic_link_flow(
            command.flow_cookie(),
            command.confirmation(),
            self.flow_keyring,
            now_unix,
            self.config.magic_link_flow_ttl_secs,
        )
        .map_err(|_| flow_error(MagicLinkServiceError::MagicLinkUnavailable))?;

        let selector_lookup = selector_lookup_hmac_from_flow_binding(verified.selector());
        let presented_verifier_hash = verifier_hash_from_flow_binding(verified.verifier());
        if consume_limits_deny(
            self.limiter,
            &self.config,
            selector_lookup.as_storage_value(),
            now_unix,
        )
        .await
        .map_err(MagicLinkFlowError::from_public_error)?
        {
            return Err(flow_error(MagicLinkServiceError::MagicLinkUnavailable));
        }

        let authentication = authenticate_scanner_flow(
            self.authentication,
            self.session_keyring,
            self.rng,
            self.lookup_hmac_key,
            &self.config,
            &selector_lookup,
            &presented_verifier_hash,
            &verified,
            now_unix,
            country,
        )
        .await
        .map_err(MagicLinkFlowError::from_public_error)?;
        Ok(ConfirmMagicLinkFlowOutcome { authentication })
    }

    /// Revoke a server-side session by id.
    pub async fn revoke_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(), MagicLinkServiceError> {
        let now_unix = self.clock.now_unix()?;
        self.sessions
            .revoke_session(session_id, now_unix)
            .await
            .map_err(map_dependency_error)
    }
}

fn validate_config(config: &MagicLinkServiceConfig) -> Result<(), MagicLinkServiceError> {
    config
        .validate()
        .map_err(|_| MagicLinkServiceError::Internal)
}

const fn flow_error(public_error: MagicLinkServiceError) -> MagicLinkFlowError {
    MagicLinkFlowError::from_public_error(public_error)
}

async fn landing_limits_deny<Limiter: RateLimiter>(
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

fn validate_scanner_candidate(
    config: &MagicLinkServiceConfig,
    candidate: Option<MagicLinkAuthenticationCandidate>,
    presented_verifier_hash: &VerifierHash,
    now_unix: u64,
) -> Result<MagicLinkAuthenticationCandidate, MagicLinkServiceError> {
    let candidate = compare_candidate_verifier(candidate, presented_verifier_hash)?;
    validate_scanner_candidate_state(config, &candidate, now_unix)?;
    Ok(candidate)
}

fn compare_candidate_verifier(
    candidate: Option<MagicLinkAuthenticationCandidate>,
    presented_verifier_hash: &VerifierHash,
) -> Result<MagicLinkAuthenticationCandidate, MagicLinkServiceError> {
    let Some(candidate) = candidate else {
        note_verifier_comparison();
        perform_dummy_verifier_comparison(presented_verifier_hash);
        return Err(MagicLinkServiceError::MagicLinkUnavailable);
    };
    note_verifier_comparison();
    if !candidate
        .verifier_hash
        .matches_hash_constant_time(presented_verifier_hash)
    {
        return Err(MagicLinkServiceError::MagicLinkUnavailable);
    }
    Ok(candidate)
}

fn validate_scanner_candidate_state(
    config: &MagicLinkServiceConfig,
    candidate: &MagicLinkAuthenticationCandidate,
    now_unix: u64,
) -> Result<(), MagicLinkServiceError> {
    if candidate.consumed_at_unix.is_some()
        || candidate.expires_at_unix <= now_unix
        || candidate.terms_version != config.terms_version
        || candidate.privacy_version != config.privacy_version
        || candidate.consented_at_unix == 0
    {
        Err(MagicLinkServiceError::MagicLinkUnavailable)
    } else {
        Ok(())
    }
}

async fn load_scanner_authentication_state<Authentication: MagicLinkAuthenticationRepository>(
    authentication: &Authentication,
    lookup_hmac_key: &LookupHmacKey,
    config: &MagicLinkServiceConfig,
    selector_lookup: &LookupHmac,
    presented_verifier_hash: &VerifierHash,
    expected_account: &dd_magic_link_core::flow_cookie::FlowAccountBinding,
    now_unix: u64,
) -> Result<(MagicLinkAuthenticationCandidate, Option<UserRecord>), MagicLinkServiceError> {
    let candidate = authentication
        .find_magic_link_for_authentication(selector_lookup)
        .await
        .map_err(map_dependency_error)?;
    let candidate = compare_candidate_verifier(candidate, presented_verifier_hash)?;
    let email_lookup = email_lookup_hmac(lookup_hmac_key, &candidate.email)
        .map_err(|_| MagicLinkServiceError::Internal)?;
    let candidate_account =
        flow_account_binding(&email_lookup).map_err(|_| MagicLinkServiceError::Internal)?;
    if !expected_account.matches_constant_time(&candidate_account) {
        return Err(MagicLinkServiceError::MagicLinkUnavailable);
    }
    validate_scanner_candidate_state(config, &candidate, now_unix)?;
    let user = authentication
        .find_user_for_authentication(&candidate.email)
        .await
        .map_err(map_dependency_error)?;
    Ok((candidate, user))
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_scanner_flow<Authentication, Rng>(
    authentication: &Authentication,
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    lookup_hmac_key: &LookupHmacKey,
    config: &MagicLinkServiceConfig,
    selector_lookup: &LookupHmac,
    presented_verifier_hash: &VerifierHash,
    verified: &VerifiedMagicLinkFlow,
    now_unix: u64,
    country: Option<String>,
) -> Result<MagicLinkAuthenticationOutcome, MagicLinkServiceError>
where
    Authentication: MagicLinkAuthenticationRepository,
    Rng: RngCore + CryptoRng,
{
    let (candidate, user) = load_scanner_authentication_state(
        authentication,
        lookup_hmac_key,
        config,
        selector_lookup,
        presented_verifier_hash,
        verified.account(),
        now_unix,
    )
    .await?;
    let user_branch = plan_user(user, &candidate.email, rng)?;
    let expectation = authentication_expectation(selector_lookup, &candidate);
    let mut plan = build_initial_authentication_plan(
        session_keyring,
        rng,
        expectation,
        user_branch,
        now_unix,
        config.session_absolute_secs,
        country.as_deref(),
    )?;

    let mut replans = 0_u8;
    loop {
        match commit_with_dependency_retries(authentication, &plan.command).await {
            Ok(()) => {
                let session_cookie = core::mem::take(&mut *plan.session_cookie);
                let (user_id, user_created) = user_outcome(&plan.command.user);
                return Ok(MagicLinkAuthenticationOutcome {
                    session_cookie,
                    user_id,
                    session_id: plan.command.session_id.clone(),
                    user_created,
                    country,
                });
            }
            Err(CommitMagicLinkAuthenticationError::Rejected) => {
                return Err(MagicLinkServiceError::MagicLinkUnavailable);
            }
            Err(CommitMagicLinkAuthenticationError::Internal) => {
                return Err(MagicLinkServiceError::Internal);
            }
            Err(CommitMagicLinkAuthenticationError::DependencyUnavailable) => {
                return Err(MagicLinkServiceError::Unavailable);
            }
            Err(CommitMagicLinkAuthenticationError::UserConflict) => {
                if replans >= 2 {
                    return Err(MagicLinkServiceError::Unavailable);
                }
                replans += 1;
                let (candidate, user) = load_scanner_authentication_state(
                    authentication,
                    lookup_hmac_key,
                    config,
                    selector_lookup,
                    presented_verifier_hash,
                    verified.account(),
                    now_unix,
                )
                .await?;
                plan.command.magic_link = authentication_expectation(selector_lookup, &candidate);
                plan.command.user = plan_user(user, &candidate.email, rng)?;
                plan.command.attempt_id = generate_authentication_attempt_id(rng)?;
            }
            Err(CommitMagicLinkAuthenticationError::SessionConflict) => {
                if replans >= 2 {
                    return Err(MagicLinkServiceError::Unavailable);
                }
                replans += 1;
                replace_session_plan(
                    &mut plan,
                    session_keyring,
                    rng,
                    now_unix,
                    config.session_absolute_secs,
                    country.as_deref(),
                )?;
            }
        }
    }
}

/// Request-path limits: the request and outbox email buckets, checked as one
/// concurrent batch — with a network-backed limiter each check is a round
/// trip, so sequential awaits would serialize four of them per request.
async fn request_and_outbox_limits_deny<Limiter: RateLimiter>(
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

async fn consume_limits_deny<Limiter: RateLimiter>(
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

/// Run every `(key, limit, window_secs)` check concurrently; report whether
/// any bucket denied.
///
/// Concurrency is an accounting choice as well as a latency one: every bucket
/// is consulted (and its counter advanced) even when another bucket denies,
/// where the previous sequential form stopped at the first denial. A denied
/// request therefore still consumes quota in every bucket, which only
/// tightens limiting. A dependency error takes precedence over a denial —
/// limiter state is unknown, so the request fails closed as unavailable.
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

fn mint_country(
    config: &MagicLinkServiceConfig,
    country: Option<&str>,
) -> Result<Option<String>, MagicLinkServiceError> {
    if !config.enforce_country {
        return Ok(country.map(str::to_owned));
    }
    let Some(country) = country else {
        return Err(MagicLinkServiceError::MagicLinkUnavailable);
    };
    validate_country(country)?;
    Ok(Some(country.to_owned()))
}

struct AuthenticationPlan {
    command: CommitMagicLinkAuthentication,
    session_cookie: Zeroizing<String>,
}

#[cfg(test)]
std::thread_local! {
    static VERIFIER_COMPARISON_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_verifier_comparison_count() {
    VERIFIER_COMPARISON_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn verifier_comparison_count() -> usize {
    VERIFIER_COMPARISON_COUNT.with(std::cell::Cell::get)
}

fn note_verifier_comparison() {
    #[cfg(test)]
    VERIFIER_COMPARISON_COUNT.with(|count| count.set(count.get() + 1));
}

fn perform_dummy_verifier_comparison(presented_verifier_hash: &VerifierHash) {
    let opaque = core::hint::black_box(presented_verifier_hash);
    let result = opaque.matches_hash_constant_time(presented_verifier_hash);
    let _ = core::hint::black_box(result);
}

fn plan_user<Rng: RngCore + CryptoRng + ?Sized>(
    user: Option<UserRecord>,
    expected_email: &dd_magic_link_core::NormalizedEmail,
    rng: &mut Rng,
) -> Result<MagicLinkAuthenticationUser, MagicLinkServiceError> {
    if let Some(user) = user {
        if user.email != *expected_email || user.disabled {
            return Err(MagicLinkServiceError::MagicLinkUnavailable);
        }
        return Ok(MagicLinkAuthenticationUser::Existing {
            user_id: user.user_id,
        });
    }

    Ok(MagicLinkAuthenticationUser::Create {
        user_id: generate_user_id(rng)?,
    })
}

/// The user id and whether the account was created, derived from the planned
/// user branch — the single source of truth, so no parallel state can drift.
fn user_outcome(user: &MagicLinkAuthenticationUser) -> (UserId, bool) {
    match user {
        MagicLinkAuthenticationUser::Existing { user_id } => (user_id.clone(), false),
        MagicLinkAuthenticationUser::Create { user_id } => (user_id.clone(), true),
    }
}

fn authentication_expectation(
    selector_lookup: &LookupHmac,
    candidate: &MagicLinkAuthenticationCandidate,
) -> MagicLinkAuthenticationExpectation {
    MagicLinkAuthenticationExpectation {
        selector_lookup_hmac: selector_lookup.clone(),
        email: candidate.email.clone(),
        expires_at_unix: candidate.expires_at_unix,
        terms_version: candidate.terms_version.clone(),
        privacy_version: candidate.privacy_version.clone(),
        consented_at_unix: candidate.consented_at_unix,
    }
}

/// Freshly generated per-attempt session material, shared by the initial plan
/// and every SessionConflict replan so the two paths cannot drift.
struct SessionPlanParts {
    session_id: SessionId,
    session_expires_at_unix: u64,
    session_cookie: Zeroizing<String>,
    attempt_id: AuthenticationAttemptId,
}

fn new_session_plan_parts<Rng: RngCore + CryptoRng>(
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    now_unix: u64,
    session_absolute_secs: u64,
    country: Option<&str>,
) -> Result<SessionPlanParts, MagicLinkServiceError> {
    let session_id = generate_session_id(rng)?;
    let session_expires_at_unix = now_unix
        .checked_add(session_absolute_secs)
        .ok_or(MagicLinkServiceError::Internal)?;
    let session_cookie = Zeroizing::new(mint_session_cookie(
        session_keyring,
        rng,
        &session_id,
        now_unix,
        country,
    )?);
    let attempt_id = generate_authentication_attempt_id(rng)?;
    Ok(SessionPlanParts {
        session_id,
        session_expires_at_unix,
        session_cookie,
        attempt_id,
    })
}

fn build_initial_authentication_plan<Rng: RngCore + CryptoRng>(
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    magic_link: MagicLinkAuthenticationExpectation,
    user: MagicLinkAuthenticationUser,
    now_unix: u64,
    session_absolute_secs: u64,
    country: Option<&str>,
) -> Result<AuthenticationPlan, MagicLinkServiceError> {
    let parts = new_session_plan_parts(
        session_keyring,
        rng,
        now_unix,
        session_absolute_secs,
        country,
    )?;
    Ok(AuthenticationPlan {
        command: CommitMagicLinkAuthentication {
            magic_link,
            now_unix,
            attempt_id: parts.attempt_id,
            user,
            session_id: parts.session_id,
            session_expires_at_unix: parts.session_expires_at_unix,
        },
        session_cookie: parts.session_cookie,
    })
}

fn replace_session_plan<Rng: RngCore + CryptoRng>(
    plan: &mut AuthenticationPlan,
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    now_unix: u64,
    session_absolute_secs: u64,
    country: Option<&str>,
) -> Result<(), MagicLinkServiceError> {
    let parts = new_session_plan_parts(
        session_keyring,
        rng,
        now_unix,
        session_absolute_secs,
        country,
    )?;
    plan.command.session_id = parts.session_id;
    plan.command.session_expires_at_unix = parts.session_expires_at_unix;
    plan.command.attempt_id = parts.attempt_id;
    plan.session_cookie = parts.session_cookie;
    Ok(())
}

async fn commit_with_dependency_retries<Authentication: MagicLinkAuthenticationRepository>(
    authentication: &Authentication,
    command: &CommitMagicLinkAuthentication,
) -> Result<(), CommitMagicLinkAuthenticationError> {
    for retry in 0..3 {
        match authentication
            .commit_magic_link_authentication(command)
            .await
        {
            Err(CommitMagicLinkAuthenticationError::DependencyUnavailable) if retry < 2 => {}
            result => return result,
        }
    }
    Err(CommitMagicLinkAuthenticationError::DependencyUnavailable)
}

fn mint_session_cookie<Rng>(
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    session_id: &SessionId,
    now_unix: u64,
    country: Option<&str>,
) -> Result<String, MagicLinkServiceError>
where
    Rng: RngCore + CryptoRng,
{
    let timestamp = u32::try_from(now_unix).map_err(|_| MagicLinkServiceError::Internal)?;
    let body = encode_session_cookie_body(session_id, country)?;
    mint_bound_cookie::<SessionCookie, _>(
        &body,
        session_keyring,
        rng,
        timestamp,
        timestamp,
        now_unix,
    )
    .map_err(MagicLinkServiceError::from)
}

/// Draw `BYTES` random bytes and render `{prefix}_{lowercase hex}` — the
/// canonical id shape the typed wrappers' service-built constructors expect.
fn generate_prefixed_hex_id<R: RngCore + CryptoRng + ?Sized, const BYTES: usize>(
    rng: &mut R,
    prefix: &str,
) -> Result<String, MagicLinkServiceError> {
    let mut bytes = [0u8; BYTES];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| MagicLinkServiceError::Unavailable)?;
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}

fn generate_user_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<UserId, MagicLinkServiceError> {
    Ok(UserId::from_service_built(
        generate_prefixed_hex_id::<_, 16>(rng, "usr")?,
    ))
}

fn generate_session_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<SessionId, MagicLinkServiceError> {
    Ok(SessionId::from_service_built(generate_prefixed_hex_id::<
        _,
        32,
    >(rng, "sid")?))
}

fn generate_authentication_attempt_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<AuthenticationAttemptId, MagicLinkServiceError> {
    Ok(AuthenticationAttemptId::from_service_built(
        generate_prefixed_hex_id::<_, 16>(rng, "aid")?,
    ))
}

fn map_dependency_error(error: DependencyError) -> MagicLinkServiceError {
    MagicLinkServiceError::from(error)
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

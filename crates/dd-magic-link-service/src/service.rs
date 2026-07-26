//! Request and consume orchestration.
//!
//! Proof-of-work is intentionally outside this service. HTTP adapters or
//! consuming applications may require and validate a PoW token before calling
//! these methods, but the magic-link service owns only magic-link, user,
//! session, limiter, outbox, clock, and randomness policy.

use dd_auth_token_core::cookie::mint_bound_cookie;
use dd_auth_token_core::keyring::{KeyRing, SessionCookie};
use dd_magic_link_core::{
    LookupHmacKey, MagicLinkToken, email_lookup_hmac, selector_lookup_hmac, verifier_hash,
};
use rand_core::{CryptoRng, RngCore};

use crate::config::MagicLinkServiceConfig;
use crate::error::{ConsumeMagicLinkError, DependencyError, MagicLinkServiceError};
use crate::session_body::encode_session_cookie_body;
use crate::traits::{
    Clock, MagicLinkOutbox, MagicLinkRepository, RateLimitDecision, RateLimiter, SessionRepository,
    UserRepository,
};
use crate::types::{
    ClientKey, ConsumeMagicLinkCommand, ConsumeMagicLinkOutcome, ConsumedMagicLink, MagicLinkEmail,
    MagicLinkRecord, RateLimitKey, RequestMagicLinkCommand, RequestMagicLinkOutcome, SessionId,
    SessionRecord, UserId, validate_country,
};

/// Request-flow-only service. It does not require user/session repositories or a
/// session-cookie keyring.
pub struct MagicLinkRequestService<'a, MagicLinks, Limiter, Outbox, ServiceClock, Rng> {
    magic_links: &'a MagicLinks,
    limiter: &'a Limiter,
    outbox: &'a Outbox,
    clock: &'a ServiceClock,
    rng: &'a mut Rng,
    lookup_hmac_key: &'a LookupHmacKey,
    config: MagicLinkServiceConfig,
}

/// Constructor inputs for [`MagicLinkRequestService`].
pub struct MagicLinkRequestServiceInputs<'a, MagicLinks, Limiter, Outbox, ServiceClock, Rng> {
    pub magic_links: &'a MagicLinks,
    pub limiter: &'a Limiter,
    pub outbox: &'a Outbox,
    pub clock: &'a ServiceClock,
    pub rng: &'a mut Rng,
    pub lookup_hmac_key: &'a LookupHmacKey,
    pub config: MagicLinkServiceConfig,
}

impl<'a, MagicLinks, Limiter, Outbox, ServiceClock, Rng>
    MagicLinkRequestService<'a, MagicLinks, Limiter, Outbox, ServiceClock, Rng>
{
    #[must_use]
    pub fn new(
        inputs: MagicLinkRequestServiceInputs<'a, MagicLinks, Limiter, Outbox, ServiceClock, Rng>,
    ) -> Self {
        Self {
            magic_links: inputs.magic_links,
            limiter: inputs.limiter,
            outbox: inputs.outbox,
            clock: inputs.clock,
            rng: inputs.rng,
            lookup_hmac_key: inputs.lookup_hmac_key,
            config: inputs.config,
        }
    }
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
    pub fn request_magic_link(
        &mut self,
        command: RequestMagicLinkCommand,
    ) -> Result<RequestMagicLinkOutcome, MagicLinkServiceError> {
        if !command.terms_accepted() || !command.privacy_accepted() {
            return Err(MagicLinkServiceError::BadRequest);
        }

        let now_unix = self.clock.now_unix()?;
        let expires_at_unix = now_unix
            .checked_add(self.config.magic_link_ttl_secs)
            .ok_or(MagicLinkServiceError::Internal)?;
        let email_lookup = email_lookup_hmac(self.lookup_hmac_key, command.email())?;

        if request_limits_deny(
            self.limiter,
            &self.config,
            email_lookup.as_storage_value(),
            command.client_key(),
            now_unix,
        )? {
            return Ok(RequestMagicLinkOutcome);
        }
        if outbox_limits_deny(
            self.limiter,
            &self.config,
            email_lookup.as_storage_value(),
            now_unix,
        )? {
            return Ok(RequestMagicLinkOutcome);
        }

        let token = MagicLinkToken::generate(self.rng)?;
        let selector_lookup = selector_lookup_hmac(self.lookup_hmac_key, token.selector())?;
        let verifier_hash = verifier_hash(self.lookup_hmac_key, token.verifier())?;

        let record = MagicLinkRecord {
            selector_lookup_hmac: selector_lookup,
            email: command.email().clone(),
            user_id: None,
            verifier_hash,
            expires_at_unix,
            consumed_at_unix: None,
            terms_version: self.config.terms_version.clone(),
            privacy_version: self.config.privacy_version.clone(),
            consented_at_unix: now_unix,
        };

        self.magic_links
            .put_magic_link_if_absent(record)
            .map_err(map_dependency_error)?;
        self.outbox
            .enqueue_magic_link(MagicLinkEmail {
                email: command.email().clone(),
                token,
                locale: command.locale(),
                expires_at_unix,
            })
            .map_err(map_dependency_error)?;

        Ok(RequestMagicLinkOutcome)
    }
}

/// Consume-flow-only service. It does not require an outbox.
pub struct MagicLinkConsumeService<'a, MagicLinks, Users, Sessions, Limiter, ServiceClock, Rng> {
    magic_links: &'a MagicLinks,
    users: &'a Users,
    sessions: &'a Sessions,
    limiter: &'a Limiter,
    clock: &'a ServiceClock,
    rng: &'a mut Rng,
    lookup_hmac_key: &'a LookupHmacKey,
    session_keyring: &'a KeyRing<SessionCookie>,
    config: MagicLinkServiceConfig,
}

/// Constructor inputs for [`MagicLinkConsumeService`].
pub struct MagicLinkConsumeServiceInputs<
    'a,
    MagicLinks,
    Users,
    Sessions,
    Limiter,
    ServiceClock,
    Rng,
> {
    pub magic_links: &'a MagicLinks,
    pub users: &'a Users,
    pub sessions: &'a Sessions,
    pub limiter: &'a Limiter,
    pub clock: &'a ServiceClock,
    pub rng: &'a mut Rng,
    pub lookup_hmac_key: &'a LookupHmacKey,
    pub session_keyring: &'a KeyRing<SessionCookie>,
    pub config: MagicLinkServiceConfig,
}

impl<'a, MagicLinks, Users, Sessions, Limiter, ServiceClock, Rng>
    MagicLinkConsumeService<'a, MagicLinks, Users, Sessions, Limiter, ServiceClock, Rng>
{
    #[must_use]
    pub fn new(
        inputs: MagicLinkConsumeServiceInputs<
            'a,
            MagicLinks,
            Users,
            Sessions,
            Limiter,
            ServiceClock,
            Rng,
        >,
    ) -> Self {
        Self {
            magic_links: inputs.magic_links,
            users: inputs.users,
            sessions: inputs.sessions,
            limiter: inputs.limiter,
            clock: inputs.clock,
            rng: inputs.rng,
            lookup_hmac_key: inputs.lookup_hmac_key,
            session_keyring: inputs.session_keyring,
            config: inputs.config,
        }
    }
}

impl<MagicLinks, Users, Sessions, Limiter, ServiceClock, Rng>
    MagicLinkConsumeService<'_, MagicLinks, Users, Sessions, Limiter, ServiceClock, Rng>
where
    MagicLinks: MagicLinkRepository,
    Users: UserRepository,
    Sessions: SessionRepository,
    Limiter: RateLimiter,
    ServiceClock: Clock,
    Rng: RngCore + CryptoRng,
{
    /// Parse and consume a raw token. Malformed tokens are rate-limited by client
    /// key when supplied, then collapsed into `MagicLinkUnavailable`.
    pub fn consume_magic_link_token(
        &mut self,
        token: &str,
        client_key: Option<ClientKey>,
        request_country: Option<String>,
    ) -> Result<ConsumeMagicLinkOutcome, MagicLinkServiceError> {
        let now_unix = self.clock.now_unix()?;
        let parsed = match MagicLinkToken::parse(token) {
            Ok(token) => token,
            Err(_) => {
                if let Some(client_key) = client_key.as_ref() {
                    let _ = malformed_consume_limit_denied(
                        self.limiter,
                        &self.config,
                        client_key,
                        now_unix,
                    )?;
                }
                return Err(MagicLinkServiceError::MagicLinkUnavailable);
            }
        };
        let command = ConsumeMagicLinkCommand::new(parsed, client_key, request_country)?;
        self.consume_magic_link(command)
    }

    /// Consume a parsed magic-link token, atomically burning the stored challenge
    /// before creating a session. With generic repositories the session write is
    /// not part of the consume transition; if session creation fails after a
    /// successful consume, the bearer link remains burned. Adapters with
    /// transactional storage may make the consume+session transition stronger.
    pub fn consume_magic_link(
        &mut self,
        command: ConsumeMagicLinkCommand,
    ) -> Result<ConsumeMagicLinkOutcome, MagicLinkServiceError> {
        let country = mint_country(&self.config, command.request_country())?;
        let now_unix = self.clock.now_unix()?;
        let selector_lookup =
            selector_lookup_hmac(self.lookup_hmac_key, command.token().selector())?;

        if consume_limits_deny(
            self.limiter,
            &self.config,
            selector_lookup.as_storage_value(),
            command.client_key(),
            now_unix,
        )? {
            return Err(MagicLinkServiceError::MagicLinkUnavailable);
        }

        let verifier_hash = verifier_hash(self.lookup_hmac_key, command.token().verifier())?;
        let consumed = self
            .magic_links
            .consume_magic_link(&selector_lookup, &verifier_hash, now_unix)
            .map_err(map_consume_error)?;

        validate_consumed_magic_link(&self.config, &consumed)?;
        let (user_id, user_created) = ensure_user(self.users, self.rng, &consumed)?;
        let session_id =
            create_session(self.sessions, self.rng, &user_id, &consumed.email, now_unix)?;
        let session_cookie = mint_session_cookie(
            self.session_keyring,
            self.rng,
            &session_id,
            now_unix,
            country.as_deref(),
        )?;

        Ok(ConsumeMagicLinkOutcome {
            session_cookie,
            user_id,
            session_id,
            user_created,
            country,
        })
    }

    /// Revoke a server-side session by id.
    pub fn revoke_session(&self, session_id: &SessionId) -> Result<(), MagicLinkServiceError> {
        let now_unix = self.clock.now_unix()?;
        self.sessions
            .revoke_session(session_id, now_unix)
            .map_err(map_dependency_error)
    }
}

fn request_limits_deny<Limiter: RateLimiter>(
    limiter: &Limiter,
    config: &MagicLinkServiceConfig,
    email_lookup: &str,
    client_key: Option<&ClientKey>,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let limits = &config.rate_limits;
    let email_short = format!("magic-link:request:email:short:{email_lookup}");
    if limit_denied(
        limiter,
        &email_short,
        limits.request_email_short_limit,
        limits.request_email_short_window_secs,
        now_unix,
    )? {
        return Ok(true);
    }
    let email_daily = format!("magic-link:request:email:daily:{email_lookup}");
    if limit_denied(
        limiter,
        &email_daily,
        limits.request_email_daily_limit,
        limits.request_email_daily_window_secs,
        now_unix,
    )? {
        return Ok(true);
    }
    if let Some(client_key) = client_key {
        let client_short = format!("magic-link:request:client:short:{}", client_key.as_str());
        if limit_denied(
            limiter,
            &client_short,
            limits.request_client_short_limit,
            limits.request_client_short_window_secs,
            now_unix,
        )? {
            return Ok(true);
        }
        let client_hourly = format!("magic-link:request:client:hourly:{}", client_key.as_str());
        if limit_denied(
            limiter,
            &client_hourly,
            limits.request_client_hourly_limit,
            limits.request_client_hourly_window_secs,
            now_unix,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn outbox_limits_deny<Limiter: RateLimiter>(
    limiter: &Limiter,
    config: &MagicLinkServiceConfig,
    email_lookup: &str,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let limits = &config.rate_limits;
    let hourly = format!("magic-link:outbox:email:hourly:{email_lookup}");
    if limit_denied(
        limiter,
        &hourly,
        limits.outbox_email_hourly_limit,
        limits.outbox_email_hourly_window_secs,
        now_unix,
    )? {
        return Ok(true);
    }
    let daily = format!("magic-link:outbox:email:daily:{email_lookup}");
    limit_denied(
        limiter,
        &daily,
        limits.outbox_email_daily_limit,
        limits.outbox_email_daily_window_secs,
        now_unix,
    )
}

fn consume_limits_deny<Limiter: RateLimiter>(
    limiter: &Limiter,
    config: &MagicLinkServiceConfig,
    selector_lookup: &str,
    client_key: Option<&ClientKey>,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let limits = &config.rate_limits;
    let selector_key = format!("magic-link:consume:selector:{selector_lookup}");
    if limit_denied(
        limiter,
        &selector_key,
        limits.consume_selector_limit,
        config.magic_link_ttl_secs,
        now_unix,
    )? {
        return Ok(true);
    }
    if let Some(client_key) = client_key {
        let client_short = format!("magic-link:consume:client:short:{}", client_key.as_str());
        if limit_denied(
            limiter,
            &client_short,
            limits.consume_client_short_limit,
            limits.consume_client_short_window_secs,
            now_unix,
        )? {
            return Ok(true);
        }
        let client_hourly = format!("magic-link:consume:client:hourly:{}", client_key.as_str());
        if limit_denied(
            limiter,
            &client_hourly,
            limits.consume_client_hourly_limit,
            limits.consume_client_hourly_window_secs,
            now_unix,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn malformed_consume_limit_denied<Limiter: RateLimiter>(
    limiter: &Limiter,
    config: &MagicLinkServiceConfig,
    client_key: &ClientKey,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let key = format!("magic-link:consume:malformed:{}", client_key.as_str());
    limit_denied(
        limiter,
        &key,
        config.rate_limits.malformed_consume_client_limit,
        config.rate_limits.malformed_consume_client_window_secs,
        now_unix,
    )
}

fn limit_denied<Limiter: RateLimiter>(
    limiter: &Limiter,
    key: &str,
    limit: u32,
    window_secs: u64,
    now_unix: u64,
) -> Result<bool, MagicLinkServiceError> {
    let key = RateLimitKey::parse(key)?;
    let decision = limiter
        .check_rate_limit(&key, limit, window_secs, now_unix)
        .map_err(map_dependency_error)?;
    Ok(decision == RateLimitDecision::Denied)
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

fn validate_consumed_magic_link(
    config: &MagicLinkServiceConfig,
    consumed: &ConsumedMagicLink,
) -> Result<(), MagicLinkServiceError> {
    if consumed.terms_version != config.terms_version
        || consumed.privacy_version != config.privacy_version
        || consumed.consented_at_unix == 0
    {
        return Err(MagicLinkServiceError::MagicLinkUnavailable);
    }
    Ok(())
}

fn ensure_user<Users, Rng>(
    users: &Users,
    rng: &mut Rng,
    consumed: &ConsumedMagicLink,
) -> Result<(UserId, bool), MagicLinkServiceError>
where
    Users: UserRepository,
    Rng: RngCore + CryptoRng,
{
    if let Some(existing) = users
        .find_user_by_email(&consumed.email)
        .map_err(map_dependency_error)?
    {
        if existing.disabled {
            return Err(MagicLinkServiceError::MagicLinkUnavailable);
        }
        return Ok((existing.user_id, false));
    }

    let user_id = generate_user_id(rng)?;
    let user = crate::types::UserRecord {
        user_id: user_id.clone(),
        email: consumed.email.clone(),
        disabled: false,
        terms_version: Some(consumed.terms_version.clone()),
        privacy_version: Some(consumed.privacy_version.clone()),
        consented_at_unix: Some(consumed.consented_at_unix),
    };

    match users.put_user_if_absent(user) {
        Ok(()) => Ok((user_id, true)),
        Err(DependencyError::ConditionalWriteFailed) => {
            let Some(existing) = users
                .find_user_by_email(&consumed.email)
                .map_err(map_dependency_error)?
            else {
                return Err(MagicLinkServiceError::Unavailable);
            };
            if existing.disabled {
                return Err(MagicLinkServiceError::MagicLinkUnavailable);
            }
            Ok((existing.user_id, false))
        }
        Err(error) => Err(map_dependency_error(error)),
    }
}

fn create_session<Sessions, Rng>(
    sessions: &Sessions,
    rng: &mut Rng,
    user_id: &UserId,
    email: &dd_magic_link_core::NormalizedEmail,
    now_unix: u64,
) -> Result<SessionId, MagicLinkServiceError>
where
    Sessions: SessionRepository,
    Rng: RngCore + CryptoRng,
{
    let session_id = generate_session_id(rng)?;
    let record = SessionRecord {
        session_id: session_id.clone(),
        user_id: user_id.clone(),
        email: email.clone(),
        created_at_unix: now_unix,
        revoked_at_unix: None,
    };
    sessions
        .put_session_if_absent(record)
        .map_err(map_dependency_error)?;
    Ok(session_id)
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

fn generate_user_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<UserId, MagicLinkServiceError> {
    let mut bytes = [0u8; 16];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| MagicLinkServiceError::Unavailable)?;
    UserId::parse(&format!("usr_{}", hex::encode(bytes)))
}

fn generate_session_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<SessionId, MagicLinkServiceError> {
    let mut bytes = [0u8; 32];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| MagicLinkServiceError::Unavailable)?;
    SessionId::parse(&format!("sid_{}", hex::encode(bytes)))
}

fn map_dependency_error(error: DependencyError) -> MagicLinkServiceError {
    MagicLinkServiceError::from(error)
}

fn map_consume_error(error: ConsumeMagicLinkError) -> MagicLinkServiceError {
    match error {
        ConsumeMagicLinkError::Unavailable => MagicLinkServiceError::MagicLinkUnavailable,
        ConsumeMagicLinkError::DependencyUnavailable => MagicLinkServiceError::Unavailable,
        ConsumeMagicLinkError::Internal => MagicLinkServiceError::Internal,
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

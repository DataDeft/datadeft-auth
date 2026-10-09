//! Scanner-safe landing, explicit confirmation, revocation, and candidate checks.

use datadeft_auth_token_core::keyring::KeyRing;
use datadeft_magic_link_core::confirm_cookie::{
    MagicLinkConfirmBindings, MagicLinkConfirmCookie, mint_magic_link_confirm,
    verify_magic_link_confirm,
};
use datadeft_magic_link_core::{
    LookupHmac, LookupHmacKey, MagicLinkToken, VerifierHash, confirm_account_binding,
    confirm_selector_binding, confirm_verifier_binding, email_lookup_hmac, selector_lookup_hmac,
    selector_lookup_hmac_from_confirm_binding, verifier_hash, verifier_hash_from_confirm_binding,
};
use rand_core::{CryptoRng, RngCore};

use crate::config::MagicLinkServiceConfig;
use crate::error::{MagicLinkFlowError, MagicLinkServiceError};
use crate::traits::{Clock, MagicLinkAuthenticationRepository, RateLimiter, SessionRepository};
use crate::types::{
    BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, MagicLinkAccountIdentity, MagicLinkAuthenticationCandidate,
    SessionCookie, SessionId,
};

use super::commit::{authenticate_scanner_flow, mint_country};
use super::limits::{consume_limits_deny, landing_limits_deny};
use super::*;

/// Canonical scanner-safe landing, confirmation, and revocation service.
/// Construct with a struct literal. Every field is a required dependency.
pub struct MagicLinkFlowService<'a, Authentication, Sessions, Limiter, ServiceClock, Rng> {
    pub authentication: &'a Authentication,
    pub sessions: &'a Sessions,
    pub limiter: &'a Limiter,
    pub clock: &'a ServiceClock,
    pub rng: &'a mut Rng,
    pub lookup_hmac_key: &'a LookupHmacKey,
    /// Previous lookup HMAC key during a rotation window, or `None`. Landing
    /// retries a selector miss with it, so links issued just before a rotation
    /// stay usable. New links and account bindings always use
    /// `lookup_hmac_key`. Drop it once the magic-link TTL has passed.
    pub previous_lookup_hmac_key: Option<&'a LookupHmacKey>,
    pub confirm_keyring: &'a KeyRing<MagicLinkConfirmCookie>,
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

        let mut found = landing_candidate(
            self.authentication,
            self.lookup_hmac_key,
            selector_lookup,
            &token,
        )
        .await?;
        // Rotation window: a link minted under the previous lookup key is
        // stored under that key's selector HMAC and verifier hash. The confirm
        // bindings carry these values, so confirmation needs no key fallback.
        if found.2.is_none()
            && let Some(previous_key) = self.previous_lookup_hmac_key
        {
            let previous_selector = selector_lookup_hmac(previous_key, token.selector())
                .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
            found = landing_candidate(self.authentication, previous_key, previous_selector, &token)
                .await?;
        }
        let (selector_lookup, presented_verifier_hash, candidate) = found;
        let candidate =
            validate_scanner_candidate(&self.config, candidate, &presented_verifier_hash, now_unix)
                .map_err(MagicLinkFlowError::from_public_error)?;

        let email_lookup = email_lookup_hmac(self.lookup_hmac_key, &candidate.email)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let selector_binding = confirm_selector_binding(&selector_lookup)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let verifier_binding = confirm_verifier_binding(&presented_verifier_hash)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let account_binding = confirm_account_binding(&email_lookup)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;

        let configured_expiry = now_unix
            .checked_add(self.config.magic_link_flow_ttl_secs)
            .ok_or_else(|| flow_error(MagicLinkServiceError::Internal))?;
        let confirm_expiry = candidate.expires_at_unix.min(configured_expiry);
        if confirm_expiry <= now_unix {
            return Err(flow_error(MagicLinkServiceError::MagicLinkUnavailable));
        }
        let confirm_expiry_u32 = u32::try_from(confirm_expiry)
            .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
        let cookie_max_age_secs = confirm_expiry
            .checked_sub(now_unix)
            .ok_or_else(|| flow_error(MagicLinkServiceError::Internal))?;
        let account_identity = MagicLinkAccountIdentity::from_normalized_email(&candidate.email);
        let flow = mint_magic_link_confirm(
            MagicLinkConfirmBindings::new(
                selector_binding,
                verifier_binding,
                account_binding,
                confirm_expiry_u32,
            ),
            self.confirm_keyring,
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

        let verified = verify_magic_link_confirm(
            command.confirm_cookie(),
            command.confirmation(),
            self.confirm_keyring,
            now_unix,
            self.config.magic_link_flow_ttl_secs,
        )
        .map_err(|_| flow_error(MagicLinkServiceError::MagicLinkUnavailable))?;

        let selector_lookup = selector_lookup_hmac_from_confirm_binding(verified.selector());
        let presented_verifier_hash = verifier_hash_from_confirm_binding(verified.verifier());
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

/// One landing lookup under `key`: the presented verifier hash and the record
/// stored at `selector_lookup` (already derived under the same key).
async fn landing_candidate<Authentication: MagicLinkAuthenticationRepository>(
    authentication: &Authentication,
    key: &LookupHmacKey,
    selector_lookup: LookupHmac,
    token: &MagicLinkToken,
) -> Result<
    (
        LookupHmac,
        VerifierHash,
        Option<MagicLinkAuthenticationCandidate>,
    ),
    MagicLinkFlowError,
> {
    let presented_verifier_hash = verifier_hash(key, token.verifier())
        .map_err(|_| flow_error(MagicLinkServiceError::Internal))?;
    let candidate = authentication
        .find_magic_link_for_authentication(&selector_lookup)
        .await
        .map_err(map_dependency_error)
        .map_err(MagicLinkFlowError::from_public_error)?;
    Ok((selector_lookup, presented_verifier_hash, candidate))
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

pub(super) fn compare_candidate_verifier(
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

pub(super) fn validate_scanner_candidate_state(
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

#[cfg(test)]
std::thread_local! {
    static VERIFIER_COMPARISON_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_verifier_comparison_count() {
    VERIFIER_COMPARISON_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn verifier_comparison_count() -> usize {
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

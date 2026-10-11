//! Requesting a magic link: validation, limits, storage, and the outbox.

use datadeft_magic_link_core::{
    LookupHmacKey, MagicLinkToken, email_lookup_hmac, selector_lookup_hmac, verifier_hash,
};
use rand_core::{CryptoRng, RngCore};

use crate::config::MagicLinkServiceConfig;
use crate::error::{DependencyError, MagicLinkServiceError};
use crate::traits::{Clock, MagicLinkOutbox, MagicLinkRepository, RateLimiter};
use crate::types::{
    MagicLinkEmail, MagicLinkRecord, RequestMagicLinkCommand, RequestMagicLinkOutcome,
};

use super::limits::request_and_outbox_limits_deny;
use super::*;

/// Request-flow-only service. It does not require user/session repositories or a
/// session-cookie keyring. Construct with a struct literal. Every field is a
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
    /// Request a magic link. A throttled request returns
    /// [`RequestMagicLinkOutcome::Throttled`] for the app's logs and metrics;
    /// the public response must stay the same generic accepted answer as a
    /// send, so callers cannot enumerate accounts or throttling policy.
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

        if let Some(throttle) = request_and_outbox_limits_deny(
            self.limiter,
            &self.config,
            email_lookup.as_storage_value(),
            now_unix,
        )
        .await?
        {
            return Ok(RequestMagicLinkOutcome::Throttled(throttle));
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
                // Resolved here, passed on, never stored.
                locale: self
                    .config
                    .locales
                    .as_ref()
                    .map(|locales| locales.resolve(command.locale_hint())),
            })
            .await
            .map_err(map_outbox_error)?;

        Ok(RequestMagicLinkOutcome::Sent)
    }
}

/// An outbox failure keeps its own value, so logs tell the email provider
/// apart from the store. Internal faults stay internal.
fn map_outbox_error(error: DependencyError) -> MagicLinkServiceError {
    match map_dependency_error(error) {
        MagicLinkServiceError::Unavailable => MagicLinkServiceError::OutboxUnavailable,
        other => other,
    }
}

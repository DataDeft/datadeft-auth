//! Initialized application state: the configured service policy, loaded
//! keyrings and the backing store/outbox pair. Built once per connection by
//! the init operation; jobs share it immutably.
mod handlers;

pub(crate) use handlers::handle;

use std::time::{SystemTime, UNIX_EPOCH};

use datadeft_magic_link_aws::{FakeDynamoDbAuthStore, FakeMagicLinkOutbox, LoadedAuthSecrets};
use datadeft_magic_link_service::{
    AccountDisplay, Clock, DependencyError, KeyRing, LocaleAllowlist, LookupHmacKey,
    MagicLinkConfirmCookie, MagicLinkFlowService, MagicLinkServiceConfig, SessionCookie,
};
use rand_core::OsRng;

use crate::protocol::{AccountDisplayPayload, ErrorCode, InitPayload, Mode};

/// Bodies carry this marker where the rendered magic-link URL belongs.
const URL_MARKER: &str = "{magic_link_url}";

pub struct App {
    store: FakeDynamoDbAuthStore,
    outbox: FakeMagicLinkOutbox,
    config: MagicLinkServiceConfig,
    lookup_hmac_key: LookupHmacKey,
    previous_lookup_hmac_key: Option<LookupHmacKey>,
    confirm_keyring: KeyRing<MagicLinkConfirmCookie>,
    session_keyring: KeyRing<SessionCookie>,
    email: EmailTemplate,
}

/// Application-supplied email content, validated at initialization.
pub(crate) struct EmailTemplate {
    pub(crate) link_base_url: String,
}

impl EmailTemplate {
    /// Validate the full template at initialization so a broken configuration
    /// fails before any traffic. The fake outbox stores unrendered emails, so
    /// only the URL base is kept; the SES renderer will own the full content.
    fn validate(payload: crate::protocol::EmailTemplatePayload) -> Result<Self, ErrorCode> {
        let base_ok = !payload.link_base_url.is_empty()
            && !payload
                .link_base_url
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            && !payload.link_base_url.contains(['{', '}']);
        let bodies_ok = !payload.subject.trim().is_empty()
            && payload.text.contains(URL_MARKER)
            && payload
                .html
                .as_deref()
                .is_none_or(|html| html.contains(URL_MARKER));
        if base_ok && bodies_ok {
            Ok(Self {
                link_base_url: payload.link_base_url,
            })
        } else {
            Err(ErrorCode::Configuration)
        }
    }

    pub(crate) fn magic_link_url(&self, token: &str) -> String {
        format!("{}{token}", self.link_base_url)
    }
}

impl App {
    /// Build the configured state, failing closed with one opaque
    /// configuration error; the application fixes its config, never retries.
    pub fn initialize(payload: InitPayload) -> Result<Self, ErrorCode> {
        // Staged: refused until the AWS wiring lands in this PR.
        if payload.mode == Mode::Aws {
            return Err(ErrorCode::Configuration);
        }
        let service = payload.service;
        let mut config =
            MagicLinkServiceConfig::new(service.terms_version, service.privacy_version);
        if let Some(value) = service.magic_link_ttl_secs {
            config.magic_link_ttl_secs = value;
        }
        if let Some(value) = service.magic_link_flow_ttl_secs {
            config.magic_link_flow_ttl_secs = value;
        }
        if let Some(value) = service.session_idle_secs {
            config.session_idle_secs = value;
        }
        if let Some(value) = service.session_absolute_secs {
            config.session_absolute_secs = value;
        }
        config.enforce_country = service.enforce_country;
        if let Some(display) = service.account_display {
            config.account_display = match display {
                AccountDisplayPayload::Masked => AccountDisplay::Masked,
                AccountDisplayPayload::Full => AccountDisplay::Full,
            };
        }
        match (&service.default_locale, service.locales.is_empty()) {
            (Some(default), _) => {
                let others = service.locales.iter().map(String::as_str);
                config.locales = Some(
                    LocaleAllowlist::new(default, others).map_err(|_| ErrorCode::Configuration)?,
                );
            }
            (None, true) => {}
            (None, false) => return Err(ErrorCode::Configuration),
        }
        config.validate().map_err(|_| ErrorCode::Configuration)?;

        let email = EmailTemplate::validate(payload.email)?;
        let secrets = LoadedAuthSecrets::from_json(
            &payload.secrets.active_document,
            payload.secrets.previous_document.as_deref(),
        )
        .map_err(|_| ErrorCode::Configuration)?;
        let LoadedAuthSecrets {
            lookup_hmac_key,
            storage_hmac_key,
            previous_lookup_hmac_key,
            confirm_keyring,
            session_keyring,
            ..
        } = secrets;

        Ok(Self {
            // The fake store keys records with the active key only; the
            // storage-side previous-key fallback is a DynamoDB adapter
            // behavior exercised by that crate's rotation tests.
            store: FakeDynamoDbAuthStore::new(storage_hmac_key),
            outbox: FakeMagicLinkOutbox::default(),
            config,
            lookup_hmac_key,
            previous_lookup_hmac_key,
            confirm_keyring,
            session_keyring,
            email,
        })
    }

    fn flow_service<'a>(
        &'a self,
        rng: &'a mut OsRng,
    ) -> MagicLinkFlowService<
        'a,
        FakeDynamoDbAuthStore,
        FakeDynamoDbAuthStore,
        FakeDynamoDbAuthStore,
        WallClock,
        OsRng,
    > {
        MagicLinkFlowService {
            authentication: &self.store,
            sessions: &self.store,
            limiter: &self.store,
            clock: &WallClock,
            rng,
            lookup_hmac_key: &self.lookup_hmac_key,
            previous_lookup_hmac_key: self.previous_lookup_hmac_key.as_ref(),
            confirm_keyring: &self.confirm_keyring,
            session_keyring: &self.session_keyring,
            config: self.config.clone(),
        }
    }
}

/// Wall clock supplied by this adapter; the library never reads one itself.
pub(crate) struct WallClock;

impl Clock for WallClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| DependencyError::Internal)
    }
}

#[cfg(test)]
#[path = "app/app_tests.rs"]
pub(crate) mod tests;

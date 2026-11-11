//! One handler per authenticated-state operation, generic over the backing
//! store and outbox. Handlers decode nothing and log nothing: they map typed
//! payloads through the service crates and return one exact result shape per
//! outcome class.
use datadeft_magic_link_service::{
    BeginMagicLinkLandingCommand, ConfirmMagicLinkFlowCommand, MagicLinkAuthenticationRepository,
    MagicLinkFlowError, MagicLinkOutbox, MagicLinkRepository, MagicLinkRequestService,
    MagicLinkServiceError, NormalizedEmail, RateLimiter, ReadMagicLinkFlowStateCommand,
    RequestMagicLinkCommand, SessionRepository, SessionValidationError, refresh_session_cookie,
    validate_session,
};
use rand_core::OsRng;

use super::{App, WallClock};
use crate::protocol::{
    Command, ConfirmPayload, ErrorCode, FlowStatePayload, LandingPayload, OutboxPeekPayload,
    RequestLinkPayload, ResultBody, SessionPayload,
};

impl<Store, Outbox> App<Store, Outbox>
where
    Store: MagicLinkRepository
        + MagicLinkAuthenticationRepository
        + SessionRepository
        + RateLimiter
        + Sync,
    Outbox: MagicLinkOutbox + Sync,
{
    /// Dispatch one authenticated-state command. Handshake, ping and init
    /// never reach this; the dispatcher owns them.
    pub(crate) async fn run(&self, command: Command) -> ResultBody {
        match command {
            Command::RequestLink(payload) => self.request_link(payload).await,
            Command::Landing(payload) => self.landing(payload).await,
            Command::FlowState(payload) => self.flow_state(payload).await,
            Command::Confirm(payload) => self.confirm(payload).await,
            Command::ValidateSession(payload) => self.validate(payload).await,
            Command::Logout(payload) => self.logout(payload).await,
            Command::FakeLastMagicLink(payload) => self.fake_last_magic_link(payload),
            Command::Handshake | Command::Ping | Command::Init(_) => error(ErrorCode::Internal),
        }
    }

    async fn request_link(&self, payload: RequestLinkPayload) -> ResultBody {
        let Ok(email) = NormalizedEmail::normalize(&payload.email) else {
            return error(ErrorCode::BadRequest);
        };
        let mut command =
            RequestMagicLinkCommand::new(email, payload.terms_accepted, payload.privacy_accepted);
        if let Some(locale) = &payload.locale {
            command = command.with_locale_hint(locale);
        }
        let mut rng = OsRng;
        let mut service = MagicLinkRequestService {
            magic_links: &self.store,
            limiter: &self.store,
            outbox: &self.outbox,
            clock: &WallClock,
            rng: &mut rng,
            lookup_hmac_key: &self.lookup_hmac_key,
            config: self.config.clone(),
        };
        match service.request_magic_link(command).await {
            Ok(outcome) => ResultBody::RequestLink {
                reason: outcome.reason(),
            },
            Err(failure) => service_error(failure),
        }
    }

    async fn landing(&self, payload: LandingPayload) -> ResultBody {
        let mut rng = OsRng;
        let command = BeginMagicLinkLandingCommand::new(payload.token);
        match self
            .flow_service(&mut rng)
            .begin_magic_link_landing(command)
            .await
        {
            Ok(outcome) => ResultBody::Landing {
                usable: true,
                confirm_cookie: Some(outcome.confirm_cookie_value().to_owned()),
                confirmation: Some(outcome.confirmation_value().to_owned()),
                account: Some(outcome.account_identity().as_str().to_owned()),
                cookie_max_age_secs: Some(outcome.cookie_max_age_secs()),
            },
            // The landing answer is uniform for every unusable link state.
            Err(failure) => match failure.public_error() {
                MagicLinkServiceError::BadRequest | MagicLinkServiceError::MagicLinkUnavailable => {
                    ResultBody::Landing {
                        usable: false,
                        confirm_cookie: None,
                        confirmation: None,
                        account: None,
                        cookie_max_age_secs: None,
                    }
                }
                other => service_error(other),
            },
        }
    }

    async fn flow_state(&self, payload: FlowStatePayload) -> ResultBody {
        let mut rng = OsRng;
        let command = ReadMagicLinkFlowStateCommand::new(payload.confirm_cookie);
        match self
            .flow_service(&mut rng)
            .read_magic_link_flow_state(command)
            .await
        {
            Ok(state) => ResultBody::FlowState {
                usable: true,
                account: Some(state.account_identity().as_str().to_owned()),
                confirmation: Some(state.confirmation_value().to_owned()),
            },
            Err(failure) => match failure.public_error() {
                MagicLinkServiceError::BadRequest | MagicLinkServiceError::MagicLinkUnavailable => {
                    ResultBody::FlowState {
                        usable: false,
                        account: None,
                        confirmation: None,
                    }
                }
                other => service_error(other),
            },
        }
    }

    async fn confirm(&self, payload: ConfirmPayload) -> ResultBody {
        let command = match ConfirmMagicLinkFlowCommand::new(
            payload.confirm_cookie,
            payload.confirmation,
            payload.country,
        ) {
            Ok(command) => command,
            Err(failure) => return flow_error(failure),
        };
        let mut rng = OsRng;
        match self
            .flow_service(&mut rng)
            .confirm_magic_link_flow(command)
            .await
        {
            Ok(outcome) => {
                let authentication = outcome.into_authentication();
                ResultBody::Confirm {
                    session_cookie: authentication.session_cookie_value().to_owned(),
                    user_id: authentication.user_id().as_str().to_owned(),
                    user_created: authentication.user_created(),
                    country: authentication.country().map(str::to_owned),
                }
            }
            Err(failure) => flow_error(failure),
        }
    }

    async fn validate(&self, payload: SessionPayload) -> ResultBody {
        match validate_session(
            &payload.session_cookie,
            payload.country.as_deref(),
            &self.session_keyring,
            &self.store,
            &WallClock,
            &self.config,
        )
        .await
        {
            Ok(validated) => {
                let mut rng = OsRng;
                match refresh_session_cookie(
                    &validated,
                    &self.session_keyring,
                    &mut rng,
                    &WallClock,
                    &self.config,
                ) {
                    Ok(refreshed) => ResultBody::ValidateSession {
                        valid: true,
                        user_id: Some(validated.session().user_id.as_str().to_owned()),
                        refreshed_cookie: refreshed
                            .map(|cookie| cookie.as_secret_value().to_owned()),
                    },
                    Err(failure) => session_error(failure),
                }
            }
            Err(SessionValidationError::InvalidSession) => ResultBody::ValidateSession {
                valid: false,
                user_id: None,
                refreshed_cookie: None,
            },
            Err(failure) => session_error(failure),
        }
    }

    async fn logout(&self, payload: SessionPayload) -> ResultBody {
        match validate_session(
            &payload.session_cookie,
            payload.country.as_deref(),
            &self.session_keyring,
            &self.store,
            &WallClock,
            &self.config,
        )
        .await
        {
            Ok(validated) => {
                let mut rng = OsRng;
                // Revoke server state first; the application clears its
                // cookie only after this reply.
                match self
                    .flow_service(&mut rng)
                    .revoke_session(&validated.session().session_id)
                    .await
                {
                    Ok(()) => ResultBody::Logout { revoked: true },
                    Err(failure) => service_error(failure),
                }
            }
            Err(SessionValidationError::InvalidSession) => ResultBody::Logout { revoked: false },
            Err(failure) => session_error(failure),
        }
    }

    /// Fake backends only: the newest outbox entry for an address, as the
    /// rendered landing URL. Exists for the package's own end-to-end tests.
    fn fake_last_magic_link(&self, payload: OutboxPeekPayload) -> ResultBody {
        let Some(outbox) = &self.dev_outbox else {
            return error(ErrorCode::Configuration);
        };
        let Ok(email) = NormalizedEmail::normalize(&payload.email) else {
            return error(ErrorCode::BadRequest);
        };
        match outbox.recorded() {
            Ok(entries) => match entries
                .into_iter()
                .rev()
                .find(|entry| entry.email.as_str() == email.as_str())
            {
                Some(entry) => ResultBody::FakeLastMagicLink {
                    found: true,
                    magic_link_url: Some(
                        self.email
                            .magic_link_url(entry.token.as_secret_value().as_str()),
                    ),
                    expires_at_unix: Some(entry.expires_at_unix),
                },
                None => ResultBody::FakeLastMagicLink {
                    found: false,
                    magic_link_url: None,
                    expires_at_unix: None,
                },
            },
            Err(_) => error(ErrorCode::Internal),
        }
    }
}

fn flow_error(failure: MagicLinkFlowError) -> ResultBody {
    service_error(failure.public_error())
}

fn service_error(failure: MagicLinkServiceError) -> ResultBody {
    error(match failure {
        MagicLinkServiceError::BadRequest => ErrorCode::BadRequest,
        MagicLinkServiceError::MagicLinkUnavailable => ErrorCode::Rejected,
        MagicLinkServiceError::Unavailable | MagicLinkServiceError::OutboxUnavailable => {
            ErrorCode::Unavailable
        }
        MagicLinkServiceError::Internal => ErrorCode::Internal,
    })
}

fn session_error(failure: SessionValidationError) -> ResultBody {
    error(match failure {
        // Stale-validation refusals cannot happen in one job; fail loud.
        SessionValidationError::InvalidSession | SessionValidationError::Internal => {
            ErrorCode::Internal
        }
        SessionValidationError::Unavailable => ErrorCode::Unavailable,
    })
}

fn error(code: ErrorCode) -> ResultBody {
    ResultBody::Error { code }
}

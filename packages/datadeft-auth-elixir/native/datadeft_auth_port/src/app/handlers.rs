//! One handler per authenticated-state operation. Handlers decode nothing
//! and log nothing: they map typed payloads through the service crates and
//! return one exact result shape per outcome class.
use datadeft_magic_link_service::{
    BeginMagicLinkLandingCommand, ConfirmMagicLinkFlowCommand, MagicLinkFlowError,
    MagicLinkRequestService, MagicLinkServiceError, NormalizedEmail, ReadMagicLinkFlowStateCommand,
    RequestMagicLinkCommand, SessionValidationError, refresh_session_cookie, validate_session,
};
use rand_core::OsRng;

use super::{App, WallClock};
use crate::protocol::{
    Command, ConfirmPayload, ErrorCode, FlowStatePayload, LandingPayload, OutboxPeekPayload,
    RequestLinkPayload, ResultBody, SessionPayload,
};

/// Dispatch one authenticated-state command. Handshake, ping and init never
/// reach this; the dispatcher owns them.
pub(crate) async fn handle(app: &App, command: Command) -> ResultBody {
    match command {
        Command::RequestLink(payload) => request_link(app, payload).await,
        Command::Landing(payload) => landing(app, payload).await,
        Command::FlowState(payload) => flow_state(app, payload).await,
        Command::Confirm(payload) => confirm(app, payload).await,
        Command::ValidateSession(payload) => validate(app, payload).await,
        Command::Logout(payload) => logout(app, payload).await,
        Command::FakeLastMagicLink(payload) => fake_last_magic_link(app, payload),
        Command::Handshake | Command::Ping | Command::Init(_) => error(ErrorCode::Internal),
    }
}

async fn request_link(app: &App, payload: RequestLinkPayload) -> ResultBody {
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
        magic_links: &app.store,
        limiter: &app.store,
        outbox: &app.outbox,
        clock: &WallClock,
        rng: &mut rng,
        lookup_hmac_key: &app.lookup_hmac_key,
        config: app.config.clone(),
    };
    match service.request_magic_link(command).await {
        Ok(outcome) => ResultBody::RequestLink {
            reason: outcome.reason(),
        },
        Err(failure) => service_error(failure),
    }
}

async fn landing(app: &App, payload: LandingPayload) -> ResultBody {
    let mut rng = OsRng;
    let command = BeginMagicLinkLandingCommand::new(payload.token);
    match app
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

async fn flow_state(app: &App, payload: FlowStatePayload) -> ResultBody {
    let mut rng = OsRng;
    let command = ReadMagicLinkFlowStateCommand::new(payload.confirm_cookie);
    match app
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

async fn confirm(app: &App, payload: ConfirmPayload) -> ResultBody {
    let command = match ConfirmMagicLinkFlowCommand::new(
        payload.confirm_cookie,
        payload.confirmation,
        payload.country,
    ) {
        Ok(command) => command,
        Err(failure) => return flow_error(failure),
    };
    let mut rng = OsRng;
    match app
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

async fn validate(app: &App, payload: SessionPayload) -> ResultBody {
    match validate_session(
        &payload.session_cookie,
        payload.country.as_deref(),
        &app.session_keyring,
        &app.store,
        &WallClock,
        &app.config,
    )
    .await
    {
        Ok(validated) => {
            let mut rng = OsRng;
            match refresh_session_cookie(
                &validated,
                &app.session_keyring,
                &mut rng,
                &WallClock,
                &app.config,
            ) {
                Ok(refreshed) => ResultBody::ValidateSession {
                    valid: true,
                    user_id: Some(validated.session().user_id.as_str().to_owned()),
                    refreshed_cookie: refreshed.map(|cookie| cookie.as_secret_value().to_owned()),
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

async fn logout(app: &App, payload: SessionPayload) -> ResultBody {
    match validate_session(
        &payload.session_cookie,
        payload.country.as_deref(),
        &app.session_keyring,
        &app.store,
        &WallClock,
        &app.config,
    )
    .await
    {
        Ok(validated) => {
            let mut rng = OsRng;
            // Revoke server state first; the application clears its cookie
            // only after this reply.
            match app
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

/// Fake mode only: the newest outbox entry for an address, as the rendered
/// landing URL. Exists for the package's own end-to-end tests.
fn fake_last_magic_link(app: &App, payload: OutboxPeekPayload) -> ResultBody {
    let Ok(email) = NormalizedEmail::normalize(&payload.email) else {
        return error(ErrorCode::BadRequest);
    };
    match app.outbox.recorded() {
        Ok(entries) => match entries
            .into_iter()
            .rev()
            .find(|entry| entry.email.as_str() == email.as_str())
        {
            Some(entry) => ResultBody::FakeLastMagicLink {
                found: true,
                magic_link_url: Some(
                    app.email
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

//! One handler per authenticated-state operation, generic over the backing
//! store and outbox. Handlers decode nothing and log nothing: they map typed
//! payloads through the service crates and return one exact result shape per
//! outcome class.
use datadeft_magic_link_service::{
    BeginMagicLinkLandingCommand, Clock, ConfirmMagicLinkFlowCommand,
    MagicLinkAuthenticationRepository, MagicLinkFlowError, MagicLinkOutbox, MagicLinkRepository,
    MagicLinkRequestService, MagicLinkServiceError, NormalizedEmail, RateLimitDecision,
    RateLimitKey, RateLimiter, ReadMagicLinkFlowStateCommand, RequestMagicLinkCommand,
    SessionRepository, SessionValidationError, refresh_session_cookie, validate_session,
};
use datadeft_pow_core::{
    MAX_FUTURE_SKEW_SECS, Solution, mint_pow_proof_cookie, proof_budget_expiry, proof_budget_key,
    verify_pow_proof_cookie,
};
use rand_core::{OsRng, RngCore};

use super::{App, WallClock, now_unix_millis};
use crate::protocol::{
    AppCommand, ConfirmPayload, ErrorCode, FlowStatePayload, LandingPayload, OutboxPeekPayload,
    PowAdmitPayload, PowVerifyPayload, RequestLinkPayload, ResultBody, SessionPayload,
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
    /// Dispatch one authenticated-state command; the lifecycle commands are
    /// a separate type the dispatcher owns, so this match is total.
    pub(crate) async fn run(&self, command: AppCommand) -> ResultBody {
        match command {
            AppCommand::RequestLink(payload) => self.request_link(payload).await,
            AppCommand::Landing(payload) => self.landing(payload).await,
            AppCommand::FlowState(payload) => self.flow_state(payload).await,
            AppCommand::Confirm(payload) => self.confirm(payload).await,
            AppCommand::ValidateSession(payload) => self.validate(payload).await,
            AppCommand::Logout(payload) => self.logout(payload).await,
            AppCommand::FakeLastMagicLink(payload) => self.fake_last_magic_link(payload),
            AppCommand::PowChallenge => self.pow_challenge(),
            AppCommand::PowVerify(payload) => self.pow_verify(payload),
            AppCommand::PowAdmit(payload) => self.pow_admit(payload).await,
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
            lookup_hmac_key: &self.shared.lookup_hmac_key,
            config: self.shared.config.clone(),
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
            Err(failure) => unusable_or_error(
                failure,
                ResultBody::Landing {
                    usable: false,
                    confirm_cookie: None,
                    confirmation: None,
                    account: None,
                    cookie_max_age_secs: None,
                },
            ),
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
            Err(failure) => unusable_or_error(
                failure,
                ResultBody::FlowState {
                    usable: false,
                    account: None,
                    confirmation: None,
                },
            ),
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
            &self.shared.session_keyring,
            &self.store,
            &WallClock,
            &self.shared.config,
        )
        .await
        {
            Ok(validated) => {
                let mut rng = OsRng;
                match refresh_session_cookie(
                    &validated,
                    &self.shared.session_keyring,
                    &mut rng,
                    &WallClock,
                    &self.shared.config,
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
            &self.shared.session_keyring,
            &self.store,
            &WallClock,
            &self.shared.config,
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

    /// Mint a fresh challenge for the application's `pow/create` route.
    fn pow_challenge(&self) -> ResultBody {
        let Some(pow) = &self.shared.pow else {
            return error(ErrorCode::Configuration);
        };
        let mut entropy = [0_u8; 16];
        if OsRng.try_fill_bytes(&mut entropy).is_err() {
            return error(ErrorCode::Internal);
        }
        let Some(now) = now_unix_millis() else {
            return error(ErrorCode::Internal);
        };
        // The policy was validated at initialization; only an insane clock
        // can fail the mint.
        match pow.mint(now, entropy) {
            Ok(challenge) => ResultBody::PowChallenge {
                chg: challenge.chg,
                dif: challenge.dif,
                tim: challenge.tim,
                tag: challenge.tag,
            },
            Err(_) => error(ErrorCode::Internal),
        }
    }

    /// Verify a posted solution and mint the proof-cookie value on success.
    /// Every verification failure collapses into one `admitted: false` shape
    /// so the application can answer with one generic "solve again" response.
    fn pow_verify(&self, payload: PowVerifyPayload) -> ResultBody {
        let Some(pow) = &self.shared.pow else {
            return error(ErrorCode::Configuration);
        };
        let Some(now) = now_unix_millis() else {
            return error(ErrorCode::Internal);
        };
        // The difficulty is the configured policy, never client input; the
        // HMAC tag binds the minted value.
        let solution = Solution {
            chg: payload.chg,
            sol: payload.sol,
            non: payload.non,
            dif: pow.difficulty,
            tim: payload.tim,
            tag: payload.tag,
        };
        let Some(verified) = pow.verify(&solution, now) else {
            return ResultBody::PowVerify {
                admitted: false,
                proof_cookie: None,
                mint_to_verify_ms: None,
            };
        };
        let mut rng = OsRng;
        match mint_pow_proof_cookie(
            &verified.tid,
            None,
            pow.proof_keyring(),
            &mut rng,
            now.as_secs(),
        ) {
            Ok(cookie) => ResultBody::PowVerify {
                admitted: true,
                proof_cookie: Some(cookie.as_secret_value().to_owned()),
                mint_to_verify_ms: verified.mint_to_verify_ms,
            },
            Err(_) => error(ErrorCode::Internal),
        }
    }

    /// Admit a gated request by its proof cookie, spending one unit of its
    /// solve's shared lifetime budget. A failing budget store refuses the
    /// request (fail closed) as `unavailable`, never as an admission.
    async fn pow_admit(&self, payload: PowAdmitPayload) -> ResultBody {
        let Some(pow) = &self.shared.pow else {
            return error(ErrorCode::Configuration);
        };
        let Ok(now) = WallClock.now_unix() else {
            return error(ErrorCode::Internal);
        };
        // Every cookie failure collapses into the uniform refusal; the bounds
        // were validated at initialization.
        let Ok(verified) = verify_pow_proof_cookie(
            &payload.proof_cookie,
            pow.proof_keyring(),
            now,
            pow.proof_ttl_secs,
        ) else {
            return ResultBody::PowAdmit { admitted: false };
        };
        let expires_at_unix = proof_budget_expiry(
            now,
            pow.proof_ttl_secs,
            pow.challenge_max_age_secs,
            MAX_FUTURE_SKEW_SECS,
        );
        // `tid` is 64 lowercase hex characters: no personal data or secrets.
        let Ok(key) = RateLimitKey::parse(&proof_budget_key(verified.tid())) else {
            return error(ErrorCode::Unavailable);
        };
        match self
            .store
            .check_lifetime_limit(&key, pow.budget_per_solve, expires_at_unix, now)
            .await
        {
            Ok(RateLimitDecision::Allowed) => ResultBody::PowAdmit { admitted: true },
            Ok(RateLimitDecision::Denied) => ResultBody::PowAdmit { admitted: false },
            Err(_) => error(ErrorCode::Unavailable),
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
                        self.shared
                            .email
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

/// The one rule for the scanner-facing reads: the two public refusals
/// collapse into the operation's uniform unusable shape, and only
/// infrastructure failures surface as error codes.
fn unusable_or_error(failure: MagicLinkFlowError, unusable: ResultBody) -> ResultBody {
    match failure.public_error() {
        MagicLinkServiceError::BadRequest | MagicLinkServiceError::MagicLinkUnavailable => unusable,
        other => service_error(other),
    }
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

//! Public API smoke tests for the additive scanner-flow staging surface.

use dd_magic_link_core::MagicLinkToken;
use dd_magic_link_service::{
    BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome, ClientKey, Clock,
    ConfirmMagicLinkFlowCommand, ConfirmMagicLinkFlowOutcome, ConsumeMagicLinkCommand,
    ConsumeMagicLinkOutcome, MagicLinkAuthenticationOutcome, MagicLinkAuthenticationRepository,
    MagicLinkConsumeService, MagicLinkConsumeServiceInputs, MagicLinkFlowError,
    MagicLinkFlowService, MagicLinkFlowServiceInputs, MagicLinkServiceError, RateLimiter,
    SessionId, SessionRepository, TemporaryAuthStateAction,
};
use rand_core::{CryptoRng, RngCore};

type UnitRawService<'a> = MagicLinkConsumeService<'a, (), (), (), (), ()>;
type UnitRawInputs<'a> = MagicLinkConsumeServiceInputs<'a, (), (), (), (), ()>;

fn accepts_old_command(_: Option<ConsumeMagicLinkCommand>) {}
fn accepts_old_outcome(_: Option<ConsumeMagicLinkOutcome>) {}
#[allow(dead_code)]
fn construct_unit_raw_service<'a>(inputs: UnitRawInputs<'a>) -> UnitRawService<'a> {
    MagicLinkConsumeService::new(inputs)
}
fn accepts_canonical_outcome(_: Option<MagicLinkAuthenticationOutcome>) {}
fn accepts_landing_command(_: Option<BeginMagicLinkLandingCommand>) {}
fn accepts_landing_outcome(_: Option<BeginMagicLinkLandingOutcome>) {}
fn accepts_confirmation_command(_: Option<ConfirmMagicLinkFlowCommand>) {}
fn accepts_confirmation_outcome(_: Option<ConfirmMagicLinkFlowOutcome>) {}
fn accepts_flow_error(_: Option<MagicLinkFlowError>) {}
fn accepts_state_action(_: Option<TemporaryAuthStateAction>) {}

#[allow(dead_code)]
fn raw_method_signatures<Authentication, Sessions, Limiter, ServiceClock, Rng>(
    service: &mut MagicLinkConsumeService<'_, Authentication, Sessions, Limiter, ServiceClock, Rng>,
    command: ConsumeMagicLinkCommand,
    session_id: &SessionId,
) where
    Authentication: MagicLinkAuthenticationRepository,
    Sessions: SessionRepository,
    Limiter: RateLimiter,
    ServiceClock: Clock,
    Rng: RngCore + CryptoRng,
{
    core::mem::drop(service.consume_magic_link(command));
    core::mem::drop(service.consume_magic_link_token("", None, None));
    core::mem::drop(service.revoke_session(session_id));
}

#[test]
fn old_raw_and_new_scanner_outcomes_coexist_during_staging() {
    accepts_old_command(None);
    accepts_old_outcome(None);
    let _command_constructor: fn(
        MagicLinkToken,
        Option<ClientKey>,
        Option<String>,
    ) -> Result<ConsumeMagicLinkCommand, MagicLinkServiceError> = ConsumeMagicLinkCommand::new;
    accepts_canonical_outcome(None);
    accepts_landing_command(None);
    accepts_landing_outcome(None);
    accepts_confirmation_command(None);
    accepts_confirmation_outcome(None);
    accepts_flow_error(None);
    accepts_state_action(None);

    let _ = core::mem::size_of::<MagicLinkFlowService<'static, (), (), (), (), ()>>();
    let _ = core::mem::size_of::<MagicLinkFlowServiceInputs<'static, (), (), (), (), ()>>();
}

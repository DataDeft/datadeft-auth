//! Public API smoke test for the final scanner-safe flow surface.

use dd_magic_link_service::{
    BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome, Clock, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, MagicLinkAuthenticationOutcome, MagicLinkAuthenticationRepository,
    MagicLinkFlowError, MagicLinkFlowService, NormalizedEmail, RateLimiter,
    RequestMagicLinkCommand, SessionId, SessionRepository, TemporaryAuthStateAction,
};
use rand_core::{CryptoRng, RngCore};

fn accepts_canonical_outcome(_: Option<MagicLinkAuthenticationOutcome>) {}
fn accepts_landing_command(_: Option<BeginMagicLinkLandingCommand>) {}
fn accepts_landing_outcome(_: Option<BeginMagicLinkLandingOutcome>) {}
fn accepts_confirmation_command(_: Option<ConfirmMagicLinkFlowCommand>) {}
fn accepts_confirmation_outcome(_: Option<ConfirmMagicLinkFlowOutcome>) {}
fn accepts_flow_error(_: Option<MagicLinkFlowError>) {}
fn accepts_state_action(_: Option<TemporaryAuthStateAction>) {}

#[allow(dead_code)]
fn scanner_method_signatures<Authentication, Sessions, Limiter, ServiceClock, Rng>(
    service: &mut MagicLinkFlowService<'_, Authentication, Sessions, Limiter, ServiceClock, Rng>,
    begin: BeginMagicLinkLandingCommand,
    confirm: ConfirmMagicLinkFlowCommand,
    session_id: &SessionId,
) where
    Authentication: MagicLinkAuthenticationRepository,
    Sessions: SessionRepository,
    Limiter: RateLimiter,
    ServiceClock: Clock,
    Rng: RngCore + CryptoRng,
{
    core::mem::drop(service.begin_magic_link_landing(begin));
    core::mem::drop(service.confirm_magic_link_flow(confirm));
    core::mem::drop(service.revoke_session(session_id));
}

#[test]
fn final_scanner_flow_surface_is_available() {
    accepts_canonical_outcome(None);
    accepts_landing_command(None);
    accepts_landing_outcome(None);
    accepts_confirmation_command(None);
    accepts_confirmation_outcome(None);
    accepts_flow_error(None);
    accepts_state_action(None);

    let request = RequestMagicLinkCommand::new(
        NormalizedEmail::parse("public-api@example.test").expect("normalized email"),
        true,
        true,
    );
    assert!(request.terms_accepted() && request.privacy_accepted());
    let landing = BeginMagicLinkLandingCommand::new("opaque-token-candidate".to_owned());
    let confirmation = ConfirmMagicLinkFlowCommand::new(
        "opaque-flow-cookie".to_owned(),
        "opaque-confirmation".to_owned(),
        Some("HU".to_owned()),
    )
    .expect("confirmation command");
    accepts_landing_command(Some(landing));
    accepts_confirmation_command(Some(confirmation));

    let _ = core::mem::size_of::<MagicLinkFlowService<'static, (), (), (), (), ()>>();
}

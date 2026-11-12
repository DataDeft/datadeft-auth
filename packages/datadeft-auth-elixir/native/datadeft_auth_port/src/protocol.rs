//! Private v1 protocol: strict envelope parsing into typed commands and
//! canonical reply encoding. The execution engine in `server` dispatches the
//! commands; `messages` holds the payload and result shapes.
mod messages;

pub(crate) use messages::{
    AccountDisplayPayload, AwsPayload, ConfirmPayload, EmailTemplatePayload, FlowStatePayload,
    LandingPayload, OutboxPeekPayload, PowAdmitPayload, PowPayload, PowVerifyPayload,
    RequestLinkPayload, SecretRefPayload, SecretsPayload, ServicePayload, SessionPayload,
};
pub use messages::{ErrorCode, InitPayload, Mode, ResultBody};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::framing::{FrameError, MAX_FRAME_BYTES};

const PROTOCOL_VERSION: u8 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    version: u8,
    id: u32,
    operation: Operation,
    #[serde(borrow)]
    payload: &'a RawValue,
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Handshake,
    Ping,
    Init,
    RequestLink,
    Landing,
    FlowState,
    Confirm,
    ValidateSession,
    Logout,
    FakeLastMagicLink,
    PowChallenge,
    PowVerify,
    PowAdmit,
}

/// A validated request: the strictly increasing wire ID and the typed command.
pub struct ParsedRequest {
    pub id: u32,
    pub command: Command,
}

/// Lifecycle commands the dispatcher owns, separated at parse time so the
/// initialized application is total over `AppCommand` and a misrouted
/// lifecycle command is unrepresentable rather than silently answered.
pub enum Command {
    Handshake,
    Ping,
    Init(Box<InitPayload>),
    App(AppCommand),
}

/// Operations served by the initialized application state.
pub enum AppCommand {
    RequestLink(RequestLinkPayload),
    Landing(LandingPayload),
    FlowState(FlowStatePayload),
    Confirm(ConfirmPayload),
    ValidateSession(SessionPayload),
    Logout(SessionPayload),
    FakeLastMagicLink(OutboxPeekPayload),
    PowChallenge,
    PowVerify(PowVerifyPayload),
    PowAdmit(PowAdmitPayload),
}

/// Fail-closed envelope parse: exact fields, exact version, and a payload
/// validated against the operation's schema (unknown fields are fatal).
pub fn parse_request(frame: &[u8]) -> Result<ParsedRequest, FrameError> {
    let text = std::str::from_utf8(frame).map_err(|_| FrameError::Invalid)?;
    let envelope: Envelope<'_> = serde_json::from_str(text).map_err(|_| FrameError::Invalid)?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(FrameError::Invalid);
    }
    let payload = envelope.payload.get();
    let command = match envelope.operation {
        Operation::Handshake => {
            let Empty {} = parse_payload(payload)?;
            Command::Handshake
        }
        Operation::Ping => {
            let Empty {} = parse_payload(payload)?;
            Command::Ping
        }
        Operation::Init => Command::Init(Box::new(parse_payload(payload)?)),
        Operation::RequestLink => Command::App(AppCommand::RequestLink(parse_payload(payload)?)),
        Operation::Landing => Command::App(AppCommand::Landing(parse_payload(payload)?)),
        Operation::FlowState => Command::App(AppCommand::FlowState(parse_payload(payload)?)),
        Operation::Confirm => Command::App(AppCommand::Confirm(parse_payload(payload)?)),
        Operation::ValidateSession => {
            Command::App(AppCommand::ValidateSession(parse_payload(payload)?))
        }
        Operation::Logout => Command::App(AppCommand::Logout(parse_payload(payload)?)),
        Operation::FakeLastMagicLink => {
            Command::App(AppCommand::FakeLastMagicLink(parse_payload(payload)?))
        }
        Operation::PowChallenge => {
            let Empty {} = parse_payload(payload)?;
            Command::App(AppCommand::PowChallenge)
        }
        Operation::PowVerify => Command::App(AppCommand::PowVerify(parse_payload(payload)?)),
        Operation::PowAdmit => Command::App(AppCommand::PowAdmit(parse_payload(payload)?)),
    };
    Ok(ParsedRequest {
        id: envelope.id,
        command,
    })
}

fn parse_payload<'a, P: Deserialize<'a>>(payload: &'a str) -> Result<P, FrameError> {
    serde_json::from_str(payload).map_err(|_| FrameError::Invalid)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Serialize)]
struct Response {
    version: u8,
    id: u32,
    result: ResultBody,
}

pub fn handshake_result() -> ResultBody {
    ResultBody::Handshake {
        build_version: env!("CARGO_PKG_VERSION"),
        max_frame_bytes: MAX_FRAME_BYTES,
    }
}

pub fn encode_response(id: u32, result: ResultBody) -> Result<Vec<u8>, FrameError> {
    let response = Response {
        version: PROTOCOL_VERSION,
        id,
        result,
    };
    serde_json::to_vec(&response).map_err(|_| FrameError::Invalid)
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;

//! Private v1 protocol types and strict envelope parsing. No authentication
//! operations yet; the execution engine in `server` dispatches these.
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
pub enum Operation {
    Handshake,
    Ping,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub struct ParsedRequest {
    pub id: u32,
    pub operation: Operation,
}

/// Fail-closed envelope parse: exact fields, exact version, and a payload
/// validated against the operation's schema (unknown fields are fatal).
pub fn parse_request(frame: &[u8]) -> Result<ParsedRequest, FrameError> {
    let text = std::str::from_utf8(frame).map_err(|_| FrameError::Invalid)?;
    let envelope: Envelope<'_> = serde_json::from_str(text).map_err(|_| FrameError::Invalid)?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(FrameError::Invalid);
    }
    match envelope.operation {
        Operation::Handshake | Operation::Ping => {
            let Empty {} =
                serde_json::from_str(envelope.payload.get()).map_err(|_| FrameError::Invalid)?;
        }
    }
    Ok(ParsedRequest {
        id: envelope.id,
        operation: envelope.operation,
    })
}

#[derive(Serialize)]
struct Response {
    version: u8,
    id: u32,
    result: ResultBody,
}

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ResultBody {
    Handshake {
        build_version: &'static str,
        max_frame_bytes: usize,
    },
    Ping,
    /// Per-request application failure; protocol faults never use this and
    /// end the process instead.
    Error {
        code: ErrorCode,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Overloaded,
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

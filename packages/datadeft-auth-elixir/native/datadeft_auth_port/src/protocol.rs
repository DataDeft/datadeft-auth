//! Private v1 bootstrap protocol. No authentication operations yet.
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::framing::{self, FrameError, MAX_FRAME_BYTES};

const PROTOCOL_VERSION: u8 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    id: u32,
    operation: Operation,
    payload: Empty,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Handshake,
    Ping,
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

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum ResultBody {
    Handshake {
        build_version: &'static str,
        max_frame_bytes: usize,
    },
    Ping,
}

pub fn serve(reader: &mut impl Read, writer: &mut impl Write) -> Result<(), FrameError> {
    let mut last_id = 0;
    let mut handshaken = false;
    while let Some(frame) = framing::read_frame(reader)? {
        let Request {
            version,
            id,
            operation,
            payload: Empty {},
        } = serde_json::from_slice(&frame).map_err(|_| FrameError::Invalid)?;
        if version != PROTOCOL_VERSION || id <= last_id {
            return Err(FrameError::Invalid);
        }
        let result = match (handshaken, operation) {
            (false, Operation::Handshake) => {
                handshaken = true;
                ResultBody::Handshake {
                    build_version: env!("CARGO_PKG_VERSION"),
                    max_frame_bytes: MAX_FRAME_BYTES,
                }
            }
            (true, Operation::Ping) => ResultBody::Ping,
            _ => return Err(FrameError::Invalid),
        };
        last_id = id;
        let reply = Response {
            version: PROTOCOL_VERSION,
            id,
            result,
        };
        let encoded = serde_json::to_vec(&reply).map_err(|_| FrameError::Invalid)?;
        framing::write_frame(writer, &encoded)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;

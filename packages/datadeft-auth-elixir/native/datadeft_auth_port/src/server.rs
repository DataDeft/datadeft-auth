//! Async bounded execution engine: strictly ordered intake, concurrent
//! bounded jobs, out-of-order replies through one writer. Protocol faults
//! stay fatal (no error reply); only per-request application failures reply
//! with the error result. Aborted in-flight work on a fatal exit is safe for
//! the bootstrap operations; mutating operations must gain durable
//! reconciliation before they land here.
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::framing::{self, FrameError};
use crate::protocol::{self, ErrorCode, Operation, ResultBody};

/// Upper bound on concurrently executing jobs. The Elixir owner enforces a
/// stricter per-connection pending cap at or below this value.
const MAX_IN_FLIGHT_JOBS: usize = 1024;
/// Bound on how long outstanding jobs may finish after stdin closes.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve<R, W>(reader: R, writer: W) -> Result<(), FrameError>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    serve_with(reader, writer, MAX_IN_FLIGHT_JOBS).await
}

async fn serve_with<R, W>(reader: R, writer: W, job_limit: usize) -> Result<(), FrameError>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let (frame_tx, mut frame_rx) = mpsc::channel::<Result<Vec<u8>, FrameError>>(1);
    tokio::task::spawn_blocking(move || read_loop(reader, &frame_tx));
    let (reply_tx, reply_rx) = mpsc::channel::<Vec<u8>>(MAX_IN_FLIGHT_JOBS);
    let mut writer_task = tokio::task::spawn_blocking(move || write_loop(writer, reply_rx));

    let mut handshaken = false;
    let mut last_id = 0_u32;
    let limiter = Arc::new(Semaphore::new(job_limit));
    let mut jobs = JoinSet::new();

    let outcome = loop {
        let frame = tokio::select! {
            received = frame_rx.recv() => match received {
                Some(Ok(frame)) => frame,
                Some(Err(error)) => break Err(error),
                None => break Ok(()),
            },
            // A finished writer means the owner is gone or stdout failed;
            // stop instead of running jobs whose replies cannot land.
            _ = &mut writer_task => break Err(FrameError::Io),
        };
        let request = match protocol::parse_request(&frame) {
            Ok(request) => request,
            Err(error) => break Err(error),
        };
        if request.id <= last_id {
            break Err(FrameError::Invalid);
        }
        last_id = request.id;
        let result = match (handshaken, request.operation) {
            (false, Operation::Handshake) => {
                handshaken = true;
                Some(protocol::handshake_result())
            }
            (true, Operation::Ping) => match limiter.clone().try_acquire_owned() {
                Ok(permit) => {
                    let reply_tx = reply_tx.clone();
                    let id = request.id;
                    jobs.spawn(async move {
                        let _permit = permit;
                        send_reply(&reply_tx, id, ResultBody::Ping).await;
                    });
                    None
                }
                Err(_) => Some(ResultBody::Error {
                    code: ErrorCode::Overloaded,
                }),
            },
            _ => break Err(FrameError::Invalid),
        };
        if let Some(result) = result {
            let encoded = protocol::encode_response(request.id, result)?;
            if reply_tx.send(encoded).await.is_err() {
                break Err(FrameError::Io);
            }
        }
    };

    match outcome {
        Ok(()) => {
            // Best effort after a clean EOF: the owner may already be gone,
            // so late write failures are not fatal.
            let drain = async { while jobs.join_next().await.is_some() {} };
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, drain).await;
            drop(reply_tx);
            let _ = writer_task.await;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn send_reply(replies: &mpsc::Sender<Vec<u8>>, id: u32, result: ResultBody) {
    // A closed channel or encoding failure is handled by the dispatcher
    // noticing the finished writer; the job itself has nowhere to report.
    if let Ok(encoded) = protocol::encode_response(id, result) {
        let _ = replies.send(encoded).await;
    }
}

fn read_loop(mut reader: impl Read, frames: &mpsc::Sender<Result<Vec<u8>, FrameError>>) {
    loop {
        match framing::read_frame(&mut reader) {
            Ok(Some(frame)) => {
                if frames.blocking_send(Ok(frame)).is_err() {
                    return;
                }
            }
            // Dropping the sender signals the clean EOF.
            Ok(None) => return,
            Err(error) => {
                let _ = frames.blocking_send(Err(error));
                return;
            }
        }
    }
}

fn write_loop(
    mut writer: impl Write,
    mut replies: mpsc::Receiver<Vec<u8>>,
) -> Result<(), FrameError> {
    while let Some(reply) = replies.blocking_recv() {
        framing::write_frame(&mut writer, &reply)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

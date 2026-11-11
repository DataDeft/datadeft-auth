//! Async bounded execution engine: strictly ordered intake, concurrent
//! bounded jobs, out-of-order replies through one writer. Protocol faults
//! stay fatal (no error reply); only per-request application failures reply
//! with the error result. Aborted in-flight work on a fatal exit is safe for
//! the read-only operations; the mutating confirm path relies on the durable
//! reconciliation design tracked on the PR before production release.
use std::future::Future;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::app::ReadyApp;
use crate::framing::{self, FrameError};
use crate::protocol::{self, Command, ErrorCode, ResultBody};

/// Upper bound on concurrently executing jobs. The Elixir owner enforces a
/// stricter per-connection pending cap at or below this value.
const MAX_IN_FLIGHT_JOBS: usize = 1024;
/// Bound on how long outstanding jobs may finish after stdin closes.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Connection lifecycle: handshake, then one initialization, then work.
enum Phase {
    AwaitHandshake,
    AwaitInit,
    Ready(ReadyApp),
}

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

    let mut phase = Phase::AwaitHandshake;
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
            // Reap jobs as they finish so completed handles never accumulate.
            // A job that failed to run to completion left its request silently
            // unanswered, which would strand the owner's caller: treat it as a
            // process fault and let the owner restart a coherent process.
            Some(finished) = jobs.join_next() => {
                if finished.is_err() {
                    break Err(FrameError::Io);
                }
                continue;
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
        let id = request.id;
        // Inline replies (handshake, init) sequence the lifecycle; everything
        // else runs as a bounded job with an out-of-order reply.
        let inline = match request.command {
            Command::Handshake => {
                if !matches!(phase, Phase::AwaitHandshake) {
                    break Err(FrameError::Invalid);
                }
                phase = Phase::AwaitInit;
                Some(protocol::handshake_result())
            }
            Command::Ping => {
                if matches!(phase, Phase::AwaitHandshake) {
                    break Err(FrameError::Invalid);
                }
                spawn_job(&mut jobs, &limiter, &reply_tx, id, async {
                    ResultBody::Ping
                })
            }
            Command::Init(payload) => {
                if !matches!(phase, Phase::AwaitInit) {
                    break Err(FrameError::Invalid);
                }
                // Initialization is the only configuration moment, before any
                // other work exists; awaiting it inline keeps the lifecycle
                // strictly ordered (the owner sends nothing else until ready,
                // and the secret fetch carries the SDK's own timeouts).
                match ReadyApp::initialize(*payload).await {
                    Ok(application) => {
                        phase = Phase::Ready(application);
                        Some(ResultBody::Init)
                    }
                    Err(code) => Some(ResultBody::Error { code }),
                }
            }
            Command::App(command) => {
                let Phase::Ready(application) = &phase else {
                    break Err(FrameError::Invalid);
                };
                let application = application.clone();
                spawn_job(&mut jobs, &limiter, &reply_tx, id, async move {
                    application.handle(command).await
                })
            }
        };
        if let Some(result) = inline {
            let encoded = protocol::encode_response(id, result)?;
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

fn overloaded() -> ResultBody {
    ResultBody::Error {
        code: ErrorCode::Overloaded,
    }
}

/// Admit one bounded job, or answer `overloaded` inline when the limit is
/// reached. The permit lives exactly as long as the job; the reply path has
/// nowhere to report, so its failures surface through the dispatcher
/// noticing the finished writer.
fn spawn_job(
    jobs: &mut JoinSet<()>,
    limiter: &Arc<Semaphore>,
    reply_tx: &mpsc::Sender<Vec<u8>>,
    id: u32,
    work: impl Future<Output = ResultBody> + Send + 'static,
) -> Option<ResultBody> {
    match limiter.clone().try_acquire_owned() {
        Ok(permit) => {
            let reply_tx = reply_tx.clone();
            jobs.spawn(async move {
                let _permit = permit;
                let result = work.await;
                send_reply(&reply_tx, id, result).await;
            });
            None
        }
        Err(_) => Some(overloaded()),
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
        // Drain whatever already queued behind it before flushing: one
        // syscall per batch under load, while a lone reply still flushes
        // immediately.
        while let Ok(reply) = replies.try_recv() {
            framing::write_frame(&mut writer, &reply)?;
        }
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

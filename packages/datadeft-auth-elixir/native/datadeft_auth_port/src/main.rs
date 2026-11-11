//! Local process entry point. Stdout is exclusively the framed protocol.
//! No input or parser/IO error is printed to stderr.
#![forbid(unsafe_code)]

mod app;
mod framing;
mod protocol;
mod server;

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Timers drive the EOF drain; the IO driver carries the AWS SDK's HTTP
    // connections (without it the first network call aborts its job).
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::from(2),
    };
    // The unlocked handles are Send; each side is driven by one task only.
    let outcome = runtime.block_on(server::serve(io::stdin(), io::stdout()));
    // Dropping the runtime would wait for the spawn_blocking stdin read,
    // which after a fatal protocol error may stay parked until the owner
    // writes or closes the pipe; shut down without waiting so the exit is
    // prompt and the owner's exit-driven reconnect fires immediately.
    runtime.shutdown_background();
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

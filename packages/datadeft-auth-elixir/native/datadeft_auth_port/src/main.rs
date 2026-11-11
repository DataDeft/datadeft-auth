//! Local process entry point. Stdout is exclusively the framed protocol.
//! No input or parser/IO error is printed to stderr.
#![forbid(unsafe_code)]

mod framing;
mod protocol;
mod server;

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::from(2),
    };
    // The unlocked handles are Send; each side is driven by one task only.
    match runtime.block_on(server::serve(io::stdin(), io::stdout())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

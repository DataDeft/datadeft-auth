//! Local process entry point. Stdout is exclusively the framed protocol.
//! No input or parser/IO error is printed to stderr.
#![forbid(unsafe_code)]

mod framing;
mod protocol;

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    match protocol::serve(&mut io::stdin().lock(), &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

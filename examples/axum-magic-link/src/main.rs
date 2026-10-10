//! Local Axum example wiring `datadeft-magic-link-service`, `datadeft-magic-link-axum`,
//! the in-memory fakes from `datadeft-magic-link-aws` (default, SDK-free build), and
//! the PoW crates together.
//!
//! This binary is intentionally local-development only. It uses the
//! crate-shipped in-memory fakes for storage/rate limiting/outbox, generates
//! fresh development secrets at startup, and exposes a
//! `/dev/latest-magic-link` helper instead of sending email.

mod dev;
mod magic_link;
mod pow;
mod redirect_mode;
mod session;
mod state;
mod util;

use std::error::Error;
use std::net::SocketAddr;

use axum::Router;
use axum::routing::{get, post};

use self::dev::*;
use self::magic_link::*;
use self::pow::*;
use self::redirect_mode::*;
use self::session::*;
use self::state::*;

const LOCAL_ORIGIN: &str = "http://127.0.0.1:3000";
const LISTEN_ADDR: &str = "127.0.0.1:3000";
const POW_DIFFICULTY: u8 = 3;

#[tokio::main]
async fn main() -> AppResult<()> {
    let app = app(build_state()?);
    let addr: SocketAddr = LISTEN_ADDR.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("local example listening on {LOCAL_ORIGIN}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// The example's routes.
fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/auth/pow/create", post(pow_create))
        .route("/auth/pow/validate", post(pow_validate))
        .route("/auth/magic-link/request", post(request_magic_link))
        .route("/auth/magic-link", get(landing_route))
        .route("/auth/magic-link/consume", post(confirm_route))
        // Redirect landing mode, for static UIs.
        .route("/auth/magic-link/open", get(redirect_landing_route))
        .route("/auth/magic-link/flow-state", get(flow_state_route))
        .route("/login/confirm", get(confirm_page))
        .route("/login/confirm.js", get(confirm_page_script))
        .route("/auth/complete", get(auth_complete))
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route("/dev/latest-magic-link", get(dev_latest_magic_link))
        .with_state(state)
}

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod tests;

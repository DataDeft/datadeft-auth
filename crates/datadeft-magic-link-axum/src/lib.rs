//! `datadeft-magic-link-axum`: optional Axum HTTP integration.
//!
//! This crate owns bounded HTTP decoding, scanner-safe magic-link handlers,
//! cookie response helpers, and generic public errors. It does not own token or
//! session cryptography and does not force an application router shape.
//!
//! # Mandatory deployment gate
//!
//! A magic-link token is present in the landing request target before an Axum
//! handler runs. Production deployments **must** configure proxy/load-balancer
//! request-line bounds and prove that outer access logs, application middleware,
//! tracing, metrics, diagnostics, error reporting, and panic capture use route
//! templates and never retain raw request targets, route captures, query fields,
//! tokens, confirmations, or cookies. Representative production-like probes must
//! verify the emitted logs and telemetry. These handlers prove non-reflection only
//! after handler entry. They cannot make an unreviewed outer HTTP stack safe.
//!
//! # Response contract
//!
//! The scanner-safe flow is headless: [`magic_link_landing`] and
//! [`magic_link_confirmation`] run the input checks and hand back structured
//! results (plus prepared cookie headers), and the application renders the
//! responses (JSON for an API, HTML for a server-rendered page). The caller
//! MUST uphold these invariants: they are the scanner-safety and
//! non-enumeration guarantees:
//!
//! - **Consumption is POST-only.** Only the same-origin confirmation POST
//!   consumes the magic link and mints a session. Never consume on a GET.
//! - **The landing GET is side-effect-free and repeatable.** Email security
//!   scanners fetch link URLs. The landing must be safe to fetch any number of
//!   times without burning the link. [`magic_link_landing`] guarantees this on
//!   the library side: do not add consuming side effects in your handler.
//! - **Respond uniformly (non-enumeration).** Return
//!   [`MagicLinkFlowResponseError::Rejected`] with the **same HTTP status you
//!   use for success** so an attacker cannot probe whether a link is
//!   valid/expired. Only genuine `Unavailable`/`Internal` failures use a 5xx.
//! - **Clear the confirm cookie** on a rejected/internal confirmation
//!   ([`clear_confirm_cookie_header`]). Preserve it on `Unavailable` so the
//!   user can retry.
//! - **Stamp security headers** ([`apply_magic_link_security_headers`]:
//!   `no-store`, `strict-origin` referrer, CSP, frame-deny) on every landing/confirmation
//!   response you render.
//! - **Never echo the raw token** into the response body or logs, and
//!   HTML-escape any rendered account identity.
//!
//! # Quickstart
//!
//! Construct the configs and keyrings once at startup, then call the handler
//! helpers from your own routes. This compiles against the SDK-free in-memory
//! fakes from `datadeft-magic-link-aws`. The complete runnable integration is
//! `examples/axum-magic-link` in the repository.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use axum::extract::{Request, State};
//! use axum::http::HeaderMap;
//! use axum::http::header::SET_COOKIE;
//! use axum::response::{Html, IntoResponse, Response};
//! use datadeft_magic_link_aws::{FakeDynamoDbAuthStore, FakeMagicLinkOutbox, StorageHmacKey};
//! use datadeft_magic_link_axum::{
//!     ConfirmCookieConfig, MagicLinkFlowResponseError, MagicLinkHttpError,
//!     MagicLinkScannerFlowConfig, SameOriginPostConfig, SameOriginRedirect, SessionCookieConfig,
//!     apply_magic_link_security_headers, magic_link_flow_state, magic_link_landing,
//!     magic_link_landing_redirect,
//! };
//! use datadeft_magic_link_service::{
//!     Clock, DependencyError, KeyId, KeyPurpose, KeyRing, KeySlot, LookupHmacKey,
//!     MagicLinkConfirmCookie, MagicLinkFlowService, MagicLinkServiceConfig, RootSecret,
//!     SessionCookie,
//! };
//! use rand_core::{OsRng, RngCore};
//!
//! /// The application owns the clock. The library never reads it directly.
//! struct SystemClock;
//!
//! impl Clock for SystemClock {
//!     fn now_unix(&self) -> Result<u64, DependencyError> {
//!         std::time::SystemTime::now()
//!             .duration_since(std::time::UNIX_EPOCH)
//!             .map(|duration| duration.as_secs())
//!             .map_err(|_| DependencyError::Internal)
//!     }
//! }
//!
//! /// Development-only keyring. Production loads real secrets (see
//! /// `resolve_auth_secrets` in datadeft-magic-link-aws and docs/security.md).
//! fn dev_keyring<P: KeyPurpose>(kid: &str, now_unix: u64) -> KeyRing<P> {
//!     let mut root = [0u8; 32];
//!     OsRng.try_fill_bytes(&mut root).expect("OS randomness");
//!     let kid = KeyId::parse(kid).expect("valid kid");
//!     let key = RootSecret::new(root).derive_key::<P>(&kid).expect("derive");
//!     let mint_until = now_unix + 90 * 24 * 60 * 60;
//!     let verify_until = mint_until + P::MAX_ABSOLUTE_AGE_SECS;
//!     KeyRing::new(vec![KeySlot::active_with_windows(kid, key, mint_until, verify_until)])
//!         .expect("keyring")
//! }
//!
//! #[derive(Clone)]
//! struct AppState {
//!     auth: FakeDynamoDbAuthStore,
//!     outbox: FakeMagicLinkOutbox,
//!     config: MagicLinkServiceConfig,
//!     http_config: Arc<MagicLinkScannerFlowConfig>,
//!     lookup_hmac_key: Arc<LookupHmacKey>,
//!     confirm_keyring: Arc<KeyRing<MagicLinkConfirmCookie>>,
//!     session_keyring: Arc<KeyRing<SessionCookie>>,
//! }
//!
//! fn build_state(now_unix: u64) -> AppState {
//!     let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
//!     let mut key = [0u8; 32];
//!     OsRng.try_fill_bytes(&mut key).expect("OS randomness");
//!     let http_config = MagicLinkScannerFlowConfig::new(
//!         SameOriginRedirect::parse("/auth/magic-link/consume").expect("post action"),
//!         SameOriginPostConfig::parse("https://example.test").expect("origin"),
//!         SessionCookieConfig::secure(&config).expect("session cookie"),
//!         ConfirmCookieConfig::secure_defaults(),
//!     )
//!     .expect("scanner config")
//!     // Mode 2 only: the static page and the flow-state route it reads.
//!     .with_redirect_landing(
//!         SameOriginRedirect::parse("/login/confirm").expect("page"),
//!         SameOriginRedirect::parse("/auth/magic-link/flow-state").expect("flow state"),
//!     )
//!     .expect("redirect landing");
//!     let mut storage_key = [0u8; 32];
//!     OsRng.try_fill_bytes(&mut storage_key).expect("OS randomness");
//!     AppState {
//!         auth: FakeDynamoDbAuthStore::new(StorageHmacKey::new(storage_key)),
//!         outbox: FakeMagicLinkOutbox::default(),
//!         config,
//!         http_config: Arc::new(http_config),
//!         lookup_hmac_key: Arc::new(LookupHmacKey::new(key)),
//!         confirm_keyring: Arc::new(dev_keyring("flow-active", now_unix)),
//!         session_keyring: Arc::new(dev_keyring("session-active", now_unix)),
//!     }
//! }
//!
//! /// Mode 1, server-rendered: the landing renders the confirm page itself.
//! /// The token stays in the server; the page holds only the account and the
//! /// confirmation value, in a same-origin POST form. Never return the
//! /// landing as JSON for a static page's JavaScript to fetch with `?token=`:
//! /// that puts the token in JavaScript. Static UIs use mode 2.
//! async fn landing(State(state): State<AppState>, request: Request) -> Response {
//!     let config = state.http_config.clone();
//!     let result = magic_link_landing(request, config.as_ref(), move |command| async move {
//!         let mut rng = OsRng;
//!         flow_service(&state, &mut rng).begin_magic_link_landing(command).await
//!     })
//!     .await;
//!
//!     let mut response = match result {
//!         Ok(landing) => {
//!             let page = format!(
//!                 "<form method=post action=/auth/magic-link/consume>\
//!                  <p>Sign in as {}</p>\
//!                  <input type=hidden name=confirmation value={}>\
//!                  <button>Continue</button></form>",
//!                 escape_html(landing.outcome.account_identity().as_str()),
//!                 escape_html(landing.outcome.confirmation_value()),
//!             );
//!             let mut response = Html(page).into_response();
//!             response.headers_mut().append(SET_COOKIE, landing.confirm_cookie);
//!             response
//!         }
//!         // The same 200 as a usable link, so link validity is not enumerable.
//!         Err(MagicLinkFlowResponseError::Rejected) => {
//!             Html("<p>Request a new link.</p>").into_response()
//!         }
//!         Err(_) => MagicLinkHttpError::Unavailable.into_response(),
//!     };
//!     apply_magic_link_security_headers(response.headers_mut());
//!     response
//! }
//!
//! /// Mode 2, redirect, for UIs served as static files: the landing answers
//! /// `303` to the configured static page for every link state (configure it
//! /// with `MagicLinkScannerFlowConfig::with_redirect_landing`), and the page
//! /// reads `{ usable, account, confirmation }` from the flow-state route,
//! /// then POSTs the confirmation like mode 1's form.
//! async fn redirect_landing(State(state): State<AppState>, request: Request) -> Response {
//!     let config = state.http_config.clone();
//!     magic_link_landing_redirect(request, config.as_ref(), move |command| async move {
//!         let mut rng = OsRng;
//!         flow_service(&state, &mut rng).begin_magic_link_landing(command).await
//!     })
//!     .await
//! }
//!
//! async fn flow_state(State(state): State<AppState>, headers: HeaderMap) -> Response {
//!     let config = state.http_config.clone();
//!     magic_link_flow_state(&headers, config.as_ref(), move |command| async move {
//!         let mut rng = OsRng;
//!         flow_service(&state, &mut rng).read_magic_link_flow_state(command).await
//!     })
//!     .await
//! }
//!
//! fn flow_service<'a>(
//!     state: &'a AppState,
//!     rng: &'a mut OsRng,
//! ) -> MagicLinkFlowService<'a, FakeDynamoDbAuthStore, FakeDynamoDbAuthStore,
//!     FakeDynamoDbAuthStore, SystemClock, OsRng> {
//!     MagicLinkFlowService {
//!         authentication: &state.auth,
//!         sessions: &state.auth,
//!         limiter: &state.auth,
//!         clock: &SystemClock,
//!         rng,
//!         lookup_hmac_key: &state.lookup_hmac_key,
//!         previous_lookup_hmac_key: None,
//!         confirm_keyring: &state.confirm_keyring,
//!         session_keyring: &state.session_keyring,
//!         config: state.config.clone(),
//!     }
//! }
//!
//! fn escape_html(value: &str) -> String {
//!     value
//!         .replace('&', "&amp;")
//!         .replace('<', "&lt;")
//!         .replace('>', "&gt;")
//!         .replace('"', "&quot;")
//!         .replace('\'', "&#39;")
//! }
//! # let _ = (build_state, landing, redirect_landing, flow_state);
//! ```

#![forbid(unsafe_code)]

mod cookie;
mod cookie_parse;
mod error;
mod extract;
mod handlers;
mod origin;
mod redirect_mode;
mod scanner_config;
mod session_auth;

#[cfg(test)]
pub(crate) mod test_fixtures;

pub use cookie::{
    ConfirmCookieConfig, CookieConfigError, DEFAULT_SESSION_COOKIE_NAME,
    DEFAULT_SESSION_COOKIE_PATH, SameSite, SessionCookieConfig, clear_confirm_cookie_header,
    clear_session_cookie_header, session_set_cookie_header, set_confirm_cookie_header,
};
/// The strict incoming-cookie selector shared with `datadeft-pow-axum`.
pub use datadeft_magic_link_service::cookie_header::{CookieHeaderError, select_cookie};
pub use error::{
    ErrorBody, GenericAcceptedBody, MagicLinkHttpError, UNAVAILABLE_ERROR_CODE,
    UNAVAILABLE_MESSAGE, generic_accepted_response,
};
pub use extract::{
    APPLICATION_JSON, CLOUDFRONT_VIEWER_COUNTRY, FORM_URLENCODED, GuardedBody,
    MAX_MAGIC_LINK_BODY_BYTES, MAX_MAGIC_LINK_LANDING_QUERY_BYTES, MagicLinkConfirmationBody,
    MagicLinkRequestJson, content_type_matches, guarded_body, parse_magic_link_request_json,
    viewer_country, viewer_country_from,
};
pub use handlers::{
    MagicLinkConfirmed, MagicLinkFlowResponseError, MagicLinkLanding,
    apply_magic_link_security_headers, handle_magic_link_request_json, magic_link_confirmation,
    magic_link_landing,
};
pub use origin::{OriginConfigError, SameOriginPostConfig, SameOriginRedirect};
pub use redirect_mode::{magic_link_flow_state, magic_link_landing_redirect};
pub use scanner_config::{
    MagicLinkScannerFlowConfig, MagicLinkScannerFlowConfigError, RedirectLanding,
};
pub use session_auth::{
    DD_SESSION_AUTH_SCHEME, SessionAuthRejection, SessionCookieValue, SessionRejectionKind,
    authenticate_session,
};

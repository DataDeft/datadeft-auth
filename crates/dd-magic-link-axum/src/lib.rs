//! `dd-magic-link-axum` — optional Axum HTTP integration.
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
//! after handler entry; they cannot make an unreviewed outer HTTP stack safe.
//!
//! # Quickstart
//!
//! Construct the configs and keyrings once at startup, then call the handler
//! helpers from your own routes. This compiles against the SDK-free in-memory
//! fakes from `dd-magic-link-aws`; the complete runnable integration is
//! `examples/axum-magic-link` in the repository.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use axum::extract::{Request, State};
//! use axum::response::Response;
//! use dd_magic_link_aws::{FakeDynamoDbAuthStore, FakeMagicLinkOutbox, StorageHmacKey};
//! use dd_magic_link_axum::{
//!     MagicLinkScannerFlowConfig, SameOriginPostConfig, SameOriginRedirect,
//!     SessionCookieConfig, TemporaryCookieConfig, handle_magic_link_landing,
//! };
//! use dd_magic_link_service::{
//!     Clock, DependencyError, KeyId, KeyPurpose, KeyRing, KeySlot, LookupHmacKey,
//!     MagicLinkFlowCookie, MagicLinkFlowService, MagicLinkServiceConfig, RootSecret,
//!     SessionCookie,
//! };
//! use rand_core::{OsRng, RngCore};
//!
//! /// The application owns the clock; the library never reads it directly.
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
//! /// Development-only keyring; production loads real secrets (see
//! /// `resolve_auth_secrets` in dd-magic-link-aws and docs/security.md).
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
//!     flow_keyring: Arc<KeyRing<MagicLinkFlowCookie>>,
//!     session_keyring: Arc<KeyRing<SessionCookie>>,
//! }
//!
//! fn build_state(now_unix: u64) -> AppState {
//!     let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
//!     let mut key = [0u8; 32];
//!     OsRng.try_fill_bytes(&mut key).expect("OS randomness");
//!     let http_config = MagicLinkScannerFlowConfig::new(
//!         SameOriginRedirect::parse("/auth/magic-link/consume").expect("post action"),
//!         SameOriginRedirect::parse("/signed-in").expect("redirect"),
//!         SameOriginPostConfig::parse("https://example.test").expect("origin"),
//!         SessionCookieConfig::production(&config).expect("session cookie"),
//!         TemporaryCookieConfig::production_defaults(),
//!     )
//!     .expect("scanner config");
//!     let mut storage_key = [0u8; 32];
//!     OsRng.try_fill_bytes(&mut storage_key).expect("OS randomness");
//!     AppState {
//!         auth: FakeDynamoDbAuthStore::new(StorageHmacKey::new(storage_key)),
//!         outbox: FakeMagicLinkOutbox::default(),
//!         config,
//!         http_config: Arc::new(http_config),
//!         lookup_hmac_key: Arc::new(LookupHmacKey::new(key)),
//!         flow_keyring: Arc::new(dev_keyring("flow-active", now_unix)),
//!         session_keyring: Arc::new(dev_keyring("session-active", now_unix)),
//!     }
//! }
//!
//! /// One route: the scanner-safe landing page. Confirmation, request, and
//! /// session authentication wire up the same way — see the example app.
//! async fn magic_link_landing(State(state): State<AppState>, request: Request) -> Response {
//!     let config = state.http_config.clone();
//!     handle_magic_link_landing(request, config.as_ref(), move |command| async move {
//!         let mut rng = OsRng;
//!         let mut service = MagicLinkFlowService {
//!             authentication: &state.auth,
//!             sessions: &state.auth,
//!             limiter: &state.auth,
//!             clock: &SystemClock,
//!             rng: &mut rng,
//!             lookup_hmac_key: &state.lookup_hmac_key,
//!             flow_keyring: &state.flow_keyring,
//!             session_keyring: &state.session_keyring,
//!             config: state.config.clone(),
//!         };
//!         service.begin_magic_link_landing(command).await
//!     })
//!     .await
//! }
//! # let _ = (build_state, magic_link_landing);
//! ```

#![forbid(unsafe_code)]

mod cookie;
mod cookie_parse;
mod error;
mod extract;
mod handlers;
mod origin;
mod scanner_config;
mod session_auth;

#[cfg(test)]
pub(crate) mod test_fixtures;

pub use cookie::{
    CookieConfigError, DEFAULT_SESSION_COOKIE_NAME, DEFAULT_SESSION_COOKIE_PATH, SameSite,
    SessionCookieConfig, TemporaryCookieConfig, clear_session_cookie_header,
    clear_temporary_cookie_header, session_set_cookie_header, set_temporary_cookie_header,
};
pub use error::{ErrorBody, GenericAcceptedBody, MagicLinkHttpError, generic_accepted_response};
pub use extract::{
    APPLICATION_JSON, CLOUDFRONT_VIEWER_COUNTRY, FORM_URLENCODED, GuardedBody,
    MAX_MAGIC_LINK_BODY_BYTES, MAX_MAGIC_LINK_LANDING_QUERY_BYTES, MagicLinkConfirmationBody,
    MagicLinkLandingToken, MagicLinkRequestJson, content_type_matches, guarded_body,
    parse_magic_link_request_json, viewer_country, viewer_country_from,
};
pub use handlers::{
    apply_magic_link_security_headers, handle_magic_link_confirmation, handle_magic_link_landing,
    handle_magic_link_request_json,
};
pub use origin::{OriginConfigError, SameOriginPostConfig, SameOriginRedirect};
pub use scanner_config::{MagicLinkScannerFlowConfig, MagicLinkScannerFlowConfigError};
pub use session_auth::{SessionAuthRejection, SessionCookieValue, authenticate_session};

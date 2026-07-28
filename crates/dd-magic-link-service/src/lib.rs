//! `dd-magic-link-service` — framework-neutral magic-link orchestration.
//!
//! Request, scanner-safe landing (`begin_magic_link_landing`), explicit
//! confirmation (`confirm_magic_link_flow`), session validation, and revocation
//! built on traits for storage, rate limiting, users, sessions, the email outbox,
//! the clock, and randomness. Public errors are generic and non-enumerating. No
//! Axum, Tokio, AWS SDK, filesystem, process environment, network, or logging
//! dependency.
//!
//! # Getting started
//!
//! The common integration depends on this crate plus `dd-magic-link-axum`
//! (HTTP) and `dd-magic-link-aws` (DynamoDB behind the `aws` feature; its
//! default SDK-free build ships in-memory fakes for every trait here). This
//! crate re-exports the keyring and lookup-key types, so the core crates are
//! not direct dependencies. A compiling quickstart lives in the
//! `dd-magic-link-axum` crate docs, and the complete runnable integration —
//! request, scanner-safe landing, confirmation, authenticated session, and
//! logout — is `examples/axum-magic-link` in the repository. Implementors of
//! a non-AWS backend start from the trait contracts in [`traits`]
//! (particularly the atomic-commit contract on
//! [`traits::MagicLinkAuthenticationRepository`]).

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod service;
pub mod session;
pub mod session_body;
pub mod traits;
pub mod types;

pub use config::{MagicLinkConfigError, MagicLinkServiceConfig, RateLimitConfig};
pub use dd_auth_token_core::keyring::{KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret};
pub use dd_magic_link_core::{
    LookupHmac, LookupHmacKey, MagicLinkFlowCookie, NormalizedEmail, VerifierHash,
    contains_magic_link_token_marker, domain_separated_lookup_hmac,
};
pub use error::{
    CommitMagicLinkAuthenticationError, DependencyError, MagicLinkFlowError, MagicLinkServiceError,
    TemporaryAuthStateAction,
};
pub use service::{MagicLinkFlowService, MagicLinkRequestService};
pub use session::{SessionValidationError, ValidatedSession, validate_session};
pub use session_body::{
    SessionBodyError, SessionCookieBody, decode_session_cookie_body, encode_session_cookie_body,
};
pub use traits::{
    Clock, MagicLinkAuthenticationRepository, MagicLinkOutbox, MagicLinkRepository,
    RateLimitDecision, RateLimiter, SessionRepository,
};
pub use types::{
    AuthenticationAttemptId, BeginMagicLinkLandingCommand, BeginMagicLinkLandingOutcome,
    CommitMagicLinkAuthentication, ConfirmMagicLinkFlowCommand, ConfirmMagicLinkFlowOutcome,
    MAX_RAW_MAGIC_LINK_TOKEN_BYTES, MagicLinkAccountIdentity, MagicLinkAuthenticationCandidate,
    MagicLinkAuthenticationExpectation, MagicLinkAuthenticationOutcome,
    MagicLinkAuthenticationUser, MagicLinkEmail, MagicLinkRecord, RateLimitKey,
    RequestMagicLinkCommand, RequestMagicLinkOutcome, SessionCookie, SessionId, SessionRecord,
    UserId, UserRecord,
};

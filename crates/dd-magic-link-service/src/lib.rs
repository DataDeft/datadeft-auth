//! `dd-magic-link-service` — framework-neutral magic-link orchestration.
//!
//! Request and consume flows built on traits for storage, rate limiting,
//! users, sessions, the email outbox, the clock, and randomness. Public
//! errors are generic and non-enumerating. No Axum, Tokio, AWS SDK, filesystem,
//! process environment, network, or logging dependency.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod service;
pub mod session;
pub mod session_body;
pub mod traits;
pub mod types;

pub use config::{MagicLinkConfigError, MagicLinkServiceConfig, RateLimitConfig};
pub use dd_magic_link_core::NormalizedEmail;
pub use error::{CommitMagicLinkAuthenticationError, DependencyError, MagicLinkServiceError};
pub use service::{
    MagicLinkConsumeService, MagicLinkConsumeServiceInputs, MagicLinkRequestService,
    MagicLinkRequestServiceInputs,
};
pub use session::{SessionValidationError, ValidatedSession, validate_session};
pub use session_body::{
    SessionBodyError, SessionCookieBody, decode_session_cookie_body, encode_session_cookie_body,
};
pub use traits::{
    Clock, MagicLinkAuthenticationRepository, MagicLinkOutbox, MagicLinkRepository,
    RateLimitDecision, RateLimiter, SessionRepository,
};
pub use types::{
    AuthenticationAttemptId, ClientKey, CommitMagicLinkAuthentication, ConsumeMagicLinkCommand,
    ConsumeMagicLinkOutcome, EmailLocale, MagicLinkAuthenticationCandidate,
    MagicLinkAuthenticationExpectation, MagicLinkAuthenticationUser, MagicLinkEmail,
    MagicLinkRecord, RateLimitKey, RequestMagicLinkCommand, RequestMagicLinkOutcome, SessionId,
    SessionRecord, UserId, UserRecord,
};

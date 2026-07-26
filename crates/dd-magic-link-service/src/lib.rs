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
pub mod session_body;
pub mod traits;
pub mod types;

pub use config::{MagicLinkServiceConfig, RateLimitConfig};
pub use dd_magic_link_core::NormalizedEmail;
pub use error::{ConsumeMagicLinkError, DependencyError, MagicLinkServiceError};
pub use service::{
    MagicLinkConsumeService, MagicLinkConsumeServiceInputs, MagicLinkRequestService,
    MagicLinkRequestServiceInputs,
};
pub use session_body::{SessionCookieBody, decode_session_cookie_body, encode_session_cookie_body};
pub use traits::{
    Clock, MagicLinkOutbox, MagicLinkRepository, RateLimitDecision, RateLimiter, SessionRepository,
    UserRepository,
};
pub use types::{
    ClientKey, ConsumeMagicLinkCommand, ConsumeMagicLinkOutcome, ConsumedMagicLink, EmailLocale,
    MagicLinkEmail, MagicLinkRecord, RateLimitKey, RequestMagicLinkCommand,
    RequestMagicLinkOutcome, SessionId, SessionRecord, UserId, UserRecord,
};

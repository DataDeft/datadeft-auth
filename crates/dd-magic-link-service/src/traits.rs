//! Service dependency traits.

use dd_magic_link_core::{LookupHmac, VerifierHash};

use crate::error::{ConsumeMagicLinkError, DependencyError};
use crate::types::{
    ConsumedMagicLink, MagicLinkEmail, MagicLinkRecord, RateLimitKey, SessionId, SessionRecord,
    UserRecord,
};

/// Deterministic clock boundary.
pub trait Clock {
    fn now_unix(&self) -> Result<u64, DependencyError>;
}

/// Magic-link challenge persistence. Implementations must store keyed lookup
/// material, not raw selectors or verifiers.
pub trait MagicLinkRepository {
    fn put_magic_link_if_absent(&self, record: MagicLinkRecord) -> Result<(), DependencyError>;

    /// Atomically consume a challenge if and only if it exists, is unconsumed,
    /// unexpired at `now_unix`, and its verifier hash matches.
    fn consume_magic_link(
        &self,
        selector_lookup_hmac: &LookupHmac,
        verifier_hash: &VerifierHash,
        now_unix: u64,
    ) -> Result<ConsumedMagicLink, ConsumeMagicLinkError>;
}

/// User account repository.
pub trait UserRepository {
    fn find_user_by_email(
        &self,
        email: &dd_magic_link_core::NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError>;

    fn put_user_if_absent(&self, user: UserRecord) -> Result<(), DependencyError>;
}

/// Server-side session repository. This supports lookup and revocation for
/// current-session, logout, and compromise-invalidation flows above HTTP.
pub trait SessionRepository {
    fn put_session_if_absent(&self, session: SessionRecord) -> Result<(), DependencyError>;

    fn find_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionRecord>, DependencyError>;

    fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at_unix: u64,
    ) -> Result<(), DependencyError>;
}

/// Rate limiter result.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RateLimitDecision {
    Allowed,
    Denied,
}

/// Rate limiter dependency. Returning [`RateLimitDecision::Denied`] is a normal
/// policy outcome and is mapped to generic public behavior by the service.
pub trait RateLimiter {
    fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window_secs: u64,
    ) -> Result<RateLimitDecision, DependencyError>;
}

/// Magic-link email outbox.
pub trait MagicLinkOutbox {
    fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError>;
}

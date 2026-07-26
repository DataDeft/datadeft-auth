//! Service dependency traits.

use core::future::Future;

use dd_magic_link_core::{LookupHmac, NormalizedEmail};

use crate::error::{CommitMagicLinkAuthenticationError, DependencyError};
use crate::types::{
    CommitMagicLinkAuthentication, MagicLinkAuthenticationCandidate, MagicLinkEmail,
    MagicLinkRecord, RateLimitKey, SessionId, SessionRecord, UserRecord,
};

/// Deterministic clock boundary.
pub trait Clock {
    fn now_unix(&self) -> Result<u64, DependencyError>;
}

/// Magic-link challenge persistence. Implementations must store keyed lookup
/// material, not raw selectors or verifiers.
pub trait MagicLinkRepository {
    fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> impl Future<Output = Result<(), DependencyError>>;
}

/// Aggregate repository for all-or-nothing magic-link authentication.
///
/// Authentication planning uses strongly consistent reads where the backing
/// store supports them. The service derives and compares the presented verifier
/// hash locally in constant time; adapters must never receive or compare the raw
/// token or verifier.
///
/// A successful [`commit_magic_link_authentication`](Self::commit_magic_link_authentication)
/// is one atomic transaction that:
///
/// - transitions exactly the expected, unconsumed and unexpired challenge with
///   nonzero consent to consumed;
/// - for an existing user, conditions both immutable email linkage and profile
///   on the planned user id and expected email, requires `disabled == false`, and
///   preserves stored consent;
/// - for a created user, derives an enabled profile and immutable email linkage
///   solely from the planned user id and expected email and consent fields;
/// - derives an unrevoked session solely from the command's session id, planned
///   user id, expected email, and `now_unix`, then creates it and its user index.
///
/// The command's `session_expires_at_unix` is the authoritative validity expiry.
/// A storage cleanup TTL may retain records at or after that time, but retention
/// must never extend validity.
///
/// `Rejected`, `UserConflict`, and `SessionConflict` are confirmed transaction
/// cancellations and must leave every item unchanged. A confirmed conflict may
/// be replanned, but every changed transaction payload requires a new attempt id.
/// `DependencyUnavailable` may have an ambiguous outcome; callers may retry only
/// the identical command with the same attempt id and must not read, generate
/// entropy, or replan while its result may be ambiguous. If the original attempt
/// committed, an immediate exact-command retry with that attempt id must return
/// success without applying a second mutation. Reusing an attempt id with any
/// changed command field must be rejected as `Internal` (or an equivalent invalid
/// command result) and must not mutate storage. An adapter-reported `Internal`
/// failure is not an ambiguous commit and must not be retried as one.
pub trait MagicLinkAuthenticationRepository {
    fn find_magic_link_for_authentication(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> impl Future<Output = Result<Option<MagicLinkAuthenticationCandidate>, DependencyError>>;

    fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> impl Future<Output = Result<Option<UserRecord>, DependencyError>>;

    fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> impl Future<Output = Result<(), CommitMagicLinkAuthenticationError>>;
}

/// Server-side session repository. This supports lookup and revocation for
/// current-session, logout, and compromise-invalidation flows above HTTP.
pub trait SessionRepository {
    /// Find the requested live session at `now_unix`.
    ///
    /// Implementations must return `None` for missing, revoked, or server-expired
    /// records. Service validation additionally checks identity, revocation, and
    /// authenticated lifetime invariants as defense in depth.
    fn find_session(
        &self,
        session_id: &SessionId,
        now_unix: u64,
    ) -> impl Future<Output = Result<Option<SessionRecord>, DependencyError>>;

    fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at_unix: u64,
    ) -> impl Future<Output = Result<(), DependencyError>>;
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
        now_unix: u64,
    ) -> impl Future<Output = Result<RateLimitDecision, DependencyError>>;
}

/// Magic-link email outbox.
pub trait MagicLinkOutbox {
    fn enqueue_magic_link(
        &self,
        email: MagicLinkEmail,
    ) -> impl Future<Output = Result<(), DependencyError>>;
}

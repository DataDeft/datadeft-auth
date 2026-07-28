//! Complete server-side session validation.
//!
//! Validation is deliberately non-sliding: it does not touch repository state or
//! re-mint the cookie. The authenticated cookie timestamp is bounded by the
//! configured idle lifetime, while its original `iat` is bounded by the absolute
//! lifetime. The repository remains authoritative for revocation and storage
//! expiry.

use core::fmt;

use dd_auth_token_core::cookie::{CLOCK_SKEW_TOLERANCE_SECS, parse_bound_cookie};
use dd_auth_token_core::keyring::KeyRing;

use crate::config::MagicLinkServiceConfig;
use crate::error::DependencyError;
use crate::session_body::decode_session_cookie_body;
use crate::traits::{Clock, SessionRepository};
use crate::types::{SessionCookie, SessionRecord};

/// Public failure classes for incoming session authentication.
///
/// No variant carries a cookie, session identifier, email address, key id, or
/// repository detail.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionValidationError {
    /// Cookie, body, repository record, freshness, expiry, or revocation failed.
    InvalidSession,
    /// A dependency is temporarily unavailable; callers may retry.
    Unavailable,
    /// Service configuration or a dependency invariant is invalid.
    Internal,
}

impl fmt::Display for SessionValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSession => f.write_str("invalid session"),
            Self::Unavailable => f.write_str("session validation unavailable"),
            Self::Internal => f.write_str("internal session validation error"),
        }
    }
}

impl std::error::Error for SessionValidationError {}

/// Authenticated server-side session and its cookie-bound country context.
pub struct ValidatedSession {
    session: SessionRecord,
    country: Option<String>,
}

impl ValidatedSession {
    /// Server-side session record that passed lookup, expiry, and revocation checks.
    #[must_use]
    pub fn session(&self) -> &SessionRecord {
        &self.session
    }

    /// Country context authenticated inside the session cookie, when present.
    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }
}

impl fmt::Debug for ValidatedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedSession(..)")
    }
}

/// Authenticate an incoming session cookie against cookie and server-side policy.
///
/// The operation validates configuration before reading the clock, reads the
/// clock exactly once, authenticates and freshness-checks the cookie, decodes its
/// body, enforces the country lock, and performs exactly one repository lookup.
/// Missing, revoked, expired, future-created, malformed, and wrong-country
/// sessions all collapse to [`SessionValidationError::InvalidSession`].
///
/// # Country pinning
///
/// A session issued with a trusted-edge country is locked to that country:
/// `request_country` (the current request's trusted-edge signal, never
/// client-supplied input) must match it on every validation, and an absent
/// signal does not satisfy the lock — fail closed. Sessions issued without a
/// country are unlocked and skip the check, so deployments without an edge
/// country header are unaffected.
///
/// This operation is not a sliding refresh: it never writes, revokes, touches, or
/// re-mints session state.
pub async fn validate_session<Sessions, ServiceClock>(
    cookie_value: &str,
    request_country: Option<&str>,
    session_keyring: &KeyRing<SessionCookie>,
    sessions: &Sessions,
    clock: &ServiceClock,
    config: &MagicLinkServiceConfig,
) -> Result<ValidatedSession, SessionValidationError>
where
    Sessions: SessionRepository,
    ServiceClock: Clock,
{
    let max_age = config
        .session_max_age()
        .map_err(|_| SessionValidationError::Internal)?;
    let now_unix = clock.now_unix().map_err(map_session_dependency_error)?;
    let verified =
        parse_bound_cookie::<SessionCookie>(cookie_value, session_keyring, now_unix, max_age)
            .map_err(|_| SessionValidationError::InvalidSession)?;
    let body = decode_session_cookie_body(verified.body())
        .map_err(|_| SessionValidationError::InvalidSession)?;
    if let Some(bound_country) = body.country.as_deref() {
        if request_country != Some(bound_country) {
            return Err(SessionValidationError::InvalidSession);
        }
    }
    let session = sessions
        .find_session(&body.session_id, now_unix)
        .await
        .map_err(map_session_dependency_error)?
        .ok_or(SessionValidationError::InvalidSession)?;

    let latest_creation = now_unix.saturating_add(CLOCK_SKEW_TOLERANCE_SECS);
    if session.revoked_at_unix.is_some()
        || session.session_id != body.session_id
        || session.created_at_unix > latest_creation
    {
        return Err(SessionValidationError::InvalidSession);
    }
    let session_age = now_unix.saturating_sub(session.created_at_unix);
    if session_age > max_age.absolute_secs {
        return Err(SessionValidationError::InvalidSession);
    }

    Ok(ValidatedSession {
        session,
        country: body.country,
    })
}

fn map_session_dependency_error(error: DependencyError) -> SessionValidationError {
    match error {
        DependencyError::Unavailable | DependencyError::RateLimited => {
            SessionValidationError::Unavailable
        }
        DependencyError::ConditionalWriteFailed | DependencyError::Internal => {
            SessionValidationError::Internal
        }
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

//! Stored records and the atomic authentication commit command.

use core::fmt;

use datadeft_magic_link_core::{LookupHmac, NormalizedEmail, VerifierHash};

use super::ids::{AuthenticationAttemptId, SessionId, UserId};

/// Magic-link record written at request time. It contains keyed lookup material,
/// never raw selectors or verifiers.
#[derive(Clone)]
pub struct MagicLinkRecord {
    pub selector_lookup_hmac: LookupHmac,
    pub email: NormalizedEmail,
    pub verifier_hash: VerifierHash,
    pub expires_at_unix: u64,
    pub consumed_at_unix: Option<u64>,
    pub terms_version: String,
    pub privacy_version: String,
    pub consented_at_unix: u64,
}

impl fmt::Debug for MagicLinkRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkRecord")
            .field("selector_lookup_hmac", &"LookupHmac(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("verifier_hash", &"VerifierHash(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("consumed_at_unix", &self.consumed_at_unix)
            .field("terms_version", &self.terms_version)
            .field("privacy_version", &self.privacy_version)
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// User repository record.
#[derive(Clone, Eq, PartialEq)]
pub struct UserRecord {
    pub user_id: UserId,
    pub email: NormalizedEmail,
    pub disabled: bool,
    pub terms_version: Option<String>,
    pub privacy_version: Option<String>,
    pub consented_at_unix: Option<u64>,
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("user_id", &"UserId(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("disabled", &self.disabled)
            .field(
                "terms_version",
                &self.terms_version.as_deref().unwrap_or("<missing>"),
            )
            .field(
                "privacy_version",
                &self.privacy_version.as_deref().unwrap_or("<missing>"),
            )
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// Server-side session record.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub email: NormalizedEmail,
    pub created_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("session_id", &"SessionId(..)")
            .field("user_id", &"UserId(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("created_at_unix", &self.created_at_unix)
            .field("revoked_at_unix", &self.revoked_at_unix)
            .finish()
    }
}

/// Strongly read challenge state used to plan an atomic authentication.
///
/// The repository returns the stored verifier hash so the service, rather than
/// an adapter or database expression, owns the single constant-time comparison
/// with the presented verifier hash. All other fields are security-relevant
/// optimistic-read state that the service validates before constructing a
/// [`CommitMagicLinkAuthentication`] command.
#[derive(Clone)]
pub struct MagicLinkAuthenticationCandidate {
    pub verifier_hash: VerifierHash,
    pub email: NormalizedEmail,
    pub expires_at_unix: u64,
    pub consumed_at_unix: Option<u64>,
    pub terms_version: String,
    pub privacy_version: String,
    pub consented_at_unix: u64,
}

impl fmt::Debug for MagicLinkAuthenticationCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkAuthenticationCandidate")
            .field("verifier_hash", &"VerifierHash(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("consumed_at_unix", &self.consumed_at_unix)
            .field("terms_version", &self.terms_version)
            .field("privacy_version", &self.privacy_version)
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// Immutable challenge fields that an atomic authentication commit must bind.
///
/// Challenge writers must keep these fields immutable after creation. The only
/// supported mutation is the atomic transition from unconsumed to consumed. An
/// adapter must condition the commit on exact equality for every field here,
/// require an unconsumed and unexpired challenge with nonzero consent, and must
/// not place verifier-derived material in transaction expressions or values.
#[derive(Clone, Eq, PartialEq)]
pub struct MagicLinkAuthenticationExpectation {
    pub selector_lookup_hmac: LookupHmac,
    pub email: NormalizedEmail,
    pub expires_at_unix: u64,
    pub terms_version: String,
    pub privacy_version: String,
    pub consented_at_unix: u64,
}

impl fmt::Debug for MagicLinkAuthenticationExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicLinkAuthenticationExpectation")
            .field("selector_lookup_hmac", &"LookupHmac(..)")
            .field("email", &"NormalizedEmail(..)")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("terms_version", &self.terms_version)
            .field("privacy_version", &self.privacy_version)
            .field("consented_at_unix", &self.consented_at_unix)
            .finish()
    }
}

/// Planned user identity and account branch for an atomic authentication.
///
/// The repository derives all persisted user fields from this id and the
/// challenge expectation, as specified by
/// [`MagicLinkAuthenticationRepository`](crate::traits::MagicLinkAuthenticationRepository).
#[derive(Clone, Eq, PartialEq)]
pub enum MagicLinkAuthenticationUser {
    Existing { user_id: UserId },
    Create { user_id: UserId },
}

impl fmt::Debug for MagicLinkAuthenticationUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Existing { .. } => f.write_str("MagicLinkAuthenticationUser::Existing(..)"),
            Self::Create { .. } => f.write_str("MagicLinkAuthenticationUser::Create(..)"),
        }
    }
}

/// Complete all-or-nothing magic-link authentication transaction.
///
/// Before submitting this command, the service completes several steps. It owns
/// token parsing, presented verifier HMAC derivation, constant-time comparison,
/// and policy/consent checks. It also owns identity and session-id generation,
/// checked session expiry calculation, and complete browser-cookie minting.
/// The command contains no raw token, selector,
/// verifier, presented verifier hash, or redundant persisted record fields.
/// See [`MagicLinkAuthenticationRepository`](crate::traits::MagicLinkAuthenticationRepository)
/// for the full atomic commit and retry contract.
#[derive(Clone, Eq, PartialEq)]
pub struct CommitMagicLinkAuthentication {
    pub magic_link: MagicLinkAuthenticationExpectation,
    pub now_unix: u64,
    pub attempt_id: AuthenticationAttemptId,
    pub user: MagicLinkAuthenticationUser,
    pub session_id: SessionId,
    /// Authoritative server-side session validity expiry from validated policy.
    /// Storage may retain the record at or after this time for cleanup, but that
    /// retention must never extend session validity.
    pub session_expires_at_unix: u64,
}

impl fmt::Debug for CommitMagicLinkAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitMagicLinkAuthentication")
            .field("magic_link", &self.magic_link)
            .field("now_unix", &self.now_unix)
            .field("attempt_id", &"AuthenticationAttemptId(..)")
            .field("user", &self.user)
            .field("session_id", &"SessionId(..)")
            .field("session_expires_at_unix", &self.session_expires_at_unix)
            .finish()
    }
}

//! Shared fakes and fixtures for the session test modules.

//! Complete session-validation tests.

use crate::test_shared::Shared;

use datadeft_auth_token_core::cookie::mint_bound_cookie;
use datadeft_auth_token_core::keyring::{KeyPurpose, KeyRing};
use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring_with_windows};
use datadeft_magic_link_core::NormalizedEmail;

use crate::session_body::encode_session_cookie_body;
use crate::types::{SessionId, UserId};

use super::*;

pub(super) struct TestClock {
    pub(super) result: Result<u64, DependencyError>,
    pub(super) calls: Shared<usize>,
}

impl TestClock {
    pub(super) fn at(now_unix: u64) -> Self {
        Self {
            result: Ok(now_unix),
            calls: Shared::new(0),
        }
    }

    pub(super) fn failing(error: DependencyError) -> Self {
        Self {
            result: Err(error),
            calls: Shared::new(0),
        }
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        self.calls.set(self.calls.get() + 1);
        self.result
    }
}

#[derive(Default)]
pub(super) struct TestSessions {
    pub(super) record: Shared<Option<SessionRecord>>,
    pub(super) storage_expires_at_unix: Shared<Option<u64>>,
    pub(super) next_error: Shared<Option<DependencyError>>,
    pub(super) return_mismatched_record: Shared<bool>,
    pub(super) find_calls: Shared<usize>,
    pub(super) revoke_calls: Shared<usize>,
    pub(super) user_disabled: Shared<bool>,
    pub(super) user_check_error: Shared<Option<DependencyError>>,
    pub(super) user_checks: Shared<usize>,
}

impl TestSessions {
    pub(super) fn with_record(record: SessionRecord) -> Self {
        Self {
            record: Shared::new(Some(record)),
            ..Self::default()
        }
    }
}

impl SessionRepository for TestSessions {
    async fn find_session(
        &self,
        session_id: &SessionId,
        now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        self.find_calls.set(self.find_calls.get() + 1);
        if let Some(error) = self.next_error.take() {
            return Err(error);
        }
        if self
            .storage_expires_at_unix
            .get()
            .is_some_and(|expires_at| expires_at < now_unix)
        {
            return Ok(None);
        }
        let record = self.record.borrow().clone();
        if !self.return_mismatched_record.get()
            && record
                .as_ref()
                .is_some_and(|record| &record.session_id != session_id)
        {
            return Ok(None);
        }
        Ok(record)
    }

    async fn revoke_session(
        &self,
        _session_id: &SessionId,
        _revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        self.revoke_calls.set(self.revoke_calls.get() + 1);
        Ok(())
    }

    async fn is_session_owner_active(
        &self,
        _user_id: &UserId,
        _session_created_at_unix: u64,
    ) -> Result<bool, DependencyError> {
        self.user_checks.set(self.user_checks.get() + 1);
        if let Some(error) = self.user_check_error.take() {
            return Err(error);
        }
        Ok(!self.user_disabled.get())
    }
}

pub(super) fn keyring() -> KeyRing<SessionCookie> {
    test_keyring_with_windows(
        0x51,
        "session-active",
        10_000,
        10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
    )
}

pub(super) fn session_id() -> SessionId {
    SessionId::parse("sid_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("session id")
}

pub(super) fn other_session_id() -> SessionId {
    SessionId::parse("sid_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .expect("other session id")
}

pub(super) fn record(created_at_unix: u64) -> SessionRecord {
    SessionRecord {
        session_id: session_id(),
        user_id: UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id"),
        email: NormalizedEmail::parse("session-user@example.com").expect("email"),
        created_at_unix,
        revoked_at_unix: None,
    }
}

pub(super) fn config() -> MagicLinkServiceConfig {
    let mut config = MagicLinkServiceConfig::new("terms-test", "privacy-test");
    config.session_idle_secs = 100;
    config.session_absolute_secs = 300;
    config
}

pub(super) fn cookie(
    keyring: &KeyRing<SessionCookie>,
    timestamp: u32,
    iat: u32,
    country: Option<&str>,
) -> String {
    let body = encode_session_cookie_body(&session_id(), country).expect("encode session body");
    raw_cookie(keyring, timestamp, iat, &body)
}

pub(super) fn raw_cookie(
    keyring: &KeyRing<SessionCookie>,
    timestamp: u32,
    iat: u32,
    body: &[u8],
) -> String {
    let mut rng = PerCallRng::starting_at(0x61);
    mint_bound_cookie::<SessionCookie, _>(
        body,
        keyring,
        &mut rng,
        timestamp,
        iat,
        u64::from(timestamp),
    )
    .expect("mint session cookie")
}

/// Keyring after a session-key rotation: a new active key plus the previous
/// key kept verify-only until `verify_until_unix`.
pub(super) fn rotated_keyring(verify_until_unix: u64) -> KeyRing<SessionCookie> {
    use datadeft_auth_token_core::keyring::{KeyId, KeySlot, RootSecret};
    let new_kid = KeyId::parse("session-new").expect("kid");
    let old_kid = KeyId::parse("session-active").expect("kid");
    let new_key = RootSecret::new([0x52; 32])
        .derive_key::<SessionCookie>(&new_kid)
        .expect("new key");
    let old_key = RootSecret::new([0x51; 32])
        .derive_key::<SessionCookie>(&old_kid)
        .expect("old key");
    KeyRing::new(vec![
        KeySlot::active_with_windows(
            new_kid,
            new_key,
            10_000,
            10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
        ),
        KeySlot::verify_only(old_kid, old_key, verify_until_unix),
    ])
    .expect("rotated keyring")
}

// --- explicit refresh ------------------------------------------------------
// Fixtures: idle 100 s, absolute 300 s; cookies issued at iat 800.

pub(super) async fn validated_at(
    cookie: &str,
    country: Option<&str>,
    keyring: &KeyRing<SessionCookie>,
    sessions: &TestSessions,
    now_unix: u64,
) -> Result<ValidatedSession, SessionValidationError> {
    validate_session(
        cookie,
        country,
        keyring,
        sessions,
        &TestClock::at(now_unix),
        &config(),
    )
    .await
}

/// Refresh in the same request: the clock reads the validation's instant.
pub(super) fn refresh(
    validated: &ValidatedSession,
    keyring: &KeyRing<SessionCookie>,
) -> Option<String> {
    let mut rng = PerCallRng::starting_at(0x71);
    let clock = TestClock::at(validated.validated_at_unix);
    refresh_session_cookie(validated, keyring, &mut rng, &clock, &config())
        .expect("refresh")
        .map(|cookie| cookie.as_secret_value().to_owned())
}

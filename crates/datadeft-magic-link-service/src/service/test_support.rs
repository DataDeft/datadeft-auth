//! Shared fakes and fixtures for the service test modules.

//! Service orchestration tests.

use crate::test_shared::Shared;
use std::collections::VecDeque;

use datadeft_auth_token_core::keyring::{KeyPurpose, KeyRing};
use datadeft_auth_token_core::test_support::{CountingRng, test_keyring_with_windows};
use datadeft_magic_link_core::{
    LookupHmac, LookupHmacKey, MagicLinkConfirmCookie, MagicLinkToken, NormalizedEmail,
    selector_lookup_hmac, verifier_hash,
};

use crate::config::MagicLinkServiceConfig;
use crate::traits::{
    Clock, MagicLinkAuthenticationRepository, MagicLinkOutbox, MagicLinkRepository,
    SessionRepository,
};
use crate::types::{RequestMagicLinkCommand, SessionCookie, SessionRecord};

use super::*;

// Crate items the service test modules use, re-exported once for all of them.
pub(super) use crate::error::*;
pub(super) use crate::traits::*;
pub(super) use crate::types::*;

pub(super) const NOW: u64 = 1_000;
pub(super) const SELECTOR: &str = "000102030405060708090a0b0c0d0e0f";
pub(super) const VERIFIER: &str =
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
pub(super) const OTHER_VERIFIER: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

pub(super) struct FixedClock {
    pub(super) now: u64,
    pub(super) calls: Shared<usize>,
}

impl FixedClock {
    pub(super) fn at(now: u64) -> Self {
        Self {
            now,
            calls: Shared::new(0),
        }
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.now)
    }
}

#[derive(Default)]
pub(super) struct AllowLimiter {
    pub(super) calls: Shared<usize>,
    pub(super) checked: Shared<Vec<String>>,
    pub(super) denied_prefixes: Shared<Vec<String>>,
    pub(super) next_error: Shared<Option<DependencyError>>,
}

impl AllowLimiter {
    pub(super) fn deny_prefix(&self, prefix: &str) {
        self.denied_prefixes.borrow_mut().push(prefix.to_owned());
    }

    pub(super) fn fail_next(&self, error: DependencyError) {
        self.next_error.set(Some(error));
    }
}

impl RateLimiter for AllowLimiter {
    async fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        _limit: u32,
        _window_secs: u64,
        _now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        self.calls.set(self.calls.get() + 1);
        self.checked.borrow_mut().push(key.as_str().to_owned());
        if let Some(error) = self.next_error.take() {
            return Err(error);
        }
        if self
            .denied_prefixes
            .borrow()
            .iter()
            .any(|prefix| key.as_str().starts_with(prefix))
        {
            Ok(RateLimitDecision::Denied)
        } else {
            Ok(RateLimitDecision::Allowed)
        }
    }
}

#[derive(Default)]
pub(super) struct FakeRepository {
    pub(super) candidate: Shared<Option<MagicLinkAuthenticationCandidate>>,
    pub(super) user: Shared<Option<UserRecord>>,
    pub(super) commands: Shared<Vec<CommitMagicLinkAuthentication>>,
    pub(super) commit_results: Shared<VecDeque<CommitMagicLinkAuthenticationError>>,
    pub(super) successful_command: Shared<Option<CommitMagicLinkAuthentication>>,
    pub(super) apply_then_unavailable_once: Shared<bool>,
    pub(super) sessions: Shared<Vec<SessionRecord>>,
    pub(super) request_records: Shared<Vec<MagicLinkRecord>>,
    pub(super) candidate_reads: Shared<usize>,
    pub(super) candidate_lookup_keys: Shared<Vec<LookupHmac>>,
    pub(super) user_reads: Shared<usize>,
    pub(super) user_lookup_emails: Shared<Vec<NormalizedEmail>>,
    pub(super) revoked: Shared<Vec<SessionId>>,
    pub(super) install_winner_on_user_conflict: Shared<bool>,
}

impl MagicLinkRepository for FakeRepository {
    async fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> Result<(), DependencyError> {
        self.request_records.borrow_mut().push(record);
        Ok(())
    }
}

impl MagicLinkAuthenticationRepository for FakeRepository {
    async fn find_magic_link_for_authentication(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        self.candidate_reads.set(self.candidate_reads.get() + 1);
        self.candidate_lookup_keys
            .borrow_mut()
            .push(selector_lookup_hmac.clone());
        if selector_lookup_hmac != &expected_selector_lookup() {
            return Ok(None);
        }
        Ok(self.candidate.borrow().clone())
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        self.user_reads.set(self.user_reads.get() + 1);
        self.user_lookup_emails.borrow_mut().push(email.clone());
        if !self
            .candidate
            .borrow()
            .as_ref()
            .is_some_and(|candidate| candidate.email == *email)
        {
            return Ok(None);
        }
        Ok(self.user.borrow().clone())
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        self.commands.borrow_mut().push(command.clone());

        if let Some(successful) = self.successful_command.borrow().as_ref()
            && successful.attempt_id == command.attempt_id
        {
            return if successful == command {
                Ok(())
            } else {
                Err(CommitMagicLinkAuthenticationError::Internal)
            };
        }

        if let Some(error) = self.commit_results.borrow_mut().pop_front() {
            if error == CommitMagicLinkAuthenticationError::UserConflict
                && self.install_winner_on_user_conflict.replace(false)
            {
                *self.user.borrow_mut() =
                    Some(existing_user("usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false));
            }
            return Err(error);
        }

        let candidate = self
            .candidate
            .borrow()
            .clone()
            .ok_or(CommitMagicLinkAuthenticationError::Rejected)?;
        if candidate.consumed_at_unix.is_some()
            || candidate.email != command.magic_link.email
            || candidate.expires_at_unix != command.magic_link.expires_at_unix
            || candidate.terms_version != command.magic_link.terms_version
            || candidate.privacy_version != command.magic_link.privacy_version
            || candidate.consented_at_unix != command.magic_link.consented_at_unix
            || candidate.expires_at_unix < command.now_unix
            || candidate.consented_at_unix == 0
        {
            return Err(CommitMagicLinkAuthenticationError::Rejected);
        }

        let (user_id, created_user) = match &command.user {
            MagicLinkAuthenticationUser::Existing { user_id } => {
                let users = self.user.borrow();
                let user = users
                    .as_ref()
                    .ok_or(CommitMagicLinkAuthenticationError::UserConflict)?;
                if user.user_id != *user_id || user.email != candidate.email || user.disabled {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                (user_id.clone(), None)
            }
            MagicLinkAuthenticationUser::Create { user_id } => {
                if self.user.borrow().is_some() {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                (
                    user_id.clone(),
                    Some(UserRecord {
                        user_id: user_id.clone(),
                        email: candidate.email.clone(),
                        disabled: false,
                        terms_version: Some(candidate.terms_version.clone()),
                        privacy_version: Some(candidate.privacy_version.clone()),
                        consented_at_unix: Some(candidate.consented_at_unix),
                    }),
                )
            }
        };

        if self
            .sessions
            .borrow()
            .iter()
            .any(|session| session.session_id == command.session_id)
        {
            return Err(CommitMagicLinkAuthenticationError::SessionConflict);
        }
        let session = SessionRecord {
            session_id: command.session_id.clone(),
            user_id,
            email: candidate.email,
            created_at_unix: command.now_unix,
            revoked_at_unix: None,
        };

        // Apply only after every condition above has succeeded.
        if let Some(user) = created_user {
            *self.user.borrow_mut() = Some(user);
        }
        self.candidate
            .borrow_mut()
            .as_mut()
            .ok_or(CommitMagicLinkAuthenticationError::Internal)?
            .consumed_at_unix = Some(command.now_unix);
        self.sessions.borrow_mut().push(session);
        *self.successful_command.borrow_mut() = Some(command.clone());

        if self.apply_then_unavailable_once.replace(false) {
            Err(CommitMagicLinkAuthenticationError::DependencyUnavailable)
        } else {
            Ok(())
        }
    }
}

impl SessionRepository for FakeRepository {
    async fn find_session(
        &self,
        session_id: &SessionId,
        _now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        Ok(self
            .sessions
            .borrow()
            .iter()
            .find(|session| &session.session_id == session_id)
            .cloned())
    }

    async fn revoke_session(
        &self,
        session_id: &SessionId,
        _revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        self.revoked.borrow_mut().push(session_id.clone());
        Ok(())
    }

    async fn is_session_owner_active(
        &self,
        _user_id: &UserId,
        _session_created_at_unix: u64,
    ) -> Result<bool, DependencyError> {
        Ok(true)
    }
}

#[derive(Default)]
pub(super) struct FakeOutbox {
    pub(super) messages: Shared<Vec<MagicLinkEmail>>,
    pub(super) next_error: Shared<Option<DependencyError>>,
}

impl FakeOutbox {
    pub(super) fn fail_next(&self, error: DependencyError) {
        self.next_error.set(Some(error));
    }
}

impl MagicLinkOutbox for FakeOutbox {
    async fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError> {
        if let Some(error) = self.next_error.take() {
            return Err(error);
        }
        self.messages.borrow_mut().push(email);
        Ok(())
    }
}

pub(super) fn lookup_key() -> LookupHmacKey {
    LookupHmacKey::new([0x42; 32])
}

pub(super) fn expected_selector_lookup() -> LookupHmac {
    selector_lookup_hmac(&lookup_key(), token(VERIFIER).selector()).expect("selector lookup")
}

pub(super) fn session_keyring_with_mint_until(mint_until_unix: u64) -> KeyRing<SessionCookie> {
    test_keyring_with_windows(
        0x11,
        "active",
        mint_until_unix,
        mint_until_unix + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
    )
}

pub(super) fn session_keyring() -> KeyRing<SessionCookie> {
    session_keyring_with_mint_until(20_000)
}

pub(super) fn confirm_keyring() -> KeyRing<MagicLinkConfirmCookie> {
    test_keyring_with_windows(0x33, "flow-active", 20_000, 20_300)
}

pub(super) fn config() -> MagicLinkServiceConfig {
    let mut config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    config.session_idle_secs = 100;
    config.session_absolute_secs = 300;
    config.enforce_country = true;
    config
}

pub(super) fn token(verifier: &str) -> MagicLinkToken {
    MagicLinkToken::parse(&format!("mlv1.{SELECTOR}.{verifier}")).expect("test token")
}

pub(super) fn candidate() -> MagicLinkAuthenticationCandidate {
    let key = lookup_key();
    let token = token(VERIFIER);
    MagicLinkAuthenticationCandidate {
        verifier_hash: verifier_hash(&key, token.verifier()).expect("verifier hash"),
        email: NormalizedEmail::parse("account@example.test").expect("email"),
        expires_at_unix: NOW + 100,
        consumed_at_unix: None,
        terms_version: "terms-v1".to_owned(),
        privacy_version: "privacy-v1".to_owned(),
        consented_at_unix: NOW - 1,
    }
}

pub(super) fn existing_user(id: &str, disabled: bool) -> UserRecord {
    UserRecord {
        user_id: UserId::parse(id).expect("user id"),
        email: NormalizedEmail::parse("account@example.test").expect("email"),
        disabled,
        terms_version: Some("old-terms".to_owned()),
        privacy_version: Some("old-privacy".to_owned()),
        consented_at_unix: Some(7),
    }
}

pub(super) fn create_commit_command(session_id: SessionId) -> CommitMagicLinkAuthentication {
    let candidate = candidate();
    CommitMagicLinkAuthentication {
        magic_link: authentication_expectation(&expected_selector_lookup(), &candidate),
        now_unix: NOW,
        attempt_id: AuthenticationAttemptId::parse("aid_000102030405060708090a0b0c0d0e0f")
            .expect("attempt id"),
        user: MagicLinkAuthenticationUser::Create {
            user_id: UserId::parse("usr_000102030405060708090a0b0c0d0e0f").expect("user id"),
        },
        session_id,
        session_expires_at_unix: NOW + 300,
    }
}

pub(super) async fn begin_flow(
    repository: &FakeRepository,
    limiter: &AllowLimiter,
    clock: &FixedClock,
    rng: &mut CountingRng,
    raw_token: String,
    config: MagicLinkServiceConfig,
) -> Result<BeginMagicLinkLandingOutcome, MagicLinkFlowError> {
    let key = lookup_key();
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService {
        authentication: repository,
        sessions: repository,
        limiter,
        clock,
        rng,
        lookup_hmac_key: &key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config,
    };
    service
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(raw_token))
        .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn confirm_flow(
    repository: &FakeRepository,
    limiter: &AllowLimiter,
    clock: &FixedClock,
    rng: &mut CountingRng,
    confirm_cookie: String,
    confirmation: String,
    country: Option<String>,
    config: MagicLinkServiceConfig,
) -> Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError> {
    let key = lookup_key();
    let confirm_keyring = confirm_keyring();
    let session_keyring = session_keyring();
    let mut service = MagicLinkFlowService {
        authentication: repository,
        sessions: repository,
        limiter,
        clock,
        rng,
        lookup_hmac_key: &key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &confirm_keyring,
        session_keyring: &session_keyring,
        config,
    };
    let command = ConfirmMagicLinkFlowCommand::new(confirm_cookie, confirmation, country)?;
    service.confirm_magic_link_flow(command).await
}

pub(super) async fn request(
    repository: &FakeRepository,
    limiter: &AllowLimiter,
    outbox: &FakeOutbox,
    rng: &mut CountingRng,
    config: MagicLinkServiceConfig,
) -> Result<RequestMagicLinkOutcome, MagicLinkServiceError> {
    let clock = FixedClock::at(NOW);
    let key = lookup_key();
    let mut service = MagicLinkRequestService {
        magic_links: repository,
        limiter,
        outbox,
        clock: &clock,
        rng,
        lookup_hmac_key: &key,
        config,
    };
    service
        .request_magic_link(RequestMagicLinkCommand::new(
            NormalizedEmail::parse("account@example.test").expect("email"),
            true,
            true,
        ))
        .await
}

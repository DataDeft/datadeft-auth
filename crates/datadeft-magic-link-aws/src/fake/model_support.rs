//! Shared harness for the model-conformance (stateful property) tests.
//!
//! The model tests drive the real service code (`MagicLinkRequestService`,
//! `MagicLinkFlowService`, `validate_session`, `refresh_session_cookie`,
//! `AuthAdminService`) over the fake store through random operation sequences,
//! and compare every outcome with a plain-Rust reference model. They are the
//! executable bridge between `spec/tla/*.tla` and the code.

use core::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

use datadeft_auth_token_core::cookie::CLOCK_SKEW_TOLERANCE_SECS;
use datadeft_auth_token_core::keyring::{KeyId, KeyRing, KeySlot, RootSecret};
use datadeft_auth_token_core::test_support::test_keyring;
use datadeft_magic_link_core::{LookupHmacKey, MagicLinkConfirmCookie, NormalizedEmail};
use datadeft_magic_link_service::{
    AdminActor, AuthAdminService, BeginMagicLinkLandingCommand, Clock, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, DependencyError, MagicLinkAuthenticationRepository,
    MagicLinkFlowError, MagicLinkFlowService, MagicLinkRequestService, MagicLinkServiceConfig,
    MagicLinkServiceError, RefreshedSessionCookie, RequestMagicLinkCommand, SessionCookie,
    SessionId, SessionValidationError, ValidatedSession, refresh_session_cookie, validate_session,
};
use rand_core::{CryptoRng, RngCore};

use super::test_support::AllowAllLimiter;
use super::*;

/// Start of model time. Fits the `u32` cookie timestamps with room to spare.
pub(super) const T0: u64 = 1_000_000;
/// Short session lifetimes so random clock steps reach every boundary.
pub(super) const IDLE: u64 = 600;
pub(super) const ABSOLUTE: u64 = 3_000;
pub(super) const SKEW: u64 = CLOCK_SKEW_TOLERANCE_SECS;
/// Short magic-link lifetimes for the flow model.
pub(super) const LINK_TTL: u64 = 120;
pub(super) const FLOW_TTL: u64 = 60;

pub(super) const EMAILS: [&str; 2] = ["carol@example.test", "dave@example.test"];

/// A user id that never exists in any model run.
pub(super) const UNKNOWN_USER: &str = "usr_ffffffffffffffffffffffffffffffff";

pub(super) fn model_config() -> MagicLinkServiceConfig {
    let mut config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");
    config.magic_link_ttl_secs = LINK_TTL;
    config.magic_link_flow_ttl_secs = FLOW_TTL;
    config.session_idle_secs = IDLE;
    config.session_absolute_secs = ABSOLUTE;
    config
}

pub(super) fn email(index: usize) -> NormalizedEmail {
    NormalizedEmail::parse(EMAILS[index % EMAILS.len()]).expect("model email")
}

pub(super) fn actor() -> AdminActor {
    AdminActor::new("admin@example.test", Some("model".to_owned())).expect("actor")
}

/// A settable clock shared by every service in one model run.
pub(super) struct ManualClock(AtomicU64);

impl ManualClock {
    pub(super) fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    pub(super) fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    pub(super) fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(self.now())
    }
}

/// SplitMix64 byte stream. Test fixture only: deterministic per seed, and
/// unlike `CountingRng` it does not repeat every 256 bytes, so ids drawn over
/// a long run never collide by construction.
pub(super) struct SplitMixRng(u64);

impl SplitMixRng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl RngCore for SplitMixRng {
    fn next_u32(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SplitMixRng {}

/// Run one model case to completion on a fresh current-thread runtime.
pub(super) fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(future)
}

pub(super) fn session_kid(generation: u8) -> String {
    format!("sess-{generation}")
}

fn session_slot_key(generation: u8) -> (KeyId, RootSecret) {
    let kid = KeyId::parse(&session_kid(generation)).expect("kid");
    (kid, RootSecret::new([0x60_u8.wrapping_add(generation); 32]))
}

/// Session keyring after `generation` rotations: the newest key is active,
/// and the one before it stays verify-only while `keep_previous` holds.
pub(super) fn session_keyring(generation: u8, keep_previous: bool) -> KeyRing<SessionCookie> {
    let (kid, root) = session_slot_key(generation);
    let key = root.derive_key::<SessionCookie>(&kid).expect("derive");
    let mut slots = vec![KeySlot::active(kid, key)];
    if keep_previous && generation > 0 {
        let (kid, root) = session_slot_key(generation - 1);
        let key = root.derive_key::<SessionCookie>(&kid).expect("derive");
        slots.push(KeySlot::verify_only(kid, key, u64::MAX));
    }
    KeyRing::new(slots).expect("session keyring")
}

/// The key id in a `v1.{kid}.{branca}` cookie value.
pub(super) fn cookie_kid(value: &str) -> &str {
    value.split('.').nth(1).expect("cookie kid")
}

/// The real services, wired to one fake store, one clock, and one RNG.
pub(super) struct Harness {
    pub(super) store: FakeDynamoDbAuthStore,
    pub(super) clock: ManualClock,
    pub(super) rng: SplitMixRng,
    pub(super) lookup_key: LookupHmacKey,
    pub(super) session_keyring: KeyRing<SessionCookie>,
    pub(super) confirm_keyring: KeyRing<MagicLinkConfirmCookie>,
    pub(super) config: MagicLinkServiceConfig,
    outbox: crate::FakeMagicLinkOutbox,
}

impl Harness {
    pub(super) fn new(seed: u64) -> Self {
        Self {
            store: FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32])),
            clock: ManualClock::new(T0),
            rng: SplitMixRng::new(seed),
            lookup_key: LookupHmacKey::new([0x42; 32]),
            session_keyring: session_keyring(0, false),
            confirm_keyring: test_keyring(0x22, "flow-model"),
            config: model_config(),
            outbox: crate::FakeMagicLinkOutbox::default(),
        }
    }

    pub(super) fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Request a link for `email` and return the raw token from the outbox.
    pub(super) async fn request(&mut self, email: &NormalizedEmail) -> String {
        MagicLinkRequestService {
            magic_links: &self.store,
            limiter: &AllowAllLimiter,
            outbox: &self.outbox,
            clock: &self.clock,
            rng: &mut self.rng,
            lookup_hmac_key: &self.lookup_key,
            config: self.config.clone(),
        }
        .request_magic_link(RequestMagicLinkCommand::new(email.clone(), true, true))
        .await
        .expect("request");
        let sent = self.outbox.recorded().expect("outbox");
        let last = sent.last().expect("one email");
        last.token.as_secret_value().to_string()
    }

    /// The scanner-safe `GET` landing. Returns the confirm cookie and the
    /// confirmation nonce.
    pub(super) async fn land(
        &mut self,
        raw_token: &str,
    ) -> Result<(String, String), MagicLinkFlowError> {
        let store = self.store.clone();
        let landing = self
            .flow_service(&store)
            .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(raw_token.to_owned()))
            .await;
        landing.map(|landing| {
            (
                landing.confirm_cookie_value().to_owned(),
                landing.confirmation_value().to_owned(),
            )
        })
    }

    /// The same-origin confirmation `POST`, through `authentication`.
    pub(super) async fn confirm_with<Authentication: MagicLinkAuthenticationRepository>(
        &mut self,
        authentication: &Authentication,
        cookie: &str,
        confirmation: &str,
        country: Option<&str>,
    ) -> Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError> {
        let command = ConfirmMagicLinkFlowCommand::new(
            cookie.to_owned(),
            confirmation.to_owned(),
            country.map(str::to_owned),
        )?;
        self.flow_service(authentication)
            .confirm_magic_link_flow(command)
            .await
    }

    /// Request, land, and confirm: the full real login.
    pub(super) async fn login(
        &mut self,
        email: &NormalizedEmail,
        country: Option<&str>,
    ) -> Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError> {
        let token = self.request(email).await;
        let (cookie, confirmation) = self.land(&token).await?;
        let store = self.store.clone();
        self.confirm_with(&store, &cookie, &confirmation, country)
            .await
    }

    /// Logout: server-side revocation through the flow service.
    pub(super) async fn logout(
        &mut self,
        session_id: &SessionId,
    ) -> Result<(), MagicLinkServiceError> {
        let store = self.store.clone();
        self.flow_service(&store).revoke_session(session_id).await
    }

    pub(super) async fn validate(
        &self,
        cookie: &str,
        country: Option<&str>,
    ) -> Result<ValidatedSession, SessionValidationError> {
        validate_session(
            cookie,
            country,
            &self.session_keyring,
            &self.store,
            &self.clock,
            &self.config,
        )
        .await
    }

    pub(super) fn refresh(
        &mut self,
        validated: &ValidatedSession,
    ) -> Result<Option<RefreshedSessionCookie>, SessionValidationError> {
        refresh_session_cookie(
            validated,
            &self.session_keyring,
            &mut self.rng,
            &self.clock,
            &self.config,
        )
    }

    pub(super) fn admin_with<'a, Repository>(
        &'a mut self,
        repository: &'a Repository,
    ) -> AuthAdminService<'a, Repository, ManualClock, SplitMixRng> {
        AuthAdminService {
            admin: repository,
            clock: &self.clock,
            rng: &mut self.rng,
        }
    }

    fn flow_service<'a, Authentication>(
        &'a mut self,
        authentication: &'a Authentication,
    ) -> MagicLinkFlowService<
        'a,
        Authentication,
        FakeDynamoDbAuthStore,
        AllowAllLimiter,
        ManualClock,
        SplitMixRng,
    > {
        MagicLinkFlowService {
            authentication,
            sessions: &self.store,
            limiter: &AllowAllLimiter,
            clock: &self.clock,
            rng: &mut self.rng,
            lookup_hmac_key: &self.lookup_key,
            previous_lookup_hmac_key: None,
            confirm_keyring: &self.confirm_keyring,
            session_keyring: &self.session_keyring,
            config: self.config.clone(),
        }
    }

    /// Drop any injected fault an operation did not reach, so it cannot leak
    /// into the next operation.
    pub(super) fn clear_faults(&self) {
        let mut inner = self.store.lock_inner().expect("lock");
        inner.next_error = None;
        inner.fail_next_authentication_pre_commit = false;
        inner.disable_user_before_next_commit = None;
    }
}

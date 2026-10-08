//! App state, the development clock, keys, and startup errors.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use datadeft_magic_link_aws::{FakeDynamoDbAuthStore, FakeMagicLinkOutbox, StorageHmacKey};
use datadeft_magic_link_axum::{
    ConfirmCookieConfig, MagicLinkScannerFlowConfig, SameOriginPostConfig, SameOriginRedirect,
    SessionCookieConfig,
};
use datadeft_magic_link_service::{
    Clock, DependencyError, KeyId, KeyPurpose, KeyRing, KeySlot, LookupHmacKey,
    MagicLinkConfirmCookie, MagicLinkServiceConfig, RootSecret, SessionCookie,
};
use datadeft_pow_core::PowSecret;
use rand_core::{OsRng, RngCore};

use super::util::*;
use super::*;

#[derive(Debug)]
pub(super) struct SetupError(&'static str);

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Error for SetupError {}

#[derive(Clone)]
pub(super) struct AppState {
    /// Crate-shipped in-memory fake implementing every repository trait plus
    /// the rate limiter, mirroring the DynamoDB adapter's storage shape.
    pub(super) auth: FakeDynamoDbAuthStore,
    pub(super) outbox: FakeMagicLinkOutbox,
    /// App-owned PoW replay set (tid -> expiry). PoW admission is outside the
    /// magic-link protocol, so its replay store is application code.
    pub(super) pow_replay: Arc<Mutex<HashMap<String, u64>>>,
    pub(super) config: MagicLinkServiceConfig,
    pub(super) http_config: Arc<MagicLinkScannerFlowConfig>,
    pub(super) lookup_hmac_key: Arc<LookupHmacKey>,
    pub(super) confirm_keyring: Arc<KeyRing<MagicLinkConfirmCookie>>,
    pub(super) session_keyring: Arc<KeyRing<SessionCookie>>,
    pub(super) pow_secret: Arc<PowSecret>,
}

/// Wall clock for the example. The library never reads the clock itself. The
/// application supplies it.
pub(super) struct LocalClock;

impl Clock for LocalClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        current_unix()
    }
}

pub(super) fn build_state() -> AppResult<AppState> {
    let now_unix = current_unix().map_err(|_| SetupError("system clock before unix epoch"))?;
    let config = MagicLinkServiceConfig::new("example-terms-v1", "example-privacy-v1");
    config.validate()?;

    let lookup_hmac_key = Arc::new(LookupHmacKey::new(random_32()?));
    let confirm_keyring = Arc::new(development_keyring::<MagicLinkConfirmCookie>(
        "ml_flow_active",
        now_unix,
    )?);
    let session_keyring = Arc::new(development_keyring::<SessionCookie>(
        "session_active",
        now_unix,
    )?);
    let pow_secret = Arc::new(PowSecret::new(random_32()?));

    let session_cookie = SessionCookieConfig::local_development(&config)?;
    let http_config = MagicLinkScannerFlowConfig::new(
        SameOriginRedirect::parse("/auth/magic-link/consume")
            .map_err(|_| SetupError("invalid magic-link POST action"))?,
        SameOriginPostConfig::parse(LOCAL_ORIGIN)?,
        session_cookie,
        ConfirmCookieConfig::local_development_defaults(),
    )?;

    Ok(AppState {
        auth: FakeDynamoDbAuthStore::new(StorageHmacKey::new(random_32()?)),
        outbox: FakeMagicLinkOutbox::default(),
        pow_replay: Arc::default(),
        config,
        http_config: Arc::new(http_config),
        lookup_hmac_key,
        confirm_keyring,
        session_keyring,
        pow_secret,
    })
}

pub(super) fn development_keyring<P: KeyPurpose>(
    kid: &str,
    now_unix: u64,
) -> AppResult<KeyRing<P>> {
    let key_id = KeyId::parse(kid)?;
    let root = RootSecret::new(random_32()?);
    let key = root.derive_key::<P>(&key_id)?;
    let mint_until = now_unix
        .checked_add(90 * 24 * 60 * 60)
        .ok_or(SetupError("development key mint window overflow"))?;
    let verify_until = mint_until
        .checked_add(P::MAX_ABSOLUTE_AGE_SECS)
        .ok_or(SetupError("development key verify window overflow"))?;
    KeyRing::new(vec![KeySlot::active_with_windows(
        key_id,
        key,
        mint_until,
        verify_until,
    )])
    .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
}

pub(super) fn random_32() -> AppResult<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SetupError("operating-system randomness unavailable"))?;
    Ok(bytes)
}

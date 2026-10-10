//! App state, the development clock, keys, and startup errors.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use datadeft_magic_link_aws::{FakeDynamoDbAuthStore, FakeMagicLinkOutbox, LoadedAuthSecrets};
use datadeft_magic_link_axum::{
    ConfirmCookieConfig, MagicLinkScannerFlowConfig, SameOriginPostConfig, SameOriginRedirect,
    SessionCookieConfig,
};
use datadeft_magic_link_service::{
    Clock, DependencyError, KeyRing, LookupHmacKey, MagicLinkConfirmCookie, MagicLinkServiceConfig,
    SessionCookie,
};
use datadeft_pow_core::{PowProofCookie, PowSecret};
use rand_core::{OsRng, RngCore};

use super::util::current_unix;
use super::*;

#[derive(Debug)]
struct SetupError(&'static str);

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

    // Production loads this document from AWS Secrets Manager
    // (`resolve_auth_secrets`); the example generates one with fresh keys so
    // every key takes the same path.
    let secrets = LoadedAuthSecrets::from_json(&development_secret_document(now_unix)?, None)
        .map_err(|_| SetupError("invalid development secret document"))?;
    // Built at startup so a `kid` too long for the proof cookie fails here.
    // The proof cookie itself arrives with the per-solve PoW budget.
    secrets
        .pow_proof_keyring::<PowProofCookie>()
        .map_err(|_| SetupError("invalid PoW proof-cookie keyring"))?;
    let pow_secret = Arc::new(PowSecret::new(*secrets.pow_challenge_secret.as_bytes()));
    let LoadedAuthSecrets {
        lookup_hmac_key,
        storage_hmac_key,
        confirm_keyring,
        session_keyring,
        ..
    } = secrets;

    let session_cookie = SessionCookieConfig::insecure_local(&config)?;
    let http_config = MagicLinkScannerFlowConfig::new(
        SameOriginRedirect::parse("/auth/magic-link/consume")
            .map_err(|_| SetupError("invalid magic-link POST action"))?,
        SameOriginPostConfig::parse(LOCAL_ORIGIN)?,
        session_cookie,
        ConfirmCookieConfig::insecure_local_defaults(),
    )?;

    Ok(AppState {
        auth: FakeDynamoDbAuthStore::new(storage_hmac_key),
        outbox: FakeMagicLinkOutbox::default(),
        pow_replay: Arc::default(),
        config,
        http_config: Arc::new(http_config),
        lookup_hmac_key: Arc::new(lookup_hmac_key),
        confirm_keyring: Arc::new(confirm_keyring),
        session_keyring: Arc::new(session_keyring),
        pow_secret,
    })
}

/// A secret document shaped like the production one (docs/security.md, "Auth
/// secret document"), with an independent random key per field.
fn development_secret_document(now_unix: u64) -> AppResult<String> {
    let mint_until = now_unix
        .checked_add(90 * 24 * 60 * 60)
        .ok_or(SetupError("development key mint window overflow"))?;
    // Covers the longest purpose lifetime (the 30-day session) plus a day.
    let verify_until = mint_until
        .checked_add(31 * 24 * 60 * 60)
        .ok_or(SetupError("development key verify window overflow"))?;
    let key = || random_32().map(|bytes| STANDARD.encode(bytes));
    Ok(serde_json::json!({
        "kid": "dev-active",
        "mint_until_unix": mint_until,
        "verify_until_unix": verify_until,
        "magic_link_lookup_hmac_b64": key()?,
        "storage_hmac_b64": key()?,
        "session_cookie_root_b64": key()?,
        "magic_link_confirm_cookie_root_b64": key()?,
        "pow_challenge_secret_b64": key()?,
        "pow_proof_cookie_root_b64": key()?,
    })
    .to_string())
}

fn random_32() -> AppResult<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SetupError("operating-system randomness unavailable"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets_with_kid(kid: &str) -> LoadedAuthSecrets {
        let mut document: serde_json::Value =
            serde_json::from_str(&development_secret_document(1_000).expect("document"))
                .expect("json");
        document["kid"] = serde_json::Value::from(kid);
        LoadedAuthSecrets::from_json(&document.to_string(), None).expect("loaded")
    }

    /// Pins the aws crate's documented 12-byte `kid` limit against the real
    /// proof-cookie purpose; the aws crate itself only tests a mirror of it.
    #[test]
    fn the_real_pow_proof_cookie_takes_a_kid_of_at_most_twelve_bytes() {
        assert!(
            secrets_with_kid("abcdefghijkl")
                .pow_proof_keyring::<PowProofCookie>()
                .is_ok()
        );
        assert!(
            secrets_with_kid("abcdefghijklm")
                .pow_proof_keyring::<PowProofCookie>()
                .is_err()
        );
    }
}

//! Fake store integration tests.

use dd_auth_token_core::keyring::{KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret, SessionCookie};
use dd_magic_link_core::{LookupHmacKey, NormalizedEmail, selector_lookup_hmac};
use dd_magic_link_service::{
    ClientKey, Clock, ConsumeMagicLinkError, DependencyError, EmailLocale, MagicLinkConsumeService,
    MagicLinkConsumeServiceInputs, MagicLinkRequestService, MagicLinkRequestServiceInputs,
    MagicLinkServiceConfig, RateLimitDecision, RateLimitKey, RateLimiter, RequestMagicLinkCommand,
    SessionRepository,
};
use rand_core::{CryptoRng, RngCore};

use super::*;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        Ok(1_000)
    }
}

struct CounterRng {
    next: u8,
}

impl CounterRng {
    fn new() -> Self {
        Self { next: 0 }
    }
}

impl RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CounterRng {}

fn session_keyring() -> KeyRing<SessionCookie> {
    let kid = KeyId::parse("active").expect("kid");
    let root = RootSecret::new([0x11; 32]);
    let key = root.derive_key::<SessionCookie>(&kid).expect("derive key");
    KeyRing::new(
        kid.clone(),
        vec![KeySlot::active_with_windows(
            kid,
            key,
            10_000,
            10_000 + SessionCookie::MAX_ABSOLUTE_AGE_SECS,
        )],
    )
    .expect("keyring")
}

fn command() -> RequestMagicLinkCommand {
    RequestMagicLinkCommand::new(
        NormalizedEmail::parse("user@example.com").expect("email"),
        EmailLocale::En,
        true,
        true,
        Some(ClientKey::parse("client-1").expect("client key")),
    )
}

#[tokio::test]
async fn fake_store_round_trips_request_and_consume_without_raw_session_storage() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let mut rng = CounterRng::new();
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let session_keyring = session_keyring();
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");

    {
        let mut request = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        });
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }

    let email = outbox.recorded().expect("recorded").remove(0);
    let selector_lookup = selector_lookup_hmac(&lookup_key, email.token.selector()).expect("hmac");
    assert!(
        store
            .magic_link_record(&selector_lookup)
            .expect("record")
            .is_some()
    );

    let outcome = {
        let mut consume = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
            magic_links: &store,
            users: &store,
            sessions: &store,
            limiter: &store,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            session_keyring: &session_keyring,
            config,
        });
        consume
            .consume_magic_link_token(&email.token.as_secret_value(), None, None)
            .await
            .expect("consume")
    };

    assert_eq!(store.user_count().expect("user count"), 1);
    assert_eq!(store.session_count().expect("session count"), 1);
    assert!(
        store
            .find_session(&outcome.session_id)
            .await
            .expect("find")
            .is_some()
    );

    let storage_keys = store.session_storage_keys().expect("storage keys");
    assert_eq!(storage_keys.len(), 1);
    assert!(storage_keys[0].starts_with("sih_"));
    assert!(!storage_keys[0].contains(outcome.session_id.as_str()));
}

#[tokio::test]
async fn fake_consume_rejects_second_use() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let outbox = crate::FakeMagicLinkOutbox::default();
    let clock = FixedClock;
    let mut rng = CounterRng::new();
    let lookup_key = LookupHmacKey::new([0x42; 32]);
    let session_keyring = session_keyring();
    let config = MagicLinkServiceConfig::new("terms-v1", "privacy-v1");

    {
        let mut request = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
            magic_links: &store,
            limiter: &store,
            outbox: &outbox,
            clock: &clock,
            rng: &mut rng,
            lookup_hmac_key: &lookup_key,
            config: config.clone(),
        });
        request
            .request_magic_link(command())
            .await
            .expect("request");
    }
    let token = outbox.recorded().expect("recorded")[0]
        .token
        .as_secret_value();

    let mut consume = MagicLinkConsumeService::new(MagicLinkConsumeServiceInputs {
        magic_links: &store,
        users: &store,
        sessions: &store,
        limiter: &store,
        clock: &clock,
        rng: &mut rng,
        lookup_hmac_key: &lookup_key,
        session_keyring: &session_keyring,
        config,
    });
    consume
        .consume_magic_link_token(&token, None, None)
        .await
        .expect("first consume");
    assert!(
        consume
            .consume_magic_link_token(&token, None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fake_store_maps_next_error_to_consume_dependency_failure() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let lookup = LookupHmacKey::new([0x42; 32]);
    let token =
        dd_magic_link_core::MagicLinkToken::generate(&mut CounterRng::new()).expect("token");
    let selector_lookup = selector_lookup_hmac(&lookup, token.selector()).expect("selector hmac");
    let verifier_hash = dd_magic_link_core::verifier_hash(&lookup, token.verifier()).expect("vh");

    store
        .set_next_error(crate::AwsAdapterError::DependencyUnavailable)
        .expect("set error");
    assert_eq!(
        store
            .consume_magic_link(&selector_lookup, &verifier_hash, 1_000)
            .await
            .unwrap_err(),
        ConsumeMagicLinkError::DependencyUnavailable
    );
}

#[tokio::test]
async fn fake_limiter_uses_fixed_windows_from_service_clock() {
    let store = FakeDynamoDbAuthStore::new(StorageHmacKey::new([0x24; 32]));
    let key = RateLimitKey::parse("magic-link:test:bucket").expect("rate key");

    assert_eq!(
        store
            .check_rate_limit(&key, 1, 60, 119)
            .await
            .expect("first hit"),
        RateLimitDecision::Allowed
    );
    assert_eq!(
        store
            .check_rate_limit(&key, 1, 60, 119)
            .await
            .expect("second same window"),
        RateLimitDecision::Denied
    );
    assert_eq!(
        store
            .check_rate_limit(&key, 1, 60, 120)
            .await
            .expect("new window"),
        RateLimitDecision::Allowed
    );
}

//! Integration tests against DynamoDB Local: the real condition expressions,
//! transactions, and cancellation reasons, which the in-memory fake only
//! mirrors. Run with `mise run dynamodb-local-test` (starts the container);
//! a plain `cargo test` skips them.
#![cfg(feature = "aws")]

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{Credentials, Region};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use datadeft_auth_token_core::test_support::test_keyring;
use datadeft_magic_link_aws::{DynamoDbAuthStore, FakeMagicLinkOutbox, StorageHmacKey};
use datadeft_magic_link_core::{MagicLinkToken, selector_lookup_hmac, verifier_hash};
use datadeft_magic_link_service::{
    AdminActor, AuthAdminService, AuthenticationAttemptId, BeginMagicLinkLandingCommand, Clock,
    CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, DependencyError, KeyRing, LookupHmacKey,
    MagicLinkAuthenticationExpectation, MagicLinkAuthenticationRepository,
    MagicLinkAuthenticationUser, MagicLinkConfirmCookie, MagicLinkFlowService, MagicLinkRecord,
    MagicLinkRepository, MagicLinkRequestService, MagicLinkServiceConfig, NormalizedEmail,
    RequestMagicLinkCommand, SessionCookie, SessionId, UserId, validate_session,
};
use rand_core::{OsRng, RngCore};

/// DynamoDB treats the attempt id (the transaction's `ClientRequestToken`) as
/// idempotent across the whole account for 10 minutes, so every id here is
/// random, as in production.
fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

struct WallClock;

impl Clock for WallClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| DependencyError::Internal)
    }
}

fn now() -> u64 {
    WallClock.now_unix().expect("clock")
}

async fn client() -> Client {
    let endpoint = std::env::var("DYNAMODB_LOCAL_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:18000".to_owned());
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(Region::new("eu-central-1"))
        .credentials_provider(Credentials::new(
            "local",
            "local",
            None,
            None,
            "dynamodb-local",
        ))
        .endpoint_url(endpoint)
        .build();
    Client::from_conf(config)
}

/// A fresh table per test: the library's single-table layout (`pk`, `sk`).
async fn table(client: &Client, name: &str) -> String {
    let table = format!("{name}-{}", now());
    let attribute = |name: &str| {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(ScalarAttributeType::S)
            .build()
            .expect("attribute")
    };
    let key = |name: &str, kind| {
        KeySchemaElement::builder()
            .attribute_name(name)
            .key_type(kind)
            .build()
            .expect("key")
    };
    client
        .create_table()
        .table_name(&table)
        .attribute_definitions(attribute("pk"))
        .attribute_definitions(attribute("sk"))
        .key_schema(key("pk", KeyType::Hash))
        .key_schema(key("sk", KeyType::Range))
        .billing_mode(BillingMode::PayPerRequest)
        .send()
        .await
        .expect("create table (is DynamoDB Local running?)");
    table
}

struct Keys {
    lookup: LookupHmacKey,
    confirm: KeyRing<MagicLinkConfirmCookie>,
    session: KeyRing<SessionCookie>,
    config: MagicLinkServiceConfig,
}

fn keys() -> Keys {
    Keys {
        lookup: LookupHmacKey::new([0x41; 32]),
        confirm: test_keyring(0x42, "flow"),
        session: test_keyring(0x43, "session"),
        config: MagicLinkServiceConfig::new("terms-v1", "privacy-v1"),
    }
}

/// Request a link, land, and confirm, all against `store`.
async fn login(
    store: &DynamoDbAuthStore,
    keys: &Keys,
    rng: &mut OsRng,
    email: &str,
) -> ConfirmMagicLinkFlowOutcome {
    let outbox = FakeMagicLinkOutbox::default();
    MagicLinkRequestService {
        magic_links: store,
        limiter: store,
        outbox: &outbox,
        clock: &WallClock,
        rng: &mut *rng,
        lookup_hmac_key: &keys.lookup,
        config: keys.config.clone(),
    }
    .request_magic_link(RequestMagicLinkCommand::new(
        NormalizedEmail::parse(email).expect("email"),
        true,
        true,
    ))
    .await
    .expect("request link");
    let token = outbox
        .recorded()
        .expect("outbox")
        .last()
        .expect("email sent")
        .token
        .as_secret_value()
        .to_string();

    let mut flow = MagicLinkFlowService {
        authentication: store,
        sessions: store,
        limiter: store,
        clock: &WallClock,
        rng: &mut *rng,
        lookup_hmac_key: &keys.lookup,
        previous_lookup_hmac_key: None,
        confirm_keyring: &keys.confirm,
        session_keyring: &keys.session,
        config: keys.config.clone(),
    };
    let landing = flow
        .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(token))
        .await
        .expect("landing");
    flow.confirm_magic_link_flow(
        ConfirmMagicLinkFlowCommand::new(
            landing.confirm_cookie_value().to_owned(),
            landing.confirmation_value().to_owned(),
            None,
        )
        .expect("confirm command"),
    )
    .await
    .expect("confirm")
}

async fn session_is_valid(store: &DynamoDbAuthStore, keys: &Keys, cookie: &str) -> bool {
    validate_session(cookie, None, &keys.session, store, &WallClock, &keys.config)
        .await
        .is_ok()
}

#[tokio::test]
#[ignore = "needs DynamoDB Local: mise run dynamodb-local-test"]
async fn login_logout_and_relogin_against_dynamodb() {
    let client = client().await;
    let store = DynamoDbAuthStore::new(
        client.clone(),
        table(&client, "flow").await,
        StorageHmacKey::new([0x31; 32]),
    );
    let keys = keys();
    let mut rng = OsRng;

    let first = login(&store, &keys, &mut rng, "flow@example.test").await;
    let first = first.authentication();
    assert!(first.user_created());
    assert!(session_is_valid(&store, &keys, first.session_cookie_value()).await);

    let second = login(&store, &keys, &mut rng, "flow@example.test").await;
    assert!(
        !second.authentication().user_created(),
        "existing user found"
    );
    assert_eq!(second.authentication().user_id(), first.user_id());
}

#[tokio::test]
#[ignore = "needs DynamoDB Local: mise run dynamodb-local-test"]
async fn rolling_rotation_keeps_one_account() {
    let client = client().await;
    let table = table(&client, "rotation").await;
    let old_node = DynamoDbAuthStore::new(
        client.clone(),
        table.clone(),
        StorageHmacKey::new([0x31; 32]),
    );
    let new_node = DynamoDbAuthStore::new(client.clone(), table, StorageHmacKey::new([0x32; 32]))
        .with_previous_storage_hmac_key(StorageHmacKey::new([0x31; 32]));
    let keys = keys();
    let mut rng = OsRng;

    let signup = login(&new_node, &keys, &mut rng, "rotate@example.test").await;
    let again = login(&old_node, &keys, &mut rng, "rotate@example.test").await;
    assert!(signup.authentication().user_created());
    assert!(
        !again.authentication().user_created(),
        "old node finds the account"
    );
    assert_eq!(
        again.authentication().user_id(),
        signup.authentication().user_id()
    );
}

/// A commit command for a fresh magic-link record, stored first.
/// A previous storage key equal to the current one is dropped. Kept, a
/// sign-up would put the same email row twice in one transaction, which
/// DynamoDB refuses for every new user.
#[tokio::test]
#[ignore = "needs DynamoDB Local: mise run dynamodb-local-test"]
async fn a_previous_key_equal_to_the_current_one_still_signs_up() {
    let client = client().await;
    let table = table(&client, "samekey").await;
    let store = DynamoDbAuthStore::new(client, table, StorageHmacKey::new([0x31; 32]))
        .with_previous_storage_hmac_key(StorageHmacKey::new([0x31; 32]));
    let keys = keys();
    let mut rng = OsRng;

    let signup = login(&store, &keys, &mut rng, "same-key@example.test").await;
    let again = login(&store, &keys, &mut rng, "same-key@example.test").await;
    assert!(signup.authentication().user_created());
    assert_eq!(
        again.authentication().user_id(),
        signup.authentication().user_id()
    );
}

async fn seeded_commit(
    store: &DynamoDbAuthStore,
    rng: &mut OsRng,
    email: &str,
    user: &str,
    attempt: &str,
    session: &str,
) -> CommitMagicLinkAuthentication {
    let lookup = LookupHmacKey::new([0x41; 32]);
    let token = MagicLinkToken::generate(rng).expect("token");
    let selector = selector_lookup_hmac(&lookup, token.selector()).expect("selector");
    let at = now();
    let record = MagicLinkRecord {
        selector_lookup_hmac: selector.clone(),
        email: NormalizedEmail::parse(email).expect("email"),
        verifier_hash: verifier_hash(&lookup, token.verifier()).expect("verifier"),
        expires_at_unix: at + 600,
        consumed_at_unix: None,
        terms_version: "terms-v1".to_owned(),
        privacy_version: "privacy-v1".to_owned(),
        consented_at_unix: at,
    };
    store
        .put_magic_link_if_absent(record.clone())
        .await
        .expect("seed link");
    CommitMagicLinkAuthentication {
        magic_link: MagicLinkAuthenticationExpectation {
            selector_lookup_hmac: selector,
            email: record.email.clone(),
            expires_at_unix: record.expires_at_unix,
            terms_version: record.terms_version.clone(),
            privacy_version: record.privacy_version.clone(),
            consented_at_unix: record.consented_at_unix,
        },
        now_unix: at,
        attempt_id: AuthenticationAttemptId::parse(attempt).expect("attempt"),
        user: MagicLinkAuthenticationUser::Create {
            user_id: UserId::parse(user).expect("user"),
        },
        session_id: SessionId::parse(session).expect("session"),
        session_expires_at_unix: at + 3_600,
    }
}

/// Cancelled creates classify by the real cancellation reasons, both with the
/// five-action transaction and with the six actions a rotation adds (the
/// previous-key email row). A regression once mapped every six-action
/// cancellation to `Internal`.
#[tokio::test]
#[ignore = "needs DynamoDB Local: mise run dynamodb-local-test"]
async fn cancelled_creates_classify_by_reason_with_and_without_rotation() {
    let client = client().await;
    for rotating in [false, true] {
        let mut store = DynamoDbAuthStore::new(
            client.clone(),
            table(&client, if rotating { "cancel-rot" } else { "cancel" }).await,
            StorageHmacKey::new([0x32; 32]),
        );
        if rotating {
            store = store.with_previous_storage_hmac_key(StorageHmacKey::new([0x31; 32]));
        }
        let mut rng = OsRng;

        let (user_1, user_2) = (
            format!("usr_{}", random_hex(16)),
            format!("usr_{}", random_hex(16)),
        );
        let first = seeded_commit(
            &store,
            &mut rng,
            "race@example.test",
            &user_1,
            &format!("aid_{}", random_hex(16)),
            &format!("sid_{}", random_hex(32)),
        )
        .await;
        store
            .commit_magic_link_authentication(&first)
            .await
            .expect("first create");

        // The same link again: the challenge condition fails.
        let replay = CommitMagicLinkAuthentication {
            attempt_id: AuthenticationAttemptId::parse(&format!("aid_{}", random_hex(16)))
                .expect("attempt"),
            session_id: SessionId::parse(&format!("sid_{}", random_hex(32))).expect("session"),
            ..first.clone()
        };
        assert_eq!(
            store
                .commit_magic_link_authentication(&replay)
                .await
                .unwrap_err(),
            CommitMagicLinkAuthenticationError::Rejected,
            "replayed link, rotating = {rotating}"
        );

        // A second link for the same new email, racing to create another user:
        // the email-row condition fails.
        let racing = seeded_commit(
            &store,
            &mut rng,
            "race@example.test",
            &user_2,
            &format!("aid_{}", random_hex(16)),
            &format!("sid_{}", random_hex(32)),
        )
        .await;
        assert_eq!(
            store
                .commit_magic_link_authentication(&racing)
                .await
                .unwrap_err(),
            CommitMagicLinkAuthenticationError::UserConflict,
            "racing create, rotating = {rotating}"
        );
    }
}

/// Disable ends every session; enable revokes first and lets a new login in.
#[tokio::test]
#[ignore = "needs DynamoDB Local: mise run dynamodb-local-test"]
async fn disable_and_enable_against_dynamodb() {
    let client = client().await;
    let store = DynamoDbAuthStore::new(
        client.clone(),
        table(&client, "admin").await,
        StorageHmacKey::new([0x31; 32]),
    );
    let keys = keys();
    let mut rng = OsRng;

    let login_one = login(&store, &keys, &mut rng, "admin@example.test").await;
    let user = login_one.authentication().user_id().clone();
    let old_cookie = login_one.authentication().session_cookie_value().to_owned();
    assert!(session_is_valid(&store, &keys, &old_cookie).await);

    let actor = AdminActor::new("ops", None).expect("actor");
    let mut admin = AuthAdminService {
        admin: &store,
        clock: &WallClock,
        rng: &mut rng,
    };
    let revoked = admin.disable_user(&user, &actor).await.expect("disable");
    assert_eq!(revoked, 1);
    assert!(
        !session_is_valid(&store, &keys, &old_cookie).await,
        "disabled"
    );
    assert_eq!(
        admin
            .disable_user(&user, &actor)
            .await
            .expect("repeat disable"),
        0
    );

    admin.enable_user(&user, &actor).await.expect("enable");
    assert!(
        !session_is_valid(&store, &keys, &old_cookie).await,
        "old session stays dead"
    );

    // The strict whole-second cutoff (0.4) rejects a login in the enable's own
    // second; wait for the next one. (0.5.0 makes the cutoff inclusive.)
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let login_two = login(&store, &keys, &mut rng, "admin@example.test").await;
    assert_eq!(login_two.authentication().user_id(), &user);
    assert!(
        session_is_valid(
            &store,
            &keys,
            login_two.authentication().session_cookie_value()
        )
        .await
    );
}

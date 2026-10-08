//! The atomic authentication commit ("aggregate") on the fake store.

//! Fake store integration tests.

use datadeft_magic_link_service::{
    AuthenticationAttemptId, CommitMagicLinkAuthenticationError, MagicLinkAuthenticationRepository,
    MagicLinkAuthenticationUser, SessionId, SessionRecord, SessionRepository, UserId,
};

use super::test_support::*;
use super::*;

#[tokio::test]
async fn aggregate_existing_user_commit_is_atomic_and_preserves_consent() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Existing {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store.seed_user(user_record(false)).expect("seed user");

    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("commit");

    let stored_user = store
        .find_user_for_authentication(&command.magic_link.email)
        .await
        .expect("find user")
        .expect("stored user");
    assert_eq!(stored_user.terms_version.as_deref(), Some("old-terms"));
    assert_eq!(stored_user.consented_at_unix, Some(100));
    assert_eq!(store.session_count().expect("sessions"), 1);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        Some(command.now_unix)
    );
    assert!(
        store
            .find_session(&command.session_id, command.session_expires_at_unix)
            .await
            .expect("find at expiry")
            .is_some()
    );
    assert!(
        store
            .find_session(&command.session_id, command.session_expires_at_unix + 1,)
            .await
            .expect("find after expiry")
            .is_none()
    );
}

#[tokio::test]
async fn aggregate_create_commit_derives_enabled_user_and_session() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;

    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("commit");

    let user = store
        .find_user_for_authentication(&command.magic_link.email)
        .await
        .expect("find user")
        .expect("created user");
    assert_eq!(user.user_id, user_id);
    assert!(!user.disabled);
    assert_eq!(user.terms_version.as_deref(), Some("terms-v1"));
    assert_eq!(user.privacy_version.as_deref(), Some("privacy-v1"));
    assert_eq!(user.consented_at_unix, Some(900));
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(store.session_count().expect("sessions"), 1);
    assert_eq!(
        store
            .user_session_index_entries(&user.user_id)
            .expect("index")[0]
            .expires_at_unix,
        command.session_expires_at_unix
    );
}

#[tokio::test]
async fn aggregate_rejects_stale_challenge_states_without_mutation() {
    for state in [
        "consumed",
        "expired",
        "consent",
        "zero-consent",
        "terms",
        "privacy",
    ] {
        let user_id = UserId::parse(USER_ID).expect("user id");
        let (store, mut record, mut command) = authentication_fixture(
            MagicLinkAuthenticationUser::Create { user_id },
            ATTEMPT_ID,
            SESSION_ID,
        );
        match state {
            "consumed" => record.consumed_at_unix = Some(999),
            "expired" => command.now_unix = 2_001,
            "consent" => command.magic_link.consented_at_unix += 1,
            "zero-consent" => {
                record.consented_at_unix = 0;
                command.magic_link.consented_at_unix = 0;
            }
            "terms" => command.magic_link.terms_version = "terms-v2".to_owned(),
            "privacy" => command.magic_link.privacy_version = "privacy-v2".to_owned(),
            _ => unreachable!("fixed test state"),
        }
        seed_challenge(&store, record).await;
        assert_eq!(
            store.commit_magic_link_authentication(&command).await,
            Err(CommitMagicLinkAuthenticationError::Rejected),
            "state {state}"
        );
        assert_eq!(store.user_count().expect("users"), 0);
        assert_eq!(store.session_count().expect("sessions"), 0);
    }
}

#[tokio::test]
async fn aggregate_disabled_user_and_user_conflicts_do_not_burn_link() {
    for disabled in [true, false] {
        let planned_id = if disabled {
            UserId::parse(USER_ID).expect("user id")
        } else {
            UserId::parse("usr_101112131415161718191a1b1c1d1e1f").expect("other user id")
        };
        let (store, record, command) = authentication_fixture(
            MagicLinkAuthenticationUser::Existing {
                user_id: planned_id,
            },
            ATTEMPT_ID,
            SESSION_ID,
        );
        seed_challenge(&store, record).await;
        store.seed_user(user_record(disabled)).expect("seed user");
        assert_eq!(
            store.commit_magic_link_authentication(&command).await,
            Err(CommitMagicLinkAuthenticationError::UserConflict)
        );
        assert_eq!(store.session_count().expect("sessions"), 0);
        assert_eq!(
            store
                .magic_link_record(&command.magic_link.selector_lookup_hmac)
                .expect("challenge")
                .expect("stored challenge")
                .consumed_at_unix,
            None
        );
    }
}

#[tokio::test]
async fn aggregate_session_conflict_is_atomic() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store
        .seed_session(
            SessionRecord {
                session_id: command.session_id.clone(),
                user_id,
                email: command.magic_link.email.clone(),
                created_at_unix: 500,
                revoked_at_unix: None,
            },
            command.session_expires_at_unix,
        )
        .expect("seed session collision");
    assert_eq!(
        store.commit_magic_link_authentication(&command).await,
        Err(CommitMagicLinkAuthenticationError::SessionConflict)
    );
    assert_eq!(store.user_count().expect("users"), 0);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        None
    );
}

#[tokio::test]
async fn aggregate_next_error_mapping_is_scrubbed_and_has_no_partial_mutation() {
    for (adapter_error, expected) in [
        (
            AwsAdapterError::ConditionalWriteFailed,
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
        ),
        (
            AwsAdapterError::RateLimited,
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
        ),
        (
            AwsAdapterError::DependencyUnavailable,
            CommitMagicLinkAuthenticationError::DependencyUnavailable,
        ),
        (
            AwsAdapterError::Internal,
            CommitMagicLinkAuthenticationError::Internal,
        ),
    ] {
        let (store, record, command) = authentication_fixture(
            MagicLinkAuthenticationUser::Create {
                user_id: UserId::parse(USER_ID).expect("user id"),
            },
            ATTEMPT_ID,
            SESSION_ID,
        );
        seed_challenge(&store, record).await;
        store.set_next_error(adapter_error).expect("inject error");

        assert_eq!(
            store.commit_magic_link_authentication(&command).await,
            Err(expected)
        );
        assert_eq!(store.user_count().expect("users"), 0);
        assert_eq!(store.session_count().expect("sessions"), 0);
        assert_eq!(
            store
                .magic_link_record(&command.magic_link.selector_lookup_hmac)
                .expect("challenge")
                .expect("stored challenge")
                .consumed_at_unix,
            None
        );
    }
}

#[tokio::test]
async fn aggregate_pre_commit_dependency_failure_has_no_authentication_mutation() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store
        .fail_next_authentication_pre_commit()
        .expect("inject pre-commit failure");

    assert_eq!(
        store.commit_magic_link_authentication(&command).await,
        Err(CommitMagicLinkAuthenticationError::DependencyUnavailable)
    );
    assert_eq!(store.user_count().expect("users"), 0);
    assert_eq!(store.session_count().expect("sessions"), 0);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        None
    );
}

#[tokio::test]
async fn aggregate_rejects_session_expiry_before_now_without_mutation() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, mut command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    command.session_expires_at_unix = command.now_unix - 1;

    assert_eq!(
        store.commit_magic_link_authentication(&command).await,
        Err(CommitMagicLinkAuthenticationError::Internal)
    );
    assert_eq!(store.user_count().expect("users"), 0);
    assert_eq!(store.session_count().expect("sessions"), 0);
    assert_eq!(
        store
            .magic_link_record(&command.magic_link.selector_lookup_hmac)
            .expect("challenge")
            .expect("stored challenge")
            .consumed_at_unix,
        None
    );
}

#[tokio::test]
async fn aggregate_attempt_id_is_exact_payload_idempotency_key() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;
    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("first commit");
    store
        .commit_magic_link_authentication(&command)
        .await
        .expect("exact retry");
    assert_eq!(store.session_count().expect("sessions"), 1);

    let mut changed = command.clone();
    changed.session_expires_at_unix += 1;
    assert_eq!(
        store.commit_magic_link_authentication(&changed).await,
        Err(CommitMagicLinkAuthenticationError::Internal)
    );
}

// Multi-threaded so the racing confirmations really run in parallel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aggregate_replay_race_has_exactly_one_commit() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, base_command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create {
            user_id: user_id.clone(),
        },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record).await;

    let mut tasks = Vec::new();
    for index in 0_u128..16 {
        let task_store = store.clone();
        let mut task_command = base_command.clone();
        task_command.attempt_id =
            AuthenticationAttemptId::parse(&format!("aid_{index:032x}")).expect("race attempt id");
        task_command.session_id =
            SessionId::parse(&format!("sid_{index:064x}")).expect("race session id");
        tasks.push(tokio::spawn(async move {
            task_store
                .commit_magic_link_authentication(&task_command)
                .await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("race task"));
    }
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| { **result == Err(CommitMagicLinkAuthenticationError::Rejected) })
            .count(),
        15
    );
    assert_eq!(store.user_count().expect("users"), 1);
    assert_eq!(store.session_count().expect("sessions"), 1);

    let mut replay = base_command;
    replay.attempt_id = AuthenticationAttemptId::parse(OTHER_ATTEMPT_ID).expect("replay attempt");
    replay.session_id = SessionId::parse(OTHER_SESSION_ID).expect("replay session");
    assert_eq!(
        store.commit_magic_link_authentication(&replay).await,
        Err(CommitMagicLinkAuthenticationError::Rejected)
    );
}

#[tokio::test]
async fn aggregate_reads_candidates_and_scrubs_store_debug() {
    let user_id = UserId::parse(USER_ID).expect("user id");
    let (store, record, command) = authentication_fixture(
        MagicLinkAuthenticationUser::Create { user_id },
        ATTEMPT_ID,
        SESSION_ID,
    );
    seed_challenge(&store, record.clone()).await;
    let candidate = store
        .find_magic_link_for_authentication(&command.magic_link.selector_lookup_hmac)
        .await
        .expect("candidate")
        .expect("stored candidate");
    assert_eq!(candidate.email, record.email);
    assert!(
        candidate
            .verifier_hash
            .matches_hash_constant_time(&record.verifier_hash)
    );
    assert_eq!(format!("{store:?}"), "FakeDynamoDbAuthStore(..)");
}

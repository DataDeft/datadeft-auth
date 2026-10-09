//! Storage-HMAC rotation model: users and sessions created under older storage
//! keys, rotations with `previous` fallback, `rekey_email_lookups`, dropping
//! the previous key, logins, lookups, and session validation, against the
//! fake store and the real services.
//!
//! The rotation procedure is the documented one (`docs/security.md`, "Rotating
//! the HMAC keys"): the previous key is dropped, or rotated out, only after
//! `rekey_email_lookups` has run. Under it:
//!
//! - every user stays resolvable by email at every step;
//! - one email never yields two user ids (no duplicate account);
//! - a session validates iff it is unrevoked and its storage key is current
//!   or previous: sessions survive a rotation and end only when their key is
//!   dropped.

use std::collections::BTreeSet;

use datadeft_magic_link_service::{
    MagicLinkServiceError, SessionId, SessionValidationError, UserId,
};
use proptest::prelude::*;

use super::model_support::*;
use super::*;

fn storage_key(generation: u8) -> StorageHmacKey {
    StorageHmacKey::new([0x30_u8.wrapping_add(generation); 32])
}

#[derive(Clone, Debug, Default)]
struct MUser {
    id: Option<UserId>,
    /// Key generations an email lookup row exists under.
    lookups: BTreeSet<u8>,
}

#[derive(Clone, Debug)]
struct MSession {
    id: SessionId,
    cookie: String,
    user: usize,
    generation: u8,
    revoked: bool,
}

#[derive(Default)]
struct Model {
    generation: u8,
    previous: Option<u8>,
    rekeyed: bool,
    users: [MUser; 2],
    sessions: Vec<MSession>,
}

impl Model {
    fn readable(&self, generation: u8) -> bool {
        generation == self.generation || self.previous == Some(generation)
    }

    /// Dropping (or rotating out) the previous key is safe once rekeyed.
    fn may_drop_previous(&self) -> bool {
        self.previous.is_none() || self.rekeyed
    }
}

#[derive(Clone, Debug)]
enum Op {
    Login { user: u8 },
    Rotate,
    Rekey,
    DropPrevious,
    Validate { session: u8 },
    Logout { session: u8 },
    RevokeAll { user: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0u8..2).prop_map(|user| Op::Login { user }),
        2 => Just(Op::Rotate),
        2 => Just(Op::Rekey),
        1 => Just(Op::DropPrevious),
        4 => any::<u8>().prop_map(|session| Op::Validate { session }),
        1 => any::<u8>().prop_map(|session| Op::Logout { session }),
        1 => (0u8..2).prop_map(|user| Op::RevokeAll { user }),
    ]
}

/// Point the harness at the shared data under the model's keys.
fn rekey_view(h: &mut Harness, base: &FakeDynamoDbAuthStore, m: &Model) {
    h.store = base.sharing_data_with_keys(storage_key(m.generation), m.previous.map(storage_key));
}

async fn apply(h: &mut Harness, base: &FakeDynamoDbAuthStore, m: &mut Model, op: &Op) {
    match *op {
        Op::Login { user } => {
            let user = usize::from(user);
            let outcome = h.login(&email(user), None).await.expect("login");
            let auth = outcome.authentication();
            let record = &mut m.users[user];
            match &record.id {
                Some(id) => {
                    assert_eq!(auth.user_id(), id, "one email, one user id");
                    assert!(!auth.user_created(), "login created a duplicate account");
                }
                None => {
                    assert!(auth.user_created());
                    record.id = Some(auth.user_id().clone());
                    // A create during a rotation also claims the previous-key
                    // row (spec/tla/KeyRotation.tla).
                    if let Some(previous) = m.previous {
                        record.lookups.insert(previous);
                    }
                }
            }
            // Found under the previous key, or created: either way the
            // lookup now exists under the current key.
            record.lookups.insert(m.generation);
            m.sessions.push(MSession {
                id: auth.session_id().clone(),
                cookie: auth.session_cookie_value().to_owned(),
                user,
                generation: m.generation,
                revoked: false,
            });
        }
        Op::Rotate => {
            if !m.may_drop_previous() {
                return;
            }
            m.previous = Some(m.generation);
            m.generation += 1;
            m.rekeyed = false;
            rekey_view(h, base, m);
        }
        Op::Rekey => {
            let missing = m
                .users
                .iter()
                .filter(|user| user.id.is_some() && !user.lookups.contains(&m.generation))
                .count();
            assert_eq!(
                h.store.rekey_email_lookups().expect("rekey"),
                missing,
                "rekey count"
            );
            for user in m.users.iter_mut().filter(|user| user.id.is_some()) {
                user.lookups.insert(m.generation);
            }
            m.rekeyed = true;
        }
        Op::DropPrevious => {
            if !m.may_drop_previous() {
                return;
            }
            m.previous = None;
            rekey_view(h, base, m);
        }
        Op::Validate { session } => {
            let Some(index) =
                (!m.sessions.is_empty()).then(|| usize::from(session) % m.sessions.len())
            else {
                return;
            };
            let record = &m.sessions[index];
            let result = h.validate(&record.cookie, None).await;
            let live = !record.revoked && m.readable(record.generation);
            assert_eq!(
                result.as_ref().map(|_| ()).map_err(|error| *error),
                if live {
                    Ok(())
                } else {
                    Err(SessionValidationError::InvalidSession)
                },
                "session validity across rotation"
            );
        }
        Op::Logout { session } => {
            let Some(index) =
                (!m.sessions.is_empty()).then(|| usize::from(session) % m.sessions.len())
            else {
                return;
            };
            let result = h.logout(&m.sessions[index].id.clone()).await;
            let readable = m.readable(m.sessions[index].generation);
            let record = &mut m.sessions[index];
            if readable && !record.revoked {
                assert_eq!(
                    result,
                    Ok(()),
                    "logout finds the session through the fallback"
                );
                record.revoked = true;
            } else {
                assert_eq!(result, Err(MagicLinkServiceError::Unavailable));
            }
        }
        Op::RevokeAll { user } => {
            let user = usize::from(user);
            let Some(id) = m.users[user].id.clone() else {
                return;
            };
            let store = h.store.clone();
            let revoked = h
                .admin_with(&store)
                .revoke_all_sessions(&id, &actor())
                .await
                .expect("revoke all");
            // The per-user index addresses sessions by their stored handle,
            // whatever key wrote it.
            let mut expected = 0;
            for session in m
                .sessions
                .iter_mut()
                .filter(|session| session.user == user && !session.revoked)
            {
                session.revoked = true;
                expected += 1;
            }
            assert_eq!(revoked, expected);
        }
    }
}

async fn check_state(h: &mut Harness, m: &Model) {
    {
        let inner = h.store.lock_inner().expect("lock");
        let known = m.users.iter().filter(|user| user.id.is_some()).count();
        assert_eq!(
            inner.user_profiles_by_id.len(),
            known,
            "one account per email"
        );
        for (index, user) in m.users.iter().enumerate() {
            let Some(id) = &user.id else { continue };
            for generation in 0..=m.generation {
                let key = storage_key(generation)
                    .hmac(
                        crate::hmac_key::EMAIL_LOOKUP_HMAC_PREFIX,
                        email(index).as_str(),
                    )
                    .expect("hmac");
                let row = inner.user_id_by_email_hmac.get(&key);
                assert_eq!(
                    row.is_some(),
                    user.lookups.contains(&generation),
                    "lookup rows"
                );
                if let Some(row) = row {
                    assert_eq!(row, id, "every lookup row names the one user id");
                }
            }
        }
    }
    // Every user resolves by email at every step.
    let store = h.store.clone();
    let admin = h.admin_with(&store);
    for (index, user) in m.users.iter().enumerate() {
        let found = admin.find_user_by_email(&email(index)).await.expect("find");
        assert_eq!(
            found.map(|summary| summary.user_id),
            user.id.clone(),
            "resolvable by email"
        );
    }
}

async fn run(ops: Vec<Op>, seed: u64) {
    let mut h = Harness::new(seed);
    let mut m = Model::default();
    let base = FakeDynamoDbAuthStore::new(storage_key(0));
    rekey_view(&mut h, &base, &m);
    for op in &ops {
        apply(&mut h, &base, &mut m, op).await;
        check_state(&mut h, &m).await;
        // Keep session timestamps distinct across steps.
        h.clock.set(h.now() + 1);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Storage-key rotation under the documented procedure keeps every user
    /// resolvable, never splits an account, and keeps sessions valid while
    /// their key is current or previous.
    #[test]
    fn storage_rotation_conforms_to_model(
        ops in prop::collection::vec(op(), 1..40),
        seed in any::<u64>(),
    ) {
        block_on(run(ops, seed));
    }
}

// --- deterministic probes --------------------------------------------------

/// A user whose only lookup row is under the previous key logs in during the
/// rotation window: found through the fallback, never re-created.
#[test]
fn login_with_lookup_only_under_previous_key_finds_the_same_account() {
    block_on(async {
        let mut h = Harness::new(7);
        let base = FakeDynamoDbAuthStore::new(storage_key(0));
        h.store = base.clone();
        let first = h.login(&email(0), None).await.expect("first login");
        h.store = base.sharing_data_with_keys(storage_key(1), Some(storage_key(0)));
        let second = h.login(&email(0), None).await.expect("second login");
        assert!(!second.authentication().user_created());
        assert_eq!(
            second.authentication().user_id(),
            first.authentication().user_id()
        );
        assert_eq!(h.store.user_count().expect("users"), 1);
    });
}

/// Documented hazard, pinned: rotating twice without `rekey_email_lookups`
/// drops the key that the only lookup row is under, and the next login
/// creates a second account for the same email.
#[test]
fn rotating_twice_without_rekey_splits_the_account() {
    block_on(async {
        let mut h = Harness::new(8);
        let base = FakeDynamoDbAuthStore::new(storage_key(0));
        h.store = base.clone();
        h.login(&email(0), None).await.expect("first login");
        h.store = base.sharing_data_with_keys(storage_key(2), Some(storage_key(1)));
        let second = h.login(&email(0), None).await.expect("second login");
        assert!(second.authentication().user_created());
        assert_eq!(h.store.user_count().expect("users"), 2);
    });
}

/// Rolling rotation, as in `spec/tla/KeyRotation.tla`: nodes on the new key
/// (current K1, previous K0) and nodes still on the old key (current K0)
/// serve the same table. A signup on a new node followed by a login on an old
/// node must reach the same account. Before the fix the create wrote only the
/// K1 row, the old node found nothing under K0, and created a second account.
#[test]
fn rolling_rotation_signup_on_new_node_then_login_on_old_node_is_one_account() {
    block_on(async {
        let mut h = Harness::new(9);
        let old_node = FakeDynamoDbAuthStore::new(storage_key(0));
        let new_node = old_node.sharing_data_with_keys(storage_key(1), Some(storage_key(0)));

        h.store = new_node.clone();
        let signup = h.login(&email(0), None).await.expect("signup on new node");
        assert!(signup.authentication().user_created());

        h.store = old_node.clone();
        let login = h.login(&email(0), None).await.expect("login on old node");
        assert!(!login.authentication().user_created());
        assert_eq!(
            login.authentication().user_id(),
            signup.authentication().user_id()
        );
        assert_eq!(h.store.user_count().expect("users"), 1);
    });
}

/// The other order: a signup on an old node, then a login on a new node,
/// which finds the account through the previous-key fallback.
#[test]
fn rolling_rotation_signup_on_old_node_then_login_on_new_node_is_one_account() {
    block_on(async {
        let mut h = Harness::new(10);
        let old_node = FakeDynamoDbAuthStore::new(storage_key(0));
        let new_node = old_node.sharing_data_with_keys(storage_key(1), Some(storage_key(0)));

        h.store = old_node.clone();
        let signup = h.login(&email(0), None).await.expect("signup on old node");

        h.store = new_node.clone();
        let login = h.login(&email(0), None).await.expect("login on new node");
        assert!(!login.authentication().user_created());
        assert_eq!(
            login.authentication().user_id(),
            signup.authentication().user_id()
        );
        assert_eq!(h.store.user_count().expect("users"), 1);
    });
}

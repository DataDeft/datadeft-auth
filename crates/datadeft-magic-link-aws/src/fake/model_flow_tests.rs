//! Magic-link flow model: random request / landing / confirm sequences,
//! including forged bindings, disabled users, expiry, ambiguous commits, and
//! racing confirms, against the real flow service and the fake store.
//!
//! Bridges `spec/tla/MagicLink.tla` and `spec/tla/MagicLinkRace.tla`:
//!
//! - ML-INV-001: the `GET` landing never consumes a link or creates state.
//! - ML-INV-002: at most one session per challenge, even under races.
//! - ML-INV-003: a challenge is consumed if and only if its session exists.
//! - ML-INV-004: a wrong selector, verifier, account, or nonce never consumes.
//! - ML-INV-005: a disabled user's confirm never burns the challenge.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use datadeft_magic_link_core::confirm_cookie::{MagicLinkConfirmBindings, mint_magic_link_confirm};
use datadeft_magic_link_core::{
    LookupHmac, MagicLinkToken, NormalizedEmail, confirm_account_binding, confirm_selector_binding,
    confirm_verifier_binding, email_lookup_hmac, selector_lookup_hmac, verifier_hash,
};
use datadeft_magic_link_service::{
    CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, ConfirmMagicLinkFlowCommand,
    ConfirmMagicLinkFlowOutcome, DependencyError, MagicLinkAuthenticationCandidate,
    MagicLinkAuthenticationRepository, MagicLinkFlowError, MagicLinkFlowService,
    MagicLinkServiceError, TemporaryAuthStateAction, UserId, UserRecord,
};
use proptest::prelude::*;
use rand_core::RngCore;
use tokio::sync::Barrier;

use super::model_support::*;
use super::test_support::AllowAllLimiter;
use super::*;

// --- reference model -------------------------------------------------------

#[derive(Clone, Debug)]
struct MLink {
    token: String,
    email: usize,
    expires: u64,
    consumed: bool,
    selector: LookupHmac,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Genuine,
    WrongSelector,
    WrongVerifier,
    WrongAccount,
    WrongNonce,
}

#[derive(Clone, Debug)]
struct MFlow {
    link: usize,
    cookie: String,
    confirmation: String,
    expires: u64,
    kind: Kind,
}

#[derive(Clone, Debug, Default)]
struct MUser {
    id: Option<UserId>,
    disabled: bool,
    watermark: Option<u64>,
}

#[derive(Default)]
struct Model {
    now: u64,
    links: Vec<MLink>,
    flows: Vec<MFlow>,
    users: [MUser; 2],
    sessions: usize,
}

impl Model {
    /// Whether confirming `flow` now creates a session.
    fn confirm_ok(&self, flow: &MFlow) -> bool {
        let link = &self.links[flow.link];
        let user = &self.users[link.email];
        flow.kind == Kind::Genuine
            && self.now <= flow.expires
            && self.now < link.expires
            && !link.consumed
            && !(user.id.is_some() && user.disabled)
    }

    /// Record a successful confirm of `flow` and check its outcome.
    fn record_success(&mut self, flow: &MFlow, outcome: &ConfirmMagicLinkFlowOutcome) {
        let auth = outcome.authentication();
        let link = &mut self.links[flow.link];
        assert!(
            !link.consumed,
            "ML-INV-002: a consumed link authenticated again"
        );
        link.consumed = true;
        self.sessions += 1;
        let user = &mut self.users[link.email];
        match &user.id {
            Some(id) => {
                assert_eq!(auth.user_id(), id, "one email, one user id");
                assert!(!auth.user_created());
            }
            None => {
                assert!(auth.user_created());
                user.id = Some(auth.user_id().clone());
            }
        }
    }
}

/// Everything a flow operation may change, for "nothing changed" checks.
#[derive(Debug, Eq, PartialEq)]
struct Fingerprint {
    consumed: Vec<(String, bool)>,
    sessions: usize,
    users: Vec<(String, bool)>,
    attempts: usize,
}

fn fingerprint(store: &FakeDynamoDbAuthStore) -> Fingerprint {
    let inner = store.lock_inner().expect("lock");
    let mut consumed: Vec<(String, bool)> = inner
        .magic_links_by_selector_hmac
        .iter()
        .map(|(key, record)| (key.clone(), record.consumed_at_unix.is_some()))
        .collect();
    consumed.sort();
    let mut users: Vec<(String, bool)> = inner
        .user_profiles_by_id
        .iter()
        .map(|(id, profile)| (id.clone(), profile.disabled))
        .collect();
    users.sort();
    Fingerprint {
        consumed,
        sessions: inner.sessions_by_hmac.len(),
        users,
        attempts: inner.authentication_attempts.len(),
    }
}

// --- repository wrappers ---------------------------------------------------

/// Commits for real, then reports the first `lost` results as ambiguous
/// `DependencyUnavailable`: a transaction that applied but lost its ack.
struct AckLossAuth {
    store: FakeDynamoDbAuthStore,
    lost: AtomicU8,
}

/// Waits at a shared barrier before its first commit, so two confirms plan
/// against the same state and then commit back to back.
struct BarrierAuth {
    store: FakeDynamoDbAuthStore,
    barrier: Arc<Barrier>,
    waited: AtomicBool,
}

impl MagicLinkAuthenticationRepository for AckLossAuth {
    async fn find_magic_link_for_authentication(
        &self,
        selector: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        self.store
            .find_magic_link_for_authentication(selector)
            .await
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        self.store.find_user_for_authentication(email).await
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        let result = self.store.commit_magic_link_authentication(command).await;
        let lost = self.lost.load(Ordering::SeqCst);
        if lost > 0 {
            self.lost.store(lost - 1, Ordering::SeqCst);
            return Err(CommitMagicLinkAuthenticationError::DependencyUnavailable);
        }
        result
    }
}

impl MagicLinkAuthenticationRepository for BarrierAuth {
    async fn find_magic_link_for_authentication(
        &self,
        selector: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        self.store
            .find_magic_link_for_authentication(selector)
            .await
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        self.store.find_user_for_authentication(email).await
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        if !self.waited.swap(true, Ordering::SeqCst) {
            self.barrier.wait().await;
        }
        self.store.commit_magic_link_authentication(command).await
    }
}

// --- operations ------------------------------------------------------------

#[derive(Clone, Debug)]
enum Op {
    Request {
        user: u8,
    },
    /// Request and land a genuine link in one step.
    Fresh {
        user: u8,
    },
    /// Request one or two fresh links for `user`, land, and race two confirms.
    RaceFresh {
        user: u8,
        same_link: bool,
    },
    /// Disable the flow's user, confirm (refused, not burned), enable, and
    /// confirm the same flow again in the same second.
    ReEnable {
        flow: u8,
    },
    /// Move the clock forward to `offset` seconds before the link expires,
    /// then land it: the flow cookie then outlives the link.
    LateLand {
        link: u8,
        offset: u64,
    },
    /// Move the clock forward to a boundary of the flow, then confirm it.
    ConfirmAt {
        flow: u8,
        target: u8,
    },
    /// `tamper`: 0 genuine token, 1 wrong verifier, 2 wrong selector.
    Land {
        link: u8,
        tamper: u8,
    },
    Forge {
        link: u8,
        kind: u8,
    },
    WrongNonce {
        flow: u8,
    },
    Confirm {
        flow: u8,
    },
    /// Disable the user between planning and commit.
    DisableRace {
        flow: u8,
    },
    PreCommitFailure {
        flow: u8,
    },
    AmbiguousCommit {
        flow: u8,
        lost: u8,
    },
    Race {
        first: u8,
        second: u8,
    },
    Disable {
        user: u8,
    },
    Enable {
        user: u8,
    },
    Advance(u64),
}

fn op() -> impl Strategy<Value = Op> {
    let steps = vec![1u64, 30, 59, 60, 61, 119, 120, 121];
    prop_oneof![
        2 => (0u8..2).prop_map(|user| Op::Request { user }),
        4 => (0u8..2).prop_map(|user| Op::Fresh { user }),
        2 => (0u8..2, any::<bool>()).prop_map(|(user, same_link)| Op::RaceFresh { user, same_link }),
        2 => any::<u8>().prop_map(|flow| Op::ReEnable { flow }),
        3 => (any::<u8>(), 0u8..4).prop_map(|(flow, target)| Op::ConfirmAt { flow, target }),
        2 => (any::<u8>(), prop::sample::select(vec![1u64, 30, 60, 61]))
            .prop_map(|(link, offset)| Op::LateLand { link, offset }),
        4 => (any::<u8>(), prop::sample::select(vec![0u8, 0, 0, 1, 2]))
            .prop_map(|(link, tamper)| Op::Land { link, tamper }),
        2 => (any::<u8>(), 0u8..3).prop_map(|(link, kind)| Op::Forge { link, kind }),
        1 => any::<u8>().prop_map(|flow| Op::WrongNonce { flow }),
        5 => any::<u8>().prop_map(|flow| Op::Confirm { flow }),
        2 => any::<u8>().prop_map(|flow| Op::DisableRace { flow }),
        1 => any::<u8>().prop_map(|flow| Op::PreCommitFailure { flow }),
        2 => (any::<u8>(), 1u8..=3).prop_map(|(flow, lost)| Op::AmbiguousCommit { flow, lost }),
        2 => (any::<u8>(), any::<u8>()).prop_map(|(first, second)| Op::Race { first, second }),
        1 => (0u8..2).prop_map(|user| Op::Disable { user }),
        2 => (0u8..2).prop_map(|user| Op::Enable { user }),
        3 => prop::sample::select(steps).prop_map(Op::Advance),
    ]
}

// --- driver ----------------------------------------------------------------

fn pick<T: Clone>(items: &[T], index: u8) -> Option<T> {
    (!items.is_empty()).then(|| items[usize::from(index) % items.len()].clone())
}

/// Change the last character of the selector (`part` 1) or verifier (`part`
/// 2) to another lowercase hex digit.
fn tamper(token: &str, part: usize) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let field = &mut parts[part];
    let last = field.pop().expect("nonempty");
    field.push(if last == '0' { '1' } else { '0' });
    parts.join(".")
}

fn expect_flow_error(
    result: Result<ConfirmMagicLinkFlowOutcome, MagicLinkFlowError>,
    expected: MagicLinkServiceError,
) {
    let error = result.expect_err("confirm must fail");
    assert_eq!(error.public_error(), expected);
    let action = if expected == MagicLinkServiceError::Unavailable {
        TemporaryAuthStateAction::Preserve
    } else {
        TemporaryAuthStateAction::Clear
    };
    assert_eq!(error.temporary_state_action(), action);
}

/// The session just created validates iff it postdates the enable watermark.
async fn check_new_session(
    h: &Harness,
    m: &Model,
    flow: &MFlow,
    outcome: &ConfirmMagicLinkFlowOutcome,
) {
    let user = &m.users[m.links[flow.link].email];
    let live = user.watermark.is_none_or(|mark| m.now > mark);
    let result = h
        .validate(outcome.authentication().session_cookie_value(), None)
        .await;
    assert_eq!(
        result.is_ok(),
        live,
        "new session validates iff created after the watermark"
    );
}

/// Confirm `flow` through `authentication` and compare with the model.
async fn confirm<A: MagicLinkAuthenticationRepository>(
    h: &mut Harness,
    m: &mut Model,
    flow: &MFlow,
    authentication: &A,
    lost_acks: u8,
) {
    let before = fingerprint(&h.store);
    let expected_ok = m.confirm_ok(flow);
    let result = h
        .confirm_with(authentication, &flow.cookie, &flow.confirmation, None)
        .await;
    if !expected_ok {
        expect_flow_error(result, MagicLinkServiceError::MagicLinkUnavailable);
        // ML-INV-004 / ML-INV-005: a refused confirm changes nothing.
        assert_eq!(
            fingerprint(&h.store),
            before,
            "refused confirm changed state"
        );
        return;
    }
    if lost_acks >= 3 {
        // Every retry lost its ack: the caller sees Unavailable (and keeps
        // the flow cookie), but the first attempt committed.
        expect_flow_error(result, MagicLinkServiceError::Unavailable);
        let link = &mut m.links[flow.link];
        link.consumed = true;
        m.sessions += 1;
        let user = &mut m.users[link.email];
        if user.id.is_none() {
            let inner = h.store.lock_inner().expect("lock");
            let email_hmac = h.store.email_hmac(&email(link.email)).expect("hmac");
            user.id = inner.user_id_by_email_hmac.get(&email_hmac).cloned();
        }
        return;
    }
    let outcome = result.expect("confirm");
    m.record_success(flow, &outcome);
    check_new_session(h, m, flow, &outcome).await;
}

async fn forge(h: &mut Harness, m: &mut Model, link_index: usize, kind: Kind) {
    let link = m.links[link_index].clone();
    if link.expires <= m.now {
        return;
    }
    let token = MagicLinkToken::parse(&link.token).expect("token");
    let stranger = MagicLinkToken::generate(&mut h.rng).expect("token");
    let key = &h.lookup_key;
    let selector = match kind {
        Kind::WrongSelector => selector_lookup_hmac(key, stranger.selector()).expect("hmac"),
        _ => link.selector.clone(),
    };
    let verifier = match kind {
        Kind::WrongVerifier => verifier_hash(key, stranger.verifier()),
        _ => verifier_hash(key, token.verifier()),
    }
    .expect("hash");
    let account_email = match kind {
        Kind::WrongAccount => email(link.email + 1),
        _ => email(link.email),
    };
    let account = email_lookup_hmac(key, &account_email).expect("hmac");
    let expires = link.expires.min(m.now + FLOW_TTL);
    let minted = mint_magic_link_confirm(
        MagicLinkConfirmBindings::new(
            confirm_selector_binding(&selector).expect("binding"),
            confirm_verifier_binding(&verifier).expect("binding"),
            confirm_account_binding(&account).expect("binding"),
            u32::try_from(expires).expect("u32"),
        ),
        &h.confirm_keyring,
        &mut h.rng,
        m.now,
    )
    .expect("mint");
    m.flows.push(MFlow {
        link: link_index,
        cookie: minted.cookie().as_secret_value().to_owned(),
        confirmation: minted.confirmation().as_value().to_owned(),
        expires,
        kind,
    });
}

/// Request and land a genuine link for `user`.
async fn fresh_flow(h: &mut Harness, m: &mut Model, user: usize) -> MFlow {
    let token = h.request(&email(user)).await;
    let parsed = MagicLinkToken::parse(&token).expect("token");
    m.links.push(MLink {
        selector: selector_lookup_hmac(&h.lookup_key, parsed.selector()).expect("hmac"),
        token: token.clone(),
        email: user,
        expires: m.now + LINK_TTL,
        consumed: false,
    });
    let (cookie, confirmation) = h.land(&token).await.expect("fresh landing");
    let flow = MFlow {
        link: m.links.len() - 1,
        cookie,
        confirmation,
        expires: m.now + FLOW_TTL,
        kind: Kind::Genuine,
    };
    m.flows.push(flow.clone());
    flow
}

/// Two confirms. When both would succeed alone they run concurrently,
/// planning against the same state; otherwise one after the other.
async fn race(h: &mut Harness, m: &mut Model, first: &MFlow, second: &MFlow) {
    if !(m.confirm_ok(first) && m.confirm_ok(second)) {
        let store = h.store.clone();
        confirm(h, m, first, &store, 0).await;
        confirm(h, m, second, &store, 0).await;
        return;
    }
    let barrier = Arc::new(Barrier::new(2));
    let wrap = |store: &FakeDynamoDbAuthStore| BarrierAuth {
        store: store.clone(),
        barrier: Arc::clone(&barrier),
        waited: AtomicBool::new(false),
    };
    let (auth_a, auth_b) = (wrap(&h.store), wrap(&h.store));
    let mut rng_a = SplitMixRng::new(h.rng.next_u64());
    let mut rng_b = SplitMixRng::new(h.rng.next_u64());
    let service = |authentication, rng| MagicLinkFlowService {
        authentication,
        sessions: &h.store,
        limiter: &AllowAllLimiter,
        clock: &h.clock,
        rng,
        lookup_hmac_key: &h.lookup_key,
        previous_lookup_hmac_key: None,
        confirm_keyring: &h.confirm_keyring,
        session_keyring: &h.session_keyring,
        config: h.config.clone(),
    };
    let command = |flow: &MFlow| {
        ConfirmMagicLinkFlowCommand::new(flow.cookie.clone(), flow.confirmation.clone(), None)
            .expect("command")
    };
    let mut service_a = service(&auth_a, &mut rng_a);
    let mut service_b = service(&auth_b, &mut rng_b);
    let (a, b) = tokio::join!(
        service_a.confirm_magic_link_flow(command(first)),
        service_b.confirm_magic_link_flow(command(second)),
    );
    if first.link == second.link {
        // ML-INV-002 under interleaving: exactly one winner.
        assert_eq!(
            a.is_ok() as u8 + b.is_ok() as u8,
            1,
            "exactly one racing confirm wins"
        );
        let (winner, outcome, loser) = match (a, b) {
            (Ok(outcome), loser) => (first, outcome, loser),
            (loser, Ok(outcome)) => (second, outcome, loser),
            _ => unreachable!(),
        };
        expect_flow_error(loser, MagicLinkServiceError::MagicLinkUnavailable);
        m.record_success(winner, &outcome);
    } else {
        // Distinct links both win; one email still maps to one user id.
        let a = a.expect("first racer");
        let b = b.expect("second racer");
        if m.links[first.link].email == m.links[second.link].email
            && m.users[m.links[first.link].email].id.is_none()
        {
            assert_eq!(a.authentication().user_id(), b.authentication().user_id());
            assert_ne!(
                a.authentication().user_created(),
                b.authentication().user_created()
            );
            let created = if a.authentication().user_created() {
                (first, &a, second, &b)
            } else {
                (second, &b, first, &a)
            };
            m.record_success(created.0, created.1);
            m.record_success(created.2, created.3);
        } else {
            m.record_success(first, &a);
            m.record_success(second, &b);
        }
    }
}

async fn apply(h: &mut Harness, m: &mut Model, op: &Op) {
    match *op {
        Op::Request { user } => {
            let user = usize::from(user);
            let token = h.request(&email(user)).await;
            let parsed = MagicLinkToken::parse(&token).expect("token");
            m.links.push(MLink {
                selector: selector_lookup_hmac(&h.lookup_key, parsed.selector()).expect("hmac"),
                token,
                email: user,
                expires: m.now + LINK_TTL,
                consumed: false,
            });
        }
        Op::Fresh { user } => {
            Box::pin(apply(h, m, &Op::Request { user })).await;
            let link = u8::try_from(m.links.len() - 1).unwrap_or(u8::MAX);
            if usize::from(link) == m.links.len() - 1 {
                Box::pin(apply(h, m, &Op::Land { link, tamper: 0 })).await;
            }
        }
        Op::RaceFresh { user, same_link } => {
            let user = usize::from(user);
            let first = fresh_flow(h, m, user).await;
            let second = if same_link {
                first.clone()
            } else {
                fresh_flow(h, m, user).await
            };
            race(h, m, &first, &second).await;
        }
        Op::ReEnable { flow } => {
            let Some(flow) = pick(&m.flows, flow) else {
                return;
            };
            let user = m.links[flow.link].email;
            if m.users[user].id.is_none() || !m.confirm_ok(&flow) {
                return;
            }
            Box::pin(apply(h, m, &Op::Disable { user: user as u8 })).await;
            let store = h.store.clone();
            // ML-INV-005: refused while disabled, and not burned.
            confirm(h, m, &flow, &store, 0).await;
            Box::pin(apply(h, m, &Op::Enable { user: user as u8 })).await;
            // The same challenge still works after re-enable.
            assert!(m.confirm_ok(&flow));
            confirm(h, m, &flow, &store, 0).await;
        }
        Op::LateLand { link, offset } => {
            let Some(index) = (!m.links.is_empty()).then(|| usize::from(link) % m.links.len())
            else {
                return;
            };
            let at = m.links[index].expires - offset;
            if at < m.now {
                return;
            }
            m.now = at;
            h.clock.set(at);
            Box::pin(apply(h, m, &Op::Land { link, tamper: 0 })).await;
        }
        Op::ConfirmAt { flow, target } => {
            let Some(flow) = pick(&m.flows, flow) else {
                return;
            };
            let link_expires = m.links[flow.link].expires;
            let at = match target {
                0 => flow.expires,
                1 => flow.expires + 1,
                2 => link_expires - 1,
                _ => link_expires,
            };
            if at < m.now {
                return;
            }
            m.now = at;
            h.clock.set(at);
            let store = h.store.clone();
            confirm(h, m, &flow, &store, 0).await;
        }
        Op::Land { link, tamper: kind } => {
            let Some(index) = (!m.links.is_empty()).then(|| usize::from(link) % m.links.len())
            else {
                return;
            };
            let record = m.links[index].clone();
            let token = match kind {
                0 => record.token.clone(),
                1 => tamper(&record.token, 2),
                _ => tamper(&record.token, 1),
            };
            let before = fingerprint(&h.store);
            let result = h.land(&token).await;
            // ML-INV-001: landing never consumes or creates anything.
            assert_eq!(fingerprint(&h.store), before, "landing changed state");
            let expected_ok = kind == 0 && !record.consumed && m.now < record.expires;
            assert_eq!(result.is_ok(), expected_ok, "landing outcome");
            if let Ok((cookie, confirmation)) = result {
                m.flows.push(MFlow {
                    link: index,
                    cookie,
                    confirmation,
                    expires: record.expires.min(m.now + FLOW_TTL),
                    kind: Kind::Genuine,
                });
            } else if let Err(error) = result {
                assert_eq!(
                    error.public_error(),
                    MagicLinkServiceError::MagicLinkUnavailable
                );
            }
        }
        Op::Forge { link, kind } => {
            let Some(index) = (!m.links.is_empty()).then(|| usize::from(link) % m.links.len())
            else {
                return;
            };
            let kind = [Kind::WrongSelector, Kind::WrongVerifier, Kind::WrongAccount]
                [usize::from(kind) % 3];
            forge(h, m, index, kind).await;
        }
        Op::WrongNonce { flow } => {
            let Some(mut flow) = pick(&m.flows, flow) else {
                return;
            };
            let mut nonce = [0u8; 32];
            h.rng.fill_bytes(&mut nonce);
            flow.confirmation = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            flow.kind = Kind::WrongNonce;
            m.flows.push(flow);
        }
        Op::Confirm { flow } => {
            let Some(flow) = pick(&m.flows, flow) else {
                return;
            };
            let store = h.store.clone();
            confirm(h, m, &flow, &store, 0).await;
        }
        Op::DisableRace { flow } => {
            let Some(flow) = pick(&m.flows, flow) else {
                return;
            };
            let user = m.links[flow.link].email;
            let Some(id) = m.users[user].id.clone() else {
                return;
            };
            if !m.confirm_ok(&flow) {
                return;
            }
            h.store.disable_user_before_next_commit(&id).expect("arm");
            let result = h
                .confirm_with(&h.store.clone(), &flow.cookie, &flow.confirmation, None)
                .await;
            // ML-INV-005: the commit saw the disabled user and burned nothing.
            expect_flow_error(result, MagicLinkServiceError::MagicLinkUnavailable);
            assert!(
                !h.store
                    .magic_link_record(&m.links[flow.link].selector)
                    .expect("record")
                    .expect("link")
                    .consumed_at_unix
                    .is_some()
            );
            m.users[user].disabled = true;
        }
        Op::PreCommitFailure { flow } => {
            let Some(flow) = pick(&m.flows, flow) else {
                return;
            };
            h.store.fail_next_authentication_pre_commit().expect("arm");
            let store = h.store.clone();
            confirm(h, m, &flow, &store, 0).await;
        }
        Op::AmbiguousCommit { flow, lost } => {
            let Some(flow) = pick(&m.flows, flow) else {
                return;
            };
            let wrapper = AckLossAuth {
                store: h.store.clone(),
                lost: AtomicU8::new(lost),
            };
            confirm(h, m, &flow, &wrapper, lost).await;
        }
        Op::Race { first, second } => {
            let (Some(a), Some(b)) = (pick(&m.flows, first), pick(&m.flows, second)) else {
                return;
            };
            race(h, m, &a, &b).await;
        }
        Op::Disable { user } | Op::Enable { user } => {
            let user = usize::from(user);
            let Some(id) = m.users[user].id.clone() else {
                return;
            };
            let disable = matches!(op, Op::Disable { .. });
            let store = h.store.clone();
            let mut admin = h.admin_with(&store);
            let result = if disable {
                admin.disable_user(&id, &actor()).await.map(|_| ())
            } else {
                admin.enable_user(&id, &actor()).await
            };
            if !disable && !m.users[user].disabled {
                assert_eq!(
                    result,
                    Err(datadeft_magic_link_service::AdminError::AlreadyInState)
                );
                return;
            }
            result.expect("admin");
            m.users[user].disabled = disable;
            if !disable {
                m.users[user].watermark = Some(m.now);
            }
        }
        Op::Advance(step) => {
            m.now += step;
            h.clock.set(m.now);
        }
    }
}

fn check_state(h: &Harness, m: &Model) {
    let inner = h.store.lock_inner().expect("lock");
    for link in &m.links {
        let stored = &inner.magic_links_by_selector_hmac[link.selector.as_storage_value()];
        assert_eq!(
            stored.consumed_at_unix.is_some(),
            link.consumed,
            "consumed flag"
        );
    }
    let consumed = inner
        .magic_links_by_selector_hmac
        .values()
        .filter(|record| record.consumed_at_unix.is_some())
        .count();
    // ML-INV-003: consumed challenges and session rows pair one to one.
    assert_eq!(
        consumed,
        inner.sessions_by_hmac.len(),
        "consume <=> session"
    );
    assert_eq!(inner.sessions_by_hmac.len(), m.sessions);
    let known = m.users.iter().filter(|user| user.id.is_some()).count();
    assert_eq!(
        inner.user_profiles_by_id.len(),
        known,
        "one account per email"
    );
    for user in &m.users {
        let Some(id) = &user.id else { continue };
        assert_eq!(
            inner.user_profiles_by_id[id.as_str()].disabled,
            user.disabled
        );
    }
}

async fn run(ops: Vec<Op>, seed: u64) {
    let mut h = Harness::new(seed);
    let mut m = Model {
        now: T0,
        ..Model::default()
    };
    for op in &ops {
        apply(&mut h, &mut m, op).await;
        h.clear_faults();
        check_state(&h, &m);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// ML-INV-001..005 over random flows, forged bindings, expiry, disabled
    /// users, ambiguous commits, and races.
    #[test]
    fn magic_link_flow_conforms_to_model(
        ops in prop::collection::vec(op(), 1..40),
        seed in any::<u64>(),
    ) {
        block_on(run(ops, seed));
    }
}

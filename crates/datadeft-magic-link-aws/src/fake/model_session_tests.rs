//! Session lifecycle model: random login / validate / refresh / clock / logout /
//! admin / key-rotation sequences against the real service code, checked
//! against a reference model after every step.
//!
//! Bridges `spec/tla/Session.tla` (SES-INV-001: a revoked or expired session
//! never validates) and extends it with the properties the code adds: idle and
//! absolute freshness, country lock, disable/enable watermark, refresh
//! invariants, admin audit pairing, and fault-tolerant `disable_user`.

use datadeft_auth_token_core::cookie::parse_bound_cookie;
use datadeft_magic_link_service::{
    AdminAction, AdminError, MagicLinkServiceError, SessionCookie, SessionHandle, SessionId,
    SessionStatus, SessionValidationError, UserId, ValidatedSession, decode_session_cookie_body,
};
use proptest::prelude::*;

use super::model_admin::{Budget, FailingAdmin, Fate, Fault};
use super::model_support::*;

// --- reference model -------------------------------------------------------

#[derive(Clone, Debug)]
struct MUser {
    id: Option<UserId>,
    disabled: bool,
    watermark: Option<u64>,
}

#[derive(Clone, Debug)]
struct MSession {
    id: SessionId,
    handle: String,
    user: usize,
    created: u64,
    revoked_at: Option<u64>,
    country: Option<&'static str>,
}

#[derive(Clone, Debug)]
struct MCookie {
    value: String,
    session: usize,
    ts: u64,
    iat: u64,
    generation: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MEvent {
    action: AdminAction,
    user: String,
    session: Option<String>,
    at: u64,
}

struct Model {
    now: u64,
    users: [MUser; 2],
    sessions: Vec<MSession>,
    cookies: Vec<MCookie>,
    events: Vec<MEvent>,
    generation: u8,
    keep_previous: bool,
}

const MAX_COOKIES: usize = 24;

impl Model {
    fn new() -> Self {
        let user = MUser {
            id: None,
            disabled: false,
            watermark: None,
        };
        Self {
            now: T0,
            users: [user.clone(), user],
            sessions: Vec::new(),
            cookies: Vec::new(),
            events: Vec::new(),
            generation: 0,
            keep_previous: false,
        }
    }

    fn user_id_or_unknown(&self, user: usize) -> UserId {
        self.users[user]
            .id
            .clone()
            .unwrap_or_else(|| UserId::parse(UNKNOWN_USER).expect("user id"))
    }

    /// Everything `parse_bound_cookie` and the country lock check.
    fn cookie_ok(&self, cookie: &MCookie, request_country: Option<&str>) -> bool {
        let now = self.now;
        let key_ok = cookie.generation == self.generation
            || (self.keep_previous && cookie.generation + 1 == self.generation);
        let country = self.sessions[cookie.session].country;
        key_ok
            && cookie.ts <= now + SKEW
            && now.saturating_sub(cookie.ts) <= IDLE
            && cookie.iat <= now + SKEW
            && now.saturating_sub(cookie.iat) <= ABSOLUTE
            && country.is_none_or(|bound| request_country == Some(bound))
    }

    /// Everything the store and the server-side record checks decide.
    fn record_ok(&self, session: &MSession) -> bool {
        let now = self.now;
        let user = &self.users[session.user];
        session.revoked_at.is_none()
            && session.created + ABSOLUTE >= now
            && session.created <= now + SKEW
            && now.saturating_sub(session.created) <= ABSOLUTE
            && user.id.is_some()
            && !user.disabled
            && user.watermark.is_none_or(|mark| session.created > mark)
    }

    /// What `revoke_all_sessions` revokes: `SessionSummary::status` is
    /// Active one clock-skew tolerance ago, so a session stays in scope until
    /// the tolerance has passed after its expiry.
    fn active(&self, session: &MSession) -> bool {
        session.revoked_at.is_none() && session.created + ABSOLUTE >= self.now.saturating_sub(SKEW)
    }

    fn revoke_audited(&mut self, index: usize, user: &UserId) {
        let now = self.now;
        let session = &mut self.sessions[index];
        session.revoked_at = Some(now);
        self.events.push(MEvent {
            action: AdminAction::RevokeSession,
            user: user.as_str().to_owned(),
            session: Some(session.handle.clone()),
            at: now,
        });
    }

    fn set_disabled_audited(&mut self, user: usize, disabled: bool) {
        let now = self.now;
        let id = self.user_id_or_unknown(user);
        let record = &mut self.users[user];
        record.disabled = disabled;
        if !disabled {
            record.watermark = Some(now);
        }
        self.events.push(MEvent {
            action: if disabled {
                AdminAction::DisableUser
            } else {
                AdminAction::EnableUser
            },
            user: id.as_str().to_owned(),
            session: None,
            at: now,
        });
    }

    /// `AuthAdminService::revoke_session`, replayed.
    fn admin_revoke(
        &mut self,
        index: usize,
        given: &UserId,
        budget: &mut Budget,
    ) -> Result<(), AdminError> {
        let session = &self.sessions[index];
        let owner = self.users[session.user].id.as_ref();
        let owned = owner == Some(given);
        let applies = owned && session.revoked_at.is_none();
        match budget.call() {
            Fate::Fail => Err(AdminError::Unavailable),
            Fate::AckLost => {
                if applies {
                    self.revoke_audited(index, given);
                }
                Err(AdminError::Unavailable)
            }
            Fate::Normal if applies => {
                self.revoke_audited(index, given);
                Ok(())
            }
            Fate::Normal => match budget.call() {
                Fate::Normal if owned => Err(AdminError::AlreadyInState),
                Fate::Normal => Err(AdminError::NotFound),
                _ => Err(AdminError::Unavailable),
            },
        }
    }

    /// `AuthAdminService::revoke_all_sessions`, replayed: one list call, then
    /// one audited revoke per active session, newest first.
    fn revoke_all(&mut self, user: usize, budget: &mut Budget) -> Result<u64, AdminError> {
        if budget.call() != Fate::Normal {
            return Err(AdminError::Unavailable);
        }
        let Some(id) = self.users[user].id.clone() else {
            return Ok(0);
        };
        let mut order: Vec<usize> = (0..self.sessions.len())
            .filter(|&index| self.sessions[index].user == user)
            .collect();
        order.sort_by_key(|&index| core::cmp::Reverse(self.sessions[index].created));
        order.retain(|&index| self.active(&self.sessions[index]));
        let mut revoked = 0;
        for index in order {
            match budget.call() {
                Fate::Normal => {
                    self.revoke_audited(index, &id);
                    revoked += 1;
                }
                Fate::Fail => return Err(AdminError::Unavailable),
                Fate::AckLost => {
                    self.revoke_audited(index, &id);
                    return Err(AdminError::Unavailable);
                }
            }
        }
        Ok(revoked)
    }

    /// `set_disabled` for a user that has never logged in: the conditional
    /// write fails and the follow-up read finds nothing.
    fn set_disabled_unknown(budget: &mut Budget) -> Result<(), AdminError> {
        match (budget.call(), budget.call()) {
            (Fate::Normal, Fate::Normal) => Err(AdminError::NotFound),
            _ => Err(AdminError::Unavailable),
        }
    }

    /// `set_disabled(disable)` for a known user, replayed.
    fn set_disabled(
        &mut self,
        user: usize,
        disable: bool,
        budget: &mut Budget,
    ) -> Result<(), AdminError> {
        let applies = self.users[user].disabled != disable;
        match budget.call() {
            Fate::Fail => Err(AdminError::Unavailable),
            Fate::AckLost => {
                if applies {
                    self.set_disabled_audited(user, disable);
                }
                Err(AdminError::Unavailable)
            }
            Fate::Normal if applies => {
                self.set_disabled_audited(user, disable);
                Ok(())
            }
            Fate::Normal => match budget.call() {
                Fate::Normal => Err(AdminError::AlreadyInState),
                _ => Err(AdminError::Unavailable),
            },
        }
    }

    fn disable(&mut self, user: usize, budget: &mut Budget) -> Result<u64, AdminError> {
        let set = if self.users[user].id.is_none() {
            Self::set_disabled_unknown(budget)
        } else {
            self.set_disabled(user, true, budget)
        };
        match set {
            Ok(()) | Err(AdminError::AlreadyInState) => self.revoke_all(user, budget),
            Err(error) => Err(error),
        }
    }

    /// `enable_user`: read the user, revoke every live session, then write.
    /// Any failure before the write leaves the user disabled.
    fn enable(&mut self, user: usize, budget: &mut Budget) -> Result<(), AdminError> {
        if budget.call() != Fate::Normal {
            return Err(AdminError::Unavailable);
        }
        if self.users[user].id.is_none() {
            return Err(AdminError::NotFound);
        }
        if !self.users[user].disabled {
            return Err(AdminError::AlreadyInState);
        }
        self.revoke_all(user, budget)?;
        self.set_disabled(user, false, budget)
    }
}

// --- operations ------------------------------------------------------------

#[derive(Clone, Debug)]
enum Op {
    Login {
        user: u8,
        country: bool,
    },
    Validate {
        cookie: u8,
        country: u8,
        refresh: bool,
        fault: bool,
    },
    /// Validate, move the clock by `delta`, then refresh with the old result.
    StaleRefresh {
        cookie: u8,
        delta: i8,
    },
    Advance(u64),
    Rewind(u64),
    /// Jump the clock to a boundary of one cookie, then validate and refresh it.
    Probe {
        cookie: u8,
        target: u8,
    },
    Logout {
        session: u8,
    },
    AdminRevoke {
        session: u8,
        wrong_owner: bool,
        fault: Fault,
    },
    RevokeAll {
        user: u8,
        fault: Fault,
    },
    Disable {
        user: u8,
        fault: Fault,
    },
    Enable {
        user: u8,
        fault: Fault,
    },
    RotateKey,
    RetirePreviousKey,
}

fn fault() -> impl Strategy<Value = Fault> {
    prop_oneof![
        4 => Just(Fault::None),
        1 => (0u8..4).prop_map(Fault::FailAt),
        1 => (0u8..4).prop_map(Fault::AckLostAt),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    let steps = vec![
        1,
        59,
        60,
        61,
        IDLE / 2 - 1,
        IDLE / 2,
        IDLE / 2 + 1,
        IDLE - 1,
        IDLE,
        IDLE + 1,
        ABSOLUTE - IDLE,
        ABSOLUTE,
        ABSOLUTE + 1,
    ];
    prop_oneof![
        4 => (0u8..2, any::<bool>()).prop_map(|(user, country)| Op::Login { user, country }),
        8 => (any::<u8>(), 0u8..3, any::<bool>(), prop::bool::weighted(0.15)).prop_map(
            |(cookie, country, refresh, fault)| Op::Validate { cookie, country, refresh, fault }
        ),
        2 => (any::<u8>(), prop::sample::select(vec![-1i8, 0, 1, 60, 61]))
            .prop_map(|(cookie, delta)| Op::StaleRefresh { cookie, delta }),
        5 => prop::sample::select(steps).prop_map(Op::Advance),
        1 => prop::sample::select(vec![1u64, 60, 61]).prop_map(Op::Rewind),
        3 => (any::<u8>(), any::<u8>()).prop_map(|(cookie, target)| Op::Probe { cookie, target }),
        2 => any::<u8>().prop_map(|session| Op::Logout { session }),
        2 => (any::<u8>(), prop::bool::weighted(0.2), fault())
            .prop_map(|(session, wrong_owner, fault)| Op::AdminRevoke { session, wrong_owner, fault }),
        2 => (0u8..2, fault()).prop_map(|(user, fault)| Op::RevokeAll { user, fault }),
        2 => (0u8..2, fault()).prop_map(|(user, fault)| Op::Disable { user, fault }),
        2 => (0u8..2, fault()).prop_map(|(user, fault)| Op::Enable { user, fault }),
        1 => Just(Op::RotateKey),
        1 => Just(Op::RetirePreviousKey),
    ]
}

const COUNTRIES: [Option<&str>; 3] = [None, Some("BE"), Some("NL")];

// --- driver ----------------------------------------------------------------

async fn login(h: &mut Harness, m: &mut Model, user: usize, country: Option<&'static str>) {
    let result = h.login(&email(user), country).await;
    if m.users[user].id.is_some() && m.users[user].disabled {
        assert_eq!(
            result.err().map(|error| error.public_error()),
            Some(MagicLinkServiceError::MagicLinkUnavailable),
            "a disabled user cannot log in"
        );
        return;
    }
    let outcome = result.expect("login");
    let auth = outcome.authentication();
    match &m.users[user].id {
        Some(id) => {
            assert_eq!(auth.user_id(), id);
            assert!(!auth.user_created());
        }
        None => {
            assert!(auth.user_created());
            m.users[user].id = Some(auth.user_id().clone());
        }
    }
    assert_eq!(auth.country(), country);
    let value = auth.session_cookie_value().to_owned();
    assert_eq!(
        cookie_kid(&value),
        session_kid(m.generation),
        "login mints under the active key"
    );
    m.sessions.push(MSession {
        id: auth.session_id().clone(),
        handle: h.store.session_hmac(auth.session_id()).expect("hmac"),
        user,
        created: m.now,
        revoked_at: None,
        country,
    });
    push_cookie(
        m,
        MCookie {
            value,
            session: m.sessions.len() - 1,
            ts: m.now,
            iat: m.now,
            generation: m.generation,
        },
    );
}

fn push_cookie(m: &mut Model, cookie: MCookie) {
    if m.cookies.len() >= MAX_COOKIES {
        m.cookies.remove(0);
    }
    m.cookies.push(cookie);
}

/// Validate `cookie` and compare with the model. Returns the validation on
/// success.
async fn validate(
    h: &Harness,
    m: &Model,
    cookie: &MCookie,
    request_country: Option<&str>,
    fault: bool,
) -> Option<ValidatedSession> {
    if fault {
        h.store
            .set_next_error(crate::error::AwsAdapterError::DependencyUnavailable)
            .expect("inject");
    }
    let result = h.validate(&cookie.value, request_country).await;
    let session = &m.sessions[cookie.session];
    let expected = if !m.cookie_ok(cookie, request_country) {
        Err(SessionValidationError::InvalidSession)
    } else if fault {
        Err(SessionValidationError::Unavailable)
    } else if m.record_ok(session) {
        Ok(())
    } else {
        Err(SessionValidationError::InvalidSession)
    };
    assert_eq!(
        result.as_ref().map(|_| ()).map_err(|error| *error),
        expected,
        "validate"
    );
    let validated = result.ok()?;
    assert_eq!(validated.session().session_id, session.id);
    assert_eq!(validated.country(), session.country);
    // Ghost check: nothing from before an enable (or a disable) is accepted.
    let user = &m.users[session.user];
    assert!(!user.disabled && user.watermark.is_none_or(|mark| session.created > mark));
    Some(validated)
}

/// Refresh a validation taken at `validated_at` and compare with the model.
fn refresh(
    h: &mut Harness,
    m: &mut Model,
    validated: &ValidatedSession,
    cookie: &MCookie,
    validated_at: u64,
) {
    let now = m.now;
    let result = h.refresh(validated);
    if now < validated_at || now - validated_at > SKEW {
        assert_eq!(
            result.err(),
            Some(SessionValidationError::InvalidSession),
            "stale refresh"
        );
        return;
    }
    let due = cookie.iat <= now
        && now.saturating_sub(cookie.ts) >= IDLE / 2
        && now.saturating_sub(cookie.iat) < ABSOLUTE;
    let refreshed = result.expect("refresh");
    assert_eq!(refreshed.is_some(), due, "refresh due");
    let Some(refreshed) = refreshed else {
        return;
    };
    let value = refreshed.as_secret_value().to_owned();
    assert_eq!(
        cookie_kid(&value),
        session_kid(m.generation),
        "refresh mints under the active key"
    );
    let max_age = h.config.session_max_age().expect("max age");
    let parsed = parse_bound_cookie::<SessionCookie>(&value, &h.session_keyring, now, max_age)
        .expect("refreshed cookie parses");
    assert_eq!(u64::from(parsed.iat()), cookie.iat, "refresh keeps iat");
    assert_eq!(u64::from(parsed.timestamp()), now);
    assert!(
        now < cookie.iat + ABSOLUTE,
        "refresh never reaches past absolute"
    );
    let body = decode_session_cookie_body(parsed.body()).expect("body");
    let session = &m.sessions[cookie.session];
    assert_eq!(body.session_id, session.id, "refresh keeps the session id");
    assert_eq!(
        body.country.as_deref(),
        session.country,
        "refresh keeps the country"
    );
    let next = MCookie {
        value,
        session: cookie.session,
        ts: now,
        iat: cookie.iat,
        generation: m.generation,
    };
    push_cookie(m, next);
}

fn pick<T: Clone>(items: &[T], index: u8) -> Option<T> {
    (!items.is_empty()).then(|| items[usize::from(index) % items.len()].clone())
}

async fn apply(h: &mut Harness, m: &mut Model, op: &Op) {
    match *op {
        Op::Login { user, country } => {
            login(h, m, usize::from(user), country.then_some("BE")).await;
        }
        Op::Validate {
            cookie,
            country,
            refresh: wants_refresh,
            fault,
        } => {
            let Some(cookie) = pick(&m.cookies, cookie) else {
                return;
            };
            let request_country = COUNTRIES[usize::from(country) % COUNTRIES.len()];
            if let Some(validated) = validate(h, m, &cookie, request_country, fault).await
                && wants_refresh
            {
                let now = m.now;
                refresh(h, m, &validated, &cookie, now);
            }
        }
        Op::StaleRefresh { cookie, delta } => {
            let Some(cookie) = pick(&m.cookies, cookie) else {
                return;
            };
            let country = m.sessions[cookie.session].country;
            let Some(validated) = validate(h, m, &cookie, country, false).await else {
                return;
            };
            let validated_at = m.now;
            m.now = m.now.saturating_add_signed(i64::from(delta));
            h.clock.set(m.now);
            refresh(h, m, &validated, &cookie, validated_at);
        }
        Op::Advance(step) => {
            m.now += step;
            h.clock.set(m.now);
        }
        Op::Rewind(step) => {
            m.now -= step;
            h.clock.set(m.now);
        }
        Op::Probe { cookie, target } => {
            let Some(cookie) = pick(&m.cookies, cookie) else {
                return;
            };
            m.now = match target % 8 {
                0 => cookie.ts + IDLE / 2 - 1,
                1 => cookie.ts + IDLE / 2,
                2 => cookie.ts + IDLE,
                3 => cookie.ts + IDLE + 1,
                4 => cookie.iat + ABSOLUTE,
                5 => cookie.iat + ABSOLUTE + 1,
                6 => cookie.ts - SKEW,
                _ => cookie.ts - SKEW - 1,
            };
            h.clock.set(m.now);
            let country = m.sessions[cookie.session].country;
            if let Some(validated) = validate(h, m, &cookie, country, false).await {
                let now = m.now;
                refresh(h, m, &validated, &cookie, now);
            }
        }
        Op::Logout { session } => {
            let Some(index) =
                (!m.sessions.is_empty()).then(|| usize::from(session) % m.sessions.len())
            else {
                return;
            };
            let result = h.logout(&m.sessions[index].id.clone()).await;
            if m.sessions[index].revoked_at.is_some() {
                assert_eq!(
                    result,
                    Err(MagicLinkServiceError::Unavailable),
                    "second logout"
                );
            } else {
                assert_eq!(result, Ok(()), "logout");
                m.sessions[index].revoked_at = Some(m.now);
            }
        }
        Op::AdminRevoke {
            session,
            wrong_owner,
            fault,
        } => {
            let Some(index) =
                (!m.sessions.is_empty()).then(|| usize::from(session) % m.sessions.len())
            else {
                return;
            };
            let owner = m.sessions[index].user;
            let given = m.user_id_or_unknown(if wrong_owner { 1 - owner } else { owner });
            let handle = SessionHandle::parse(&m.sessions[index].handle).expect("handle");
            let repository = FailingAdmin::new(&h.store, fault);
            let result = h
                .admin_with(&repository)
                .revoke_session(&given, &handle, &actor())
                .await;
            let expected = m.admin_revoke(index, &given, &mut Budget::new(fault));
            assert_eq!(result, expected, "admin revoke");
        }
        Op::RevokeAll { user, fault } => {
            let user = usize::from(user);
            let id = m.user_id_or_unknown(user);
            let repository = FailingAdmin::new(&h.store, fault);
            let result = h
                .admin_with(&repository)
                .revoke_all_sessions(&id, &actor())
                .await;
            assert_eq!(
                result,
                m.revoke_all(user, &mut Budget::new(fault)),
                "revoke all"
            );
        }
        Op::Disable { user, fault } => {
            let user = usize::from(user);
            let id = m.user_id_or_unknown(user);
            let repository = FailingAdmin::new(&h.store, fault);
            let result = h.admin_with(&repository).disable_user(&id, &actor()).await;
            assert_eq!(result, m.disable(user, &mut Budget::new(fault)), "disable");
            if result.is_ok() {
                assert_disable_complete(h, &id).await;
            }
        }
        Op::Enable { user, fault } => {
            let user = usize::from(user);
            let id = m.user_id_or_unknown(user);
            let repository = FailingAdmin::new(&h.store, fault);
            let result = h.admin_with(&repository).enable_user(&id, &actor()).await;
            assert_eq!(result, m.enable(user, &mut Budget::new(fault)), "enable");
        }
        Op::RotateKey => {
            m.generation += 1;
            m.keep_previous = true;
            h.session_keyring = session_keyring(m.generation, true);
        }
        Op::RetirePreviousKey => {
            m.keep_previous = false;
            h.session_keyring = session_keyring(m.generation, false);
        }
    }
}

/// A disable that returned `Ok` left the user disabled with no active
/// session, however many earlier attempts failed part-way.
async fn assert_disable_complete(h: &mut Harness, id: &UserId) {
    let store = h.store.clone();
    let admin = h.admin_with(&store);
    let user = admin.get_user(id).await.expect("get user").expect("user");
    assert!(user.disabled, "disable leaves the user disabled");
    let sessions = admin.list_sessions_for_user(id).await.expect("sessions");
    assert!(
        sessions
            .iter()
            .all(|(_, status)| *status != SessionStatus::Active),
        "disable leaves no active session"
    );
}

/// Compare the whole store with the model.
fn check_state(h: &Harness, m: &Model) {
    let inner = h.store.lock_inner().expect("lock");
    assert_eq!(
        inner.sessions_by_hmac.len(),
        m.sessions.len(),
        "session rows"
    );
    for session in &m.sessions {
        let stored = &inner.sessions_by_hmac[&session.handle];
        assert_eq!(
            stored.record.revoked_at_unix, session.revoked_at,
            "revocation state"
        );
        assert_eq!(stored.record.created_at_unix, session.created);
        assert_eq!(stored.expires_at_unix, session.created + ABSOLUTE);
    }
    let known = m.users.iter().filter(|user| user.id.is_some()).count();
    assert_eq!(
        inner.user_profiles_by_id.len(),
        known,
        "one profile per email"
    );
    for user in &m.users {
        let Some(id) = &user.id else { continue };
        assert_eq!(
            inner.user_profiles_by_id[id.as_str()].disabled,
            user.disabled,
            "disabled flag"
        );
        assert_eq!(
            inner.sessions_valid_after.get(id.as_str()).copied(),
            user.watermark,
            "watermark"
        );
    }
    // Every admin state change has exactly one event, and no event exists
    // without its change: the stored trail equals the model's, in order.
    let stored: Vec<MEvent> = inner
        .admin_events
        .iter()
        .map(|event| MEvent {
            action: event.action,
            user: event.user_id.as_str().to_owned(),
            session: event
                .session
                .as_ref()
                .map(|handle| handle.as_str().to_owned()),
            at: event.at_unix,
        })
        .collect();
    assert_eq!(stored, m.events, "audit trail");
    let mut ids: Vec<&str> = inner
        .admin_events
        .iter()
        .map(|event| event.event_id.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), inner.admin_events.len(), "event ids are unique");
}

async fn run(ops: Vec<Op>, seed: u64) {
    let mut h = Harness::new(seed);
    let mut m = Model::new();
    for op in &ops {
        apply(&mut h, &mut m, op).await;
        h.clear_faults();
        assert_eq!(h.now(), m.now);
        check_state(&h, &m);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// SES-INV-001 and the session invariants: validation accepts exactly the
    /// sessions the model calls live; refresh keeps iat, id, and country and
    /// never passes the absolute lifetime; stale validations cannot refresh;
    /// nothing from before an enable validates; disable is retry-safe; the
    /// audit trail pairs one event with every admin change.
    #[test]
    fn session_lifecycle_conforms_to_model(
        ops in prop::collection::vec(op(), 1..48),
        seed in any::<u64>(),
    ) {
        block_on(run(ops, seed));
    }
}

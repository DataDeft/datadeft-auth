//! Local Axum example wiring `dd-pow-core`, `dd-magic-link-service`, and
//! `dd-magic-link-axum` together.
//!
//! This binary is intentionally local-development only. It uses in-memory
//! storage, generates fresh development secrets at startup, and exposes a
//! `/dev/latest-magic-link` helper instead of sending email.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{LOCATION, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dd_auth_token_core::keyring::{KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret};
use dd_magic_link_axum::{
    APPLICATION_JSON, AuthFlowCookieConfig, MagicLinkHttpError, MagicLinkRequestJson,
    MagicLinkScannerFlowConfig, SameOriginPostConfig, SameOriginRedirect, SessionCookieConfig,
    authenticate_session, clear_session_cookie_header, generic_accepted_response, guarded_body,
    handle_magic_link_confirmation, handle_magic_link_landing,
};
use dd_magic_link_core::MagicLinkFlowCookie;
use dd_magic_link_core::{LookupHmac, LookupHmacKey, NormalizedEmail};
use dd_magic_link_service::{
    Clock, CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, DependencyError,
    MagicLinkAuthenticationCandidate, MagicLinkAuthenticationRepository, MagicLinkEmail,
    MagicLinkFlowService, MagicLinkFlowServiceInputs, MagicLinkOutbox, MagicLinkRecord,
    MagicLinkRepository, MagicLinkRequestService, MagicLinkRequestServiceInputs,
    MagicLinkServiceConfig, RateLimitDecision, RateLimitKey, RateLimiter, SessionCookie, SessionId,
    SessionRecord, SessionRepository, UserRecord, validate_session,
};
use dd_pow_core::{Challenge, PowSecret, Solution, mint_challenge, verify_solution};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const LOCAL_ORIGIN: &str = "http://127.0.0.1:3000";
const LISTEN_ADDR: &str = "127.0.0.1:3000";
const POW_DIFFICULTY: u8 = 3;
const POW_CHALLENGE_TTL_SECS: u64 = 5 * 60;

#[tokio::main]
async fn main() -> AppResult<()> {
    let state = build_state()?;
    let app = Router::new()
        .route("/", get(index))
        .route("/auth/pow/challenge", get(pow_challenge))
        .route("/auth/magic-link/request", post(request_magic_link))
        .route("/auth/magic-link", get(magic_link_landing))
        .route("/auth/magic-link/consume", post(magic_link_confirmation))
        .route("/auth/complete", get(auth_complete))
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route("/dev/latest-magic-link", get(dev_latest_magic_link))
        .with_state(state);

    let addr: SocketAddr = LISTEN_ADDR.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("local example listening on {LOCAL_ORIGIN}");
    axum::serve(listener, app).await?;
    Ok(())
}

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
struct SetupError(&'static str);

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Error for SetupError {}

#[derive(Clone)]
struct AppState {
    store: Arc<MemoryStore>,
    config: MagicLinkServiceConfig,
    http_config: Arc<MagicLinkScannerFlowConfig>,
    lookup_hmac_key: Arc<LookupHmacKey>,
    flow_keyring: Arc<KeyRing<MagicLinkFlowCookie>>,
    session_keyring: Arc<KeyRing<SessionCookie>>,
    pow_secret: Arc<PowSecret>,
}

fn build_state() -> AppResult<AppState> {
    let now_unix = current_unix().map_err(|_| SetupError("system clock before unix epoch"))?;
    let config = MagicLinkServiceConfig::new("example-terms-v1", "example-privacy-v1");
    config.validate()?;

    let lookup_hmac_key = Arc::new(LookupHmacKey::new(random_32()?));
    let flow_keyring = Arc::new(development_keyring::<MagicLinkFlowCookie>(
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
        SameOriginRedirect::parse("/auth/complete")
            .map_err(|_| SetupError("invalid magic-link success redirect"))?,
        SameOriginPostConfig::parse(LOCAL_ORIGIN)?,
        session_cookie,
        AuthFlowCookieConfig::local_development_defaults(),
    )?;

    Ok(AppState {
        store: Arc::new(MemoryStore::default()),
        config,
        http_config: Arc::new(http_config),
        lookup_hmac_key,
        flow_keyring,
        session_keyring,
        pow_secret,
    })
}

fn development_keyring<P: KeyPurpose>(kid: &str, now_unix: u64) -> AppResult<KeyRing<P>> {
    let key_id = KeyId::parse(kid)?;
    let root = RootSecret::new(random_32()?);
    let key = root.derive_key::<P>(&key_id)?;
    let mint_until = now_unix
        .checked_add(90 * 24 * 60 * 60)
        .ok_or(SetupError("development key mint window overflow"))?;
    let verify_until = mint_until
        .checked_add(P::MAX_ABSOLUTE_AGE_SECS)
        .ok_or(SetupError("development key verify window overflow"))?;
    KeyRing::new(
        key_id.clone(),
        vec![KeySlot::active_with_windows(
            key_id,
            key,
            mint_until,
            verify_until,
        )],
    )
    .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
}

fn random_32() -> AppResult<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SetupError("operating-system randomness unavailable"))?;
    Ok(bytes)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn pow_challenge(State(state): State<AppState>) -> Result<Json<PowChallengeJson>, Response> {
    let mut entropy = [0_u8; 16];
    OsRng.try_fill_bytes(&mut entropy).map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "randomness unavailable\n").into_response()
    })?;
    let now_unix = current_unix()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "clock unavailable\n").into_response())?;
    let now =
        OffsetDateTime::from_unix_timestamp(i64::try_from(now_unix).map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "clock unavailable\n").into_response()
        })?)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "clock unavailable\n").into_response())?
        .format(&Rfc3339)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "clock unavailable\n").into_response())?;
    let challenge = mint_challenge(&state.pow_secret, POW_DIFFICULTY, &now, entropy)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "pow unavailable\n").into_response())?;
    Ok(Json(PowChallengeJson::from(challenge)))
}

async fn request_magic_link(State(state): State<AppState>, request: Request) -> Response {
    match request_magic_link_inner(state, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn request_magic_link_inner(
    state: AppState,
    request: Request,
) -> Result<Response, MagicLinkHttpError> {
    let guarded = guarded_body(request, &[APPLICATION_JSON], 4096).await?;
    let body: RequestMagicLinkWithPow =
        serde_json::from_slice(&guarded.bytes).map_err(|_| MagicLinkHttpError::BadRequest)?;
    verify_pow_solution(&state, body.pow).map_err(|_| MagicLinkHttpError::Forbidden)?;
    let command = MagicLinkRequestJson {
        email: body.email,
        locale: body.locale,
        terms_accepted: body.terms_accepted,
        privacy_accepted: body.privacy_accepted,
    }
    .into_command()?;

    let mut rng = OsRng;
    let mut service = MagicLinkRequestService::new(MagicLinkRequestServiceInputs {
        magic_links: state.store.as_ref(),
        limiter: state.store.as_ref(),
        outbox: state.store.as_ref(),
        clock: state.store.as_ref(),
        rng: &mut rng,
        lookup_hmac_key: state.lookup_hmac_key.as_ref(),
        config: state.config.clone(),
    });
    service
        .request_magic_link(command)
        .await
        .map_err(MagicLinkHttpError::from)?;
    Ok(generic_accepted_response())
}

async fn magic_link_landing(State(state): State<AppState>, request: Request) -> Response {
    let config = state.http_config.clone();
    handle_magic_link_landing(request, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        let mut service = MagicLinkFlowService::new(MagicLinkFlowServiceInputs {
            authentication: state.store.as_ref(),
            sessions: state.store.as_ref(),
            limiter: state.store.as_ref(),
            clock: state.store.as_ref(),
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            flow_keyring: state.flow_keyring.as_ref(),
            session_keyring: state.session_keyring.as_ref(),
            config: state.config.clone(),
        });
        service.begin_magic_link_landing(command).await
    })
    .await
}

async fn magic_link_confirmation(State(state): State<AppState>, request: Request) -> Response {
    let config = state.http_config.clone();
    handle_magic_link_confirmation(request, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        let mut service = MagicLinkFlowService::new(MagicLinkFlowServiceInputs {
            authentication: state.store.as_ref(),
            sessions: state.store.as_ref(),
            limiter: state.store.as_ref(),
            clock: state.store.as_ref(),
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            flow_keyring: state.flow_keyring.as_ref(),
            session_keyring: state.session_keyring.as_ref(),
            config: state.config.clone(),
        });
        service.confirm_magic_link_flow(command).await
    })
    .await
}

async fn auth_complete() -> Html<&'static str> {
    Html(
        "<!doctype html><h1>Signed in</h1><p>The scanner-safe POST completed. Try <a href=\"/me\">/me</a>.</p>",
    )
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth_state = state.clone();
    match authenticate_session(
        &headers,
        state.http_config.session_cookie(),
        move |cookie| async move {
            validate_session(
                cookie.as_str(),
                auth_state.session_keyring.as_ref(),
                auth_state.store.as_ref(),
                auth_state.store.as_ref(),
                &auth_state.config,
            )
            .await
        },
    )
    .await
    {
        Ok(session) => Html(format!(
            "<!doctype html><h1>Authenticated</h1><p>User: {}</p><p>Email: {}</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Logout</button></form>",
            escape_html(session.session().user_id.as_str()),
            escape_html(session.session().email.as_str()),
        ))
        .into_response(),
        Err(rejection) => rejection.into_response(),
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_same_origin_post(&headers) {
        return (StatusCode::FORBIDDEN, "forbidden\n").into_response();
    }

    let auth_state = state.clone();
    let session = match authenticate_session(
        &headers,
        state.http_config.session_cookie(),
        move |cookie| async move {
            validate_session(
                cookie.as_str(),
                auth_state.session_keyring.as_ref(),
                auth_state.store.as_ref(),
                auth_state.store.as_ref(),
                &auth_state.config,
            )
            .await
        },
    )
    .await
    {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };

    let mut rng = OsRng;
    let service = MagicLinkFlowService::new(MagicLinkFlowServiceInputs {
        authentication: state.store.as_ref(),
        sessions: state.store.as_ref(),
        limiter: state.store.as_ref(),
        clock: state.store.as_ref(),
        rng: &mut rng,
        lookup_hmac_key: state.lookup_hmac_key.as_ref(),
        flow_keyring: state.flow_keyring.as_ref(),
        session_keyring: state.session_keyring.as_ref(),
        config: state.config.clone(),
    });
    if service
        .revoke_session(&session.session().session_id)
        .await
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "logout unavailable\n").into_response();
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/"));
    response.headers_mut().append(
        SET_COOKIE,
        clear_session_cookie_header(state.http_config.session_cookie()),
    );
    response
}

async fn dev_latest_magic_link(State(state): State<AppState>) -> Response {
    match state.store.latest_magic_link() {
        Some(link) => Html(format!(
            "<!doctype html><h1>Development outbox</h1><p>This endpoint exposes a local-only bearer magic link for the example app.</p><p><a href=\"{}\">Continue sign in</a></p>",
            escape_html(&link),
        ))
        .into_response(),
        None => (StatusCode::NOT_FOUND, "no development magic-link email queued\n").into_response(),
    }
}

fn verify_pow_solution(
    state: &AppState,
    body: PowSolutionJson,
) -> Result<(), dd_pow_core::PowError> {
    let now_unix = current_unix().map_err(|_| dd_pow_core::PowError::InvalidTimestamp)?;
    let verified = verify_solution(
        &state.pow_secret,
        &body.into_solution(),
        now_unix,
        POW_CHALLENGE_TTL_SECS,
        POW_DIFFICULTY,
    )?;
    let expires_at_unix = now_unix
        .checked_add(POW_CHALLENGE_TTL_SECS)
        .ok_or(dd_pow_core::PowError::InvalidTimestamp)?;
    state
        .store
        .consume_pow_tid(&verified.tid, now_unix, expires_at_unix)
        .map_err(|error| match error {
            DependencyError::Internal => dd_pow_core::PowError::Internal,
            DependencyError::Unavailable
            | DependencyError::ConditionalWriteFailed
            | DependencyError::RateLimited => dd_pow_core::PowError::InvalidSolution,
        })?;
    Ok(())
}

fn is_same_origin_post(headers: &HeaderMap) -> bool {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return false;
    };
    origins.next().is_none() && origin.as_bytes() == LOCAL_ORIGIN.as_bytes()
}

fn current_unix() -> Result<u64, DependencyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DependencyError::Internal)
}

#[derive(Debug, Deserialize)]
struct RequestMagicLinkWithPow {
    email: String,
    locale: String,
    terms_accepted: bool,
    privacy_accepted: bool,
    pow: PowSolutionJson,
}

#[derive(Debug, Serialize)]
struct PowChallengeJson {
    chg: String,
    dif: u8,
    tim: String,
    tag: String,
}

impl From<Challenge> for PowChallengeJson {
    fn from(value: Challenge) -> Self {
        Self {
            chg: value.chg,
            dif: value.dif,
            tim: value.tim,
            tag: value.tag,
        }
    }
}

#[derive(Debug, Deserialize)]
struct PowSolutionJson {
    chg: String,
    sol: String,
    non: String,
    dif: u8,
    tim: String,
    tag: String,
}

impl PowSolutionJson {
    fn into_solution(self) -> Solution {
        Solution {
            chg: self.chg,
            sol: self.sol,
            non: self.non,
            dif: self.dif,
            tim: self.tim,
            tag: self.tag,
        }
    }
}

#[derive(Default)]
struct MemoryStore {
    inner: Mutex<MemoryStoreInner>,
}

#[derive(Default)]
struct MemoryStoreInner {
    magic_links: HashMap<String, MagicLinkRecord>,
    users_by_email: HashMap<String, UserRecord>,
    sessions: HashMap<String, SessionRecord>,
    session_expires_at: HashMap<String, u64>,
    committed_attempts: HashMap<String, CommitMagicLinkAuthentication>,
    outbox: Vec<MagicLinkEmail>,
    rate_limits: HashMap<String, RateLimitBucket>,
    pow_tids: HashMap<String, u64>,
}

#[derive(Debug, Clone, Copy)]
struct RateLimitBucket {
    window_start_unix: u64,
    count: u32,
}

impl MemoryStore {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryStoreInner>, DependencyError> {
        self.inner.lock().map_err(|_| DependencyError::Internal)
    }

    fn latest_magic_link(&self) -> Option<String> {
        let inner = self.inner.lock().ok()?;
        let email = inner.outbox.last()?;
        let token = email.token.as_secret_value();
        Some(format!("/auth/magic-link?token={}", token.as_str()))
    }

    fn consume_pow_tid(
        &self,
        tid: &str,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), DependencyError> {
        let mut inner = self.lock()?;
        inner
            .pow_tids
            .retain(|_, expires_at| *expires_at > now_unix);
        if inner.pow_tids.contains_key(tid) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        inner.pow_tids.insert(tid.to_owned(), expires_at_unix);
        Ok(())
    }
}

impl Clock for MemoryStore {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        current_unix()
    }
}

impl MagicLinkRepository for MemoryStore {
    async fn put_magic_link_if_absent(
        &self,
        record: MagicLinkRecord,
    ) -> Result<(), DependencyError> {
        let key = record.selector_lookup_hmac.as_storage_value().to_owned();
        let mut inner = self.lock()?;
        if inner.magic_links.contains_key(&key) {
            return Err(DependencyError::ConditionalWriteFailed);
        }
        inner.magic_links.insert(key, record);
        Ok(())
    }
}

impl MagicLinkAuthenticationRepository for MemoryStore {
    async fn find_magic_link_for_authentication(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        let inner = self.lock()?;
        Ok(inner
            .magic_links
            .get(selector_lookup_hmac.as_storage_value())
            .map(|record| MagicLinkAuthenticationCandidate {
                verifier_hash: record.verifier_hash.clone(),
                email: record.email.clone(),
                expires_at_unix: record.expires_at_unix,
                consumed_at_unix: record.consumed_at_unix,
                terms_version: record.terms_version.clone(),
                privacy_version: record.privacy_version.clone(),
                consented_at_unix: record.consented_at_unix,
            }))
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        let inner = self.lock()?;
        Ok(inner.users_by_email.get(email.as_str()).cloned())
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CommitMagicLinkAuthenticationError::Internal)?;

        if let Some(committed) = inner.committed_attempts.get(command.attempt_id.as_str()) {
            return if committed == command {
                Ok(())
            } else {
                Err(CommitMagicLinkAuthenticationError::Internal)
            };
        }

        let selector_key = command.magic_link.selector_lookup_hmac.as_storage_value();
        let record = inner
            .magic_links
            .get(selector_key)
            .cloned()
            .ok_or(CommitMagicLinkAuthenticationError::Rejected)?;
        if record.consumed_at_unix.is_some()
            || record.email != command.magic_link.email
            || record.expires_at_unix != command.magic_link.expires_at_unix
            || record.terms_version != command.magic_link.terms_version
            || record.privacy_version != command.magic_link.privacy_version
            || record.consented_at_unix != command.magic_link.consented_at_unix
            || record.expires_at_unix <= command.now_unix
            || record.consented_at_unix == 0
        {
            return Err(CommitMagicLinkAuthenticationError::Rejected);
        }

        let (user_id, created_user) = match &command.user {
            dd_magic_link_service::MagicLinkAuthenticationUser::Existing { user_id } => {
                let user = inner
                    .users_by_email
                    .get(record.email.as_str())
                    .ok_or(CommitMagicLinkAuthenticationError::UserConflict)?;
                if user.user_id != *user_id || user.email != record.email || user.disabled {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                (user_id.clone(), None)
            }
            dd_magic_link_service::MagicLinkAuthenticationUser::Create { user_id } => {
                if inner.users_by_email.contains_key(record.email.as_str()) {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                (
                    user_id.clone(),
                    Some(UserRecord {
                        user_id: user_id.clone(),
                        email: record.email.clone(),
                        disabled: false,
                        terms_version: Some(record.terms_version.clone()),
                        privacy_version: Some(record.privacy_version.clone()),
                        consented_at_unix: Some(record.consented_at_unix),
                    }),
                )
            }
        };

        if inner.sessions.contains_key(command.session_id.as_str()) {
            return Err(CommitMagicLinkAuthenticationError::SessionConflict);
        }

        if let Some(user) = created_user {
            inner
                .users_by_email
                .insert(record.email.as_str().to_owned(), user);
        }
        let stored = inner
            .magic_links
            .get_mut(selector_key)
            .ok_or(CommitMagicLinkAuthenticationError::Internal)?;
        stored.consumed_at_unix = Some(command.now_unix);
        inner.sessions.insert(
            command.session_id.as_str().to_owned(),
            SessionRecord {
                session_id: command.session_id.clone(),
                user_id,
                email: record.email,
                created_at_unix: command.now_unix,
                revoked_at_unix: None,
            },
        );
        inner.session_expires_at.insert(
            command.session_id.as_str().to_owned(),
            command.session_expires_at_unix,
        );
        inner
            .committed_attempts
            .insert(command.attempt_id.as_str().to_owned(), command.clone());
        Ok(())
    }
}

impl SessionRepository for MemoryStore {
    async fn find_session(
        &self,
        session_id: &SessionId,
        now_unix: u64,
    ) -> Result<Option<SessionRecord>, DependencyError> {
        let inner = self.lock()?;
        let Some(expires_at) = inner.session_expires_at.get(session_id.as_str()) else {
            return Ok(None);
        };
        if *expires_at <= now_unix {
            return Ok(None);
        }
        Ok(inner.sessions.get(session_id.as_str()).cloned())
    }

    async fn revoke_session(
        &self,
        session_id: &SessionId,
        revoked_at_unix: u64,
    ) -> Result<(), DependencyError> {
        let mut inner = self.lock()?;
        if let Some(session) = inner.sessions.get_mut(session_id.as_str()) {
            session.revoked_at_unix = Some(revoked_at_unix);
        }
        Ok(())
    }
}

impl RateLimiter for MemoryStore {
    async fn check_rate_limit(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window_secs: u64,
        now_unix: u64,
    ) -> Result<RateLimitDecision, DependencyError> {
        let mut inner = self.lock()?;
        let bucket = inner
            .rate_limits
            .entry(key.as_str().to_owned())
            .or_insert(RateLimitBucket {
                window_start_unix: now_unix,
                count: 0,
            });
        if now_unix >= bucket.window_start_unix.saturating_add(window_secs) {
            bucket.window_start_unix = now_unix;
            bucket.count = 0;
        }
        bucket.count = bucket.count.saturating_add(1);
        if bucket.count > limit {
            Ok(RateLimitDecision::Denied)
        } else {
            Ok(RateLimitDecision::Allowed)
        }
    }
}

impl MagicLinkOutbox for MemoryStore {
    async fn enqueue_magic_link(&self, email: MagicLinkEmail) -> Result<(), DependencyError> {
        let mut inner = self.lock()?;
        inner.outbox.push(email);
        Ok(())
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>datadeft-auth Axum magic-link example</title>
</head>
<body>
  <main>
    <h1>datadeft-auth Axum magic-link example</h1>
    <p>This local example gates magic-link requests with a low-development proof of work.</p>
    <form id="login-form">
      <label>Email <input name="email" type="email" value="local@example.test" required></label>
      <input type="hidden" name="locale" value="en">
      <label><input name="terms" type="checkbox" checked> Accept terms</label>
      <label><input name="privacy" type="checkbox" checked> Accept privacy policy</label>
      <button type="submit">Request magic link</button>
    </form>
    <pre id="status" aria-live="polite"></pre>
    <p><a href="/dev/latest-magic-link">Open development outbox</a></p>
  </main>
  <script>
    const status = document.getElementById('status');
    const hex = (buffer) => Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('');
    async function sha256(value) {
      return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
    }
    async function solvePow(challenge) {
      let nonce = 0;
      const target = '0'.repeat(challenge.dif);
      while (true) {
        const non = String(nonce);
        const sol = await sha256(challenge.chg + non);
        if (sol.startsWith(target)) {
          return { chg: challenge.chg, sol, non, dif: challenge.dif, tim: challenge.tim, tag: challenge.tag };
        }
        nonce += 1;
      }
    }
    document.getElementById('login-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      status.textContent = 'Minting and solving local proof of work...';
      const challenge = await fetch('/auth/pow/challenge').then((response) => response.json());
      const pow = await solvePow(challenge);
      status.textContent = 'Requesting magic link...';
      const response = await fetch('/auth/magic-link/request', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: form.get('email'),
          locale: form.get('locale'),
          terms_accepted: form.get('terms') === 'on',
          privacy_accepted: form.get('privacy') === 'on',
          pow,
        }),
      });
      if (response.ok) {
        status.innerHTML = 'Request accepted. Open <a href="/dev/latest-magic-link">the development outbox</a>.';
      } else {
        status.textContent = `Request failed with HTTP ${response.status}.`;
      }
    });
  </script>
</body>
</html>
"#;

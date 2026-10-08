//! Local Axum example wiring `datadeft-magic-link-service`, `datadeft-magic-link-axum`,
//! the in-memory fakes from `datadeft-magic-link-aws` (default, SDK-free build), and
//! `datadeft-pow-core` together.
//!
//! This binary is intentionally local-development only. It uses the
//! crate-shipped in-memory fakes for storage/rate limiting/outbox, generates
//! fresh development secrets at startup, and exposes a
//! `/dev/latest-magic-link` helper instead of sending email. The only
//! app-owned storage here is the PoW replay set, which is deliberately outside
//! the magic-link protocol.

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
use datadeft_magic_link_aws::{FakeDynamoDbAuthStore, FakeMagicLinkOutbox, StorageHmacKey};
use datadeft_magic_link_axum::{
    APPLICATION_JSON, ConfirmCookieConfig, MagicLinkFlowResponseError, MagicLinkHttpError,
    MagicLinkRequestJson, MagicLinkScannerFlowConfig, SameOriginPostConfig, SameOriginRedirect,
    SessionCookieConfig, apply_magic_link_security_headers, authenticate_session,
    clear_confirm_cookie_header, clear_session_cookie_header, generic_accepted_response,
    guarded_body, magic_link_confirmation, magic_link_landing, session_set_cookie_header,
    viewer_country_from,
};
use datadeft_magic_link_service::{
    Clock, DependencyError, KeyId, KeyPurpose, KeyRing, KeySlot, LookupHmacKey,
    MagicLinkConfirmCookie, MagicLinkFlowService, MagicLinkRequestService, MagicLinkServiceConfig,
    RootSecret, SessionCookie, refresh_session_cookie, validate_session,
};
use datadeft_pow_core::{
    Challenge, PowSecret, Solution, UnixMillis, mint_challenge, verify_solution,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

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
        .route("/auth/magic-link", get(landing_route))
        .route("/auth/magic-link/consume", post(confirm_route))
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
    /// Crate-shipped in-memory fake implementing every repository trait plus
    /// the rate limiter, mirroring the DynamoDB adapter's storage shape.
    auth: FakeDynamoDbAuthStore,
    outbox: FakeMagicLinkOutbox,
    /// App-owned PoW replay set (tid -> expiry). PoW admission is outside the
    /// magic-link protocol, so its replay store is application code.
    pow_replay: Arc<Mutex<HashMap<String, u64>>>,
    config: MagicLinkServiceConfig,
    http_config: Arc<MagicLinkScannerFlowConfig>,
    lookup_hmac_key: Arc<LookupHmacKey>,
    confirm_keyring: Arc<KeyRing<MagicLinkConfirmCookie>>,
    session_keyring: Arc<KeyRing<SessionCookie>>,
    pow_secret: Arc<PowSecret>,
}

/// Wall clock for the example. The library never reads the clock itself. The
/// application supplies it.
struct LocalClock;

impl Clock for LocalClock {
    fn now_unix(&self) -> Result<u64, DependencyError> {
        current_unix()
    }
}

fn build_state() -> AppResult<AppState> {
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
    KeyRing::new(vec![KeySlot::active_with_windows(
        key_id,
        key,
        mint_until,
        verify_until,
    )])
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

async fn pow_challenge(
    State(state): State<AppState>,
) -> Result<Json<PowChallengeJson>, (StatusCode, &'static str)> {
    let mut entropy = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "randomness unavailable\n"))?;
    let now = current_unix_millis()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "clock unavailable\n"))?;
    let challenge = mint_challenge(&state.pow_secret, POW_DIFFICULTY, now, entropy)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "pow unavailable\n"))?;
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
        terms_accepted: body.terms_accepted,
        privacy_accepted: body.privacy_accepted,
    }
    .into_command()?;

    let mut rng = OsRng;
    let mut service = MagicLinkRequestService {
        magic_links: &state.auth,
        limiter: &state.auth,
        outbox: &state.outbox,
        clock: &LocalClock,
        rng: &mut rng,
        lookup_hmac_key: state.lookup_hmac_key.as_ref(),
        config: state.config.clone(),
    };
    service
        .request_magic_link(command)
        .await
        .map_err(MagicLinkHttpError::from)?;
    Ok(generic_accepted_response())
}

// The landing GET is side-effect-free (the library guarantees it never
// consumes the link), so this application owns the interstitial page. It
// renders the account and a form that POSTs the confirmation back same-origin
// This step consumes the link. Errors are returned with the SAME
// 200 status as success so link validity is not enumerable.
async fn landing_route(State(state): State<AppState>, request: Request) -> Response {
    let config = state.http_config.clone();
    let result = magic_link_landing(request, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        let mut service = MagicLinkFlowService {
            authentication: &state.auth,
            sessions: &state.auth,
            limiter: &state.auth,
            clock: &LocalClock,
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            previous_lookup_hmac_key: None,
            confirm_keyring: state.confirm_keyring.as_ref(),
            session_keyring: state.session_keyring.as_ref(),
            config: state.config.clone(),
        };
        service.begin_magic_link_landing(command).await
    })
    .await;

    match result {
        Ok(landing) => {
            let page = format!(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Confirm sign in</title></head><body><main><h1>Confirm sign in</h1><p>Sign in as <strong>{}</strong>.</p><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"confirmation\" value=\"{}\"><button type=\"submit\">Continue sign in</button></form></main></body></html>",
                escape_html(landing.outcome.account_identity().as_str()),
                escape_html(config.post_action().as_str()),
                escape_html(landing.outcome.confirmation_value()),
            );
            let mut response = Html(page).into_response();
            response
                .headers_mut()
                .append(SET_COOKIE, landing.confirm_cookie);
            apply_magic_link_security_headers(response.headers_mut());
            response
        }
        // Same 200 status as success (non-enumeration); dependency/internal
        // failures may use their own status.
        Err(MagicLinkFlowResponseError::Rejected) => scanner_page(
            StatusCode::OK,
            "<!doctype html><h1>Unable to continue sign in</h1><p>Request a new link.</p>",
        ),
        Err(MagicLinkFlowResponseError::Unavailable) => scanner_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service temporarily unavailable.",
        ),
        Err(MagicLinkFlowResponseError::Internal) => {
            scanner_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
        }
    }
}

// The confirmation POST is the only step that consumes the link and mints the
// session. On success this app 303-redirects to /auth/complete with the session
// cookie. An SPA would return JSON instead.
async fn confirm_route(State(state): State<AppState>, request: Request) -> Response {
    let config = state.http_config.clone();
    let result = magic_link_confirmation(request, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        let mut service = MagicLinkFlowService {
            authentication: &state.auth,
            sessions: &state.auth,
            limiter: &state.auth,
            clock: &LocalClock,
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            previous_lookup_hmac_key: None,
            confirm_keyring: state.confirm_keyring.as_ref(),
            session_keyring: state.session_keyring.as_ref(),
            config: state.config.clone(),
        };
        service.confirm_magic_link_flow(command).await
    })
    .await;

    match result {
        Ok(confirmed) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SEE_OTHER;
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/auth/complete"));
            response
                .headers_mut()
                .append(SET_COOKIE, confirmed.session_cookie);
            response
                .headers_mut()
                .append(SET_COOKIE, confirmed.clear_confirm_cookie);
            apply_magic_link_security_headers(response.headers_mut());
            response
        }
        Err(MagicLinkFlowResponseError::Rejected) => {
            let mut response = scanner_page(StatusCode::BAD_REQUEST, "Invalid confirmation.");
            response.headers_mut().append(
                SET_COOKIE,
                clear_confirm_cookie_header(config.confirm_cookie()),
            );
            response
        }
        Err(MagicLinkFlowResponseError::Unavailable) => scanner_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service temporarily unavailable.",
        ),
        Err(MagicLinkFlowResponseError::Internal) => {
            scanner_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
        }
    }
}

fn scanner_page(status: StatusCode, body: &'static str) -> Response {
    let mut response = (status, Html(body)).into_response();
    apply_magic_link_security_headers(response.headers_mut());
    response
}

async fn auth_complete() -> Html<&'static str> {
    Html(
        "<!doctype html><h1>Signed in</h1><p>The scanner-safe POST completed. Try <a href=\"/me\">/me</a>.</p>",
    )
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth_state = state.clone();
    // Country pinning: pass the trusted-edge signal for this request. Sessions
    // issued without a country are unlocked and ignore it.
    let country = viewer_country_from(&headers, state.http_config.country_header());
    match authenticate_session(
        &headers,
        state.http_config.session_cookie(),
        move |cookie| async move {
            validate_session(
                cookie.as_str(),
                country.as_deref(),
                auth_state.session_keyring.as_ref(),
                &auth_state.auth,
                &LocalClock,
                &auth_state.config,
            )
            .await
        },
    )
    .await
    {
        Ok(session) => {
            let mut response = Html(format!(
                "<!doctype html><h1>Authenticated</h1><p>User: {}</p><p>Email: {}</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Logout</button></form>",
                escape_html(session.session().user_id.as_str()),
                escape_html(session.session().email.as_str()),
            ))
            .into_response();
            // Authenticated pages are never cacheable, and a refreshed bearer
            // cookie must not be stored by any shared cache: no-store et al.
            apply_magic_link_security_headers(response.headers_mut());
            // Sliding session: re-issue the cookie once half the idle lifetime
            // has passed. The absolute lifetime and revocation still apply.
            let mut rng = OsRng;
            match refresh_session_cookie(
                &session,
                state.session_keyring.as_ref(),
                &mut rng,
                &LocalClock,
                &state.config,
            ) {
                Ok(Some(refreshed)) => {
                    match session_set_cookie_header(
                        state.http_config.session_cookie(),
                        refreshed.as_secret_value(),
                    ) {
                        Ok(header) => {
                            response.headers_mut().append(SET_COOKIE, header);
                        }
                        Err(_) => {
                            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
                                .into_response();
                        }
                    }
                }
                // Not due yet: keep the current cookie.
                Ok(None) => {}
                // A failed refresh does not end a valid session, but operators
                // must see it: a lapsed session-key mint window would otherwise
                // silently log everyone out at the idle limit. The error kind
                // carries no secret.
                Err(error) => eprintln!("session refresh failed: {error}"),
            }
            response
        }
        Err(rejection) => rejection.into_response(),
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_same_origin_post(&headers) {
        return (StatusCode::FORBIDDEN, "forbidden\n").into_response();
    }

    let auth_state = state.clone();
    let country = viewer_country_from(&headers, state.http_config.country_header());
    let session = match authenticate_session(
        &headers,
        state.http_config.session_cookie(),
        move |cookie| async move {
            validate_session(
                cookie.as_str(),
                country.as_deref(),
                auth_state.session_keyring.as_ref(),
                &auth_state.auth,
                &LocalClock,
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
    let service = MagicLinkFlowService {
        authentication: &state.auth,
        sessions: &state.auth,
        limiter: &state.auth,
        clock: &LocalClock,
        rng: &mut rng,
        lookup_hmac_key: state.lookup_hmac_key.as_ref(),
        previous_lookup_hmac_key: None,
        confirm_keyring: state.confirm_keyring.as_ref(),
        session_keyring: state.session_keyring.as_ref(),
        config: state.config.clone(),
    };
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
    match latest_magic_link(&state.outbox) {
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
) -> Result<(), datadeft_pow_core::PowError> {
    let now = current_unix_millis().map_err(|_| datadeft_pow_core::PowError::InvalidTimestamp)?;
    let verified = verify_solution(
        &state.pow_secret,
        &body.into_solution(),
        now,
        POW_CHALLENGE_TTL_SECS,
        POW_DIFFICULTY,
    )?;
    // The replay table keeps whole-second bookkeeping.
    let now_unix = now.as_secs();
    let expires_at_unix = now_unix
        .checked_add(POW_CHALLENGE_TTL_SECS)
        .ok_or(datadeft_pow_core::PowError::InvalidTimestamp)?;
    consume_pow_tid(&state.pow_replay, &verified.tid, now_unix, expires_at_unix)
        .map_err(|_| datadeft_pow_core::PowError::InvalidSolution)?;
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

fn current_unix_millis() -> Result<UnixMillis, DependencyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .map(UnixMillis::from_millis)
        .ok_or(DependencyError::Internal)
}

#[derive(Debug, Deserialize)]
struct RequestMagicLinkWithPow {
    email: String,
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

/// Local-development helper: render the newest outbox email as a clickable
/// relative magic link instead of sending real mail.
fn latest_magic_link(outbox: &FakeMagicLinkOutbox) -> Option<String> {
    let email = outbox.recorded().ok()?.pop()?;
    let token = email.token.as_secret_value();
    Some(format!("/auth/magic-link?token={}", token.as_str()))
}

/// Single-use PoW proof enforcement: reject a tid that was already spent and
/// drop expired entries.
fn consume_pow_tid(
    replay: &Mutex<HashMap<String, u64>>,
    tid: &str,
    now_unix: u64,
    expires_at_unix: u64,
) -> Result<(), DependencyError> {
    let mut tids = replay.lock().map_err(|_| DependencyError::Internal)?;
    tids.retain(|_, expires_at| *expires_at > now_unix);
    if tids.contains_key(tid) {
        return Err(DependencyError::ConditionalWriteFailed);
    }
    tids.insert(tid.to_owned(), expires_at_unix);
    Ok(())
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

#[cfg(test)]
mod tests {
    //! Logout contract from docs/security.md: logout is a CSRF-protected
    //! unsafe method, and it revokes server state before clearing the cookie.

    use axum::http::header::COOKIE;
    use datadeft_magic_link_service::{
        BeginMagicLinkLandingCommand, ConfirmMagicLinkFlowCommand, NormalizedEmail,
        RequestMagicLinkCommand, SessionRepository,
    };

    use super::*;

    /// Log in through the real services and return the session cookie value.
    async fn logged_in(state: &AppState) -> (String, datadeft_magic_link_service::SessionId) {
        let mut rng = OsRng;
        MagicLinkRequestService {
            magic_links: &state.auth,
            limiter: &state.auth,
            outbox: &state.outbox,
            clock: &LocalClock,
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            config: state.config.clone(),
        }
        .request_magic_link(RequestMagicLinkCommand::new(
            NormalizedEmail::parse("logout-test@example.test").expect("email"),
            true,
            true,
        ))
        .await
        .expect("request");
        let email = state.outbox.recorded().expect("outbox").remove(0);
        let mut service = MagicLinkFlowService {
            authentication: &state.auth,
            sessions: &state.auth,
            limiter: &state.auth,
            clock: &LocalClock,
            rng: &mut rng,
            lookup_hmac_key: state.lookup_hmac_key.as_ref(),
            previous_lookup_hmac_key: None,
            confirm_keyring: state.confirm_keyring.as_ref(),
            session_keyring: state.session_keyring.as_ref(),
            config: state.config.clone(),
        };
        let landing = service
            .begin_magic_link_landing(BeginMagicLinkLandingCommand::new(
                email.token.as_secret_value().to_string(),
            ))
            .await
            .expect("landing");
        let outcome = service
            .confirm_magic_link_flow(
                ConfirmMagicLinkFlowCommand::new(
                    landing.confirm_cookie_value().to_owned(),
                    landing.confirmation_value().to_owned(),
                    None,
                )
                .expect("command"),
            )
            .await
            .expect("confirm");
        (
            outcome.authentication().session_cookie_value().to_owned(),
            outcome.authentication().session_id().clone(),
        )
    }

    fn logout_headers(state: &AppState, cookie: &str, origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let name = state.http_config.session_cookie().name();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{name}={cookie}")).expect("cookie"),
        );
        if let Some(origin) = origin {
            headers.insert(ORIGIN, HeaderValue::from_str(origin).expect("origin"));
        }
        headers
    }

    async fn session_is_live(
        state: &AppState,
        id: &datadeft_magic_link_service::SessionId,
    ) -> bool {
        let now = current_unix().expect("clock");
        state
            .auth
            .find_session(id, now)
            .await
            .expect("find")
            .is_some()
    }

    #[tokio::test]
    async fn logout_without_same_origin_is_forbidden_and_keeps_the_session() {
        let state = build_state().expect("state");
        let (cookie, session_id) = logged_in(&state).await;
        for origin in [None, Some("https://attacker.example.test"), Some("null")] {
            let response = logout(
                State(state.clone()),
                logout_headers(&state, &cookie, origin),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(response.headers().get(SET_COOKIE).is_none());
            assert!(session_is_live(&state, &session_id).await);
        }
    }

    #[tokio::test]
    async fn logout_revokes_server_state_and_old_cookie_stops_working() {
        let state = build_state().expect("state");
        let (cookie, session_id) = logged_in(&state).await;

        let response = logout(
            State(state.clone()),
            logout_headers(&state, &cookie, Some(LOCAL_ORIGIN)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cleared = response
            .headers()
            .get(SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("clearing cookie");
        assert!(cleared.contains("Max-Age=0"));
        // Server-side invalidation, not just cookie clearing.
        assert!(!session_is_live(&state, &session_id).await);

        // A captured copy of the old cookie no longer authenticates.
        let replay = logout(
            State(state.clone()),
            logout_headers(&state, &cookie, Some(LOCAL_ORIGIN)),
        )
        .await;
        assert_ne!(replay.status(), StatusCode::SEE_OTHER);
    }
}

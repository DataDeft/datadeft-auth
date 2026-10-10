//! The redirect landing mode (docs/security.md, "Redirect landing mode"), for
//! apps whose UI is static files: the emailed link lands on
//! `/auth/magic-link/open`, which redirects to the static page
//! `/login/confirm`. That page reads `/auth/magic-link/flow-state` and posts
//! the confirmation to the same route as the server-rendered mode.

use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, REFERRER_POLICY, X_FRAME_OPTIONS};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use datadeft_magic_link_axum::{magic_link_flow_state, magic_link_landing_redirect};
use rand_core::OsRng;

use super::state::AppState;

/// `GET /auth/magic-link/open?token=…`: `303` to the static page for every
/// link state; never consumes the link.
pub(super) async fn redirect_landing_route(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let config = state.http_config.clone();
    magic_link_landing_redirect(request, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        state
            .flow_service(&mut rng)
            .begin_magic_link_landing(command)
            .await
    })
    .await
}

/// `GET /auth/magic-link/flow-state`: `{ usable, account, confirmation }` for
/// the static page; read-only and repeatable.
pub(super) async fn flow_state_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let config = state.http_config.clone();
    magic_link_flow_state(&headers, config.as_ref(), move |command| async move {
        let mut rng = OsRng;
        state
            .flow_service(&mut rng)
            .read_magic_link_flow_state(command)
            .await
    })
    .await
}

/// `GET /login/confirm`: the static confirm page. In production it is a file
/// on a CDN; the headers below are what that CDN must send. It holds the
/// account and the confirmation value, so: scripts only from this origin, no
/// third-party anything, no framing.
pub(super) async fn confirm_page() -> Response {
    let mut response = Html(CONFIRM_PAGE_HTML).into_response();
    static_page_headers(response.headers_mut());
    response
}

/// `GET /login/confirm.js`: the page's only script.
pub(super) async fn confirm_page_script() -> Response {
    let mut response = CONFIRM_PAGE_JS.into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    static_page_headers(headers);
    response
}

fn static_page_headers(headers: &mut HeaderMap) {
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("strict-origin"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

const CONFIRM_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Confirm sign in</title>
  <script src="/login/confirm.js" defer></script>
</head>
<body>
  <main>
    <h1>Confirm sign in</h1>
    <p id="status" aria-live="polite">Checking your link…</p>
    <form id="confirm" hidden>
      <p>Sign in as <strong id="account"></strong>.</p>
      <button type="submit">Continue sign in</button>
    </form>
  </main>
</body>
</html>
"#;

const CONFIRM_PAGE_JS: &str = r#"const status = document.getElementById('status');
const form = document.getElementById('confirm');
const unusable = 'This link cannot be used. Request a new one.';

(async () => {
  const response = await fetch('/auth/magic-link/flow-state', {
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!response.ok) {
    status.textContent = 'The service is busy. Reload this page in a moment.';
    return;
  }
  const state = await response.json();
  if (!state.usable) {
    status.textContent = unusable;
    return;
  }
  document.getElementById('account').textContent = state.account;
  status.textContent = '';
  form.hidden = false;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const confirmed = await fetch('/auth/magic-link/consume', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ confirmation: state.confirmation }),
    });
    form.hidden = true;
    if (confirmed.ok) {
      window.location.assign('/auth/complete');
    } else {
      status.textContent = unusable;
    }
  });
})();
"#;

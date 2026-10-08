//! Development-only pages: the index and the outbox helper.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use datadeft_magic_link_aws::FakeMagicLinkOutbox;

use super::state::*;
use super::util::*;

pub(super) async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

pub(super) async fn dev_latest_magic_link(State(state): State<AppState>) -> Response {
    match latest_magic_link(&state.outbox) {
        Some(link) => Html(format!(
            "<!doctype html><h1>Development outbox</h1><p>This endpoint exposes a local-only bearer magic link for the example app.</p><p><a href=\"{}\">Continue sign in</a></p>",
            escape_html(&link),
        ))
        .into_response(),
        None => (StatusCode::NOT_FOUND, "no development magic-link email queued\n").into_response(),
    }
}

/// Local-development helper: render the newest outbox email as a clickable
/// relative magic link instead of sending real mail.
pub(super) fn latest_magic_link(outbox: &FakeMagicLinkOutbox) -> Option<String> {
    let email = outbox.recorded().ok()?.pop()?;
    let token = email.token.as_secret_value();
    Some(format!("/auth/magic-link?token={}", token.as_str()))
}

pub(super) const INDEX_HTML: &str = r#"<!doctype html>
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

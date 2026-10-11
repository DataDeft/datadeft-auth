# Integration guide

This guide shows how to wire the datadeft-auth libraries into an Axum
application. Read it first. Then follow it from top to bottom.

The libraries own the auth logic. Your application owns routes, deployment
policy, secrets, email templates, logs, and edge policy.

## Read these next, in order

1. [architecture.md](architecture.md): components, flows, and trust
   boundaries.
2. [security.md](security.md): required security behavior and the TTL
   baseline. These rules are not optional.
3. The module docs and the compiling quickstart in
   `crates/datadeft-magic-link-axum/src/lib.rs`.
4. `examples/axum-magic-link`: a complete, runnable, fake-backed integration.
   This is your reference. Copy its wiring.

Do not invent an approach. Follow the example and the trait contracts.

## Install

You need Rust 1.88 or newer.

```toml
[dependencies]
datadeft-pow-core           = "0.5"
datadeft-magic-link-service = "0.5"
datadeft-magic-link-axum    = "0.5"
datadeft-magic-link-aws     = { version = "0.5", features = ["aws"] }
# Add datadeft-pow-axum = "0.5" for the PoW HTTP helpers.
```

The latest published version is 0.4.1. Until 0.5.0 is on the registries,
replace each version with
`{ git = "https://github.com/DataDeft/datadeft-auth", rev = "<commit>" }`.
Keep `features`.

```sh
bun add @datadeft/protect-client
```

Cargo adds the other core crates as transitive dependencies. The service and
Axum crates re-export the types that you need. Commit your lockfiles. After
0.5.0 is on the registries, you need no git credentials and no vendored
TypeScript.

To upgrade an existing app, see [Upgrading from 0.4](#upgrading-from-04).

## What you provide

The libraries hold no globals. You inject every dependency.

- **A `Clock` and a CSPRNG.** Use the OS CSPRNG. Never use a fake clock or
  fake entropy in production.
- **Keyrings** that you build from a `RootSecret` from AWS Secrets Manager.
  `resolve_auth_secrets` in `datadeft-magic-link-aws` loads them.
  - Use one keyring per purpose: `SessionCookie`, `MagicLinkConfirmCookie`,
    and `PowProofCookie` (the proof cookie).
  - Configure an active slot and verify-only slots.
  - Rotate about every 90 days. Keep the previous key verify-only for at least
    31 days.
- **A `MagicLinkEmailRenderer`.** You own the subject, the text and HTML
  bodies, and the copy for each language. It takes `MagicLinkEmail { email,
  token, expires_at_unix, locale }` and returns `RenderedMagicLinkEmail`. The
  library never stores or templates the message body.
  - Set `MagicLinkServiceConfig::locales` to a `LocaleAllowlist` to get a
    resolved `locale`. The optional `locale` hint in the request selects one of
    its entries. Any other value gets the default.
  - Set Reply-To with `SesMagicLinkOutbox::with_reply_to`. Requests cannot
    set it.
- **Storage and delivery adapters.** Use `datadeft-magic-link-aws` for
  DynamoDB and SES. As an alternative, implement the repository, session,
  limiter, and outbox traits yourself. Use `FakeDynamoDbAuthStore` and
  `FakeMagicLinkOutbox` in tests.
- **Routes, cookie configuration, redirects, body limits, and token-safe
  logging.**

## The flow you wire

The Axum handlers are headless. They check input and return structured results
plus prepared cookie headers. Your application renders the responses.

1. **Request.** `POST` to `request_magic_link`. It validates consent,
   normalizes and validates the email, and mints a selector and a verifier. It
   stores the record under keyed lookup material (never the raw token). Then it
   gives the URL to your outbox.
2. **Landing.** The landing is a `GET`. It has no side effects and you can
   repeat it. It sets the confirm cookie (`dd_auth_confirm`) and never consumes
   the token. Select one mode:
   - **Server-rendered mode:** `magic_link_landing`
     (`begin_magic_link_landing`). Render the account and a same-origin `POST`
     form.
   - **Redirect landing mode:** use it for UIs that you serve as static files.
     Enable it with
     `MagicLinkScannerFlowConfig::with_redirect_landing(page, flow_state)`.
     `magic_link_landing_redirect` answers `303` to `page` for every link
     state. The page sends a `GET` to `flow_state` (`magic_link_flow_state`,
     `read_magic_link_flow_state`) to get `{ usable, account, confirmation }`.
     Then the page shows the account and posts the confirmation. Obey the
     static page rules in [security.md](security.md#redirect-landing-mode).

   Never return the landing that carries the token as JSON for a static page to
   fetch. That puts the token in JavaScript.
3. **Confirm.** `POST` to `magic_link_confirmation`
   (`confirm_magic_link_flow`). Accept same-origin requests only. It consumes
   the token and creates the session in one atomic transaction. Then it issues
   the session cookie (`dd_session`). Clear `dd_auth_confirm` at this step.
4. **Validate.** Check `dd_session` on protected routes. On logout, revoke
   server state before you clear the cookie. There is no refresh token. When
   the session lifetime ends, the user signs in again with a new magic link.

## Cookies

| Cookie | Purpose | Default lifetime | Path |
| --- | --- | --- | --- |
| `dd_session` (session cookie) | logged-in session | 24h idle, 30d absolute | `/` |
| `dd_auth_confirm` (confirm cookie) | scanner-safe confirmation flow | 5 minutes | `/auth` |
| `dd_pow` (proof cookie) | proof-of-work admission | 3 hours | `/` |

All three cookies are `HttpOnly`, `Secure` (outside local development),
`SameSite=Lax`, and host-only.

## Security invariants you must uphold

This section gives the critical invariants. See [security.md](security.md) for
the full set.

- Consume the magic link only on the same-origin confirmation `POST`. Never
  consume it on `GET`.
- Make sure that the landing `GET` has no side effects and that a client can
  repeat it. Email scanners prefetch it.
- Give uniform responses, so that an attacker cannot probe link validity:
  - A rejected landing returns the same HTTP status as success.
  - A rejected confirmation returns one generic failure (the example answers
    `400`).
  - Only genuine `Unavailable` or `Internal` failures use the constant `503`.
- Clear `dd_auth_confirm` on a `Rejected` confirmation. Keep it on
  `Unavailable` so that the user can retry. On `Internal`, you can clear it or
  keep it.
- Set security headers on every landing and confirmation response.
- Never echo the raw token into a body or logs. HTML-escape each rendered
  account identity.
- Implement the repository contract atomically, with strong reads.
- Store only keyed HMAC lookup material and verifier hashes. Never store raw
  tokens, selectors, or verifiers.
- Store the normalized email as readable data at rest. DynamoDB KMS and
  least-privilege IAM protect it. Do not add application-layer field
  encryption.

## The mandatory deployment gate

The landing request target carries the magic-link token. Before production, do
these steps:

1. Configure proxy or load-balancer request-line bounds.
2. Prove that access logs, middleware, tracing, metrics, and error reporting
   use route templates. They must never keep raw request targets, tokens,
   confirmations, or cookies.

The handlers prove non-reflection only after handler entry. They cannot make
an unreviewed outer stack safe. See "Mandatory deployment gate" in
`crates/datadeft-magic-link-axum/src/lib.rs`.

## Proof-of-work admission

Proof-of-work is the primary defense against dumb bots. We recommend it.

On the server, wire `datadeft-pow-axum`:

1. For `pow/create`, route a `POST` to `mint_pow_challenge`.
2. For `pow/validate`, route a `POST` to `verify_pow_solution`. It returns a
   `PowAdmission`. The `PowAdmission` holds the `dd_pow` `Set-Cookie` header
   and the server-derived `mint_to_verify_ms` solve-timing signal (see
   [security.md](security.md#solve-timing-signal)). Its `classify_solve` hook
   can put an app-defined class byte into the cookie. To opt out, pass
   `|_| None`.
3. Gate the magic-link request behind a valid `dd_pow` cookie.

In the browser, bundle the `@datadeft/protect-client/worker` entry into an ES
module worker that you serve. Then call
`protect({ workerUrl, createUrl, validateUrl })` on your login page. See the
[client README](../packages/dd-protect-client/README.md).

The challenge lifetime is 2 minutes. The proof cookie is stateless and lasts 3
hours by default. You can configure its lifetime.

### Per-solve budget

A proof cookie is stateless. Without a budget, one solve admits unlimited
requests for 3 hours. To limit it, gate every protected route with
`admit_proof`. `admit_proof` verifies the `dd_pow` cookie. Then it spends one
unit from the per-solve budget of that solve.

`ProofBudgetPolicy::new(5)` gives 5 admissions per solve. `new` accepts
`1..=1000` (`MAX_PROOF_BUDGET_PER_SOLVE`). The budget has these properties:

- **shared:** one counter per solve (`tid`) for the whole deployment, never
  per node.
- **over the proof's lifetime:** the first spend sets the counter's expiry
  past every cookie that solve can produce. The counter never refills before
  that expiry.
- **fail closed:** a store failure refuses the request.

`spec/tla/PowBudget.tla` checks these three rules. Implement `ProofBudget` over
the lifetime counter of the shared limiter. The example does it in a few lines:

```rust
impl ProofBudget for MyBudget {
    async fn spend(&self, tid: &str, per_solve: u32, expires_at_unix: u64, now_unix: u64)
        -> Result<ProofBudgetDecision, ProofBudgetUnavailable>
    {
        let key = RateLimitKey::parse(&format!("pow:budget:{tid}"))
            .map_err(|_| ProofBudgetUnavailable)?;
        match self.store.check_lifetime_limit(&key, per_solve, expires_at_unix, now_unix).await {
            Ok(RateLimitDecision::Allowed) => Ok(ProofBudgetDecision::Spent),
            Ok(RateLimitDecision::Denied) => Ok(ProofBudgetDecision::Exhausted),
            Err(_) => Err(ProofBudgetUnavailable),
        }
    }
}
```

On `Err`, return the `ProofRejection` itself:

- A missing, invalid or expired proof, or a used-up budget, answers `401` with
  `WWW-Authenticate: DD-PoW`. Then `@datadeft/protect-client` solves and
  retries once. The new solve gets a new budget.
- A store failure answers the constant `503` (fail closed).

Log `ProofRejection::reason()` internally. Never send it.

### PoW keys

Load both PoW keys from the auth secret document
([security.md](security.md#auth-secret-document)), not from app-specific
fields:

```rust
let secrets = resolve_auth_secrets(&secrets_manager, &config.secrets).await?;
let pow_secret = PowSecret::new(*secrets.pow_challenge_secret.as_bytes());
let pow_proof_keyring = secrets.pow_proof_keyring::<PowProofCookie>()?; // at startup
```

During a rotation, if `secrets.previous_pow_challenge_secret` is set, also
verify challenges with it. Some challenges carry the previous secret. These are
the challenges that the server minted before the rotation, within the challenge
max age. The challenge max age is 120 s by default
(`DEFAULT_POW_CHALLENGE_MAX_AGE_SECS`).

## Clock-skew policy

The default tolerance is 60 seconds of future skew.
[security.md](security.md#clock-skew) gives the policy. To apply a stricter
bound:

- For 30 seconds, use
  `verify_solution_with_clock_skew(..., 30)` and
  `verify_pow_proof_cookie_with_clock_skew(..., 30)`.
- In Axum, set `PowPolicy::new(difficulty, 120)?.with_clock_skew_secs(30)?`
  for challenges. At your gate, use the explicit proof-cookie verifier with the
  same bound.
- datadeft-auth-token-core also exposes `mint_bound_cookie_with_clock_skew` and
  `parse_bound_cookie_with_clock_skew`. Both functions take `clock_skew_secs`
  as the last argument.
- The PoW policy does not silently change the cookie validation of another
  subsystem.

## Runtime note

The dependency traits require `Send` futures and use static dispatch only. Run
on a multi-threaded Tokio runtime (the Axum default). Do not wrap the traits in
`dyn` trait objects.

## Definition of done

Complete the production checklist in [onboarding.md](onboarding.md). In
particular, make sure that:

- The magic-link flow works end to end against real DynamoDB and SES.
- Integration tests cover replay, concurrent confirmation, ambiguous retry,
  logout, and post-revocation visibility.
- A production-like probe confirms that logs contain no token material.
- The consuming application tests pass.

Report the changed files, the traits that you implemented, and the
security-sensitive decisions. Also report the tests that you added and each
checklist item that you could not complete.

## Upgrading from 0.4

0.5.0 is a breaking release. The library is pre-1.0 and has no production
deployments. To upgrade, start with a new table and a new secret document. The
library provides no data migration, and every existing session ends.

### Ids and storage

- **Hyphen ids:** user, session, attempt and admin event ids are now `usr-`,
  `sid-`, `aid-` and `evt-` followed by lowercase hex. Session display ids are
  `sess-`. Parsers refuse the 0.4 underscore form. Stored 0.4 users, sessions,
  and audit events stop working. Every live session cookie also stops working,
  because it carries the session id. Start from an empty table.
- **Keyed lookup values** (`emh_`, `mlh_`, `mlv_`, `sih_`, `rlh_`) are
  unchanged.

### Configuration and types

- **Cookie config constructors** (`SessionCookieConfig`,
  `ConfirmCookieConfig`, `PowProofCookieConfig`): `production(...)` is now
  `secure(...)`, `local_development(...)` is `insecure_local(...)`, and the
  `*_defaults()` constructors follow (`secure_defaults()`,
  `insecure_local_defaults()`). The `secure()` getter is now `is_secure()`.
- **Email normalization:** the library now normalizes the email.
  `NormalizedEmail::normalize` trims and ASCII-lowercases the whole address
  (local part included, a documented policy). `MagicLinkRequestJson` uses it.
  0.5 renames `NormalizedEmail::parse` to `from_normalized`. It only validates,
  and it refuses uppercase and surrounding whitespace. Remove app-side
  normalization.
- **Email locale and Reply-To:** `MagicLinkEmail` gains `locale`. The library
  resolves it from the optional `locale` hint in the request against
  `MagicLinkServiceConfig::locales` (a `LocaleAllowlist`). The library never
  stores it. `MagicLinkRequestJson` accepts the `locale` field.
  `SesMagicLinkOutbox::with_reply_to` sets Reply-To for every email. Remove
  per-request outboxes.
- **New config fields:** `MagicLinkServiceConfig` gains `country_policy`
  (default `CountryPolicy::Exact`) and `locales` (default `None`).
  `MagicLinkConfigError` gains `InvalidCountryPolicy`. Struct literals and
  exhaustive matches must add them.
- **Country groups:** `MagicLinkServiceConfig::country_policy` can be
  `CountryPolicy::eu27()`. With this policy, sessions move between EU countries.
  Outside the group, the country match stays exact. Remove edge rewrites of the
  country header. `ValidatedSession::country()` returns the pinned value, which
  is `EU` for a session in the group.
- **Admin writes are versioned:**
  `AuthAdminRepository::set_user_disabled_audited` takes
  `expected_version: Option<u64>`. Use `None` for an unconditional disable. Use
  `Some(version read)` for an enable. `UserSummary` carries `admin_version`. If
  an enable loses a race, it returns `AdminError::Conflict` and writes nothing.
  Then read again and decide again.
- **Request outcome:** `request_magic_link` returns
  `RequestMagicLinkOutcome::Sent` or `Throttled(RequestThrottle)` instead of a
  unit struct. Count the outcome. The public answer stays the same `200`.
- **Redirect landing mode:** this mode is new. It is for static confirm pages
  (`with_redirect_landing`, `magic_link_landing_redirect`,
  `magic_link_flow_state`). Server-rendered mode is unchanged.
- **`KeyPurpose`:** every impl must declare `LARGEST_BODY_BYTES`, the largest
  body that the purpose mints. Use 0 only for test purposes.

### HTTP responses and clients

- **Response contract** ([security.md](security.md#http-response-contract)):
  - One generic `400` for shape errors (including `UnsupportedMediaType` and
    `PayloadTooLarge`) and for an unusable link (`MagicLinkUnavailable`).
  - `401` + `WWW-Authenticate: DD-Session` for an invalid session.
  - The constant `503` for every fault. `Internal` no longer answers `500`.
  - 0.5 removes `MagicLinkHttpError::Forbidden`. The library sends no `403`.
  - `reason()` labels use namespaces (`magic_link_*`, `session_*`, `pow_*`).
    Alert on their counts, not on raw `5xx` rates.
- **Browser client:** `@datadeft/protect-client` adds `protectedFetch`. On
  `401` + `DD-PoW`, it solves and retries once. On `503`, it uses a backoff
  with equal jitter for repeatable requests. In the frontend, replace status
  inference with `protectedFetch`.
- **PoW statuses and the per-solve budget:** a rejected solution, a missing or
  invalid proof, and a used-up budget answer `401` with
  `WWW-Authenticate: DD-PoW` (`PowFlowError` and `ProofRejection` implement
  `IntoResponse`). Faults answer one constant `503`. The library no longer
  sends `403` or `500` here. Replace hand-written PoW budgets and cookie
  parsing with `admit_proof` and a `ProofBudget`. Build the `ProofBudget` over
  `RateLimiter::check_lifetime_limit`. Every `RateLimiter` must now implement
  that method.
- **Strict cookie reading:** `select_cookie` is in
  `datadeft_auth_token_core::cookie_header`, and both Axum crates re-export it.
  It selects one cookie from the `Cookie` fields. It requires exactly one
  occurrence and a bounded unquoted value. It skips malformed foreign cookies.
  Do not parse `Cookie` headers by hand. Use `select_cookie`.
- **Session rejections:** `SessionAuthRejection::kind()` returns a
  `SessionRejectionKind` (`Invalid`, `Unavailable`, `Internal`).
  `clear_cookie_header()` returns the header that clears the cookie on
  `Invalid`. Apps with their own error envelope read these values. They do not
  infer the reason from the rendered status.

### Secrets

- **Secret field rename:** `aws_storage_hmac_b64` is now `storage_hmac_b64`. A
  document with the old name no longer loads.
- **Auth secret document:** add `pow_challenge_secret_b64` and
  `pow_proof_cookie_root_b64` (32 random bytes each, independent of the other
  fields). Keep `kid` at 12 bytes or fewer. Remove app-owned PoW key fields.
  Load the keys from `LoadedAuthSecrets` instead.
- **Previous secret document (`AWSPREVIOUS`):** it must also have the 0.5
  shape. Every field is mandatory, and the library checks its `kid`. Do one of
  these:
  - Deploy the first 0.5 document with `AuthSecretsConfig::previous = None`.
  - Rewrite the previous version with both PoW fields and a `kid` of 12 bytes
    or fewer.
- **One value per field:** the auth secret document rejects the same value in
  two secret fields.
- **`kid` length:** `resolve_auth_secrets` fails for a `kid` over 38 bytes,
  and `pow_proof_keyring` fails for one over 12 bytes.
- **`LoadedAuthSecrets`:** you can no longer build it with a struct literal.
  Use `LoadedAuthSecrets::from_json`.

### Behavior changes

- The re-enable cutoff is inclusive. The library accepts a session that it
  creates in the same second as `enable_user`. Thus an immediate re-login
  works.
- `enable_user` revokes every live session first. Each one writes a
  `RevokeSession` audit event.
- `revoke_all_sessions` also revokes sessions that expired within the last
  60 s (the clock-skew tolerance).
- `domain_separated_lookup_hmac` rejects NUL in `domain` or `prefix`.
- Sign-up during a storage-key rotation writes the email lookup row under both
  the current and the previous key.
- The library ignores a previous storage key that is equal to the current key.
- `pow_proof_keyring` refuses the session and confirm cookie purposes, so the
  PoW root never keys those cookies.

## Upgrading from the git-tag crates

The crates once had `dd-*` names, and apps used them as git dependencies.

- `dd-<name>` is now `datadeft-<name>`. Imports `dd_<name>` become
  `datadeft_<name>`. The browser client is now `@datadeft/protect-client`.
- Replace old git or vendored dependencies with the dependencies in
  [Install](#install). Update the imports and regenerate the lockfiles. You
  need Rust 1.88 or newer.
- No compatibility aliases exist.
- Cookie names (`dd_pow`, `dd_session`, `dd_auth_confirm`), HMAC/HKDF domains,
  stored keys, and wire formats are unchanged. Thus you need no session or data
  migration.
- 0.3.0 also changes `mint_to_verify_ms` to `Option<u64>` (see
  `CHANGELOG.md`).
- `@datadeft/protect-client` now starts a module worker. See the
  [client README](../packages/dd-protect-client/README.md) for the worker
  entry.

# Integration guide

This guide shows how to wire the datadeft-auth libraries into an Axum
application. Read it first, then follow it top to bottom.

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
   This is your reference. Mirror its wiring.

Do not invent an approach. Follow the example and the trait contracts.

## Install

Rust 1.88 or newer is required. Until 0.5.0 is published, pin a git revision:

```toml
[dependencies]
datadeft-pow-core           = { git = "https://github.com/DataDeft/datadeft-auth", rev = "<commit>" }
datadeft-magic-link-service = { git = "https://github.com/DataDeft/datadeft-auth", rev = "<commit>" }
datadeft-magic-link-axum    = { git = "https://github.com/DataDeft/datadeft-auth", rev = "<commit>" }
datadeft-magic-link-aws     = { git = "https://github.com/DataDeft/datadeft-auth", rev = "<commit>", features = ["aws"] }
# Add datadeft-pow-axum from the same rev for the PoW HTTP helpers.
```

After 0.5.0 is published to the registries:

```toml
[dependencies]
datadeft-pow-core           = "0.5"
datadeft-magic-link-service = "0.5"
datadeft-magic-link-axum    = "0.5"
datadeft-magic-link-aws     = { version = "0.5", features = ["aws"] }
# Add datadeft-pow-axum = "0.5" for the PoW HTTP helpers.
```

```sh
bun add @datadeft/protect-client
```

The other core crates arrive transitively; the service and Axum crates
re-export the types you need. Commit your lockfiles. Once published, you need
no git credentials or vendored TypeScript.

Upgrading an existing app? See [Upgrading from 0.4](#upgrading-from-04).

## What you provide

The libraries hold no globals. You inject every dependency.

- **A `Clock` and a CSPRNG.** Use the OS CSPRNG. Never use a fake clock or
  fake entropy in production.
- **Keyrings** built from a `RootSecret` loaded from AWS Secrets Manager.
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
    resolved `locale`. The request's optional `locale` hint picks one of its
    entries; anything else gets the default.
  - Set Reply-To with `SesMagicLinkOutbox::with_reply_to`. Requests cannot
    set it.
- **Storage and delivery adapters.** Use `datadeft-magic-link-aws` for
  DynamoDB and SES, or implement the repository, session, limiter, and outbox
  traits yourself. Use `FakeDynamoDbAuthStore` and `FakeMagicLinkOutbox` in
  tests.
- **Routes, cookie configuration, redirects, body limits, and token-safe
  logging.**

## The flow you wire

The Axum handlers are headless: they check input and return structured results
plus prepared cookie headers. Your application renders the responses.

1. **Request.** `POST` to `request_magic_link`. It validates consent,
   normalizes and validates the email, and mints a selector and a verifier. It
   stores the record under keyed lookup material (never the raw token) and
   hands the URL to your outbox.
2. **Landing.** A `GET`. It is side-effect-free and repeatable. It sets the
   confirm cookie (`dd_auth_confirm`) and never consumes the token. Pick one
   mode:
   - **Server-rendered mode:** `magic_link_landing`
     (`begin_magic_link_landing`). Render the account and a same-origin `POST`
     form.
   - **Redirect landing mode**, for UIs served as static files: enable it with
     `MagicLinkScannerFlowConfig::with_redirect_landing(page, flow_state)`.
     `magic_link_landing_redirect` answers `303` to `page` for every link
     state. The page `GET`s `flow_state` (`magic_link_flow_state`,
     `read_magic_link_flow_state`) for `{ usable, account, confirmation }`,
     shows the account, and posts the confirmation. Follow the static page
     rules in [security.md](security.md#redirect-landing-mode).

   Never return the token-bearing landing as JSON for a static page to fetch.
   That puts the token in JavaScript.
3. **Confirm.** `POST` to `magic_link_confirmation`
   (`confirm_magic_link_flow`), same-origin only. It consumes the token and
   creates the session in one atomic transaction, then issues the session
   cookie (`dd_session`). Clear `dd_auth_confirm` here.
4. **Validate.** Check `dd_session` on protected routes. On logout, revoke
   server state before you clear the cookie. There is no refresh token. When
   the session lifetime lapses, the user signs in again with a new magic link.

## Cookies

| Cookie | Purpose | Default lifetime | Path |
| --- | --- | --- | --- |
| `dd_session` (session cookie) | logged-in session | 24h idle, 30d absolute | `/` |
| `dd_auth_confirm` (confirm cookie) | scanner-safe confirmation flow | 5 minutes | `/auth` |
| `dd_pow` (proof cookie) | proof-of-work admission | 3 hours | `/` |

All are `HttpOnly`, `Secure` (outside local development), `SameSite=Lax`, and
host-only.

## Security invariants you must uphold

The critical ones are below. See [security.md](security.md) for the full set.

- Consume the magic link only on the same-origin confirmation `POST`, never
  on `GET`.
- Keep the landing `GET` side-effect-free and repeatable. Email scanners
  prefetch it.
- Respond uniformly, so an attacker cannot probe link validity:
  - A rejected landing returns the same HTTP status as success.
  - A rejected confirmation returns one generic failure (the example answers
    `400`).
  - Only genuine `Unavailable` or `Internal` failures use the constant `503`.
- Clear `dd_auth_confirm` on a `Rejected` confirmation. Keep it on
  `Unavailable` so the user can retry. Clearing it on `Internal` is optional.
- Stamp security headers on every landing and confirmation response.
- Never echo the raw token into a body or logs. HTML-escape any rendered
  account identity.
- Implement the repository contract atomically, with strong reads. Store only
  keyed HMAC lookup material and verifier hashes, never raw tokens, selectors,
  or verifiers.
- Store the normalized email readable at rest, protected by DynamoDB KMS and
  least-privilege IAM. Do not add application-layer field encryption.

## The mandatory deployment gate

The landing request target carries the magic-link token. Before production:

- Configure proxy or load-balancer request-line bounds.
- Prove that access logs, middleware, tracing, metrics, and error reporting
  use route templates. They must never keep raw request targets, tokens,
  confirmations, or cookies.

The handlers prove non-reflection only after handler entry. They cannot make
an unreviewed outer stack safe. See "Mandatory deployment gate" in
`crates/datadeft-magic-link-axum/src/lib.rs`.

## Proof-of-work admission

Proof-of-work is the primary defense against dumb bots. It is recommended.

Server side, wire `datadeft-pow-axum`:

1. `POST` to `mint_pow_challenge` for `pow/create`.
2. `POST` to `verify_pow_solution` for `pow/validate`. It returns a
   `PowAdmission`: the `dd_pow` `Set-Cookie` header plus the server-derived
   `mint_to_verify_ms` solve-timing signal (see
   [security.md](security.md#solve-timing-signal)). Its `classify_solve` hook
   can stamp an app-defined class byte into the cookie; pass `|_| None` to opt
   out.
3. Gate the magic-link request behind a valid `dd_pow` cookie.

Browser side, bundle the `@datadeft/protect-client/worker` entry into a served
ES module worker. Then call `protect({ workerUrl, createUrl, validateUrl })` on
your login page. See the
[client README](../packages/dd-protect-client/README.md).

The challenge lifetime is 2 minutes. The proof cookie lasts 3 hours by
default, is configurable, and is stateless.

### Per-solve budget

A proof cookie is stateless, so on its own one solve admits unlimited requests
for 3 hours. Bound it: gate every protected route with `admit_proof`. It
verifies the `dd_pow` cookie and spends one unit of its solve's budget.

`ProofBudgetPolicy::new(5)` buys 5 admissions per solve. `new` accepts
`1..=1000` (`MAX_PROOF_BUDGET_PER_SOLVE`). The budget is:

- **shared:** one counter per solve (`tid`) for the whole deployment, never
  per node;
- **over the proof's lifetime:** the first spend fixes the counter's expiry,
  past every cookie that solve can produce, and it never refills before then;
- **fail closed:** a store failure refuses the request.

`spec/tla/PowBudget.tla` checks these three rules. Implement `ProofBudget` over
the shared limiter's lifetime counter. The example does it in a few lines:

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
  `WWW-Authenticate: DD-PoW`. The protect client then solves (which buys a
  fresh budget) and retries once.
- A store failure answers the constant `503` (fail closed).

Log `ProofRejection::reason()` internally; never send it.

### PoW keys

Load both PoW keys from the auth secret document
([security.md](security.md#auth-secret-document)), not from app-specific
fields:

```rust
let secrets = resolve_auth_secrets(&secrets_manager, &config.secrets).await?;
let pow_secret = PowSecret::new(*secrets.pow_challenge_secret.as_bytes());
let pow_proof_keyring = secrets.pow_proof_keyring::<PowProofCookie>()?; // at startup
```

During a rotation, also verify challenges with
`secrets.previous_pow_challenge_secret` when it is set. Challenges minted
within the challenge max age (120 s by default,
`DEFAULT_POW_CHALLENGE_MAX_AGE_SECS`) before the rotation carry the previous
secret.

## Clock-skew policy

The default tolerance is 60 seconds of future skew; the policy is in
[security.md](security.md#clock-skew). To apply a stricter bound:

- For 30 seconds, use
  `verify_solution_with_clock_skew(..., 30)` and
  `verify_pow_proof_cookie_with_clock_skew(..., 30)`.
- In Axum, set `PowPolicy::new(difficulty, 120)?.with_clock_skew_secs(30)?`
  for challenges, and use the explicit proof-cookie verifier with the same
  bound at your gate.
- The token crate also exposes `mint_bound_cookie_with_clock_skew` and
  `parse_bound_cookie_with_clock_skew`; both take `clock_skew_secs` last.
- The PoW policy does not silently change another subsystem's cookie
  validation.

## Runtime note

The dependency traits require `Send` futures and use static dispatch only. Run
on a multi-threaded Tokio runtime (the Axum default). Do not wrap the traits in
`dyn` trait objects.

## Definition of done

Complete the production checklist in [onboarding.md](onboarding.md). In
particular:

- The magic-link flow works end to end against real DynamoDB and SES.
- Integration tests cover replay, concurrent confirmation, ambiguous retry,
  logout, and post-revocation visibility.
- A production-like probe confirms that logs contain no token material.
- The consuming application tests pass.

Report changed files, the traits you implemented, security-sensitive
decisions, tests added, and any checklist item you could not complete.

## Upgrading from 0.4

0.5.0 is a breaking release. The library is pre-1.0 and has no production
deployments. Upgrading means a fresh table and a fresh secret document. No data
migration is provided, and every existing session ends.

### Ids and storage

- **Hyphen ids:** user, session, attempt and admin event ids are now `usr-`,
  `sid-`, `aid-` and `evt-` followed by lowercase hex. Session display ids are
  `sess-`. Parsers refuse the 0.4 underscore form. Stored 0.4 users, sessions
  and audit events stop working, and so does every live session cookie (it
  carries the session id). Start from an empty table. Keyed lookup values
  (`emh_`, `mlh_`, `mlv_`, `sih_`, `rlh_`) are unchanged.

### Configuration and types

- **Cookie config constructors** (`SessionCookieConfig`,
  `ConfirmCookieConfig`, `PowProofCookieConfig`): `production(...)` is now
  `secure(...)`, `local_development(...)` is `insecure_local(...)`, and the
  `*_defaults()` constructors follow (`secure_defaults()`,
  `insecure_local_defaults()`). The `secure()` getter is now `is_secure()`.
- **Email normalization:** the library normalizes now.
  `NormalizedEmail::normalize` trims and ASCII-lowercases the whole address
  (local part included, a documented policy). `MagicLinkRequestJson` uses it.
  `NormalizedEmail::parse` is renamed `from_normalized` and only validates: it
  refuses uppercase and surrounding whitespace. Drop app-side normalization.
- **Email locale and Reply-To:** `MagicLinkEmail` gains `locale`. It is
  resolved from the request's optional `locale` hint against
  `MagicLinkServiceConfig::locales` (a `LocaleAllowlist`) and never stored.
  `MagicLinkRequestJson` accepts the `locale` field.
  `SesMagicLinkOutbox::with_reply_to` sets Reply-To for every email. Drop
  per-request outboxes.
- **New config fields:** `MagicLinkServiceConfig` gains `country_policy`
  (default `CountryPolicy::Exact`) and `locales` (default `None`).
  `MagicLinkConfigError` gains `InvalidCountryPolicy`. Struct literals and
  exhaustive matches must add them.
- **Country groups:** `MagicLinkServiceConfig::country_policy` can be
  `CountryPolicy::eu27()`. Sessions then move between EU countries and stay
  exact elsewhere. Drop edge rewrites of the country header.
  `ValidatedSession::country()` returns the pinned value, which is `EU` for a
  session in the group.
- **Admin writes are versioned:**
  `AuthAdminRepository::set_user_disabled_audited` takes
  `expected_version: Option<u64>`: `None` for an (unconditional) disable,
  `Some(version read)` for an enable. `UserSummary` carries `admin_version`.
  An enable that lost a race returns `AdminError::Conflict` (nothing written);
  re-read and decide again.
- **Request outcome:** `request_magic_link` returns
  `RequestMagicLinkOutcome::Sent` or `Throttled(RequestThrottle)` instead of a
  unit struct. Count it; the public answer stays the same `200`.
- **Redirect landing mode:** new, for static confirm pages
  (`with_redirect_landing`, `magic_link_landing_redirect`,
  `magic_link_flow_state`). Server-rendered mode is unchanged.
- **`KeyPurpose`:** every impl must declare `LARGEST_BODY_BYTES`, the largest
  body the purpose mints. Use 0 only for test purposes.

### HTTP responses and clients

- **Response contract** ([security.md](security.md#http-response-contract)):
  - One generic `400` for shape errors (including `UnsupportedMediaType` and
    `PayloadTooLarge`) and for an unusable link (`MagicLinkUnavailable`).
  - `401` + `WWW-Authenticate: DD-Session` for an invalid session.
  - The constant `503` for every fault; `Internal` no longer answers `500`.
  - `MagicLinkHttpError::Forbidden` is removed; the library sends no `403`.
  - `reason()` labels are namespaced (`magic_link_*`, `session_*`, `pow_*`).
    Alert on their counts, not raw `5xx` rates.
- **Browser client:** `@datadeft/protect-client` adds `protectedFetch`. It
  solves on `401` + `DD-PoW` and retries once, and backs off with equal jitter
  on `503` for repeatable requests. Replace status inference in the frontend
  with it.
- **PoW statuses and the per-solve budget:** a rejected solution, a missing or
  invalid proof, and a used-up budget answer `401` with
  `WWW-Authenticate: DD-PoW` (`PowFlowError` and `ProofRejection` implement
  `IntoResponse`). Faults answer one constant `503`. The library no longer
  sends `403` or `500` here. Replace hand-written PoW budgets and cookie
  parsing with `admit_proof` and a `ProofBudget` over
  `RateLimiter::check_lifetime_limit`, which every `RateLimiter` must now
  implement.
- **Strict cookie reading:** `select_cookie` (in
  `datadeft_auth_token_core::cookie_header`, re-exported by both Axum crates)
  selects one cookie from the `Cookie` fields: exactly one occurrence, a
  bounded unquoted value, malformed foreign cookies skipped. Use it instead of
  parsing `Cookie` headers by hand.
- **Session rejections:** `SessionAuthRejection::kind()` returns a
  `SessionRejectionKind` (`Invalid`, `Unavailable`, `Internal`), and
  `clear_cookie_header()` returns the header that clears the cookie on
  `Invalid`. Apps with their own error envelope read these instead of
  inferring the reason from the rendered status.

### Secrets

- **Secret field rename:** `aws_storage_hmac_b64` is now `storage_hmac_b64`. A
  document with the old name no longer loads.
- **Auth secret document:** add `pow_challenge_secret_b64` and
  `pow_proof_cookie_root_b64` (32 random bytes each, independent of the other
  fields). Keep `kid` at 12 bytes or fewer. Remove app-owned PoW key fields
  and load the keys from `LoadedAuthSecrets` instead.
- **Previous secret document (`AWSPREVIOUS`):** it must be 0.5-shaped too.
  Every field is required and its `kid` is checked. Either deploy the first
  0.5 document with `AuthSecretsConfig::previous = None`, or rewrite the
  previous version with both PoW fields and a `kid` of 12 bytes or fewer.
- **One value per field:** the auth secret document rejects the same value
  reused in two secret fields.
- **`kid` length:** `resolve_auth_secrets` fails for a `kid` over 38 bytes,
  and `pow_proof_keyring` fails for one over 12 bytes.
- **`LoadedAuthSecrets`:** it can no longer be built with a struct literal.
  Use `LoadedAuthSecrets::from_json`.

### Behaviour changes

- The re-enable cutoff is inclusive: a session created in the same second as
  `enable_user` is accepted, so an immediate re-login works.
- `enable_user` revokes every live session first. Each one writes a
  `RevokeSession` audit event.
- `revoke_all_sessions` also revokes sessions that expired within the last
  60 s (the clock-skew tolerance).
- `domain_separated_lookup_hmac` rejects NUL in `domain` or `prefix`.
- Sign-up during a storage-key rotation writes the email lookup row under both
  the current and the previous key.
- A previous storage key equal to the current one is ignored.
- `pow_proof_keyring` refuses the session and confirm cookie purposes, so the
  PoW root never keys those cookies.

## Upgrading from the git-tag crates

The crates were once named `dd-*` and consumed as git dependencies.

- `dd-<name>` is now `datadeft-<name>`; imports `dd_<name>` become
  `datadeft_<name>`. The browser client is now `@datadeft/protect-client`.
- Replace old git or vendored dependencies with the ones in
  [Install](#install), update imports, and regenerate lockfiles. Rust 1.88 or
  newer is required.
- No compatibility aliases exist.
- Cookie names (`dd_pow`, `dd_session`, `dd_auth_confirm`), HMAC/HKDF domains,
  stored keys, and wire formats are unchanged, so no session or data migration
  is needed.
- 0.3.0 also changes `mint_to_verify_ms` to `Option<u64>` (see
  `CHANGELOG.md`).
- The client now starts a module worker. See the
  [client README](../packages/dd-protect-client/README.md) for the worker
  entry.

# datadeft-auth 0.5.0 plan

- **Status:** in progress on `main`. Nothing is released. Per-item status is
  in Section 4.
- **Release type:** breaking (pre-1.0). Upgrading means a fresh auth table and
  a fresh secret document; every 0.4 session ends. No migration tools.
- **First consumer:** CeleraTax (core-dev cell), PR DataDeft/celeratax#149,
  which adopts 0.5.0 in one go.
- **No release candidates.** CeleraTax tests against a pinned commit of `main`
  (git dependency); 0.5.0 is published once that passes.

## 1. Goals

1. Consumers need no workarounds for: id format, static confirm pages, email
   normalization, email locale, EU session roaming, PoW keys, the PoW
   per-solve budget, cookie parsing, or session-rejection handling.
2. One public HTTP status contract that leaks nothing about accounts, links,
   limits, or quotas.
3. Fix the 0.4.0 security bugs found during the CeleraTax review.
4. Keep every rule in `docs/security.md` except those this plan changes on
   purpose, and update the doc where it does.

## 2. Non-goals

- Configurable status codes, id separators, or anything else with more than
  one supported way.
- Provider-specific email folding (Gmail dots, plus tags).
- An admin UI. The library stays headless.
- Passwords, OAuth, WebAuthn.
- GDPR erasure in this release (deferred, see 4.11).

## 3. Upgrade contract

| Area | 0.4 | 0.5.0 | Consumer action |
|---|---|---|---|
| Ids | `usr_`, `sid_`, `aid_`, `evt_`, `sess_` | `usr-`, `sid-`, `aid-`, `evt-`, `sess-` | Update id validators, fixtures, OpenAPI |
| Auth table | 0.4 rows | Ids changed; new lifetime counters | Create a fresh table |
| Secret document | 4 keys, `aws_storage_hmac_b64` | 6 keys (adds `pow_challenge_secret_b64`, `pow_proof_cookie_root_b64`); `storage_hmac_b64` replaces `aws_storage_hmac_b64`; no value may repeat across key fields | Write a new document; `AWSPREVIOUS` must be 0.5-shaped or unset |
| Sessions | — | All 0.4 sessions end (the cookie body carries the session id) | Users sign in again |
| Cookie names | `dd_session`, `dd_auth_confirm`, `dd_pow` | Unchanged | None |
| Cookie config | `production` / `local_development` | `secure` / `insecure_local`; getter `is_secure()` | Rename calls |
| Email | App normalizes | Library normalizes (`normalize`); `parse` is `from_normalized` | Drop app-side normalization |
| `RateLimiter` | `check_rate_limit` | Adds required `check_lifetime_limit` | Custom limiters implement it |
| Statuses | Mixed (400/401/403/500/503) | Section 5 | Adopt the contract |

Stored-format markers (`v1.<kid>.…`, the magic-link token prefix, HKDF info
strings) are unchanged. Cookie bodies change only because they carry ids.

## 4. Work items

Status: **Done** (on `main`, tested), **In progress**, **Accepted** (decided
in Section 10, not done yet), **Deferred**.

### 4.1 Hyphen ids (#1) — Done
- Every library-minted id is `<tag>-<lowercase hex>`: `usr-` + 32, `sid-` + 64,
  `aid-` + 32, `evt-` + 32, and the display id `sess-` + 8.
- Parsers accept only that form; the underscore form is refused (tested).
  `Debug` stays redacted.
- Keyed lookup values (`emh_`, `mlh_`, `mlv_`, `sih_`, `rlh_`) are storage
  material, not ids, and keep their underscores.
- `docs/security.md` has an identifier-format table.

### 4.2 Redirect landing mode and flow state (#2) — Done

1. `GET /…/landing?token=…` (`magic_link_landing_redirect`) validates without
   consuming and answers `303` to **one** app-configured same-origin page for
   **every** link state. Usable: sets the `HttpOnly` confirm cookie. Unusable:
   clears it. No token, selector, verifier or confirmation value is ever in
   `Location`. A dependency outage is the constant `503`.
2. `GET /…/flow-state` (`magic_link_flow_state`, service
   `read_magic_link_flow_state`):
   - reads only the confirm cookie; returns
     `{ "usable": true, "account": …, "confirmation": … }`;
   - any missing, invalid, expired, used, throttled or cross-site request gets
     the one answer `200 { "usable": false }`, which also clears the cookie, so
     the page can say "request a new link"; a dependency outage is the
     constant `503`, so the page can say "try again";
   - same-origin only: no CORS headers, `Cross-Origin-Resource-Policy:
     same-origin`, and `Sec-Fetch-Site` must be present and `same-origin`;
   - `Cache-Control: no-store` plus the landing security headers;
   - throttled per selector like the landing; repeatable; read-only, never
     consumes (`spec/tla/MagicLink.tla`, `FlowStateRead`).
3. The confirmation `POST` is unchanged.
4. The app chooses both routes:
   `MagicLinkScannerFlowConfig::with_redirect_landing(page, flow_state)` fails
   at startup unless the confirm cookie's `Path` covers the flow-state route
   and the confirmation route.

Static confirm page rules (new section in `security.md`):
- Strict CSP: no third-party scripts, styles, fonts or analytics, and no error
  beacons that send page content. The page holds the account and the
  confirmation value.
- `Referrer-Policy: strict-origin`.
- No shared navigation or session scripts. The page shows the account and
  posts the confirmation, nothing else.

The server-rendered mode stays supported; both are documented with when to
use each.

**Acceptance (all met):** no token material in any redirect; flow state works
with the cookie alone and fails generically; round trip landing → flow state →
confirm through the example router; cross-site and header-less flow-state
requests refused; repeated scanner GETs burn nothing; the example ships both
modes.

### 4.3 Quickstart (#3) — Done
- The `datadeft-magic-link-axum` quickstart shows the server-rendered mode and
  the redirect mode. Nothing implies the token is held in JavaScript.

### 4.4 Email normalization (#4) — Done
- `NormalizedEmail::normalize(&str)`: trim, then ASCII-lowercase the whole
  address. Lowercasing the local part is a documented policy choice.
- `parse` is renamed `from_normalized` and only validates: it refuses
  uppercase and surrounding whitespace, so every value is normalized.
- `MagicLinkRequestJson` uses `normalize`. Oversized input is refused before
  allocating.
- Tests: case and whitespace map to one identity; dots and plus tags are kept;
  `normalize` is idempotent (property test and fuzz target); no address in
  errors or `Debug`.

### 4.5 Email locale and Reply-To (#5) — Done
- `MagicLinkServiceConfig::locales` is a `LocaleAllowlist`. A request carries
  an optional, bounded locale hint; the service resolves it (exact tag, then
  language, then the default). Only the resolved `Locale` reaches
  `MagicLinkEmail` and the renderer; it is never stored (tested against every
  stored field).
- An unknown or malformed hint resolves to the default; it is not an error.
- Reply-To is outbox configuration only (`SesMagicLinkOutbox::with_reply_to`,
  validated, at most 4 addresses), never per request. A captured SES request
  shows `ReplyToAddresses` only when configured.

### 4.6 Country groups (#6) — Done
- `MagicLinkServiceConfig::country_policy`: `CountryPolicy::Exact` (default) or
  `CountryPolicy::Groups(..)`, with `CountryPolicy::eu27()` built in (tag `EU`).
- One mapping (`CountryPolicy::pin`) runs when the session is bound and on
  every validation. Missing-country behaviour and `enforce_country` are
  unchanged.
- Tests: EU→EU accepted, EU→non-EU rejected, non-EU exact only, missing
  country fails closed, and a session bound under one policy fails closed
  under another (a policy change never widens an existing session).
  Overlapping groups are refused at configuration.

### 4.7 PoW keys in the secret document (#7) — Done
- Required `pow_challenge_secret_b64` and `pow_proof_cookie_root_b64`, with
  previous-key rotation for both.
- A `kid` too long for its cookie is refused when the keyring is built (PoW
  proof cookie: 12 bytes; session cookie: 38).
- Unknown (app-owned) fields stay allowed.
- Hardening found in review: one value in two key fields is refused;
  `pow_proof_keyring` refuses the session and confirm cookie purposes; a
  previous storage key equal to the current one is ignored (it made every
  sign-up fail against real DynamoDB).
- The full document is in `security.md`.

### 4.8 Per-solve PoW budget (#8) — Done
- pow-core: the `ProofBudget` trait (a shared counter per solve).
  pow-axum: `admit_proof` reads the `dd_pow` cookie with the strict selector,
  verifies it, and spends one unit of its solve's budget
  (`ProofBudgetPolicy`, 1–1000 per solve).
- The app implements `ProofBudget` in a few lines over the shared limiter's
  new `RateLimiter::check_lifetime_limit` (the example shows it). The
  windowed `check_rate_limit` could not be used: a proof spanning two fixed
  windows would get its budget twice.
- Semantics (checked in `spec/tla/PowBudget.tla`): global across nodes;
  counted over the proof's whole lifetime (the first spend fixes an expiry past
  every cookie that solve can produce, and it never refills before then); fails
  closed.
- Missing, invalid or expired proof, or a used-up budget → `401` +
  `WWW-Authenticate: DD-PoW`: a new solve buys a fresh budget, so an honest
  client is never locked out until the cookie expires. Store failure → the
  constant `503` (fail closed).
- Tests: N admissions then `401` + `DD-PoW`, and a re-solve resumes; a re-posted solution shares the budget; a
  store failure fails closed; DynamoDB Local proves no refill across windows
  and that 20 concurrent spends from two nodes admit exactly the budget.

### 4.9 Public strict cookie selector (#9) — Done
- `cookie_header::select_cookie` in token-core: exactly one occurrence across
  all `Cookie` fields, non-empty, unquoted, bounded value; malformed foreign
  cookies skipped; field-count and byte caps. Re-exported and used by both
  Axum crates.
- Tests for duplicates, empty and oversize values, and malformed neighbours;
  a new fuzz target.

### 4.10 Session rejection details (#10) — Done
- `SessionAuthRejection::kind()` (`Invalid`, `Unavailable`, `Internal`) and
  `clear_cookie_header()`. Rendering follows Section 5.

### 4.11 GDPR erasure (#11) — Deferred past 0.5.0
- Not in 0.5.0; account deletion stays `disable_user` meanwhile.
- The design is checked in `spec/tla/Erasure.tla`: the atomic step also removes
  pending magic links and previous-key lookups; validation rejects an erased
  owner at once; session revocation is a separate retry-safe step; the same
  email then registers as a new user.

### 4.12 Re-enable cutoff (#12) — Done
- The cutoff is inclusive (`>=`) in whole seconds: a login right after
  `enable_user` works. Sessions from before the disable stay invalid because
  `enable_user` revokes every live session first; the watermark is defence in
  depth.
- Checked in `spec/tla/Session.tla` (the inclusive cutoff without revoking
  first is a killed mutant) and against DynamoDB Local.

### 4.13 Naming and docs (#13) — Done
- Cookie configs: `secure(..)` / `insecure_local(..)` and the `*_defaults`
  constructors; the getter is `is_secure()`. The PoW cookie defaults no longer
  use `.expect`.
- `aws_storage_hmac_b64` → `storage_hmac_b64`.
- Install versions in the docs are current.
- `disable_user` is documented as retry-safe, returning the sessions revoked
  (`0` on a repeat call).

### 4.14 Reason reporting — Done
- Every public refusal has a stable internal reason, never sent:
  `MagicLinkHttpError::reason()` and `ProofRejection::reason()`, distinct per
  cause, with no identifiers, emails or token material. No logging dependency.
- `RequestMagicLinkOutcome` is `Sent` or `Throttled(RequestThrottle)`, so
  throttled requests, which answer the generic `200`, are counted too.
  `SessionRejectionKind` has `reason()` as well; labels are namespaced
  (`magic_link_*`, `session_*`, `pow_*`).
- Docs: alert on reason counts, not raw `5xx` rates; give load balancers a
  dedicated health endpoint (done in `security.md`).

### 4.15 Security fixes folded into 0.5.0 (affect 0.4.x) — Done
- **Duplicate accounts during storage-key rotation:** a sign-up on a node with
  the new key, then a login on a node still on the old key, created a second
  account. A create now claims the email row under both keys. Tested in the
  fake, in TLA+ (`KeyRotation.tla`) and against DynamoDB Local.
- **A re-enabled user could get an old session back** when host clocks
  disagree. Enable now revokes every live session first. Tested with skewed
  clocks and in TLA+.
- **NUL framing in keyed lookups:** domain and prefix must not contain NUL.
- The changelog gets a short "Security fixes" section advising 0.4.0 users to
  upgrade before rotating storage keys or using disable/enable in production.

### 4.16 Admin concurrency: conditional writes — Done
In 0.4, concurrent admin actions on one user were last-write-wins: a delayed
enable could undo a later disable (ADM-F1).
- Each user profile carries an `admin_version`; every disable and enable
  bumps it.
- An enable writes only if the version is still the one it read; a lost race
  returns `AdminError::Conflict` and the admin re-reads and decides.
- A disable is unconditional apart from the user existing (disabling is the
  safe direction): it never loses a race, and its version bump fences any
  enable that read the user earlier, even on an already-disabled user.
- Checked in `spec/tla/AdminRace.tla` (each rule is a killed mutant), the
  admin race tests, the model tests, and against DynamoDB Local.

### 4.17 Protect client and the status contract — Done
- `@datadeft/protect-client` exports `protectedFetch(input, init, config,
  options)`:
  - `401` + `WWW-Authenticate: DD-PoW`: solve once, resend once;
  - `503`: for requests safe to repeat (`GET`, `HEAD`, `OPTIONS`, or
    `repeatable: true`), equal-jitter backoff (base 1 s, cap 30 s, 3 retries by
    default) — the client side of Section 5;
  - anything else, including the app's own `401`/`403` and `DD-Session`, is
    returned untouched.
- Tests: solve-and-retry, never solves twice, pass-through, backoff timings,
  no retry of a non-repeatable `POST`. README updated; the packed-consumer
  check passes.

## 5. Public HTTP status contract

| Status | Meaning | Body / headers | Client action |
|---|---|---|---|
| `401` + `WWW-Authenticate: DD-PoW` | Proof of work missing, invalid or expired, its per-solve budget used up, or a posted solution failed | Constant body, `no-store` | Solve, retry once |
| `401` + `WWW-Authenticate: DD-Session` | Session missing, invalid, expired or revoked | Constant body; clear-cookie header | Sign in again |
| `400` | Shape error that leaks nothing: bad JSON, invalid email syntax, wrong content type, oversize body | One generic body | Fix the request; no retry |
| `503` | Everything security-sensitive or failed: rate limits, quotas, dependency and server faults | One constant body, byte-identical across both Axum crates, `no-store`; reason internal (4.14) | Equal-jitter backoff |
| `403` | Never sent by the library; the app's, for business authorization | — | App-defined |
| `200` / `303` | Success; the generic accepted request response; landing redirects; flow-state answers | As in 4.2 | — |

Rules:
- No `429`, no `500`. No status reveals account existence, link state, limits
  or quotas.
- The request endpoint answers the same `200` whether it sent, throttled or
  dropped the email; the landing redirect is the same for every link state.
- Apps may use non-leaking `4xx` on their own routes.
- Statuses are not configurable.
- **Acceptance (met):** contract tests per crate, plus one table over every
  library refusal across both Axum crates (`examples/axum-magic-link`,
  `contract_tests`); `security.md` "HTTP response contract".

## 6. Documentation

- `docs/integration.md`: "Upgrading from 0.4" (kept current per item), both
  landing modes, the status contract, reasons, the PoW budget, country policy,
  the locale allowlist.
- `docs/security.md`: identifier formats, static confirm page rules, the full
  secret document, the response contract, email normalization policy, email
  language and Reply-To, country groups, admin concurrency.
- `CHANGELOG.md` 0.5.0: generated by release-please from the commit footers;
  `docs/release-notes-0.5.0.md` holds the upgrade summary and the "Security
  fixes" section (4.15) to merge into it in the release PR.
- `examples/axum-magic-link`: hyphen ids, both landing modes, normalized email,
  locale allowlist, EU groups, PoW keys from the secret document, the PoW budget
  with the `401`/`503` contract (done), reason logging.

## 7. Testing and verification

- `mise run verify` green: fmt, clippy, tests, docs, audit, API guards,
  TypeScript checks, TLA+ models (`mise run spec`) and their mutants
  (`mise run spec-mutants`).
- Unit and property tests per item; DynamoDB adapter behaviour proved against
  DynamoDB Local (`mise run dynamodb-local-test`); fuzz targets for every
  untrusted-input parser (`mise run fuzz`).
- Two-node tests for 4.8, 4.15 and 4.16.
- Packed-consumer check for `@datadeft/protect-client`, including
  `protectedFetch`.

## 8. Release plan

1. Finish Section 4 on `main`.
2. CeleraTax pins that commit in PR #149 on core-dev, with a fresh table and
   secret document, and runs:
   - its router suite;
   - a real SES/DynamoDB login;
   - an Exchange Online (Safe Links) mailbox test confirming scanners don't
     burn links;
   - a log probe confirming no token material reaches any log.
3. Fix findings, then publish 0.5.0 to crates.io and npm.

## 9. CeleraTax adoption checklist (PR #149)

- `usr-` ids. Remove the `usr_` changes from the 0.4 migration.
- A static Astro `/{lang}/login/confirm/` page on the redirect mode, following
  4.2's page rules. Remove the API-rendered landing page.
- Status contract:
  - allow `401` with `DD-PoW` / `DD-Session` in `backends/api/AGENTS.md`, and
    the "`503` for anything security-sensitive, non-leaking `4xx` allowed"
    rule;
  - `403` for business authorization only;
  - `protectedFetch` on the login page.
- Alarms on reason counts (4.14); a health endpoint for the ALB.
- Remove workarounds:
  - EU header rewrite → `CountryPolicy::eu27()`;
  - own PoW key parsing → the library's secret-document fields;
  - hand-written PoW budget → `admit_proof` + `ProofBudget` (4.8);
  - hand-written cookie parsing → `select_cookie` (4.9);
  - status inference → `SessionAuthRejection::kind()` (4.10);
  - app-side email normalization → `normalize` (4.4);
  - per-request SES outbox → locale allowlist and `with_reply_to` (4.5).
- Secret document: drop CeleraTax's own `pow_*` parsing; rename
  `aws_storage_hmac_b64` → `storage_hmac_b64`; no value in two fields.
- Account deletion stays `disable_user` until erasure ships (4.11).

## 10. Decisions

Decided by the maintainers:

1. **4.16 conditional admin writes:** in 0.5.0.
2. **4.17 client name:** `protectedFetch`, with the `503` backoff.
3. **Flow-state `Sec-Fetch-Site`:** a request without the header is refused
   (the generic `{ "usable": false }`).
4. **Reasons:** typed enums, plus an internal `Sent` / `Throttled(reason)`
   disposition on the request outcome.

Also resolved: the flow-state route is app-chosen and validated against the
confirm cookie path; erasure is deferred; no release candidates; shape errors
are `400`.

## 11. Pre-release review findings (2026-10-11)

Simplify, code and security reviews of `v0.4.1..HEAD`, merged with an external
agent's review. Only real issues were taken; marginal refactors are listed as
deferred.

| Finding | Verdict | Status |
| --- | --- | --- |
| Storage-key rotation reset per-solve budgets (counter id was keyed) | Real | Fixed: unkeyed domain-separated SHA-256 id (`lt_…`); DynamoDB Local test |
| Duplicate country group tags accepted | Real | Fixed: `DuplicateTag` |
| Request country equal to a group tag (`EU`) pinned as that group | Real | Fixed: `pin` returns `None`, fails closed; `XX` refused as a tag |
| Disable retry loop could reverse a concurrent enable | Real | Fixed: disable unconditional (bumps version), only enable fenced; `AdminRace.tla` updated |
| Token-core tests did not build with default features (hidden by feature unification) | Real | Fixed: gated; new `mise run test-default-features` in `verify` |
| A zero limit admitted one request | Real | Fixed: `limit == 0` denies, both limiter checks |
| Rejected landing cleared the confirm cookie (cross-site junk link ended a live flow) | Real | Fixed: no `Set-Cookie` on a rejected landing |
| Example page treated a `503` on confirm as a dead link | Real | Fixed: keeps the form, "try again" |
| `protectedFetch` matched `DD-PoW` case-sensitively | Real | Fixed: case-insensitive (RFC 9110) |
| Raw secret JSON string not zeroized after load | Real (hygiene) | Fixed: `Zeroizing<String>`; the SDK's own buffer is out of our control |
| `expect` in pow-core `hmac_tag_raw` | Rule violation | Fixed: error propagated |
| Dot segments accepted in same-origin paths | Config footgun | Fixed: `.`/`..` segments refused |
| Flow-state `503` headers differ from other routes' `503` | Not an issue | Within a route every `503` is identical; extra headers are per route |
| Exhausted cookie replay costs a budget write per request | Documented | Edge per-IP limits bound it (`security.md`) |
| Cross-site confirm `POST` clears the confirm cookie | Accepted | User clicks the link again; nothing consumed (`security.md`) |
| `previous_pow_challenge_secret` needs app-side fallback verification | Documented | `integration.md` |

Deferred (marginal or cross-crate API proposals, not 0.5.0): shared cookie
building in token-core; `MAX_BODY_BYTES` semantics; one
`RateLimiter::check_counter`; `ConstantTimeEq` for `LookupHmacKey`; a pow-core
test-support solver; `BatchGetItem` for admin session reads; decoding the
secret document once; sharing one in-progress solve across `protectedFetch`
calls; a role-based cancellation classifier; test-wrapper dedup; country
policies valid by construction.

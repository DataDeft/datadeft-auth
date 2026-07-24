# Datadeft auth extraction plan

## Goal

Create a standalone `datadeft-auth` repository containing reusable Rust authentication libraries extracted from the existing application code, with clear crate boundaries, deterministic core crates, optional framework/cloud adapters, and a local-first integration path.

## Proposed repository layout

```text
datadeft-auth/
  Cargo.toml
  crates/
    dd-pow-core/
    dd-auth-token-core/
    dd-magic-link-core/
    dd-magic-link-service/
    dd-magic-link-axum/
    dd-magic-link-aws/
  packages/
    dd-protect-client/
  examples/
    axum-magic-link/
  docs/
  LICENSE
  README.md
```

## Open decisions

These decisions need owner input. Safe interim defaults are for local extraction only and should not be mistaken for production policy.

| Input | Needed decision | Current status / default |
| --- | --- | --- |
| New repo | GitHub org/name + local path | local path: current `datadeft-auth`; GitHub: TODO |
| Naming | `dd-*` or `datadeft-*` | `dd-*` for crate/package names |
| License | License expression | `MIT` |
| Provenance | Confirm source-derived code is yours / license-compatible | Owner attests source-derived code is owned and may be extracted; still audit dependency licenses and accidental third-party notices before public publish. |
| Publish target | Private git first, private registry, or crates.io | local path deps first, then private git, then crates.io after audit |
| API style | Axum-only for now, or framework-neutral first | framework-neutral core/service first; Axum adapter crate |
| Storage/email | Traits only first, or also extract DynamoDB/SES now | traits first; DynamoDB/SES in phase 6 |
| Cookie/session defaults | Generic names vs project-provided config only | secure-by-default helpers; production apps provide explicit config |

## Security and product decisions

| Decision | Policy |
| --- | --- |
| Email identity and normalization | Use exact match on an app-provided normalized email value. Do not do provider-specific aliasing: no Gmail dot folding, no plus-address/tag stripping, and no hidden provider-specific case rules. The consuming app owns any case normalization before constructing `NormalizedEmail`. |
| Cookie names and scope | Use normal lower `snake_case` cookie names, optionally app-prefixed, for example `dd_session`. Do not require `__Host-` or `__Secure-` prefixes for the first version. Primary session cookies use explicit `Path=/`, host-only scope by default, `HttpOnly`, `Secure` outside local development, `SameSite=Lax`, and explicit TTL. Temporary auth helper cookies use the narrowest practical auth path unless they intentionally need app-wide access. |
| Magic-link URL and post-consume redirect | Use a scanner-safe click-to-confirm flow. The email link opens a `GET` landing route with the token in the URL, but `GET` must not consume the token or create a session. The user clicks a same-origin `POST` confirmation. The `POST` atomically consumes the token, clears temporary flow state, creates the session, and redirects with `303 See Other` to a clean URL without token material. Example paths are configurable; docs/examples may use `GET /auth/magic-link`, `POST /auth/magic-link/consume`, and redirect `/auth/complete`. |
| Token and cookie TTL baseline | Use `magic_link_ttl=10m`, `magic_link_flow_ttl=5m`, `pow_challenge_ttl=5m`, `pow_proof_cookie_ttl=10m`, `session_idle_ttl=24h`, `session_absolute_ttl=30d`, and 24h cleanup grace after expiry. Server-side expiry wins; cookies must not outlive the server-side validity they represent. |
| Rate-limit thresholds and client keys | Use configurable v1 starting thresholds: request magic link by email HMAC `3/15m` and `10/24h`; request magic link by client key `10/10m` and `50/1h`; email outbox by email HMAC `3/1h` and `10/24h`; consume by selector `5` failed attempts per token TTL; consume by client key `20/10m` and `100/1h`; malformed consume by client key `20/10m`; PoW challenge mint by client key `30/10m`; PoW verify failures by client key `30/10m`. Client keys are app-supplied; Axum helpers may derive HMACs from trusted reverse-proxy client IPs only when configured. |
| Secret manager abstraction | Production uses AWS Secrets Manager. Use an extremely thin `SupportedSecretManager` enum with `AwsSecretsManager` as the v1 supported variant plus redacted `SecretRef` config. Core crates accept loaded key material/keyrings only; AWS SDK lookup lives in adapter/setup code, not core. |
| Key rotation cadence | For 30-day session validity, rotate session/cookie keys about every 90 days and retain the previous key verify-only for at least 31 days. Map `AWSCURRENT` to active and `AWSPREVIOUS` to verify-only when rotation is enabled. Magic-link and PoW keys retain previous material only for their short TTL plus 24h cleanup grace. Do not rotate session keys faster than verify-only retention unless explicit older verify-only refs are supported. |
| AWS adapter timing | Build framework-neutral service traits and fakes first, then extract DynamoDB/SES/AWS Secrets Manager adapters after one-time consume, rate-limit, outbox, and scanner-safe flow contracts pass service tests. AWS code must satisfy the service contract, not define it. |

## Open product/security questions

No product/security questions are currently blocking local extraction. Consuming-project names and rollout order are intentionally kept out of these public repo docs.

## Source material to seed

Copy these as starting material from the source project:

```text
backends/pow
backends/crypto
backends/domain/src/auth/*
backends/domain/src/auth_store.rs
backends/domain/src/types.rs
backends/domain/src/errors.rs
backends/api/src/api/pow.rs
backends/api/src/api/session/*
backends/adapters/src/dynamodb/{sessions,users,rate_counters,fake}.rs
backends/adapters/src/ses.rs
frontends/pow
docs/backends/pow
docs/backends/api/*magic-link*
docs/backends/api/*auth*
```

Initial mapping:

| Target | Source material |
| --- | --- |
| `dd-pow-core` | `backends/pow`, deterministic tests, `docs/backends/pow` |
| `dd-auth-token-core` | `backends/crypto`, session cookie and PoW cookie code from `backends/domain/src/auth/*`, shared domain `types/errors` as needed |
| `dd-magic-link-core` | magic-link token grammar, selector/verifier types, redacted debug, verifier HMAC helpers from `backends/domain/src/auth/*` |
| `dd-magic-link-service` | request/consume orchestration, `auth_store.rs`, repo/limiter/outbox abstractions, domain `types/errors` as needed |
| `dd-magic-link-axum` | `backends/api/src/api/pow.rs`, `backends/api/src/api/session/*`, Axum handlers/body guards/cookie response helpers |
| `dd-magic-link-aws` | `backends/adapters/src/dynamodb/{sessions,users,rate_counters,fake}.rs`, `backends/adapters/src/ses.rs` |
| `dd-protect-client` | `frontends/pow` |
| `examples/axum-magic-link` | minimal app wiring service + Axum + fake or AWS adapters |

## Phase plan

| Phase | Package(s) | Work | Output |
| --- | --- | --- | --- |
| 0 | Repo setup | Create workspace, crate skeletons, `mise` tasks including audit, lint/test CI, MIT license file, release metadata | Clean standalone repo |
| 1 | `dd-pow-core` | Move `backends/pow`; rename crate; remove source-project naming; keep deterministic tests | Publishable PoW core |
| 2 | `dd-auth-token-core` | Move crypto/base62/branca/keyring/session cookie/PoW cookie; make issuer/audience/cookie names configurable; add key separation and secure cookie config rules | Reusable session/token foundation |
| 3 | `dd-magic-link-core` | Move token grammar, selector/verifier types, redacted debug, verifier HMAC helpers, explicit normalized-email boundary | IO-free magic-link primitives |
| 4 | `dd-magic-link-service` | Extract request/consume flows behind traits: store, limiter, user/session repo, outbox, clock, rng; enforce one-time atomic consume semantics | Service-level reusable magic-link flow |
| 5 | `dd-magic-link-axum` | Optional Axum body guards, route handlers, secure cookie response helpers, token-URL scrubbing, generic public errors | Drop-in Axum integration |
| 6 | `dd-magic-link-aws` | Optional DynamoDB/SES adapter extraction with conditional writes, features, and fakes | AWS implementation |
| 7 | Integration back | Replace consuming-project local auth code with local path/git deps from this repo | Proof extraction works |
| 8 | Publish prep | License/provenance/dependency audit, `cargo publish --dry-run`, README examples | crates.io-ready |

## Crate contracts

### `dd-pow-core`

Purpose: pure proof-of-work challenge minting and verification.

Must:

- Be deterministic and IO-free.
- Accept clock/entropy/config from the caller.
- Keep token/challenge formats versioned and covered by vectors.
- Include tamper, expired, invalid difficulty, and round-trip tests.

Must not:

- Depend on Axum, Tokio, AWS SDK, filesystem, environment, or logging.
- Encode application-specific names or domains.

### `dd-auth-token-core`

Purpose: reusable token/session/cookie primitives.

Must:

- Own Branca/keyring/base62/session cookie/PoW cookie primitives.
- Make issuer, audience, cookie names, TTLs, and key IDs configurable.
- Use purpose-separated loaded key material and key IDs for each token/cookie/HMAC context.
- Accept key material/keyrings from callers; do not resolve secret-manager references in core.
- Provide secure cookie configuration types that make unsafe production settings explicit.
- Redact secrets and cookie values in `Debug`.
- Return typed errors that do not leak secrets or PII.

Must not:

- Read process environment or system clock directly.
- Depend on web framework or cloud SDK crates.

### `dd-magic-link-core`

Purpose: IO-free magic-link primitives.

Must:

- Own token grammar, selector/verifier domain types, parsing, formatting, and verifier HMAC helpers.
- Define one current magic-link token version with domain-separated purpose markers.
- Use constant-time comparison for verifier-derived material.
- Redact tokens, selectors, verifiers, HMAC inputs, and normalized emails.
- Expose an exact-match normalized-email boundary; do not silently implement provider-specific alias rules, dot folding, plus-tag stripping, or hidden case folding.
- Include golden/vector, tamper, parse-fail, expired, unknown-key, and round-trip tests.

Must not:

- Send email, read storage, or perform rate limiting.
- Support legacy token formats unless explicitly versioned and documented.

### `dd-magic-link-service`

Purpose: framework-neutral magic-link request/consume orchestration.

Must:

- Depend on traits for store, limiter, user repo, session repo, outbox/email, clock, and rng.
- Use core crates for token/session behavior.
- Enforce one-time magic-link consumption with an atomic store transition before or in the same transaction as session creation.
- Enforce expiration and generic public failures for missing, invalid, expired, consumed, throttled, and unknown-user cases.
- Provide limiter hooks for request, consume, and outbox-send flows by normalized-email HMAC, selector-derived key, and app-supplied client key.
- Keep public flow errors generic and non-enumerating.
- Include fake/in-memory test implementations where useful.

Must not:

- Depend on Axum or AWS SDK.
- Log tokens, emails, cookies, session IDs, or key material.

### `dd-magic-link-axum`

Purpose: optional Axum HTTP integration.

Must:

- Own Axum extractors/body guards, route handlers, cookie response helpers, and generic public errors.
- Map service errors into safe HTTP responses.
- Keep route paths and cookie names configurable.
- Default cookie helpers to normal lower `snake_case` names, `HttpOnly`, `Secure` outside explicit local development, conservative `SameSite`, host-only scope, explicit `Path=/` for primary session cookies, narrow auth paths for temporary helper cookies where practical, and explicit TTL.
- Scrub token material from logs, route captures, query strings, redirects, headers, and telemetry.
- Implement scanner-safe magic-link flow: `GET` landing renders a click-to-confirm page without consuming; same-origin `POST` consumes atomically; success redirects with `303 See Other` to a clean URL without token material.
- Include handler tests with fake service/storage.

Must not:

- Own core token/session logic.
- Depend directly on AWS SDK.

### `dd-magic-link-aws`

Purpose: optional AWS infrastructure adapters.

Must:

- Own DynamoDB implementations for sessions, users, rate counters, and magic-link storage as needed.
- Implement one-time magic-link consume with DynamoDB conditional writes/deletes or an equivalent atomic transition.
- Own SES outbox/email implementation.
- Own the AWS Secrets Manager resolver for `SupportedSecretManager::AwsSecretsManager`, mapping configured secret references into redacted loaded key material/keyrings.
- Keep AWS dependency surface behind features.
- Include fakes or local test doubles for service tests.
- Scrub AWS errors before exposing public errors.

Must not:

- Change token grammar or session semantics.
- Leak table keys, raw identifiers, emails, tokens, or provider error payloads through public errors.

### `dd-protect-client`

Purpose: optional browser/client proof-of-work helper.

Must:

- Stay optional and not block Rust crate publishing.
- Match `dd-pow-core` challenge format through vectors.
- Avoid application-specific branding.

## Multi-agent operating model

Use a parent orchestrator plus focused library agents.

### Orchestrator responsibilities

- Own all open decisions and ask the user when a decision blocks safe work.
- Assign one crate/package to one agent at a time.
- Preserve dependency direction and public API boundaries.
- Review every cross-crate API proposal before implementation.
- Ensure final verification runs at repo level.
- Keep publish/provenance/license work centralized.

### Library agent rules

Each library agent must:

1. Read `AGENTS.md`, `docs/rust-standards.md`, `docs/operating.md`, and `docs/security.md` before editing.
2. Work only in its owned crate/package paths unless the work packet grants another path.
3. Treat all other crates as read-only context.
4. Keep core crates deterministic and IO-free.
5. Add or preserve tests for moved behavior.
6. Redact `Debug` for sensitive types.
7. Run targeted validation before handoff.
8. Report changed files, public API changes, validation, risks, and open questions.

### Single-library lanes

| Lane | Owned paths | Read-only context | First validation target |
| --- | --- | --- | --- |
| Repo setup | `Cargo.toml`, `.github/`, `.mise.toml`, `README.md`, `LICENSE-*`, `docs/`, crate skeleton manifests | all planned source paths | `mise run verify` once crates compile |
| PoW core | `crates/dd-pow-core/` | `backends/pow`, `docs/backends/pow`, `frontends/pow` | `cargo test -p dd-pow-core --all-features` |
| Auth token core | `crates/dd-auth-token-core/` | `backends/crypto`, auth/session code, `dd-pow-core` API | `cargo test -p dd-auth-token-core --all-features` |
| Magic-link core | `crates/dd-magic-link-core/` | auth magic-link code, `dd-auth-token-core` API | `cargo test -p dd-magic-link-core --all-features` |
| Magic-link service | `crates/dd-magic-link-service/` | domain auth flows, `auth_store.rs`, core APIs | `cargo test -p dd-magic-link-service --all-features` |
| Axum adapter | `crates/dd-magic-link-axum/` | API pow/session handlers, service API | `cargo test -p dd-magic-link-axum --all-features` |
| AWS adapter | `crates/dd-magic-link-aws/` | DynamoDB/SES adapters, service traits | `cargo test -p dd-magic-link-aws --all-features` |
| Browser client | `packages/dd-protect-client/` | `frontends/pow`, `dd-pow-core` vectors | package test/build command once chosen |
| Example/integration | `examples/axum-magic-link/` and consuming-project dependency config | all published local crates | example compile + consuming project tests |

### Work packet template

```md
## Agent work packet

Goal:
Owned paths:
Read-only context:
Allowed dependencies:
Forbidden dependencies:
Required public API:
Required tests:
Validation commands:
Stop and ask if:
```

### Handoff template

```md
## Agent handoff

Changed files:
Public API added/changed:
Security-sensitive behavior:
Tests added/updated:
Validation run:
Validation not run:
Open questions:
Follow-up work:
```

### Cross-crate proposal template

```md
## Cross-crate API proposal

Producer crate:
Consumer crate(s):
Proposed API:
Reason:
Security impact:
Compatibility impact:
Tests required:
```

## Acceptance criteria by phase

### Phase 0 acceptance

- Workspace builds with crate skeletons.
- `mise run fmt`, `mise run check`, `mise run test`, `mise run clippy`, `mise run audit`, and `mise run verify` are defined.
- MIT `LICENSE` file exists.
- CI runs the same verify commands available for the current phase.
- Docs link from `docs/index.md`.

### Phase 1 acceptance

- `dd-pow-core` has no application names.
- Core API is deterministic and IO-free.
- Existing deterministic tests pass.
- Challenge/token format vectors exist.

### Phase 2 acceptance

- Token/session primitives are reusable and configurable.
- Key material is purpose-separated by token/cookie/HMAC context, with active, verify-only, and retired states.
- Unknown key IDs fail closed.
- Session key rotation supports the documented 90-day cadence and at least 31-day verify-only retention for 30-day session validity.
- Secure cookie configuration makes unsafe production settings explicit.
- Secret/cookie debug output is redacted.
- Typed errors do not leak sensitive values.
- Session/PoW cookie tests pass.

### Phase 3 acceptance

- Magic-link token grammar is owned by `dd-magic-link-core`.
- Selector/verifier/HMAC helpers are pure and tested.
- The exact-match normalized-email boundary is explicit and tested.
- Tamper, invalid parse, expired, unknown-key, and round-trip cases are covered.

### Phase 4 acceptance

- Request/consume flows use traits for all IO.
- Magic-link consume is one-time and atomic relative to session creation.
- Replay and concurrent consume/race tests pass against service fakes.
- Limiter hooks cover request, consume, outbox-send, and PoW flows by sensitive keyed material and app-supplied client keys, with configurable v1 thresholds.
- Fakes cover store, limiter, users, sessions, outbox, clock, and rng.
- Public errors are generic, safe, and non-enumerating.

### Phase 5 acceptance

- Axum integration compiles only when the adapter crate is used.
- HTTP errors do not enumerate users or leak token/session details.
- Cookie helpers default to normal lower `snake_case` names, `HttpOnly`, `Secure` outside local development, conservative `SameSite`, host-only scope, explicit `Path=/` for primary session cookies, narrow auth paths for temporary helper cookies where practical, and explicit TTL.
- Magic-link handlers scrub token material from logs, route/query fields, redirects, headers, and telemetry.
- Magic-link `GET` landing route does not consume or create a session, and requires explicit user click/confirmation.
- Magic-link `POST` consume route atomically consumes the token, clears temporary flow state, creates the session, and redirects with `303 See Other` to a clean URL without token material.

### Phase 6 acceptance

- DynamoDB/SES/AWS Secrets Manager adapter code lives only in `dd-magic-link-aws` or setup/example code, never in core crates.
- AWS dependencies are feature-gated where practical.
- Magic-link consume uses conditional writes/deletes or an equivalent atomic transition.
- Replay and concurrent consume/race tests pass against the AWS adapter or a faithful fake.
- Adapter errors are scrubbed.
- AWS Secrets Manager resolver tests prove `AWSCURRENT` active loading, optional `AWSPREVIOUS` verify-only loading, unknown/missing secret failure, and redacted errors/debug output.
- Rotation tests cover 90-day session key rotation, 31-day verify-only retention, verify-only rejection for minting, and retired-key rejection.

### Phase 7 acceptance

- At least one consuming project uses local path or git dependencies from this repo.
- Consuming project auth tests pass.
- Any API friction is captured before publish prep.

### Phase 8 acceptance

- Provenance and license audit is complete.
- Dependency/license/vulnerability audit passes.
- README examples compile.
- `cargo publish --dry-run` passes for each publishable crate.
- Public API review is complete.

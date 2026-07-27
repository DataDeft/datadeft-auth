# Agent instructions

## Required reading

Before editing Rust code, read:

- `docs/rust-standards.md`
- `docs/operating.md`
- `docs/security.md`
- `docs/plan.md` for phase scope and crate ownership

## Operating model

- Use the one-orchestrator, one-library-per-agent model.
- Each agent owns exactly one crate/package unless explicitly assigned a repo-wide task.
- Do not edit another agent's crate without orchestrator approval.
- Treat cross-crate public API changes as proposals first.
- Use `mise` tasks instead of manually retyping command pipelines.
- Run `mise run verify` before calling work complete when the workspace is available.

## Rust best practices

- Explicit over clever.
- Prefer plain functions, structs, enums, traits, and generics.
- Do not author application/library macros.
- No `unwrap`, `expect`, or `panic!` in production code.
- No `unsafe` unless justified by a written security/design note.
- Library APIs return typed errors, not `anyhow`, as public error types.
- Keep public APIs small, documented, and stable.
- Prefer dependency injection over globals, process environment reads, or singletons.
- Keep optional integrations behind feature flags.

## Layering rules

- Core crates must stay IO-free and deterministic.
- Do not add Axum, Tokio, AWS SDK, filesystem, environment, network, or logging dependencies to `*-core` crates.
- Adapter crates own IO, network, clocks, and external dependency mapping.
- Service crates depend on traits, not concrete infrastructure.
- No circular dependencies.

Allowed dependency graph:

```text
dd-auth-token-core      -> (no workspace crates)
dd-magic-link-core     -> dd-auth-token-core
dd-magic-link-service  -> dd-magic-link-core, dd-auth-token-core
dd-magic-link-axum     -> dd-magic-link-service
dd-magic-link-aws      -> dd-magic-link-service
examples/*             -> adapter and service crates as needed
```

## Security rules

- Do not commit secrets, tokens, cookies, production data, customer emails, AWS credentials, key material, or `.env` files.
- Do not log or expose secret/token/customer data.
- Security-sensitive values must use redacted `Debug`.
- Use constant-time comparison for verifier hashes, token MAC/tag values, and stored secret-derived values.
- Use HMAC, not bare SHA-256, for lookup keys derived from secrets or PII.
- Email identity is exact match on an app-provided normalized value; do not add Gmail dot folding, plus-tag stripping, or hidden provider-specific alias rules.
- Validate `NormalizedEmail` structure before use: one address, no display-name form, no CR/LF/NUL/control characters, no empty values, and documented length caps.
- Magic-link consumption must be one-time and atomic relative to session creation.
- Scanner-safe flow state must bind the selector, verifier proof, exact account, expiry, and an independent confirmation nonce; `GET` landing routes never consume or create sessions.
- Confirmation pages must identify the account, prevent framing, and submit same-origin `POST`; redirects after consume must be fixed, same-origin, or allowlisted.
- Cookie helpers must default to normal lower `snake_case` names, `HttpOnly`, `Secure` outside explicit local development, conservative `SameSite`, host-only scope, explicit `Path=/` for primary session cookies, narrow auth paths for temporary helper cookies where practical, and explicit TTL.
- Clear temporary magic-link flow cookies on successful authentication and terminal failures. Independent PoW middleware owns its own proof-cookie lifecycle.
- Use the documented TTL baseline unless the consuming app explicitly configures stricter values: magic link 10m, flow 5m, PoW challenge 5m, PoW proof cookie 10m, session idle 24h, session absolute 30d, cleanup grace 24h.
- Generate bearer secrets and nonces from CSPRNG entropy outside tests; enforce the documented entropy minimums for selectors, verifiers, session IDs/tokens, flow nonces, and PoW challenge nonces.
- Magic-link selectors and verifiers are two independent CSPRNG draws; neither may be derived from the other.
- The GET landing route is throttled by a keyed selector and does dummy work on miss like the consume path — no unthrottled read oracle.
- Login CSRF is mitigated by account identification on the confirm page (UX-dependent); logout is a CSRF-protected unsafe method.
- Use purpose-separated keys/peppers; do not reuse one secret across token, cookie, HMAC, and PoW contexts.
- Production secret storage uses the thin supported-manager enum with `AwsSecretsManager` for v1; core crates receive loaded keyrings only and must not resolve secrets or depend on AWS SDK.
- For 30-day session validity, rotate session/cookie keys about every 90 days and keep the previous key verify-only for at least 31 days; map `AWSCURRENT` to active and `AWSPREVIOUS` to verify-only when enabled.
- Default session model must support server-side invalidation on logout and compromise before clearing cookies; stateless-only sessions are an explicit non-default tradeoff.
- Scrub magic-link token material from URLs, logs, redirects, headers, telemetry, errors, fixtures, and snapshots.
- PoW difficulty must be configurable with a documented production floor; proof cookies must bind to their challenge and auth flow, with single-use or a small replay cap. PoW admission is an independent consuming-application concern.
- Magic-link owns limiter hooks for keyed normalized-email request/outbox limits and keyed-selector landing/consume limits, with generic public responses and the documented targeted-lockout tradeoff. IP, global, malformed-request, and PoW controls belong to the consuming application or edge.
- Prefer one current supported token/storage shape. Do not add legacy compatibility paths unless explicitly versioned and approved.

## Testing and validation

Each crate should include:

- unit tests for pure functions
- golden/vector tests for token formats
- tamper tests for security-sensitive parsing/verification
- round-trip tests for mint/parse or encode/decode flows

Common validation commands:

```sh
mise run fmt
mise run check
mise run test
mise run clippy
mise run audit
mise run verify
```

Recommended verify pipeline:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo deny check
```

## Handoff expectations

When finishing a task, report:

- changed files
- public API added/changed
- security-sensitive behavior
- tests added/updated
- validation run and not run
- open questions
- follow-up work

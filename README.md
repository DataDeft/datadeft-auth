# datadeft-auth

Reusable Rust authentication libraries: proof-of-work, encrypted session
tokens, and scanner-safe magic-link login. Extracted from internal
application code into small, deterministic, IO-free cores plus optional
framework and cloud adapters.

> **Status:** preparing the first registry release, `0.3.0`. APIs are pre-1.0.
> Publishing awaits maintainer approval and registry setup; the commands below
> apply once that release is available. See [releasing.md](docs/releasing.md).
> Start with [`docs/architecture.md`](docs/architecture.md) and
> [`docs/onboarding.md`](docs/onboarding.md).
> [`docs/security.md`](docs/security.md) is the normative security policy.

## What this is

A set of libraries a Rust API service calls from its own HTTP handlers. The
libraries own the **security-critical, reusable** parts (PoW, token grammar,
session cookies, magic-link request/consume orchestration). The consuming
application keeps everything product-specific (router, paths, JSON shapes,
email templates, redirects, consent policy, locale, audit/WAL, infra).

## No application-specific code

The libraries were extracted from application code. The public crates and the
npm package must contain no application branding, domains, cookie names,
issuer/audience values, email templates, or product-specific policies.
That excludes:

- application-specific cookie names, issuers, audiences, and domains
- CDN, viewer-country, or regional enforcement logic
- audit/WAL event emission
- application package names and branded email templates

## Crate shape

```
datadeft-pow-core
datadeft-pow-axum            (optional)
datadeft-auth-token-core
datadeft-magic-link-core
datadeft-magic-link-service
datadeft-magic-link-axum     (optional)
datadeft-magic-link-aws      (optional)
```

Dependency direction (the adapters are siblings and neither depends on the other):

```
datadeft-auth-token-core      -> (no workspace crates)
datadeft-magic-link-core     -> datadeft-auth-token-core
datadeft-magic-link-service  -> datadeft-magic-link-core, datadeft-auth-token-core
datadeft-magic-link-axum     -> datadeft-magic-link-service
datadeft-magic-link-aws      -> datadeft-magic-link-service
```

### `datadeft-pow-core`

Pure Rust, IO-free proof-of-work core. Owns challenge minting and solution
verification. The caller injects clock, entropy, difficulty, max age, and
secret. No Axum, Tokio, AWS SDK, filesystem, environment, logging, or
application-specific domains. Deterministic and fully testable.

### `datadeft-auth-token-core`

Reusable Branca / base62 / keyring / session-cookie / PoW-cookie primitives.
Cookie name, issuer, audience, TTLs, key IDs, and key material are all
**configurable**: there are no baked-in product values. `Debug` is redacted
for keys, cookies, session IDs, and secret-bearing types. Core APIs never
read the environment or the clock directly.

### `datadeft-magic-link-core`

IO-free magic-link primitives. Owns the token grammar, selector/verifier
types, parsing, formatting, verifier hash helpers, and redacted `Debug`.
Stores only keyed lookup material, never raw token parts. No email sending,
database access, rate limiting, Axum, AWS, or application copy.

### `datadeft-magic-link-service`

Framework-neutral orchestration for magic-link requests, scanner-safe
confirmation, and server-revocable sessions. It depends on traits for storage,
rate limiting, an email delivery hook (named
`MagicLinkOutbox`, but not necessarily durable), clock, and randomness.
Implements the reusable core of:

- **request:** validate caller-decoded input → apply keyed normalized-email limits
  → create challenge → ask the app-provided delivery hook to deliver or durably
  enqueue the email under its keyed normalized-email outbox limit
- **landing:** validate and apply a keyed-selector limit without consuming →
  identify the exact account → mint short-lived confirmation state bound to the
  selector, verifier proof, exact account, expiry, and an independent nonce
- **confirmation:** verify bound state locally, including its keyed-selector limit
  → atomically consume the challenge
  with user/session creation → return the encrypted session cookie value
- **session:** validate cookie freshness plus server-side state, support
  revocation, and re-issue the cookie with `refresh_session_cookie` so active
  users stay signed in up to the absolute lifetime

Public errors are generic and non-enumerating. IP, global, malformed-request,
and PoW admission controls belong to the consuming application or edge and are
not magic-link API inputs. No Axum or AWS dependency.

### `datadeft-magic-link-axum`

Optional Axum integration. Owns bounded request guards, strict same-origin
confirmation, secure flow/session cookie helpers, scanner-safe account
confirmation pages, generic session `401` handling with cookie clearing, and
safe HTTP error mapping. It does **not** own token/session cryptography or
storage transactions, and it does **not** force a router: consumers call the
library functions from their own routes. Production deployments must also
scrub token-bearing request targets from proxy, access, trace, and error logs.

### `datadeft-magic-link-aws`

Optional AWS adapter. Owns DynamoDB implementations for the
magic-link/session/user/rate-counter traits and an SES sending adapter if
desired. AWS SDK dependencies live here and **only** here. The adapter scrubs its
errors before they cross the public boundary.

### `packages/dd-protect-client`

Optional browser proof-of-work client. The public package must contain **no** consuming-application branding. It
must match `datadeft-pow-core` challenge/solution vectors exactly.

## Email templates and branding

The libraries must **not** send application-branded email by default. Every consuming application provides its own subject, text, and HTML
templates (or a renderer).

The service crate models email as **data/traits**, for example:

- recipient
- token, or an already-rendered action URL (depending on the final API)
- subject
- text body
- optional HTML body

If `datadeft-magic-link-aws` includes an SES sender, it sends **app-provided
message content**. It must not bake in application copy, logos, domains,
colors, or URLs.

## How a consuming API uses this

The API service keeps its own router, paths, request IDs, observability,
config loading, public error style, redirects, product-specific user policy,
consent/terms/privacy versions, locale support, email templates, WAL/audit
events, and infrastructure wiring. It calls these libraries from its own
handlers.

The request path constructs `MagicLinkRequestService` and calls
`request_magic_link(...)`. The service applies request and delivery limits,
stores the challenge, and passes the token only to the application-provided
`MagicLinkOutbox` implementation. That trait does not itself guarantee durable
queueing. The public response remains generic.

The only login path is scanner-safe:

1. A bounded landing handler calls
   `MagicLinkFlowService::begin_magic_link_landing(...)`. This validates without
   consuming, identifies the exact account, and returns a short-lived encrypted
   flow cookie plus a separate confirmation value.
2. The confirmation page shows the account and submits the confirmation value
   by same-origin `POST`. It never embeds the raw magic-link token.
3. The POST handler calls `confirm_magic_link_flow(...)`, which verifies state
   bound to the selector, verifier proof, exact account, expiry, and independent
   nonce, mints the encrypted session cookie value, and asks the authentication
   repository to consume the challenge and create
   user/session state atomically.
4. The API applies that value with policy-derived attributes using the Axum
   helpers and maps only the generic outcome into its own fixed redirect or error
   response.

The consuming application still owns its router, templates, deployment logging
policy, infrastructure wiring, and repository implementations. There is no raw
consume alternative.
## Which crates do I depend on?

For the common case (Axum HTTP + DynamoDB storage) the recipe is **three
crates**: the service crate re-exports the keyring and lookup-key types, so
the core crates are not direct dependencies:

```toml
[dependencies]
datadeft-magic-link-service = { path = "../datadeft-auth/crates/datadeft-magic-link-service" }
datadeft-magic-link-axum    = { path = "../datadeft-auth/crates/datadeft-magic-link-axum" }
datadeft-magic-link-aws     = { path = "../datadeft-auth/crates/datadeft-magic-link-aws", features = ["aws"] }
# Optional pre-request admission hardening:
datadeft-pow-core           = { path = "../datadeft-auth/crates/datadeft-pow-core" }
```

For development and tests, `datadeft-magic-link-aws` **without** the `aws` feature
is SDK-free. It provides `FakeDynamoDbAuthStore` and `FakeMagicLinkOutbox`,
in-memory implementations of every storage trait that mirror the DynamoDB
adapter's semantics. For a different backend (for example Postgres), depend on
`datadeft-magic-link-service` + `datadeft-magic-link-axum` and implement the repository
traits.

The complete integration includes request, scanner-safe landing, confirmation,
authenticated session, and logout, wired on the shipped fakes. It is
[`examples/axum-magic-link`](examples/axum-magic-link/src/). Start
there. A compiling quickstart also lives in the `datadeft-magic-link-axum` crate
docs.

## Install from registries

```toml
[dependencies]
datadeft-pow-core = "0.4"
# Optional HTTP integration:
datadeft-pow-axum = "0.4"
```

```sh
bun add @datadeft/protect-client
```

Rust requires 1.88 or newer. Applications no longer need git credentials or
vendored client sources. Use the [integration guide](docs/integration.md) for
magic-link dependencies, crate/import renames, and configurable clock skew.

For library development, local `path` dependencies remain supported.

## Repository tasks

Tasks are run via `mise` once the workspace exists:

```sh
mise run fmt
mise run check
mise run test
mise run clippy
mise run audit
mise run verify   # fmt + clippy + test + docs + audit
```

See [`docs/operating.md`](docs/operating.md) for the full operating model.

## Current delivery focus

The core, service, Axum, and AWS library surfaces are complete, and the
runnable integration example ships in
[`examples/axum-magic-link`](examples/axum-magic-link/src/). The
remaining work is production evidence: deployment logging attestation, live
DynamoDB validation, and an immutable release reference. Browser PoW and
country-aware PoW admission remain planned application integration. See the
status and MVP IDs in `docs/onboarding.md`.

## Documentation

- [Documentation index](docs/index.md)
- [Software architecture](docs/architecture.md)
- [Customer onboarding and implementation status](docs/onboarding.md)
- [Security rules](docs/security.md)
- [Formal assurance roadmap](docs/formal-methods.md)
- [Rust standards](docs/rust-standards.md)
- [Operating model](docs/operating.md)

## License

[MIT](LICENSE).

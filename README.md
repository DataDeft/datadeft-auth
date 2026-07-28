# datadeft-auth

Reusable Rust authentication libraries: proof-of-work, encrypted session
tokens, and scanner-safe magic-link login. Extracted from internal
application code into small, deterministic, IO-free cores plus optional
framework and cloud adapters.

> **Status:** unpublished `0.1.0` workspace. APIs are not yet stable.
> Start with [`docs/architecture.md`](docs/architecture.md) and
> [`docs/onboarding.md`](docs/onboarding.md);
> [`docs/security.md`](docs/security.md) is the normative security policy.

## What this is

A set of libraries a Rust API service calls from its own HTTP handlers. The
libraries own the **security-critical, reusable** parts (PoW, token grammar,
session cookies, magic-link request/consume orchestration). The consuming
application keeps everything product-specific (router, paths, JSON shapes,
email templates, redirects, consent policy, locale, audit/WAL, infra).

## Reference source is porting material only

Code under [`to-be-porting/`](to-be-porting/) is **copied reference source**,
not finished library code. It exists only as the material to extract from.
Git ignores it (see [`.gitignore`](.gitignore)) and it must never be wired
into the public crates verbatim. When extracting, remove all application
branding, domains, cookie names, issuer/audience values, email templates,
and product-specific policies.

Examples of things to strip during extraction:

- cookie names like `ct_session` / `ct_pow`
- issuer/audience like `celeratax-auth` / `app.celeratax.hu`
- CloudFront / viewer-country / EU-27 enforcement logic
- WAL/audit event emission
- `@panzerotti/protect-client` package naming
- any CeleraTax/Panzerotti-branded email templates

## Crate shape

```
dd-pow-core
dd-auth-token-core
dd-magic-link-core
dd-magic-link-service
dd-magic-link-axum     (optional)
dd-magic-link-aws      (optional)
```

Dependency direction (adapters are siblings; neither depends on the other):

```
dd-auth-token-core      -> (no workspace crates)
dd-magic-link-core     -> dd-auth-token-core
dd-magic-link-service  -> dd-magic-link-core, dd-auth-token-core
dd-magic-link-axum     -> dd-magic-link-service
dd-magic-link-aws      -> dd-magic-link-service
```

### `dd-pow-core`

Pure Rust, IO-free proof-of-work core. Owns challenge minting and solution
verification. The caller injects clock, entropy, difficulty, max age, and
secret. No Axum, Tokio, AWS SDK, filesystem, environment, logging, or
application-specific domains. Deterministic and fully testable.

### `dd-auth-token-core`

Reusable Branca / base62 / keyring / session-cookie / PoW-cookie primitives.
Cookie name, issuer, audience, TTLs, key IDs, and key material are all
**configurable** — there are no baked-in product values. `Debug` is redacted
for keys, cookies, session IDs, and secret-bearing types. Core APIs never
read the environment or the clock directly.

### `dd-magic-link-core`

IO-free magic-link primitives. Owns the token grammar, selector/verifier
types, parsing, formatting, verifier hash helpers, and redacted `Debug`.
Stores only keyed lookup material, never raw token parts. No email sending,
database access, rate limiting, Axum, AWS, or application copy.

### `dd-magic-link-service`

Framework-neutral orchestration for magic-link requests, scanner-safe
confirmation, and server-revocable sessions. Depends on traits — not concrete
infrastructure — for storage, rate limiting, an email delivery hook (named
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
- **session:** validate cookie freshness plus server-side state, and support
  revocation without sliding refresh

Public errors are generic and non-enumerating. IP, global, malformed-request,
and PoW admission controls belong to the consuming application or edge and are
not magic-link API inputs. No Axum or AWS dependency.

### `dd-magic-link-axum`

Optional Axum integration. Owns bounded request guards, strict same-origin
confirmation, secure flow/session cookie helpers, scanner-safe account
confirmation pages, generic session `401` handling with cookie clearing, and
safe HTTP error mapping. It does **not** own token/session cryptography or
storage transactions, and it does **not** force a router — consumers call the
library functions from their own routes. Production deployments must also
scrub token-bearing request targets from proxy, access, trace, and error logs.

### `dd-magic-link-aws`

Optional AWS adapter. Owns DynamoDB implementations for the
magic-link/session/user/rate-counter traits and an SES sending adapter if
desired. AWS SDK dependencies live here and **only** here. Adapter errors
are scrubbed before crossing the public boundary.

### `packages/dd-protect-client`

Optional browser proof-of-work client, extracted from `frontends/pow`. The
final public package must contain **no** CeleraTax/Panzerotti branding. It
must match `dd-pow-core` challenge/solution vectors exactly.

## Email templates and branding

The copied CeleraTax email templates under
`to-be-porting/celeratax/backends/adapters/templates` are **reference
material only**. The libraries must **not** send CeleraTax-branded email by
default. Every consuming application provides its own subject, text, and HTML
templates (or a renderer).

The service crate models email as **data/traits**, for example:

- recipient
- token, or an already-rendered action URL (depending on the final API)
- subject
- text body
- optional HTML body

If `dd-magic-link-aws` includes an SES sender, it sends **app-provided
message content**. It must not bake in CeleraTax copy, logos, domains,
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
`MagicLinkOutbox` implementation; that trait does not itself guarantee durable
queueing. The public response remains generic.

The only login path is scanner-safe:

1. A bounded landing handler calls
   `MagicLinkFlowService::begin_magic_link_landing(...)`. This validates without
   consuming, identifies the exact account, and returns a short-lived encrypted
   flow cookie plus a separate confirmation value.
2. The confirmation page shows the account and submits the confirmation value
   by same-origin `POST`; it never embeds the raw magic-link token.
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
crates** — the service crate re-exports the keyring and lookup-key types, so
the core crates are not direct dependencies:

```toml
[dependencies]
dd-magic-link-service = { path = "../datadeft-auth/crates/dd-magic-link-service" }
dd-magic-link-axum    = { path = "../datadeft-auth/crates/dd-magic-link-axum" }
dd-magic-link-aws     = { path = "../datadeft-auth/crates/dd-magic-link-aws", features = ["aws"] }
# Optional pre-request admission hardening:
dd-pow-core           = { path = "../datadeft-auth/crates/dd-pow-core" }
```

For development and tests, `dd-magic-link-aws` **without** the `aws` feature
is SDK-free and provides `FakeDynamoDbAuthStore` / `FakeMagicLinkOutbox` —
in-memory implementations of every storage trait that mirror the DynamoDB
adapter's semantics. For a different backend (for example Postgres), depend on
`dd-magic-link-service` + `dd-magic-link-axum` and implement the repository
traits.

The complete integration — request, scanner-safe landing, confirmation,
authenticated session, and logout, wired on the shipped fakes — is
[`examples/axum-magic-link`](examples/axum-magic-link/src/main.rs). Start
there; a compiling quickstart also lives in the `dd-magic-link-axum` crate
docs.

## Local development

Start with local path dependencies, not git or crates.io.

Later, private-git consumption should pin exact commits or tags:

```toml
dd-pow-core = { git = "ssh://git@github.com/datadeft/datadeft-auth.git", package = "dd-pow-core", rev = "<commit-sha>" }
```

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

The core, service, Axum, and AWS library surfaces are implemented, and the
runnable integration example ships in
[`examples/axum-magic-link`](examples/axum-magic-link/src/main.rs). Remaining
work is production evidence: deployment logging attestation, live DynamoDB
validation, and an immutable release reference. Browser PoW and country-aware
PoW admission remain planned application integration; see the status and MVP
IDs in `docs/onboarding.md`.

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

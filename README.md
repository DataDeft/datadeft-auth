# datadeft-auth

Reusable Rust authentication libraries: proof-of-work, encrypted session
tokens, and scanner-safe magic-link login. Extracted from internal
application code into small, deterministic, IO-free cores plus optional
framework and cloud adapters.

> **Status:** local-first, pre-0.1.0. Not published. APIs are not stable.
> See [`docs/plan.md`](docs/plan.md) for the extraction roadmap and
> [`docs/security.md`](docs/security.md) for the security rules every crate
> must satisfy.

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
dd-auth-token-core      -> dd-pow-core
dd-magic-link-core     -> dd-auth-token-core, dd-pow-core
dd-magic-link-service  -> dd-magic-link-core, dd-auth-token-core, dd-pow-core
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

Framework-neutral orchestration for magic-link request and consume flows.
Depends on traits — not concrete infrastructure — for storage, rate
limiting, users, sessions, the email outbox, the clock, and randomness.
Implements the reusable core of:

- **request:** validate caller-decoded input → rate limit → create challenge
  → ask the app-provided outbox to send the email
- **consume:** rate limit attempts → verify and burn the token atomically →
  ensure a user according to app policy → create a session → return the
  session token/cookie payload

Public errors are generic and non-enumerating. No Axum or AWS dependency.

### `dd-magic-link-axum`

Optional Axum integration. Owns request guards, body decoding helpers, cookie
response helpers, and safe HTTP error mapping. It does **not** own core
token/session logic, and it does **not** force a router — consumers can call
library functions from their own routes. Any route helpers it provides are
optional and configurable.

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

Pseudocode for a request handler:

```text
1. The API handler decodes the inbound request (JSON/form).
2. It calls dd_magic_link_service::request(...).
3. The service rate-limits and creates the challenge via traits.
4. The service hands back an email request (recipient, token, etc.).
5. The API renders its OWN email template and stores/sends via its trait adapter.
6. The API maps the generic service result into its OWN HTTP response.
7. The router stays in the API; the library never owns a route.
```

Consume is analogous: the API decodes, calls
`dd_magic_link_service::consume(...)`, gets back a generic session result,
mints the session cookie, and maps the outcome into its own HTTP response.

## Local development

Start with local path dependencies, not git or crates.io.

```toml
[dependencies]
dd-pow-core          = { path = "../datadeft-auth/crates/dd-pow-core" }
dd-auth-token-core   = { path = "../datadeft-auth/crates/dd-auth-token-core" }
dd-magic-link-core   = { path = "../datadeft-auth/crates/dd-magic-link-core" }
dd-magic-link-service = { path = "../datadeft-auth/crates/dd-magic-link-service" }
```

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

## Extraction order

1. Create workspace + crate skeletons (`Cargo.toml`, `mise` tasks, CI, license).
2. Extract `dd-pow-core` from `to-be-porting/celeratax/backends/pow`.
3. Extract `dd-auth-token-core` from `crypto` + auth keyring/session/pow-cookie.
4. Extract `dd-magic-link-core` from the auth `magic_link`/token/verifier pieces.
5. Extract `dd-magic-link-service` from session request/consume orchestration
   behind traits.
6. Add optional Axum and AWS adapters **only after** core/service APIs are stable.
7. Integrate back into consuming projects via path dependencies to prove usability.
8. Only then consider private git or crates.io publishing.

## Documentation

- [Extraction plan](docs/plan.md)
- [Rust standards](docs/rust-standards.md)
- [Operating model](docs/operating.md)
- [Security rules](docs/security.md)

## License

[MIT](LICENSE).

# datadeft-auth

Reusable Rust authentication libraries: proof-of-work (PoW), encrypted session
tokens, and scanner-safe magic-link login. Small, deterministic, IO-free cores
plus optional framework and cloud adapters.

**Status:** pre-1.0. `0.5.0` is a breaking release being validated; the latest
published version on crates.io and npm is `0.4.1`.

## What this is

A Rust API service calls these libraries from its own HTTP handlers.

- **The libraries own** the security-critical, reusable parts: PoW, the token
  grammar, session cookies, and magic-link request and consume orchestration.
- **Your application owns** everything product-specific: router, paths, JSON
  shapes, email templates, redirects, consent policy, locale, audit/WAL,
  deployment logging, infrastructure, and repository implementations.

The public crates and the npm package contain no application-specific code:

- no application branding, domains, cookie names, issuers, or audiences
- no branded email templates or application package names; the application
  supplies the subject, text, and HTML, and the SES sender sends only that
  app-provided content
- no country detection or CDN header logic (country pinning policy,
  `CountryPolicy`, is library-owned; the country value comes from the
  application's trusted edge)
- no audit/WAL event emission

The only login path is scanner-safe: a `GET` landing never consumes the link,
and a same-origin `POST` confirms it. There is no raw consume alternative. See
[architecture.md](docs/architecture.md) for the flows.

## Crates

| Crate | Purpose |
| --- | --- |
| `datadeft-auth-token-core` | Branca, base62, keyring, session-cookie, and PoW-cookie primitives. All names, TTLs, and keys are configurable. |
| `datadeft-magic-link-core` | IO-free token grammar, selector/verifier types, and verifier hashes. Stores only keyed lookup material. |
| `datadeft-magic-link-service` | Framework-neutral request, scanner-safe confirmation, and server-revocable sessions. Depends on traits only. |
| `datadeft-magic-link-axum` | Optional Axum helpers: request guards, same-origin confirmation, cookies, safe error mapping. Does not force a router. |
| `datadeft-magic-link-aws` | Optional DynamoDB and SES adapters. The only crate with AWS SDK dependencies. Scrubs its errors at the public boundary. |
| `datadeft-pow-core` | IO-free PoW challenge minting and verification. |
| `datadeft-pow-axum` | Optional Axum PoW endpoints, proof cookie, and per-solve admission (`admit_proof`). |
| `@datadeft/protect-client` | Optional browser PoW client (`packages/dd-protect-client`). Matches the `datadeft-pow-core` vectors exactly. |

The adapters are siblings; neither depends on the other. See
[architecture.md](docs/architecture.md) for the dependency graph.

## Install

Rust 1.88 or newer is required. The common case is Axum plus DynamoDB. The
service crate re-exports the keyring and lookup-key types, so you do not
depend on the core crates directly.

```toml
[dependencies]
datadeft-magic-link-service = "0.5"
datadeft-magic-link-axum    = "0.5"
datadeft-magic-link-aws     = { version = "0.5", features = ["aws"] }
datadeft-pow-axum           = "0.5"
datadeft-pow-core           = "0.5"
```

Until 0.5.0 is on the registries (latest published: 0.4.1), replace each
version with `{ git = "https://github.com/DataDeft/datadeft-auth", rev = "<commit>" }`
(keep `features`).

```sh
bun add @datadeft/protect-client
```

For tests, use `datadeft-magic-link-aws` **without** the `aws` feature. It is
SDK-free and provides `FakeDynamoDbAuthStore` and `FakeMagicLinkOutbox`. For
another backend (for example Postgres), implement the repository traits. For
library development, local `path` dependencies remain supported.

## Start here

1. [Integration guide](docs/integration.md): wire the libraries step by step,
   and upgrade from 0.4.
2. [`examples/axum-magic-link`](examples/axum-magic-link/src/): the complete
   runnable integration on the shipped fakes. A compiling quickstart also
   lives in the `datadeft-magic-link-axum` crate docs.
3. [Security rules](docs/security.md): the normative security policy.

## Documentation

- [Documentation index](docs/index.md)
- [Architecture](docs/architecture.md)
- [Onboarding](docs/onboarding.md): production checklist, status, and backlog
- [Security rules](docs/security.md)
- [Formal assurance](docs/formal-methods.md)
- [Rust standards](docs/rust-standards.md)
- [Operating model](docs/operating.md): `mise` tasks, including
  `mise run verify`
- [Integration guide](docs/integration.md)
- [Releasing](docs/releasing.md)

## License

[MIT](LICENSE).

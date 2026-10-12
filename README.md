# datadeft-auth

Reusable Rust authentication libraries: proof-of-work (PoW), encrypted session
tokens, and scanner-safe magic-link login. Small, deterministic, IO-free cores
plus optional framework and cloud adapters.

**Status:** pre-1.0. The latest version on crates.io and npm is `0.5.0`.

## What this is

A Rust API service calls these libraries from its own HTTP handlers.

- **The libraries own** the security-critical, reusable parts: PoW, the token
  grammar, session cookies, and magic-link request and consume orchestration.
- **Your application owns** everything product-specific: router, paths, JSON
  shapes, email templates, redirects, consent policy, locale, audit/WAL,
  deployment logging, infrastructure, and repository implementations.

The public crates and the npm package contain no application-specific code:

- no application branding, domains, cookie names, issuers, or audiences
- no branded email templates or application package names. The application
  supplies the subject, text, and HTML. The SES sender sends only that
  app-provided content.
- no country detection or CDN header logic. The library owns the country
  pinning policy (`CountryPolicy`). The country value comes from the trusted
  edge of the application.
- no audit/WAL event emission

The only login path is scanner-safe: a `GET` landing never consumes the link,
and a same-origin `POST` confirms it. There is no raw consume alternative. See
[architecture.md](docs/architecture.md) for the flows.

## Crates

| Crate | Purpose |
| --- | --- |
| `datadeft-auth-token-core` | Generic Branca, base62, keyring, and bound-cookie primitives. The session cookie purpose lives in `datadeft-magic-link-service`. The PoW proof cookie purpose lives in `datadeft-pow-core`. |
| `datadeft-magic-link-core` | IO-free token grammar, selector/verifier types, and verifier hashes. Stores only keyed lookup material. |
| `datadeft-magic-link-service` | Framework-neutral request, scanner-safe confirmation, and server-revocable sessions. Depends on traits only. |
| `datadeft-magic-link-axum` | Optional Axum helpers: request guards, same-origin confirmation, cookies, safe error mapping. Does not force a router. |
| `datadeft-magic-link-aws` | Optional DynamoDB and SES adapters. The only crate with AWS SDK dependencies. Scrubs its errors at the public boundary. |
| `datadeft-pow-core` | IO-free PoW challenge minting and verification. |
| `datadeft-pow-axum` | Optional Axum PoW endpoints, proof cookie, and per-solve admission (`admit_proof`). |
| `@datadeft/protect-client` | Optional browser PoW client (`packages/dd-protect-client`). Matches the `datadeft-pow-core` vectors exactly. |

The adapters are siblings. Neither adapter depends on the other. See
[architecture.md](docs/architecture.md) for the dependency graph.

## Install

This is the single install block for the libraries. You need Rust 1.88 or
newer. The common case is Axum plus DynamoDB. The service crate re-exports
the keyring and lookup-key types.

```toml
[dependencies]
datadeft-magic-link-service = "0.5"
datadeft-magic-link-axum    = "0.5"
datadeft-magic-link-aws     = { version = "0.5", features = ["aws"] }
datadeft-pow-axum           = "0.5"
datadeft-pow-core           = "0.5"
# Optional core crates. Add them only when you use their items directly
# (for example, you implement KeyPurpose or read token and email types
# that are not re-exported):
datadeft-auth-token-core    = "0.5"
datadeft-magic-link-core    = "0.5"
```

```sh
bun add @datadeft/protect-client
```

Pin the crate version from crates.io and commit your lockfiles. To test an
unpublished commit, replace each version with
`{ git = "https://github.com/DataDeft/datadeft-auth", rev = "<commit>" }`.
Keep `features`.

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

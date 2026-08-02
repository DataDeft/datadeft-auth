# Changelog

All notable changes to this workspace are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-02

First tagged release.

### Added

- **Magic-link passwordless authentication.** Scanner-safe flow: a
  side-effect-free landing `GET` mints a short-lived confirm cookie, and a
  same-origin confirmation `POST` consumes a single-use token and issues the
  session. Atomic authentication commit for the DynamoDB adapter.
- **Encrypted cookies** (`dd-auth-token-core`): Branca / XChaCha20-Poly1305 with
  an HKDF-SHA256 keyring, purpose separation, base62 codec, and two-clock
  session freshness (idle plus absolute). Cookies: `dd_session` (session) and
  `dd_auth_confirm` (confirmation flow).
- **Proof-of-work admission.** `dd-pow-core` provides pure challenge
  mint/verify and the `dd_pow` proof-cookie codec. `dd-pow-axum` provides
  headless `pow/create` and `pow/validate` glue. Proof-cookie lifetime is
  configurable (3 h default, 24 h ceiling) and stateless (reusable within its
  lifetime).
- **`dd-protect-client`**: a zero-dependency TypeScript browser client that
  solves challenges in Web Workers, matching the `dd-pow-core` wire contract
  byte for byte. Shipped as TypeScript source.
- **Axum integration** (`dd-magic-link-axum`): headless landing/confirmation
  handlers, validated cookie configuration, and scanner-safe security headers.
- **AWS adapters** (`dd-magic-link-aws`, `aws` feature): DynamoDB single-table
  store and an SES outbox, plus in-memory fakes for tests.
- **Session country pinning**: an opportunistic lock derived from a configurable
  trusted-edge header, fail-closed on a locked session with no signal.
- A runnable example at `examples/axum-magic-link`.

### Security

- Raw magic-link tokens, selectors, and verifiers are never stored. Storage
  keeps keyed HMAC lookup material and verifier hashes only.
- The normalized email is stored at rest in readable form, protected by
  DynamoDB encryption at rest (KMS) and least-privilege IAM. No application-layer
  field encryption.
- Purpose-separated keys per cookie kind. A value minted for one purpose cannot
  validate as another, even under the same root secret.
- No refresh token by design. A session lives within its idle and absolute TTLs.
  Re-authentication is a fresh magic link.

### Notes

- **Distribution:** crates are `publish = false`. Consume them by a pinned path
  or Git revision (or the `v0.1.0` tag).
- **Deployment defaults:** inline SES delivery is accepted (MVP-006), and the
  normalized email is stored readable under KMS/IAM (MVP-007). Both seams remain
  configurable per deployment.
- **Dependency traits** require `Send` futures and use static dispatch only. The
  library does not support `dyn` trait objects.
- **Not yet included:** published crates on a registry (MVP-004) and
  country-aware PoW difficulty policy (MVP-013).

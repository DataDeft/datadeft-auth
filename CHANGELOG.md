# Changelog

All notable changes to this workspace are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - Unreleased

### Changed

- Rename the seven Rust crates from `dd-*` to `datadeft-*`, including Rust
  import paths and source directories. Registry installs use version `0.2`.
- Prepare crates.io metadata, versioned path dependencies, README and dual
  license texts. MIT OR Apache-2.0 is proposed, pending Istvan's sign-off.
- Declare and verify Rust 1.88, matching the `time` dependency requirement.
- Package the browser client as `@datadeft/protect-client` with ESM and `.d.ts`
  exports for the main module and `./worker`. Workers now start as ES modules.
  No runtime dependencies or install scripts; Bun workspace and packed-consumer
  checks replace TypeScript source distribution.

### Added

- Explicit clock-skew variants for PoW and cookie verification/minting plus
  `PowPolicy::with_clock_skew_secs`. Existing calls keep the 60-second default;
  deployments can select 30 seconds (CeleraTax NFR-SEC-012) or zero.
- Release-please PRs and tagged releases using crates.io/npm OIDC publishing,
  with verification, an opt-in repository variable, and an approval environment.
- [Registry migration guide](docs/migration-registries.md) and
  [maintainer release runbook](docs/releasing.md), including first-publish
  bootstrap and npm provenance prerequisites.

Wire formats, cookie names, cryptographic domains, and expiry bounds are unchanged.
This entry describes prepared changes, not a completed registry publication.

## [0.2.0] - 2026-08-03

Solve-timing release. Breaking for `dd-pow-core` / `dd-pow-axum` callers;
wire-compatible with deployed challenges, proof cookies, and the shipped
browser client.

### Changed

- **PoW clock is milliseconds** (breaking). `mint_challenge`,
  `verify_solution`, `mint_pow_challenge`, and `verify_pow_solution` now take
  a `UnixMillis` newtype instead of seconds/RFC3339 strings; the unit change
  is a compile error, never a silent ×1000. Mint formats `tim` itself,
  RFC3339 with millisecond precision (whole seconds still format
  fraction-free, so previously minted challenges and all goldens are
  unchanged). Freshness checks are now millisecond-exact.
- **Proof-cookie body budget** (`PowProofCookie::MAX_BODY_BYTES`) is 65, up
  from 64, so the one-byte-larger v2 body keeps the established 12-byte kid
  budget.

### Added

- **Solve-timing signal.** `Verified::mint_to_verify_ms` and
  `PowAdmission::mint_to_verify_ms` (the new return type of
  `verify_pow_solution`, carrying the `Set-Cookie` header) expose the
  server-derived mint→verify delta. `tim` is HMAC-bound, so the delta is
  inflatable but not deflatable: an implausibly fast solve is definitive
  native-solver evidence. Soft signal only — for risk tagging, histograms, and
  difficulty tuning, never hard blocking. Documented in `docs/security.md`,
  "Solve-timing signal".
- **Proof-cookie v2 body with an opaque solve-class byte.**
  `mint_pow_proof_cookie` takes `Option<u8>`: `None` mints the v1 body
  (byte-identical to 0.1.x cookies), `Some` mints the versioned v2 body
  carrying one app-defined byte inside the encrypted payload.
  `VerifiedPowProof::solve_class()` returns it; v1 cookies verify unchanged
  and report `None`. `verify_pow_solution` exposes this as a
  `classify_solve: FnOnce(u64) -> Option<u8>` hook mapping the delta to the
  stamped byte. The library assigns the byte no meaning: quantization and
  policy stay in the app.

## [0.1.1] - 2026-08-02

Housekeeping patch. No behavioral change to any crate: the two source edits are
lint-driven refactors that preserve behavior.

### Changed

- **CI is one mise-driven job.** `ci.yml` collapses to checkout, toolchain,
  cache, and `mise run verify`, so local and CI run the same gate. The root
  config now lives at `mise.toml`, and `scripts/api-guard.ts` fails the build if
  a hidden `.mise.toml` reappears. Shell guards and the awk API checks are gone.
- Behavior-preserving clippy refactors in `dd-pow-core` (`ops.rs`) and
  `dd-magic-link-aws` (`window.rs`) to satisfy stable 1.97.

### Documentation

- Add `docs/integration.md`, a consumer entry point for implementation agents.
- Mark modeled claims as covered in `docs/formal-methods.md`, and freeze the
  MVP status at the release in `docs/onboarding.md`.

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

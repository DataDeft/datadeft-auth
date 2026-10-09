# Changelog

All notable changes to this workspace are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0](https://github.com/DataDeft/datadeft-auth/compare/v0.3.0...v0.4.0) (2026-10-09)


### ⚠ BREAKING CHANGES

* **admin:** SessionRepository::is_user_active is replaced by is_session_owner_active(user_id, session_created_at_unix).
* **service:** SessionRepository implementors must add is_user_active.
* **pow:** PowError::MaxAgeTooLarge is renamed InvalidMaxAge and also covers zero.
* max ages above these ceilings are now errors.
* PowPolicy::with_clock_skew_secs now returns Result<PowPolicy, PowPolicyError>; PowError and PowPolicyError gain a variant.
* **magic-link:** these six types no longer implement PartialEq/Eq.
* **token-core:** read Verified fields through the new getters.
* **aws:** MagicLinkFlowService has a new field, previous_lookup_hmac_key (use None when not rotating), and LoadedAuthSecrets has two new public fields.

### Features

* **aws:** DynamoDB admin API with an append-only audit trail ([f4cdf79](https://github.com/DataDeft/datadeft-auth/commit/f4cdf79b9a0e35b3a77337380f246da48c519cb1))
* **service:** admin API for users, sessions, and an audit trail ([9a74f2c](https://github.com/DataDeft/datadeft-auth/commit/9a74f2cfeda0e95e03339e5809c2d2cef0e85862))
* **service:** explicit sliding session refresh ([72b4d8d](https://github.com/DataDeft/datadeft-auth/commit/72b4d8d10d94ccadb4d3756e048dea94e1be3d32))
* **service:** reject sessions of disabled users on every request ([6513289](https://github.com/DataDeft/datadeft-auth/commit/651328942ea9d4fcb9df90e7123385645fbe3b29))


### Bug Fixes

* **admin:** make disable retry-safe and enable never restore old sessions ([7fcdc09](https://github.com/DataDeft/datadeft-auth/commit/7fcdc09f88245b2a73e1afb5474c4082f84c0260))
* **admin:** revoke only active sessions; strict re-enable watermark ([6b77300](https://github.com/DataDeft/datadeft-auth/commit/6b77300196da32f94499601a0bc3e9def5d10d70))
* **aws:** keep session rows for the audit trail ([f31e11b](https://github.com/DataDeft/datadeft-auth/commit/f31e11b745a23fff4c8dba2c140987d2edcfd7d0))
* **aws:** support rotating the storage and lookup HMAC keys ([dce7fbd](https://github.com/DataDeft/datadeft-auth/commit/dce7fbd47297b1fcfda98ac31a73caa8100b6543))
* **axum:** skip malformed foreign cookies instead of failing auth ([fa07c39](https://github.com/DataDeft/datadeft-auth/commit/fa07c397513cc141a9433ca53e35c2ea4884a80d))
* **axum:** use strict-origin referrer so confirmation POSTs carry Origin ([460b39d](https://github.com/DataDeft/datadeft-auth/commit/460b39d748f0f111e0d59ea47d5f6c4d02e09485))
* cap configurable clock skew at 300 seconds ([24101bb](https://github.com/DataDeft/datadeft-auth/commit/24101bb2e3f326e652f423621435296d6fc58d35))
* cap cookie and PoW challenge max age ([425f71b](https://github.com/DataDeft/datadeft-auth/commit/425f71b463de0cf7aac06584f277c34274fdc030))
* **magic-link:** remove non-constant-time equality from secret types ([c7cd501](https://github.com/DataDeft/datadeft-auth/commit/c7cd501573442c7e1102366de488f0d3e79f8d66))
* **pow:** reject a zero challenge max age in the core verifier ([86fe461](https://github.com/DataDeft/datadeft-auth/commit/86fe4617532ed2ed7f22958f1672198111e4d963))
* **protect-client:** typed errors for non-JSON challenges; no body echo ([225caa3](https://github.com/DataDeft/datadeft-auth/commit/225caa336c098a8d0387a2462999b70f9a7dc87b))
* **protect-client:** validate challenges; clamp workerCount to 1..=8 ([ce25eae](https://github.com/DataDeft/datadeft-auth/commit/ce25eae6e3b61badc200a8f1fe89452b8ee421bb))
* **service:** refresh only a fresh validation; harden example ([27fbe0a](https://github.com/DataDeft/datadeft-auth/commit/27fbe0a7636896a4e9dad3ce17213c77b5ffce00))
* **token-core:** make branca::Verified fields private ([7110f7c](https://github.com/DataDeft/datadeft-auth/commit/7110f7c73c79621e70b1c0da807c543e912e212b))

## [0.3.0](https://github.com/DataDeft/datadeft-auth/compare/v0.2.0...v0.3.0) (2026-10-08)

First registry release (crates.io and npm). Breaking for PoW callers that read
the solve-timing value.

### Changed

- **Solve-timing delta is `Option<u64>`** (breaking).
  `Verified::mint_to_verify_ms` and `PowAdmission::mint_to_verify_ms` are now
  `Option<u64>`, and `verify_pow_solution`'s `classify_solve` closure takes
  `Option<u64>`. The value is `None` when the challenge `tim` is ahead of the
  verifying clock (accepted within the configured clock-skew tolerance).
  Previously it was clamped to `0`, which reads as the fastest possible solve
  and could falsely flag honest clients when instance clocks disagree.
  Existing `|_| None` classifiers compile unchanged; classifiers that read the
  value must handle `None` and never treat it as fast.
- The solve-timing trust argument (`docs/security.md`) now states the
  cross-instance clock assumption behind fast-floor gating, and
  `docs/migration-v0.2.0.md` documents the rolling-upgrade constraint for v2
  proof cookies (return a class byte only once every node runs v0.2.0+).
- Rename the seven Rust crates from `dd-*` to `datadeft-*`, including Rust
  import paths and source directories. Registry installs use version `0.3`.
- Prepare crates.io metadata, versioned path dependencies, READMEs, and MIT
  license texts.
- Declare and verify Rust 1.88, matching the `time` dependency requirement.
- Package the browser client as `@datadeft/protect-client` with ESM and `.d.ts`
  exports for the main module and `./worker`. Workers now start as ES modules.
  No runtime dependencies or install scripts; Bun workspace and packed-consumer
  checks replace TypeScript source distribution.

### Added

- Explicit clock-skew variants for PoW and cookie verification/minting plus
  `PowPolicy::with_clock_skew_secs`. Existing calls keep the 60-second default;
  deployments can select a stricter bound such as 30 seconds, or zero.
- Release-please PRs and tagged releases using crates.io/npm OIDC publishing,
  with verification, an opt-in repository variable, and an approval environment.
- Consumer upgrade notes in [integration.md](docs/integration.md) and a
  [maintainer release runbook](docs/releasing.md), including first-publish
  bootstrap and npm provenance prerequisites.

Wire formats, cookie names, cryptographic domains, and expiry bounds are unchanged.

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

# datadeft_auth — Elixir 0.8 implementation in progress

Elixir server implementation of datadeft-auth, compatible with Rust 0.7, using a
tiny Rustler crypto NIF over the existing Rust core. This package is incomplete
and is not ready for authentication or production use. The repository version
stays aligned at 0.7.0 until the 0.8 release is prepared.

## Usage

See [USAGE.md](USAGE.md) for local installation, working API examples and the
boundary between available primitives and the unfinished login integration.
See [RELEASE-READINESS.md](RELEASE-READINESS.md) for CI evidence and release blockers;
a green draft implementation PR is not a ready 0.8.0 release.

## Development

Requires Elixir >= 1.16, OTP >= 26, and the repository's pinned Rust toolchain:

```sh
mise run elixir-verify
```

Implemented slices: email identity, lookup-key rotation/rekeying, challenge
storage, atomic consume/account/session transactions, shared counters and bounded
Branca encode/decode, plus purpose-bound confirm and session cookies with key
rotation. Framework-neutral authentication orchestration, HTTP integration and
production AWS IO remain incomplete.
See [the checklist](IMPLEMENTATION.md).

## Tiny native boundary

Exactly two native operations initially: production Branca encode and decode.
The wrapper delegates to `datadeft-auth-token-core`; it contains no authentication
service, infrastructure, solver or custom cipher. Inputs are bounded in Elixir
and Rust, calls run on dirty CPU schedulers, and encoding uses OS entropy.
Decode alone never establishes freshness, purpose or session validity.

Rustler/Jason are build dependencies; no Rustler application process runs.
Tests also use Jason and OTP HTTP against loopback-only DynamoDB Local.
No production DynamoDB HTTP client is bundled: IO is explicitly injected.

Source-checkout compilation works today. Precompiled artifacts and clean Hex
archive/Mix release consumers are not yet implemented or validated; do not publish
the current archive with repository-relative Cargo paths. NIF load failure fails
closed, without an alternate algorithm or BEAM fallback.
See [the approved native boundary and safety contract](CRYPTO-DEPENDENCIES.md).

Compatibility fixtures live in `spec/compatibility/`; package-local tests also
work without repository fixtures. Repository checks additionally exercise the
official Rust Branca vectors through the NIF. A native fault can crash BEAM;
Rustler is not process isolation, and BEAM secrets cannot promise zeroization.

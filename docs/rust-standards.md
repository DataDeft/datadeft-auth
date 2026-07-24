# Rust standards

## Core principles

- Explicit over clever.
- Prefer plain functions, structs, enums, traits, and generics.
- Do not write macros for application/library logic.
- No `unwrap`, `expect`, or `panic!` in production paths.
- Core crates must be deterministic and IO-free.
- Adapter crates own IO, network, clocks, and external dependency mapping.
- Security-sensitive values must use redacted `Debug`.
- `unsafe` is not allowed unless a short security/design note explains why there is no safe alternative.

## Crate layering

Allowed dependency graph:

```text
dd-auth-token-core      -> dd-pow-core
dd-magic-link-core     -> dd-auth-token-core, dd-pow-core
dd-magic-link-service  -> dd-magic-link-core, dd-auth-token-core, dd-pow-core
dd-magic-link-axum     -> dd-magic-link-service
dd-magic-link-aws      -> dd-magic-link-service
examples/*             -> adapter and service crates as needed
```

Rules:

- `*-core` crates must not depend on Axum, Tokio, AWS SDK, tracing, filesystem, process environment, or network clients.
- Core functions receive clock/entropy/config as input.
- Adapter crates may depend on Tokio/AWS/Axum.
- Axum and AWS adapter crates are siblings; neither adapter may depend on the other.
- Shared adapter concerns belong in service traits or core domain types, not cross-adapter imports.
- Service crates depend on traits, not concrete infrastructure.
- No circular dependencies.
- Keep public APIs small and stable.
- Keep optional integrations behind feature flags.
- Prefer dependency injection over globals, singletons, or environment reads.

## Error handling

- Library APIs return typed errors.
- Public error enums should implement:
  - `Debug`
  - `Display`
  - `std::error::Error`
  - `Clone`/`Copy` where practical
  - `Eq`/`PartialEq` where practical
- Do not leak tokens, cookies, HMAC inputs, key material, email addresses, or raw identifiers in errors.
- `anyhow` is acceptable in examples, binaries, tests, and setup code, but not as the main public library error type.
- Conversion from adapter-specific errors into public errors must scrub sensitive data.

## No application macros

Do not author our own macros for:

- dispatch
- key building
- field mapping
- trait forwarding
- token parsing
- storage shape generation
- route generation

Allowed:

- serde derives
- test macros
- `tokio::test`
- established crate derives/attributes where they improve clarity

## Secrets and redaction

Any type wrapping secret or sensitive material must redact `Debug`.

Example:

```rust
impl core::fmt::Debug for MagicLinkToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MagicLinkToken(..)")
    }
}
```

Redact:

- magic-link tokens
- selectors/verifiers
- session IDs
- Branca keys
- HMAC peppers
- cookie values
- normalized emails when used as user identifiers

## Determinism

Core APIs should not call:

- system clock
- random number generators
- environment variables
- filesystem
- network
- logging

Instead, callers inject:

- `now_unix`
- `now_rfc3339`
- entropy bytes
- key material
- config values

## Tests

Each crate must have:

- unit tests for pure functions
- golden/vector tests for token formats
- tamper tests for security-sensitive parsing/verification
- round-trip tests for mint/parse or encode/decode flows
- public API smoke tests that compile with default features

Prefer property tests for token grammar and cryptographic wrappers when cheap.

Test code may use `unwrap`/`expect` only when the failure message makes the test failure clearer. Production code may not.

## Module layout

Use one feature module plus co-located tests.

```text
src/
  lib.rs
  magic_link.rs
  magic_link_tests.rs
  session_cookie.rs
  session_cookie_tests.rs
```

Wire tests with:

```rust
#[cfg(test)]
#[path = "magic_link_tests.rs"]
mod magic_link_tests;
```

Entry files decode/delegate/encode only. Business logic lives in named modules.

## Naming

- Rust symbols: `snake_case`
- Types/enums/traits: `UpperCamelCase`
- JSON fields: `snake_case`
- Cookie names: lower `snake_case`, optionally app-prefixed, for example `dd_session`
- HTTP paths: `kebab-case`
- CLI flags: `--kebab-case`
- Environment variables: `SCREAMING_SNAKE_CASE`
- Opaque IDs: `tag-<body>`

Opaque identifiers must not encode real-world facts.

## Public API shape

- Prefer owned domain types at crate boundaries.
- Use `&str`, `&[u8]`, and borrowed views internally where helpful, but do not make public APIs lifetime-heavy without a clear payoff.
- Expose builders/config structs for required configuration.
- Use `#[non_exhaustive]` for public structs/enums only when we intentionally reserve expansion space.
- Document security-relevant invariants on public types and functions.
- Keep serde support explicit and feature-gated when it is not required by the core behavior.

## Features and dependencies

- Default features should be minimal.
- Avoid adding dependencies for tiny helpers.
- Pin broad integration dependencies to adapter crates, not core crates.
- Every dependency added for crypto, parsing, HTTP, AWS, or async must have a clear owner crate and reason.

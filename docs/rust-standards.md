# Rust standards

## Core principles

- Prefer explicit code over clever code.
- Use plain functions, structs, enums, traits, and generics.
- Do not write application macros.
- Do not use `unwrap`, `expect`, or `panic!` in production paths.
- Keep core crates deterministic and IO-free.
- Put IO, network, clocks, and external mapping in adapters.
- Redact `Debug` for sensitive values.
- Do not use `unsafe` without a security note.

## Crate layering

Allowed dependency graph:

```text
dd-auth-token-core      -> no workspace crates
dd-magic-link-core     -> dd-auth-token-core
dd-magic-link-service  -> dd-magic-link-core, dd-auth-token-core
dd-magic-link-axum     -> dd-magic-link-service
dd-magic-link-aws      -> dd-magic-link-service
examples               -> selected adapters and services
```

Rules:

- Keep `*-core` crates free of IO.
- Keep Axum, Tokio, AWS SDK, tracing, files, env, and network out of core crates.
- Pass clock, entropy, and config into core functions.
- Put Tokio, AWS, and Axum in adapter crates.
- Keep Axum and AWS adapters as siblings.
- Do not make adapters depend on each other.
- Put shared adapter concerns in service traits or core types.
- Make service crates depend on traits.
- Avoid circular dependencies.
- Keep public APIs small.
- Put optional integrations behind feature flags.
- Prefer dependency injection over globals and environment reads.

## Error handling

- Return typed errors from library APIs.
- Scrub adapter errors before public conversion.
- Do not leak tokens, cookies, HMAC inputs, key material, emails, or raw IDs.

Public error enums should implement these traits where practical:

- `Debug`
- `Display`
- `std::error::Error`
- `Clone`
- `Copy`
- `Eq`
- `PartialEq`

Use `anyhow` only in examples, binaries, tests, and setup code.

## No application macros

Do not write macros for these tasks:

- dispatch
- key building
- field mapping
- trait forwarding
- token parsing
- storage shape generation
- route generation

You can use these macro forms:

- serde derives
- test macros
- `tokio::test`
- established crate derives and attributes

## Secrets and redaction

Any type that wraps secret or sensitive material must redact `Debug`.

Example:

```rust
impl core::fmt::Debug for MagicLinkToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MagicLinkToken(..)")
    }
}
```

Redact these values:

- magic-link tokens
- selectors
- verifiers
- session IDs
- Branca keys
- HMAC peppers
- cookie values
- normalized emails used as user IDs

## Determinism

Core APIs must not call these sources:

- system clock
- random number generators
- environment variables
- filesystem
- network
- logging

Callers inject these inputs:

- `now_unix`
- `now: UnixMillis` (PoW mint/verify; the library formats RFC3339 internally)
- CSPRNG entropy bytes
- deterministic fixture entropy for tests
- key material
- config values

Adapters that create secrets or nonces must use OS-backed CSPRNGs. A reviewed cryptographic RNG can replace OS RNG when needed.

## Tests

Each crate must include these tests:

- unit tests for pure functions
- golden tests for token formats
- tamper tests for security parsing and verification
- round-trip tests for mint, parse, encode, or decode flows
- public API smoke tests with default features

Prefer property tests for token grammar and crypto wrappers when cheap.

Test code may use `unwrap` and `expect`. Add a clear failure message when that helps.

Production code must not use `unwrap` or `expect`.

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

Wire tests with this pattern:

```rust
#[cfg(test)]
#[path = "magic_link_tests.rs"]
mod magic_link_tests;
```

Entry files decode, delegate, and encode. Put business logic in named modules.

## Naming

- Rust symbols use `snake_case`.
- Types, enums, and traits use `UpperCamelCase`.
- JSON fields use `snake_case`.
- Cookie names use lower `snake_case`.
- HTTP paths use `kebab-case`.
- CLI flags use `--kebab-case`.
- Environment variables use `SCREAMING_SNAKE_CASE`.
- Opaque IDs use `tag-<body>`.

Opaque IDs must not encode real-world facts.

## Public API shape

- Prefer owned domain types at crate boundaries.
- Use `&str` and `&[u8]` inside crates where helpful.
- Avoid lifetime-heavy public APIs without a clear payoff.
- Expose builders or config structs for required config.
- Add `#[non_exhaustive]` only when we reserve expansion space.
- Document security invariants on public types and functions.
- Gate serde support when core behavior does not require it.

## Features and dependencies

- Keep default features minimal.
- Avoid dependencies for tiny helpers.
- Put broad integration dependencies in adapter crates.
- Give each crypto, parsing, HTTP, AWS, or async dependency an owner crate.
- Record the reason for each such dependency.

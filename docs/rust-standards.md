# Rust standards

## Core principles

- Prefer explicit code over clever code.
- Use plain functions, structs, enums, traits, and generics.
- Do not write application or library macros (see
  [No application macros](#no-application-macros)).
- Do not use `unwrap`, `expect`, or `panic!` in production code.
- Do not use `unsafe` without a written security or design note.
- Redact `Debug` for sensitive values.

## Crate layering

Allowed dependency graph:

```text
datadeft-auth-token-core     -> no workspace crates
datadeft-magic-link-core     -> datadeft-auth-token-core
datadeft-magic-link-service  -> datadeft-magic-link-core, datadeft-auth-token-core
datadeft-magic-link-axum     -> datadeft-magic-link-service
datadeft-magic-link-aws      -> datadeft-magic-link-service
datadeft-pow-core            -> datadeft-auth-token-core
datadeft-pow-axum            -> datadeft-pow-core, datadeft-auth-token-core
examples/*                   -> adapter and service crates as needed
```

Core crates:

- Keep `*-core` crates deterministic and free of IO.
- Keep Axum, Tokio, AWS SDK, tracing, files, env, and network out of them.
- Pass clock, entropy, and config into core functions.

Adapters and services:

- Put IO, network, clocks, and external mapping in adapter crates. Tokio,
  AWS, and Axum belong there.
- Keep the Axum and AWS adapters as siblings. Adapters do not depend on each
  other.
- Put shared adapter concerns in service traits or core types.
- Service crates depend on traits, not concrete infrastructure.

Everywhere:

- Avoid circular dependencies.
- Keep public APIs small.
- Put optional integrations behind feature flags.
- Prefer dependency injection over globals and environment reads.

## Error handling

- Return typed errors from library APIs.
- Use `anyhow` only in examples, binaries, tests, and setup code.
- Scrub adapter errors before you convert them to public errors.
- Do not leak tokens, cookies, HMAC inputs, key material, emails, or raw IDs.

Where practical, implement these traits on public error enums: `Debug`,
`Display`, `std::error::Error`, `Clone`, `Copy`, `Eq`, `PartialEq`.

## No application macros

Do not write macros for dispatch, key building, field mapping, trait
forwarding, token parsing, storage shape generation, or route generation.

You may use:

- serde derives
- test macros
- `tokio::test`
- established crate derives and attributes

## Secrets and redaction

Any type that wraps secret or sensitive material must redact `Debug`:

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

Core APIs must not call the system clock, random number generators,
environment variables, the filesystem, the network, or logging.

Callers inject these inputs instead:

- `now_unix`
- `now: UnixMillis` for PoW mint and verify (the library formats RFC3339
  internally)
- CSPRNG entropy bytes
- deterministic fixture entropy for tests
- key material
- config values

Adapters that create secrets or nonces must use an OS-backed CSPRNG. A
reviewed cryptographic RNG may replace the OS RNG when needed.

## Tests

Each crate must include:

- unit tests for pure functions
- golden tests for token formats
- tamper tests for security parsing and verification
- round-trip tests for mint, parse, encode, or decode flows
- public API smoke tests with default features

When property tests are cheap, prefer them for token grammar and crypto
wrappers.

Test code may use `unwrap` and `expect`. When it helps, add a clear failure
message. Production code must not use them.

## Module layout

Keep files small enough to read in one sitting:

- Production files: about 400 lines at most.
- Test files: about 600 lines at most.
- Split along feature boundaries, never mid-feature.

`lib.rs` holds only crate docs, `mod` declarations, and `pub use` re-exports.
It holds no functions, types, or impls.

Split a large module with the `module.rs` + `module/` layout. Never use
`mod.rs`. The parent file documents the module, declares its children, and
re-exports them, so the public API does not change:

```text
src/
  lib.rs
  service.rs              # docs, `mod request; mod flow;`, re-exports
  service/
    request.rs
    flow.rs
    flow_tests.rs         # `#[cfg(test)] mod flow_tests;` in service.rs
```

A small module stays flat: one feature file plus a co-located `*_tests.rs`
wired with `#[path]`:

```rust
#[cfg(test)]
#[path = "magic_link_tests.rs"]
mod magic_link_tests;
```

Put shared test fixtures in a `test_support.rs` child module (`#[cfg(test)]`,
items `pub(super)`).

Entry files decode, delegate, and encode. Put business logic in named
modules.

## Naming

| Thing | Style |
| --- | --- |
| Rust symbols | `snake_case` |
| Types, enums, traits | `UpperCamelCase` |
| JSON fields | `snake_case` |
| Cookie names | lower `snake_case` |
| HTTP paths | `kebab-case` |
| CLI flags | `--kebab-case` |
| Environment variables | `SCREAMING_SNAKE_CASE` |
| Opaque IDs | `tag-<body>` |

Opaque IDs must not encode real-world facts.

## Public API shape

- Prefer owned domain types at crate boundaries.
- Use `&str` and `&[u8]` inside crates where helpful.
- Avoid lifetime-heavy public APIs without a clear payoff.
- Expose builders or config structs for required config.
- Add `#[non_exhaustive]` only when you reserve expansion space.
- Document security invariants on public types and functions.
- Gate serde support when core behavior does not require it.

## Features and dependencies

- Keep default features minimal.
- Avoid dependencies for tiny helpers.
- Put broad integration dependencies in adapter crates.
- Give each crypto, parsing, HTTP, AWS, or async dependency an owner crate.
  Record the reason for the dependency.

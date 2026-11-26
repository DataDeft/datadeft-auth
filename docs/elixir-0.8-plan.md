# Elixir 0.8 plan

Status: owner-approved in the planning conversation, including byte-for-byte
Rust parity and minimal additional Rust code. Crypto dependency selection and
any project-specific native runtime component were separately gated below.

Amendment approved by the owner in the implementation conversation: "approved,
keep it extremely small and lean". A crypto-only Rustler NIF is now authorized,
replacing the no-native/no-Rust-build requirement. Services and IO stay in Elixir;
no Port, native auth engine or solver. The exact initial boundary, six-question
justification, safety and build/release contract are recorded in
[`hex/datadeft_auth/CRYPTO-DEPENDENCIES.md`](../hex/datadeft_auth/CRYPTO-DEPENDENCIES.md).
This amendment supersedes the original no-NIF/no-Rust acceptance wording below;
precompiled consumers plus a working source-build fallback replace that gate.
Delivery: one PR, built in small tested commits. Do not publish from this work.

## Goal

A simple, functionally complete Elixir implementation with the same layering and
byte-for-byte compatibility as Rust 0.7.0. Rust and Elixir must work together in
one system: cookies, magic links, PoW challenges/proofs, keys and DynamoDB records
must be interchangeable. Preserve security behavior, not just successful flows.
No new token formats, storage shapes or compatibility fallbacks.

Implement shared DynamoDB data first: both servers must safely use the same table,
account identities, sessions, revocations, limits and rotation state. Broader
cross-language wire/crypto parity remains the target, but sharing application
code or introducing a native wrapper is not a prerequisite for this first step.
Measure what can be reused as implementation proceeds; do not build a generic
sharing layer.

## Repository layout (owner-approved)

- `crates/`: existing Rust libraries; keep their current locations.
- `hex/datadeft_auth/`: one publishable Elixir package, including `lib/`, `test/`,
  `mix.exs`, `mix.lock` and package-local tasks/configuration.
- `hex/examples/bandit_magic_link/`: independent Mix consumer example.
- `hex/`: all Elixir-specific code, tests, examples, scripts and documentation.
  No root Mix umbrella and no Elixir implementation under `packages/`.
- `packages/dd-protect-client/`: one browser client shared by both servers.
- `examples/axum-magic-link/`: existing Rust example.
- `spec/compatibility/`: language-neutral contract and shared synthetic vectors.
- Root configuration, `.github/`, `scripts/` and `docs/`: repository orchestration,
  release configuration and cross-language documentation. Elixir code stays in
  `hex/`; root tasks may invoke it.

Mirror the Rust layers under `hex/datadeft_auth/lib/datadeft_auth/`: `token/`,
`magic_link/core/`, `magic_link/service/`, `magic_link/plug/`, `pow/core/`,
`pow/plug/` and `aws/`. Keep tests similarly organized, with fakes in test support.
Create files as needed rather than prebuilding empty abstractions.

Use one Hex package, `datadeft_auth`, with separate Token, MagicLink.Core,
MagicLink.Service, MagicLink.Plug, AWS, PoW.Core and PoW.Plug namespaces.
Core functions receive time, entropy and loaded keys. Services use behaviours;
adapters own IO. Plug supplies HTTP integration; Bandit runs the example only.
No Phoenix, Port, worker-pool framework or optimization work. The approved
crypto-only Rustler exception is limited to the native-boundary contract above. If implementation establishes that reuse is
absolutely necessary, propose a tiny wrapper over the existing Rust libraries,
limited to the specific missing operation. Obtain owner approval of its API,
transport, build/deployment cost and safety implications before adding it. Never
copy Rust authentication logic into a new wrapper implementation.
Use OTP crypto where compatible. Do not claim deterministic secret zeroization
on BEAM.

## Feature justification

1. Problem: Elixir applications need authentication without a subprocess or Rust
   compiler on production hosts, while sharing a system with Rust applications.
2. Existing solution: Rust libraries and the former Elixir Port binding implement
   the workflows and formats; existing tests provide reference behavior.
3. Gap: the binding requires Rust and a transport process. A new incompatible
   format would prevent the required mixed-language deployment.
4. Smallest solution: one Elixir package mirroring the existing layers and exact
   formats, with shared compatibility vectors. Keeping the Port avoids a second
   implementation but retains the unwanted subprocess. The approved amendment
   reuses only crypto through a tiny NIF, retaining Elixir services and IO.
5. Cost: maintaining two security implementations, exact crypto/framing parity,
   AWS dependencies and mixed-language integration tests. No format migration or
   speculative performance work.
6. Proof: fixed-input byte comparisons, bidirectional verification, shared-table
   race tests, browser interoperability, clean precompiled consumers and native
   source-build fallback.

## Iterations (one PR)

1. **Freeze the contract.** Inventory Rust public workflows and exact wire/storage
   formats. Record a parity checklist covering auth, sessions, account lookup,
   admin, country/locale policy, rotation, limits and HTTP refusals. Create shared
   deterministic vectors from Rust using test-only entropy and clocks. Reuse the
   existing datadeft-auth libraries and test-support APIs as the reference; add
   only tiny test/vector glue where needed. Do not reimplement Rust auth logic,
   create a second Rust service, restore the Port, or add a general bridge layer.
2. **Prove shared-data compatibility first.** Implement the exact DynamoDB key
   derivation, attribute encoding and repository semantics needed for a small
   cross-language test against one DynamoDB Local table. Reuse existing Rust
   adapters; add only necessary test glue. Prove account identity and atomic
   writes before expanding to the full repository contract in iteration 6.
3. **Prove crypto parity.** Implement canonical Base62, exact Branca
   XChaCha20-Poly1305 framing, HKDF/HMAC and BLAKE3 compatibility. Use OTP crypto
   where compatible, and reuse existing Rust crypto through the approved tiny
   NIF. Assess native build requirements and maintain shared test vectors.
   Do not substitute AES-GCM or SHA-256 for existing algorithms. If a required
   primitive cannot reasonably be delivered without custom native code, stop for
   owner review rather than silently changing the scope or format.
4. **Implement pure cores.** Exact email normalization, identifiers, magic-link
   grammar/lookups, cookie bodies/keyrings and PoW mint/verify. Compare identical
   bytes with fixed inputs and accept each language's output in the other.
5. **Implement services.** Request, scanner-safe landing/confirmation, atomic
   consume/session creation, validation/refresh/logout, account lookup and audited
   administration. Inject repositories, limiters, delivery, clocks and entropy.
   Use a simple serialized in-memory adapter for tests/development only.
6. **Implement AWS.** Match DynamoDB keys, attributes, transactions, conditions,
   consistency, retention and rotation; add SES and Secrets Manager adapters.
   Test both implementations against the same DynamoDB Local table, including
   cross-language consume races, revocation, account uniqueness, key rotation and
   shared PoW lifetime budgets. Never assume exact bytes alone prove atomicity.
7. **Implement HTTP.** Small Plug helpers plus a Bandit example matching the Rust
   reference flow. Preserve cookies, same-origin/CSRF checks, headers, body bounds,
   generic refusals and existing browser PoW compatibility. Applications own routes,
   rendering, authorization and edge controls.
8. **Finish the single PR.** Remove dangling Port references in workspace tasks,
   CI, release checks and docs without disturbing unrelated staged changes. Check
   Hex archive and Mix release consumers, native source fallback and precompiled
   consumption without a Rust toolchain. Run `mise run verify`,
   mixed-language tests and an independent security review. Document any checks
   that could not run. Version 0.8 through the repository's release process.

## Done means

- With identical explicit inputs, deterministic encodings and cryptographic
  outputs match Rust byte for byte; production entropy remains fresh CSPRNG data.
- Rust-issued values work in Elixir and Elixir-issued values work in Rust.
- Both implementations safely share records, account identities, revocations,
  limits and rotation state during rolling deployment.
- Tamper, malformed input, expiry, replay, failure and concurrency tests pass.
- GET never consumes; confirmation creates at most one session; logout revokes
  before cookie clearing; storage/limiter failures fail closed.
- Rust is required for source builds and repository compatibility checks, not
  in a bundled runtime release. Precompiled consumers and source-build fallback
  must both pass clean-consumer tests before release.

## Implementation tracking

The itemized test-first checklist lives in
[`hex/datadeft_auth/IMPLEMENTATION.md`](../hex/datadeft_auth/IMPLEMENTATION.md).
Shared vectors and parity checks live in
[`spec/compatibility/`](../spec/compatibility/README.md).

## Decisions before implementation

- Scope and one-package namespace layout: approved by the owner.
- Rust 0.7.0 is the frozen reference; review any reference changes explicitly.
- Keep additional Rust limited to necessary compatibility-test glue over existing
  libraries. The later owner-approved exception permits only the tiny crypto NIF,
  not a second Rust authentication service.
- Approve crypto dependencies after iteration 3's investigation. Standard OTP
  native crypto is allowed. The crypto-only NIF decision is now approved as
  described above; broader native scope still requires a separate decision.

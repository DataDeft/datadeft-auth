# Proposal: Elixir bindings for datadeft-auth

**Status:** proposed; review required before implementation.
**Baseline:** current Rust API at 0.5.0; reconcile with the separately proposed
0.6.0 changes before implementation.
**Deliverable of this PR:** this plan only. No NIF, runtime dependency,
implementation, release, or publishing configuration is authorized by merging
this document alone. Explicit approval of the implementation scope is required.

## 1. Decision summary

Create an optional Hex package, provisionally named `datadeft_auth`, exposing
existing Rust functionality through Rustler NIFs. Do not port the crypto or
reimplement security policy in Elixir.

Recommended sequence:

1. A bounded, source-built binding to the three deterministic core crates.
2. A separately approved asynchronous bridge to the magic-link service traits.
3. Optional Plug/Phoenix integration after the service bridge passes its gates.
4. Precompiled binaries only after source-build packaging and release controls
   are proven.

Phase 1 is a **primitives binding**, not a complete Phoenix authentication
solution. A complete magic-link login requires phases 2 and 3. Do not advertise
feature parity until those phases are implemented and validated.

### Review decisions

- [ ] Approve Rustler rather than a Rust sidecar/port or an Elixir rewrite.
- [ ] Approve phase 1 as the first implementation scope.
- [ ] Confirm whether full magic-link orchestration is a required follow-up.
- [ ] Confirm package name/Hex ownership and supported Elixir/OTP versions.
- [ ] Approve source-build-only initial distribution.
- [ ] Approve the new adapter dependency graph and workspace/release changes.
- [ ] Decide whether Plug support ships separately or as an optional integration.
- [ ] Approve a documentation-only branch exception to the no-branches rule
      when opening this plan as a standalone draft PR.

## 2. Why reuse Rust, and what remains Elixir

```text
Phoenix / consuming Elixir application
  -> DatadeftAuth public Elixir modules
  -> private Rustler NIF adapter
       -> datadeft-auth-token-core
       -> datadeft-magic-link-core
       -> datadeft-pow-core
       -> datadeft-magic-link-service (phase 2 only)
```

Rust remains authoritative for parsing, canonical encodings, AEAD, HKDF, HMAC,
constant-time verification, freshness, and service state transitions. Elixir
owns supervision, application wiring, storage implementations, delivery,
HTTP/Plug integration, and deployment config. Routes, templates, redirects,
consent policy, trusted-edge interpretation, and business authorization remain
application responsibilities.

Do not depend on the Axum adapters. Do not pull AWS/Tokio into core crates.
Do not embed a Tokio runtime merely to execute phase 1 functions.

Alternatives:

| Approach | Benefit | Cost / reason not selected initially |
| --- | --- | --- |
| Rustler NIF | Direct reuse, small call overhead, resource-backed secrets | Native faults can terminate the VM; requires scheduler and release review |
| External Rust port/sidecar | Native crash isolation | Protocol, process lifecycle, deployment and IO overhead |
| Elixir implementation | No native toolchain | Duplicated crypto/protocol maintenance and security review |

If native safety or supported-target validation fails, stop and review the port
alternative rather than quietly switching architecture.

## 3. Proposed owned paths and dependencies

One implementation agent owns the new package, including its native crate.
Existing crates are read-only unless a separate public-API proposal is approved.
The orchestrator owns root tasks, CI, release tooling, and shared docs.

```text
packages/datadeft-auth-elixir/
  mix.exs
  mix.lock
  .formatter.exs
  .gitignore
  mise.toml
  README.md
  LICENSE
  lib/datadeft_auth.ex
  lib/datadeft_auth/{native,keys,email,token,magic_link,pow,error}.ex
  native/datadeft_auth_nif/
    Cargo.toml
    src/lib.rs
    src/{boundary,keys,email,token,magic_link,pow,error}.rs
  test/...
```

Names/layout are proposed, not promised public APIs. Keep modules small and
entry points limited to decode/delegate/encode. Rustler's established attributes,
derives and registration macros are permitted subject to review; do not author
application macros. No handwritten unsafe code is proposed. Rustler itself has
an FFI/unsafe boundary, so document that dependency's trust scope explicitly.

New allowed edges: `datadeft-auth-nif` -> the three core crates; optionally the
service crate after phase 2 approval. No reverse edges. This extends the current
approved graph and requires review before implementation.

Recommend a workspace member at `packages/datadeft-auth-elixir/native/datadeft_auth_nif`
with `publish = false`, inheriting workspace lint/version policy. Root Cargo
membership and all-member CI will need an Erlang/NIF build assessment first.
If that would force Erlang onto Rust-only consumers, propose a separately locked
native workspace instead; do not introduce an unverified second build graph.

Dependencies and owners:

- Elixir package: Rustler for native build/loading; no Phoenix requirement.
- Native adapter: Rustler, existing core crates, reviewed OS-backed entropy
  support compatible with the existing `rand_core` API.
- Optional Elixir integration: Plug, only after phase 3 approval.
- Test/docs tools: minimum necessary, pinned; review licenses and advisories.
- No Rust `test-support` feature or deterministic RNG in production builds.

## 4. Proposed phase 1 API

Use documented typespecs and `{:ok, value} | {:error, %DatadeftAuth.Error{}}` for
fallible calls, including malformed public arguments. Avoid bang functions in
the initial API. Error structs contain fixed codes, never offending input.
`Native` is private infrastructure, not a supported consumer API.

| Module / operation | Existing Rust behavior | Elixir result / constraints |
| --- | --- | --- |
| `Keys.load/1` | Root secrets, typed purpose keyrings and validity windows | Opaque, purpose-specific native handles; reject malformed/duplicate slots |
| `Email.normalize/1` | `NormalizedEmail::normalize` | Validated normalized address; trim then ASCII-lowercase the whole address |
| `MagicLink.generate/0` | `MagicLinkToken::generate` | Bearer token wrapper; selector and verifier generated independently |
| `MagicLink.parse/1` | Strict `MagicLinkToken::parse` | Opaque parsed handle; syntax validity is not authentication |
| `MagicLink.lookup_material/2` | Keyed selector lookup and verifier hash | Sensitive storage wrappers; no raw verifier fields |
| `Token.encrypt/4`, `Token.decrypt/4` | Branca encode/decode | Advanced low-level API; mandatory freshness policy in wrapper |
| `Pow.mint_challenge/3` | `mint_challenge` | Exact browser-compatible `{chg, dif, tim, tag}` fields |
| `Pow.verify_solution/3` | `verify_solution_with_clock_skew` | Opaque verified solve with safe accessors for timing/identity |
| `Pow.mint_proof/3`, `Pow.verify_proof/3` | Existing purpose-bound proof cookies | Bind proof to verified solve, use typed keyring and mandatory TTL/skew |

Arities are illustrative: finalize options/struct fields in the phase 1 API
review. Prefer config structs over long positional argument lists. Do not
expose arbitrary caller-defined key purposes or generic string-selected crypto
operations. Export raw bearer values only through explicitly named accessors
needed for delivery, cookie setting, or persistence boundaries.

`Token` is an advanced primitive, **not session authorization**. Raw Branca
decode authenticates bytes but does not check freshness. The public wrapper must
require `now_unix`, max age and skew, verify authenticated timestamps, and apply
bounds before returning plaintext. It does not supply revocation, country locks,
idle refresh, or server-side session checks. If this cannot be presented safely,
omit the generic token API from the first release in favor of typed cookies.

Proof minting takes a native verified-solve resource, not a caller-fabricated
map. Parsed and verified states must be distinct types. Stateless proof
verification is not admission: there must be no misleading `admit_proof`
function until a shared atomic lifetime-budget adapter is wired and tested.

Time units must be explicit: PoW uses `now_unix_ms`; tokens/key windows use
`now_unix` seconds. The application injects the clock; do not read environment
variables or silently use system time inside deterministic operations.

## 5. NIF boundary and BEAM safety

- Validate public argument type, byte size, integer range, collection count and
  option keys in Elixir; repeat security-relevant bounds in Rust because private
  NIF entry points are still callable. Check bounds before copying/allocating.
- Accept binaries, not arbitrary charlists/iolists. Validate UTF-8 only where
  required. Do not deserialize an arbitrary JSON/term blob to select operations.
- Reuse Rust caps. Examples: Branca payload <= 1024 bytes and token <= 1437
  bytes; magic-link and PoW limits come from their own current parsers. Maintain
  an explicit audited table where a Rust constant is not public.
- Initially schedule crypto/parsing on dirty CPU schedulers. Benchmark bounded
  normalization before allowing it on normal schedulers. Never solve PoW inside
  a NIF, perform network IO there, or block waiting for an Elixir callback.
- No production `unwrap`, `expect`, `panic!`, logging, or new unsafe code. Review
  Rustler panic behavior and build profile; panic catching is not protection
  from aborts, OOM, UB, or a native crash.
- Native resources own keys and verified states, with redacted Rust `Debug` and
  Elixir `Inspect`. Immutable resources avoid shared mutation and lock-order
  hazards; destructors must not block or perform IO.
- Do not create atoms from input. Use a finite compile-time set of error atoms;
  fixed string keys for protocol data when useful.
- Use native key handles after startup so keys are not repeatedly copied through
  BEAM heaps. Key imports and exported tokens still create BEAM binaries: GC is
  not guaranteed zeroization, and redacted `Inspect` does not stop tracing or
  crash dumps. Document operational controls and avoid secret-bearing exceptions.
- Handle NIF load/ABI errors explicitly. No silent pure-Elixir crypto fallback.
- Pin a supported NIF ABI. Test resource lifetime, concurrency, code upgrades
  and invalid resource types. Until upgrade compatibility is demonstrated,
  require rolling VM restarts for native upgrades; never serialize resources.

## 6. Security parity requirements

`docs/security.md` remains normative. The binding must not weaken these rules:

- OS CSPRNG at the adapter; independent selector/verifier draws; no production
  nonce injection. Fail closed on entropy failure.
- Purpose-separated keys/peppers, active versus verify-only windows, unknown-key
  rejection, rotation coverage and no key-byte accessor.
- Constant-time secret-derived comparisons remain in Rust. Elixir equality must
  never substitute for verifier/MAC verification.
- Strict canonical current token grammar; no legacy parser or compatibility
  fallback. No Gmail dot/plus folding or provider-specific email rules.
- Baseline TTLs: link 10m, confirm 5m, challenge 2m, proof 3h, session idle 24h,
  absolute 30d; cleanup grace 24h. Respect existing hard ceilings. Default clock
  skew 60s; optional stricter settings; maximum 300s where supported. A skew
  allowance never extends expiry or a key window.
- PoW difficulty configurable with production floor guidance 5–6 leading zero
  hex characters, benchmarked for supported browsers; test-only low difficulty
  must be explicit. Reject downgrade attempts and preserve exact wire fields.
- A solve can only buy its shared lifetime budget; no ETS/node-local production
  substitute, refill on rotation, or fail-open behavior.
- No credentials, addresses, cookie values, or token-bearing URLs in logs,
  telemetry metadata, exception messages, fixtures, snapshots or error returns.
  Use synthetic test data and deterministic vectors only in tests.
- Internal fixed reason labels are for trusted diagnostics, not HTTP responses.

## 7. Phase 2: service bridge (separate approval gate)

The service crate uses generic dependency traits returning `Send` futures, not
object-safe dynamic traits. Direct synchronous callbacks from a NIF into Elixir
are not an acceptable implementation. Do not rewrite the flow in Elixir just
to avoid this boundary.

Recommended spike: concrete Rust implementations of the existing traits send
bounded correlated requests to a supervised Elixir adapter process. A bounded
Rust worker/executor runs service futures outside NIF schedulers. Replies enter
through a short NIF and resolve pending operations. This is a proposal to prove,
not an assumption that existing Rustler APIs solve the lifecycle automatically.

Before committing to this bridge, demonstrate:

1. Each job has a unique correlation reference, authorized responder, immutable
   context, bounded deadline, monitored caller, and at most one accepted reply.
2. Queue depth, outstanding jobs and reply sizes are capped. Overload, owner
   death, worker restart, timeout and malformed replies fail closed.
3. NIF environments/borrowed terms never outlive a call; cross-thread data is
   owned and Rustler's supported thread/message facilities are used.
4. Cancellation cannot be interpreted as rollback. Once an atomic authentication
   commit is dispatched, a timeout may mean it committed. Preserve the identical
   command and attempt id for reconciliation; never regenerate entropy/replan
   while that result is ambiguous. A worker/process restart must not lose this
   obligation; prove a durable strategy or block production release.
5. Late, duplicate, stale and spoofed replies cannot complete another operation.
6. Shutdown drains or safely abandons jobs, with documented commit semantics.

Proposed Elixir behaviours mirror `MagicLinkRepository`,
`MagicLinkAuthenticationRepository`, `SessionRepository`, `RateLimiter`,
`MagicLinkOutbox`, and `Clock`. Callbacks carry validated typed values and bounded
results; never raw verifier secrets. The outbox necessarily receives the link
for delivery and must redact it. Storage adapters key IDs/email/limiter values
according to the existing HMAC policy.

Preserve the exact atomic repository contract: consume expected unexpired link,
validate immutable account linkage/consent, and create session in one transaction.
Confirmed conflicts may replan with a new attempt id; ambiguous dependency
outcomes may retry only the identical command/id. No read-modify-write consume.

Release the service bridge only with a shared transactional backend conformance
suite. Test fakes are not production storage. Selecting Ecto/Postgres, DynamoDB,
or another first-party backend requires its own ownership and security review;
no new production backend is implicitly included here.

Service API coverage: request, scanner-safe landing, optional flow-state read,
confirmation, session validation/refresh, logout/revocation. Country policy,
locale/consent handling and account masking must remain Rust-owned. Admin APIs
and 0.6 erasure are deferred until explicit scope approval, not silently dropped
from a claim of full parity.

## 8. Phase 3: optional Plug/Phoenix adapter

Keep it framework-neutral Plug, with a Phoenix example, not a generated router.
Use service operations from phase 2; no Axum reuse or policy port hidden in HTTP
helpers. Reproduce the normative response and cookie contracts:

- `GET` landing never consumes/creates sessions; keyed-selector throttle and
  dummy miss work. Same-origin confirmation `POST` binds selector, verifier
  proof, exact account, expiry and independent nonce.
- Identify the account (masked by default), HTML-escape it, prevent framing,
  use no-store/CSP/X-Frame-Options and `Referrer-Policy: strict-origin`.
- Fixed/same-origin/allowlisted clean redirects; no token in Location or JS.
- Host-only lower snake_case cookies; HttpOnly; Secure except explicit local
  dev; conservative SameSite; explicit TTL and paths (`/` for session).
- Revoke server state before clearing session cookie. Clear temporary cookies
  on success/terminal failure, preserve on dependency failure as required.
  Logout is CSRF-protected POST. PoW owns its independent cookie lifecycle.
- Generic 400 for non-sensitive shape failures, 401 with `DD-PoW`/`DD-Session`,
  one byte-identical no-store 503 for sensitive failures. Never library-generated
  403/500/429; preserve generic request/landing exceptions in the security spec.
- Same-origin flow-state fetch rules and cookie path coverage if redirect
  landing is included. No permissive CORS shortcut.

Add a complete fake-backed example and a production-readiness checklist. State
clearly that edge/IP/global controls and trusted country headers belong to apps.

## 9. Build, packaging and release

Proposed compatibility starting point: Elixir >= 1.16, OTP >= 26, Rust >= 1.88.
These are targets to validate against the selected Rustler version, not support
claims. Pin the tested Rustler version and NIF ABI; publish an exact CI matrix.
Start source-build testing with Linux x86_64 glibc and macOS arm64. Add Linux
arm64, musl and Windows only with native test coverage, not compilation alone.

Consumers should install a Hex dependency normally; local development uses a
path dependency. An unpublished git dependency must document the monorepo
package/subdirectory requirements and be tested in a clean consumer app.

Hex cannot rely on relative paths into the repository. The artifact must include
reviewed NIF source and resolve released Rust dependencies by exact compatible
versions, or bundle an approved self-contained source layout. Recommend version
plus local-path Cargo dependencies for development, with packaging that removes
repo-relative paths in a temporary staging tree and uses registry versions.
Prove it with an isolated unpacked Hex build outside the checkout. Never mutate
the working source tree or skip verification to package it.

Follow the repository's shared release version unless maintainers approve a
separate policy. Extend release-please, release checks, lockfiles and package
boundaries deliberately; the current tooling assumes seven publishable Rust
crates and one npm package. The NIF crate remains unpublished on crates.io.
Publish order: Rust crates first, then build/test the exact Hex artifact against
those released versions, then approved Hex upload. Do not add Hex publishing
credentials or enable uploads in this planning PR. Review the actual Hex auth
mechanism and least-privilege release process before enabling it.

Initial release builds from source and needs Rust, Erlang/Elixir, and platform
build tools. Future RustlerPrecompiled support requires an approved target/ABI
matrix, immutable tagged artifacts, checksums, provenance, dependency auditing,
source fallback tests and release authorization. Do not download unsigned or
unverified mutable binaries during installation.

## 10. Test plan and release gates

Phase 1:

- Rust unit and Elixir boundary tests, typespec/docs examples, round trips.
- Existing core golden vectors through the binding; Rust-minted values parsed
  in Elixir API and browser PoW vectors verified by Rust through the NIF.
- Synthetic malformed, tampered, noncanonical and trailing input; invalid UTF-8,
  overlong binaries/maps, integer overflow/negative values, wrong key/resource,
  unknown kid and expired/verify-only key behavior.
- Expiry/skew boundaries in explicit units; no TTL bypass on generic tokens.
- Independent draws, RNG failure handling, no production fixed-nonce entrypoint.
- Attempted forged verified-solve handles cannot mint proof cookies.
- Redacted Inspect/Debug/errors and telemetry; finite atom count under fuzzed
  input. No secret-bearing assertion failures in shared CI output.
- Parallel calls, resource GC, NIF loading, supported OTP/OS matrix, release mode,
  representative scheduler latency and bounded-memory measurements under load.
- Unpacked Hex archive tests outside repo; clean consuming Mix app; archive
  allowlist, dependency/license audit, build without core test-support features.

Phases 2–3 add:

- Request/landing/confirm/session/logout end-to-end tests against trait fakes and
  shared transactional backend conformance tests.
- Concurrent confirm: exactly one session; ambiguous commit identical retry;
  conflict/replan; stale replies; owner/worker crash; queue overflow and shutdown.
- Multi-node lifetime PoW budget, expiry, exhausted proof replay, rotation and
  unavailable budget storage; never node-local admission.
- Account-disable/revocation, idle/absolute lifetime, refresh and country policy.
- Uniform HTTP body/header tests; scanner safety, origin/CSRF/frame protection,
  redirect scrubbing, account escaping, cookie creation/clearing/preservation.

Task integration proposed for implementation: package-level `fmt`, `fmt-check`,
`check`, `test`, `docs`, `package-check`, `verify`; root `elixir-verify` included in
`mise run verify` only after toolchain provisioning is reviewed. Use mise tasks
rather than duplicate command pipelines. Run full `mise run verify` before
calling implementation complete; existing Rust/TS/formal checks must still pass.

## 11. Work packets and sequencing

| Packet | Owned changes | Exit gate |
| --- | --- | --- |
| P0: approve design | This plan only | Reviewer decisions recorded; no implementation yet |
| P1: packaging spike | New package/native scaffold; orchestrator root wiring | NIF loads; isolated source package builds; ABI matrix selected |
| P2: core binding | Package API, resources, errors, core delegation | All phase 1 vectors/tamper/resource/scheduler tests pass |
| P3: phase 1 release readiness | Docs, tasks, release metadata and artifact checks | Security/API review plus full verify; explicit release approval |
| P4: async bridge spike | Approved service bridge, test behaviours | Correlation, lifecycle and ambiguous-commit durability proven |
| P5: service integration | Bridge APIs and backend conformance | One-time concurrent consume and revocable sessions proven |
| P6: optional HTTP integration | Approved Plug package/example | Full security-contract integration tests pass |
| P7: precompiled distribution | Separate release infrastructure change | Native target, provenance and recovery review |

P1 must settle Cargo/Hex packaging before P2 expands the API. P4 cannot be
reported as complete authentication support. Each packet returns changed paths,
public API deltas, security behavior, tests, validation run/not run, open
questions and follow-up work. Cross-crate API needs are proposals, not drive-by
edits. No implementation starts until explicit scope approval after plan review.

## 12. Risks and remaining questions

| Risk | Mitigation / blocking decision |
| --- | --- |
| Native fault terminates VM | Small audited boundary, no new unsafe, malformed-input tests; reconsider port if unacceptable |
| Dirty scheduler saturation | Strict caps, application admission/edge limits, latency/load measurements |
| Secrets copied on BEAM heap | Opaque key resources, redacted wrappers, explicit export points and operational guidance |
| Async callback lifecycle/ambiguous commits | Phase 2 proof and durable reconciliation gate before production |
| Hex archive depends on monorepo | Isolated artifact build gate before first release |
| Release tooling assumes existing package count | Orchestrator-reviewed changes; no new automatic uploads initially |
| 0.6 API changes while binding is designed | Pin/reconcile baseline; no obsolete compatibility API |

Open review questions:

1. Is the first goal core functionality, or a complete Phoenix login integration?
2. Are source builds acceptable for the first release, and which deployment
   targets/OTP versions are actually required?
3. Is same-VM native crash risk acceptable, or is a port required?
4. Should advanced generic Branca tokens be public, or only typed cookies?
5. Which first-party transactional backend should phase 2 target, if any?
6. Should admin/erasure parity be required before calling the binding complete?
7. Should this ship with 0.6 or follow independently after that Rust API settles?
8. Who owns the Hex name and approves the eventual publishing setup?

## 13. Planning PR validation and scope

Only this Markdown proposal changes. No public API, security behavior, package
version, dependencies or runtime code change. Review source references and
Markdown structure; run repository verification where available and record its
actual outcome in the handoff. Implementation-specific tests are deliberately
not present in this PR. Approval of this design is not approval to publish a
package or enable CI credentials.

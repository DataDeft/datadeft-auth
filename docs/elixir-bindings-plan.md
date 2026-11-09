# Proposal: Elixir bindings for datadeft-auth

**Status:** proposed; no implementation until explicit scope approval.
**Baseline:** Rust 0.5.0; reconcile with the proposed 0.6.0 API before starting.
**This PR:** documentation only. No runtime, API, dependency, version, or security
behavior changes; design approval does not authorize publication or credentials.

## 1. Recommendation and review decisions

Create an optional Hex package, provisionally `datadeft_auth`, that calls the
existing Rust implementation through Rustler NIFs. Do not port the crypto or
security policy to Elixir.

**Confirmed scope:** lowest-level, framework-independent bindings first. The
library requires neither Plug nor Phoenix; Phoenix is an example consumer only.

Deliver in separately approved phases:

1. **Core primitives:** bounded, source-built bindings to the three core crates.
2. **Magic-link service:** a framework-neutral asynchronous bridge to Rust traits.
3. **Example:** a Phoenix consumer showing application-owned HTTP integration.
4. **Precompiled binaries:** only after source packaging/release controls work.

Phase 1 is not a complete authentication solution. Full magic-link login needs
the service bridge plus application-owned storage, delivery and HTTP wiring—not
Phoenix. Do not claim parity while service/admin features are missing. Reusable
Plug helpers are deferred and require a separate proposal.

Reviewer decisions:

- [ ] Accept same-VM native crash risk and Rustler, rather than a port/sidecar.
- [x] Start with low-level, framework-independent bindings; Phoenix only an example.
- [ ] Confirm whether full login and admin/erasure parity are required follow-ups.
- [ ] Decide whether generic Branca tokens should be public or only typed cookies.
- [ ] Confirm Hex name/ownership, source-build acceptance, and required OS/OTP targets.
- [ ] Approve the dependency graph, workspace strategy, and shared release version;
      decide whether to ship with or after 0.6.0.
- [ ] Select a transactional backend for phase 2, if any.

## 2. Architecture and ownership

```text
Any Elixir application (Phoenix optional)
  -> DatadeftAuth public API
  -> private Rustler NIF adapter
       -> datadeft-auth-token-core
       -> datadeft-magic-link-core
       -> datadeft-pow-core
       -> datadeft-magic-link-service (phase 2)
```

Rust owns canonical parsing, AEAD, HKDF/HMAC, constant-time verification,
freshness and service state transitions. Elixir owns supervision, storage and
email adapters, HTTP wiring and deployment config. Routes, templates, redirects,
consent policy, business authorization and trusted-edge interpretation remain
application responsibilities. Do not depend on Axum, add AWS/Tokio to core
crates, or embed an async runtime for phase 1.

Rustler offers direct reuse, low call overhead and resource-backed secrets, but
native faults can terminate the VM. A port/sidecar offers crash isolation at the
cost of a protocol, lifecycle management and deployment/IO overhead. An Elixir
rewrite removes native tooling but duplicates security maintenance. If NIF
safety or target validation fails, review the port alternative before proceeding.

### Package and dependencies

One agent owns `packages/datadeft-auth-elixir/`, including its native crate:

- Mix metadata/lockfile, formatter, mise tasks, README and license.
- `lib/datadeft_auth.ex` and `{native,keys,email,token,magic_link,pow,error}` modules.
- `native/datadeft_auth_nif/` with Cargo metadata and corresponding Rust modules.
- Rust tests, ExUnit boundary tests and package/consumer checks.

Keep entry points decode/delegate/encode and modules small. Existing crates are
read-only; public API changes need a separate proposal. The orchestrator owns
root CI/tasks, release tooling and shared docs.

Approve new edges from `datadeft-auth-nif` to the three cores and, in phase 2,
the service crate; no reverse edges. Recommend a workspace member with
`publish = false`, inheriting lint/version policy. First assess whether workspace
CI would require Erlang for Rust-only builds; if so, propose a separately locked
native workspace and verify both build graphs.

Dependencies: Rustler for build/loading and FFI; existing cores; reviewed
OS-backed entropy compatible with their `rand_core` API. Phoenix/Plug dependencies
belong only to the separately packaged example. Pin and audit dependencies/test tools. No production core `test-support` feature
or deterministic RNG. Use established Rustler attributes/derives/registration
macros, not custom application macros. Document Rustler's unsafe FFI trust scope;
no handwritten unsafe code is proposed.

## 3. Phase 1 API

Provide typespecs and `{:ok, value} | {:error, %DatadeftAuth.Error{}}`, including
malformed arguments. Use fixed error codes without offending input; no initial
bang API. `Native` is private infrastructure. Names/arities below are proposals;
finalize config structs and options in API review.

| Operation | Rust delegation / public contract |
| --- | --- |
| `Keys.load/1` | Purpose-specific opaque keyrings; validate slots, IDs and validity windows |
| `Email.normalize/1` | `NormalizedEmail::normalize`: trim, then ASCII-lowercase the whole address |
| `MagicLink.generate/0` | `MagicLinkToken::generate`; independent selector/verifier draws |
| `MagicLink.parse/1` | Strict parser; opaque parsed handle, not proof of authentication |
| `MagicLink.lookup_material/2` | Keyed selector lookup/verifier hash; sensitive storage wrappers, no raw verifier fields |
| `Token.encrypt/4`, `Token.decrypt/4` | Branca primitives with mandatory freshness policy in the wrapper |
| `Pow.mint_challenge/3` | Exact browser-compatible `{chg, dif, tim, tag}` fields |
| `Pow.verify_solution/3` | Existing skew-aware verifier; opaque verified solve, timing/identity accessors |
| `Pow.mint_proof/3`, `Pow.verify_proof/3` | Purpose-bound cookies; typed keyrings, mandatory TTL/skew, bind to verified solve |

Do not expose arbitrary key purposes or string-selected crypto dispatch. Export
bearer values only through explicit accessors needed for delivery/cookies/storage.
Parsed and verified resources are distinct: proof minting must accept a native
verified solve, never a fabricated map.

**Token decryption is not session authorization.** Raw Branca decode checks
integrity, not time. Require injected `now_unix`, max age and skew; validate
bounds/authenticated timestamps before returning plaintext. It supplies no
revocation, country locks, idle refresh or server-side checks. Omit generic
Branca from the first release if this distinction cannot be made safe.

**Proof verification is not admission.** Do not expose `admit_proof` until a
shared atomic lifetime-budget adapter is wired and tested.

Use explicit units: PoW `now_unix_ms`; token/key-window `now_unix` seconds.
Inject the clock; no environment reads or implicit system time in deterministic
operations. Adapter-owned entropy comes from an OS CSPRNG, not caller nonces.

## 4. NIF and security invariants

`docs/security.md` is normative; this binding adds no weaker interpretation.

### BEAM boundary

- Validate types, sizes, integer ranges, collection counts and option keys in
  Elixir and repeat security bounds in Rust, before copying/allocating. Accept
  binaries, not arbitrary iolists; validate UTF-8 where needed. No generic
  JSON/term-driven operation dispatch.
- Reuse parser caps: Branca payload <= 1024 bytes, token <= 1437 bytes; audit
  magic-link/PoW caps against current Rust parsers, recording non-public limits.
- Start crypto/parsing on dirty CPU schedulers; benchmark normalization before
  using normal schedulers. Never solve PoW, perform network IO, or wait for an
  Elixir callback in a NIF.
- No production `unwrap`, `expect`, `panic!`, logging or new unsafe code. Review
  Rustler panic/build behavior; catching panics cannot contain aborts, OOM or UB.
- Immutable native resources own keys/verified states; redact Rust `Debug` and
  Elixir `Inspect`. Destructors must not block or do IO. Never serialize handles.
- No input-derived atoms: use finite error atoms and fixed protocol keys.
- Key handles reduce BEAM copies but cannot erase imported/exported binaries.
  GC does not guarantee zeroization; Inspect redaction does not stop tracing or
  crash dumps. Document operational controls and avoid secret-bearing exceptions.
- Pin Rustler/NIF ABI and handle load errors explicitly, without crypto fallback.
  Require rolling VM restarts until resource/code-upgrade safety is demonstrated.

### Protocol parity

- Independent CSPRNG draws, fail-closed entropy errors, no production nonce
  injection. Purpose-separated keys/peppers, active/verify-only windows, unknown
  key rejection, rotation coverage and no key-byte accessor.
- Secret-derived comparisons stay constant-time in Rust, never Elixir equality.
  Accept only canonical current formats; no legacy fallback or email alias rules.
- TTL baseline: link 10m, confirm 5m, challenge 2m, proof 3h, session idle 24h,
  absolute 30d; cleanup grace 24h. Preserve hard ceilings. Skew defaults to 60s,
  configurable up to 300s where supported; never extends expiry/key validity.
- Configurable PoW difficulty with production guidance of 5–6 leading zero hex
  characters, benchmarked in browsers; explicit test-only low values. Preserve
  wire fields and downgrade protection. Shared lifetime budgets never refill on
  rotation or fail open; no ETS/node-local production substitute.
- No keys, addresses, cookies, token URLs or identifiers in logs, telemetry,
  exceptions, snapshots or public errors. Fixtures use synthetic data and
  test-only vectors. Internal fixed reason labels stay out of HTTP responses.

## 5. Phase 2: asynchronous service bridge

Existing service traits are generic and return `Send` futures, not object-safe
trait objects. Do not synchronously call Elixir from a NIF or rewrite the flow
in Elixir to bypass this constraint.

Spike concrete Rust trait adapters that send bounded, correlated requests to a
supervised Elixir process. A bounded worker/executor runs service futures outside
NIF schedulers; short reply NIFs resolve pending work. Prove this lifecycle before
committing to it:

1. Unique correlation references, authorized responders, immutable context,
   deadlines, monitored callers and at most one accepted reply.
2. Bounded queues/jobs/replies; fail closed on overload, death, restart, timeout
   or malformed replies. Late, duplicate, stale and spoofed replies cannot
   complete another operation; shutdown has explicit drain/abandon semantics.
3. Owned cross-thread data and supported Rustler messaging; no borrowed terms or
   NIF environments surviving their call.
4. **Timeout is not rollback.** After dispatching an atomic commit, preserve the
   identical command/attempt ID for reconciliation. Do not regenerate entropy
   or replan while its outcome is ambiguous. Prove durable recovery across
   worker/process restarts or block production release.

Elixir behaviours mirror `MagicLinkRepository`,
`MagicLinkAuthenticationRepository`, `SessionRepository`, `RateLimiter`,
`MagicLinkOutbox` and `Clock`. Use validated typed values/bounded replies, never
raw verifiers. The outbox must receive—and redact—the delivery link. Storage
adapters apply existing HMAC keying to IDs, email and limiter values.

Preserve the atomic repository contract: consume the expected unexpired link,
validate immutable account linkage/consent, and create the session in one
transaction. Confirmed conflicts may replan with a new attempt ID; ambiguous
outcomes permit only identical-command/ID retries. No read-modify-write consume.

Require shared transactional-backend conformance tests. Fakes are not production
storage; Ecto/Postgres, DynamoDB or another first-party backend needs separate
ownership/security review and is not implicitly included.

Cover request, scanner-safe landing, optional flow-state read, confirmation,
session validation/refresh and logout/revocation. Rust retains country policy,
locale/consent handling and account masking. Admin and 0.6 erasure need explicit
scope approval before claiming full parity.

## 6. Phase 3: Phoenix example only

Provide a separately packaged, fake-backed Phoenix example—not a library framework
dependency or generated router. It demonstrates application-owned HTTP wiring to
phase 2; other stacks can wire the same APIs. The example must preserve the
normative HTTP contract:

- Landing `GET` never consumes/creates sessions; keyed-selector throttle and
  dummy miss work. Same-origin confirmation `POST` binds selector, verifier
  proof, exact account, expiry and independent nonce.
- Mask account by default, HTML-escape it, prevent framing, and set no-store,
  CSP/X-Frame-Options and `Referrer-Policy: strict-origin`. Redirect only to
  clean fixed/same-origin/allowlisted URLs; no token in Location or JavaScript.
- Host-only lower snake_case cookies, HttpOnly, Secure except explicit local
  dev, conservative SameSite, explicit TTL/path (`/` for session). Revoke before
  clearing session; clear temporary state on success/terminal failure, preserve
  on dependency failure as specified. Logout is CSRF-protected POST; PoW owns
  its own cookie lifecycle.
- Generic 400 shape errors, 401 with `DD-PoW`/`DD-Session`, byte-identical
  no-store 503 for sensitive failures; never library-generated 403/500/429.
  Preserve generic request/landing exceptions from the security spec.
- If redirect landing is included, enforce same-origin flow-state fetch rules
  and cookie-path coverage; no permissive CORS shortcut.

Document production readiness, app-owned IP/global/edge controls and trusted
country headers.

## 7. Packaging, compatibility and release

Proposed starting targets: Elixir >= 1.16, OTP >= 26, Rust >= 1.88; Linux x86_64
glibc and macOS arm64. Validate against pinned Rustler/NIF ABI before claiming
support. Add Linux arm64, musl or Windows only with native execution tests, not
cross-compilation alone.

Use Hex dependencies for consumers and local paths for development. Test any
unpublished monorepo git/subdirectory installation in a clean consumer app.

**Hex must build outside this repository.** Include reviewed NIF source and
resolve exact compatible released Rust versions, or approve a self-contained
source bundle. Recommend version-plus-path Cargo dependencies in development,
removing repo-relative paths in a temporary packaging tree for registry builds.
Verify the unpacked archive in isolation; never mutate working source or skip
verification to package it.

Keep the shared release version unless maintainers choose otherwise. Update
release-please, lockfiles, archive boundaries and checks that currently assume
seven Rust crates/one npm package; keep the NIF crate unpublished on crates.io.
Release Rust first, build/test the exact Hex artifact against those versions,
then approve Hex publication. Review Hex authentication/least privilege separately;
this plan does not enable uploads or credentials.

Initial source installs require Rust, Erlang/Elixir and platform build tools.
Future RustlerPrecompiled support needs an approved target/ABI matrix, immutable
tagged artifacts, checksums/provenance, audits, source-fallback tests and release
approval. No unsigned or unverified mutable install-time downloads.

## 8. Validation

| Area | Required coverage |
| --- | --- |
| Core delegation | Rust units, ExUnit boundaries, typespec/docs examples, round trips, existing golden vectors and browser PoW interoperability |
| Hostile input | Tamper/noncanonical/trailing input, UTF-8, oversized binaries/maps, negative/overflow integers, wrong resources/keys, unknown kid |
| Security | Expiry/skew units/boundaries, active/verify-only rotation, RNG failure/independent draws, no fixed-nonce production API, forged solve rejection |
| BEAM safety | Redacted errors/Inspect/Debug/telemetry, fuzzed finite atom count, concurrency/GC, NIF load/upgrade behavior, OTP/OS/release builds, scheduler latency and bounded memory under load |
| Distribution | Unpacked Hex outside repo, clean Mix consumer, archive allowlist, license/advisory audit, no core test-support in production |
| Service bridge | End-to-end flows, backend conformance, concurrent confirm creates exactly one session, identical ambiguous retries, conflict/replan, spoofed/stale replies, death/restart/overload/shutdown |
| Session/admission | Revocation/disable, idle/absolute expiry and refresh, country policy; multi-node proof budgets, replay, expiry, rotation and storage failure |
| HTTP | Uniform bodies/headers, scanner safety, origin/CSRF/frame defenses, escaped accounts, scrubbed redirects and cookie lifecycle |

Tests must not leak secrets through assertion output. Add package mise tasks
`fmt`, `fmt-check`, `check`, `test`, `docs`, `package-check`, `verify`; integrate
root `elixir-verify` after toolchain provisioning review. Run full
`mise run verify` before completion; existing Rust/TS/formal checks must pass.

## 9. Implementation gates and handoff

| Packet | Deliverable | Exit gate |
| --- | --- | --- |
| P0 | Plan review only | Explicit implementation scope approval |
| P1 | Package/native scaffold and orchestrator root wiring | NIF loads, isolated Hex source build, workspace/ABI matrix settled |
| P2 | Core API/resources/errors | Phase 1 vectors, tamper, resource and scheduler tests |
| P3 | Phase 1 docs/tasks/release metadata | Security/API review, full verify, separate release approval |
| P4 | Async bridge spike | Correlation/lifecycle and durable ambiguous-commit recovery proven |
| P5 | Service integration/backend conformance | Concurrent one-time consume and revocable sessions proven |
| P6 | Standalone Phoenix example | Full HTTP security-contract tests; no framework dependencies in the library |
| P7 | Precompiled distribution | Target/provenance/recovery review |

Resolve packaging before expanding the API. Do not report the async spike as
complete authentication. Each packet reports paths/API changes, security behavior,
tests, validation run/not run, open questions and follow-ups. Cross-crate changes
remain proposals; no implementation or publishing starts on implicit approval.

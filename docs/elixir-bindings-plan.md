# Proposal: Elixir bindings for datadeft-auth

**Status:** proposed; no implementation until explicit scope approval.
**Baseline:** Rust 0.5.0; reconcile with the proposed 0.6.0 API before starting.
**This PR:** documentation only. No runtime, API, dependency, version, or security
behavior changes; design approval does not authorize publication or credentials.

## 1. Recommendation and review decisions

Create an optional Hex package, provisionally `datadeft_auth`, that calls the
existing Rust implementation through a supervised Rust executable over an Erlang
Port. No Rust code is loaded into BEAM; do not port crypto/security policy to Elixir.

**Confirmed scope:** high-level authentication operations first, without framework
dependencies. The library requires neither Plug nor Phoenix; Phoenix is an example
consumer only. "Framework-independent" does not mean a public crypto toolkit.
Use a separate Rust process for native crash isolation. Support ARM64 and x86
(assumed x86_64/AMD64; confirm whether 32-bit x86 is needed).

Deliver the first usable release as high-level magic-link and session workflows,
backed by the Rust service and application-supplied storage, delivery and limits.
The Port/async bridge is required infrastructure, not a later optional feature.
Include independent high-level PoW operations; callers never assemble crypto steps.

Build in gated packets (section 9), then add a Phoenix example and, separately,
prebuilt executables. No primitives-only initial release. Generic Branca, raw
selector/verifier generation and HMAC helpers stay internal. Admin/erasure parity
and reusable Plug helpers require separate scope approval.

Reviewer decisions:

- [x] Use a separate Rust process, not Rustler/NIFs, to isolate native crashes.
- [x] Start with high-level workflows, framework-independent; Phoenix only an example.
- [x] Admin operations and account erasure are not required for the first release;
      defer them to separately approved follow-up work.
- [ ] Confirm Hex name/ownership, source-build acceptance, and required OS/OTP targets.
- [ ] Approve the dependency graph, workspace strategy, and shared release version;
      decide whether to ship with or after 0.6.0.
- [ ] Select the first production transactional backend or confirm a behaviours-only
      release with a fake-backed example and explicit production-adapter requirements.

## 2. Architecture and ownership

```text
Any Elixir application (Phoenix optional)
  -> DatadeftAuth public API
  -> supervised Port owner
  <-> framed stdin/stdout protocol
  <-> Rust executable
       -> datadeft-auth-token-core
       -> datadeft-magic-link-core
       -> datadeft-pow-core
       -> datadeft-magic-link-service
```

Rust owns canonical parsing, AEAD, HKDF/HMAC, constant-time verification,
freshness and service state transitions. Elixir owns supervision, storage and
email adapters, HTTP wiring and deployment config. Routes, templates, redirects,
consent policy, business authorization and trusted-edge interpretation remain
application responsibilities. Do not depend on Axum, add AWS/Tokio to core
crates. The Port adapter owns the executor needed for service futures.

The Rust process can crash without terminating BEAM. Supervision restarts it,
but pending calls fail and process-local handles become invalid. This costs
serialization and process lifecycle management compared with a NIF; it still
reuses the Rust code. Process separation is crash containment, not a sandbox or
a guarantee against system-wide resource exhaustion. No network listener or
independently deployed service is required.

### Package and dependencies

One agent owns `packages/datadeft-auth-elixir/`, including its native crate:

- Mix metadata/lockfile, formatter, mise tasks, README and license.
- `lib/datadeft_auth.ex`, public config/auth/PoW/error types and behaviours;
  private Port/protocol/key/token plumbing.
- `native/datadeft_auth_port/` with Cargo metadata, executable and Rust modules.
- Rust tests, ExUnit boundary tests and package/consumer checks.

Keep entry points decode/delegate/encode and modules small. Existing crates are
read-only; public API changes need a separate proposal. The orchestrator owns
root CI/tasks, release tooling and shared docs.

Approve new edges from `datadeft-auth-port` to the three cores and the service
crate; no reverse edges. Recommend a workspace member with
`publish = false`, inheriting lint/version policy. Rust-only builds need no Erlang;
Mix integration tests do.

Dependencies: existing cores/service, an adapter-owned async executor, reviewed
OS-backed entropy compatible with their `rand_core` API, and small audited
protocol codecs (proposed JSON with serde on
Rust and a reviewed Elixir codec). No Rustler/FFI dependency. Phoenix/Plug belong
only to the example. Pin/audit tools and dependencies; no production core
`test-support`, deterministic RNG, custom application macros or new unsafe code.

## 3. First-release API: authentication, not crypto

Provide typespecs and `{:ok, value} | {:error, %DatadeftAuth.Error{}}`, including
malformed arguments. Fixed error codes contain no offending input; no initial
bang API. Port/protocol/key/token internals are private. Names below illustrate
workflows, not finalized arities; use validated config and command structs.

| Operation | Consumer-facing contract |
| --- | --- |
| Start/configure supervised client | Supply adapters, secret loader and policy; validate key purposes/windows internally; ready only after worker initialization |
| `Auth.request_magic_link` | Normalize/validate email, enforce consent and keyed limits, persist challenge and enqueue delivery; generic public accepted response |
| `Auth.begin_confirmation` | Scanner-safe landing: validate/throttle link and prepare short-lived bound flow state/account display, without consuming or creating a session |
| `Auth.read_confirmation` | Read usable flow state where needed, preserving selector limits and generic failure behavior |
| `Auth.confirm_login` | Verify bound confirmation, atomically consume link/create session and return session value plus temporary-state action |
| `Auth.validate_session` | Check authenticated lifetime, server state, owner activity and country policy; return validated identity, not just decrypted bytes |
| `Auth.refresh_session` | Refresh only after validation, preserve original identity/absolute expiry and use active keys |
| `Auth.logout` | Revoke server-side session before returning a session-clear action |
| `Pow.create_challenge` | Browser-compatible challenge from configured difficulty/time and OS entropy |
| `Pow.complete_challenge` | Verify submitted solution and mint its bound proof; no caller-constructed verified state |
| `Pow.admit_proof` | Verify proof and spend shared atomic lifetime budget; deny exhausted/invalid proofs and fail closed on storage faults |

The application wires HTTP and applies explicit cookie/temporary-state actions;
operations do not require a Plug connection. Confirmation account display and
flow values follow Rust policy; raw emailed tokens must not reach rendered pages
or JavaScript. Errors/outcomes distinguish internal diagnostics from generic
public responses. Supply a concise end-to-end example of these operations.

Generic Branca encrypt/decrypt, raw token-part generation, standalone HMAC and
caller-defined crypto purposes are out of the initial public API. Verification
is never authorization by decryption alone. PoW admission remains independent
of magic-link operations and requires the shared budget behaviour, not a local
counter. Reuse core verification/minting; keep any new admission glue adapter-owned
and test against the existing contract.

Inject a clock dependency in client config, not timestamps on every public call;
Rust remains deterministic. Protocol time fields use explicit units: PoW
`now_unix_ms`, token/key windows `now_unix` seconds. Entropy is OS-backed inside
the adapter; callers do not supply nonces.

## 4. Process boundary and security invariants

`docs/security.md` is normative; this binding adds no weaker interpretation.

### Port protocol and lifecycle

- Launch a trusted absolute executable path with `Port.open({:spawn_executable,
  path}, ...)`, not a shell. Elixir supervision owns startup, exit monitoring,
  restart backoff, shutdown and OS-child cleanup. Prove no orphan remains after
  owner/VM death. Use stdin/stdout only; never merge stderr into protocol output.
- Propose length-prefixed frames (`{:packet, 4}`) with versioned JSON envelopes:
  protocol version, request ID, fixed operation and typed payload/result. Encode
  arbitrary bytes as canonical base64; validate integer ranges exactly. Reject
  unsupported versions, duplicate/unknown fields and malformed frames. No
  arbitrary term deserialization, executable names or input-derived atoms.
- Handshake protocol/build versions before accepting calls; no silent fallback.
  Validate frame sizes before Rust allocation and bound decoder depth, strings,
  collections and operation inputs on both sides. Assess BEAM Port receive-buffer
  limits too; an application-level check after receipt is not an allocation cap.
- One worker initially, with bounded in-flight calls, queues, frames and output;
  handle backpressure without blocking the Port owner indefinitely. Give each
  call a deadline and unique ID; route at most one reply. Drop late replies and
  distinguish application errors from transport failure. Never auto-replay a
  failed call, especially a mutation. A caller timeout does not cancel execution.
- Rust owns typed key/parsed/verified objects in a capped handle table. Handles
  are opaque, unguessable and scoped to a worker generation; reject stale,
  wrong-type or cross-worker handles. Define expiry/explicit release and caller
  cleanup; BEAM GC cannot free remote objects. Restart invalidates all handles.
- On worker exit, fail pending calls once. Reload keys through an explicit
  application-supplied initialization callback before marking the replacement
  ready; never persist secret handles or use environment/argv for key transport.
- Validate operation types/ranges before copying. Reuse Rust caps: Branca payload
  <= 1024 bytes, token <= 1437 bytes; audit magic-link/PoW parser caps. No PoW
  solving or unrelated IO in the core worker; no production unwrap/expect/panic,
  secret logging or new unsafe code.
- Redact Rust Debug and Elixir Inspect/errors. Key handles reduce repeated
  transport but initial keys/exported values still exist in pipe buffers and
  BEAM binaries; GC is not guaranteed zeroization. Document tracing/core-dump
  controls. Do not log protocol frames, raw stderr or child crash payloads.

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

## 5. Required infrastructure: asynchronous service bridge

Existing service traits are generic and return `Send` futures, not object-safe
trait objects. Keep orchestration in Rust: concrete trait adapters exchange
bounded callback request/reply frames with supervised Elixir adapters over the
same Port. A Rust executor drives futures while the protocol loop continues
processing replies; do not block that loop waiting on callbacks. Keep this
runtime in the adapter, not core/service crates. Prove:

1. Unique correlation references, authorized responders, immutable context,
   deadlines, monitored callers and at most one accepted reply.
2. Bounded queues/jobs/replies; fail closed on overload, death, restart, timeout
   or malformed replies. Late, duplicate, stale and spoofed replies cannot
   complete another operation; shutdown has explicit drain/abandon semantics.
3. Separate operation/callback IDs and owned data; concurrent protocol IO cannot
   deadlock an operation awaiting an Elixir storage/email reply.
4. **Timeout is not rollback.** After dispatching an atomic commit, preserve the
   identical command/attempt ID for reconciliation. Do not regenerate entropy
   or replan while its outcome is ambiguous. Prove durable recovery across
   worker/process restarts or block production release.

Elixir behaviours mirror `MagicLinkRepository`,
`MagicLinkAuthenticationRepository`, `SessionRepository`, `RateLimiter`,
`MagicLinkOutbox` and `Clock`; a proof-budget behaviour mirrors `ProofBudget`
for independent PoW admission. Use validated typed values/bounded replies, never
raw verifiers. The outbox must receive—and redact—the delivery link. Storage
adapters apply existing HMAC keying to IDs, email and limiter values.

Preserve the atomic repository contract: consume the expected unexpired link,
validate immutable account linkage/consent, and create the session in one
transaction. Confirmed conflicts may replan with a new attempt ID; ambiguous
outcomes permit only identical-command/ID retries. No read-modify-write consume.

Require shared transactional-backend conformance tests. Fakes are not production
storage; Ecto/Postgres, DynamoDB or another first-party backend needs separate
ownership/security review and is not implicitly included.

These behaviours are required for the first high-level release, not deferred
until after a primitives release. Rust retains country policy,
locale/consent handling and account masking. Admin and 0.6 erasure need explicit
scope approval before claiming full parity.

## 6. Phoenix example only

Provide a separately packaged, fake-backed Phoenix example—not a library framework
dependency or generated router. It demonstrates application-owned HTTP wiring to
the public auth API; other stacks can wire the same operations. The example must preserve the
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

Required architectures: ARM64 and x86 (provisionally x86_64; confirm 32-bit needs).
Proposed baseline: Elixir >= 1.16, OTP >= 26, Rust >= 1.88. Confirm OS/libc coverage;
propose Linux glibc on both architectures and macOS ARM64, with macOS x86_64,
musl and Windows requiring explicit scope. Every supported target needs native
execution tests, not cross-compilation alone. The executable has an OS/CPU/libc
target, not an Erlang NIF ABI; the versioned protocol is the compatibility boundary.

Use Hex dependencies for consumers and local paths for development. Test any
unpublished monorepo git/subdirectory installation in a clean consumer app.

**Hex must build outside this repository.** Include reviewed executable source and
resolve exact compatible released Rust versions, or approve a self-contained
source bundle. Recommend version-plus-path Cargo dependencies in development,
removing repo-relative paths in a temporary packaging tree for registry builds.
Verify the unpacked archive in isolation; never mutate working source or skip
verification to package it.

Keep the shared release version unless maintainers choose otherwise. Update
release-please, lockfiles, archive boundaries and checks that currently assume
seven Rust crates/one npm package; keep the Port executable crate unpublished on crates.io.
Release Rust first, build/test the exact Hex artifact against those versions,
then approve Hex publication. Review Hex authentication/least privilege separately;
this plan does not enable uploads or credentials.

Initial source installs require Rust, Erlang/Elixir and platform build tools.
Build the executable into the Mix release and verify its executable permissions,
path and child lifecycle in an isolated deployment. Future prebuilt executables
need a target/libc matrix, immutable tagged artifacts, checksums/provenance,
audits, source-build fallback tests and release approval. No unsigned or
unverified mutable install-time downloads.

## 8. Validation

| Area | Required coverage |
| --- | --- |
| Core delegation | Rust units, ExUnit boundaries, typespec/docs examples, round trips, existing golden vectors and browser PoW interoperability |
| Hostile input | Tamper/noncanonical/trailing input, UTF-8, oversized binaries/maps, negative/overflow integers, wrong/stale handles/keys, unknown kid |
| Security | Expiry/skew units/boundaries, active/verify-only rotation, RNG failure/independent draws, no fixed-nonce production API, forged solve rejection |
| Process/protocol safety | Redaction, finite atom count; fragmented/oversized/malformed frames, version mismatch, duplicate IDs, stale handles, queue saturation, deadlines, worker kill/restart, key reload and orphan cleanup; BEAM survives child crash; latency/memory under load |
| Distribution | Unpacked Hex outside repo, clean Mix consumer/release, executable permissions/path, native ARM64/x86_64 tests on supported OS/libc targets, archive/license/advisory audit, no core test-support |
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
| P1 | Package/Port executable scaffold and root wiring | Handshake/lifecycle, isolated Hex/release build, CPU/OS/libc matrix settled |
| P2 | Required async bridge spike | Correlation/lifecycle, callback bounds and durable ambiguous-commit recovery proven |
| P3 | High-level auth/session API and backend conformance | End-to-end request/confirm/logout, concurrent one-time consume, revocation and refresh proven |
| P4 | High-level PoW API and budget behaviour | Browser interoperability and shared lifetime admission/failure tests |
| P5 | First-release docs/tasks/artifact readiness | Security/API review, full verify, clean consumer build and explicit release approval |
| P6 | Standalone Phoenix example | Full HTTP security-contract tests; no framework dependencies in the library |
| P7 | Precompiled distribution | Target/provenance/recovery review |

Resolve packaging before expanding the API. Do not report the async spike as
complete authentication. Each packet reports paths/API changes, security behavior,
tests, validation run/not run, open questions and follow-ups. Cross-crate changes
remain proposals; no implementation or publishing starts on implicit approval.

# Elixir 0.8 implementation checklist

Owner-approved scope: [the plan](../../docs/elixir-0.8-plan.md).
One implementation PR; no publication. Current package version remains 0.7.0
to match repository release checks until the 0.8 release is prepared.

Work one observable feature at a time: failing test, minimal implementation,
green focused suite, then compatibility/regression checks. A green slice is
not a completed authentication system.

## 1. Foundation and reference contract

- [x] Independent Mix package under `hex/datadeft_auth/`; no umbrella; owner-approved tiny crypto NIF.
- [x] Package-local format/compile/test tasks and test-only support.
- [x] Shared synthetic vectors asserted by Rust and Elixir.
- [x] Root compatibility gate and shared-table CI task.
- [x] Remove obsolete Port membership/tasks/release checks.
- [ ] Complete workflow and wire/storage-format inventory.
- [ ] Clean source-archive and consumer Mix release gates.

## 2. Shared DynamoDB data (first priority)

- [x] Storage HMAC domain/framing and redacted 32-byte key.
- [x] Exact email normalization, including Rust Unicode trim and ASCII case policy.
- [x] Canonical user identifiers and redacted account records.
- [x] Keyed email lookup plus authoritative profile read; strongly consistent.
- [x] Reject dangling, corrupt, mismatched and malformed profile/lookup rows.
- [x] Read an account created by the existing Rust login workflow.
- [x] Exact fixed-window and rotation-independent lifetime-counter keys.
- [x] Conditional counters, first-use expiry, TTL saturation and fail-closed errors.
- [x] Shared-table Rust/Elixir quota exhaustion and barrier-started race test.
- [x] Previous-key fallback, email lookup migration and rekeying (including Rust-created dormant accounts).
- [x] Magic-link record encoding/strict decoding, read by both Rust and Elixir.
- [x] Atomic consume + account + session + index transaction.
- [x] Cross-language same-challenge consume/create contention and Rust reads of Elixir-created account/session.
- [x] Distinct-challenge account-creation contention, disable checks and immutable-field binding in DynamoDB Local.
- [ ] Distinct-challenge account-creation contention across Rust and Elixir.
- [ ] Session reads, owner status and revocation across implementations.
- [ ] Audited administration, pagination and enable/disable race contracts.
- [ ] Production AWS client/signing/credential adapter.
- [ ] SES and Secrets Manager loading/rotation.

The current IO boundary is injected as `{module, state}`. The only concrete
Elixir HTTP client is loopback-only test support, not a production AWS adapter.

## 3. Crypto and pure cores

- [x] Owner-approved crypto-only Rustler boundary ([contract](CRYPTO-DEPENDENCIES.md)); b3/JOSE not selected.
- [x] Rust-compatible Base62 integer codec, golden vectors and round trips.
- [x] Bounded Branca encode/decode over the existing Rust production API, including canonicality/tamper checks.
- [ ] Higher-level purpose-bound cookie/keyring API and clean native artifact/source-archive consumers.
- [ ] HKDF and purpose/key-ID-bound cookie keyrings.
- [x] Magic-link grammar, independently drawn selector/verifier, lookup HMACs.
- [ ] Confirm/session/proof cookie bodies, expiry, skew and key-window parity.
- [ ] BLAKE3 PoW identity and exact challenge/tag/work formats.
- [ ] Bidirectional cookie/token/proof verification, tamper and rotation vectors.

No new formats or algorithm substitutions. The owner has approved a tiny Rustler
crypto wrapper over existing Rust libraries; no native service or generic bridge.

## 4. Framework-neutral services

- [ ] Request (consent, locale, keyed request/outbox limits, generic response).
- [ ] Landing (selector limit, dummy work, account display, bound flow cookie).
- [ ] Read flow state (same binding, limits and terminal-state handling).
- [ ] Confirm (nonce/account/verifier binding, one-time atomic commit).
- [ ] Validate session, logout-specific validation, refresh and revoke.
- [ ] Exact/grouped country policy and locale allowlists.
- [ ] Account/admin queries and audited mutations, including disable/enable safety.
- [ ] Independent proof admission and per-solve policy.

## 5. Plug and delivery

- [ ] Strict body/header/cookie parsing and HTTP refusal parity.
- [ ] Cookie defaults/clearing, same-origin POST/CSRF, fixed redirects and safe headers.
- [ ] Independent Plug PoW middleware using the shared lifetime budget.
- [ ] Bandit example consuming the one shared browser client.
- [ ] End-to-end HTTP and browser interoperability tests.
- [ ] Supported runtime/platform matrix and clean consumer archive/release tests.
- [ ] Independent security/API review and full verification before merge.

## Validation commands

```sh
mise run elixir-verify               # builds the tiny crypto NIF with Rust
mise run compatibility-test          # shared Rust/Elixir vectors
mise run dynamodb-compatibility-test # disposable Docker table + Rust/Elixir
mise run verify                     # full workspace, excluding Docker integration
```

Earlier Rust additions were compatibility tests only. The owner-approved native
increment now adds a tiny crypto adapter, without changing any core public API. Cargo.lock drops the removed Port dependencies and patches
`url` to 2.5.9 (plus its form_urlencoded patch) to resolve RUSTSEC-2026-0592 found
by verification. The existing Bun lock normalization task was needed for release
checks after Bun emitted JSONC. Jason supports Rustler's build and DynamoDB Local
tests. Rustler is compile-time only; production loads the tiny native library.

## Foundation checkpoint

- Package-local verification: 30 tests passed; 4 explicit integration/vector tests
  excluded from the standalone gate.
- Shared vectors: Rust reference test passed; Elixir gate ran 32 tests with no
  failures (2 Docker-specific tests excluded).
- DynamoDB compatibility: 32 Elixir tests passed (2 vector tests excluded),
  including the Rust subprocess sharing the table, quota, race and account.
- Existing Rust DynamoDB Local regression gate: 10 passed, with only the
  separately orchestrated mixed-language test filtered out.
- `mise run verify`: passed, including audit, Rust tests/Clippy/docs, browser
  package, formal checks, workflow/release checks and shared vectors.
- `git diff --check`: passed.
- Linux floor-runtime image checks were attempted but could not complete due to
  image/tool downloads timing out; their orchestration was stopped. Local tests
  use Elixir 1.19.5 / OTP 28. The platform matrix remains unverified locally.
- Full auth flows, cookie parity, production AWS delivery, archive/release
  consumers and independent security review remain unfinished.

## Rotation increment

Previous-key account reads migrate the current lookup only after validating the
profile. Rekey scans all pages, counts only successful conditional writes and is
idempotent. Unit tests cover outages/corruption and equal-key deduplication;
DynamoDB Local proves login-time migration and dormant-account rekeying over
accounts created by the real Rust workflow. Full workspace verification and the
mixed-language Docker gate passed.

## Magic-link primitive/storage increment

Strict `mlv1` grammar, independently requested entropy, role-bound lookup HMACs,
canonical stored hashes and redacted token/key/record inspection are implemented.
Challenge writes use conditional creation, store keyed material only and retain
Rust's TTL policy. Candidate reads are strongly consistent and side-effect-free;
all required fields and optional consumption timestamps decode strictly.
DynamoDB Local proves Rust reads Elixir-written challenges and vice versa.
The mixed gate reports 50 tests, zero failures, two vector exclusions; full
`mise run verify` passed. Crypto dependency selection remains pending approval.

## Atomic authentication repository increment

One DynamoDB transaction binds every immutable challenge field, checks unconsumed
and unexpired state plus nonzero consent, claims both email keys during rotation,
and creates the keyed session and permanent audit index. Existing profiles must
still be enabled and linked to the exact account; stored consent is preserved.
No raw bearer, session ID, attempt ID or verifier-derived material is persisted
in transaction rows/conditions (the attempt ID is only the idempotency token).
Cancellation attribution and identical-command retry semantics match Rust.

DynamoDB Local proves exact retry succeeds, changed-payload ID reuse fails,
replay cannot create a second session, mixed Rust/Elixir consume has one winner,
and distinct-challenge creation cannot split an account. Tests also reject disabled
profiles, session collisions, stale/expired/changed challenge expectations and
zero consent without partial writes. Rust resolves an Elixir-created account
through its old-key row and reads its session. The mixed gate reports 58 tests,
zero failures, two vector exclusions. Existing Rust DynamoDB regressions and full
workspace verification passed. Framework-neutral authentication orchestration,
cookie minting and production IO remain unimplemented.

## Owner-approved tiny NIF increment

The owner approved replacing the no-native requirement with an extremely small
crypto-only Rustler wrapper. The first slice is two calls, 63 lines of Rust
including the entry module: Branca encode/decode delegate directly to the existing
production core, with bounded inputs and fixed error atoms even for direct native
calls. Encode uses OsRng; both calls use dirty CPU scheduling. No core API change,
test-support production feature, service engine, resources, solver or unsafe
adapter code. Low-level decode deliberately does not authorize or check TTL.

Validation passed: full workspace verify (including Clippy, Rust tests/docs/audit
and expanded API guard), official Rust Branca vectors through the NIF, package
round-trip/tamper/canonicality/argument tests, mixed-language DynamoDB gate
(61 tests, zero failures, three exclusions), and a source-built production Mix
release exercising its bundled NIF. Rustler/Jason remain compile-time dependencies.
CI now provisions the native source toolchain for the Linux BEAM matrix.

Not yet validated: the updated Linux container matrix, clean source archive
fallback, precompiled artifacts and independent native-boundary security review.
Those remain release gates; no artifact has been published.

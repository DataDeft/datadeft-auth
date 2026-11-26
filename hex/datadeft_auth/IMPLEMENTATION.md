# Elixir 0.8 implementation checklist

Owner-approved scope: [the plan](../../docs/elixir-0.8-plan.md).
One implementation PR; no publication. Current package version remains 0.7.0
to match repository release checks until the 0.8 release is prepared.

Work one observable feature at a time: failing test, minimal implementation,
green focused suite, then compatibility/regression checks. A green slice is
not a completed authentication system.

## 1. Foundation and reference contract

- [x] Independent Mix package under `hex/datadeft_auth/`; no umbrella or Rust runtime.
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
- [ ] Previous-key fallback, email lookup migration and rekeying.
- [ ] Magic-link record encoding/strict decoding.
- [ ] Atomic consume + account + session + index transaction.
- [ ] Cross-language consume and account-creation contention tests.
- [ ] Session reads, owner status and revocation across implementations.
- [ ] Audited administration, pagination and enable/disable race contracts.
- [ ] Production AWS client/signing/credential adapter.
- [ ] SES and Secrets Manager loading/rotation.

The current IO boundary is injected as `{module, state}`. The only concrete
Elixir HTTP client is loopback-only test support, not a production AWS adapter.

## 3. Crypto and pure cores

- [ ] Dependency investigation and owner approval before selecting crypto packages.
- [ ] Canonical Base62 and exact Branca/XChaCha20-Poly1305.
- [ ] HKDF and purpose/key-ID-bound cookie keyrings.
- [ ] Magic-link grammar, independently drawn selector/verifier, lookup HMACs.
- [ ] Confirm/session/proof cookie bodies, expiry, skew and key-window parity.
- [ ] BLAKE3 PoW identity and exact challenge/tag/work formats.
- [ ] Bidirectional cookie/token/proof verification, tamper and rotation vectors.

No new formats, algorithm substitutions or hand-rolled native bridge. A wrapper
over existing Rust libraries requires a separately reviewed, necessary operation.

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
mise -C hex/datadeft_auth run verify  # no Rust needed
mise run compatibility-test          # shared Rust/Elixir vectors
mise run dynamodb-compatibility-test # disposable Docker table + Rust/Elixir
mise run verify                     # full workspace, excluding Docker integration
```

Rust additions are compatibility tests only; no Rust auth implementation or
public API changed. Cargo.lock drops the removed Port dependencies and patches
`url` to 2.5.9 (plus its form_urlencoded patch) to resolve RUSTSEC-2026-0592 found
by verification. The existing Bun lock normalization task was needed for release
checks after Bun emitted JSONC. Jason is test-only JSON support for DynamoDB
Local. Production Elixir uses OTP crypto and currently has no Hex dependencies.

## Latest checkpoint

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

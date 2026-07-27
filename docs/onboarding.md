# Customer onboarding and implementation status

**Status:** Current onboarding checklist. This is the live implementation backlog; `fix.md`, `review.md`, and `plan.md` are historical inputs.

## Can a customer use this today?

| Surface | Status | Customer action |
| --- | --- | --- |
| Magic-link core/service | Ready for integration | Supply clock, CSPRNG, keyrings, repository, limiter, and outbox implementations |
| Scanner-safe Axum helpers | Ready for integration | Own routes; configure exact Origin, fixed redirects, flow/session cookies, body limits, and token-safe logging |
| In-memory AWS-style fakes | Ready for development/tests | Do not use fake secrets, clocks, or entropy in production |
| DynamoDB/SES adapters | Available behind `aws` feature | Provision and validate table/IAM/TTL/encryption, renderer, SES identity, and live transaction behavior |
| Session validation/revocation | Ready for integration | Invoke validation on protected requests and revoke server state on logout/compromise |
| PoW Rust core | Ready as a primitive | Build the independent endpoint, policy, replay/proof lifecycle, and browser integration |
| Browser PoW client | **Not implemented** | Implement `dd-protect-client` or provide an application-owned compatible solver |
| Country-aware PoW | **Not implemented** | Implement upstream monotonic difficulty policy; never lower below base/floor |
| Runnable example | **Not implemented** | Current example is a placeholder; use the API descriptions until MVP-001 lands |
| Published package/crates | **Not published** | Consume by pinned path/git revision; APIs remain pre-stable |

## Production integration checklist

A magic-link deployment can be put into production when the consuming application has completed and recorded the following:

- [ ] Use an OS-backed CSPRNG and distinct production secrets for flow cookies, session cookies, lookup HMACs, storage HMACs, and independent PoW concerns.
- [ ] Configure active and verify-only keyrings with the retention rules in [security.md](security.md).
- [ ] Implement `MagicLinkOutbox` with application-owned email templates and a token-safe URL.
- [ ] Implement the aggregate authentication repository contract atomically. For AWS, use the provided DynamoDB transaction shape.
- [ ] Provision DynamoDB TTL, encryption, backups, least-privilege IAM, and strongly consistent session/authentication reads.
- [ ] Decide whether inline SES delivery is acceptable or wrap delivery in a durable outbox.
- [ ] Configure exact same-origin confirmation, fixed/same-origin redirect, production-secure cookies, and session validation on protected routes.
- [ ] Verify proxies, access logs, middleware, tracing, metrics, diagnostics, and error reporting never retain token-bearing request targets, cookies, or confirmation values.
- [ ] Run live or production-like authentication replay, concurrent confirmation, rollback, logout, and post-revocation tests.
- [ ] Document that normalized email is stored in DynamoDB records and apply the required privacy/IAM/KMS/retention controls.
- [ ] Run `mise run verify` and the consuming application's integration tests against an immutable commit/tag.

PoW is optional application admission and is not required by the magic-link protocol. If a deployment requires PoW, the PoW-specific MVP items below must also be complete.

## Implementation backlog

| ID | Priority | Status | Work | Acceptance evidence |
| --- | --- | --- | --- | --- |
| MVP-001 | P0 onboarding | Planned | Replace the placeholder with a runnable fake-backed Axum example covering request, landing, confirmation, authenticated session, and logout | Example compiles; end-to-end test passes; no production secrets |
| MVP-002 | P0 deployment | Required per deployment | Attest that raw magic-link request targets and tokens are scrubbed from every outer logging/telemetry layer | Production-like probe report with representative failures and redirects |
| MVP-003 | P0 AWS deployment | Required for AWS users | Validate real DynamoDB transaction cancellation, replay, concurrency, rollback, TTL, and post-revocation visibility | Live/local AWS integration suite and recorded schema/IAM checklist |
| MVP-004 | P0 distribution | Planned | Publish or provide an immutable private tag/SHA, supported feature matrix, MSRV, and API review | Consumer builds from immutable reference and `cargo publish --dry-run` or private-release equivalent passes |
| MVP-005 | P1 API | Planned | Decide and implement explicit `Future + Send` and dyn-safety policy before external API freeze | Compile tests for multithreaded Tokio/Axum generic callers |
| MVP-006 | P1 delivery | Decision required | Choose durable outbox semantics or explicitly support/document inline SES failure behavior | Failure/retry tests and documented operational contract |
| MVP-007 | P1 privacy | Decision required | Accept plaintext normalized-email storage controls or add application-level encryption | Written data classification and tested storage policy |
| MVP-010 | PoW delivery | Not implemented | Implement and vector-test `dd-protect-client` browser worker with cancellation and timeout | Browser/Rust shared vectors and target-device benchmark report |
| MVP-011 | PoW delivery | Not implemented | Implement challenge endpoint and upstream admission middleware | HTTP integration tests for mint, solve, verify, expiry, downgrade, and generic errors |
| MVP-012 | PoW security | Not implemented | Implement authenticated proof-cookie/replay lifecycle with single-use or small use cap | Replay/concurrency tests and proof-cookie key-rotation tests |
| MVP-013 | PoW policy | Not implemented | Define trusted country source and monotonic country difficulty policy | Tests prove `effective >= production_floor`, `effective >= base`, and country changes never decrease active-flow difficulty |
| MVP-014 | P1 boundary cleanup | Planned | Decide whether to remove the current magic-link session-country field or keep it explicitly as non-authoritative session context | Public API and docs expose one unambiguous owner for country policy |
| MVP-020 | Assurance | Future | Add executable TLA+ state models and CI model checking | Model-check report linked from `formal-methods.md` |
| MVP-021 | Assurance | Future | Add deterministic simulation, fuzzing, and bounded verification targets | Seeded failure schedules, fuzz corpus, and Kani proof reports |

## PoW target decisions still required

Before MVP-010 through MVP-014 are treated as implemented, define:

- trusted country source and behavior when missing;
- country risk classes and required difficulty for each class;
- whether difficulty is fixed at challenge mint or may only increase during one admission flow;
- challenge and proof-cookie lifetime;
- replay store and use cap;
- generic public errors and challenge issuance controls;
- browser performance targets and accessibility fallback.

The minimum invariant is fixed now:

```text
effective_difficulty >= production_floor
effective_difficulty >= configured_base_difficulty
country policy may increase effective_difficulty, never decrease it
```

## Integration order

1. Pin an immutable repository revision.
2. Wire core/service with fakes and complete the scanner-safe HTTP flow.
3. Replace fakes with the chosen repository/outbox adapters.
4. Add session authentication and server-side logout/revocation.
5. Complete the deployment logging and live storage gates.
6. If required, place independent PoW admission before the protected request endpoint.
7. Run the full consumer integration and release checklist.

See [architecture.md](architecture.md) for component and sequence diagrams and [formal-methods.md](formal-methods.md) for future assurance work.

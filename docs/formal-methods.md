# Formal assurance roadmap

**Status:** Draft, non-normative, and not model-checked. No formal proof is currently claimed.

The production priority is a working, tested integration. Formal methods are planned follow-up work that strengthens evidence without replacing cryptographic review, live infrastructure tests, or deployment controls.

## Available tooling

The development environment currently includes the Rust `tla` TLA+ checker, Kani, Cargo Fuzz, Quint, and Creusot. This document does not install or configure them. Tool versions and CI integration will be pinned when the corresponding MVP begins.

## Claims to model

| Claim ID | Safety claim | Current implementation evidence | Planned method |
| --- | --- | --- | --- |
| ML-INV-001 | `GET` landing never consumes a challenge or creates a session | Service/Axum landing tests | TLA+ action invariant |
| ML-INV-002 | One challenge is consumed at most once | Atomic fake race tests and DynamoDB conditions | TLA+ concurrent state exploration |
| ML-INV-003 | Successful confirmation atomically pairs consumption with session creation | Aggregate repository contract and five-action transaction tests | TLA+ transaction model plus DST failpoints |
| ML-INV-004 | Wrong selector, verifier, account, nonce, expiry, or consent cannot authenticate | Tamper/mismatch tests | TLA+ abstract guards; Tamarin later if justified |
| ML-INV-005 | Disabled-user/session-conflict failures do not burn the challenge | Fake transaction tests | TLA+ transition invariant |
| SES-INV-001 | Revoked or expired sessions never validate | Session boundary tests and strong-read request test | TLA+ session lifecycle model |
| POW-INV-001 | Accepted proof has authentic challenge metadata, valid freshness, required work, and current minimum difficulty | PoW vector/tamper/downgrade tests | TLA+ policy model plus Kani pure-policy proof |
| POW-INV-002 | Country policy never lowers required difficulty | Not implemented | TLA+ invariant and property tests for MVP-013 |
| POW-INV-003 | A proof cannot exceed its configured replay budget | Not implemented | TLA+ replay model and deterministic concurrency tests |
| BOUND-INV-001 | Parsers reject values outside documented caps without panic | Unit/property tests | Cargo Fuzz and selected Kani harnesses |

## Initial TLA+ models

### Magic-link authentication

Abstract states:

```text
Challenge = Absent | Issued | Consumed | Expired
Flow      = Absent | Started | Expired
Session   = Absent | Active | Revoked | Expired
User      = Missing | Enabled | Disabled
```

Actions:

- `RequestLink`
- `BeginLanding`
- `Confirm`
- `AtomicCommit`
- `AmbiguousRetry`
- `DisableUser`
- `RevokeSession`
- `AdvanceTime`

Primary invariants are ML-INV-001 through ML-INV-005 and SES-INV-001. The model must include competing confirmations, disable-before-commit, session-ID conflict, ambiguous transaction result, replay, and expiry boundaries.

### PoW admission

Abstract states:

```text
Challenge = Absent | Issued | Expired
Proof     = Absent | Verified | Spent
Admission = Rejected | Accepted
```

The policy model defines:

```text
EffectiveDifficulty(country) =
    Max(ProductionFloor, BaseDifficulty, CountryRequired(country))
```

Actions include mint, country-policy update, solve, verify, consume proof, replay, and advance time. Invariant POW-INV-002 requires that an active flow's required difficulty never decreases after any policy/country transition.

## Deterministic simulation testing

After the state models stabilize, MVP-021 should add an executable model-based harness using injected clock, entropy, scheduler, and repository failpoints. It should generate:

- concurrent confirmations and replays;
- failures before/after each repository operation;
- ambiguous transaction responses followed by exact retry;
- user disable and session revoke races;
- expiry at every inclusive/exclusive boundary;
- proof replay and country-difficulty changes.

The harness compares implementation state with a small reference state machine. Live DynamoDB tests remain necessary because a simulation cannot prove AWS behavior.

## Bounded verification and fuzzing

Suggested first targets:

- Kani: country difficulty monotonicity, expiry arithmetic, fixed flow-body framing, and pure transition helpers.
- Cargo Fuzz: magic-link grammar, Branca/Base62 decode, flow/session cookie wrappers, Axum query/cookie/body parsers, and DynamoDB item decoding.
- Creusot: evaluate only for small pure functions where proof cost is justified.
- Tamarin: consider later for symbolic attacker correspondence (flow-cookie authenticity, confirmation binding, replay). Do not start here unless TLA+/DST reveals a protocol ambiguity.

## Proof boundaries

A successful model check proves the model within configured bounds; it does not prove:

- the implementation conforms without traceability and conformance tests;
- the cryptographic primitives themselves;
- AWS, SES, proxy, browser, or network behavior;
- email delivery liveness;
- human recognition of the account confirmation page;
- absence of token logging outside the handler.

Every formal claim must link model action, code path, test, tool/version, constants, explored state count, and any assumptions. Until those artifacts exist, the correct label remains **planned assurance**, not formally verified.

## Planned deliverables

| ID | Deliverable | Completion condition |
| --- | --- | --- |
| MVP-020 | TLA+ magic-link/session and PoW policy models | `tla` checks all listed invariants in CI with recorded bounds and no counterexample |
| MVP-021 | Deterministic simulation and fault schedules | Reproducible seeded schedules cover concurrency and failure transitions |
| MVP-022 | Fuzz and bounded-proof targets | Corpus and Kani reports are retained in CI artifacts |
| MVP-023 | Claim-to-evidence report | Each claim links implementation, tests, models, assumptions, and residual risk |

Current production onboarding requirements are tracked in [onboarding.md](onboarding.md).

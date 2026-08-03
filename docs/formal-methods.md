# Formal assurance roadmap

**Status:** Draft and non-normative. The repository does not claim formal proof.

Production work comes first. Formal methods will add evidence later. They do not replace crypto review, live tests, or deployment controls.

## Tooling

The development environment has these tools:

- Rust `tla` checker: `tla-checker` 0.3.9 from crates.io (the `tla` binary)
- Kani
- Cargo Fuzz
- Quint
- Creusot

The first TLA+ models live in [../spec/tla](../spec/tla). Run them with `mise
run spec`. This document does not install the other tools. CI will pin their
versions when each MVP starts.

## Claims to model

| Claim | Safety property | Current evidence | Planned method |
| --- | --- | --- | --- |
| ML-INV-001 | `GET` landing never consumes a challenge. | Service and Axum tests | TLA+ invariant |
| ML-INV-002 | One challenge has at most one consume. | Fake race tests and DynamoDB conditions | TLA+ state search |
| ML-INV-003 | Confirmation pairs consume and session creation. | Repository contract tests | TLA+ transaction model |
| ML-INV-004 | Wrong bound data cannot authenticate. | Tamper tests | TLA+ guards |
| ML-INV-005 | Disabled-user failures do not burn a challenge. | Fake transaction tests | TLA+ invariant |
| SES-INV-001 | Revoked or expired sessions never validate. | Session boundary tests | TLA+ session model |
| POW-INV-001 | Accepted proof has valid challenge metadata. | PoW vectors and tamper tests | TLA+ plus Kani |
| POW-INV-002 | Country policy never lowers difficulty. | TLA+ model (`Pow.tla`) | TLA+ plus property tests |
| POW-INV-003 | An opt-in single-use proof cannot be replayed. | Not ready | TLA+ replay model |
| BOUND-INV-001 | Parsers reject over-cap values safely. | Unit and property tests | Fuzzing and Kani |

ML-INV-001..005, SES-INV-001, and POW-INV-001..002 now have TLA+ models in
[../spec/tla](../spec/tla), gated by the `formal-spec` CI job (`mise run spec`).
POW-INV-003 and BOUND-INV-001 remain future work. Replay is opt-in, and parser
bounds belong to fuzzing and Kani.

The v0.2.0 solve-timing signal (`Verified::mint_to_verify_ms`, the proof-cookie
solve-class byte) is deliberately outside the models. It is observational: it
adds no admission transition and changes no invariant. The clock-unit change
(seconds to milliseconds) is also invisible to the models, which treat expiry
abstractly without time units. Timing-derived *policy* (for example, a fast
floor that denies admission) would be a new guard on the accept transition and
would need a model extension before shipping.

## Magic-link model

Use these abstract states:

```text
Challenge = Absent | Issued | Consumed | Expired
Flow      = Absent | Started | Expired
Session   = Absent | Active | Revoked | Expired
User      = Missing | Enabled | Disabled
```

Use these actions:

- RequestLink
- Landing
- Confirm
- AtomicCommit
- AmbiguousRetry
- DisableUser
- RevokeSession
- AdvanceTime

The model must include these cases:

1. Competing confirmations.
2. Disable before commit.
3. Session-ID conflict.
4. Ambiguous transaction result.
5. Replay.
6. Expiry boundaries.

## PoW model

Use these abstract states:

```text
Challenge = Absent | Issued | Expired
Proof     = Absent | Verified | Spent
Admission = Rejected | Accepted
```

The policy model defines this rule:

```text
EffectiveDifficulty(country) =
    Max(ProductionFloor, BaseDifficulty, CountryRequired(country))
```

The model should include these actions:

- mint
- country policy update
- solve
- verify
- consume proof
- replay
- advance time

POW-INV-002 requires one rule. An active flow difficulty must not decrease after any policy or country transition.

## Deterministic simulation tests

Add a model-based harness after the state models stabilize.

The harness should use injected clock, entropy, scheduler, and repository failpoints.

It should generate these cases:

- concurrent confirmations and replays
- failures before and after repository operations
- ambiguous transaction responses with exact retry
- user disable and session revoke races
- expiry at each boundary
- proof replay and country difficulty changes

The harness compares implementation state with a small reference state machine. Live DynamoDB tests remain necessary.

## Fuzzing and bounded checks

Start with these targets:

- Kani for country difficulty monotonicity.
- Kani for expiry arithmetic.
- Kani for fixed flow-body framing.
- Kani for pure transition helpers.
- Cargo Fuzz for magic-link grammar.
- Cargo Fuzz for Branca and Base62 decode.
- Cargo Fuzz for flow and session cookie wrappers.
- Cargo Fuzz for Axum parsers.
- Cargo Fuzz for DynamoDB item decoding.
- Creusot only for small pure functions.
- Tamarin later if protocol ambiguity appears.

## Proof boundaries

A successful model check proves only the model within configured bounds.

It does not prove these claims:

- The implementation matches the model.
- The crypto primitives are correct.
- AWS behavior is correct.
- SES behavior is correct.
- Proxy behavior is correct.
- Browser behavior is correct.
- Email delivery is live.
- A human recognizes the account page.
- Logs outside the handler omit token material.

Each formal claim must link these artifacts:

1. Model action.
2. Code path.
3. Test.
4. Tool version.
5. Constants.
6. Explored state count.
7. Assumptions.

Until those artifacts exist, call the work planned assurance.

## Planned deliverables

| ID | Deliverable | Done when |
| --- | --- | --- |
| MVP-020 | TLA+ magic-link and PoW models | CI checks all listed invariants. |
| MVP-021 | Simulation and fault schedules | Seeded schedules cover failure transitions. |
| MVP-022 | Fuzz and Kani targets | CI keeps corpus and proof reports. |
| MVP-023 | Claim evidence report | Each claim links code, tests, models, and risk. |

Current production requirements live in [onboarding.md](onboarding.md).

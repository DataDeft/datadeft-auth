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

| Claim | Safety property | Model (`spec/tla`) | Code evidence |
| --- | --- | --- | --- |
| ML-INV-001 | `GET` landing never consumes a challenge. | `MagicLink.tla` | Service and Axum tests; `model_flow_tests` |
| ML-INV-002 | One challenge has at most one consume. | `MagicLink.tla`, `MagicLinkRace.tla` | Fake race tests, DynamoDB conditions; `model_flow_tests` |
| ML-INV-003 | Confirmation pairs consume and session creation. | `MagicLink.tla` | Repository contract tests; `model_flow_tests` |
| ML-INV-004 | Wrong bound data cannot authenticate. | `MagicLink.tla` | Tamper tests; `hmac_and_confirm_properties` |
| ML-INV-005 | Disabled-user failures do not burn a challenge. | `MagicLink.tla` | Fake transaction tests; `model_flow_tests` |
| SES-INV-001 | A revoked session never validates. | `Session.tla` | `model_session_tests` |
| SES-INV-002/003 | No session validates past its absolute or idle lifetime. | `Session.tla` | `model_session_tests`, `model_boundary_tests`, `cookie_integrity` |
| SES-INV-004/005 | A disabled owner's sessions, and sessions created at or before the enable watermark, never validate. | `Session.tla` (`SessionAdmin.cfg`) | `model_session_tests` |
| SES-INV-006..008 | Refresh keeps `iat`, never passes the absolute lifetime, and only follows a same-request validation. | `Session.tla` | `model_boundary_tests`, `refresh_tests` |
| SES-INV-009 | No session that existed at a re-enable validates afterwards, whatever the clocks say. | `Session.tla` (`SessionAdmin.cfg`) | `pre_disable_session_from_a_clock_ahead_node_stays_dead_after_enable` |
| ROT-INV-001/002 | One email never has two accounts during a rolling storage-key rotation. | `KeyRotation.tla` | `rolling_rotation_*`, `model_rotation_tests` |
| POW-INV-001 | Accepted proof met the production floor. | `Pow.tla` | PoW vectors, tamper tests; `pow_security` |
| POW-INV-002 | A policy change after mint never lowers a challenge's difficulty. | `Pow.tla` | `pow_security` |
| POW-INV-003 | An opt-in single-use proof cannot be replayed. | Not modeled: replay within the proof TTL is allowed by design; callers cap it with `Verified::tid`. | `pow_security` (tid stability) |
| LIVE-001 | The happy path always reaches a session, including through an ambiguous commit and its retry. | `Liveness.tla` | `model_flow_tests` |
| BOUND-INV-001 | Parsers reject over-cap values safely. | Out of scope for TLA+ | Totality property tests; fuzzing and Kani planned |

`mise run spec` checks every model. `mise run spec-mutants` proves each
invariant can fail: it breaks the model the way a plausible code bug would and
requires the checker to report that exact violation. Both run in
`mise run verify`. The `model_*_tests` in `datadeft-magic-link-aws` drive the
real services and the fake store through random operation sequences and check
the same invariants, which links the models to the code.

Findings the models produced:

- **SES-F1 (fixed in this release).** A login host whose clock runs ahead
  stamps `created_at` after a quick re-enable's watermark, and `enable_user`
  did not wait for the disable's revocation, so a pre-disable session could
  validate again. `enable_user` now revokes every live session before it
  re-enables. Counterexample: run `Session.tla` with
  `EnableRevokesFirst = FALSE`.
- **ROT-F1 (fixed in this release).** During a rolling storage-key rotation,
  a user created on a host with the new key had a lookup row only under that
  key; a later login on a host still on the old key created a second
  account. Creation now also writes the previous-key row. Counterexample:
  `KeyRotation.tla` with `DualWrite = FALSE`.
- **LIVE-F1 (fixed in the model).** The checker evaluates leads-to on cycles
  only, and `--allow-deadlock` hid stuck states, so the old liveness model
  passed even with its retry removed. Success is now an explicit terminal
  state and the model runs without `--allow-deadlock`.

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

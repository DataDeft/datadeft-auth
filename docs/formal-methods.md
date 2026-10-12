# Formal assurance roadmap

**Status:** Draft and non-normative. The repository does not claim formal
proof.

Production work comes first. Formal methods add evidence later. They do not
replace crypto review, live tests, or deployment controls.

## Tooling

`mise.toml` pins one formal tool: the Rust `tla` checker (`tla-checker` 0.3.9
from crates.io, the `tla` binary). The TLA+ models live in
[../spec/tla](../spec/tla).

Cargo Fuzz runs the fuzz targets. It is not pinned in `mise.toml`. See
[Fuzzing and bounded checks](#fuzzing-and-bounded-checks).

Kani, Quint, and Creusot are planned tools. The repository does not install
them. CI will pin their versions when each MVP starts.

## Claims to model

| Claim | Safety property | Model (`spec/tla`) | Code evidence |
| --- | --- | --- | --- |
| ML-INV-001 | `GET` landing never consumes a challenge. | `MagicLink.tla` | Service and Axum tests, `model_flow_tests` |
| ML-INV-002 | One challenge has at most one consume. | `MagicLink.tla`, `MagicLinkRace.tla` | Fake race tests, DynamoDB conditions, `model_flow_tests` |
| ML-INV-003 | Confirmation pairs consume and session creation. | `MagicLink.tla` | Repository contract tests, `model_flow_tests` |
| ML-INV-004 | Wrong bound data cannot authenticate. | `MagicLink.tla` | Tamper tests, `hmac_and_confirm_properties` |
| ML-INV-005 | Disabled-user failures do not burn a challenge. | `MagicLink.tla` | Fake transaction tests, `model_flow_tests` |
| SES-INV-001 | A revoked session never validates. | `Session.tla` | `model_session_tests` |
| SES-INV-002/003 | No session validates past its absolute or idle lifetime. | `Session.tla` | `model_session_tests`, `model_boundary_tests`, `cookie_integrity` |
| SES-INV-004/005 | A disabled owner's sessions, and sessions created before the enable watermark, never validate. | `Session.tla` (`SessionAdmin.cfg`) | `model_session_tests` |
| SES-INV-006..008 | Refresh keeps `iat`, never passes the absolute lifetime, and only follows a same-request validation. | `Session.tla` | `model_boundary_tests`, `refresh_tests` |
| SES-INV-009 | No session that existed at a re-enable validates afterwards, whatever the clocks say. | `Session.tla` (`SessionAdmin.cfg`) | `pre_disable_session_from_a_clock_ahead_node_stays_dead_after_enable` |
| ROT-INV-001/002 | One email never has two accounts during a rolling storage-key rotation. | `KeyRotation.tla` | `rolling_rotation_*`, `model_rotation_tests` |
| POW-INV-004 | One PoW solve buys at most its budget of admissions across all nodes and its lifetime. | `PowBudget.tla` | `admission_tests`, `lifetime_limit_never_refills_against_dynamodb` |
| ADM-INV-001 | No enable applies on top of a change it did not see (a disable is unconditional by design). | `AdminRace.tla` | `a_stale_admin_write_conflicts_instead_of_undoing_a_later_one`, `a_stale_admin_write_is_refused_against_dynamodb` |
| ADM-INV-002 | An enable never undoes a disable reported as successful after the enable read the user. | `AdminRace.tla` | `a_disable_of_a_disabled_user_still_fences_a_slow_enable` |
| ERASE-INV-001..005 | Erasure leaves no lookup to the user, no address in the profile, no valid session, no account from an older link. Re-signup is a new user (planned, low priority). | `Erasure.tla` | Not implemented yet |
| POW-INV-001 | Accepted proof met the production floor. | `Pow.tla` | PoW vectors, tamper tests, `pow_security` |
| POW-INV-002 | A policy change after mint never lowers a challenge's difficulty. | `Pow.tla` | `pow_security` |
| POW-INV-003 | POW-INV-004 supersedes this claim. The per-solve budget (`admit_proof`), keyed by `Verified::tid`, bounds reuse of a proof within its TTL. | `PowBudget.tla` | `admission_tests`, `pow_security` (tid stability) |
| LIVE-001 | The happy path always reaches a session, including through an ambiguous commit and its retry. | `Liveness.tla` | `model_flow_tests` |
| BOUND-INV-001 | Parsers reject over-cap values safely. | Out of scope for TLA+ | Totality property tests, cargo-fuzz targets in `fuzz/` (`mise run fuzz`), Kani planned |

## How the models are checked

| Task | What it does | In `mise run verify` |
| --- | --- | --- |
| `mise run spec` | Checks all 9 models in 10 configs (`Session.tla` also runs with `SessionAdmin.cfg`). | Yes |
| `mise run spec-mutants` | Runs 44 mutants. Each breaks a model the way a plausible code bug would. The checker must report that exact violation. | Yes |

Every `INVARIANT` and `PROPERTY` in a cfg (except `TypeOK`) has a mutant that
targets it. An untargeted one fails `spec-mutants`.

The `model_*_tests` in `datadeft-magic-link-aws` link the models to the code.
They drive the real services and the fake store through random operation
sequences and check the same invariants.

The Session configs check the shipped re-enable cutoff. Since 0.5.0 the cutoff
is inclusive (`WatermarkStrict = FALSE`, CeleraTax #12). Validation accepts a
session created in the enable's own second. `Inv_NoAcceptBeforeWatermark`
checks that sessions created before it never validate. The inclusive cutoff is
safe only because enable revokes first.

## Findings

- **SES-F1 (fixed in 0.5.0).** A login host whose clock runs ahead stamps
  `created_at` after a quick re-enable's watermark. `enable_user` did not wait
  for the disable's revocation, so a pre-disable session could validate again.
  `enable_user` now revokes every live session before it re-enables.
  Counterexample:
  `tla spec/tla/Session.tla --config spec/tla/SessionAdmin.cfg --allow-deadlock -c EnableRevokesFirst=FALSE`.
- **ROT-F1 (fixed in 0.5.0).** During a rolling storage-key rotation, a user
  created on a host with the new key had a lookup row only under that key. A
  later login on a host still on the old key created a second account.
  Creation now also writes the previous-key row. Counterexample:
  `KeyRotation.tla` with `DualWrite = FALSE`.
- **LIVE-F1 (fixed in the model).** The checker evaluates leads-to on cycles
  only, and `--allow-deadlock` hid stuck states. So the old liveness model
  passed even with its retry removed. Success is now an explicit terminal
  state, and the model runs without `--allow-deadlock`.
- **ADM-F1 (fixed in 0.5.0).** Concurrent admin actions on one user were
  last-write-wins. Take an enable whose final write arrived after three
  events: another admin's enable, a login, and a later disable. That enable
  undid the disable. It also revived a session whose revocation failed. Users
  cannot reach this. The fix:
  - An enable is conditional on the profile's `admin_version`. A stale one
    fails with `AdminError::Conflict`.
  - A disable is unconditional and always bumps the version. So it fences a
    slow enable even on an already-disabled user, and never loses a race
    itself.

  `AdminRace.tla` checks both (each is a killed mutant). The race tests pin
  them in code.

## Outside the models

- The solve-timing signal (`Verified::mint_to_verify_ms`, the proof-cookie
  solve-class byte) is observational. It adds no admission transition and
  changes no invariant.
- Timing-derived *policy* (for example, a fast floor that denies admission)
  would be a new guard on the accept transition. It needs a model extension
  before it ships.

## Model sketches

[../spec/tla/README.md](../spec/tla/README.md) describes each model and how to
run it. The [claims table](#claims-to-model) maps each invariant to its model.
The `effective_difficulty` rule is in
[onboarding.md](onboarding.md#pow-decisions).

## Deterministic simulation tests

Done: the `model_*_tests` in
`crates/datadeft-magic-link-aws/src/fake` are the simulation harness. They
drive the real services and the fake store through random operation
sequences. A plain-Rust reference model checks every step. The harness injects
the clock, the entropy, and repository faults.

The harness covers these cases:

- concurrent confirmations and replays
- failures before and after admin repository operations
- ambiguous commit results with exact retry
- user disable and session revoke races
- expiry at each boundary
- rolling storage-key rotation

These items remain:

- PoW proof replay and budget sequences. No model test drives
  `datadeft-pow-axum`.
- Country difficulty changes. The repository has no country policy yet.
- Seeded fault schedules for the DynamoDB adapter. The harness uses the fake
  store only, so live DynamoDB tests remain necessary.

## Fuzzing and bounded checks

`fuzz/` has 11 cargo-fuzz targets for the untrusted-input parsers.
`mise run fuzz` runs each for 60 s with `-max_len=10000`. It needs nightly Rust
and `cargo install cargo-fuzz`. It is not part of `mise run verify`.

Fuzz targets in `fuzz/fuzz_targets`:

| Target | Input under test |
| --- | --- |
| `base62_decode` | Base62 decode and re-encode round trip |
| `bound_cookie_parse` | Bound cookie and cookie wrapper parse |
| `branca_decode` | Branca decode |
| `confirm_cookie` | Magic-link confirm cookie verify |
| `cookie_header` | `Cookie` header value selection |
| `magic_link_token` | Magic-link token grammar |
| `normalized_email` | `NormalizedEmail` normalize and validate |
| `pow_proof_cookie` | PoW proof cookie verify |
| `pow_solution` | PoW solution verify |
| `request_json` | Axum magic-link request JSON parse |
| `session_body` | Session cookie body encode and decode |

Planned bounded checks:

- Kani for country difficulty monotonicity.
- Kani for expiry arithmetic.
- Kani for fixed flow-body framing.
- Kani for pure transition helpers.
- Creusot only for small pure functions.
- Tamarin later, if protocol ambiguity appears.
- Cargo Fuzz for DynamoDB item decoding (no target yet).

## Proof boundaries

A successful model check proves only the model, within its configured bounds.
It does not prove that:

- the implementation matches the model
- the crypto primitives are correct
- AWS, SES, proxy, or browser behavior is correct
- email delivery is live
- a human recognizes the account page
- logs outside the handler omit token material

Each formal claim must link:

1. Model action.
2. Code path.
3. Test.
4. Tool version.
5. Constants.
6. Explored state count.
7. Assumptions.

Until those artifacts exist, call the work planned assurance.

## Planned deliverables

MVP-020 (TLA+ models) is done. CI checks every model and mutant in
`mise run verify`.

| ID | Deliverable | Done when |
| --- | --- | --- |
| MVP-021 | Simulation and fault schedules | Seeded schedules cover failure transitions. |
| MVP-022 | Fuzz and Kani targets | CI keeps corpus and proof reports. |
| MVP-023 | Claim evidence report | Each claim links code, tests, models, and risk. |

Current production requirements live in [onboarding.md](onboarding.md).

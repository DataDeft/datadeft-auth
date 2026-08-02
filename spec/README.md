# Formal specifications

TLA+ models for the datadeft-auth safety invariants. This is the concrete
start of **MVP-020** in [docs/formal-methods.md](../docs/formal-methods.md).

The models are non-normative. A model check proves a property of the model
within its bounds. It does not prove that the Rust code matches the model, that
the crypto primitives are correct, or that AWS, SES, or browser behavior is
correct.

## Tool

The checker is `tla-checker` 0.3.9 from crates.io. It installs the `tla` binary.

```sh
cargo install tla-checker --version 0.3.9
```

`tla` is a native-Rust explicit-state TLA+ model checker. It reads a `.tla`
spec and an auto-loaded `Spec.cfg` (TLC-style). It checks safety invariants by
default and liveness under `--check-liveness`.

## Layout

```text
spec/
  README.md          this plan
  tla/
    README.md        how to run each model and read the results
    MagicLink.tla    magic-link authentication state machine
    MagicLink.cfg    constants and invariants for MagicLink
    MagicLinkRace.tla  two confirmations racing over one challenge
    MagicLinkRace.cfg  constants and invariants for MagicLinkRace
    Session.tla      session validation lifecycle
    Session.cfg      constants and invariants for Session
    Pow.tla          proof-of-work admission difficulty
    Pow.cfg          constants and invariants for Pow
```

## How to run

Each spec deadlocks at a terminal state (a consumed challenge, an expired
challenge), so pass `--allow-deadlock`.

```sh
tla spec/tla/MagicLink.tla --allow-deadlock
tla spec/tla/Pow.tla --allow-deadlock
```

Both report "No errors found" today.

## What each model covers

The abstraction models control flow and the atomic transaction. It does not
model the token grammar, selector, verifier, HMAC, or Branca. The model assumes
the crypto checks are correct and asks whether the state machine around them is
safe.

### MagicLink.tla

One magic-link challenge and one browser session. It checks these invariants
from the formal-methods roadmap.

| Invariant | Claim | Code anchor |
| --- | --- | --- |
| ML-INV-001 | A consumed challenge was consumed by a POST, never a GET landing. | `begin_magic_link_landing` is side-effect-free |
| ML-INV-002 | At most one session per challenge. | atomic commit guard on `Issued` |
| ML-INV-003 | Consume and session creation are one atomic pair. | `commit_magic_link_authentication` transaction |
| ML-INV-004 | Only a correct selector, verifier, and account binding authenticates. A wrong binding is rejected before any consume. | flow-cookie constant-time binding checks |
| ML-INV-005 | A disabled-user confirm does not burn the challenge. It stays reusable and works after re-enable. | `~userDisabled` guard on the atomic commit |

### MagicLinkRace.tla

Two confirmations race over one challenge. It covers the atomic transaction, an
ambiguous transaction result, and an exact-command retry.

| Invariant | Claim | Code anchor |
| --- | --- | --- |
| ML-INV-002 (concurrent) | At most one session per challenge under racing confirmations and an ambiguous-then-retried commit. No double-spend. | atomic conditional transaction plus the attempt-id retry contract |

### Session.tla

One session record and a moving clock. Validation interleaves with revoke and
expiry.

| Invariant | Claim | Code anchor |
| --- | --- | --- |
| SES-INV-001 | A revoked or expired session never validates. | `authenticate_session` strong read plus TTL checks |

### Pow.tla

One challenge across a set of countries with mutable risk classes. The policy
raises or lowers a country's required difficulty over time. It checks the
difficulty guard and the mint-time monotonicity.

| Invariant | Claim | Code anchor |
| --- | --- | --- |
| POW-INV-001 | An accepted proof met the production floor. | `verify_solution` difficulty floor |
| POW-INV-002 | An accepted proof met the difficulty bound into its challenge. A policy decrease after mint cannot lower the bar. | tag-bound `dif`, `min_difficulty` check |

## What we still need to model

The models cover ML-INV-001..005 (including the concurrent double-spend case),
SES-INV-001, and POW-INV-001..002 (across country risk classes). The next work
items, in rough order:

1. Liveness: a solved challenge under a fair schedule reaches an accepted
   session. Run with `--check-liveness`.
2. Scale the race model to three or more attempts and confirm the state count
   stays tractable.

Each new invariant should link a model action, a code path, and a test, per the
MVP-023 evidence rule.

## Bounds

The constants stay small on purpose. Explicit-state checking explores every
reachable state, so a small bound gives fast, exhaustive coverage of the
interleavings that matter (`MaxTime = 2`, `MaxDiff = 2`). Raise a bound only
when a new action needs more range to show a case.

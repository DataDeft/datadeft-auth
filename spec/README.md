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
  README.md            this plan
  tla/
    README.md          how to run each model and read the results
    MagicLink.tla      magic-link authentication state machine
    MagicLinkRace.tla  two confirmations racing over one challenge
    Session.tla        session validation, refresh, revocation, disable/enable, clock skew
    Session.cfg        validation and refresh (one session, no admin)
    SessionAdmin.cfg   disable, revoke-all, enable (one session, no refresh)
    KeyRotation.tla    first signup during a rolling storage-key rotation
    PowBudget.tla      per-solve PoW budget across nodes (planned)
    Erasure.tla        user erasure (planned; low priority)
    Pow.tla            proof-of-work admission difficulty
    Liveness.tla       happy-path progress
    *.cfg              constants and invariants per model
scripts/spec-mutants.ts  the mutation check (one mutant per invariant)
```

## How to run

```sh
mise run spec           # every model
mise run spec-mutants   # every invariant must catch its mutant
```

Both are part of `mise run verify`. Most models end in terminal states, so
they run with `--allow-deadlock`. `Liveness.tla` does not: see below.

## What each model covers

The abstraction models control flow, clocks, and the atomic transactions. It
does not model the token grammar, selector, verifier, HMAC, or Branca. The
model assumes the crypto checks are correct and asks whether the state machine
around them is safe. The crypto and parsers are covered by vector, tamper, and
property tests in the crates.

### MagicLink.tla

One magic-link challenge and one browser session: ML-INV-001..005 (landing
never consumes, at most one session, consume and session creation together,
wrong binding rejected before any consume, a disabled user's confirm does not
burn the challenge). Disabling a user also ends their session; that is
modeled in `Session.tla`.

`FlowStateRead` models a planned redirect landing mode. It is not in the code
yet.

### MagicLinkRace.tla

Two confirmations race over one challenge, with an ambiguous transaction
result and an exact retry: no double spend.

### Session.tla

True time is separate from each host's clock reading: a reading is
`now + off` with `off` in `0..Skew`, and `Tol` is the code's
`CLOCK_SKEW_TOLERANCE_SECS`. The cookie carries `iat` (absolute bound) and the
Branca timestamp (idle bound); the server row carries `created_at` from the
login host's clock. Ghost variables record ground truth from true time and
true event order at every accept, never from the guard's own readings, so an
invariant fails when a guard is wrong.

`Session.cfg` checks validation and refresh: revoked, past-idle, and
past-absolute sessions never validate; refresh keeps `iat`, never mints past
the absolute lifetime, and only follows a same-request validation.

Both configurations check the shipped re-enable cutoff, which is inclusive
(`WatermarkStrict = FALSE`, since 0.5.0): a session created in the enable's
own second is accepted, so an immediate re-login works. It is safe only
because enable revokes first; the "inclusive cutoff without revoking first"
mutant shows the failure otherwise.

`SessionAdmin.cfg` checks the admin paths with injected revoke failures:
disabled owners never validate, sessions created before the enable watermark
never validate (`Inv_NoAcceptBeforeWatermark`), and no session that existed at
a re-enable validates
afterwards (`Inv_NoPreEnableSurvivor`). That last one failed for the 0.4.1
code (`EnableRevokesFirst = FALSE`); see finding SES-F1 in
[docs/formal-methods.md](../docs/formal-methods.md).

### KeyRotation.tla

Hosts on the old storage key and hosts on the new key (with the old one as
previous) serve the same table during a rolling rotation. One email must never
get two accounts. It failed for the 0.4.1 code (`DualWrite = FALSE`): finding
ROT-F1.

### PowBudget.tla

One solved proof presented to several nodes over its lifetime. The planned
per-solve budget holds (at most N admissions per solve) only with all three
design rules: one shared counter (not per node), counted over the proof's
lifetime (not a window that refills), and failing closed when the limiter is
unavailable. Each rule has a mutant.

### Erasure.tla

Erasing a user during a storage-key rotation, with pending links and
sessions whose revocation runs as a separate, retry-safe step. It holds only
if erasure removes the lookup rows under every key, deletes pending links, and
validation treats an erased owner as inactive at once. Low priority; parked
until erasure is implemented.

### Pow.tla

One challenge, with a difficulty policy that can change after mint (modeled
as per-country classes; the library takes one difficulty from `PowPolicy`, so
classes are the application's concern). An accepted proof met the production
floor and the difficulty bound into its challenge.

Proof-cookie replay within its TTL is allowed by design (POW-INV-003 is not a
library invariant): callers that need single use cap it with
`Verified::tid`.

### Liveness.tla

Happy-path progress, including an ambiguous commit and its retry.
`tla-checker` 0.3.9 has no `WF` fairness and evaluates leads-to on cycles
only, so a stuck state that is a deadlock goes unnoticed under
`--allow-deadlock`. Success is therefore an explicit terminal self-loop
(`Done`) and the model runs without `--allow-deadlock`: any other end state is
reported as a deadlock.

## Mutation check

An invariant that no reachable state can violate proves nothing.
`scripts/spec-mutants.ts` holds one mutant per invariant: an edit that mimics
a plausible bug (a dropped guard, a re-stamped field, the 0.4.1 behaviour of a
fixed finding). Each mutant runs with only its target invariant enabled, and
the script fails unless the checker reports that exact violation.

## Limits

- A model check proves properties of the model within its bounds, not that the
  Rust code matches it. The `model_*_tests` in `datadeft-magic-link-aws` run
  the same invariants against the real services and the fake store.
- Conditional liveness under expiry and disable needs fairness. Run the
  models under TLC for that.
- The bounds are small on purpose (one or two sessions, a few seconds of
  time). Raise a bound only when a new action needs more range.

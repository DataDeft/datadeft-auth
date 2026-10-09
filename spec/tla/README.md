# TLA+ models

See [../README.md](../README.md) for the plan and the invariant catalog.

## Run

```sh
tla MagicLink.tla --allow-deadlock
tla MagicLinkRace.tla --allow-deadlock
tla Session.tla --allow-deadlock
tla Session.tla --config SessionAdmin.cfg --allow-deadlock
tla KeyRotation.tla --allow-deadlock
tla Pow.tla --allow-deadlock
tla Liveness.tla --check-liveness
```

Each command auto-loads the matching `.cfg` unless `--config` names another.
A clean run ends with "Model checking complete. No errors found." and a state
count. A violation prints a numbered trace from the initial state to the bad
state. To see a fixed finding's counterexample, flip its constant:

```sh
tla Session.tla --config SessionAdmin.cfg --allow-deadlock -c EnableRevokesFirst=FALSE
tla KeyRotation.tla --allow-deadlock -c DualWrite=FALSE
```

## Useful flags

| Flag | Use |
| --- | --- |
| `--allow-deadlock` | Allow terminal states. These protocols end. |
| `--list-invariants` | Show the invariants the checker found. |
| `--validate` | Parse and type-check the spec without exploring. |
| `--trace-json FILE` | Write a counterexample trace as JSON. |
| `--check-liveness` | Also check liveness and fairness properties. |
| `-c NAME=VALUE` | Override a constant on the command line. |

## Confirm an invariant has teeth

`mise run spec-mutants` does this for every invariant; see
`scripts/spec-mutants.ts`. To add an invariant, add a mutant that breaks it.

## Constants

| Spec | Constant | Value | Meaning |
| --- | --- | --- | --- |
| MagicLink | `MaxTime` | 2 | Bounded clock for expiry. |
| MagicLinkRace | `Attempts` | `{a1, a2}` | Confirm attempts racing over one challenge. |
| Session | `Idle`, `Abs` | 4, 7 (admin: 2, 3) | Idle and absolute lifetimes. |
| Session | `Tol`, `Skew` | 1, 1 | Code skew tolerance; real clock spread between hosts. |
| Session | `MaxTime` | 10 (admin: 5) | Bound on true time. |
| Session | `EnableRevokesFirst` | TRUE | The fix for SES-F1; FALSE is 0.4.1. |
| KeyRotation | `Procs` | `{p1, p2}` | Signups for one email. |
| KeyRotation | `DualWrite` | TRUE | The fix for ROT-F1; FALSE is 0.4.1. |
| Pow | `Floor`, `Base`, `MaxDiff` | 1, 1, 2 | Difficulty floor, base, bound. |
| Pow | `Countries` | `{c1, c2}` | Policy classes (application-level). |

# TLA+ models

See [../README.md](../README.md) for the plan and the invariant catalog.

## Run

```sh
tla MagicLink.tla --allow-deadlock
tla MagicLinkRace.tla --allow-deadlock
tla Session.tla --allow-deadlock
tla Session.tla --config SessionAdmin.cfg --allow-deadlock
tla KeyRotation.tla --allow-deadlock
tla PowBudget.tla --allow-deadlock
tla AdminRace.tla --allow-deadlock
tla Erasure.tla --allow-deadlock
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
| Session | `WatermarkStrict` | FALSE | The shipped inclusive re-enable cutoff: accept `created >= wm` (0.5.0). TRUE is the 0.4 `created > wm`, used by the SES-F1 mutant. |
| Session | `WatermarkSlack` | 0 | Enable stores `wm = reading + WatermarkSlack`. 0 is the current code. |
| Session | `RevokeMayFail` | TRUE | Revoke-all may stop part way (dependency error). |
| KeyRotation | `Procs` | `{p1, p2}` | Signups for one email. |
| KeyRotation | `DualWrite` | TRUE | The fix for ROT-F1; FALSE is 0.4.1. |
| Pow | `Floor`, `Base`, `MaxDiff` | 1, 1, 2 | Difficulty floor, base, bound. |
| Pow | `Countries` | `{c1, c2}` | Policy classes (application-level). |
| AdminRace | `Admins` | `{a1, a2}` | Admins acting on one user concurrently. |
| AdminRace | `MaxActs` | 2 | Read-then-write actions per admin. |
| AdminRace | `Versioned` | TRUE | Writes are conditional on the version read; FALSE is 0.4's last-write-wins. |
| AdminRace | `DisableAlwaysWrites` | TRUE | A disable of a disabled user still writes and bumps the version; FALSE is a no-op that fences no enable. |
| AdminRace | `RetryOnRace` | TRUE | A disable that lost the version race while the user stayed disabled re-reads and writes again; FALSE reports success unfenced. |
| AdminRace | `MaxRetries` | 2 | Re-reads a disable makes before answering `Conflict`. |
| PowBudget | `Nodes` | `{n1, n2}` | Nodes the one proof is presented to. |
| PowBudget | `Budget` | 2 | Admissions per proof. |
| PowBudget | `Lifetime` | 3 | Ticks the proof is valid. |
| PowBudget | `Window` | 1 | Window length when `OverLifetime = FALSE`. |
| PowBudget | `Shared` | TRUE | One budget counter for all nodes; FALSE is one per node. |
| PowBudget | `OverLifetime` | TRUE | Budget counted over the proof's lifetime; FALSE is a window that refills. |
| PowBudget | `FailClosed` | TRUE | An unavailable limiter denies; FALSE admits uncounted. |
| Erasure | `Users` | `{u1, u2, u3}` | User ids. |
| Erasure | `Links` | `{l1, l2, l3}` | Magic links for the erased email. |
| Erasure | `ErasePendingLinks` | TRUE | The erase write also deletes pending links for the email. |
| Erasure | `ErasedIsInactive` | TRUE | Validation rejects an erased owner at once, like a disabled one. |
| Erasure | `EraseAllKeys` | TRUE | The erase write removes lookup rows under every storage key. |

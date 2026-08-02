# TLA+ models

See [../README.md](../README.md) for the plan and the invariant catalog.

## Run

```sh
tla MagicLink.tla --allow-deadlock
tla MagicLinkRace.tla --allow-deadlock
tla Session.tla --allow-deadlock
tla Pow.tla --allow-deadlock
tla Liveness.tla --check-liveness --allow-deadlock
```

Each command auto-loads the matching `.cfg`. A
clean run ends with "Model checking complete. No errors found." and a state
count. A violation prints a numbered trace from the initial state to the bad
state.

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

An invariant that no reachable state can violate is worthless. Break the model
on purpose and confirm the checker reports the counterexample.

Example for POW-INV-002. In `Pow.tla`, the `SolveVerify` action accepts work
against the bound difficulty:

```text
w >= mintedDiff
```

Change it to the current effective difficulty:

```text
w >= Effective
```

Run `tla Pow.tla --allow-deadlock`. The checker finds a trace: a challenge
mints at difficulty 2, a policy update lowers the country requirement, and a
proof with work 1 passes. That violates `Inv002_AcceptedMeetsMint`. Restore the
guard and the run is clean again.

## Constants

| Spec | Constant | Value | Meaning |
| --- | --- | --- | --- |
| MagicLink | `MaxTime` | 2 | Bounded clock for expiry. |
| MagicLinkRace | `Attempts` | `{a1, a2}` | Confirm attempts racing over one challenge. |
| Session | `TTL` | 1 | Session absolute lifetime. |
| Session | `MaxTime` | 3 | Bounded clock. |
| Pow | `Floor` | 1 | Production difficulty floor. |
| Pow | `Base` | 1 | Configured base difficulty. |
| Pow | `MaxDiff` | 2 | Upper bound on difficulty values. |
| Pow | `Countries` | `{c1, c2}` | Country risk classes. |

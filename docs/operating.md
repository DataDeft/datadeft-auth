# Operating model

## Local development first

Initial development uses local path dependencies, not GitHub, crates.io, or private registries.

Example consuming-project dependency:

```toml
[dependencies]
dd-pow-core = { path = "../datadeft-auth/crates/dd-pow-core" }
dd-magic-link-core = { path = "../datadeft-auth/crates/dd-magic-link-core" }
```

## Task runner

Use `mise` for repository tasks.

Common tasks should exist:

```sh
mise run fmt
mise run check
mise run test
mise run clippy
mise run audit
mise run verify
```

`verify` should run formatting, clippy, tests, docs checks, and the configured dependency audit.

Recommended commands behind tasks:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo deny check
```

## Development loop

1. Work in the auth library repo.
2. Run `mise run verify`.
3. Use local path deps from a consuming project.
4. Run the consuming project tests.
5. Only then consider tagging or publishing.

## Multi-agent library model

This repo is developed with a single-orchestrator, one-library-per-agent model.

- The orchestrator owns repo-wide choices, user questions, dependency boundaries, merge order, and final acceptance.
- Each implementation agent owns exactly one crate or package at a time.
- Agents must not edit another agent's crate without orchestrator approval.
- Only one writer may modify a given crate/worktree at once.
- If multiple agents work concurrently, use separate git branches or worktrees.
- Cross-crate public API changes require a short handoff note before implementation.

Agent ownership:

| Agent lane | Owns | Primary output |
| --- | --- | --- |
| Repo setup agent | workspace root, CI, licensing, docs, `mise` tasks | standalone buildable repo |
| PoW core agent | `crates/dd-pow-core` | deterministic PoW core |
| Auth token core agent | `crates/dd-auth-token-core` | reusable session/token/cookie primitives |
| Magic-link core agent | `crates/dd-magic-link-core` | IO-free magic-link primitives |
| Magic-link service agent | `crates/dd-magic-link-service` | trait-based request/consume orchestration |
| Axum adapter agent | `crates/dd-magic-link-axum` | HTTP integration and response helpers |
| AWS adapter agent | `crates/dd-magic-link-aws` | DynamoDB/SES adapters and fakes |
| Browser client agent | `packages/dd-protect-client` | optional browser PoW client |
| Example/integration agent | `examples/axum-magic-link` and consuming-project integration | proof that extraction works |

## Agent work packet

Every agent receives a packet with:

```text
Goal:
Owned paths:
Read-only context paths:
Allowed dependencies:
Forbidden dependencies:
Public API expectations:
Tests required:
Validation commands:
Escalation questions:
```

Every agent returns a handoff with:

```text
Changed files:
Public API added/changed:
Security-sensitive behavior:
Validation run:
Validation not run:
Open questions:
Follow-up work:
```

## Cross-crate change protocol

Before changing another crate's public API, write a short proposal:

```text
Producer crate:
Consumer crate(s):
Proposed type/function/trait change:
Reason:
Security impact:
Migration impact:
Tests needed:
```

The orchestrator accepts, revises, or rejects the proposal before implementation.

## Merge order

1. Phase 0 repo setup.
2. `dd-pow-core`.
3. `dd-auth-token-core`.
4. `dd-magic-link-core`.
5. `dd-magic-link-service`.
6. `dd-magic-link-axum`.
7. `dd-magic-link-aws`.
8. `dd-protect-client` and examples, if in scope.
9. Consuming-project integration.
10. Publish preparation.

A downstream agent may scaffold early, but should not lock public API against unreviewed upstream code.

## Versioning

Before public publishing, use `0.x` versions.

Recommended early versions:

```text
0.1.0 - first local extraction
0.2.0 - first second-project integration
0.3.0 - API cleanup after integration feedback
1.0.0 - stable public API, after security/provenance audit
```

## Commit policy

- Small focused commits.
- One crate or one behavior change per commit where practical.
- Commit generated lockfile changes.
- Do not commit secrets.
- Do not commit local `.env` files.
- Include validation notes in commit/PR descriptions.

## Release policy

Do not publish to crates.io until:

- provenance is audited
- MIT `LICENSE` file exists
- docs exist
- examples compile
- public API is reviewed
- dependency/license/vulnerability audit passes
- `cargo publish --dry-run` passes for every publishable crate

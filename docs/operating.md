# Operating model

## Local development

Use local path dependencies during initial work.

Example consuming-project dependency:

```toml
[dependencies]
datadeft-pow-core = { path = "../datadeft-auth/crates/datadeft-pow-core" }
datadeft-magic-link-core = { path = "../datadeft-auth/crates/datadeft-magic-link-core" }
```

## Task runner

Use `mise` tasks. Do not hand-type long command chains.

Common tasks:

```sh
mise run fmt
mise run check
mise run test
mise run clippy
mise run audit
mise run verify
```

`verify` runs format, Clippy, tests, docs, and dependency audit.

Recommended commands behind tasks:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo deny check
```

## Development loop

1. Work in this repository.
2. Run `mise run verify`.
3. Use local path deps from a consuming project.
4. Run consuming project tests.
5. Tag or publish only after those checks pass.

## Multi-agent model

Use one orchestrator and one owner for each crate.

The orchestrator owns repo-wide decisions. The orchestrator owns user questions, dependency boundaries, merge order, and acceptance.

Each implementation agent owns one crate or package. Agents must not edit another crate without orchestrator approval.

Only one writer may modify a crate or worktree at a time. Use separate worktrees for concurrent implementation.

Public API changes across crates need a short proposal first.

## Agent ownership

| Lane | Owns | Output |
| --- | --- | --- |
| Repo setup | Workspace root, CI, licensing, docs, tasks | Buildable repo |
| PoW core | `crates/datadeft-pow-core` | Deterministic PoW core |
| Auth token core | `crates/datadeft-auth-token-core` | Token and cookie primitives |
| Magic-link core | `crates/datadeft-magic-link-core` | Magic-link primitives |
| Magic-link service | `crates/datadeft-magic-link-service` | Trait-based auth flow |
| Axum adapter | `crates/datadeft-magic-link-axum` | HTTP integration |
| AWS adapter | `crates/datadeft-magic-link-aws` | DynamoDB and SES adapters |
| Browser client | `packages/dd-protect-client` | Browser PoW client |
| Example | `examples/axum-magic-link` | Integration proof |

## Work packet

Each agent receives this packet.

```text
Goal:
Owned paths:
Read-only context:
Allowed dependencies:
Forbidden dependencies:
Public API expectations:
Tests required:
Validation commands:
Escalation questions:
```

Each agent returns this handoff.

```text
Changed files:
Public API added or changed:
Security-sensitive behavior:
Validation run:
Validation not run:
Open questions:
Follow-up work:
```

## Cross-crate changes

Write a proposal before you change another crate public API.

```text
Producer crate:
Consumer crates:
Proposed type, function, or trait change:
Reason:
Security impact:
Migration impact:
Tests needed:
```

The orchestrator accepts, changes, or rejects the proposal.

## Merge order

1. Repo setup.
2. `datadeft-pow-core`.
3. `datadeft-auth-token-core`.
4. `datadeft-magic-link-core`.
5. `datadeft-magic-link-service`.
6. `datadeft-magic-link-axum`.
7. `datadeft-magic-link-aws`.
8. `dd-protect-client` and examples.
9. Consuming-project integration.
10. Publish preparation.

A downstream agent may scaffold early. It must not lock public API against unreviewed upstream code.

## Versioning

Use `0.x` versions before public publishing.

Recommended early versions:

```text
0.1.0 - first local extraction
0.2.0 - first second-project integration
0.3.0 - API cleanup after integration feedback
1.0.0 - stable public API after audits
```

## Commit policy

- Make small focused commits.
- Change one crate or one behavior per commit where practical.
- Commit generated lockfile changes.
- Do not commit secrets.
- Do not commit local `.env` files.
- Include validation notes in commit or PR text.

## Release policy

Do not publish until the repo meets these conditions.

1. Provenance audit passed.
2. Istvan has approved MIT OR Apache-2.0 and the bundled license texts.
3. Docs exist.
4. Examples compile.
5. Public API review passed.
6. Dependency audit passed.
7. License audit passed.
8. Workspace archive verification passed for every crate; per-crate registry dry-runs pass once their dependencies exist.
9. Both Istvan and Roland approved the PR; registry bootstrap and OIDC setup follow [releasing.md](releasing.md).

# Operating model

## Local development

1. Work in this repository.
2. Run `mise run verify`.
3. To test in a consuming project, use local `path` dependencies.
4. Run the tests of the consuming project.

Releases go through release-please. See [releasing.md](releasing.md).

## Task runner

Use `mise` tasks. Do not type long command chains by hand.

```sh
mise run fmt
mise run check
mise run test
mise run clippy
mise run audit
mise run verify
```

`verify` runs fmt-check, clippy, test, test-default-features, docs, audit,
token-core-guard, ts-verify, spec, spec-mutants, release-check, and
workflow-check.

Other tasks:

| Task | What it does | In `verify` |
| --- | --- | --- |
| `spec`, `spec-mutants` | Check the TLA+ models and prove each invariant can fail. | Yes |
| `fuzz` | Fuzz every untrusted-input parser for 60 s each. It needs nightly Rust and `cargo install cargo-fuzz`. | No |
| `dynamodb-local-test` | Run integration tests against DynamoDB Local. It needs Docker. | No |

## Agent ownership

[AGENTS.md](../AGENTS.md) defines the multi-agent model. Only one writer
changes a crate at a time. All work goes to `main`. Do not use feature
branches or worktrees.

| Lane | Owns | Output |
| --- | --- | --- |
| Repo setup | Workspace root, CI, licensing, docs, tasks | Buildable repo |
| PoW core | `crates/datadeft-pow-core` | Deterministic PoW core |
| PoW Axum | `crates/datadeft-pow-axum` | PoW HTTP glue, proof cookie, `admit_proof` |
| Auth token core | `crates/datadeft-auth-token-core` | Token and cookie primitives |
| Magic-link core | `crates/datadeft-magic-link-core` | Magic-link primitives |
| Magic-link service | `crates/datadeft-magic-link-service` | Trait-based auth flow |
| Axum adapter | `crates/datadeft-magic-link-axum` | HTTP integration |
| AWS adapter | `crates/datadeft-magic-link-aws` | DynamoDB and SES adapters |
| Browser client | `@datadeft/protect-client` (`packages/dd-protect-client`) | Browser PoW client |
| Example | `examples/axum-magic-link` | Integration proof |

## Work packet

Each agent receives this packet:

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

Each agent returns this handoff:

```text
Changed files:
Public API added or changed:
Security-sensitive behavior:
Tests added or updated:
Validation run:
Validation not run:
Open questions:
Follow-up work:
```

## Cross-crate changes

Before you change the public API of another crate, write a proposal:

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

## Versioning

The library is pre-1.0. Breaking changes bump the minor version. See
[CHANGELOG.md](../CHANGELOG.md). The project publishes no pre-release
versions.

## Commit policy

- Make small, focused commits.
- Where practical, change one crate or one behavior per commit.
- Commit generated lockfile changes.
- Do not commit secrets or local `.env` files.
- Include validation notes in the commit or PR text.

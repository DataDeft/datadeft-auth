# Operating model

## Local development

Use local path dependencies during initial work. Add them in a consuming
project:

```toml
[dependencies]
datadeft-pow-core = { path = "../datadeft-auth/crates/datadeft-pow-core" }
datadeft-magic-link-core = { path = "../datadeft-auth/crates/datadeft-magic-link-core" }
```

Development loop:

1. Work in this repository.
2. Run `mise run verify`.
3. In a consuming project, use the local path dependencies.
4. Run the consuming project's tests.
5. After those checks pass, tag or publish.

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

The core commands behind the tasks:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo deny check
```

## Multi-agent model

- Use one orchestrator and one owner for each crate.
- The orchestrator owns repo-wide decisions: user questions, dependency
  boundaries, merge order, and acceptance.
- Each implementation agent owns one crate or package. It must not edit
  another crate without orchestrator approval.
- Only one writer may change a crate at a time. All work goes to `main`. Do
  not use feature branches or worktrees.
- Public API changes across crates need a short proposal first (see
  [Cross-crate changes](#cross-crate-changes)).

## Agent ownership

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

## Merge order

1. Repo setup.
2. `datadeft-pow-core`.
3. `datadeft-auth-token-core`.
4. `datadeft-pow-axum`.
5. `datadeft-magic-link-core`.
6. `datadeft-magic-link-service`.
7. `datadeft-magic-link-axum`.
8. `datadeft-magic-link-aws`.
9. `@datadeft/protect-client` and examples.
10. Consuming-project integration.
11. Publish preparation.

A downstream agent may scaffold early. It must not lock its public API against
unreviewed upstream code.

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

## Release policy

Before you publish, make sure that all of these conditions are true:

1. The provenance audit passed.
2. The maintainers have approved the MIT license (2026-10-08).
3. The docs exist.
4. The examples compile.
5. The public API review passed.
6. The dependency audit passed.
7. The license audit passed.
8. The workspace archive verification passed for every crate. Each per-crate
   registry dry run passes when its dependencies exist.
9. Two maintainers approved the PR. The registry bootstrap and the OIDC setup
   follow [releasing.md](releasing.md).

# Operating model

## Feature justification

Every feature must pass the [feature-justification gate](feature-justification.md)
before implementation: establish the problem, inspect existing capabilities,
identify the gap, choose the smallest solution, account for costs, and define
acceptance criteria. Obtain project-owner or explicitly delegated approval of
the justification and scope before coding. Apply the same review to in-progress
features before merge; release-plan inclusion is not sufficient approval.

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
mise run ts-fmt
mise run check
mise run test
mise run clippy
mise run audit
mise run verify
```

`verify` runs fmt-check, clippy, test, test-default-features, docs, audit,
token-core-guard, ts-verify, elixir-verify, spec, spec-mutants, release-check, and
workflow-check, plus shared Rust/Elixir compatibility vectors. The Elixir
gate requires Elixir >= 1.16 / OTP >= 26 and the workspace Rust toolchain to
source-build the owner-approved tiny crypto NIF. CI provisions the runtime pairs
and native source toolchain; clean precompiled consumers remain a release gate. See
[`hex/datadeft_auth`](../hex/datadeft_auth/README.md).

`ts-verify` checks every TypeScript and JavaScript file against Prettier,
type-checks and lints the workspace `scripts/`, then runs the npm package gate.
`mise run ts-fmt` applies the formatting.

Other tasks:

| Task | What it does | In `verify` |
| --- | --- | --- |
| `spec`, `spec-mutants` | Check the TLA+ models and prove each invariant can fail. | Yes |
| `fuzz` | Fuzz every untrusted-input parser for 60 s each. It needs nightly Rust and `cargo install cargo-fuzz`. | No |
| `dynamodb-local-test` | Rust integration tests against DynamoDB Local. It needs Docker. | No |
| `dynamodb-compatibility-test` | Mixed Rust/Elixir account lookup and shared counter/race tests. It needs Docker. | No |
| `compatibility-test` | Shared storage-HMAC and email vectors asserted by Rust and Elixir. | Yes |

## Agent ownership

[AGENTS.md](../AGENTS.md) defines the multi-agent model. Only one writer
changes a crate at a time. The default is work on `main`, without feature
branches or worktrees. Owner-approved exception: ongoing Elixir 0.8 work uses
`feat/elixir-0.8` and a draft PR, requested in the implementation conversation.
Its already-landed foundation remains on `main`; no revert/history rewrite is
part of that request. No worktree is needed.

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
| Elixir implementation | `hex/` | Native Elixir package, tests and examples; implementation in progress |
| Example | `examples/axum-magic-link` | Integration proof |

## Work packet

Each agent receives this packet:

```text
Goal:
Approved feature justification and scope (reference, when implementing a feature):
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

Cross-crate API review is additional to the feature-justification gate, not a
substitute for it. Before you change the public API of another crate, write a
proposal:

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

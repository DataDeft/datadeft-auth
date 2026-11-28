# Elixir 0.8.0 release readiness

**Decision: not release-ready. Do not publish or mark the implementation PR ready
for release yet.** This is a feature-completeness decision, not a CI failure.

## PR and version status

- [PR #45](https://github.com/DataDeft/datadeft-auth/pull/45) is the **draft
  implementation PR** for the entire 0.8 scope, not a generated release PR.
- It includes foundation commits through `211b3e3`, originally pushed to `main`.
  The owner approved moving all 0.8 work into #45 before resetting `main` to the
  pre-0.8 baseline (`ad09ae8`) plus the unrelated URL security fix (`e4ce914`).
  The original 0.8 commits remain intact and reachable on `feat/elixir-0.8`.
- At this assessment, the open release PR is
  [#44, release 0.7.1](https://github.com/DataDeft/datadeft-auth/pull/44), **not 0.8.0**.
- The latest published repository release is 0.7.0. Package/workspace version
  stays aligned at 0.7.0 until the approved release process prepares a bump.
- No 0.8.0 Hex release or native precompiled distribution has been published by
  this work. A future release PR must be created through the release process,
  after implementation acceptance; do not rename #44 to imply readiness.

## Evidence: green current foundation

GitHub CI run [46017758099](https://github.com/DataDeft/datadeft-auth/actions/runs/46017758099)
passed for #45 at commit `4dea18f`:

| Check | Result |
| --- | --- |
| Workspace `verify` job, including its configured DynamoDB/release-smoke/package steps | Passed |
| Debian, x86-64, Elixir 1.16.3 / OTP 26 | Passed |
| Debian, AArch64, Elixir 1.19 / OTP 28 | Passed |
| Alpine, x86-64, Elixir 1.19 / OTP 28 | Passed |
| Alpine, AArch64, Elixir 1.16.3 / OTP 26 | Passed |

These matrix checks **source-build the NIF from the repository**. They do not
prove precompiled artifact downloads, clean Hex archive/source fallback,
complete login flows or production readiness. Later commits need their own green
checks; the cited run is evidence for that specific revision.

The documented email/Branca examples were executed successfully. The foundation
also has exact Rust vectors, crypto tamper/canonicality tests, atomic transaction
and mixed-language DynamoDB contention tests. See [USAGE.md](USAGE.md) for what
can actually be used now, and [IMPLEMENTATION.md](IMPLEMENTATION.md) for details.

## Release blockers

| Area | Still required |
| --- | --- |
| Cookie/crypto parity | Confirm/session interop and rotating keyrings pass; proof bodies, full PoW and their bidirectional vectors remain |
| Authentication services | Session validation/refresh/revoke and country policy are implemented; request, scanner-safe landing/flow state/confirmation, locale and independent proof admission remain |
| Repository/admin behavior | Shared session reads/revocation pass; audited administration, enable/disable race safety and distinct-challenge cross-language account-creation contention remain |
| Production AWS | DynamoDB transport/signing/credentials/error mapping, SES and Secrets Manager integration |
| HTTP/application delivery | Plug parsing/refusal/cookie/CSRF policy, independent PoW middleware, Bandit example and end-to-end/browser interoperability |
| Native distribution | Checksummed precompiled artifacts, clean archive consumers and source-build fallback without broken repository-relative Cargo paths |
| Acceptance/release | Independent security/API review, full final verification, supported artifact matrix, version/release metadata and release notes |

## Ready means

1. Complete the approved scope and acceptance checklist, or obtain explicit
   owner approval for a reduced release scope. Do not equate a green primitive
   slice with a functionally complete authentication library.
2. Prove Rust/Elixir wire and shared-storage interoperability for the completed
   workflows, including failure, replay, expiry, rotation and race behavior.
3. Exercise a real consuming Plug/Bandit app and clean native distribution paths.
4. Complete independent security/API review and all final release gates.
5. Only then mark #45 ready for review/merge and prepare the 0.8.0 release via the
   repository's release process. Publication is a separate explicit action.

This document is a status assessment, not approval to merge, bump or publish.

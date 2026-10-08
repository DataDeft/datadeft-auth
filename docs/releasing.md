# Registry releases

This prepares `0.3.0` as the first registry release. `v0.2.0` already exists as a
git release; never move that tag. All seven Rust crates and the npm client use
one version and one release PR. No package has been published by this work.

## Approval and one-time setup (maintainers)

Before the first publication:

1. Confirm the seven `datadeft-*` names below and `@datadeft/protect-client`.
   The license is MIT (approved 2026-10-08).
2. Obtain **approval from two maintainers** on the implementation PR and
   every release PR. Configure branch protection for two approvals and verify
   the identities before merging. A CODEOWNERS list or an environment with two
   reviewers does not require both people to approve; GitHub environments
   accept one of their configured reviewers. Do not substitute that for the
   two PR approvals.
3. Create the npm `datadeft` organization, add the maintainers, enable account
   and organization 2FA, and ensure publishing rights for the scope. Use
   maintainer accounts with 2FA on GitHub/crates.io as supported.
4. Approve making this repository public, or approve a different public source
   repository and update the package/workflow identity consistently. It is
   currently private. **npm provenance requires public source**, even for a
   public package. Publishing crates already makes their bundled source public.
   This preparation does not change repository visibility.
5. Enable Actions to create PRs under repository Actions settings. Keep the
   built-in `GITHUB_TOKEN`; no PAT, npm token, or crates.io token belongs in
   repository secrets. For bot-created PRs, a maintainer may need to select
   **Approve workflows to run** before CI starts.
6. Create the GitHub environment **`registry-release`** with required maintainer
   review, prevent self-review where supported, and restrict deployment to
   protected `v*` tags. Protect release tags against unauthorized creation,
   deletion, and replacement. Leave the repository variable
   **`REGISTRY_PUBLISH_ENABLED` unset** until bootstrap and sign-offs are complete.

## First-publish bootstrap is a separate, manual approval

The registries currently require the package to exist before a trusted
publisher can be configured. crates.io explicitly requires an API token for
initial publication; npm trust also requires an existing package. Therefore
an entirely OIDC-only first publication is not currently possible. See the
[crates.io prerequisites](https://crates.io/docs/trusted-publishing) and
[npm trust prerequisites](https://docs.npmjs.com/cli/v11/commands/npm-trust/).

After the approved release is tagged, a maintainer must bootstrap the real reviewed
packages from that exact tag using a local, narrowly scoped, short-lived
crates.io credential and interactive npm login/2FA. Do not create placeholder
packages or put bootstrap credentials in CI. Run the checks below and publish
the crates one at a time in this order, dry-running each immediately before its
upload; each newly published dependency then becomes resolvable for the next:

1. `datadeft-auth-token-core`
2. `datadeft-pow-core`
3. `datadeft-pow-axum`
4. `datadeft-magic-link-core`
5. `datadeft-magic-link-service`
6. `datadeft-magic-link-aws`
7. `datadeft-magic-link-axum`

AWS precedes magic-link Axum because the latter's documentation tests use the
AWS crate's SDK-free fakes. The example application remains `publish = false`.
The authoritative order is in `scripts/registry-release.ts`.

Build and pack the npm client from the same tag before its interactive public
publish. A local bootstrap publication cannot carry the requested GitHub OIDC
provenance. If provenance is mandatory on the very first npm version, stop and
approve a separate bootstrap design; do not silently remove `--provenance` from
CI. Subsequent releases use the prepared OIDC/provenance workflow. Revoke the
local bootstrap credential when done. Do not rerun automated publication for
an already uploaded version; registry versions are immutable.

## Registry trusted-publisher configuration

Configure each of the seven crates in crates.io **Settings → Trusted
Publishing**, and the npm package in **Settings → Trusted publishing**:

| Field | Exact value |
| --- | --- |
| Provider | GitHub Actions |
| Repository owner / organization | `DataDeft` |
| Repository | `datadeft-auth` |
| Workflow filename | `release.yml` |
| GitHub environment | `registry-release` |

Enter the filename only, without `.github/workflows/`. These names must match
case and spelling. Use GitHub-hosted runners. On npm explicitly enable the
publisher's **direct `npm publish`** permission; stage-only permission cannot
run this workflow. After configuration, select **Require two-factor
authentication and disallow tokens** for npm publishing access.

npm currently expires a new publisher configuration if its first successful
publish does not happen within two days. Create the configurations close to
the next approved release (or recreate them if expired). See
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

Only after the setup is verified, set the repository variable
`REGISTRY_PUBLISH_ENABLED=true`. It is a non-secret opt-in switch, not a
credential. The environment remains the human approval gate for uploads.

## Verification and release flow

Use these tasks on a clean, committed checkout:

```sh
mise run verify
mise run msrv
mise run workflow-check
mise run package-crates
mise run crates-dry-run
```

`verify` includes Rust formatting, Clippy, tests, docs, cargo-deny, API guards,
release metadata checks, the five TLA+ safety/liveness models, and the npm build,
tests, dry-run, and isolated packed-consumer checks. `msrv` requires
`rustup toolchain install 1.88.0 --profile minimal` once.

`package-crates` uses current stable Cargo's workspace staging registry to
package and build all seven archives with all features before any public
upload. Individual `cargo publish --dry-run` calls cannot resolve unpublished
renamed dependencies from crates.io; the dry-run task tries every crate and
reports each failure. Do not bypass archive verification or remove dependency
versions to hide that bootstrap limitation.

1. Merge conventionally named changes after both PR approvals.
2. `release-please.yml` opens/updates a single release PR using `GITHUB_TOKEN`.
   It updates `version.txt`, workspace Cargo version and dependency versions,
   Cargo.lock, npm package.json and Bun's lockfile, and CHANGELOG.md. Keep these
   versions synchronized. Use `mise run js-lock` when changing JS dependencies;
   it normalizes Bun's JSONC output for release-please's strict JSON updater.
3. Approve any pending bot-created CI runs, review the full release PR, and
   obtain two maintainer approvals before merge.
4. Release-please creates the matching `vX.Y.Z` tag/release. Since a tag created
   by `GITHUB_TOKEN` does not trigger a push workflow, it explicitly dispatches
   `release.yml` on that tag. Human-created release tags also trigger it.
   [GitHub documents this event behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
5. The release workflow validates the tag/version and ancestry on main, runs
   verification and archive builds, and waits for environment approval.
   crates.io authentication happens after compilation, then crates publish in
   dependency order; Cargo waits for index availability. The npm job follows
   with `npm publish --provenance --access public --ignore-scripts`.
6. Confirm all registry versions and npm provenance before telling consumers to
   update. No consumer repository is modified by this release tooling.

The workflow uses Node 24 (npm 11.5.1+ is required for OIDC). Action references
are pinned to commit IDs. OIDC permission is restricted to publishing jobs;
crates.io's temporary token is revoked by the auth action's post-step. Checkout
credentials are not persisted in publishing jobs.

For a partial publication, stop and identify the last successful package.
Do not overwrite or automatically skip an existing version: inspect the
uploaded artifact and obtain an approved recovery plan for the remaining
packages. A manual workflow dispatch must select the exact release tag;
branch dispatches do not publish.

## Public-source review

`docs/security.md` was reviewed for publication in this change. It contains
security policy, architecture, synthetic examples, and placeholder key fields;
no production secret, credential, cookie capture, or customer data was found
there. Disclosure of that design is intentional: source secrecy is not a
security boundary. This is not a replacement for the separate security review
or the required provenance sign-off.

Rust tarballs allow only sources, tests (including deterministic vectors),
README, and license texts, plus Cargo-generated metadata/lockfiles. npm packing
asserts the exact seven-file distribution (two JS, two declarations, README,
package.json, and the license). `docs/security.md` is linked from crate READMEs
rather than bundled; do not change repository visibility before its review and
approval are complete.

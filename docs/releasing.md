# Registry releases

All seven Rust crates and the npm client share one version and one release PR.
The registries hold `0.4.0` and `0.4.1`; `0.5.0` is next. No
release-candidate or other pre-release versions are published: consumers test
an unpublished version via a git ref. Never move a release tag.

## Approval and one-time setup (maintainers)

Done for `0.4.0`; kept for reference and for new maintainers. Before the first
publication:

1. Confirm the seven `datadeft-*` names below and `@datadeft/protect-client`.
   The license is MIT (approved 2026-10-08).
2. Get **approval from two maintainers** on the implementation PR and on every
   release PR. Configure branch protection for two approvals and verify the
   identities before merging. CODEOWNERS or a two-reviewer environment does
   not replace this: an environment accepts any one of its reviewers.
3. Create the npm `datadeft` organization and add the maintainers. Enable
   account and organization 2FA, and give the maintainers publishing rights
   for the scope. Use maintainer accounts with 2FA on GitHub and crates.io
   where supported.
4. Keep the source repository public. **npm provenance requires public
   source**, even for a public package. To publish from a different public
   repository, update the package and workflow identity to match. Publishing
   crates already makes their bundled source public.
5. In the repository Actions settings, allow Actions to create PRs. Keep the
   built-in `GITHUB_TOKEN`. No PAT, npm token, or crates.io token belongs in
   repository secrets. For bot-created PRs, a maintainer may need to select
   **Approve workflows to run** before CI starts.
6. Create the GitHub environment **`registry-release`**. Require maintainer
   review, prevent self-review where supported, and restrict deployment to
   protected `v*` tags. Protect release tags against unauthorized creation,
   deletion, and replacement. Leave the repository variable
   **`REGISTRY_PUBLISH_ENABLED` unset** until bootstrap and sign-offs are
   complete.

## First-publish bootstrap is a separate, manual approval

Done for `0.4.0`. Applies again only to a new package name.

An OIDC-only first publication is not currently possible. Both registries
require the package to exist before you can configure a trusted publisher, and
crates.io requires an API token for the first upload. See the
[crates.io prerequisites](https://crates.io/docs/trusted-publishing) and
[npm trust prerequisites](https://docs.npmjs.com/cli/v11/commands/npm-trust/).

After the approved release is tagged, a maintainer bootstraps the real,
reviewed packages from that exact tag. Use a local, narrowly scoped,
short-lived crates.io credential and an interactive npm login with 2FA. Do not
create placeholder packages or put bootstrap credentials in CI. Run the checks
below, then publish the crates one at a time in this order, dry-running each
just before its upload. Each published crate becomes resolvable for the next.

1. `datadeft-auth-token-core`
2. `datadeft-pow-core`
3. `datadeft-pow-axum`
4. `datadeft-magic-link-core`
5. `datadeft-magic-link-service`
6. `datadeft-magic-link-aws`
7. `datadeft-magic-link-axum`

`datadeft-magic-link-aws` comes before `datadeft-magic-link-axum` because the
Axum crate's documentation tests use the AWS crate's SDK-free fakes. The
example application stays `publish = false`. The authoritative order is in
`scripts/registry-release.ts`.

Then build and pack the npm client from the same tag and publish it
interactively as public. A local bootstrap cannot carry GitHub OIDC
provenance. If provenance is mandatory on the very first npm version, stop and
approve a separate bootstrap design; do not silently remove `--provenance`
from CI. Later releases use the prepared OIDC/provenance workflow. Revoke the
local bootstrap credential when done. Registry versions are immutable: never
rerun automated publication for an already uploaded version.

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

Enter the filename only, without `.github/workflows/`; case and spelling must
match. Use GitHub-hosted runners. On npm, enable the publisher's **direct `npm
publish`** permission (stage-only cannot run this workflow), then select
**Require two-factor authentication and disallow tokens**.

npm expires a new publisher configuration if its first successful publish
does not happen within two days. Create the configurations close to the next
approved release, or recreate them if they expire. See
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

Only after you verify the setup, set the repository variable
`REGISTRY_PUBLISH_ENABLED=true`. It is a non-secret opt-in switch, not a
credential. The environment remains the human approval gate for uploads.

## Verification and release flow

Run these tasks on a clean, committed checkout:

```sh
mise run verify
mise run msrv
mise run workflow-check
mise run package-crates
mise run crates-dry-run
```

- `verify` runs Rust formatting, Clippy, tests, default-feature tests
  (`test-default-features`), docs, cargo-deny, the API guards, release
  metadata checks, the nine TLA+ safety and liveness models (ten configs,
  `spec`), the 44 spec mutants (`spec-mutants`), and the npm build, tests,
  dry run, and isolated packed-consumer checks.
- `msrv` needs `rustup toolchain install 1.88.0 --profile minimal` once.
- `package-crates` uses current stable Cargo's workspace staging registry. It
  packages and builds all seven archives with all features before any public
  upload.
- `crates-dry-run` tries every crate and reports each failure. A single
  `cargo publish --dry-run` cannot resolve unpublished renamed dependencies
  from crates.io. Do not bypass archive verification or remove dependency
  versions to hide this bootstrap limitation.

Release steps:

1. Merge conventionally named changes after both PR approvals.
2. `release-please.yml` opens or updates a single release PR using
   `GITHUB_TOKEN`. It updates `version.txt`, the workspace Cargo version and
   dependency versions, `Cargo.lock`, the npm `package.json` and Bun's
   lockfile, and `CHANGELOG.md`. Keep these versions synchronized. When you
   change JS dependencies, use `mise run js-lock`: it normalizes Bun's JSONC
   output for release-please's strict JSON updater.
3. Approve any pending bot-created CI runs. Review the full release PR and get
   two maintainer approvals before merge.
4. Release-please creates the `vX.Y.Z` tag and release, then dispatches
   `release.yml` on that tag, because a tag created by `GITHUB_TOKEN` does not
   trigger a push workflow. Human-created release tags also trigger it. See
   [GitHub's event behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
5. The release workflow checks the tag, the version, and ancestry on main. It
   runs verification and archive builds, then waits for environment approval.
   crates.io authentication happens after compilation. The crates then
   publish in dependency order, and Cargo waits for index availability. The
   npm job follows with `npm publish --provenance --access public
   --ignore-scripts`.
6. Confirm all registry versions and npm provenance before you tell consumers
   to update. The release tooling modifies no consumer repository.

The workflow uses Node 24 (OIDC needs npm 11.5.1 or newer) and pins actions
to commit IDs. Only the publishing jobs get OIDC permission, and they do not
persist checkout credentials. The auth action's post-step revokes crates.io's
temporary token.

If a publication is partial, stop and identify the last successful package.
Do not overwrite or automatically skip an existing version. Inspect the
uploaded artifact and get an approved recovery plan for the remaining
packages. A manual workflow dispatch must select the exact release tag;
branch dispatches do not publish.

## Public-source review

`docs/security.md` was reviewed for publication. It contains security policy,
architecture, synthetic examples, and placeholder key fields. No production
secret, credential, cookie capture, or customer data was found. Disclosing the
design is intentional: source secrecy is not a security boundary. This review
does not replace the separate security review or the required provenance
sign-off.

Rust tarballs allow only sources, tests (including deterministic vectors),
README, and license texts, plus Cargo-generated metadata and lockfiles. npm
packing asserts the exact seven-file distribution: two JS files, two
declaration files, README, `package.json`, and the license. Crate READMEs link
`docs/security.md` rather than bundle it.

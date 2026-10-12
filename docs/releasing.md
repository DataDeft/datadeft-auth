# Registry releases

All seven Rust crates and the npm client share one version and one release PR.
The registries hold `0.4.0`, `0.4.1` and `0.5.0`. The project publishes no
release-candidate or other pre-release versions. Consumers test an unpublished
version through a git ref. Never move a release tag.

CI publishing is not enabled yet: the repository variable
`REGISTRY_PUBLISH_ENABLED` is unset and the `registry-release` environment
does not exist. The release workflow therefore runs `verify` and skips both
upload jobs. Until a maintainer completes the setup below, publish by hand
([Manual publish](#manual-publish)).

## Manual publish

Run these steps after the release PR is merged and release-please has created
the `vX.Y.Z` tag. Paste each block separately and check it before the next.

```fish
# 1. Prepare and check the tagged release.
git fetch --tags
git checkout vX.Y.Z
rm -rf target/package
mise run verify; and mise run package-crates
```

```fish
# 2. Publish the crates in dependency order. The loop stops at a failure.
cargo login
for c in datadeft-auth-token-core datadeft-pow-core datadeft-pow-axum datadeft-magic-link-core datadeft-magic-link-service datadeft-magic-link-aws datadeft-magic-link-axum
    cargo publish --locked -p $c; or break
    sleep 2
end
```

```fish
# 3. Publish the npm client, then clean up.
npm login
mise run ts-verify
cd packages/dd-protect-client
npm publish --access public --ignore-scripts
cd ../..
git checkout main
cargo logout
```

If a crate fails, do not publish the earlier crates again. Fix the cause and
continue from the crate that failed. Revoke the crates.io token afterwards. A
manual npm publish carries no provenance.

## Approval and one-time setup (maintainers)

The first publication (`0.4.0`) is done. The remaining steps enable CI
publishing. Before you set `REGISTRY_PUBLISH_ENABLED`, do these steps:

1. Confirm the seven `datadeft-*` names below and `@datadeft/protect-client`.
   The license is MIT (approved 2026-10-08).
2. Get **approval from two maintainers** on the implementation PR and on every
   release PR. Configure branch protection for two approvals. Verify the
   identities before you merge. CODEOWNERS does not replace this rule. A
   two-reviewer environment also does not replace it, because an environment
   accepts any one of its reviewers.
3. Create the npm `datadeft` organization and add the maintainers. Enable 2FA
   for the account and for the organization. Give the maintainers publishing
   rights for the scope. On GitHub and crates.io, use maintainer accounts with
   2FA where the service supports it.
4. Keep the source repository public. **npm provenance requires public
   source**, even for a public package. To publish from a different public
   repository, update the package and workflow identity to match. A crate
   publication already makes its bundled source public.
5. In the repository Actions settings, let Actions create PRs. Keep the
   built-in `GITHUB_TOKEN`. Do not put a PAT, an npm token, or a crates.io
   token in repository secrets. For PRs that a bot creates, a maintainer may
   have to select **Approve workflows to run** before CI starts.
6. Create the GitHub environment **`registry-release`**. Require maintainer
   review. Where GitHub supports it, prevent self-review. Restrict deployment
   to protected `v*` tags. Protect release tags against unauthorized creation,
   deletion, and replacement. Leave the repository variable
   **`REGISTRY_PUBLISH_ENABLED` unset** until the bootstrap and the sign-offs
   are complete.

## First-publish bootstrap is a separate, manual approval

The maintainers did this bootstrap for `0.4.0`. It applies again only to a new
package name.

You cannot currently do a first publication with OIDC only. Both registries
require the package to exist before you can configure a trusted publisher.
crates.io also requires an API token for the first upload. See the
[crates.io prerequisites](https://crates.io/docs/trusted-publishing) and
[npm trust prerequisites](https://docs.npmjs.com/cli/v11/commands/npm-trust/).

When the approved release has its tag, a maintainer bootstraps the real,
reviewed packages from that exact tag. Do not create placeholder packages. Do
not put bootstrap credentials in CI.

1. Get a local, narrowly scoped, short-lived crates.io credential.
2. Use an interactive npm login with 2FA.
3. Run the checks below.
4. Publish the crates one at a time in this order. Do a dry run of each crate
   immediately before its upload. Each published crate becomes resolvable for
   the next crate.
   1. `datadeft-auth-token-core`
   2. `datadeft-pow-core`
   3. `datadeft-pow-axum`
   4. `datadeft-magic-link-core`
   5. `datadeft-magic-link-service`
   6. `datadeft-magic-link-aws`
   7. `datadeft-magic-link-axum`
5. From the same tag, build and pack the npm client.
6. Publish the npm client interactively as public.
7. When you are done, revoke the local bootstrap credential.

`datadeft-magic-link-aws` comes before `datadeft-magic-link-axum` because the
documentation tests of the Axum crate use the SDK-free fakes of the AWS crate.
The example application stays `publish = false`. `scripts/registry-release.ts`
holds the authoritative order.

A local bootstrap cannot carry GitHub OIDC provenance. If provenance is
mandatory on the very first npm version, stop and approve a separate bootstrap
design. Do not silently remove `--provenance` from CI. Later releases use the
prepared OIDC/provenance workflow. Registry versions are immutable. Never rerun
automated publication for a version that is already uploaded.

## Registry trusted-publisher configuration

Configure each of the seven crates in crates.io **Settings → Trusted
Publishing**. Configure the npm package in **Settings → Trusted publishing**:

| Field | Exact value |
| --- | --- |
| Provider | GitHub Actions |
| Repository owner / organization | `DataDeft` |
| Repository | `datadeft-auth` |
| Workflow filename | `release.yml` |
| GitHub environment | `registry-release` |

Enter the filename only, without `.github/workflows/`. The case and the
spelling must match. Use GitHub-hosted runners. On npm, enable the **direct
`npm publish`** permission of the publisher. The stage-only permission cannot
run this workflow. Then select **Require two-factor authentication and
disallow tokens**.

npm expires a new publisher configuration if its first successful publish does
not occur within two days. Create the configurations close to the next
approved release. If they expire, create them again. See
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

Set the repository variable `REGISTRY_PUBLISH_ENABLED=true` only after you
verify the setup. This variable is a non-secret opt-in switch, not a
credential. The environment stays the human approval gate for uploads.

## Verification and release flow

On a clean, committed checkout, run these tasks:

```sh
mise run verify
mise run msrv
mise run workflow-check
mise run package-crates
mise run crates-dry-run
```

- `verify` runs Rust formatting, Clippy, tests, default-feature tests
  (`test-default-features`), docs, cargo-deny, the API guards, and the release
  metadata checks. It also runs the nine TLA+ safety and liveness models (ten
  configs, `spec`) and the 44 spec mutants (`spec-mutants`). Last, it runs the
  npm build, tests, dry run, and isolated packed-consumer checks.
- Before the first `msrv` run, run
  `rustup toolchain install 1.88.0 --profile minimal` one time.
- `package-crates` uses the workspace staging registry of current stable
  Cargo. Before any public upload, it packages and builds all seven archives
  with all features.
- `crates-dry-run` tries every crate and reports each failure. A single
  `cargo publish --dry-run` cannot resolve unpublished renamed dependencies
  from crates.io. Do not bypass archive verification to hide this bootstrap
  limitation. Do not remove dependency versions to hide it.

Release steps:

1. After both PR approvals, merge the changes that have conventional names.
2. `release-please.yml` opens or updates a single release PR with
   `GITHUB_TOKEN`. It updates `version.txt`, the workspace Cargo version, and
   the dependency versions. It also updates `Cargo.lock`, the npm
   `package.json`, Bun's lockfile, and `CHANGELOG.md`. Keep these versions
   synchronized. When you change JS dependencies, use `mise run js-lock`. This
   task normalizes Bun's JSONC output for release-please's strict JSON updater.
3. Approve any pending CI runs that a bot created. Review the full release PR.
   Before the merge, get two maintainer approvals.
4. Release-please creates the `vX.Y.Z` tag and the release. Then it dispatches
   `release.yml` on that tag. It must dispatch the workflow because a tag that
   `GITHUB_TOKEN` creates does not trigger a push workflow. Release tags that a
   human creates also trigger it. See
   [GitHub's event behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
5. The release workflow checks the tag, the version, and the ancestry on main.
   It runs verification and archive builds, then waits for environment
   approval. The crates.io authentication occurs after compilation. Then the
   crates publish in dependency order, and Cargo waits for index availability.
   The npm job follows with `npm publish --provenance --access public
   --ignore-scripts`.
6. Before you tell consumers to update, confirm all registry versions and the
   npm provenance. The release tooling changes no consumer repository.

The workflow uses Node 24, because OIDC needs npm 11.5.1 or newer. It pins
actions to commit IDs. Only the publishing jobs get OIDC permission. These jobs
do not persist checkout credentials. The post-step of the auth action revokes
the temporary crates.io token.

If a publication is partial, do these steps:

1. Stop the release.
2. Identify the last successful package.
3. Inspect the uploaded artifact.
4. Get an approved recovery plan for the remaining packages.

Do not overwrite an existing version. Do not skip an existing version
automatically. A manual workflow dispatch must select the exact release tag.
Branch dispatches do not publish.

## Public-source review

The publication review covered `docs/security.md`. The file contains security
policy, architecture, synthetic examples, and placeholder key fields. The
review found no production secret, credential, cookie capture, or customer
data. The design disclosure is intentional, because source secrecy is not a
security boundary. This review does not replace the separate security review
or the required provenance sign-off.

Rust tarballs allow only sources, tests (including deterministic vectors),
README, and license texts. They also allow Cargo-generated metadata and
lockfiles. npm packing asserts the exact seven-file distribution: two JS
files, two declaration files, README, `package.json`, and the license. Crate
READMEs link to `docs/security.md` and do not bundle it.

# Registry releases

All seven Rust crates and the npm client share one version and one release PR.
For the published versions, see crates.io and npm. The project publishes no
release-candidate or other pre-release versions. Consumers test an unpublished
version through a git ref. Never move a release tag.

Releases publish from a maintainer's machine. On a `vX.Y.Z` tag, the
`release.yml` workflow validates the tag, checks the ancestry on main, and
runs the full verification and archive builds. It never uploads. There are no
registry credentials in CI.

## Account requirements

- Two maintainers approve every release PR before the merge.
- The publishing maintainer keeps 2FA enabled on npm (account and the
  `datadeft` organization) and on crates.io.
- Do not put a PAT, an npm token, or a crates.io token in repository secrets.
- A local npm publish carries no provenance.

## Publishing

Run these steps after the release PR is merged, release-please has created the
`vX.Y.Z` tag, and the `release.yml` verification run on that tag is green.
Paste each block separately and check it before the next.

```fish
# 1. Prepare and check the tagged release.
git fetch --tags origin
git checkout vX.Y.Z
rm -rf target/package
mise run verify; and mise run package-crates
mise run crates-dry-run
```

```fish
# 2. Publish the crates in dependency order. The task checks the release
# metadata, the clean checkout, and the exact tag, then stops at a failure.
cargo login
mise run publish-crates
```

```fish
# 3. Publish the npm client, then clean up.
npm login
mise run ts-verify
mise run publish-npm
git checkout main
cargo logout
npm logout
```

If a crate fails, do not publish the earlier crates again. Fix the cause and
continue from the crate that failed with `cargo publish --locked -p <crate>`,
following the order in `scripts/registry-release.ts`. Revoke the crates.io
token afterwards.

## Verification and release flow

Before you publish, make sure that these conditions are true:

1. The provenance audit passed.
2. The public API review passed.
3. The docs exist and the examples compile.
4. The dependency and license audits (`cargo deny check`) passed.
5. The archive verification (`package-crates`) passed for every crate.
6. Two maintainers approved the release PR.
7. The `release.yml` verification run on the tag is green.

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
  `mise run msrv-install` one time (Rust 1.94.1).
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
5. The verification workflow checks the tag, the version, and the ancestry on
   main, then runs verification and archive builds. When it is green, a
   maintainer publishes from the tag ([Publishing](#publishing)). Cargo waits
   for index availability between dependent crates.
6. Before you tell consumers to update, confirm all registry versions. The
   release tooling changes no consumer repository.

If a publication is partial, do these steps:

1. Stop the release.
2. Identify the last successful package.
3. Inspect the uploaded artifact.
4. Get an approved recovery plan for the remaining packages.

Do not overwrite an existing version. Do not skip an existing version
automatically.

## Public-source review

Rust tarballs allow only sources, tests (including deterministic vectors),
README, and license texts. They also allow Cargo-generated metadata and
lockfiles. npm packing asserts the exact seven-file distribution: two JS
files, two declaration files, README, `package.json`, and the license. Crate
READMEs link to `docs/security.md` and do not bundle it.

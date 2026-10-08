#!/usr/bin/env bun
// API and repo-hygiene guard. Run with `mise run api-guard`.
//
// Replaces the awk/grep checks that used to live inline in ci.yml. Three
// invariants:
//   1. `encode_with_nonce` stays gated behind `test`/`test-support`. It is a
//      nonce-reuse footgun and must never appear in the default public API.
//   2. No crate enables `datadeft-auth-token-core/test-support` outside
//      `[dev-dependencies]`. As a normal dependency feature it would unify into
//      a default build and pull the footgun in.
//   3. The root mise config lives at `mise.toml`, not `.mise.toml`. A stale
//      hidden copy silently merges with the real one and drifts, so the hidden
//      name must never come back.

import { Glob } from "bun";

const errors: string[] = [];

// -- Check 1: encode_with_nonce gating -------------------------------------
const brancaPath = "crates/datadeft-auth-token-core/src/branca.rs";
const brancaLines = (await Bun.file(brancaPath).text()).split("\n");
const fnIndex = brancaLines.findIndex((line) => line.includes("pub fn encode_with_nonce"));

if (fnIndex === -1) {
    errors.push(`${brancaPath}: pub fn encode_with_nonce not found`);
} else {
    const gate = brancaLines[fnIndex - 1] ?? "";
    if (!gate.includes('cfg(any(test, feature = "test-support"))')) {
        errors.push(
            `${brancaPath}:${fnIndex + 1}: encode_with_nonce is not gated behind ` +
                `#[cfg(any(test, feature = "test-support"))]`,
        );
    }
}

// -- Check 2: test-support only under [dev-dependencies] --------------------
// Only workspace manifest locations: a repo-wide `**` scan walks `target/`,
// which a concurrent `cargo doc` rewrites, and crashes on vanished dirs.
const manifestPaths: string[] = [];
for (const pattern of ["Cargo.toml", "crates/*/Cargo.toml", "examples/*/Cargo.toml"]) {
    for await (const path of new Glob(pattern).scan({ onlyFiles: true })) {
        manifestPaths.push(path);
    }
}
if (manifestPaths.length < 2) {
    errors.push(`found only ${manifestPaths.length} Cargo.toml files; manifest scan is broken`);
}
for (const path of manifestPaths) {

    let underDevDependencies = false;
    (await Bun.file(path).text()).split("\n").forEach((line, index) => {
        const header = line.match(/^\s*\[([^\]]+)\]/);
        if (header) underDevDependencies = header[1]!.includes("dev-dependencies");

        const enablesTestSupport =
            line.includes("datadeft-auth-token-core") && line.includes("test-support");
        if (enablesTestSupport && !underDevDependencies) {
            errors.push(
                `${path}:${index + 1}: test-support enabled outside ` +
                    `[dev-dependencies]: ${line.trim()}`,
            );
        }
    });
}

// -- Check 3: no hidden .mise.toml -----------------------------------------
if (await Bun.file(".mise.toml").exists()) {
    errors.push(".mise.toml exists: root mise config must live at mise.toml, not the hidden name");
}

// -- Report ----------------------------------------------------------------
if (errors.length > 0) {
    console.error("api-guard failed:");
    for (const error of errors) console.error(`  - ${error}`);
    process.exit(1);
}

console.log("api-guard ok: encode_with_nonce gated, test-support is dev-only, no hidden .mise.toml.");

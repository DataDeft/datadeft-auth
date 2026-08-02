#!/usr/bin/env bun
// API-hygiene guard for dd-auth-token-core. Run with `mise run api-guard`.
//
// Replaces the awk/grep checks that used to live inline in ci.yml. Two
// invariants:
//   1. `encode_with_nonce` stays gated behind `test`/`test-support`. It is a
//      nonce-reuse footgun and must never appear in the default public API.
//   2. No crate enables `dd-auth-token-core/test-support` outside
//      `[dev-dependencies]`. As a normal dependency feature it would unify into
//      a default build and pull the footgun in.

import { Glob } from "bun";

const errors: string[] = [];

// -- Check 1: encode_with_nonce gating -------------------------------------
const brancaPath = "crates/dd-auth-token-core/src/branca.rs";
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
const cargoFiles = new Glob("**/Cargo.toml");
for await (const path of cargoFiles.scan({ onlyFiles: true })) {
    if (path.includes("target/") || path.includes("node_modules/")) continue;

    let underDevDependencies = false;
    (await Bun.file(path).text()).split("\n").forEach((line, index) => {
        const header = line.match(/^\s*\[([^\]]+)\]/);
        if (header) underDevDependencies = header[1]!.includes("dev-dependencies");

        const enablesTestSupport =
            line.includes("dd-auth-token-core") && line.includes("test-support");
        if (enablesTestSupport && !underDevDependencies) {
            errors.push(
                `${path}:${index + 1}: test-support enabled outside ` +
                    `[dev-dependencies]: ${line.trim()}`,
            );
        }
    });
}

// -- Report ----------------------------------------------------------------
if (errors.length > 0) {
    console.error("api-guard failed:");
    for (const error of errors) console.error(`  - ${error}`);
    process.exit(1);
}

console.log("api-guard ok: encode_with_nonce gated, test-support is dev-only.");

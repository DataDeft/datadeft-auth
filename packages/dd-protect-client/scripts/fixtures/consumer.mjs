import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { protect, ProtectError } from "@datadeft/protect-client";

assert.equal(new ProtectError("solve", "example").code, "solve");
const challenge = { chg: "packed-consumer", dif: 1, tim: "1700000000", tag: "fixture-tag" };
let validations = 0;
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
    assert.equal(init.method, "POST");
    assert.equal(init.credentials, "same-origin");
    if (url === "/pow/create") return Response.json(challenge);
    assert.equal(url, "/pow/validate");
    const solution = JSON.parse(init.body);
    assert.equal(solution.chg, challenge.chg);
    assert.equal(solution.tim, challenge.tim);
    assert.equal(solution.tag, challenge.tag);
    assert.match(solution.non, /^\d+$/);
    assert.match(solution.sol, /^0[0-9a-f]{63}$/);
    assert.equal(solution.sol, createHash("sha256").update(challenge.chg + solution.non).digest("hex"));
    validations += 1;
    return Response.json({ status: "ok" });
};

try {
    // Resolving both exports from an installed tarball catches accidental source imports.
    const workerPath = fileURLToPath(import.meta.resolve("@datadeft/protect-client/worker"));
    assert.ok(workerPath.endsWith("/dist/protect-worker.js"));
    await protect({
        workerUrl: workerPath, createUrl: "/pow/create", validateUrl: "/pow/validate", workerCount: 2,
    });

    // A side-effect-only import must retain the worker's message handler under tree shaking.
    const bundled = await Bun.build({
        entrypoints: ["./worker-entry.js"], target: "browser", format: "esm", minify: true,
        outdir: "./bundle",
    });
    assert.equal(bundled.success, true, String(bundled.logs));
    assert.equal(bundled.outputs.length, 1);
    await protect({
        workerUrl: bundled.outputs[0].path,
        createUrl: "/pow/create", validateUrl: "/pow/validate", workerCount: 2,
    });
    assert.equal(validations, 2);
} finally {
    globalThis.fetch = originalFetch;
}

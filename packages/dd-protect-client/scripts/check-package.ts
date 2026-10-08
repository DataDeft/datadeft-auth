import assert from "node:assert/strict";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dir, "..");
const consumerRoot = await mkdtemp(resolve(tmpdir(), "datadeft-protect-package-"));

async function run(command: string[], cwd: string): Promise<string> {
    const child = Bun.spawn(command, { cwd, stdout: "pipe", stderr: "inherit" });
    const output = await new Response(child.stdout).text();
    assert.equal(await child.exited, 0, `Failed: ${command.join(" ")}`);
    return output;
}

interface PackResult {
    filename: string;
    files: { path: string }[];
}

try {
    const manifest = await Bun.file(resolve(packageRoot, "package.json")).json();
    assert.equal(manifest.name, "@datadeft/protect-client");
    assert.equal(manifest.private, undefined);
    for (const kind of ["dependencies", "peerDependencies", "optionalDependencies"]) {
        // eslint-disable-next-line security/detect-object-injection -- fixed dependency field names
        assert.deepEqual(Object.keys(manifest[kind] ?? {}), [], `${kind} must stay empty`);
    }
    for (const lifecycle of [
        "preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly",
        "prepack", "postpack", "publish", "postpublish",
    ]) {
        // eslint-disable-next-line security/detect-object-injection -- fixed lifecycle names
        assert.equal(manifest.scripts?.[lifecycle], undefined, `${lifecycle} is not allowed`);
    }
    const expectedFiles = [
        "LICENSE", "README.md", "package.json",
        "dist/protect.d.ts", "dist/protect.js",
        "dist/protect-worker.d.ts", "dist/protect-worker.js",
    ].sort();
    const dryRun: PackResult[] = JSON.parse(await run(
        ["npm", "pack", "--dry-run", "--json", "--ignore-scripts"], packageRoot,
    ));
    assert.equal(dryRun.length, 1);
    assert.deepEqual(dryRun[0]?.files.map((file) => file.path).sort(), expectedFiles);
    for (const license of ["LICENSE"]) {
        assert.equal(
            // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed license names under the package directory
            await readFile(resolve(packageRoot, license), "utf8"),
            // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed license names under the workspace directory
            await readFile(resolve(packageRoot, "../..", license), "utf8"),
            `${license} must match the workspace license`,
        );
    }

    const packed: PackResult[] = JSON.parse(await run(
        ["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", consumerRoot], packageRoot,
    ));
    const archive = packed[0]?.filename;
    assert.ok(archive, "npm pack must produce an archive");
    assert.deepEqual(packed[0]?.files.map((file) => file.path).sort(), expectedFiles);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed filename in our newly created temporary directory
    await writeFile(resolve(consumerRoot, "package.json"), JSON.stringify({ private: true, type: "module" }));
    await run([
        "npm", "install", resolve(consumerRoot, archive), "--offline", "--ignore-scripts",
        "--omit=dev", "--no-package-lock", "--no-audit", "--no-fund",
    ], consumerRoot);
    for (const fixture of ["consumer.mjs", "consumer.ts", "worker-entry.js"]) {
        await copyFile(resolve(import.meta.dir, "fixtures", fixture), resolve(consumerRoot, fixture));
    }
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed filename in our newly created temporary directory
    await writeFile(resolve(consumerRoot, "tsconfig.json"), JSON.stringify({
        compilerOptions: {
            target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext",
            lib: ["ES2022", "DOM"], types: [], strict: true, noEmit: true,
        },
        include: ["consumer.ts"],
    }));
    await run([
        "bun", Bun.resolveSync("typescript/bin/tsc", packageRoot), "-p", "tsconfig.json",
    ], consumerRoot);
    await run(["bun", "consumer.mjs"], consumerRoot);
    console.log("npm pack dry-run, tarball allow-list, isolated type-check, and real packed/bundled workers passed");
} finally {
    await rm(consumerRoot, { recursive: true, force: true });
}

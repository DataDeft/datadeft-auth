import { copyFile, rm } from "node:fs/promises";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dir, "..");
const workspaceRoot = resolve(packageRoot, "../..");

await rm(resolve(packageRoot, "dist"), { recursive: true, force: true });
for (const config of ["tsconfig.build.json", "tsconfig.worker-build.json"]) {
    const compiler = Bun.spawn(["bun", Bun.resolveSync("typescript/bin/tsc", packageRoot), "-p", config], {
        cwd: packageRoot,
        stdout: "inherit",
        stderr: "inherit",
    });
    if ((await compiler.exited) !== 0) {
        throw new Error(`TypeScript build failed: ${config}`);
    }
}
for (const license of ["LICENSE-MIT", "LICENSE-APACHE"]) {
    await copyFile(resolve(workspaceRoot, license), resolve(packageRoot, license));
}

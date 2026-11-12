#!/usr/bin/env bun
// Publication order includes dev-dependencies: AWS precedes the Axum doc example.
import { TOML } from "bun";

export const crates = [
  "datadeft-auth-token-core",
  "datadeft-pow-core",
  "datadeft-pow-axum",
  "datadeft-magic-link-core",
  "datadeft-magic-link-service",
  "datadeft-magic-link-aws",
  "datadeft-magic-link-axum",
];

function requireCondition(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

async function run(args: string[]): Promise<number> {
  const child = Bun.spawn(args, { stdout: "inherit", stderr: "inherit" });
  return child.exited;
}

async function check(): Promise<string> {
  const root = TOML.parse(await Bun.file("Cargo.toml").text()) as any;
  const version = root.workspace.package.version;
  const mise = TOML.parse(await Bun.file("mise.toml").text()) as any;
  requireCondition(mise.vars.msrv === root.workspace.package["rust-version"], "mise msrv var and workspace rust-version must match");
  const pkg = await Bun.file("packages/dd-protect-client/package.json").json();
  requireCondition(pkg.version === version, "Rust and npm versions must match");
  const elixir = await Bun.file("packages/datadeft-auth-elixir/mix.exs").text();
  // Match the release-please marker semantically, not its exact byte layout.
  const elixirVersion = elixir.match(/x-release-please-start-version[\s\S]*?@version "([^"]+)"[\s\S]*?x-release-please-end/)?.[1];
  requireCondition(elixirVersion === version, "Rust and Elixir versions must match");
  const port = TOML.parse(await Bun.file("packages/datadeft-auth-elixir/native/datadeft_auth_port/Cargo.toml").text()) as any;
  requireCondition(port.package.publish === false && port.package.version.workspace, "Port executable must remain unpublished and inherit the release version");
  const bunLock = await Bun.file("bun.lock").json();
  requireCondition(bunLock.workspaces["packages/dd-protect-client"].version === version, "Bun lock version differs; run mise run js-lock");
  requireCondition((await Bun.file("version.txt").text()).trim() === version, "version.txt must match");
  requireCondition(pkg.name === "@datadeft/protect-client" && !pkg.private, "Wrong npm publish identity");
  requireCondition(pkg.license.replace(/[()]/g, "") === root.workspace.package.license, "License metadata differs");
  requireCondition(!pkg.dependencies && !pkg.peerDependencies, "npm runtime and peer dependencies must stay empty");
  for (const script of ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack", "postpack"]) {
    requireCondition(!pkg.scripts?.[script], `Unexpected npm lifecycle hook: ${script}`);
  }
  const lock = TOML.parse(await Bun.file("Cargo.lock").text()) as any;
  for (const name of [...crates, "axum-magic-link", "datadeft-auth-port"]) {
    requireCondition(lock.package.some((p: any) => p.name === name && !p.source && p.version === version), `${name}: stale Cargo.lock version`);
  }
  const seen = new Set<string>();
  for (const name of crates) {
    const base = `crates/${name}`;
    const manifest = TOML.parse(await Bun.file(`${base}/Cargo.toml`).text()) as any;
    requireCondition(manifest.package.name === name, `Incorrect crate name: ${name}`);
    requireCondition(manifest.package.publish !== false, `${name} is not publishable`);
    requireCondition(manifest.package.version.workspace, `${name} must inherit the release version`);
    for (const field of ["license", "repository", "rust-version"]) {
      requireCondition(manifest.package[field]?.workspace && root.workspace.package[field], `${name}: missing ${field}`);
    }
    requireCondition(manifest.package.description && manifest.package.readme && manifest.package.keywords?.length, `${name}: incomplete metadata`);
    for (const license of ["LICENSE"]) {
      requireCondition(await Bun.file(`${base}/${license}`).text() === await Bun.file(license).text(), `${name}: stale ${license}`);
    }
    for (const section of ["dependencies", "dev-dependencies", "build-dependencies"]) {
      for (const [dep, value] of Object.entries(manifest[section] ?? {}) as [string, any][]) {
        if (!value.path) continue;
        requireCondition(value.version === version, `${name}: ${dep} needs the current versioned path dependency`);
        requireCondition(dep === name || seen.has(dep), `${name}: ${dep} must publish earlier`);
      }
    }
    seen.add(name);
  }
  const metadata = Bun.spawnSync(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], { stderr: "inherit" });
  requireCondition(metadata.exitCode === 0, "Cargo.lock is stale");
  const packages = JSON.parse(metadata.stdout.toString()).packages;
  requireCondition(packages.filter((p: any) => p.publish === null || p.publish.length > 0).length === crates.length, "Unexpected publishable workspace member");
  console.log(`Release metadata and dependency order valid: ${version}`);
  return version;
}

const command = process.argv[2];
requireCondition(["check", "dry-run", "publish"].includes(command ?? ""), "Use check, dry-run, or publish");
const version = await check();
if (command === "publish") {
  const git = (...args: string[]) => Bun.spawnSync(["git", ...args]);
  requireCondition(git("status", "--porcelain").stdout.toString() === "", "Publish from a clean checkout");
  requireCondition(git("describe", "--tags", "--exact-match").stdout.toString().trim() === `v${version}`, "Release tag must match every package version");
  requireCondition(git("merge-base", "--is-ancestor", "HEAD", "origin/main").exitCode === 0, "Release tag must point at reviewed origin/main history");
}
if (command !== "check") {
  const failed: string[] = [];
  for (const name of crates) {
    console.log(`\n${command}: ${name}@${version}`);
    const args = ["cargo", "publish", "--locked", "-p", name];
    // Full workspace archive verification runs before OIDC auth. Cargo waits for
    // each successful upload to become available before the next dependent crate.
    if (command === "dry-run") args.push("--dry-run");
    else args.push("--no-verify");
    if (await run(args) !== 0) {
      failed.push(name);
      if (command === "publish") break;
    }
  }
  requireCondition(failed.length === 0, `${command} failed: ${failed.join(", ")}`);
}

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

// The manifest fields the checks read; TOML and JSON parse to untyped data.
type Inherited = { workspace?: boolean };
type Dependency = string | { path?: string; version?: string };
type WorkspaceManifest = { workspace: { package: Record<string, string> } };
type CrateManifest = {
  package: Record<string, Inherited | undefined> & {
    name: string;
    publish?: boolean;
    version: Inherited;
    description?: string;
    readme?: string;
    keywords?: string[];
  };
} & Partial<Record<"dependencies" | "dev-dependencies" | "build-dependencies", Record<string, Dependency>>>;
type MiseConfig = { tools: { rust?: { version?: string } } };
type CargoLock = { package: { name: string; source?: string; version: string }[] };
type CargoMetadata = { packages: { publish: string[] | null }[] };

function requireCondition(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

async function run(args: string[]): Promise<number> {
  const child = Bun.spawn(args, { stdout: "inherit", stderr: "inherit" });
  return child.exited;
}

async function check(): Promise<string> {
  const root = TOML.parse(await Bun.file("Cargo.toml").text()) as WorkspaceManifest;
  const version = root.workspace.package.version;
  const releaseConfig = await Bun.file("release-please-config.json").json();
  requireCondition(
    releaseConfig.packages?.["."]?.["changelog-type"] === "github",
    "Release notes must use GitHub PR-oriented generation to avoid duplicate merge/commit entries",
  );
  const mise = TOML.parse(await Bun.file("mise.toml").text()) as MiseConfig;
  requireCondition(
    mise.tools.rust?.version === root.workspace.package["rust-version"],
    "mise rust version and workspace rust-version must match",
  );
  const pkg = await Bun.file("packages/dd-protect-client/package.json").json();
  requireCondition(pkg.version === version, "Rust and npm versions must match");
  const elixir = await Bun.file("hex/datadeft_auth/mix.exs").text();
  // Match the release-please marker semantically, not its exact byte layout.
  const elixirVersion = elixir.match(
    /x-release-please-start-version[\s\S]*?@version "([^"]+)"[\s\S]*?x-release-please-end/,
  )?.[1];
  requireCondition(elixirVersion === version, "Rust and Elixir versions must match");
  const bunLock = await Bun.file("bun.lock").json();
  requireCondition(
    bunLock.workspaces["packages/dd-protect-client"].version === version,
    "Bun lock version differs; run mise run js-lock",
  );
  requireCondition((await Bun.file("version.txt").text()).trim() === version, "version.txt must match");
  requireCondition(pkg.name === "@datadeft/protect-client" && !pkg.private, "Wrong npm publish identity");
  requireCondition(pkg.license.replace(/[()]/g, "") === root.workspace.package.license, "License metadata differs");
  requireCondition(!pkg.dependencies && !pkg.peerDependencies, "npm runtime and peer dependencies must stay empty");
  for (const script of [
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "postpack",
  ]) {
    requireCondition(!pkg.scripts?.[script], `Unexpected npm lifecycle hook: ${script}`);
  }
  const lock = TOML.parse(await Bun.file("Cargo.lock").text()) as CargoLock;
  for (const name of [...crates, "axum-magic-link"]) {
    requireCondition(
      lock.package.some((p) => p.name === name && !p.source && p.version === version),
      `${name}: stale Cargo.lock version`,
    );
  }
  const seen = new Set<string>();
  for (const name of crates) {
    const base = `crates/${name}`;
    const manifest = TOML.parse(await Bun.file(`${base}/Cargo.toml`).text()) as CrateManifest;
    requireCondition(manifest.package.name === name, `Incorrect crate name: ${name}`);
    requireCondition(manifest.package.publish !== false, `${name} is not publishable`);
    requireCondition(manifest.package.version.workspace, `${name} must inherit the release version`);
    for (const field of ["license", "repository", "rust-version"]) {
      requireCondition(
        manifest.package[field]?.workspace && root.workspace.package[field],
        `${name}: missing ${field}`,
      );
    }
    requireCondition(
      manifest.package.description && manifest.package.readme && manifest.package.keywords?.length,
      `${name}: incomplete metadata`,
    );
    for (const license of ["LICENSE"]) {
      requireCondition(
        (await Bun.file(`${base}/${license}`).text()) === (await Bun.file(license).text()),
        `${name}: stale ${license}`,
      );
    }
    for (const section of ["dependencies", "dev-dependencies", "build-dependencies"] as const) {
      for (const [dep, value] of Object.entries(manifest[section] ?? {})) {
        if (typeof value === "string" || !value.path) continue;
        requireCondition(value.version === version, `${name}: ${dep} needs the current versioned path dependency`);
        requireCondition(dep === name || seen.has(dep), `${name}: ${dep} must publish earlier`);
      }
    }
    seen.add(name);
  }
  const metadata = Bun.spawnSync(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], {
    stderr: "inherit",
  });
  requireCondition(metadata.exitCode === 0, "Cargo.lock is stale");
  const packages = (JSON.parse(metadata.stdout.toString()) as CargoMetadata).packages;
  requireCondition(
    packages.filter((p) => p.publish === null || p.publish.length > 0).length === crates.length,
    "Unexpected publishable workspace member",
  );
  console.log(`Release metadata and dependency order valid: ${version}`);
  return version;
}

const command = process.argv[2];
requireCondition(["check", "dry-run", "publish"].includes(command ?? ""), "Use check, dry-run, or publish");
const version = await check();
if (command === "publish") {
  const git = (...args: string[]) => Bun.spawnSync(["git", ...args]);
  requireCondition(git("status", "--porcelain").stdout.toString() === "", "Publish from a clean checkout");
  requireCondition(
    git("describe", "--tags", "--exact-match").stdout.toString().trim() === `v${version}`,
    "Release tag must match every package version",
  );
  requireCondition(
    git("merge-base", "--is-ancestor", "HEAD", "origin/main").exitCode === 0,
    "Release tag must point at reviewed origin/main history",
  );
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
    if ((await run(args)) !== 0) {
      failed.push(name);
      if (command === "publish") break;
    }
  }
  requireCondition(failed.length === 0, `${command} failed: ${failed.join(", ")}`);
}

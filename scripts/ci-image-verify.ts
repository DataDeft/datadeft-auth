#!/usr/bin/env bun
// Verify the Elixir package inside an official `elixir` image, Debian (glibc)
// or Alpine (musl). Run with `mise run elixir-image-verify <image>`, for
// example `mise run elixir-image-verify elixir:1.19-otp-28-alpine`.
//
// The host downloads a pinned mise and a pinned rustup-init and checks each
// against its SHA-256 before the container can run it; no installer script is
// piped to a shell. The container gets the checkout at /work and the verified
// binaries read-only at /tools, then runs the same `elixir-verify` task as the
// host jobs. It runs as root and is removed afterwards, along with the
// downloads. Only the downloads are digest-pinned: the image tag floats, and
// Rust is the workspace's pinned version. Meant for CI: locally on Linux,
// build output in the checkout ends up owned by root.

import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOML } from "bun";

const MISE_VERSION = "2026.11.8";
// The workspace's single Rust version, so the image builds what CI builds.
const RUST_VERSION = (TOML.parse(await Bun.file("mise.toml").text()) as { tools: { rust: { version: string } } }).tools
  .rust.version;
const RUSTUP_VERSION = "1.29.3";

// Digests from the mise release's SHASUMS256.txt and rustup's
// rustup-init.sha256 files; update them together with the versions above.
// The static musl build of mise runs on both glibc and musl.
const MISE_SHA256: Record<string, string> = {
  x64: "1fe64489a99b6227b7f7e67ae4dd3293c20ecbbcd74b1367456010359383e712",
  arm64: "3febd613b6e49f928acdacda006662cee252f160ebc3fc48f5197260e61dc758",
};
const RUSTUP_SHA256: Record<string, string> = {
  "x86_64-unknown-linux-gnu": "b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55",
  "aarch64-unknown-linux-gnu": "9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282",
  "x86_64-unknown-linux-musl": "1552169aba2836777136ccff7a381e95c17233b5d8250cd5e10ae3cb971bfcfc",
  "aarch64-unknown-linux-musl": "956deacdc27ab82ae7ac821d5d3e9e95e4795d476d17efe99743bb8531ca1031",
};

const PATH = "/root/.cargo/bin:/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

function requireCondition(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

async function run(args: string[]): Promise<void> {
  console.log(`==> ${args.join(" ")}`);
  const code = await Bun.spawn(args, { stdout: "inherit", stderr: "inherit" }).exited;
  requireCondition(code === 0, `command failed (${code}): ${args.join(" ")}`);
}

// Downloads `url` to `path`, keeping it only when it matches `sha256`.
async function fetchVerified(url: string, path: string, sha256: string): Promise<void> {
  const response = await fetch(url);
  requireCondition(response.ok, `download failed (${response.status}): ${url}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const actual = new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
  requireCondition(actual === sha256, `SHA-256 mismatch for ${url}: ${actual}`);
  await Bun.write(path, bytes);
  await chmod(path, 0o755);
  console.log(`${path}: OK`);
}

const image = Bun.argv[2];
requireCondition(image, "usage: ci-image-verify.ts <elixir image, Alpine tags ending in -alpine>");
const alpine = image.endsWith("-alpine");
const libc = alpine ? "musl" : "gnu";
const arch = process.arch;
const triple = `${arch === "x64" ? "x86_64" : "aarch64"}-unknown-linux-${libc}`;
const miseSha = MISE_SHA256[arch];
const rustupSha = RUSTUP_SHA256[triple];
requireCondition(miseSha && rustupSha, `unsupported platform: ${arch}-${libc}`);

const tools = await mkdtemp(join(tmpdir(), "ci-image-tools-"));
const container = `ci-image-verify-${process.pid}`;
const exec = (args: string[], env: string[] = []) =>
  run(["docker", "exec", "-e", `PATH=${PATH}`, ...env.flatMap((e) => ["-e", e]), container, ...args]);

try {
  await fetchVerified(
    `https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${arch}-musl`,
    join(tools, "mise"),
    miseSha,
  );
  await fetchVerified(
    `https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init`,
    join(tools, "rustup-init"),
    rustupSha,
  );

  // Inside the try: a container created by a failed `docker run` is removed too.
  // `--init` reaps orphans: a Port child outliving its BEAM would otherwise stay
  // a zombie under `sleep`, and the pipe-closure tests would see it alive.
  await run([
    "docker",
    "run",
    "-d",
    "--init",
    "--name",
    container,
    "-v",
    `${process.cwd()}:/work`,
    "-v",
    `${tools}:/tools:ro`,
    "-w",
    "/work",
    image,
    "sleep",
    "infinity",
  ]);

  // Record the distribution and libc in the job log.
  await exec(["cat", "/etc/os-release"]);
  // musl's ldd prints its version and exits non-zero.
  await exec(["ldd", "--version"]).catch(() => {});

  if (alpine) {
    await exec(["apk", "add", "--no-cache", "build-base", "git"]);
  } else {
    await exec(["apt-get", "update"]);
    await exec(["apt-get", "install", "-y", "--no-install-recommends", "build-essential", "ca-certificates", "git"]);
  }
  await exec(["rustup-init", "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", RUST_VERSION]);

  // The mounted checkout is owned by another user.
  await exec(["git", "config", "--global", "--add", "safe.directory", "*"]);
  await exec(["mix", "local.hex", "--force"]);
  await exec(["mix", "local.rebar", "--force"]);

  // The workspace's bun and node tools serve other tasks and have no musl
  // builds; elixir-verify needs neither. Rust is already installed above.
  await exec(["mise", "run", "elixir-verify"], ["MISE_TRUSTED_CONFIG_PATHS=/work", "MISE_DISABLE_TOOLS=bun,node,rust"]);
} finally {
  // No container exists when the downloads or `docker run` failed early.
  await run(["docker", "rm", "-f", container]).catch(() => {});
  await rm(tools, { recursive: true, force: true });
}

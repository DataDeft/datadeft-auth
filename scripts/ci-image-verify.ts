#!/usr/bin/env bun
// Run the native Elixir package gate on the supported BEAM/Linux matrix.
// Only the orchestration binary is downloaded (pinned and checksum-verified).
// No Rust toolchain, compiler, Port executable or NIF build is needed.
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const MISE_VERSION = "2026.11.8";
const MISE_SHA256: Record<string, string> = {
  x64: "1fe64489a99b6227b7f7e67ae4dd3293c20ecbbcd74b1367456010359383e712",
  arm64: "3febd613b6e49f928acdacda006662cee252f160ebc3fc48f5197260e61dc758",
};

function requireCondition(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

async function run(args: string[]): Promise<void> {
  const code = await Bun.spawn(args, { stdout: "inherit", stderr: "inherit" }).exited;
  requireCondition(code === 0, `command failed (${code}): ${args.join(" ")}`);
}

const image = Bun.argv[2];
requireCondition(image, "usage: ci-image-verify.ts <elixir image>");
const sha = MISE_SHA256[process.arch];
requireCondition(sha, `unsupported architecture: ${process.arch}`);
const tools = await mkdtemp(join(tmpdir(), "ci-image-tools-"));
const container = `ci-image-verify-${process.pid}`;
const exec = (args: string[]) => run([
  "docker", "exec", "-e", "PATH=/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "-e", "MISE_TRUSTED_CONFIG_PATHS=/work", "-e", "MISE_DISABLE_TOOLS=bun,node,rust",
  container, ...args,
]);

try {
  const url = `https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${process.arch}-musl`;
  const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  requireCondition(response.ok, `download failed (${response.status}): ${url}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  requireCondition(new Bun.CryptoHasher("sha256").update(bytes).digest("hex") === sha, "mise SHA-256 mismatch");
  const binary = join(tools, "mise");
  await Bun.write(binary, bytes);
  await chmod(binary, 0o755);

  // CI checkout is mounted read-write for Mix build products. Never mount
  // developer credentials or forward tokens into the disposable container.
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
  await exec(["mix", "local.hex", "--force"]);
  await exec(["mise", "run", "elixir-verify"]);
} finally {
  await run(["docker", "rm", "-f", container]).catch(() => {});
  await rm(tools, { recursive: true, force: true });
}

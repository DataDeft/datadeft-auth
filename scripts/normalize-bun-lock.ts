#!/usr/bin/env bun
// release-please's JSON updater requires strict JSON; Bun emits JSONC.
import { resolve } from "node:path";
const { parseConfigFileTextToJson } = await import(Bun.resolveSync(
  "typescript", resolve(import.meta.dir, "../packages/dd-protect-client"),
));
const path = "bun.lock";
const parsed = parseConfigFileTextToJson(path, await Bun.file(path).text());
if (parsed.error) throw new Error("Could not parse bun.lock");
await Bun.write(path, JSON.stringify(parsed.config, null, 2) + "\n");

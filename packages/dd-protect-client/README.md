# dd-protect-client

Optional browser proof-of-work client for [`dd-pow-core`](../../crates/dd-pow-core).
It mints a challenge, solves it in Web Workers, and posts the solution. On
success the server sets the `dd_pow` proof cookie. The solver matches the
`dd-pow-core` wire contract exactly (`SHA-256(challenge + nonce)`, lowercase
hex, `difficulty` leading zero hex characters, decimal nonce), so the two are
interoperable by construction.

De-branded: no CeleraTax/Panzerotti naming, copy, or hardcoded routes. Zero
runtime dependencies — only browser built-ins (`fetch`, `Worker`,
`crypto.subtle`).

## Distribution

Shipped as **TypeScript source**, not a built bundle. The consuming app's build
(Bun, Vite, esbuild, …) compiles it. Types come straight from the source, so
there is no `dist/` and no generated `.d.ts`.

## Usage

```ts
import { protect, ProtectError } from "dd-protect-client";

try {
  await protect({
    workerUrl: "/pow-worker.js", // the built worker the app serves (see below)
    createUrl: "/api/v1/session/pow/create",
    validateUrl: "/api/v1/session/pow/validate",
  });
  // The dd_pow cookie is now set. Proceed with the gated request.
} catch (e) {
  if (e instanceof ProtectError) {
    switch (e.code) {
      case "network": // offline, DNS, or CORS
      case "timeout": // request or solve exceeded its limit
      case "server":  // non-2xx from the admission API; see e.status
      case "solve":   // worker crash, CSP block, or nonce exhaustion
    }
  }
}
```

`createUrl` and `validateUrl` are required — the library never hardcodes routes.
Optional knobs: `workerCount` (default `navigator.hardwareConcurrency`),
`solveTimeoutMs` (default 30000), `fetchTimeoutMs` (default 10000).

## The worker: you build it, you serve it

Web Workers load from a URL, so the worker cannot be bundled into the client
the way a normal import is. The app builds `dd-protect-client/worker` into a
served static file and passes its path as `workerUrl`. Two ways:

**Static asset (explicit, CSP-friendly):**

```sh
bun build node_modules/dd-protect-client/ts/protect-worker.ts \
  --outfile public/pow-worker.js --target browser
```

then `protect({ workerUrl: "/pow-worker.js", ... })`.

**Bundler-native:** most bundlers emit the worker for you from a URL:

```ts
const workerUrl = new URL("dd-protect-client/worker", import.meta.url);
await protect({ workerUrl, createUrl, validateUrl });
```

`workerUrl` accepts a `string` or a `URL`, so both models work.

## Development

```sh
bun install
bun run lint        # ESLint + eslint-plugin-security
bun run typecheck   # tsc: client (DOM) and worker (WebWorker) checked separately
bun test            # unit tests + real worker integration tests
```

Or `mise run verify` for all three. The worker source (WebWorker lib) and the
client (DOM lib) type-check under separate tsconfigs to avoid the standard
`self`/global conflict.

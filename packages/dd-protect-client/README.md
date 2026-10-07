# @datadeft/protect-client

Optional browser proof-of-work client for
[`datadeft-pow-core`](https://crates.io/crates/datadeft-pow-core).
It mints a challenge, solves it in Web Workers, and posts the solution. On
success the server sets the `dd_pow` proof cookie. The solver uses
`SHA-256(challenge + nonce)`, lowercase hex, `difficulty` leading zero hex
characters, and a decimal nonce, matching the Rust wire contract.

Zero runtime or peer dependencies. The package uses browser built-ins
(`fetch`, module `Worker`, and `crypto.subtle`) and requires a secure browser
context (HTTPS, or localhost during development).

## Install

```sh
bun add @datadeft/protect-client
```

The npm archive contains ESM JavaScript and TypeScript declarations in `dist/`.
Consumers do not need TypeScript to execute it, a repository checkout, or install
scripts. The main export is `@datadeft/protect-client`; the separate
`@datadeft/protect-client/worker` export initializes the Web Worker.

## Usage

```ts
import { protect, ProtectError } from "@datadeft/protect-client";

try {
  await protect({
    workerUrl: "/pow-worker.js",
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

`createUrl` and `validateUrl` are required: the library never hardcodes routes.
Optional knobs: `workerCount` (default `navigator.hardwareConcurrency`),
`solveTimeoutMs` (default 30000), and `fetchTimeoutMs` (default 10000).

## Serve the worker

Create an application entry file, for example `src/pow-worker.ts`:

```ts
import "@datadeft/protect-client/worker";
```

Build that entry into your application's static assets:

```sh
bun build ./src/pow-worker.ts --outfile ./public/pow-worker.js --target browser --format esm
```

Pass the served same-origin URL (`/pow-worker.js` in this example) to `protect`.
The client starts it with `{ type: "module" }`. The package marks the worker as
having side effects so bundlers preserve its message handlers when importing it
this way. Do not import the worker into your application's main thread.

If your bundler has a worker URL asset feature, use that feature to build the
same entry and pass its emitted URL. A bare package name in `new URL(...)` is
not a portable browser package resolver. `workerUrl` accepts either a `string`
or a `URL`. Serve the worker with a JavaScript content type and allow its URL
in your application's `worker-src` CSP directive.

## Migration from the source package

Replace imports from `dd-protect-client` or a vendored copy with
`@datadeft/protect-client`, remove the vendored files, and build the worker entry
above. Replace any `node_modules/dd-protect-client/ts/protect-worker.ts` build
paths with the public `@datadeft/protect-client/worker` export. The proof-of-work
wire format and the `protect` / `ProtectError` API remain the same.

## Development

From the repository root:

```sh
mise run ts-verify
```

Or, from this package directory:

```sh
mise run install
mise run verify
```

Verification includes ESLint, separate DOM/worker type checks, unit tests,
real worker tests, an ESM/declaration build, and `npm pack --dry-run`. It also
installs a local tarball into an isolated temporary consumer without network
access or install scripts, checks its declarations without Bun types, and
executes both the packed worker and a tree-shaken worker bundle. Builds are
explicit; there are no install, pack, or publish lifecycle hooks.

`mise run build` creates `dist/` and copies the workspace license texts into
the package. `mise run pack-check` rebuilds and runs the packaging checks.

## License

MIT OR Apache-2.0. Both license texts are included in the npm archive.

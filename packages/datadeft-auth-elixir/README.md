# datadeft_auth (implementation in progress)

Framework-independent Elixir authentication backed by a **separate Rust process**.
No Rust code loads into BEAM; no Phoenix, Plug, Rustler or HTTP server is required.

**Current scope: P1 transport foundation only.** It starts the executable, checks
protocol/build compatibility and exercises health/lifecycle behavior. Magic-link,
session, PoW, DynamoDB/SES and secret initialization are not implemented yet.
This is not an authentication release and must not be deployed for login.

## Development

The build environment needs Elixir >= 1.16, OTP >= 26, Rust >= 1.94.1 and platform
build tools. Approved deployment targets are Linux glibc x86_64 and AArch64; macOS
ARM64 is a development host. Target/runtime matrix CI must pass before claiming
support. The glibc floor and minimum-runtime tests are still release gates.

From the repository root:

```sh
mise -C packages/datadeft-auth-elixir run deps
mise run elixir-verify
```

Critical APIs, protocol parsing and connection lifecycle helpers have typespecs.
The contracts cover configuration bounds, closed error codes, wire IDs/results,
pending callers/timers and connection state, including the exhausted-ID sentinel.
`test/type_contract_test.exs` guards against accidentally dropping these specs or
types. Typespecs do not enforce runtime validation or prove implementation
correctness; runtime checks remain necessary, and Dialyzer is not yet configured.

Use `deps-update` only when intentionally updating the committed Mix lockfile.
The Mix compiler builds the unpublished Rust workspace executable and installs it
in the application's `priv/`. Mix releases include it; production hosts need
neither Cargo nor a Rust compiler.

Add `{DatadeftAuth, name: MyAuth}` to your supervision tree. Startup is asynchronous:

```elixir
DatadeftAuth.status(MyAuth)
# {:ok, :transport_ready} or {:error, %DatadeftAuth.Error{code: :unavailable}}
```

This checks **transport only**, not AWS or authentication readiness.

## Transport contract (private)

- A trusted absolute executable path, stdin/stdout only, no shell/network socket.
- Four-byte big-endian length prefix, 1–4096 byte UTF-8 JSON body, v1 envelope.
  Only handshake and ping exist in P1. Strict fields, duplicate-key rejection,
  monotonic non-reused uint32 IDs, exact build-version handshake.
- Rust checks lengths before allocation. Elixir parses the raw Port stream
  itself rather than using `packet: 4`, which would allow the VM driver to
  allocate an advertised body before validation.
- Elixir retains at most a partial frame plus the current driver chunk; there
  are at most 32 outstanding requests by default. OS pipe/Port flow control is
  not a hard VM-memory bound against a compromised child flooding output. The
  executable is trusted local code, not an adversarial plugin; system resource
  limits remain an operational concern. The GenServer mailbox likewise is not
  an ingress-rate limiter; application/edge admission is still required.
- Deadlines remove pending calls; replies arriving later are ignored. No
  automatic replay. Timeout never means rollback. Caller death frees tracking.
- EOF/exit/protocol fault fails pending calls with fixed redacted errors, closes
  the Port, and retries with bounded exponential backoff (100ms–5s). Successful
  handshake resets backoff. Supervisor owns the Port owner; owner/VM death
  closes the child's stdin. The current child exits on EOF.
- Errors and status omit payloads; stdout is protocol-only, stderr is not merged.
  Custom `:executable` is trusted deployment configuration, never request input.
  It must implement EOF cleanup. No secrets belong in args, logs or crash output.

Future AWS execution must preserve responsive EOF handling during jobs, initialize
keys before auth readiness, and prove durable reconciliation for ambiguous commits
across both Rust and BEAM crashes. P1 restart tests do not prove those future gates.

## Packaging

`mise run package-check` stages sources without changing the checkout, materializes
workspace metadata into a standalone manifest, generates its lockfile, builds a
Hex archive, unpacks it outside the repository, runs its tests and builds/executes
a clean consumer Mix release. It uploads nothing. Package sources include tests
and the Rust source/lockfile, not a compiled binary or build caches.

The packaging script currently covers the transport crate's serde dependencies.
Future local workspace dependencies must be replaced with exact released registry
versions and tested before an authentication artifact can ship. It must not rely
on this checkout being available.

## Dependency rationale

- Rust serde/serde_json: strict, typed, bounded bootstrap protocol parsing.
- Elixir Jason: reviewed maintained JSON codec; ordered-object decoding preserves
  duplicate keys for explicit rejection, never converts input to atoms.
- No cryptographic dependencies or AWS SDKs are added to the transport yet.

MIT. The public package name is `datadeft_auth`, owned by Hex user `l1x`.
No publishing or version bump is authorized by this infrastructure change.

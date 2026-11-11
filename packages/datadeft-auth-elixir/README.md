# datadeft_auth (implementation in progress)

Framework-independent Elixir authentication backed by a **separate Rust process**.
No Rust code loads into BEAM; no Phoenix, Plug, Rustler or HTTP server is required.

**Current scope: transport plus the magic-link/session API.** The executable
runs bounded concurrent jobs and serves request, landing, flow-state,
confirm, validate-session and logout against either the crate-shipped
in-memory store (`mode: :fake`) or DynamoDB/SES with Secrets Manager key
loading (`mode: :aws`, deployment-role credential chain). PoW operations and
durable ambiguous-commit recovery are still staged, and the AWS mode has not
passed a production readiness review. This is not an authentication release
and must not be deployed for login.

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
`test/type_contract_test.exs` guards the public contracts and the redaction
callback against accidentally dropping their specs or types. Typespecs do not enforce runtime validation or prove implementation
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
- Four-byte big-endian length prefix, 1–16384 byte UTF-8 JSON body, v1
  envelope (sized for the one-time configuration frame). Strict fields,
  duplicate-key rejection, monotonic non-reused uint32 IDs, exact
  build-version handshake, then exactly one init before auth operations.
  Requests run as bounded concurrent jobs; replies may arrive out of order
  and are routed by ID with the echoed operation checked against the pending
  one. Per-request application failures use one closed error result;
  protocol faults stay fatal.
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

`mise run package-check` stages sources without changing the checkout,
materializes a self-contained Rust workspace (the port executable plus the
vendored `datadeft-*` crates it builds from), generates its lockfile, builds a
Hex archive, unpacks it outside the repository, runs its tests and
builds/executes a clean consumer Mix release. It uploads nothing. Package
sources include tests and the Rust sources/lockfile, not a compiled binary or
build caches.

Publishing uses the same staging: `mise run package-stage` materializes the
standalone manifest and lockfile under `_build/publish_stage` and builds the
Hex archive there; `mix hex.publish` is then run manually from that directory.
`mix hex.publish` from the checkout itself fails by design, because the
workspace-inherited Cargo manifest and lockfile only exist in a stage.

Vendoring keeps the published package independent of both this checkout and
unpublished registry versions; the staged workspace inherits the tested
dependency floors and lints verbatim from the repository root.

## Dependency rationale

- Rust serde/serde_json: strict, typed, bounded protocol parsing.
- Rust tokio: bounded concurrent job execution over the Port pipe, required
  by the AWS SDK clients this process will own.
- Rust rand_core (getrandom): OS-backed CSPRNG for the service entropy inputs.
- The workspace `datadeft-*` service/adapter crates own all cryptography; the
  port adds no cryptographic dependencies of its own.
- Rust aws-config + aws-sdk-dynamodb/sesv2/secretsmanager: the port owns the
  AWS clients and the supported deployment-role credential chain; core and
  service crates receive loaded material only.
- Elixir Jason: reviewed maintained JSON codec; ordered-object decoding preserves
  duplicate keys for explicit rejection, never converts input to atoms.

MIT. The public package name is `datadeft_auth`, owned by Hex user `l1x`.
No publishing or version bump is authorized by this infrastructure change.

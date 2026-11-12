# datadeft_auth

Framework-independent Elixir authentication backed by a **separate Rust process**.
No Rust code loads into BEAM; no Phoenix, Plug, Rustler or HTTP server is required.

**Implemented:** supervised transport, explicit initialization, bounded service
execution, magic-link/session operations, and independent PoW admission. Fake mode
uses the shipped in-memory store/outbox; AWS mode reuses Rust DynamoDB, SES and
Secrets Manager adapters with the supported AWS credential chain.

**Source integration:** the binding targets the released Rust 0.6.0 baseline;
it is not yet published to Hex. Deployment still requires review of the
consuming application's HTTP security, IAM/resources and recovery UX; local
AWS integration tests are not live production validation. A lost confirmation
reply is an **indeterminate outcome by contract** (owner-approved): a timeout
is not rollback, the library never replays the commit, and the application's
recovery path is offering a fresh sign-in link.

## Build and runtime

Build with Elixir >= 1.16, OTP >= 26, Rust >= 1.94.1 and native build tools.
The initial distribution builds from source. Mix releases include the executable;
production hosts need neither Cargo nor a Rust compiler.

The native CI pairs are:

| Target | Build host / glibc | Elixir / OTP |
| --- | --- | --- |
| Linux x86_64 | Ubuntu 22.04 / 2.35 | 1.16.3 / 26.2 |
| Linux AArch64 | Ubuntu 24.04 / 2.39 | 1.19 / 28 |

The aggregate verification job also exercises its configured x86_64 Linux host.
These are source-build/native-execution checks, not a promise that a binary built
on a newer distribution runs on an older libc. Older libc versions and every
architecture/runtime cross-product have not been validated. macOS ARM64 is a
local development host, not an approved deployment target. Alpine/musl, Windows
and 32-bit systems are outside the initial scope.

From the repository root:

```sh
mise -C packages/datadeft-auth-elixir run deps
mise run elixir-verify
mise run port-test
mise run port-clippy
mise run dynamodb-local-test # requires Docker; uses no live AWS resources
mise run verify
```

Typespecs document the public API and protocol/lifecycle contracts, and tests
check their presence. They are not static verification; Dialyzer is not configured.
Use `deps-update` only when intentionally updating the committed Mix lockfile.

## Install from source

Until an approved Hex publication, use a checked-out source dependency in your
application's `mix.exs` (adjust the path to your checkout):

```elixir
{:datadeft_auth, path: "../datadeft-auth/packages/datadeft-auth-elixir"}
```

Run `mix deps.get` and build `MIX_ENV=prod mix release` on the target Linux
architecture/libc with Rust installed. Deploy the resulting Mix release,
which includes the native executable; do not copy a macOS-built executable to
Linux. For a self-contained source artifact, use `package-stage` below rather
than copying this subdirectory alone: its development Cargo paths refer to
workspace crates. Git/subdirectory dependency installation is not validated.

## Explicit application configuration

The following illustrates the AWS configuration shape; replace the resource,
policy, sender and URL placeholders with reviewed application configuration.
It is not authorization to access resources or deploy without the application checks.

```elixir
config = %{
  mode: :aws,
  service: %{
    terms_version: "terms-v1",
    privacy_version: "privacy-v1"
  },
  email: %{
    link_base_url: "https://auth.example.test/auth/magic-link/landing?token=",
    subject: "Sign in",
    text: "Open {magic_link_url} to sign in."
  },
  secrets: %{
    active_ref: %{name_or_arn: "<auth-secret-name>", stage: "AWSCURRENT"},
    previous_ref: %{name_or_arn: "<auth-secret-name>", stage: "AWSPREVIOUS"}
  },
  aws: %{
    region: "eu-central-1",
    table: "<auth-table-name>",
    from_email: "login@example.test"
  }
}

children = [{DatadeftAuth, name: MyAuth, config: config, request_timeout: 5000}]
```

Keys load inside Rust from Secrets Manager; production configuration does not
contain raw secret documents. Previous-version loading is optional and follows
the existing Rust rotation policy. Configuration and keys reload on reconnect;
there is no background key-rotation polling. Deployments must deliberately reload
workers when rotating keys and retain previous keys for the required windows.

Use deployment roles/the supported AWS credential chain, least-privilege IAM,
HTTPS, configured DynamoDB encryption/TTL/backups and an approved SES identity.
Credentials never belong in this config, source, arguments or logs. `endpoint_url`,
inline documents and `fake_outbox` are local-test facilities, not production
shortcuts. `mode: :fake` is only for tests/development; state disappears on restart.

Email text and optional HTML must contain `{magic_link_url}`; subject must not.
The base URL is trusted application configuration with the token appended; review
its scheme, destination and query construction. The current renderer uses one
configured template for all resolved locale hints, not translated templates.

Startup is asynchronous:

```elixir
DatadeftAuth.status(MyAuth)
# {:ok, :transport_ready} or {:error, %DatadeftAuth.Error{code: :unavailable}}
```

With config, requests become available only after initialization is accepted.
Status is a transport ping, not a live DynamoDB/SES health probe. Without config,
`{DatadeftAuth, name: MyAuth}` is health-only and auth operations return a
configuration error. Give supervised instances distinct names/child IDs.

## Consuming-application HTTP mapping

Use the reference application's released **0.6.0 route layout** below.
The binding does not mount routes, render pages, issue redirects or set cookies;
all HTTP behavior belongs to the consuming application, with no Plug/Phoenix
requirement. Route names are not private Port operation names.

| Application route | Binding call | Application responsibility |
| --- | --- | --- |
| `POST /auth/magic-link/request` | `request_link(server, email, opts)` | Supply explicit consent; return generic acceptance, never the internal reason label. |
| `GET /auth/magic-link/landing` | `landing(server, token)` | Server-rendered mode: uniform scanner-safe page, account identification and bound confirmation form. Never consume on GET. |
| `GET /auth/magic-link/open` | `landing(server, token)` | Static-UI mode: same fixed `303` to `/auth/magic-link/confirm` for usable and unusable links. Set temporary state only when usable; do not clear it on an unusable cross-site landing. |
| `GET /auth/magic-link/confirm` | None | Serve the static confirmation page; it reads flow state, identifies the account and submits same-origin POST. This is not the consume endpoint. |
| `GET /auth/magic-link/confirm.js` | None | Serve the same-origin script with strict confirmation-page security headers. |
| `GET /auth/magic-link/flow-state` | `flow_state(server, cookie)` | Require same-origin fetch; clear unusable temporary state. |
| `POST /auth/magic-link/consume` | `confirm(server, cookie, confirmation, opts)` | Require same-origin/CSRF checks; set the session cookie and clear temporary state on success. |
| `GET /auth/magic-link/complete` | None | Fixed completion page, not another consume or session-creation operation. |
| `POST /auth/logout` | `logout(server, cookie, opts)` | CSRF-protected revocation before cookie clearing; pass the trusted country signal. |
| `POST /auth/pow/create` | `pow_challenge(server)` | Return the existing browser-compatible challenge shape. |
| `POST /auth/pow/validate` | `pow_verify(server, solution)` | Set the proof cookie only after verification; this does not spend its admission budget. |
| `GET /dev` | None | Development form only; do not mount in production. |
| `GET /dev/me` | `validate_session(server, cookie, opts)` | Development protected-resource demonstration only. |
| `GET /dev/latest-magic-link` | `fake_last_magic_link(server, email)` | Local test outbox only; never expose bearer links in production. |

Choose one landing mode in `email.link_base_url`: the configuration example uses
`https://auth.example.test/auth/magic-link/landing?token=`; static-UI mode uses
`https://auth.example.test/auth/magic-link/open?token=`. The destination remains
explicit application configuration, not a hardcoded library path. No old-route
aliases or automatic fallback redirects are supplied.

For real protected application routes, call `validate_session` server-side, then
enforce application authorization. Set any returned refreshed cookie; clear an
invalid session cookie. There is no required `/auth/session/validate` endpoint.
For each action protected by PoW, call `pow_admit(server, proof_cookie)` before
performing the action and fail closed on errors/exhaustion. Admission is independent
of magic-link operations; there is no new public admission endpoint.

Public operations return `{:ok, result}` or `{:error, %DatadeftAuth.Error{}}`.
Malformed argument types, malformed/duplicate/unknown options, invalid UTF-8 and
oversized payloads are refused without exposing their values. Results redact
bearer material, account identities and user IDs in Inspect; raw field access
still exposes those values to the application. Do not log fields or serialize
whole results into errors/telemetry.

`country` must come from a configured trusted edge, never user-submitted input.
Request consent options default false. Locale is presentation only. The application
owns permission checks; a successful cookie decryption is not authorization.

Enable PoW explicitly with `pow: %{difficulty: 5, proof_budget_per_solve: 1}` and
benchmark the configured difficulty on intended clients. Challenge TTL defaults
to 120 seconds, proof TTL to 10800; optional lifetime settings retain Rust caps.
A verified solution does not authorize an action: call `pow_admit` and check its
result. Budgets live in the shared store, not ETS or a process-local counter.

`fake_last_magic_link` reads the local test outbox and returns a bearer URL. It is
not a production API; do not expose it through a deployed route.

## Failure and HTTP handling

Error codes are private diagnostics, not HTTP status codes. The consuming HTTP
layer owns same-origin/CSRF validation, fixed redirects, account escaping,
no-store/CSP/frame/referrer headers, cookie attributes/lifetimes, trusted-edge
interpretation and IP/global admission. Preserve the repository's documented
uniform 400/401/503 contract and generic request/landing exceptions; never expose
internal reasons. No framework-specific HTTP helpers are included here.

Use host-only, HttpOnly cookies with explicit TTL, conservative SameSite and Secure
outside explicit local HTTP development. Primary session cookies use `Path=/`.
Optional `__Host-` session names require Secure, host-only scope and `Path=/`;
the binding does not set cookies or read old-name aliases. See
[the adoption guide](https://github.com/DataDeft/datadeft-auth/blob/v0.6.0/docs/integration.md#adopting-__host--cookie-names)
for the explicit application-owned migration and its temporary trade-off.
The reference confirm cookie uses `Path=/auth` to cover flow-state and consumption;
it therefore also accompanies the same-origin static confirmation page/script.
This is the accepted route-layout trade-off, not permission to expose the cookie
to JavaScript. Read exactly one configured cookie and refuse duplicates. Clear
with the same name/path/security attributes used when setting it. Magic-link
completion clears temporary flow state, not the independently owned PoW cookie.

Confirmation rejection/shape failure clears temporary flow state. On unavailable,
timeout or transport failure, do not infer rollback, do not automatically replay
the mutation and do not treat a fresh public call as the same commit attempt.
Logout is a separate revocation workflow; keep the session cookie on dependency
failure rather than declaring logout complete.

## Private transport contract

- Trusted absolute executable path; stdin/stdout only; no shell/network listener.
- Four-byte big-endian length prefix; 1–16384-byte UTF-8 JSON bodies; v1 envelope,
  strict fields/duplicate-key rejection and monotonic non-reused uint32 IDs.
- Exact build/version handshake, then explicit initialization before auth work.
  The owner's 30-second initialization deadline closes the pipe on expiry;
  native initialization observes EOF and cancels a stalled SDK future.
  Jobs/replies are bounded; replies may arrive out of order and must match the
  pending request's ID and operation. Application failures are per-request;
  malformed protocol is fatal.
- Rust checks the prefix before allocation. Elixir parses raw Port chunks rather
  than VM `packet: 4`, which could allocate an advertised body before validation.
- Default pending cap is 32. Port/pipe backpressure is not a hard VM-memory cap
  against a compromised child, nor is the GenServer mailbox an ingress limiter.
- Deadlines/caller death remove tracking; late replies are discarded. Neither
  cancels an already dispatched transaction. No automatic mutation replay.
- Failure closes the Port, fails pending calls once and restarts with bounded
  backoff. Configuration is resent before the replacement accepts auth work.
- Status/errors omit payloads; stdout is protocol-only and stderr is not merged.
  Executable paths/config are trusted deployment input. Protect crash dumps and
  tracing; process separation is crash containment, not a sandbox.

## Validation and deployment boundary

- **Outcome contract:** no durable commit plan or automatic replay. Transport
  tests cover lost replies across restart and discarded late confirmation
  replies. Applications own fresh-link recovery (see `confirm/4`).
- **Authentication:** fake-backed Elixir tests and a real DynamoDB Local pipe
  test cover country binding, concurrent one-time confirmation, cross-node key
  rotation, revocation, shared PoW budgets and dependency failure. Adapter tests
  exercise due/not-due refresh, original/refreshed cookie revocation and separate
  idle/absolute expiry without a production clock-override API.
- **Source delivery:** the isolated archive runs the Elixir suite, and a clean
  consumer Mix release completes request/landing/flow-state/confirm/validate/
  logout through its bundled executable. Native Linux CI must pass on the exact
  revision you consume. These tests do not validate your live AWS setup.
- **Before deployment:** review the application-owned HTTP responsibilities
  above, provision least-privilege AWS resources, verify real mail delivery in
  your approved environment, and exercise fresh-link recovery in your UI.
  A transport ping is not a dependency-health or production-readiness signal.

A package `docs` task, rendered API site, Dialyzer and Credo are not configured;
typespecs and passing tests must not be described as static verification.

Phoenix examples and prebuilt distribution are separately gated follow-ups.
No publishing, version bump, live AWS validation or production configuration
changes are authorized by this work.

## Packaging

`mise run elixir-verify` builds an isolated Hex source archive, unpacks/tests that
archive outside the repository, and builds/executes a clean consumer Mix release.
Sources vendor the workspace crates and stage a self-contained Cargo workspace;
no repository-relative dependencies, compiled binaries or build caches ship.
It uploads nothing. Fixtures and packaging stages use independent random temporary
names so concurrent BEAM instances do not reuse VM-local directory identifiers.

`mise -C packages/datadeft-auth-elixir run package-stage` creates a reviewable
source archive under `_build/publish_stage`. Publishing requires separate approval
and runs manually from that stage, never directly from the checkout.

## Dependency rationale

- Rust serde/serde_json: strict private protocol encoding/decoding.
- Rust Tokio: bounded service execution and existing AWS SDK futures.
- Rust rand_core/getrandom: OS-backed service entropy.
- Existing Rust service/AWS/PoW crates: authentication, storage, email, limits and
  cryptography; no duplicated Elixir security implementation.
- Existing AWS SDK/config crates: process-owned clients and supported credentials.
- Elixir Jason: maintained JSON codec; ordered objects preserve duplicate keys
  for validation without creating input-derived atoms.

MIT. Public package name: `datadeft_auth`, Hex owner: `l1x`.

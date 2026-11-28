# Using the Elixir 0.8 work in progress

**Development preview, not a complete login library yet.** The latest published
repository release is Rust 0.7.0; this native Elixir 0.8 implementation is not a
published Hex release. Its package version remains 0.7.0 for repository release
alignment. Do not add an assumed `~> 0.8` Hex dependency yet.

The crypto, storage and framework-neutral request, confirmation and session
services described below run with injected IO. Optional Plug helpers handle the
magic-link/session HTTP flow; production AWS transport is not bundled yet. Follow
[IMPLEMENTATION.md](IMPLEMENTATION.md) for the actual acceptance checklist.

## 1. Develop against the full repository checkout

Keep the full repository available: the tiny native crate depends on the Rust
core in `crates/`. A sparse checkout of just `hex/datadeft_auth/` is not enough.

Requirements: Elixir >= 1.16, OTP >= 26, the Rust toolchain pinned in root
`mise.toml`, and a native linker/toolchain. Ensure `cargo` is available in the
shell where your consumer compiles. Precompiled native distribution and clean
Hex-archive source fallback are not ready yet.

From the repository root:

```sh
mise run elixir-verify
mise -C hex/datadeft_auth run native-release-smoke
```

In a sibling application's `mix.exs`, add a local path dependency:

```elixir
{:datadeft_auth, path: "../datadeft-auth/hex/datadeft_auth"}
```

Then use your application's normal `mix deps.get` and `mix compile` commands.
The native library compiles at build time. A bundled Mix release needs the native
library, but not a Rust compiler or separate Rust process at runtime. Build for
the deployment OS/architecture/libc; do not copy a macOS artifact into Linux.
The current four-job Linux source-build matrix has passed CI; see
[release readiness](RELEASE-READINESS.md) for revision-specific evidence.
Precompiled artifact and clean-consumer validation remain release gates.

## 2. Email identity: available now

This normalizes exactly like Rust: trim surrounding Unicode whitespace, then
ASCII-lowercase the whole address, including the local part. It does not fold
Gmail dots or strip plus tags.

```elixir
alias DatadeftAuth.MagicLink.Core.Email

{:ok, email} = Email.normalize("  Developer@Example.Test  ")
"developer@example.test" = Email.value(email)
{:error, :invalid_email} = Email.normalize("not an address")
```

Use `Email.from_normalized/1` when reading stored identities: it validates without
silently repairing them. Inspection is redacted; `Email.value/1` is explicit
sensitive access, not something to put in logs.

## 3. Branca crypto: available now, not session authentication

This is the tiny NIF's current public Elixir API. The following is a development
round-trip check, not a recipe for issuing login or session cookies. Run it in a
script, not an interactive shell that prints secret assignments.

```elixir
alias DatadeftAuth.Token.Branca

# Ephemeral development key. Production must load stable, purpose-separated
# secrets and use the higher-level keyring/cookie API once it is implemented.
key = :crypto.strong_rand_bytes(32)
now_unix = System.system_time(:second)
payload = <<1, 2, 3>>

{:ok, token} = Branca.encode(payload, key, now_unix)
{:ok, {^now_unix, nonce, ^payload}} = Branca.decode(token, key)
24 = byte_size(nonce)
{:error, :invalid_token} = Branca.decode("not-a-token", key)

:ok
```

`encode/3` draws a fresh OS CSPRNG nonce internally. You do not choose the nonce.
`decode/2` returns authenticated `{timestamp, nonce, plaintext}` and rejects
wrong keys, tampering and noncanonical encodings. Calls run on dirty CPU
schedulers; the wrapper delegates to the existing Rust token core.

Limits: 32-byte key, at most 1024 plaintext bytes, at most 1437 token bytes, and
a timestamp in `0..4_294_967_295`. Encode returns `{:error, :invalid_input}` for
bad shape and may return `{:error, :unavailable}`. Decode returns
`{:error, :invalid_token}` or `{:error, :unavailable}` on failure.

**Successful decryption is not a login.** This primitive does not check TTL,
future skew, purpose, key windows, country, account status or server-side session
revocation. Never authorize a request from its result alone. Do not turn the
example payload into an improvised session format: Rust compatibility requires
the exact higher-level framing. `DatadeftAuth.Token.Keyring`,
`DatadeftAuth.MagicLink.Core.ConfirmCookie`, and
`DatadeftAuth.MagicLink.Service.SessionCookie` now implement that crypto framing
and freshness. For session admission use `DatadeftAuth.MagicLink.Service.Session`
with an injected live session repository, not `SessionCookie.open/4` alone.

Never print/log keys, tokens or plaintext. NIF load failure has no alternate
crypto fallback. A native fault can crash BEAM; Rustler is not process isolation.
See [CRYPTO-DEPENDENCIES.md](CRYPTO-DEPENDENCIES.md) for the safety contract.

## 4. DynamoDB storage: implemented boundary, application IO still required

The adapter is `DatadeftAuth.AWS.DynamoDB`. It currently provides:

- `new/4` (or `new/3` with the documented default cleanup grace): explicit table,
  `DatadeftAuth.AWS.StorageKey`, and `{client_module, client_state}`.
- `find_user_for_authentication/2`: keyed lookup plus strongly consistent,
  authoritative profile validation.
- `with_previous_storage_key/2` and `rekey_email_lookups/1`: rotation fallback,
  migration and dormant-account rekeying.
- `put_magic_link_if_absent/2` and `find_magic_link_for_authentication/2`: keyed
  challenge creation and side-effect-free candidate reads.
- `commit_magic_link_authentication/2`: atomic consume/account/session/index
  transaction, **for a trusted service that has already performed verification**.
- `find_session/3`, `is_session_owner_active/3`, and `revoke_session/3`: strongly
  read and revoke live sessions, including across the rotation window.
- `check_rate_limit/5` and `check_lifetime_limit/5`: shared atomic counters.

The client must implement `DatadeftAuth.AWS.DynamoDB.Client.request/3` with the
DynamoDB JSON AttributeValue protocol and scrubbed error contract. Production
signing, credentials, HTTP, timeouts and error classification are not bundled yet.
The loopback-only DynamoDB Local client in `test/support/` is test code, not an
AWS client to deploy. Never use ephemeral development storage keys for a real
shared table: all nodes need the configured current/previous keys.

Do not directly expose the commit API as a route. It is not a verifier and does
not replace confirmation binding, consent/policy checks or cookie minting. A
transaction `:unavailable` result may have committed: only retry the identical
command with its original attempt ID; do not regenerate IDs or blindly replan.

The real mixed-language test is
[`test/compatibility/dynamodb_test.exs`](test/compatibility/dynamodb_test.exs).
It demonstrates shared account identity and transaction/counter behavior, not a
complete production login integration.

## 5. Session admission: available with injected IO

Construct `Session.new/3` with a session keyring, a repository such as
`{DatadeftAuth.AWS.DynamoDB, store}`, and a function returning
`{:ok, unix_seconds}`. Default bounds are 24 hours idle and 30 days absolute;
`Session.new/5` takes stricter ages and a country policy.

- `Session.validate/3` accepts a cookie and a **trusted-edge** country (or
  `nil`). It checks both freshness bounds, live storage and owner status.
- `Session.refresh/2` accepts only the normal validation result, in the same
  request. It returns `{:ok, nil}` until reissue is due and preserves original
  issue time, session ID and country. Send any fresh cookie with `no-store`.
- For logout, call `Session.validate_for_logout/2` and pass the returned record's
  session ID to `Session.revoke/2`. It skips only idle/country admission checks,
  and cannot feed refresh. Require a CSRF-protected same-origin POST and revoke
  server state before clearing the cookie. Plug consumers can use the `logout/2`
  helper below.

## 6. Requesting magic links with injected delivery

Use `DatadeftAuth.MagicLink.Service.Request.new/4` with a purpose-separated
lookup key, your terms/privacy version pair, and injected repository, limiter,
outbox and clock. The DynamoDB adapter implements both repository and limiter.
An optional `LocaleAllowlist` resolves request hints to configured email locales.

`Request.request/5` checks both consents, applies the four keyed limits,
persists the challenge, then passes a redacted `Mail` to the outbox. Render its
bearer token only for delivery. The host application must render the same
public response for sent and throttled outcomes and own edge/IP/global limits.

## 7. Scanner-safe flow with injected storage

Your Plug/Bandit application owns routes, rendering, authorization and edge
controls. The framework-neutral `DatadeftAuth.MagicLink.Service.Flow` provides
`land/2`, `read_state/2` and `confirm/4`. Use the same lookup key, consent
versions and challenge TTL as the request service. Pair with your session
service using the same session keyring, absolute lifetime and country policy.
The framework-neutral application integration follows this scanner-safe sequence:

1. Request: validate identity/consent/locale, apply keyed limits, enqueue email,
   and return a generic public response.
2. Landing `GET`: verify candidate state, identify the account and mint bound
   temporary flow state. Never consume a link or create a session here.
3. Confirmation: same-origin, CSRF-protected `POST`; validate the bound nonce,
   account and verifier; mint the cookie before the atomic authentication commit;
   clear temporary flow state and redirect to a fixed clean URL.
4. Authenticated requests: validate cookie policy plus live server-side session
   and account state. Refresh only after successful validation.
5. Logout: CSRF-protected `POST`; revoke server-side state before clearing the
   cookie. Independent PoW middleware owns its own proof-cookie lifecycle.

## 8. Optional Plug adapter

Add `{:plug, "~> 1.20 and >= 1.20.4"}` to the consuming project to enable
`DatadeftAuth.MagicLink.Plug`. Build its configuration with `new/5`, passing the
canonical public HTTPS origin, request service, flow service, session service,
and optional fixed redirect paths. Do not construct the origin or redirect
paths from a request. For loopback development only, pass `insecure_local: true`.
Country binding is opt-in via `country_header:`, and only safe when the edge
overwrites the header and direct origin access is blocked.

| Route (example mounting) | Helper |
| --- | --- |
| `POST /auth/magic-link/request` | `request/2` — bounded JSON; sent and throttled share one response |
| `GET /auth/magic-link/open?token=…` | `open/2` — redirect to a fixed confirmation page without echoing the token |
| `GET /auth/magic-link/flow-state` | `flow_state/2` — same-origin fetch metadata required, no CORS; returns the account label and nonce |
| `POST /auth/magic-link/consume` | `confirm/2` — checks exact origin and nonce, sets session, clears flow, redirects |
| An authenticated route | `authenticate/2` — returns the live record and an unsent no-store connection, or sends `401`/`503` |
| `POST /auth/logout` | `logout/2` — checks exact origin, revokes, then clears the session and redirects |

Alternatively, use `landing/3` and a server-rendered, escaped confirmation form
instead of `open/2` and `flow_state/2`. Mount flow-state and confirmation under
`/auth` so the short-lived `dd_auth_confirm` cookie is in scope. The handlers
read their own bounded bodies; don't run generic body parsers first. Log only
`conn.private[:datadeft_auth_reason]` for these handlers, never the raw request,
full connection, URL query, body, or cookie and response headers. Apply this
logging exclusion at the app, proxy, and edge before deployment.

The [independent Bandit example](../examples/bandit_magic_link/README.md) shows
browser login and logout with local-only storage and delivery. It has no PoW,
production transport or deployment configuration. Draft PR #45 tracks the
remaining work.

## Validation

From the repository root:

```sh
mise run verify
mise run compatibility-test
mise run dynamodb-compatibility-test  # Docker required
mise -C hex/datadeft_auth run native-release-smoke
```

No release is published by these tasks. Precompiled artifacts, clean archive
consumers, shared-browser PoW integration and independent security review remain
release acceptance gates.

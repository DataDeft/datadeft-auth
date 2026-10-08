# Integration guide

This guide is for an application that consumes the datadeft-auth libraries. It
is the entry point for an implementation agent. Read it first, then follow the
links to the authoritative docs and the runnable example.

Scope: this guide shows how to wire the libraries into an Axum application. The
libraries own the auth logic. Your application owns routes, deployment policy,
secrets, email templates, logs, and edge policy.

## Read these next, in order

1. [architecture.md](architecture.md) for the components, the flow, and the
   trust boundaries.
2. [security.md](security.md) for the required security behavior and the TTL
   baseline. These rules are not optional.
3. The module docs and the compiling quickstart in
   `crates/datadeft-magic-link-axum/src/lib.rs`.
4. `examples/axum-magic-link` for a complete, runnable, fake-backed integration.
   This is your reference. Mirror its wiring.

Do not invent an approach. Follow the example and the trait contracts.

## Install registry versions

The first registry release is being prepared; use these dependencies after it
has been approved and published. Rust 1.88 or newer is required.

```toml
[dependencies]
datadeft-pow-core           = "0.2"
datadeft-magic-link-service = "0.2"
datadeft-magic-link-axum    = "0.2"
datadeft-magic-link-aws     = { version = "0.2", features = ["aws"] }
# Add datadeft-pow-axum = "0.2" for the PoW HTTP helpers.
```

```sh
bun add @datadeft/protect-client
```

The other core crates arrive transitively. The service and Axum crates
re-export the types needed for magic-link integration. Commit the consumer
lockfiles. No git credentials or vendored TypeScript are needed.
See [migration-registries.md](migration-registries.md) for the complete rename
map and worker migration.

## What you provide

The libraries hold no globals. You inject every dependency.

- A `Clock` and a CSPRNG. Use the OS CSPRNG. Never use a fake clock or fake
  entropy in production.
- Keyrings built from a `RootSecret` loaded from AWS Secrets Manager. Use one
  keyring per purpose: `SessionCookie`, `MagicLinkConfirmCookie`, and the
  proof-cookie purpose `PowProofCookie`. Configure an active slot and
  verify-only slots. Rotate about every 90 days and keep the previous key
  verify-only for at least 31 days. `resolve_auth_secrets` in
  `datadeft-magic-link-aws` loads them.
- A `MagicLinkEmailRenderer`. You own the subject, the text, and the HTML body,
  and you own languages. The library gives you `MagicLinkEmail { email, token,
  expires_at_unix }`. You return `RenderedMagicLinkEmail`. The library never
  stores or templates the message body.
- The storage and delivery adapters. Use `datadeft-magic-link-aws` for DynamoDB and
  SES, or implement the repository, session, limiter, and outbox traits
  yourself. Use `FakeDynamoDbAuthStore` and `FakeMagicLinkOutbox` for tests.
- Routes, cookie configuration, redirects, body limits, and token-safe logging.

## The flow you wire

The Axum handlers are headless. They run the input checks and return structured
results plus prepared cookie headers. Your application renders the responses.

1. Request. `POST` to `request_magic_link`. It validates consent and the
   normalized email, mints a selector and a verifier, stores only keyed lookup
   material, and hands the URL to your outbox.
2. Landing. `GET` to `magic_link_landing` (`begin_magic_link_landing`). This is
   side-effect-free and repeatable. It sets the `dd_auth_confirm` cookie. It
   never consumes the token. Render the account page and a same-origin `POST`
   form.
3. Confirm. `POST` to `magic_link_confirmation` (`confirm_magic_link_flow`).
   Same-origin only. It consumes the token and creates the session in one atomic
   transaction, and it issues the `dd_session` cookie. Clear `dd_auth_confirm`
   here.
4. Validate. Check `dd_session` on protected routes. On logout, revoke server
   state before you clear the cookie. There is no refresh token. When the
   session lifetime lapses, the user re-authenticates with a new magic link.

## Cookies

| Cookie | Purpose | Default lifetime | Path |
| --- | --- | --- | --- |
| `dd_session` | logged-in session | 24h idle, 30d absolute | `/` |
| `dd_auth_confirm` | scanner-safe confirmation flow | 5 minutes | `/auth` |
| `dd_pow` | proof-of-work admission | 3 hours | `/` |

All are `HttpOnly`, `Secure` (outside local development), `SameSite=Lax`, and
host-only.

## Security invariants you must uphold

See [security.md](security.md) for the full set. The critical ones:

- Consume the magic link only on the same-origin confirmation `POST`. Never on
  `GET`.
- Keep the landing `GET` side-effect-free and repeatable. Email scanners
  prefetch it.
- Respond uniformly. Return a rejected landing or confirmation with the same
  HTTP status as success, so an attacker cannot probe link validity. Only
  genuine `Unavailable` or `Internal` failures use a 5xx.
- Clear `dd_auth_confirm` on a rejected or internal confirmation. Preserve it on
  `Unavailable` so the user can retry.
- Stamp security headers on every landing and confirmation response.
- Never echo the raw token into a body or logs. HTML-escape any rendered account
  identity.
- Implement the repository contract atomically. Use strong reads. Store only
  keyed HMAC lookup material and verifier hashes, never raw tokens, selectors,
  or verifiers.
- Store the normalized email at rest readable, protected by DynamoDB KMS and
  least-privilege IAM. Do not add application-layer field encryption.

## The mandatory deployment gate

A magic-link token appears in the landing request target. You must configure
proxy or load-balancer request-line bounds. You must also prove that access
logs, middleware, tracing, metrics, and error reporting use route templates and
never retain raw request targets, tokens, confirmations, or cookies. The
handlers prove non-reflection only after handler entry. They cannot make an
unreviewed outer stack safe. See the "Mandatory deployment gate" section in
`crates/datadeft-magic-link-axum/src/lib.rs`.

## Proof-of-work admission

Proof-of-work is the primary defense against dumb bots. It is recommended.

Migrating an existing consumer from v0.1.x? Follow
[migration-v0.2.0.md](migration-v0.2.0.md); it is written to be handed to an
implementation agent as-is.

Wire the `datadeft-pow-axum` glue. `POST` to `mint_pow_challenge` for `pow/create`,
and `POST` to `verify_pow_solution` for `pow/validate`, which returns a
`PowAdmission`: the `dd_pow` `Set-Cookie` header plus the server-derived
`mint_to_verify_ms` solve-timing signal (see "Solve-timing signal" in
`docs/security.md`). Its `classify_solve` hook can stamp an app-defined
class byte into the cookie; pass `|_| None` to opt out. Gate the magic-link
request behind a valid `dd_pow` cookie. On the browser,
bundle the `@datadeft/protect-client/worker` entry into a served ES module
worker, then call `protect({ workerUrl, createUrl, validateUrl })` on your login
page. See [../packages/dd-protect-client/README.md](../packages/dd-protect-client/README.md).

The challenge lifetime is 2 minutes. The proof-cookie lifetime is 3 hours by
default, configurable, and stateless.

## Runtime note

The dependency traits require `Send` futures and use static dispatch only. Run
on a multi-threaded Tokio runtime, which is the Axum default. Do not wrap the
traits in `dyn` trait objects.

## Definition of done

Complete the production checklist in [onboarding.md](onboarding.md). In
particular:

- The magic-link flow works end to end against real DynamoDB and SES.
- Integration tests cover replay, concurrent confirmation, ambiguous retry,
  logout, and post-revocation visibility.
- A production-like probe confirms that logs contain no token material.
- The consuming application tests pass.

Report changed files, the traits you implemented, security-sensitive decisions,
tests added, and any checklist item you could not complete.

## Clock-skew policy

Existing APIs allow timestamps up to 60 seconds ahead of the verifier. This is
a future-time tolerance, not extra TTL. For a stricter 30-second requirement, use
`verify_solution_with_clock_skew(..., 30)` and
`verify_pow_proof_cookie_with_clock_skew(..., 30)`. Axum users set
`PowPolicy::new(difficulty, 120)?.with_clock_skew_secs(30)` for challenges and
use the explicit proof-cookie verifier with the same bound at their gate.
Zero rejects all future timestamps.

The token crate also exposes `mint_bound_cookie_with_clock_skew` and
`parse_bound_cookie_with_clock_skew`; both take `clock_skew_secs` last. Existing
magic-link service wrappers retain their 60-second policy. The PoW policy does
not silently change another subsystem's cookie validation.

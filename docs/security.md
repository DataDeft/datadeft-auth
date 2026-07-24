# Security rules

## Security model

Source code secrecy is not a security boundary. Secrets, keys, peppers, and runtime config provide security.

This repo must never contain:

- production Branca keys
- HMAC peppers
- session secrets
- AWS credentials
- magic-link tokens
- captured cookies
- real customer emails
- production database dumps

## Token design

- Magic-link tokens are one-time secret bearer credentials.
- Store only keyed lookup material, never raw token parts, raw selectors, or raw verifiers.
- Session cookies must be encrypted/authenticated.
- Token kinds must be domain-separated so one token type cannot validate as another.
- Verification must fail closed, including unknown key IDs, expired values, malformed inputs, and storage races.
- Token parsers must reject malformed, ambiguous, mixed-version, or trailing-data inputs.

## One-time magic-link consumption

Magic-link consume flows must enforce one-time use.

Required behavior:

- Lookup by keyed selector material only.
- Check expiration before creating a session.
- Compare verifier-derived material in constant time.
- Atomically consume the token before or in the same transaction as session creation.
- Use conditional delete/update, consumed markers, or an equivalent compare-and-swap mechanism in storage adapters.
- Treat already-consumed, missing, expired, malformed, and invalid-verifier tokens as the same public failure class.
- Apply failed-attempt throttling where the store can safely count attempts without leaking identifiers.
- Include replay tests and concurrent consume/race tests for service logic and real storage adapters.

## HMAC lookup material

Use secret-keyed HMAC for lookup keys derived from:

- email addresses
- magic-link selectors
- magic-link verifiers
- session IDs
- rate-limit keys containing sensitive material

Do not use bare SHA-256 for secret or PII-derived lookup material.

## Logging

Never log:

- raw magic-link tokens
- raw selectors/verifiers
- raw cookies
- Branca tokens
- session IDs
- key material
- HMAC peppers
- email addresses unless explicitly approved for a specific app

Use redacted `Debug` and app-level derived identifiers.

## Timing and comparison

Use constant-time comparison for:

- verifier hashes
- token MAC/tag values
- stored secret-derived values

Do not add early-return comparison logic for secrets.

## Configuration

- Production secrets must come from the consuming application, not this library repo.
- Cookie names, issuer, audience, TTLs, peppers, and keys must be configurable.
- Examples may include clearly fake development values only.
- No production-looking domains, emails, tokens, keys, ARNs, table names, or account IDs in tests or docs.
- No production key, pepper, cookie, issuer, audience, domain, or TTL default may be silently assumed by library code.

## Key management and rotation

- Use purpose-separated keys and peppers for Branca tokens, session cookies, HMAC lookup material, PoW signing/MAC material, and any adapter-specific encryption/MAC use.
- Do not reuse one secret across token kinds, lookup domains, cookies, and proof-of-work contexts.
- Symmetric keys and peppers must provide at least 256 bits of entropy unless a chosen primitive requires more.
- Key IDs must be validated and domain-separated; unknown key IDs fail closed.
- Keyrings should support explicit states: active for minting, verify-only for migration, and retired/disabled for rejection.
- Rotation tests must cover active-key minting, verify-only validation, retired-key rejection, and unknown-key rejection.
- Development examples may generate fake keys, but production code must require caller-supplied key material.

## Cookie security

Cookie helpers must be secure by default.

Required defaults and rules:

- Cookie names use lower `snake_case`, optionally with an app prefix, for example `dd_session` or `dd_auth_state`.
- Do not require `__Host-` or `__Secure-` cookie-name prefixes for the first version.
- `HttpOnly` for session and auth cookies.
- `Secure` except for explicitly marked local-development HTTP use.
- Conservative `SameSite`; use `Lax` by default, `Strict` when the app can tolerate it, and `None` only with `Secure` plus explicit configuration.
- Host-only cookies by default; do not set `Domain` unless the consuming app explicitly configures it.
- Primary session cookies use explicit `Path=/` when they are intended to authenticate the whole app.
- Temporary auth helper cookies use the narrowest practical auth path, such as `/auth` or `/api/auth`, unless they intentionally need app-wide access.
- Never rely on browser default cookie path behavior; always set `Path` explicitly.
- Explicit `Max-Age` or expiry tied to the session/token TTL.
- Clear cookies on logout, invalid session, and expired session responses where the adapter can do so.
- Document CSRF expectations for cookie-authenticated routes; unsafe methods need CSRF protection or equivalent same-site guarantees.

## Email identity and normalization

Email identity is an exact match on the app-provided normalized email value.

- Prefer a `NormalizedEmail` domain type that the consuming application constructs before calling these libraries.
- The libraries compare normalized email values exactly for user lookup, HMAC lookup material, rate-limit keys, storage keys, and tests.
- Do not implement provider-specific alias handling: no Gmail dot folding, no plus-address/tag stripping, and no provider-specific alias expansion.
- Do not apply hidden case-folding rules. If a consuming app lowercases all or part of an email address, it must do so before constructing `NormalizedEmail`.
- Treat normalized emails as sensitive identifiers and redact them in `Debug`, errors, logs, fixtures, and snapshots.

## Magic-link URL handling

Magic-link tokens commonly appear in URLs and must be treated as log-sensitive secrets.

- Do not log full consume URLs, query strings, route captures, or redirect destinations that contain token material.
- Scrub token path/query fields before tracing, metrics labels, access logs, error reports, and panic payloads.
- Consume the token and redirect to a clean URL without the token.
- Do not place token values in `Location` headers, HTML, JavaScript, analytics events, or downstream callback URLs.
- Set or document `Referrer-Policy: no-referrer` or an equivalent policy for magic-link landing/consume flows.

## Rate limiting and abuse controls

Magic-link request and consume flows must have limiter hooks that support non-enumerating abuse resistance.

Minimum limiter use cases:

- request by normalized-email HMAC
- request by client/app-derived key, such as IP hash or device/session key supplied by the app
- consume by selector-derived key
- consume by client/app-derived key
- optional outbox/email send limiting

Public responses for throttled, unknown-user, already-consumed, expired, and invalid-token cases must remain generic unless a consuming app explicitly opts into different UX.

## One supported way

No legacy support in these libraries unless explicitly versioned and documented.

Do not add:

- dual-read
- dual-write
- compatibility fallback
- old token parser branch
- deprecated alias

Forward version markers are allowed, for example:

```text
v1
pow-v1
ml1
```

They name the one current format.

## Dependency and supply-chain hygiene

- Prefer small, maintained crates with clear security posture.
- Avoid dependencies that can parse or execute untrusted input unless required.
- Keep network/cloud SDK dependencies out of core crates.
- Review crypto-related dependencies before adding them.
- Run `cargo deny`, `cargo audit`, or an equivalent vulnerability/license/yank check before release.
- Add a `mise run audit` task once dependency policy tooling is configured, and include it in release verification.
- Document the reason for every dependency added for crypto, parsing, HTTP, AWS, async, or token handling.

## Security review checklist

Before a phase is accepted, confirm:

- No secret values appear in source, docs, tests, examples, fixtures, logs, or snapshots.
- `Debug` is redacted for sensitive types.
- Error messages do not expose sensitive values.
- Tests include tamper, replay, expired-token, malformed-token, and unknown-key cases where applicable.
- Magic-link consume tests prove one-time use and include a concurrent consume/race case for service/storage layers.
- Cookie helpers default to `HttpOnly`, `Secure` outside local development, conservative `SameSite`, host-only scope, explicit path, and explicit TTL.
- Key material is purpose-separated and rotation states are tested where keyrings exist.
- Rate-limit hooks cover request and consume flows with generic public responses.
- Magic-link URL handling scrubs token material from logs, redirects, headers, and telemetry.
- Core code is deterministic and cannot read clock, randomness, environment, filesystem, or network.
- Adapter code maps infrastructure failures into safe public errors.
- Dependency audit/license checks pass before release.

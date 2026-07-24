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

## Token and cookie inventory

| Item | Where it lives | Secret? | Purpose | Recommended TTL |
| --- | --- | --- | --- | ---: |
| Magic-link token | Email URL on the landing `GET` route | Yes | Proves the user has access to the email link | 10 minutes |
| Magic-link selector | Part of the magic-link token | Not sufficient alone | Keyed lookup input; never store raw | Same as magic link |
| Magic-link verifier | Part of the magic-link token | Yes | Secret checked during consume | Same as magic link |
| Magic-link flow cookie or nonce | Browser cookie or server-side state after `GET` landing | Sensitive flow secret | Binds scanner-safe landing to user-click `POST` consume | 5 minutes, capped by remaining magic-link TTL |
| PoW challenge token | Response body or temporary client state | MACed/signed integrity value | Browser work challenge | 5 minutes |
| PoW solution/proof | Request body/header from browser | Not long-term secret | Shows a challenge was solved | One request; verify immediately |
| PoW proof cookie | Browser cookie | Sensitive short-lived auth-flow value | Lets the auth flow continue without repeated PoW | 10 minutes |
| Session ID or session token | Encrypted/authenticated session cookie or server-side store key | Yes | Identifies an authenticated session | Idle/absolute session TTL |
| Session cookie | Browser cookie | Yes | Authenticates user requests | Idle 24 hours; absolute 30 days |
| Key IDs | Token/cookie metadata | No | Selects verification key | No independent TTL |
| HMAC lookup keys | Database/storage | Sensitive derived value | Lookup without storing raw PII/token parts | Cleanup TTL only, not validity |
| Rate-limit keys | Limiter store | Sensitive derived value | Abuse protection | Window-specific, for example 10 minutes, 1 hour, or 24 hours |

## TTL baseline

| Config | Recommended value | Notes |
| --- | ---: | --- |
| `magic_link_ttl` | 10 minutes | Acceptable range is usually 5–15 minutes. |
| `magic_link_flow_ttl` | 5 minutes | Must not exceed remaining magic-link TTL. |
| `pow_challenge_ttl` | 5 minutes | Limits stale challenge replay. |
| `pow_proof_cookie_ttl` | 10 minutes | Short auth-flow continuity only. |
| `session_idle_ttl` | 24 hours | Sliding refresh is allowed, but only within absolute TTL. |
| `session_absolute_ttl` | 30 days | Hard cap even with activity. |
| `magic_link_cleanup_grace` | 24 hours after expiry | Cleanup only; does not extend token validity. |
| `session_cleanup_grace` | 24 hours after absolute expiry | Cleanup only; does not extend session validity. |

Rules:

- Magic-link and PoW values are pre-auth and must be short-lived.
- Session cookies are post-auth and may be longer-lived.
- Server-side expiry wins over browser cookie expiry.
- Cookies must not outlive the server-side session/token validity they represent.
- Sliding sessions may refresh idle expiry, but must never exceed absolute expiry.
- Cleanup TTL is for storage deletion only; it is not validity TTL.
- Expired, consumed, missing, malformed, and invalid tokens all return the same generic public failure.

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

## Secret manager abstraction

Production deployments use AWS Secrets Manager for secret storage, but core crates must not know how to fetch secrets.

Use an extremely thin supported-manager enum plus secret-reference config. It is configuration only; it is not a dependency-injection framework.

Example shape:

```rust
#[non_exhaustive]
pub enum SupportedSecretManager {
    AwsSecretsManager,
}

pub struct SecretRef {
    pub manager: SupportedSecretManager,
    pub name: SecretName,
    pub version_stage: Option<SecretVersionStage>,
}
```

Rules:

- V1 supports `AwsSecretsManager`. Add new variants only when an implementation and tests exist.
- Core crates accept loaded key material/keyrings only; they must not depend on AWS SDK, environment variables, network clients, or secret-manager resolvers.
- Adapter/setup code resolves `SecretRef` values into redacted secret material and purpose-separated keyrings before calling core/service APIs.
- The abstraction should do only lookup metadata and loaded-secret handoff. Do not add policy engines, global registries, background refreshers, implicit environment reads, or provider-specific behavior to core APIs.
- For AWS Secrets Manager, map `AWSCURRENT` to the active key by explicit config and `AWSPREVIOUS` to verify-only only when rotation is intentionally enabled.
- Retired/disabled keys are not loaded for verification.
- Secret names, ARNs, version IDs, and version stages are operational metadata: do not expose them in public errors, telemetry labels, or default `Debug` for secret references.
- Secret payloads must be redacted in `Debug` and zeroized where practical.

## Rotation cadence baseline

For a 30-day absolute session validity, old session keys must remain available for verification/decryption for at least the full session lifetime after they stop minting new cookies.

Recommended v1 cadence:

| Secret/key class | Active rotation cadence | Verify-only retention | Notes |
| --- | ---: | ---: | --- |
| Session cookie encryption/signing keys | 90 days | 31 days after replacement | 30-day absolute session TTL plus deploy/clock-skew grace. |
| Branca/session token keys, if separate from cookie keys | 90 days | 31 days after replacement | Match the longest token/session validity that key can verify. |
| Magic-link HMAC peppers/keys | 90 days | `magic_link_ttl` + 24h cleanup grace | Never mint new links with old keys; keep only long enough to reject/verify outstanding records safely. |
| PoW signing/MAC keys | 90 days | `pow_challenge_ttl` + 24h cleanup grace | Keep old key only for outstanding challenges/proof cookies. |
| Rate-limit HMAC peppers | 90 days | longest limiter window + 24h | During rotation, apps may accept temporary limiter bucket fragmentation. |

Rules:

- `AWSCURRENT` is the active mint/encrypt/sign key.
- `AWSPREVIOUS` is verify-only/decrypt-only when rotation is intentionally enabled.
- Never mint new tokens, cookies, HMAC lookup values, or PoW challenges with verify-only keys.
- Session keys should not rotate more frequently than the verify-only retention window unless the implementation supports an explicit list of older verify-only secret references beyond `AWSPREVIOUS`.
- With the 30-day session baseline, keep the previous session key for at least 31 days and prefer 90-day session key rotation.
- If a value validates with a verify-only session key, the adapter may reissue the cookie with the active key after normal authorization checks.
- Magic-link and PoW keys can retire much sooner than session keys because their validity windows are minutes, not days.
- Unknown, missing, retired, disabled, or malformed key IDs fail closed with generic public errors.

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

Scanner-safe magic-link flow:

1. The email link opens a `GET` landing route with the token in the URL.
2. The `GET` route must not consume the token, create a session, or mark the token as used.
3. The `GET` route renders a generic confirmation page requiring an explicit user action, such as a “Continue sign in” button.
4. The confirmation action submits a same-origin `POST` consume request. Do not auto-submit with JavaScript or redirect automatically from `GET` to consume.
5. The `POST` consume route atomically consumes the token, clears any temporary flow state, creates the session, and redirects with `303 See Other` to a clean URL without token material.

Implementation rules:

- Do not log full landing/consume URLs, query strings, route captures, or redirect destinations that contain token material.
- Scrub token path/query fields before tracing, metrics labels, access logs, error reports, and panic payloads.
- Prefer a short-lived `HttpOnly` flow cookie or server-side nonce between landing and consume so token material is not embedded in HTML forms.
- If a fallback form value must carry token material, it must be short-lived, single-use, `Cache-Control: no-store`, and never rendered with third-party assets.
- Do not place token values in `Location` headers, JavaScript, analytics events, downstream callback URLs, or clean post-consume pages.
- Landing pages must use `Cache-Control: no-store` and no third-party scripts, pixels, stylesheets, or analytics.
- Set or document `Referrer-Policy: no-referrer` or an equivalent policy for magic-link landing/consume flows.
- Treat scanner safety as protection against GET-only email scanners; active scanners that submit forms are handled by short TTLs, one-time atomic consume, and generic failure handling.

## Rate limiting and abuse controls

Magic-link request, consume, and PoW flows must have limiter hooks that support non-enumerating abuse resistance.

Limiter keys:

- `normalized email HMAC` is derived from the exact-match `NormalizedEmail` value with a rate-limit pepper and domain-separated purpose string.
- `selector-derived key` is derived from magic-link selector lookup material, never the raw selector.
- `client key` is supplied by the consuming app. For Axum helpers, derive it from a trusted reverse-proxy client IP only when the request came through configured trusted proxy infrastructure.
- Do not store raw emails, raw IP addresses, raw selectors, raw verifiers, or raw tokens in limiter storage.

V1 starting thresholds:

| Flow | Limiter key | Suggested threshold | Public response |
| --- | --- | ---: | --- |
| Request magic link | normalized email HMAC | 3 per 15 min, 10 per 24h | Always generic accepted |
| Request magic link | client key | 10 per 10 min, 50 per 1h | Always generic accepted |
| Email outbox send | normalized email HMAC | 3 per 1h, 10 per 24h | Suppress send, generic accepted |
| Magic-link consume | selector-derived key | 5 failed attempts per token TTL | Generic invalid/expired |
| Magic-link consume | client key | 20 per 10 min, 100 per 1h | Generic invalid/expired |
| Malformed consume attempts | client key | 20 per 10 min | Generic invalid/expired |
| PoW challenge mint | client key | 30 per 10 min | Generic throttled/try later |
| PoW verify failures | client key | 30 per 10 min | Generic failure |

Rules:

- Treat these thresholds as configurable v1 starting values; production apps may tighten them after observing traffic.
- Unknown user, throttled user, and successful request-magic-link responses must look the same publicly.
- For request flow throttling, suppress email sends but return the same generic accepted response.
- Limiter storage failures on abuse-sensitive paths should fail closed with a generic try-later response.
- Public responses for throttled, unknown-user, already-consumed, expired, and invalid-token cases must remain generic unless a consuming app explicitly opts into different UX.

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
- Key material is purpose-separated and rotation states are tested where keyrings exist, including 90-day session rotation, at least 31-day verify-only retention, verify-only rejection for minting, and retired-key rejection.
- Rate-limit hooks cover request, consume, outbox-send, and PoW flows with generic public responses and configurable v1 thresholds.
- Magic-link URL handling scrubs token material from logs, redirects, headers, and telemetry.
- Core code is deterministic and cannot read clock, randomness, environment, filesystem, or network.
- Adapter code maps infrastructure failures into safe public errors.
- Dependency audit/license checks pass before release.

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
- **Storage keying is adapter-owned by decision (2026-07-27).** The repository
  traits pass raw `SessionId` / `NormalizedEmail` / `RateLimitKey` values, and
  each storage adapter must key them (via the shared
  `dd_magic_link_core::domain_separated_lookup_hmac` framing, under its own
  domain and secret — see `StorageHmacKey` in `dd-magic-link-aws`) before any
  value reaches storage. The type system does not enforce this: a new
  repository implementation that stores raw ids would compile. Accepted
  because every adapter is first-party; any new adapter MUST replicate the
  keying (the `dd-magic-link-aws` pinned `sih`/`emh`/`rlh` vectors are the
  reference), and this decision must be revisited before accepting
  third-party adapters. Moving derivation into the service later changes
  every stored partition key and requires a data migration.
- Session cookies must be encrypted/authenticated.
- Token kinds must be domain-separated so one token type cannot validate as another.
- Verification must fail closed, including unknown key IDs, expired values, malformed inputs, and storage races.
- Token parsers must reject malformed, ambiguous, mixed-version, or trailing-data inputs.
- Token encodings must be canonical: exactly one accepted string per token. Where the underlying codec is non-canonical, the token parser must reject non-canonical spellings (for example by re-encoding and comparing). base62 is a big-*integer* codec, so leading `'0'` digits and embedded `CR`/`LF` decode to the same bytes; `dd-auth-token-core::branca::decode` rejects those forms so `"0"+token` cannot pass as a second valid spelling. This is malleability, not forgery — the AEAD payload is unchanged — but it breaks any layer that treats the token string as a unique handle.
- Do not use an integer codec (base62 here) to round-trip arbitrary byte strings such as hashes, IDs, or serialized blobs: leading `0x00` bytes are silently dropped. Use a byte-oriented codec (hex/base64) or frame the length.
- Cookie/token validation must enforce freshness, and the freshness bound must be a required parameter of the validation call — never optional, never a documentation-only expectation. A caller must not be able to obtain a verified value without stating a TTL. Passing the current time into a validator that does not itself check the token's age is a footgun; make the age check mandatory in the same call.
- Sliding sessions need two clocks: an idle bound against last-activity time and an absolute bound against a separate issue-time (`iat`) claim carried inside the authenticated payload. A single re-minted timestamp cannot express both, so absolute expiry silently disappears if `iat` is not stored. Decide this in the payload format before launch.
- Session country is an **opportunistic lock**, sourced only from a configured
  trusted-edge header (never from request bodies). When the edge supplies a
  country at confirmation, the session is bound to it and every validation
  requires the same country — an absent signal does not satisfy the lock (fail
  closed). Sessions issued without a country are unlocked and skip the check.
  The lock is only meaningful if the edge strips or overwrites the header on
  every request and the origin is not directly reachable.
- Reject future-dated tokens beyond a small clock-skew tolerance. `now - timestamp` with saturating subtraction reads a rewound/skewed minting clock as permanently fresh; bound the timestamp in both directions.
- Internal encrypted payloads that are never parsed by a client should use a compact, non-self-describing framing, not JSON.
- **Scanner-safe response contract.** The magic-link HTTP flow is two-step so that email security scanners (which fetch link URLs) cannot burn or complete a login. The consuming application MUST enforce: (1) the magic link is consumed **only** by the same-origin confirmation POST — never on a GET; (2) the landing GET is **side-effect-free and repeatable** (the library guarantees this — do not add consuming side effects); (3) landing/confirmation failures are returned **uniformly** — a rejected landing uses the **same HTTP status as success** so link validity is not enumerable; (4) the flow cookie is cleared on a rejected/internal confirmation and preserved on a dependency failure; (5) `no-store`/CSP/frame-deny security headers are stamped on every such response; (6) the raw token is never echoed into a body or log and any rendered account identity is HTML-escaped. The `dd-magic-link-axum` helpers do the input gauntlet and hand back structured results; the application owns the rendered responses under this contract. A JSON byte array expands ~3.5x against a fixed ciphertext budget and turns a large body into an inexplicable generic failure; there is no interop reason for a self-describing codec on an internal payload.

## Bearer secret entropy

All bearer secrets and anti-guessing nonces must come from a CSPRNG at the adapter/setup boundary. Test fixtures may use deterministic bytes only in tests.

Minimum raw entropy before encoding:

| Value | Minimum entropy | Notes |
| --- | ---: | --- |
| Magic-link selector | 128 bits | Not sufficient alone, but must resist online enumeration. |
| Magic-link verifier | 256 bits | Primary bearer secret. |
| Magic-link flow nonce/cookie | 128 bits | Prefer 256 bits when cheap. |
| Session ID/session token random component | 256 bits | Applies to server-side IDs and encrypted-token identifiers. |
| PoW challenge nonce/random component | 128 bits | Challenge must also be MACed/signed. |
| CSRF/POST confirmation nonce | 128 bits | May be the same bound flow nonce when designed that way. |

Rules:

- Never derive bearer secrets from timestamps, counters, emails, IP addresses, user IDs, UUIDv1/v7 alone, or non-cryptographic RNGs.
- Encoded lengths must preserve the required entropy after base64/base62/hex encoding.
- Generation failures fail closed.
- Magic-link selectors and verifiers must be generated as two independent CSPRNG draws. Neither may be derived from the other, and they must not share randomness (for example, by slicing one random block). The selector is the lower-value lookup half; if the verifier is computable from it, the two-secret split collapses into a single forgeable secret.

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

## Proof-of-work requirements

- PoW difficulty must be configurable with a documented minimum floor; examples may choose development-only low values but production config must be explicit.
- Challenge formats must be versioned and domain-separated, for example `pow-v1`.
- Challenge random/nonces must satisfy the bearer entropy table and be MACed/signed.
- PoW proof cookies must be bound to the challenge and the auth flow.
- PoW admission and any source-specific replay context are independent concerns owned by the consuming application. The magic-link API neither carries nor interprets that context.
- PoW proof cookies are short-lived auth-flow continuity values, not general bearer sessions.
- Prefer single-use proof cookies. If multi-request continuity is needed, enforce a small per-proof use cap and reject replay beyond that cap.
- PoW proof cookies must be cleared on successful auth-flow completion and on terminal auth-flow failure.

## One-time magic-link consumption

Magic-link consume flows must enforce one-time use.

Required behavior:

- Lookup by keyed selector material only.
- Check expiration before creating a session.
- Compare verifier-derived material in constant time.
- Atomically consume the token before or in the same transaction as session creation.
- Use conditional delete/update, consumed markers, or an equivalent compare-and-swap mechanism in storage adapters.
- Key consumed-markers, revocation lists, replay caches, and dedup rows on an authenticated, string-independent token identity — never on the raw token string. For Branca tokens this is the authenticated nonce, exposed as `dd-auth-token-core::branca::Jti`; type such stores as `Set<Jti>` / `Map<Jti, _>`. Keying on the string is unsafe because non-canonical spellings map to distinct strings but the same token, and because upstream infrastructure you do not control (CDN/edge cache keys, gateway rate limiters, WAF rules, SIEM dedup, a unique index added in a migration) may also key on the string.
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

Enumeration-resistant flows must also avoid obvious timing or work-factor differences:

- Missing selector/token records should still perform dummy verifier/MAC work before returning a generic failure.
- Unknown-user and throttled request-magic-link paths should avoid observable send-vs-suppress timing differences where practical.
- Do not promise strict matched latency if it would create a denial-of-service risk; prefer bounded dummy work, background/outbox handoff, and generic responses.
- The GET landing route's flow-state lookup must perform the same dummy work on a selector miss as on a hit and apply a keyed-selector limit, so it is neither a timing/guessing oracle nor an unthrottled DB-read denial-of-service vector.

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
- Key derivation must bind the key id, not only the purpose: derive with `info = purpose || 0x00 || kid` (or an equivalent unambiguous framing). Otherwise two kids derived from one root secret produce identical keys, "rotation" becomes two labels on one key, and cross-kid separation rests only on a string compare. Changing the derivation `info` invalidates all live tokens, so fix the framing before launch.
- Keyrings should support explicit states: active for minting, verify-only for migration, and retired/disabled for rejection.
- Rotation tests must cover active-key minting, verify-only validation, retired-key rejection, and unknown-key rejection.
- Development examples may generate fake keys, but production code must require caller-supplied key material.

## Secret manager abstraction

Production deployments use AWS Secrets Manager for secret storage, but core crates must not know how to fetch secrets.

Use an extremely thin supported-manager enum plus secret-reference config. It is configuration only; it is not a dependency-injection framework.

The implemented shape (see `dd-magic-link-aws/src/config.rs`):

```rust
pub enum SupportedSecretManager {
    AwsSecretsManager,
}

pub enum SecretVersionRef {
    /// Resolve by provider version stage, e.g. "AWSCURRENT" / "AWSPREVIOUS".
    Stage(String),
    /// Resolve by provider version id.
    VersionId(String),
}

pub struct SecretRef {
    pub manager: SupportedSecretManager,
    /// AWS Secrets Manager secret name or ARN. Redacted in `Debug`.
    pub name_or_arn: String,
    pub version: SecretVersionRef,
}
```

### The auth secret document

Each `SecretRef` must resolve to a JSON document with exactly these fields
(`AuthSecretsConfig` takes an active document and, during rotation, an
optional previous one):

```json
{
  "kid": "prod-2026-07",
  "mint_until_unix": 1790000000,
  "verify_until_unix": 1792600000,
  "magic_link_lookup_hmac_b64": "<32 bytes, standard base64>",
  "aws_storage_hmac_b64": "<32 bytes, standard base64>",
  "session_cookie_root_b64": "<32 bytes, standard base64>",
  "magic_link_flow_cookie_root_b64": "<32 bytes, standard base64>"
}
```

- `kid` is the key id for every keyring slot derived from this document; it
  must satisfy `KeyId::parse` (1–64 chars).
- `mint_until_unix` / `verify_until_unix` are the active slot's rotation
  windows; `verify_until_unix` must be at least `mint_until_unix` plus the
  longest purpose lifetime (see the rotation cadence below).
- Each `*_b64` value is exactly 32 random bytes, standard base64. Generate
  each one independently:

```sh
openssl rand -base64 32
```

Never reuse one value across fields — the four secrets separate the lookup
HMAC, adapter storage HMAC, session-cookie root, and flow-cookie root
concerns, and `resolve_auth_secrets` derives purpose-separated keyrings from
them.

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
- Clear cookies on logout, invalid session, expired session responses, successful auth-flow completion, and terminal auth-flow failure where the adapter can do so.
- Document CSRF expectations for cookie-authenticated routes; unsafe methods need CSRF protection or equivalent same-site guarantees.
- `__Host-` and `__Secure-` cookie prefixes are optional future hardening, not v1 requirements. If used, document their browser requirements and path/domain tradeoffs.
- Pre-release review item: before public release, reconsider defaulting the primary session and magic-link flow cookies to `__Host-` (they already use host-only + `Secure` + `Path=/`), since it is the direct defense against cookie-tossing/fixation from a sibling subdomain or active network attacker. Deferred from v1 per the no-`__`-prefix decision.

## Session revocation

The default session model must support server-side invalidation.

- Logout must invalidate the server-side session record or revocation handle before clearing the browser cookie.
- Logout must be an unsafe method (POST) protected by same-site cookies or an equivalent CSRF defense. Forced-logout CSRF is a low-severity but real annoyance and must be closed.
- Compromise response must be able to revoke a session before its absolute TTL expires.
- Stolen cookies must not remain valid for the full 30-day absolute TTL after logout or explicit revocation.
- Stateless session tokens without server-side revocation are not the default. If a consuming app chooses stateless-only sessions, document the tradeoff clearly and use shorter TTLs.
- Invalidated, missing, expired, and malformed sessions map to safe generic auth failures and should clear the session cookie where possible.

## Email identity and normalization

Email identity is an exact match on the app-provided normalized email value.

- Prefer a `NormalizedEmail` domain type that the consuming application constructs before calling these libraries.
- The libraries compare normalized email values exactly for user lookup, HMAC lookup material, rate-limit keys, storage keys, and tests.
- Do not implement provider-specific alias handling: no Gmail dot folding, no plus-address/tag stripping, and no provider-specific alias expansion.
- Do not apply hidden case-folding rules. If a consuming app lowercases all or part of an email address, it must do so before constructing `NormalizedEmail`.
- `NormalizedEmail` must represent exactly one structurally valid mailbox address for this product boundary.
- Reject empty values, multiple addresses, display-name forms, CR/LF, NUL, control characters, and leading/trailing whitespace before email is used for storage, HMAC, rate limiting, or sending.
- Enforce documented length limits for local part, domain, and full address.
- Treat normalized emails as sensitive identifiers and redact them in `Debug`, errors, logs, fixtures, and snapshots.

## Magic-link URL handling

Magic-link tokens commonly appear in URLs and must be treated as log-sensitive secrets.

Scanner-safe magic-link flow:

1. The email link opens a `GET` landing route with the token in the URL.
2. The `GET` route must not consume the token, create a session, or mark the token as used.
3. The `GET` route creates or validates short-lived flow state bound to the selector, verifier proof, exact account, explicit expiry, and an independent confirmation nonce.
4. The `GET` route renders a generic confirmation page requiring an explicit user action, such as a “Continue sign in” button.
5. The confirmation page must identify the account being signed into using safe, user-recognizable text, for example a masked email, without exposing raw token material.
6. The confirmation action submits a same-origin `POST` consume request bound to the flow state. Do not auto-submit with JavaScript or redirect automatically from `GET` to consume.
7. The `POST` consume route validates flow-state binding, atomically consumes the token, clears temporary magic-link flow state, creates the session, and redirects with `303 See Other` to a clean URL without token material.

Implementation rules:

- Do not log full landing/consume URLs, query strings, route captures, or redirect destinations that contain token material.
- Scrub token path/query fields before tracing, metrics labels, access logs, error reports, and panic payloads.
- Prefer a short-lived `HttpOnly` flow cookie or server-side nonce between landing and consume so token material is not embedded in HTML forms.
- Flow state must be AEAD-authenticated and bound to the selector, verifier proof, exact account, explicit expiry, and an independently generated confirmation nonce. It must never carry a generic source identity.
- If a fallback form value must carry token material, it must be short-lived, single-use, `Cache-Control: no-store`, and never rendered with third-party assets.
- Do not place token values in `Location` headers, JavaScript, analytics events, downstream callback URLs, or clean post-consume pages.
- Post-consume redirect targets must be fixed, same-origin relative paths or explicit allowlist entries. Do not accept arbitrary `next=`/return URLs.
- Landing pages must use `Cache-Control: no-store` and no third-party scripts, pixels, stylesheets, or analytics.
- Landing/confirmation pages must prevent framing with `Content-Security-Policy: frame-ancestors 'none'`; `X-Frame-Options: DENY` may also be sent for older clients.
- Set or document `Referrer-Policy: no-referrer` or an equivalent policy for magic-link landing/consume flows.
- Terminal consume failures must clear temporary magic-link flow cookies. Independent PoW middleware owns its own proof-cookie lifecycle.
- Treat scanner safety as protection against GET-only email scanners; active scanners that submit forms are handled by short TTLs, flow-state binding, one-time atomic consume, and generic failure handling.
- Login CSRF / cross-account sign-in: the flow cookie is minted on a GET the attacker can trigger, so it cannot prove the victim initiated the flow. The primary mitigation is the confirmation page identifying the account (masked email) and the user recognizing it is not theirs. Offer an optional mode where the user re-enters or explicitly confirms the email at consume. State this UX dependency explicitly in consuming apps.

## Rate limiting and abuse controls

Magic-link owns only limiter hooks based on its concrete secret or PII-derived domains:

- `normalized email HMAC` is derived from the exact-match `NormalizedEmail` value with a rate-limit pepper and domain-separated purpose string. It limits requests and outbox sends.
- `selector-derived key` is derived from magic-link selector lookup material, never the raw selector. It limits landing and consume attempts.
- Do not store raw emails, raw selectors, raw verifiers, or raw tokens in limiter storage.

IP, network-source, global fanout, malformed-request, and PoW admission controls are independent responsibilities of the consuming application or edge. They are not magic-link command fields, flow-state fields, or magic-link limiter domains.

V1 starting thresholds:

| Flow | Limiter key | Suggested threshold | Public response |
| --- | --- | ---: | --- |
| Request magic link | normalized email HMAC | 3 per 15 min, 10 per 24h | Always generic accepted |
| Email outbox send | normalized email HMAC | 3 per 1h, 10 per 24h | Suppress send, generic accepted |
| Magic-link landing route | selector-derived key | 30 per 10 min | Generic landing page; no flow state created |
| Magic-link consume | selector-derived key | 5 failed attempts per token TTL | Generic invalid/expired |

Rules:

- Treat these thresholds as configurable v1 starting values; production apps may tighten them after observing traffic.
- Unknown user, throttled user, and successful request-magic-link responses must look the same publicly.
- For request flow throttling, suppress email sends but return the same generic accepted response.
- Limiter storage failures on abuse-sensitive paths should fail closed with a generic try-later response.
- Per-email request limits intentionally trade availability for inbox-abuse protection; targeted attackers can spend a victim's quota. Document this tradeoff in consuming apps that surface retry guidance.
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
- Token parsers reject non-canonical encodings (for example zero-prefixed base62), and revocation/replay/dedup stores key on a string-independent token identity (`Jti`), not the raw token string.
- Bearer secret generation enforces documented entropy minimums and uses CSPRNG entropy outside tests.
- Magic-link consume tests prove one-time use and include a concurrent consume/race case for service/storage layers.
- Scanner-safe flow tests prove `GET` does not consume, `POST` requires bound flow state, confirmation pages cannot be framed, terminal failures clear temporary cookies, and redirects are fixed/same-origin/allowlisted.
- Cookie helpers default to `HttpOnly`, `Secure` outside local development, conservative `SameSite`, host-only scope, explicit path, and explicit TTL.
- Session logout and compromise flows invalidate server-side session state before clearing cookies.
- Key material is purpose-separated and rotation states are tested where keyrings exist, including 90-day session rotation, at least 31-day verify-only retention, verify-only rejection for minting, and retired-key rejection.
- PoW tests independently cover minimum difficulty config, CSPRNG challenge entropy, challenge/auth-flow binding, replay limits, and proof-cookie clearing.
- Magic-link rate-limit hooks cover keyed-email request/outbox and keyed-selector landing/consume flows with generic public responses and configurable v1 thresholds, including the documented targeted-lockout tradeoff; upstream controls are tested by the consuming application or edge.
- Magic-link URL handling scrubs token material from logs, redirects, headers, and telemetry.
- Email input tests reject multiple addresses, display-name forms, CR/LF, NUL, control characters, empty values, and values outside documented length limits before send/storage/HMAC use.
- Timing tests or review checks cover dummy verifier/MAC work on missing records and non-enumerating request paths where practical.
- Core code is deterministic and cannot read clock, randomness, environment, filesystem, or network.
- Adapter code maps infrastructure failures into safe public errors.
- Dependency audit/license checks pass before release.

# Security rules

## Security model

Source code secrecy is not a boundary. Secrets, keys, peppers, and runtime config provide security.

The repo must never contain these values:

- production Branca keys
- HMAC peppers
- session secrets
- AWS credentials
- magic-link tokens
- captured cookies
- real customer emails
- production database dumps

## Clock skew

Existing PoW and bound-cookie helpers allow 60 seconds of future timestamp
skew. Explicit `*_with_clock_skew` helpers take a caller-supplied seconds bound;
PoW Axum uses `PowPolicy::with_clock_skew_secs`. Apps with a stricter
requirement can select 30 seconds. Apply the same bound separately to challenge and proof-cookie
verification. Zero forbids future timestamps. The tolerance is capped at
`MAX_CLOCK_SKEW_SECS` (300 seconds); larger values are rejected as a
configuration error. Skew never extends an expired
TTL or the lifetime of a key. Magic-link service wrappers retain the default.

## Freshness bounds are capped

Cookie verification rejects an idle or absolute max age longer than the cookie
type's own `MAX_ABSOLUTE_AGE_SECS` (sessions 30 days, PoW proof 24 hours,
confirm 5 minutes) with `TokenError::InvalidTimestamp`. PoW challenge
verification and `PowPolicy::new` reject a challenge max age above
`MAX_CHALLENGE_MAX_AGE_SECS` (10 minutes). A misconfigured bound fails loudly
instead of making old cookies or stockpiled solutions valid.

## Token design

- Treat magic-link tokens as one-time bearer secrets.
- Store keyed lookup material only.
- Never store raw token parts.
- Never store raw selectors.
- Never store raw verifiers.
- Encrypt and authenticate session cookies.
- Separate token kinds by domain.
- Fail closed on unknown key IDs.
- Fail closed on expired values.
- Fail closed on malformed input.
- Fail closed on storage races.
- Reject malformed, ambiguous, mixed-version, or trailing token input.
- Accept exactly one canonical string for each token.
- Reject non-canonical Base62 spellings.
- Do not use Base62 for arbitrary bytes.
- Use hex or base64 for byte strings.
- Make freshness checks mandatory in validation calls.
- Require the caller to pass a freshness bound.
- Store both idle and absolute session time data.
- Reject future-dated tokens beyond clock skew.
- Use compact internal framing for encrypted payloads.

### Adapter storage keying

Repository traits pass raw `SessionId`, `NormalizedEmail`, and `RateLimitKey` values. Each storage adapter must key those values before storage.

Use the shared `datadeft_magic_link_core::domain_separated_lookup_hmac` framing. Use an adapter-specific domain and secret.

The type system does not enforce this rule. A new repository could store raw IDs and still compile.

Only first-party adapters have approval. New adapters must copy the keying behavior. Use the `datadeft-magic-link-aws` vectors as the reference.

Moving key derivation into the service changes stored partition keys. That change requires a data migration.

### Session country lock

Session country is an opportunistic lock. It comes only from a configured trusted-edge header.

Never take country from request bodies.

When confirmation supplies country, bind the session to that country. Each validation must see the same country.

Absent country does not satisfy a locked session. Fail closed.

A session without country stays unlocked. It skips the country check.

The lock only works when the edge strips or overwrites the header. The origin must not be directly reachable.

### Scanner-safe response contract

The magic-link HTTP flow uses two steps. This prevents link scanners from burning or completing login.

The consuming application must follow these rules:

1. Consume magic links only on the same-origin confirmation `POST`.
2. Never consume a magic link on `GET`.
3. Keep the landing `GET` side-effect-free and repeatable.
4. Return uniform landing and confirmation failures.
5. Use the same status for rejected landing and successful landing.
6. Clear the confirm cookie on rejected confirmation.
7. Clear the confirm cookie on internal confirmation failure.
8. Preserve the confirm cookie on dependency failure.
9. Add `no-store`, CSP, and frame-denial headers.
10. Never echo the raw token into a body.
11. Never log the raw token.
12. HTML-escape rendered account identity.

`datadeft-magic-link-axum` runs the input gauntlet. The application owns rendered responses under this contract.

## Bearer secret entropy

All bearer secrets and anti-guessing nonces must come from a CSPRNG. Test fixtures may use deterministic bytes only in tests.

| Value | Minimum entropy | Notes |
| --- | ---: | --- |
| Magic-link selector | 128 bits | Must resist online enumeration. |
| Magic-link verifier | 256 bits | Primary bearer secret. |
| Magic-link confirm nonce | 128 bits | Use 256 bits when cheap. |
| Session ID | 256 bits | Applies to server-side IDs. |
| Session token random part | 256 bits | Applies to encrypted tokens. |
| PoW challenge nonce | 128 bits | MAC the challenge. |
| CSRF confirmation nonce | 128 bits | May share the bound confirm nonce. |

Rules:

- Never derive bearer secrets from timestamps.
- Never derive bearer secrets from counters.
- Never derive bearer secrets from emails.
- Never derive bearer secrets from IP addresses.
- Never derive bearer secrets from user IDs.
- Never derive bearer secrets from UUIDv1 or UUIDv7 alone.
- Never derive bearer secrets from non-crypto RNGs.
- Preserve required entropy after encoding.
- Fail closed on generation failure.
- Draw magic-link selectors and verifiers independently.
- Do not derive selector from verifier.
- Do not derive verifier from selector.
- Do not slice one random block for both values.

## Token and cookie inventory

| Item | Secret | TTL |
| --- | --- | ---: |
| Magic-link token | Yes | 10 minutes |
| Magic-link selector | Lookup only | 10 minutes |
| Magic-link verifier | Yes | 10 minutes |
| Magic-link confirm cookie | Sensitive | 5 minutes |
| PoW challenge token | MACed | 2 minutes |
| PoW solution | No long-term secret | One request |
| PoW proof cookie | Sensitive | 3 hours (default) |
| Session ID or token | Yes | Session TTL |
| Session cookie | Yes | 24 hours idle, 30 days absolute |
| Key ID | No | No independent TTL |
| HMAC lookup value | Sensitive | Cleanup TTL only |
| Rate-limit key | Sensitive | Window-specific |

## TTL baseline

| Config | Value |
| --- | ---: |
| `magic_link_ttl` | 10 minutes |
| `magic_link_flow_ttl` | 5 minutes |
| `pow_challenge_ttl` | 2 minutes |
| `pow_proof_cookie_ttl` | 3 hours default, 24-hour ceiling |
| `session_idle_ttl` | 24 hours |
| `session_absolute_ttl` | 30 days |
| `magic_link_cleanup_grace` | 24 hours after expiry |

## Retention

Nothing that identifies an account or its activity is deleted; the rows are
the audit trail. DynamoDB TTL (the `ttl` attribute) is set only on rows that
carry no audit value:

| Row | Retention |
| --- | --- |
| User profile, email lookup | Kept; disabling is a flag, never a delete |
| Session, per-user session index | Kept; expiry and revocation are fields |
| Admin audit events | Kept; append-only |
| Magic-link challenge | TTL: expiry plus `magic_link_cleanup_grace` |
| Rate-limit counter | TTL: window end plus cleanup grace |

Validity never depends on deletion: every read checks `expires_at_unix` and
`revoked_at_unix`.

## Admin operations

`AuthAdminService` gives consuming projects the data and audited mutations for
their own admin UI. Who is an admin is the application's decision; authorize
every admin endpoint before calling the service.

- Queries: `list_users`, `get_user`, `find_user_by_email`,
  `list_sessions_for_user`, `list_active_sessions`, `list_admin_events`. Pages
  use an opaque `PageCursor` and a limit clamped to 100; a page may be shorter
  than the limit while more remain, so continue while `next` is set.
- Mutations: `revoke_session` (final), `revoke_all_sessions`, `disable_user`,
  `enable_user`. Each writes the change and an append-only `AdminEvent`
  (event id, time, action, user, session, admin id and reason) in one
  transaction: both or neither.
- Sessions are addressed by `SessionHandle`, the keyed hash they are stored
  under, never by the raw session id, which is not stored. Show
  `display_id()` (`sess_xxxxxxxx`) in UIs; pass the full handle back.
- Disabling a user takes effect on the next request: `validate_session` checks
  the user's status every time. `disable_user` then revokes every session so
  the audit trail records each one ending. Enabling does not restore revoked
  sessions; the user logs in again.
- Admin ids and reasons are length-capped and may not contain control
  characters. `Debug` output redacts the reason.

Rules:

- Keep magic-link and PoW values short-lived.
- Let session cookies live longer than pre-auth values.
- Let server-side expiry win over browser cookie expiry.
- Do not let cookies outlive server-side validity.
- Never let sliding refresh exceed absolute expiry.
- Refresh only through `refresh_session_cookie` after `validate_session`. It
  re-issues the cookie once half the idle lifetime has passed, keeps the
  original `iat`, session ID, and country, mints under the active key, and
  never writes storage. Validation itself stays read-only.
- Sliding refresh means a stolen cookie that keeps being used stays valid until
  the absolute lifetime or revocation. Revoke server state on logout and on
  suspected compromise.
- Use cleanup TTL only for storage deletion.
- Return the same public failure for invalid token states.

Invalid token states include expired, consumed, missing, malformed, and invalid verifier.

## Proof-of-work requirements

- Make PoW difficulty configurable.
- Document a production floor.
- Use explicit production config.
- Use development-only low values only in examples.
- Version challenge formats.
- Domain-separate challenge formats.
- MAC challenge random data and metadata.
- Bind proof cookies to the challenge and auth flow.
- Keep PoW admission outside magic-link APIs.
- Treat proof cookies as short-lived flow values.
- Bound the proof-cookie lifetime with a configurable TTL under a hard ceiling.
- Reuse the proof cookie within its lifetime. The shipped cookie is stateless.
- Add single-use replay capping only where a deployment needs it.
- Clear proof cookies on auth success.
- Clear proof cookies on terminal auth failure.

### Solve-timing signal

`datadeft-pow-core::Verified::mint_to_verify_ms`, surfaced by `datadeft-pow-axum` as
`PowAdmission::mint_to_verify_ms`, is the server-derived mint→verify delta of
a successful solve, in milliseconds.

Trust argument:

- Both instants come from server clocks. The challenge `tim` is HMAC-bound
  in the tag, so a client cannot backdate it, and the client never reports
  its own timing. No client clock is involved.
- The delta is inflatable but not deflatable by the client. A client can sit
  on a solved challenge to look slower, but can never look faster than its
  true solve.
- "Implausibly fast" is therefore unfakeable by the client: a delta below the
  browser-physical floor for the difficulty is strong evidence of a
  native-speed solver, under the clock assumption below.
- Clock assumption: when one instance mints and another verifies, the delta
  is shifted by the clock offset between them. A verifier whose clock runs
  behind the minter's shrinks every delta by that offset. The value is `None`
  when the verifying clock is behind `tim` (accepted within
  `MAX_FUTURE_SKEW_SECS`), because the delta is then unknown. A fast floor is
  only sound when instance clocks are synchronized well below the floor (on
  AWS, the Amazon Time Sync Service).
- The delta includes network round trips and client-side queueing, not pure
  solve time.

Consumption rules:

- Use the delta for risk tagging, triage, per-difficulty histograms, and
  difficulty tuning.
- The fast direction is the only one sound enough to gate on. Slow or
  "human-looking" deltas must stay soft: a bot that sleeps before submitting
  is timing-indistinguishable from a human per request.
- Calibrate any fast floor from field data per difficulty, never from theory.
- Never treat `None` as a fast solve. Count it separately in metrics; a
  rising `None` rate indicates clock drift between instances.
  Genuine cohorts mix device speeds, so their solve-time distribution is a
  mixture of exponentials; tests against a single theoretical exponential
  reject honest traffic.
- The browser-side floor exists only because the shipped `dd-protect-client`
  worker pays an async `crypto.subtle` round trip per attempt. A WASM or
  native-speed client, including a future optimization of the official
  client, erases it. Revisit every threshold before changing the client's
  solve loop.
- Aggregation (per-IP, per-cohort, distribution-shape tests) is an app or
  edge concern. The library exposes the per-solve delta only.
- To carry a classification statelessly to later gate checks, stamp an
  app-defined byte into the proof cookie's encrypted v2 body
  (`solve_class`). The library assigns the byte no meaning: the minting app
  defines the quantization, the reading app the policy, and both stay
  outside the library.

## One-time magic-link consumption

Magic-link consume flows must enforce one-time use.

Required behavior:

1. Look up by keyed selector material only.
2. Check expiration before session creation.
3. Compare verifier-derived material in constant time.
4. Consume the token atomically with session creation.
5. Use conditional delete, update, or compare-and-swap storage.
6. Key replay stores on authenticated token identity.
7. Never key replay stores on the raw token string.
8. Collapse consumed, missing, expired, malformed, and invalid-verifier cases.
9. Apply failed-attempt limits where storage can do so safely.
10. Add replay tests.
11. Add concurrent consume tests.

For Branca tokens, key dedup stores on `datadeft-auth-token-core::branca::Jti`.

## HMAC lookup material

Use secret-keyed HMAC for these lookup keys:

- email addresses
- magic-link selectors
- magic-link verifiers
- session IDs
- rate-limit keys with sensitive material

Do not use bare SHA-256 for secret-derived or PII-derived lookup material.

## Data at rest

HMACs keep raw selectors, verifiers, session IDs, and emails out of record
keys. Raw tokens are never stored. The normalized email is stored as a record
attribute, because the application needs it to send mail and identify the
account. The keyed lookup keys therefore protect against guessing record
addresses, not against reading a full table dump. Protect auth tables with
encryption at rest, least-privilege access, and backup controls.

## Logging

Never log these values:

- raw magic-link tokens
- raw selectors
- raw verifiers
- raw cookies
- Branca tokens
- session IDs
- key material
- HMAC peppers
- email addresses without app approval

Use redacted `Debug`. Use app-level derived identifiers.

## Timing and comparison

Use constant-time comparison for these values:

- verifier hashes
- token MAC values
- token tag values
- stored secret-derived values

Do not add early-return comparison logic for secrets.

Enumeration-resistant flows need bounded dummy work.

- Do dummy verifier work on a missing selector.
- Avoid clear timing gaps for unknown-user request paths.
- Avoid clear timing gaps for throttled request paths.
- Do not promise strict matched latency.
- Prefer bounded dummy work and generic responses.
- Apply a keyed-selector limit on landing.
- Avoid unthrottled read oracles.

## Configuration

- Production secrets must come from the consuming application.
- Do not put production secrets in this repo.
- Make cookie names configurable.
- Make issuer and audience configurable where used.
- Make TTLs configurable.
- Make peppers and keys configurable.
- Use fake development values only in examples.
- Do not add production-looking domains to tests or docs.
- Do not add production-looking emails to tests or docs.
- Do not add production-looking tokens to tests or docs.
- Do not add production-looking ARNs to tests or docs.
- Do not assume production defaults silently.

## Key management and rotation

- Use purpose-separated keys and peppers.
- Separate Branca token keys.
- Separate session cookie keys.
- Separate HMAC lookup keys.
- Separate PoW signing keys.
- Separate adapter encryption keys.
- Do not reuse one secret across purposes.
- Use at least 256 bits for symmetric keys and peppers.
- Validate key IDs.
- Domain-separate key IDs.
- Fail closed on unknown key IDs.
- Bind key derivation to purpose and key ID.
- Support active keys for minting.
- Support verify-only keys for migration.
- Reject retired or disabled keys.
- Test active-key minting.
- Test verify-only validation.
- Test retired-key rejection.
- Test unknown-key rejection.

## Secret manager config

Production deployments use AWS Secrets Manager for secret storage. Core crates must not fetch secrets.

Use a thin config shape only. Do not add a policy engine. Do not add implicit environment reads.

The AWS adapter supports this shape:

```rust
pub enum SupportedSecretManager {
    AwsSecretsManager,
}

pub enum SecretVersionRef {
    Stage(String),
    VersionId(String),
}

pub struct SecretRef {
    pub manager: SupportedSecretManager,
    pub name_or_arn: String,
    pub version: SecretVersionRef,
}
```

Rules:

- Support `AwsSecretsManager` in v1.
- Add new managers only with code and tests.
- Let adapters resolve `SecretRef` values.
- Pass loaded key material into core and service APIs.
- Map `AWSCURRENT` to active material by explicit config.
- Map `AWSPREVIOUS` to verify-only material only when enabled.
- Do not load retired keys.
- Redact secret names in `Debug`.
- Redact ARNs in `Debug`.
- Redact version IDs in `Debug`.
- Redact version stages in `Debug`.
- Redact secret payloads in `Debug`.
- Zeroize secret payloads where practical.

### Auth secret document

Each `SecretRef` must resolve to one JSON document.

`AuthSecretsConfig` takes one active document. It can take one previous document during rotation.

```json
{
  "kid": "example-2026-07",
  "mint_until_unix": 1790000000,
  "verify_until_unix": 1792600000,
  "magic_link_lookup_hmac_b64": "<32 bytes, standard base64>",
  "aws_storage_hmac_b64": "<32 bytes, standard base64>",
  "session_cookie_root_b64": "<32 bytes, standard base64>",
  "magic_link_confirm_cookie_root_b64": "<32 bytes, standard base64>"
}
```

Document rules:

- `kid` is the key ID for each derived keyring slot.
- `kid` must pass `KeyId::parse`.
- `mint_until_unix` sets the active mint window.
- `verify_until_unix` sets the verify window.
- `verify_until_unix` must cover the longest purpose lifetime.
- Each `*_b64` value must decode to 32 bytes.
- Generate each `*_b64` value independently.
- Do not reuse one value across fields.

Example generation command:

```sh
openssl rand -base64 32
```

The four secret fields separate these purposes:

- magic-link lookup HMAC
- AWS storage HMAC
- session-cookie root
- confirm-cookie root

## Rotation cadence

For 30-day session validity, keep old session keys for the full session lifetime. Keep them after they stop minting new cookies.

Recommended cadence:

| Secret class | Active rotation | Verify-only retention |
| --- | ---: | ---: |
| Session cookie keys | 90 days | 31 days |
| Branca session token keys | 90 days | 31 days |
| Magic-link lookup HMAC key | 90 days | Link TTL plus 24 hours |
| AWS storage HMAC key | 90 days | 31 days, and until `rekey_email_lookups` has run |
| PoW signing keys | 90 days | Challenge TTL plus 24 hours |
| Rate-limit HMAC keys | 90 days | Longest window plus 24 hours |

Rules:

- Use `AWSCURRENT` for active material.
- Use `AWSPREVIOUS` for verify-only material when enabled.
- Never mint with verify-only keys.
- Never mint HMAC lookup values with old keys. Previous HMAC keys are only
  for read fallback during rotation.
- Do not rotate session keys faster than verify retention.
- Keep previous session keys for at least 31 days.
- Reissue cookies with active keys after normal authorization checks.
- Retire magic-link and PoW keys sooner than session keys.
- Fail closed on unknown, missing, retired, disabled, or malformed key IDs.

### Rotating the HMAC keys

The storage and lookup HMAC keys address records, so rotating them needs a
read fallback, not just a verify-only slot. `LoadedAuthSecrets` exposes the
previous document's HMAC keys only when they differ from the active ones.

1. Write a new secret version with fresh values. Secrets Manager moves the old
   version to `AWSPREVIOUS`; load it as the previous document.
2. Pass `previous_storage_hmac_key` to
   `DynamoDbAuthStore::with_previous_storage_hmac_key` and
   `previous_lookup_hmac_key` to `MagicLinkFlowService::previous_lookup_hmac_key`.
   Sessions and email lookups that miss under the new key retry under the
   previous one. A user found that way gets a lookup row under the new key.
   Links issued just before the rotation stay usable.
3. Before dropping the previous document, run
   `DynamoDbAuthStore::rekey_email_lookups` (needs `dynamodb:Scan`). It writes
   new-key lookup rows for users who did not log in during the window. It is
   idempotent.
4. Keep the previous document for at least 31 days so pre-rotation sessions
   expire naturally, then remove it.

Rate-limit counters restart once at rotation; limits are best-effort.
Removing the previous storage key before step 3 strands users who have not
logged in since the rotation: their next login creates a second account.

## Cookie security

Cookie helpers must use safe defaults.

Rules:

- Use lower `snake_case` cookie names.
- Do not require `__Host-` or `__Secure-` in v1.
- Use `HttpOnly` for auth cookies.
- Use `Secure` outside local development.
- Use conservative `SameSite`.
- Use host-only scope by default.
- Set `Domain` only through explicit app config.
- Set `Path=/` for primary session cookies.
- Use narrow paths for temporary auth cookies.
- Always set `Path` explicitly.
- Set explicit `Max-Age` or expiry.
- Clear cookies on logout.
- Clear cookies on invalid session.
- Clear cookies on expired session responses.
- Clear confirm cookies after auth success.
- Clear confirm cookies on terminal auth failure.
- Document CSRF expectations for cookie routes.
- Protect unsafe methods from CSRF.

Before public release, review `__Host-` defaults again.

## Session revocation

The default session model must support server-side invalidation.

- Revoke server-side session state before cookie clearing on logout.
- Use `POST` for logout.
- Protect logout from CSRF.
- Support compromise revocation before absolute expiry.
- Do not make stateless sessions the default.
- Document the tradeoff if an app chooses stateless sessions.
- Use shorter TTLs for stateless sessions.
- Map invalid sessions to generic auth failures.
- Clear the session cookie where possible.

## Email identity

Email identity uses exact match on an app-provided normalized email value.

- Let the consuming app normalize email before library use.
- Do not add Gmail dot folding.
- Do not strip plus tags.
- Do not add provider alias rules.
- Do not add hidden case folding.
- Reject empty values.
- Reject multiple addresses.
- Reject display-name forms.
- Reject CR, LF, NUL, and control characters.
- Reject leading and trailing whitespace.
- Enforce documented length caps.
- Treat normalized email as sensitive.
- Redact normalized email in `Debug`.
- Redact normalized email in errors, logs, fixtures, and snapshots.

### Normalized email at rest

The store keeps the normalized email in readable form. The atomic authentication
transaction needs that value for its equality checks, and lookups key on
`HMAC(email)` so no index holds a raw address.

- Store the normalized email at rest in readable form.
- Protect it with provider encryption at rest (DynamoDB KMS) and least-privilege IAM.
- Do not add application-layer email field encryption.
- Keep raw tokens, selectors, and verifiers out of storage. Store keyed HMAC and verifier hashes only.

## Magic-link URL handling

Magic-link tokens often appear in URLs. Treat them as log-sensitive secrets.

Scanner-safe flow:

1. Email opens a `GET` landing route with the token.
2. `GET` never consumes the token.
3. `GET` never creates a session.
4. `GET` creates short-lived flow state.
5. Flow state binds selector, verifier proof, account, expiry, and nonce.
6. The page asks the user to click a button.
7. The page identifies the account.
8. The page does not expose raw token material.
9. Same-origin `POST` consumes the flow.
10. `POST` validates bound flow state.
11. `POST` commits token consumption and session creation atomically.
12. `POST` clears temporary state.
13. `POST` redirects to a clean URL.

Implementation rules:

- Do not log full landing URLs.
- Do not log token-bearing query strings.
- Scrub token route fields before metrics.
- Scrub token route fields before traces.
- Prefer an `HttpOnly` confirm cookie.
- Never render raw token material in forms.
- Never place tokens in `Location` headers.
- Never place tokens in JavaScript.
- Never place tokens in analytics events.
- Use fixed or allowlisted post-consume redirects.
- Do not accept arbitrary `next` URLs.
- Add `Cache-Control: no-store` to landing pages.
- Do not load third-party assets on landing pages.
- Prevent framing with CSP.
- Add `X-Frame-Options: DENY` for old clients.
- Set `Referrer-Policy: strict-origin`. It keeps the token-bearing path and
  query out of `Referer`. Do not use `no-referrer`: browsers then send
  `Origin: null` on the confirmation form POST, and the same-origin check
  rejects it.
- Clear confirm cookies on terminal consume failure.

Scanner safety protects against GET-only scanners. Active scanners that submit forms rely on TTL, binding, one-time consume, and generic failures.

The confirmation page mitigates login CSRF by showing the account. Offer a stronger mode when the app needs one.

## Rate limiting and abuse controls

Magic-link owns these limiter domains:

- normalized-email request limits
- normalized-email outbox limits
- selector landing limits
- selector consume limits

The consuming app owns these controls:

- IP limits
- network-source limits
- global fanout limits
- malformed-request admission
- PoW admission

Starting thresholds:

| Flow | Key | Limit | Public response |
| --- | --- | ---: | --- |
| Request | Email HMAC | 3 per 15 minutes | Generic accepted |
| Request | Email HMAC | 10 per 24 hours | Generic accepted |
| Outbox | Email HMAC | 3 per 1 hour | Generic accepted |
| Outbox | Email HMAC | 10 per 24 hours | Generic accepted |
| Landing | Selector key | 30 per 10 minutes | Generic landing |
| Consume | Selector key | 5 per token TTL | Generic invalid |

Rules:

- Make thresholds configurable.
- Return generic responses for throttled users.
- Return generic responses for unknown users.
- Return generic responses for consumed tokens.
- Return generic responses for expired tokens.
- Return generic responses for invalid tokens.
- Fail closed on limiter storage failures.
- Document the targeted-lockout tradeoff.

## One supported way

Do not add legacy support unless the project approves a versioned path.

Do not add these paths:

- dual-read
- dual-write
- compatibility fallback
- old token parser branch
- deprecated alias

You can use forward version markers.

```text
v1
pow-v1
ml1
```

They name the one current format.

## Dependency hygiene

- Prefer small maintained crates.
- Avoid unnecessary untrusted-input parsers.
- Keep cloud SDKs out of core crates.
- Review crypto dependencies before use.
- Run `cargo deny` or `cargo audit` before release.
- Add dependency audit to `mise run verify`.
- Document each crypto, parsing, HTTP, AWS, async, or token dependency.

## Security checklist

Before phase acceptance, confirm these items:

1. Source contains no secret values.
2. Docs contain no secret values.
3. Tests contain no secret values.
4. Examples contain no secret values.
5. `Debug` redacts sensitive types.
6. Errors do not expose sensitive values.
7. Tests cover tamper cases.
8. Tests cover replay cases.
9. Tests cover expiry cases.
10. Tests cover malformed tokens.
11. Tests cover unknown keys.
12. Token parsers reject non-canonical encodings.
13. Replay stores key on `Jti` or equivalent identity.
14. Entropy generation meets minimums.
15. Magic-link consume tests prove one-time use.
16. Scanner flow tests prove `GET` is non-consuming.
17. Scanner flow tests prove `POST` requires bound state.
18. Confirmation pages prevent framing.
19. Terminal failures clear confirm cookies.
20. Redirects stay fixed or allowlisted.
21. Cookie helpers use secure defaults.
22. Logout revokes server state before cookie clearing.
23. Key rotation tests cover active keys.
24. Key rotation tests cover verify-only keys.
25. Key rotation tests cover retired keys.
26. PoW tests cover difficulty floor.
27. PoW tests cover challenge entropy.
28. PoW tests cover replay limits.
29. Rate-limit tests cover email and selector domains.
30. URL handling scrubs token material.
31. Email input tests cover invalid structures.
32. Timing review covers dummy work.
33. Core code has no IO sources.
34. Adapter errors map to safe public errors.
35. Solve-timing consumers gate on fast deltas only; slow deltas stay soft.
35. Dependency audit passes before release.

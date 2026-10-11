# Security rules

## Security model

Source code secrecy is not a boundary. Secrets, keys, peppers and runtime
config provide security.

Never put these in the repo, including docs, tests and examples:

- production Branca keys, HMAC peppers, session secrets, AWS credentials
- magic-link tokens and captured cookies
- real customer emails and production database dumps
- production-looking domains, emails, tokens or ARNs

## Clock skew

- PoW and bound-cookie helpers allow 60 seconds of future timestamp skew by
  default. Apps with a stricter requirement can select 30 seconds.
- Explicit `*_with_clock_skew` helpers take a caller-supplied bound in
  seconds. datadeft-pow-axum uses `PowPolicy::with_clock_skew_secs`.
- Apply the bound separately to challenge and proof-cookie verification.
- A bound of zero forbids future timestamps.
- The library caps the bound at `MAX_CLOCK_SKEW_SECS` (300 seconds). A larger
  value is a configuration error.
- Skew never extends an expired TTL or a key's lifetime.
- The magic-link service wrappers keep the default.

## Freshness bounds are capped

A misconfigured bound fails loudly. It does not make old cookies or
stockpiled solutions valid:

- Cookie verification rejects an idle or absolute max age above the cookie
  type's `MAX_ABSOLUTE_AGE_SECS` with `TokenError::InvalidTimestamp`. The caps
  are 30 days for the session cookie, 24 hours for the proof cookie and 5
  minutes for the confirm cookie.
- PoW challenge verification and `PowPolicy::new` reject a challenge max age
  above `MAX_CHALLENGE_MAX_AGE_SECS` (10 minutes).

## Token design

- Treat magic-link tokens as one-time bearer secrets.
- Store keyed lookup material only. Never store raw tokens, selectors or
  verifiers.
- Encrypt and authenticate session cookies.
- Separate token kinds by domain.
- Fail closed on unknown key IDs, expired values, malformed input and
  storage races.
- Reject malformed, ambiguous, mixed-version or trailing token input.
- Accept exactly one canonical string per token. Reject non-canonical Base62
  spellings.
- Do not use Base62 for arbitrary bytes. Use hex or base64 for byte strings.
- Pass a freshness bound to every validation call. Freshness checks are
  mandatory.
- Store both idle and absolute session times.
- Reject future-dated tokens beyond the clock skew.
- Use compact internal framing for encrypted payloads.

### Adapter storage keying

Repository traits pass raw `SessionId`, `NormalizedEmail` and `RateLimitKey`
values. Each storage adapter must key these values before it stores them.
Use the shared `datadeft_magic_link_core::domain_separated_lookup_hmac`
framing with an adapter-specific domain and secret.

- The type system does not enforce this. A new repository could store raw
  IDs and still compile.
- The project approves only first-party adapters. A new adapter must copy the
  keying behavior. Use the `datadeft-magic-link-aws` vectors as the reference.
- If key derivation moves into the service, the stored partition keys change.
  This change needs a data migration.

### Session country lock

Session country is an opportunistic lock.

- Take country only from a configured trusted-edge header, never from a
  request body.
- When confirmation supplies a country, bind the session to it. Every
  validation must see the same country.
- A missing country does not satisfy a locked session. Fail closed.
- A session bound without a country stays unlocked and skips the check.
- The lock works only when the edge strips or overwrites the header. The
  origin must also not be directly reachable.

#### Country groups

`MagicLinkServiceConfig::country_policy` defaults to `CountryPolicy::Exact`.
`CountryPolicy::eu27()` or a custom `CountryGroup` pins a country inside a
group to the group's tag (`EU`). A session can then move freely between the
countries of the group. The policy pins any other country exactly. The same
mapping runs at binding and on every validation. A session bound under one
policy fails closed under another.

Trade-off: a group weakens the lock on purpose. A stolen session cookie then
works from any country in the group. Choose the smallest group your users
need. This is still much safer than rewriting the trusted header at the edge.
A rewrite would hide the real country from everything else.

Configuration validation refuses:

- a country in two groups
- duplicate tags
- tags other than `EU` or ISO user-assigned codes (`XX` and `XK` excluded)

A request country of `EU` or a user-assigned code pins to nothing under every
policy. The library treats it as missing, so it fails closed.

## Bearer secret entropy

All bearer secrets and anti-guessing nonces come from a CSPRNG. Use
deterministic bytes only in tests.

| Value | Minimum entropy | Notes |
| --- | ---: | --- |
| Magic-link selector | 128 bits | Must resist online enumeration. |
| Magic-link verifier | 256 bits | Primary bearer secret. |
| Magic-link confirm nonce | 128 bits | Use 256 bits when cheap. |
| Session ID | 256 bits | Applies to server-side IDs. |
| Session token random part | 256 bits | Applies to encrypted tokens. |
| PoW challenge nonce | 128 bits | MAC the challenge. |
| CSRF confirmation nonce | 128 bits | May share the bound confirm nonce. |

- Never derive bearer secrets from timestamps, counters, emails, IP
  addresses, user IDs, UUIDv1 or UUIDv7 alone, or non-crypto RNGs.
- Keep the required entropy after encoding.
- Fail closed when generation fails.
- Draw magic-link selectors and verifiers independently. Never derive one
  from the other. Never slice them from one shared random block.

### Identifier formats

Library-minted ids use one form, `<tag>-<lowercase hex>`. Parsers accept no
other form and refuse the 0.4 underscore form.

| Id | Form | Random bits |
| --- | --- | ---: |
| User id | `usr-` + 32 hex | 128 |
| Session id | `sid-` + 64 hex | 256 |
| Authentication attempt id | `aid-` + 32 hex | 128 |
| Admin event id | `evt-` + 32 hex | 128 |
| Session display id | `sess-` + 8 hex | (label only) |

The library validates ids on input and redacts them in `Debug`. Keyed lookup
values (`emh_`, `mlh_`, `mlv_`, `sih_`, `rlh_`) are storage material, not
ids, and keep their underscore form.

## TTL baseline

Use these values unless the consuming app configures stricter ones.

| Config | Value |
| --- | ---: |
| `magic_link_ttl` | 10 minutes |
| `magic_link_flow_ttl` | 5 minutes |
| `pow_challenge_ttl` | 2 minutes |
| `pow_proof_cookie_ttl` | 3 hours default, 24-hour ceiling |
| `session_idle_ttl` | 24 hours |
| `session_absolute_ttl` | 30 days |
| `magic_link_cleanup_grace` | 24 hours after expiry |

### Token and cookie inventory

| Item | Secret | TTL |
| --- | --- | ---: |
| Magic-link token | Yes | 10 minutes |
| Magic-link selector | Lookup only | 10 minutes |
| Magic-link verifier | Yes | 10 minutes |
| Confirm cookie | Sensitive | 5 minutes |
| PoW challenge token | MACed | 2 minutes |
| PoW solution | No long-term secret | One request |
| Proof cookie (`dd_pow`) | Sensitive | 3 hours (default) |
| Session ID or token | Yes | Session TTL |
| Session cookie | Yes | 24 hours idle, 30 days absolute |
| Key ID | No | No independent TTL |
| HMAC lookup value | Sensitive | Cleanup TTL only |
| Rate-limit key | Sensitive | Window-specific |

### Lifetime rules

- Keep magic-link and PoW values short-lived. Session cookies may live
  longer than pre-auth values.
- Server-side expiry wins over browser cookie expiry. Cookies must not
  outlive server-side validity.
- Sliding refresh never exceeds absolute expiry.
- Refresh only through `refresh_session_cookie` after `validate_session`. It
  re-issues the cookie after half the idle lifetime has passed. It keeps the
  original `iat`, session ID and country. It mints under the active key and
  never writes storage. Validation itself stays read-only.
- Trade-off: with sliding refresh, an attacker who keeps using a stolen
  cookie keeps it valid until the absolute lifetime ends or until
  revocation. Revoke server state on logout and on suspected compromise.
- Use the cleanup TTL only for storage deletion.

## Retention

The library never deletes rows that identify an account or its activity.
These rows are the audit trail. The library sets DynamoDB TTL (the `ttl`
attribute) only on rows with no audit value:

| Row | Retention |
| --- | --- |
| User profile, email lookup | Kept. Disabling is a flag, never a delete |
| Session, per-user session index | Kept. Expiry and revocation are fields |
| Admin audit events | Kept. Append-only |
| Magic-link challenge | TTL: expiry plus `magic_link_cleanup_grace` |
| Rate-limit counter | TTL: window end plus cleanup grace |
| Lifetime counter (per-solve budget) | TTL: the expiry fixed at first use plus cleanup grace |

Validity never depends on deletion. Every read checks `expires_at_unix` and
`revoked_at_unix`.

## Admin operations

`AuthAdminService` gives consuming projects the data and audited mutations
for their own admin UI. The application decides who is an admin. Authorize
every admin endpoint before you call the service.

**Queries:** `list_users`, `get_user`, `find_user_by_email`,
`list_sessions_for_user`, `list_active_sessions`, `list_admin_events`.

- Pages use an opaque `PageCursor` and a limit. The service clamps the limit
  to 100.
- A page can be shorter than the limit when more items remain. Continue
  while `next` has a value.

**Mutations:** `revoke_session` (final), `revoke_all_sessions`,
`disable_user`, `enable_user`.

- Each mutation writes the change and an append-only `AdminEvent` in one
  transaction. The event holds the event id, time, action, user, session,
  admin id and reason. The transaction writes both or neither.
- Admin transactions use the audit event id as the DynamoDB idempotency
  token.

**Session handles:** the service addresses sessions by `SessionHandle`. This
is the keyed hash under which storage keeps the session. The library does not
store the raw session id. Show `display_id()` (`sess-xxxxxxxx`) in UIs and
pass the full handle back.

**Disable:**

- Takes effect on the next request. `validate_session` checks the user's
  status on every call.
- `disable_user` then revokes every session, so the audit trail records the
  end of each one. It returns the number of sessions that the call revoked.
- Safe to retry. After an error, the user may already be disabled, and a new
  call finishes the revocation. A repeat call on a disabled user is not an
  error. It returns `0` when no session is left to revoke.

**Enable:**

- Never restores a session from before the disable. `enable_user` first
  revokes every session that is still live. This step finishes a disable
  whose revocation failed or is still running. It re-enables the user only
  after that step succeeds. On an error the user stays disabled, so a retry
  is safe.
- It also stamps a `sessions_valid_after` watermark on the profile.
  Validation accepts only sessions created at or after the watermark, in
  whole seconds. A login right after the enable therefore works. The user
  logs in again.
- The revocation step does not depend on clocks. The watermark alone would
  not be enough. A session's `created_at` comes from the auth host's clock.
  That clock can run ahead of the admin host's clock by up to the skew
  tolerance (`spec/tla/Session.tla`, `Inv_NoPreEnableSurvivor`).

**Revoke all:** `revoke_all_sessions` ends only active sessions. It does not
touch expired sessions, so the work and the audit trail stay bounded. A
session counts as expired only when the clock-skew tolerance has passed since
its expiry. Thus an admin host with a fast clock cannot skip a session that a
slower host still accepts.

**Concurrent actions** on the same user cannot overwrite each other (ADM-F1,
fixed in 0.5.0):

- Every disable and enable bumps the profile's `admin_version`.
- An enable is conditional on the version that it reads at its start. If
  another admin changed the user in between, the enable fails with
  `AdminError::Conflict` and writes nothing. For example, a disable can occur
  while a slow enable still revokes sessions. Re-read with `get_user` and
  decide again.
- A disable has no condition except that the user must exist. Disable is the
  safe direction, so it never loses a race. On an already-disabled user, it
  still records the attempt and bumps the version. It keeps the time and
  admin of the first disable.

**Other rules:**

- Audit events within the same second list in event-id order, not action
  order. Use the timestamps.
- The library, not IAM, enforces "append-only". The admin role needs
  `TransactWriteItems`, which can also overwrite rows. For tamper evidence,
  enable DynamoDB point-in-time recovery or stream exports.
- If you upgrade from a version that set `ttl` on session rows, run
  `DynamoDbAuthStore::remove_legacy_session_ttl` once. This stops TTL from
  deleting retained sessions. Admin listings skip index rows whose session
  row is gone.
- Admin ids and reasons have length caps and must not contain control
  characters. `Debug` redacts the reason.

## Proof-of-work requirements

- Make PoW difficulty configurable. Document a production floor. Use explicit
  production config. Put low development-only values in examples only.
- Version and domain-separate challenge formats.
- MAC the challenge random data and metadata.
- Bind proof cookies to the solved challenge (`tid`).
- Keep PoW admission outside magic-link APIs.
- Bound the proof-cookie lifetime with a configurable TTL under a hard
  ceiling.
- The proof cookie is stateless and reusable within its lifetime. Bound that
  reuse with the per-solve budget. Gate routes with `admit_proof` and a
  shared `ProofBudget` ([integration.md](integration.md), "Per-solve
  budget").
- If a client replays an exhausted proof cookie in a loop, each attempt gets
  `401` without a new admission. Each attempt still costs one budget write.
  Per-IP and global request limits at the edge bound that cost. The library
  does not bound it.
- Budget counters (`RateLimiter::check_lifetime_limit`) use an unkeyed,
  domain-separated SHA-256 of the key as their storage key. Thus storage-key
  rotation never splits or resets a budget. For this reason, lifetime keys
  must carry no personal data. The PoW budget keys by the random solve id.
- The PoW layer owns the proof-cookie lifecycle. The magic-link flow does not
  clear the proof cookie.

### Solve-timing signal

`datadeft-pow-core::Verified::mint_to_verify_ms` is the server-derived
mint-to-verify delta of a successful solve, in milliseconds.
`datadeft-pow-axum` exposes it as `PowAdmission::mint_to_verify_ms`.

Why you can trust it:

- Both instants come from server clocks. The tag HMAC-binds the challenge
  `tim`, so a client cannot backdate it. The client never reports its own
  timing.
- A client can make the delta larger if it holds a solved challenge. It can
  never make the delta smaller than its true solve time.
- Thus a client cannot fake an "implausibly fast" delta. Given the clock
  assumption below, a delta below the browser-physical floor for the
  difficulty is strong evidence of a native-speed solver.
- Clock assumption: when one instance mints and another verifies, the delta
  shifts by the clock offset between them. A verifier whose clock runs behind
  the minter's shrinks every delta by that offset. If the verifying clock is
  behind `tim`, the value is `None`, because the delta is then unknown. The
  verifier accepts such a `tim` within `MAX_FUTURE_SKEW_SECS`. A fast floor
  is sound only when the offset between instance clocks is well below the
  floor. On AWS, the Amazon Time Sync Service gives this synchronization.
- The delta includes network round trips and client-side queueing, not only
  solve time.

How to use it:

- Use the delta for risk tagging, triage, per-difficulty histograms and
  difficulty tuning.
- Gate only on the fast direction. Keep slow or "human-looking" deltas soft.
  A bot that sleeps before it submits looks like a human on each request.
- Calibrate any fast floor from field data per difficulty, never from
  theory.
- Never treat `None` as a fast solve. Count it separately. A rising `None`
  rate means clock drift between instances.
- Genuine cohorts mix device speeds, so their solve times are a mixture of
  exponentials. Tests against a single theoretical exponential reject honest
  traffic.
- The browser-side floor exists only because the shipped
  `@datadeft/protect-client` worker pays an async `crypto.subtle` round trip
  per attempt. A WASM or native-speed client erases the floor. A future
  optimization of the official client also erases it. Before you change the
  client's solve loop, revisit every threshold.
- Aggregation (per-IP, per-cohort, distribution-shape tests) belongs to the
  app or edge. The library exposes only the per-solve delta.
- You can carry a classification to later gate checks statelessly. To do
  this, stamp an app-defined byte (`solve_class`) into the proof cookie's
  encrypted v2 body.
  The library gives the byte no meaning. The minting app defines the
  quantization, and the reading app defines the policy.

## One-time magic-link consumption

Magic-link consume flows must enforce one-time use:

1. Look up by keyed selector material only.
2. Check expiry before creating the session.
3. Compare verifier-derived material in constant time.
4. Consume the token atomically with session creation. Use conditional
   delete, update or compare-and-swap storage.
5. Key replay stores on authenticated token identity, never on the raw token
   string. For Branca tokens, key dedup stores on
   `datadeft-auth-token-core::branca::Jti`.
6. Return the same public failure for every invalid token state: expired,
   consumed, missing, malformed and invalid verifier.
7. If storage can apply failed-attempt limits safely, apply them.
8. Add replay tests and concurrent consume tests.

## HMAC lookup material

Use secret-keyed HMAC, never bare SHA-256, for lookup keys derived from
secrets or PII:

- email addresses
- magic-link selectors and verifiers
- session IDs
- rate-limit keys with sensitive material

## Data at rest

- The library never stores raw tokens, selectors or verifiers. It stores only
  keyed HMACs and verifier hashes. HMACs keep raw selectors, verifiers,
  session IDs and emails out of record keys.
- The library stores the normalized email as a readable record attribute.
  The app needs it to send mail and to identify the account. The atomic
  authentication transaction needs it for its equality checks. Lookups key on
  `HMAC(email)`, so no index holds a raw address.
- Do not add application-layer email field encryption.
- Keyed lookup keys stop an attacker from guessing record addresses. They do
  not stop an attacker who reads a full table dump. Protect auth tables with
  provider encryption at rest (DynamoDB KMS), least-privilege IAM and backup
  controls.

## Logging

Never log:

- raw magic-link tokens, selectors, verifiers or cookies
- Branca tokens or session IDs
- key material or HMAC peppers
- email addresses, unless the app approves

Use redacted `Debug` and app-level derived identifiers.

## Timing and comparison

Use constant-time comparison for verifier hashes, token MAC and tag values,
and stored secret-derived values. Never add early-return comparison logic for
secrets.

Enumeration-resistant flows need bounded dummy work:

- Do dummy verifier work on a missing selector.
- Avoid clear timing gaps on unknown-user and throttled request paths.
- Prefer bounded dummy work and generic responses. Do not promise strictly
  matched latency.
- Apply a keyed-selector limit on landing, so there is no unthrottled read
  oracle.

## Configuration

- Production secrets come from the consuming application.
- Make cookie names, TTLs, peppers and keys configurable. Where you use an
  issuer and audience, make them configurable too.
- Use fake development values only in examples.
- Never assume production defaults silently.

## Key management and rotation

- Use purpose-separated keys and peppers. Branca token keys, session cookie
  keys, HMAC lookup keys, PoW signing keys and adapter encryption keys are
  all separate. Never reuse one secret across purposes.
- Use at least 256 bits for symmetric keys and peppers.
- Validate and domain-separate key IDs. Bind key derivation to purpose and
  key ID.
- Mint with active keys. Use verify-only keys for migration. Reject retired,
  disabled and unknown keys.
- Test active-key minting, verify-only validation, and retired-key and
  unknown-key rejection.

## Secret manager config

Production uses AWS Secrets Manager. Core crates never fetch secrets. Use a
thin config shape. Do not use a policy engine or implicit environment reads.

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

- v1 supports `AwsSecretsManager` only. Add a manager only with code and
  tests.
- Adapters resolve `SecretRef` values. Core and service APIs receive loaded
  key material.
- Map `AWSCURRENT` to active material by explicit config. Map `AWSPREVIOUS`
  to verify-only material only when the config enables it. Never load
  retired keys.
- Redact secret names, ARNs, version IDs, version stages and secret payloads
  in `Debug`.
- Zeroize secret payloads where practical.

### Auth secret document

Each `SecretRef` resolves to one JSON document. `AuthSecretsConfig` takes one
active document. During rotation, it also takes one previous document.

```json
{
  "kid": "ex-2026-07",
  "mint_until_unix": 1790000000,
  "verify_until_unix": 1792600000,
  "magic_link_lookup_hmac_b64": "<32 bytes, standard base64>",
  "storage_hmac_b64": "<32 bytes, standard base64>",
  "session_cookie_root_b64": "<32 bytes, standard base64>",
  "magic_link_confirm_cookie_root_b64": "<32 bytes, standard base64>",
  "pow_challenge_secret_b64": "<32 bytes, standard base64>",
  "pow_proof_cookie_root_b64": "<32 bytes, standard base64>"
}
```

The six secret fields are, in order: magic-link lookup HMAC, storage HMAC,
session cookie root, confirm cookie root, PoW challenge HMAC secret and
proof cookie root.

- `kid` is the key ID for each derived keyring slot. It must pass
  `KeyId::parse` and be at most 12 bytes. Every keyring refuses a `kid` that
  leaves no room for the largest cookie body of its purpose. The proof
  cookie allows 12 bytes, and the session cookie allows 38.
- The 12-byte limit applies to the previous document too.
  `pow_proof_keyring` enforces it when it builds the keyring.
- Every field is required. The loader ignores unknown fields, so an app can
  keep its own fields in the document. Give these fields names that cannot
  collide with future library fields (for example, an `app_` prefix).
- `mint_until_unix` sets the active mint window. `verify_until_unix` sets the
  verify window. It must cover the longest purpose lifetime.
- Each `*_b64` value must decode to 32 bytes. Generate each value
  independently. Never reuse a value across fields:

```sh
openssl rand -base64 32
```

`LoadedAuthSecrets` supplies the PoW keys and does not depend on the PoW
crates:

- `pow_challenge_secret` (and `previous_pow_challenge_secret` during
  rotation) as redacted key bytes for `PowSecret::new`.
- `pow_proof_keyring::<PowProofCookie>()` for the proof cookie keyring. The
  root of the previous document is its verify-only slot. Build the keyring
  at startup, so that a bad `kid` fails there.

## Rotation cadence

For 30-day session validity, keep old session keys for the full session
lifetime after they stop minting.

| Secret class | Active rotation | Verify-only retention |
| --- | ---: | ---: |
| Session cookie keys | 90 days | 31 days |
| Branca session token keys | 90 days | 31 days |
| Magic-link lookup HMAC key | 90 days | Link TTL plus 24 hours |
| Storage HMAC key | 90 days | 31 days, and until `rekey_email_lookups` runs |
| PoW signing keys | 90 days | Needs challenge TTL plus 24 hours. In practice, it lasts while the app loads the previous document (see below). |
| Rate-limit HMAC keys | 90 days | Longest window plus 24 hours |

- `AWSCURRENT` is active material. `AWSPREVIOUS` is verify-only material when
  the config enables it.
- Never mint with verify-only keys. Never mint HMAC lookup values with old
  keys. Use previous HMAC keys only as a read fallback during rotation.
- Do not rotate session keys faster than their verify retention. Keep
  previous session keys for at least 31 days.
- Reissue cookies with active keys after normal authorization checks.
- Retire magic-link and PoW keys sooner than session keys.
- Fail closed on unknown, missing, retired, disabled or malformed key IDs.

All keys share one document. The previous PoW keys (challenge secret and
proof cookie root) stay verifiable while the app loads the previous
document. This period lasts until its `verify_until_unix` (at least 31 days
for session keys). That is longer than the PoW keys need.

If a PoW key leaks, write a new version and drop `previous` sooner. This
also ends the previous session keys, so users of those cookies must log in
again. If the storage key changed, run `rekey_email_lookups` first.

### Rotating the HMAC keys

The storage and lookup HMAC keys address records. Thus, the rotation of
these keys needs a read fallback, not only a verify-only slot.
`LoadedAuthSecrets` exposes the HMAC keys of the previous document only when
they differ from the active keys.

1. Write a new secret version with fresh values. Secrets Manager moves the
   old version to `AWSPREVIOUS`. Load it as the previous document.
2. Pass `previous_storage_hmac_key` to
   `DynamoDbAuthStore::with_previous_storage_hmac_key`. Pass
   `previous_lookup_hmac_key` to
   `MagicLinkFlowService::previous_lookup_hmac_key`.
   - If a session or email lookup misses under the new key, it tries again
     under the previous key. A user that it finds this way gets a lookup row
     under the new key.
   - A user that the library creates during the window gets lookup rows
     under both keys. Thus, a host that still uses the old key during a
     rolling deploy finds the account. It does not create a second account
     (`spec/tla/KeyRotation.tla`).
   - Links that the service issued just before the rotation stay usable.
3. Before you drop the previous document, run
   `DynamoDbAuthStore::rekey_email_lookups` (needs `dynamodb:Scan`). It
   writes new-key lookup rows for users who did not log in during the window.
   It is idempotent.
4. Keep the previous document for at least 31 days, so that pre-rotation
   sessions expire naturally. Then remove it.

If you remove the previous storage key before step 3, you strand users who
have not logged in since the rotation. Their next login creates a second
account.

Keyed window rate-limit counters restart once at rotation. These limits are
best-effort. Per-solve lifetime counters do not restart.

## Cookie security

Cookie helpers use safe settings by default:

- Lower `snake_case` names. v1 does not require `__Host-` and `__Secure-`.
  Review the `__Host-` defaults again before public release.
- `HttpOnly` for auth cookies.
- `Secure` outside local development.
- Conservative `SameSite`.
- Host-only scope. Set `Domain` only through explicit app config.
- Always set `Path` explicitly: `Path=/` for primary session cookies, narrow
  paths for temporary auth cookies.
- Explicit `Max-Age` or expiry.

Clear these cookies:

- the session cookie on logout, invalid session and expired session
  responses
- the confirm cookie after authentication success and on terminal
  authentication failure

Document the CSRF expectations of each cookie route. Protect unsafe methods
from CSRF.

## Session revocation

The default session model supports server-side invalidation.

- On logout, revoke server-side session state before you clear the cookie.
- Logout is a CSRF-protected `POST`.
- Support compromise revocation before absolute expiry.
- Stateless sessions are not the default. If an app uses them, the app must
  document the trade-off and use shorter TTLs.
- Map invalid sessions to the generic `401` + `DD-Session` failure. Clear
  the session cookie where possible.

## Email identity

Email identity is an exact match on the normalized address. The library owns
the one normalization rule, `NormalizedEmail::normalize`. Thus, every app
gets the same identities.

- Trim surrounding whitespace. Then lowercase the whole address in ASCII.
- The lowercase conversion of the local part is a documented policy choice.
  RFC 5321 lets a mail host treat `Alice@` and `alice@` as different
  mailboxes. On such a host, the two mailboxes share one account. Almost no
  host does this, and users expect that case does not matter.
- No Gmail dot folding, plus-tag stripping or other provider alias rules.
- `NormalizedEmail::from_normalized` only validates. Use it for values that
  the app reads back from storage. It refuses uppercase letters and
  surrounding whitespace. It does not convert them.
- Reject empty values, multiple addresses, display-name forms, CR, LF, NUL
  and other control characters, and whitespace inside the address.
- Enforce the documented length caps.
- Treat the normalized email as sensitive. Redact it in `Debug`, errors,
  logs, fixtures and snapshots.

For storage, see [Data at rest](#data-at-rest).

## Magic-link URL handling

Magic-link tokens appear in URLs. Thus, treat URLs as log-sensitive secrets.

The scanner-safe flow has two steps, so that link scanners cannot use up a
link or complete a login:

1. The email opens a `GET` landing route with the token.
2. The `GET` never consumes the token or creates a session. It has no side
   effects except the creation of short-lived flow state. It is repeatable.
3. The flow state binds the selector, verifier proof, account, expiry and an
   independent confirmation nonce.
4. The page identifies the account and asks the user to click a button. It
   exposes no raw token material.
5. A same-origin `POST` validates the bound flow state. It commits token
   consumption and session creation atomically. Then it clears temporary
   state and redirects to a clean URL.

Rules:

- Do not log full landing URLs or token-bearing query strings.
- Scrub token route fields before metrics and traces.
- Prefer an `HttpOnly` confirm cookie.
- Never put tokens in rendered forms or bodies, `Location` headers,
  JavaScript or analytics events.
- Use fixed or allowlisted post-consume redirects. Never accept arbitrary
  `next` URLs.
- Landing pages send `Cache-Control: no-store` and load no third-party
  assets.
- Prevent framing with CSP. Also send `X-Frame-Options: DENY` for old
  clients.
- Set `Referrer-Policy: strict-origin`. It keeps the token-bearing path and
  query out of `Referer`. Do not use `no-referrer`. With it, browsers send
  `Origin: null` on the confirmation form `POST`, and the same-origin check
  rejects that request.

Limits of the design:

- Scanner safety protects against `GET`-only scanners. TTL, binding,
  one-time consumption and generic failures stop active scanners that submit
  forms.
- The confirmation page mitigates login CSRF because it shows the account.
  If the app needs a stronger mode, offer one.

### Scanner-safe response contract

`datadeft-magic-link-axum` runs the input gauntlet. The application owns the
rendered responses and must:

1. Return uniform landing and confirmation failures. Use the same status for
   a rejected landing as for a successful landing.
2. Clear the confirm cookie on a rejected confirmation. On an internal
   confirmation failure, clearing it is optional. Preserve it on a dependency
   failure.
3. Send `no-store`, CSP and frame-denial headers.
4. HTML-escape the rendered account identity.

Accepted trade-off: the confirmation route rejects a cross-site form `POST`
and clears the confirm cookie (rule 2). Thus, another site can end a flow in
progress. The user then clicks the link again. This consumes no token and
creates no session. The landing `GET` never clears the cookie on a rejected
link.

### Redirect landing mode

Use this mode for UIs that you serve as static files
(`MagicLinkScannerFlowConfig::with_redirect_landing`). In this mode, the
token also never reaches JavaScript:

1. The emailed link opens the landing `GET`. The landing validates the link
   but does not consume it. It sets the `HttpOnly` confirm cookie. For every
   link state, it answers `303` to one configured same-origin page.
   - An unusable link gets no `Set-Cookie` at all. Landings are cross-site by
     nature. Thus, a clearing header would let any site end a sign-in in
     progress with a junk link.
   - A cookie from an earlier link still reads as the state of that link.
   - `Location` never carries the token, selector, verifier or confirmation
     value.
2. The page sends a `GET` to the flow-state route. This route:
   - reads only the confirm cookie
   - requires exactly `Sec-Fetch-Site: same-origin`
   - sends no CORS headers, and sends
     `Cross-Origin-Resource-Policy: same-origin` plus the security headers of
     the landing
   - has the same per-selector throttle as the landing, and never writes
   - answers `{ "usable": true, "account": …, "confirmation": … }` for a
     usable link
   - answers `{ "usable": false }` and clears the cookie for anything
     unusable
   - answers the constant `503` on an outage
3. The page posts `{ confirmation }` same-origin to the confirmation route.
   It does this exactly as the form does in server-rendered mode.

The `Path` of the confirm cookie must cover the flow-state route and the
confirmation route. Otherwise, the configuration refuses it.

The static page holds the account and the confirmation value. Thus, it
follows the rules of the landing page:

- A strict CSP:
  - scripts only from the same origin
  - no third-party scripts, styles, fonts or analytics
  - no error beacons that send page content
  - `frame-ancestors 'none'`
- `Referrer-Policy: strict-origin` and `Cache-Control: no-store`.
- No shared navigation or session scripts. The page shows the account and
  posts the confirmation. It does nothing else. On `{ "usable": false }`, it
  offers "request a new link". On `503`, it asks the user to try again later.

### Email language and Reply-To

- The email language comes from `MagicLinkServiceConfig::locales`, an
  app-configured `LocaleAllowlist`. A request can carry a locale hint. The
  service resolves the hint to an allowed locale or to the default. The
  renderer sees only the resolved `Locale`, never request text. The service
  does not store the locale.
- Only the outbox configuration sets Reply-To
  (`SesMagicLinkOutbox::with_reply_to`). A request never sets it. If a
  request could choose Reply-To, anyone could send our genuine login emails
  with their own reply address. That is phishing from our domain.

## HTTP response contract

The library has one supported mapping, and apps cannot configure it. Clients
act on it. Nothing else about a refusal is public.

| Response | Meaning | Client action |
| --- | --- | --- |
| `401` + `WWW-Authenticate: DD-PoW` | The proof of work is missing, invalid or expired, its per-solve budget is used up, or a posted solution failed. | Solve a challenge, then retry once. A new solve gives a fresh per-solve budget. |
| `401` + `WWW-Authenticate: DD-Session` | The session is missing, invalid, expired or revoked. The response clears the session cookie. | Sign in again. |
| `400`, one generic body | A shape error that leaks nothing: bad JSON, an invalid email address, wrong content type, oversize body, an unusable magic link (`MagicLinkUnavailable`). | Fix the request. Do not retry. |
| `503`, one constant body, `no-store` | Everything security-sensitive or failed: rate limits, quotas, dependency or server faults. | Wait a backoff delay with equal jitter, then retry. Never retry without jitter. |
| `403` | The library never sends it. The app owns it for business authorization. | App-defined. |

The library never sends `403`, `500` or `429`.

These exceptions also reveal nothing:

- The magic-link request answers the same generic `200` when it sends,
  throttles or drops the email.
- The landing answers the same page for every link state.
- The confirmation answers with one human-readable page on failure.

Rules:

- The `503` body, status and `Cache-Control: no-store` are byte-identical for
  every reason, across `datadeft-magic-link-axum` and `datadeft-pow-axum`. A
  route can add its own fixed security headers. For example, the flow-state
  route sends the security headers of the landing on every answer. In one
  route, every `503` is byte-identical, so no reason is distinguishable.
- Log and count the internal reason. Never send it. The typed reasons are
  `MagicLinkHttpError`, `ProofRejection` and `SessionRejectionKind`. The
  request endpoint always answers `200` in public. Its typed reason is
  `RequestMagicLinkOutcome` (`Sent` or `Throttled(RequestThrottle)`). Each
  type has a stable `reason()` label for metrics. The label contains no
  identifiers, emails or token material.
- Alert on the reason counts, not on raw `5xx` rates. A bot flood is many
  `503`s by design. Point load-balancer health checks at a dedicated health
  endpoint.
- A `4xx` that does not leak is acceptable only where it reveals nothing
  about accounts, links, limits or quotas.

## Rate limiting and abuse controls

| Owner | Controls |
| --- | --- |
| Magic-link | Normalized-email request and outbox limits. Selector landing and consume limits. |
| Consuming app or edge | IP, network-source and global fanout limits. Malformed-request admission. PoW admission. |

Start with these thresholds:

| Flow | Key | Limit | Public response |
| --- | --- | ---: | --- |
| Request | Email HMAC | 3 per 15 minutes | Generic accepted |
| Request | Email HMAC | 10 per 24 hours | Generic accepted |
| Outbox | Email HMAC | 3 per 1 hour | Generic accepted |
| Outbox | Email HMAC | 10 per 24 hours | Generic accepted |
| Landing | Selector key | 30 per 10 minutes | Generic landing |
| Consume | Selector key | 5 per token TTL | Generic invalid |

- Make thresholds configurable.
- Return generic responses for throttled users, unknown users, and consumed,
  expired or invalid tokens.
- Fail closed when limiter storage fails.
- Document the targeted-lockout trade-off.

The request and outbox limits count each attempt before the send. A send that
fails at the outbox (reason `magic_link_outbox_unavailable`) still uses quota.
During an email-provider outage, a user reaches the limit sooner. This is
deliberate: a refund needs a second write and makes the count racy. Alert on
the outbox reason.

## One supported way

Do not add legacy support unless the project approves a versioned path. Do
not add dual-read, dual-write, a compatibility fallback, an old token parser
branch or a deprecated alias.

Forward version markers are acceptable. They name the one current format:

```text
v1
pow-v1
ml1
```

## Dependency hygiene

- Prefer small, maintained crates.
- Avoid unnecessary untrusted-input parsers.
- Keep cloud SDKs out of core crates.
- Review crypto dependencies before use.
- Document each crypto, parsing, HTTP, AWS, async or token dependency.
- Run `cargo deny` or `cargo audit` before release. The dependency audit is
  part of `mise run verify`.

## Security checklist

Before phase acceptance, confirm these items:

1. Source, docs, tests and examples contain no secret values.
2. `Debug` redacts sensitive types, and errors expose no sensitive values.
3. Tests cover tamper, replay, expiry, malformed-token and unknown-key cases.
4. Token parsers reject non-canonical encodings.
5. Replay stores use `Jti` or an equivalent identity as the key.
6. Entropy generation meets the minimums.
7. Magic-link consume tests prove one-time use.
8. Scanner flow tests prove that `GET` does not consume and that `POST`
   requires bound state.
9. Confirmation pages prevent framing.
10. A `Rejected` confirmation clears the confirm cookie. `Unavailable`
    preserves it. Clearing on `Internal` is optional.
11. Redirects stay fixed or allowlisted.
12. Cookie helpers use secure defaults.
13. Logout revokes server state before it clears the cookie.
14. Key rotation tests cover active, verify-only and retired keys.
15. PoW tests cover the difficulty floor, challenge entropy and replay
    limits.
16. Rate-limit tests cover the email and selector domains.
17. URL handling scrubs token material.
18. Email input tests cover invalid structures.
19. Timing review covers dummy work.
20. Core code has no IO sources.
21. Adapter errors map to safe public errors.
22. Solve-timing consumers gate on fast deltas only. Slow deltas stay soft.
23. The dependency audit passes before release.

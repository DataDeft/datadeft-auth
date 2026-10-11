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
  seconds. PoW Axum uses `PowPolicy::with_clock_skew_secs`.
- Apply the bound separately to challenge and proof-cookie verification.
- Zero forbids future timestamps.
- The bound is capped at `MAX_CLOCK_SKEW_SECS` (300 seconds). Larger values
  are a configuration error.
- Skew never extends an expired TTL or a key's lifetime.
- Magic-link service wrappers keep the default.

## Freshness bounds are capped

A misconfigured bound fails loudly instead of making old cookies or
stockpiled solutions valid:

- Cookie verification rejects an idle or absolute max age above the cookie
  type's `MAX_ABSOLUTE_AGE_SECS` (session 30 days, proof cookie 24 hours,
  confirm cookie 5 minutes) with `TokenError::InvalidTimestamp`.
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
- Freshness checks are mandatory: the caller must pass a freshness bound to
  every validation call.
- Store both idle and absolute session times.
- Reject future-dated tokens beyond the clock skew.
- Use compact internal framing for encrypted payloads.

### Adapter storage keying

Repository traits pass raw `SessionId`, `NormalizedEmail` and `RateLimitKey`
values. Each storage adapter must key them before storage, using the shared
`datadeft_magic_link_core::domain_separated_lookup_hmac` framing with an
adapter-specific domain and secret.

- The type system does not enforce this. A new repository could store raw
  IDs and still compile.
- Only first-party adapters are approved. New adapters must copy the keying
  behavior, using the `datadeft-magic-link-aws` vectors as the reference.
- Moving key derivation into the service changes stored partition keys and
  needs a data migration.

### Session country lock

Session country is an opportunistic lock.

- Take country only from a configured trusted-edge header, never from a
  request body.
- When confirmation supplies a country, bind the session to it. Every
  validation must see the same country.
- A missing country does not satisfy a locked session: fail closed.
- A session bound without a country stays unlocked and skips the check.
- The lock only works when the edge strips or overwrites the header and the
  origin is not directly reachable.

#### Country groups

`MagicLinkServiceConfig::country_policy` defaults to `CountryPolicy::Exact`.
`CountryPolicy::eu27()`, or custom `CountryGroup`s, pins a country inside a
group to the group's tag (`EU`), so a session moves freely between the
group's countries. Any other country stays pinned exactly. The same mapping
runs at binding and on every validation. A session bound under one policy
fails closed under another.

Trade-off: a group weakens the lock on purpose. A stolen session cookie then
works from any country in the group. Choose the smallest group your users
need. This is still much safer than rewriting the trusted header at the edge,
which would hide the real country from everything else.

Configuration validation refuses:

- a country in two groups
- duplicate tags
- tags other than `EU` or ISO user-assigned codes (`XX` and `XK` excluded)

A request country of `EU` or a user-assigned code pins to nothing under every
policy. It is treated as missing and fails closed.

## Bearer secret entropy

All bearer secrets and anti-guessing nonces come from a CSPRNG.
Deterministic bytes are allowed only in tests.

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
- Draw magic-link selectors and verifiers independently. Neither is derived
  from the other, and they never share one sliced random block.

### Identifier formats

Library-minted ids use one form, `<tag>-<lowercase hex>`. Parsers accept
nothing else; the 0.4 underscore form is refused.

| Id | Form | Random bits |
| --- | --- | ---: |
| User id | `usr-` + 32 hex | 128 |
| Session id | `sid-` + 64 hex | 256 |
| Authentication attempt id | `aid-` + 32 hex | 128 |
| Admin event id | `evt-` + 32 hex | 128 |
| Session display id | `sess-` + 8 hex | (label only) |

Ids are validated on input and redacted in `Debug`. Keyed lookup values
(`emh_`, `mlh_`, `mlv_`, `sih_`, `rlh_`) are storage material, not ids, and
keep their underscore form.

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
  re-issues the cookie once half the idle lifetime has passed, keeps the
  original `iat`, session ID and country, mints under the active key, and
  never writes storage. Validation itself stays read-only.
- Trade-off: with sliding refresh, a stolen cookie that keeps being used
  stays valid until the absolute lifetime or revocation. Revoke server state
  on logout and on suspected compromise.
- Use the cleanup TTL only for storage deletion.

## Retention

Nothing that identifies an account or its activity is deleted; those rows
are the audit trail. DynamoDB TTL (the `ttl` attribute) is set only on rows
with no audit value:

| Row | Retention |
| --- | --- |
| User profile, email lookup | Kept; disabling is a flag, never a delete |
| Session, per-user session index | Kept; expiry and revocation are fields |
| Admin audit events | Kept; append-only |
| Magic-link challenge | TTL: expiry plus `magic_link_cleanup_grace` |
| Rate-limit counter | TTL: window end plus cleanup grace |
| Lifetime counter (per-solve budget) | TTL: the expiry fixed at first use plus cleanup grace |

Validity never depends on deletion: every read checks `expires_at_unix` and
`revoked_at_unix`.

## Admin operations

`AuthAdminService` gives consuming projects the data and audited mutations
for their own admin UI. The application decides who is an admin. Authorize
every admin endpoint before calling the service.

**Queries:** `list_users`, `get_user`, `find_user_by_email`,
`list_sessions_for_user`, `list_active_sessions`, `list_admin_events`.

- Pages use an opaque `PageCursor` and a limit clamped to 100.
- A page may be shorter than the limit while more remain. Continue while
  `next` is set.

**Mutations:** `revoke_session` (final), `revoke_all_sessions`,
`disable_user`, `enable_user`.

- Each writes the change and an append-only `AdminEvent` (event id, time,
  action, user, session, admin id and reason) in one transaction: both or
  neither.
- Admin transactions use the audit event id as the DynamoDB idempotency
  token.

**Session handles:** sessions are addressed by `SessionHandle`, the keyed
hash they are stored under. The raw session id is not stored. Show
`display_id()` (`sess-xxxxxxxx`) in UIs and pass the full handle back.

**Disable:**

- Takes effect on the next request: `validate_session` checks the user's
  status every time.
- `disable_user` then revokes every session, so the audit trail records each
  one ending, and returns how many sessions that call revoked.
- Safe to retry: after an error the user may already be disabled, and
  calling again finishes revoking. A repeat call on a disabled user is not an
  error; it returns `0` once nothing is left to revoke.

**Enable:**

- Never restores a session from before the disable. `enable_user` first
  revokes every session still live (finishing a disable whose revocation
  failed or is still running). It re-enables only after that succeeds; on an
  error the user stays disabled, so it is safe to retry.
- It also stamps a `sessions_valid_after` watermark on the profile.
  Validation accepts only sessions created at or after it (whole seconds), so
  a login right after the enable works. The user logs in again.
- The revocation step does not depend on clocks. The watermark alone would
  not be enough: a session's `created_at` comes from the auth host's clock,
  which may be up to the skew tolerance ahead of the admin host's
  (`spec/tla/Session.tla`, `Inv_NoPreEnableSurvivor`).

**Revoke all:** `revoke_all_sessions` ends only active sessions. Expired ones
are left untouched, so the work and audit trail stay bounded. A session
counts as expired only once the clock-skew tolerance has passed after its
expiry, so an admin host whose clock runs ahead cannot skip a session that a
slower host still accepts.

**Concurrent actions** on the same user cannot overwrite each other (ADM-F1,
fixed in 0.5.0):

- Every disable and enable bumps the profile's `admin_version`.
- An enable is conditional on the version read at its start. If another admin
  changed the user in between (for example, a disable made while a slow
  enable was still revoking sessions), it fails with `AdminError::Conflict`
  and writes nothing. Re-read with `get_user` and decide again.
- A disable is unconditional apart from the user existing. Disabling is the
  safe direction, so it never loses a race. On an already-disabled user it
  still records the attempt and bumps the version, keeping the first
  disable's time and admin.

**Other rules:**

- Audit events within the same second list in event-id order, not action
  order. Use the timestamps.
- The library, not IAM, enforces "append-only": the admin role needs
  `TransactWriteItems`, which could also overwrite rows. Enable DynamoDB
  point-in-time recovery or stream exports for tamper evidence.
- When upgrading from a version that set `ttl` on session rows, run
  `DynamoDbAuthStore::remove_legacy_session_ttl` once, so TTL cannot delete
  retained sessions. Admin listings skip index rows whose session row is
  gone.
- Admin ids and reasons are length-capped and may not contain control
  characters. `Debug` redacts the reason.

## Proof-of-work requirements

- Make PoW difficulty configurable, document a production floor, and use
  explicit production config. Low development-only values belong in examples
  only.
- Version and domain-separate challenge formats.
- MAC the challenge random data and metadata.
- Bind proof cookies to the solved challenge (`tid`).
- Keep PoW admission outside magic-link APIs.
- Bound the proof-cookie lifetime with a configurable TTL under a hard
  ceiling.
- The proof cookie is stateless and reusable within its lifetime. Bound that
  reuse with the per-solve budget: gate routes with `admit_proof` and a
  shared `ProofBudget` ([integration.md](integration.md), "Per-solve
  budget").
- An exhausted proof cookie replayed in a loop gets `401` without a new
  admission, but each attempt still costs one budget write. Per-IP and global
  request limits at the edge bound that cost; the library does not.
- Budget counters (`RateLimiter::check_lifetime_limit`) are stored under an
  unkeyed, domain-separated SHA-256 of the key, so storage-key rotation never
  splits or resets a budget. Lifetime keys must therefore carry no personal
  data (the PoW budget keys by the random solve id).
- The PoW layer owns the proof-cookie lifecycle. Magic-link does not clear
  the proof cookie.

### Solve-timing signal

`datadeft-pow-core::Verified::mint_to_verify_ms`, exposed by
`datadeft-pow-axum` as `PowAdmission::mint_to_verify_ms`, is the
server-derived mint-to-verify delta of a successful solve, in milliseconds.

Why it can be trusted:

- Both instants come from server clocks. The challenge `tim` is HMAC-bound in
  the tag, so a client cannot backdate it, and the client never reports its
  own timing.
- A client can inflate the delta (by sitting on a solved challenge) but never
  deflate it below its true solve time.
- So "implausibly fast" cannot be faked: a delta below the browser-physical
  floor for the difficulty is strong evidence of a native-speed solver,
  given the clock assumption below.
- Clock assumption: when one instance mints and another verifies, the delta
  shifts by the clock offset between them. A verifier whose clock runs behind
  the minter's shrinks every delta by that offset. The value is `None` when
  the verifying clock is behind `tim` (accepted within
  `MAX_FUTURE_SKEW_SECS`), because the delta is then unknown. A fast floor is
  sound only when instance clocks are synchronized well below the floor (on
  AWS, the Amazon Time Sync Service).
- The delta includes network round trips and client-side queueing, not only
  solve time.

How to use it:

- Use the delta for risk tagging, triage, per-difficulty histograms and
  difficulty tuning.
- Gate only on the fast direction. Slow or "human-looking" deltas must stay
  soft: a bot that sleeps before submitting looks like a human per request.
- Calibrate any fast floor from field data per difficulty, never from
  theory.
- Never treat `None` as a fast solve. Count it separately; a rising `None`
  rate means clock drift between instances.
- Genuine cohorts mix device speeds, so their solve times are a mixture of
  exponentials. Tests against a single theoretical exponential reject honest
  traffic.
- The browser-side floor exists only because the shipped
  `@datadeft/protect-client` worker pays an async `crypto.subtle` round trip
  per attempt. A WASM or native-speed client, including a future
  optimization of the official client, erases it. Revisit every threshold
  before changing the client's solve loop.
- Aggregation (per-IP, per-cohort, distribution-shape tests) belongs to the
  app or edge. The library exposes only the per-solve delta.
- To carry a classification to later gate checks statelessly, stamp an
  app-defined byte (`solve_class`) into the proof cookie's encrypted v2 body.
  The library gives the byte no meaning: the minting app defines the
  quantization and the reading app the policy.

## One-time magic-link consumption

Magic-link consume flows must enforce one-time use:

1. Look up by keyed selector material only.
2. Check expiry before creating the session.
3. Compare verifier-derived material in constant time.
4. Consume the token atomically with session creation, using conditional
   delete, update or compare-and-swap storage.
5. Key replay stores on authenticated token identity, never on the raw token
   string. For Branca tokens, key dedup stores on
   `datadeft-auth-token-core::branca::Jti`.
6. Return the same public failure for every invalid token state: expired,
   consumed, missing, malformed and invalid verifier.
7. Apply failed-attempt limits where storage can do so safely.
8. Add replay tests and concurrent consume tests.

## HMAC lookup material

Use secret-keyed HMAC, never bare SHA-256, for lookup keys derived from
secrets or PII:

- email addresses
- magic-link selectors and verifiers
- session IDs
- rate-limit keys with sensitive material

## Data at rest

- Raw tokens, selectors and verifiers are never stored; only keyed HMACs and
  verifier hashes are. HMACs keep raw selectors, verifiers, session IDs and
  emails out of record keys.
- The normalized email is stored readable as a record attribute. The app
  needs it to send mail and identify the account, and the atomic
  authentication transaction needs it for its equality checks. Lookups key on
  `HMAC(email)`, so no index holds a raw address.
- Do not add application-layer email field encryption.
- Keyed lookup keys stop guessing of record addresses, not reading of a full
  table dump. Protect auth tables with provider encryption at rest (DynamoDB
  KMS), least-privilege IAM and backup controls.

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
- Make cookie names, TTLs, peppers and keys configurable, and issuer and
  audience where used.
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
thin config shape: no policy engine and no implicit environment reads.

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
  to verify-only material only when enabled. Never load retired keys.
- Redact secret names, ARNs, version IDs, version stages and secret payloads
  in `Debug`.
- Zeroize secret payloads where practical.

### Auth secret document

Each `SecretRef` resolves to one JSON document. `AuthSecretsConfig` takes one
active document, plus one previous document during rotation.

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
session-cookie root, confirm-cookie root, PoW challenge HMAC secret and PoW
proof-cookie root.

- `kid` is the key ID for each derived keyring slot. It must pass
  `KeyId::parse` and be at most 12 bytes. Every keyring refuses a `kid` that
  leaves no room for its purpose's largest cookie body; the proof cookie
  allows 12 bytes, the session cookie 38.
- The 12-byte limit applies to the previous document too. It is enforced
  when `pow_proof_keyring` is built.
- Every field is required. Unknown fields are ignored, so an app may keep its
  own fields in the document. Name them so they cannot collide with future
  library fields (for example, an `app_` prefix).
- `mint_until_unix` sets the active mint window. `verify_until_unix` sets the
  verify window and must cover the longest purpose lifetime.
- Each `*_b64` value must decode to 32 bytes. Generate each one
  independently and never reuse a value across fields:

```sh
openssl rand -base64 32
```

`LoadedAuthSecrets` hands over the PoW keys without depending on the PoW
crates:

- `pow_challenge_secret` (and `previous_pow_challenge_secret` during
  rotation) as redacted key bytes for `PowSecret::new`.
- `pow_proof_keyring::<PowProofCookie>()` for the proof-cookie keyring, with
  the previous document's root as a verify-only slot. Build it at startup so
  a bad `kid` fails there.

## Rotation cadence

For 30-day session validity, keep old session keys for the full session
lifetime after they stop minting.

| Secret class | Active rotation | Verify-only retention |
| --- | ---: | ---: |
| Session cookie keys | 90 days | 31 days |
| Branca session token keys | 90 days | 31 days |
| Magic-link lookup HMAC key | 90 days | Link TTL plus 24 hours |
| Storage HMAC key | 90 days | 31 days, and until `rekey_email_lookups` has run |
| PoW signing keys | 90 days | Needs challenge TTL plus 24 hours; in practice as long as the previous document is loaded (see below) |
| Rate-limit HMAC keys | 90 days | Longest window plus 24 hours |

- `AWSCURRENT` is active material. `AWSPREVIOUS` is verify-only material when
  enabled.
- Never mint with verify-only keys. Never mint HMAC lookup values with old
  keys; previous HMAC keys are only a read fallback during rotation.
- Do not rotate session keys faster than their verify retention. Keep
  previous session keys for at least 31 days.
- Reissue cookies with active keys after normal authorization checks.
- Retire magic-link and PoW keys sooner than session keys.
- Fail closed on unknown, missing, retired, disabled or malformed key IDs.

All keys share one document. The previous PoW keys (challenge secret and
proof-cookie root) stay verifiable while the previous document is loaded,
that is until its `verify_until_unix` (at least 31 days for session keys).
That is longer than the PoW keys need. If a PoW key leaks, write a new
version and drop `previous` sooner. This also ends the previous session keys,
so users of those cookies log in again. Run `rekey_email_lookups` first if
the storage key changed.

### Rotating the HMAC keys

The storage and lookup HMAC keys address records, so rotating them needs a
read fallback, not just a verify-only slot. `LoadedAuthSecrets` exposes the
previous document's HMAC keys only when they differ from the active ones.

1. Write a new secret version with fresh values. Secrets Manager moves the
   old version to `AWSPREVIOUS`; load it as the previous document.
2. Pass `previous_storage_hmac_key` to
   `DynamoDbAuthStore::with_previous_storage_hmac_key` and
   `previous_lookup_hmac_key` to
   `MagicLinkFlowService::previous_lookup_hmac_key`.
   - Sessions and email lookups that miss under the new key retry under the
     previous one. A user found that way gets a lookup row under the new key.
   - A user created during the window gets lookup rows under both keys, so a
     host still on the old key during a rolling deploy finds the account
     instead of creating a second one (`spec/tla/KeyRotation.tla`).
   - Links issued just before the rotation stay usable.
3. Before dropping the previous document, run
   `DynamoDbAuthStore::rekey_email_lookups` (needs `dynamodb:Scan`). It
   writes new-key lookup rows for users who did not log in during the window.
   It is idempotent.
4. Keep the previous document for at least 31 days so pre-rotation sessions
   expire naturally, then remove it.

Removing the previous storage key before step 3 strands users who have not
logged in since the rotation: their next login creates a second account.

Keyed window rate-limit counters restart once at rotation; limits are
best-effort. Per-solve lifetime counters do not restart.

## Cookie security

Cookie helpers default to safe settings:

- Lower `snake_case` names. `__Host-` and `__Secure-` are not required in
  v1; review `__Host-` defaults again before public release.
- `HttpOnly` for auth cookies.
- `Secure` outside local development.
- Conservative `SameSite`.
- Host-only scope. Set `Domain` only through explicit app config.
- Always set `Path` explicitly: `Path=/` for primary session cookies, narrow
  paths for temporary auth cookies.
- Explicit `Max-Age` or expiry.

Clear cookies:

- the session cookie on logout, invalid session and expired session
  responses
- the confirm cookie after authentication success and on terminal
  authentication failure

Document the CSRF expectations of each cookie route, and protect unsafe
methods from CSRF.

## Session revocation

The default session model supports server-side invalidation.

- On logout, revoke server-side session state before clearing the cookie.
- Logout is a CSRF-protected `POST`.
- Support compromise revocation before absolute expiry.
- Stateless sessions are not the default. An app that chooses them must
  document the trade-off and use shorter TTLs.
- Map invalid sessions to the generic `401` + `DD-Session` failure and clear
  the session cookie where possible.

## Email identity

Email identity is an exact match on the normalized address. The library owns
the one normalization rule, `NormalizedEmail::normalize`, so every app gets
the same identities.

- Trim surrounding whitespace, then lowercase the whole address in ASCII.
- Lowercasing the local part is a documented policy choice. RFC 5321 lets a
  mail host treat `Alice@` and `alice@` as different mailboxes; on such a
  host the two would share one account. Practically no host does this, and
  users expect case not to matter.
- No Gmail dot folding, plus-tag stripping or other provider alias rules.
- `NormalizedEmail::from_normalized` only validates; use it for values read
  back from storage. It refuses uppercase letters and surrounding whitespace
  instead of converting them.
- Reject empty values, multiple addresses, display-name forms, CR, LF, NUL
  and other control characters, and whitespace inside the address.
- Enforce the documented length caps.
- Treat the normalized email as sensitive. Redact it in `Debug`, errors,
  logs, fixtures and snapshots.

For storage, see [Data at rest](#data-at-rest).

## Magic-link URL handling

Magic-link tokens appear in URLs, so treat URLs as log-sensitive secrets.

The scanner-safe flow has two steps, so link scanners cannot burn or
complete a login:

1. The email opens a `GET` landing route with the token.
2. The `GET` never consumes the token or creates a session. It is
   side-effect-free and repeatable apart from creating short-lived flow state.
3. The flow state binds the selector, verifier proof, account, expiry and an
   independent confirmation nonce.
4. The page identifies the account, asks the user to click a button, and
   exposes no raw token material.
5. A same-origin `POST` validates the bound flow state, commits token
   consumption and session creation atomically, clears temporary state, and
   redirects to a clean URL.

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
- Prevent framing with CSP, plus `X-Frame-Options: DENY` for old clients.
- Set `Referrer-Policy: strict-origin`. It keeps the token-bearing path and
  query out of `Referer`. Do not use `no-referrer`: browsers then send
  `Origin: null` on the confirmation form `POST`, and the same-origin check
  rejects it.

Limits of the design:

- Scanner safety protects against `GET`-only scanners. Active scanners that
  submit forms are stopped by TTL, binding, one-time consumption and generic
  failures.
- The confirmation page mitigates login CSRF by showing the account. Offer a
  stronger mode when the app needs one.

### Scanner-safe response contract

`datadeft-magic-link-axum` runs the input gauntlet. The application owns the
rendered responses and must:

1. Return uniform landing and confirmation failures, with the same status
   for a rejected landing as for a successful one.
2. Clear the confirm cookie on a rejected confirmation. Clearing it on an
   internal confirmation failure is optional. Preserve it on a dependency
   failure.
3. Send `no-store`, CSP and frame-denial headers.
4. HTML-escape the rendered account identity.

Accepted trade-off: a cross-site form `POST` to the confirmation route is
rejected and clears the confirm cookie (rule 2), so another site can end a
flow in progress. The user clicks the link again; nothing is consumed or
created. The landing `GET` never clears the cookie on a rejected link.

### Redirect landing mode

For UIs served as static files
(`MagicLinkScannerFlowConfig::with_redirect_landing`). The token still never
reaches JavaScript:

1. The emailed link hits the landing `GET`. It validates without consuming,
   sets the `HttpOnly` confirm cookie, and answers `303` to one configured
   same-origin page for every link state.
   - An unusable link gets no `Set-Cookie` at all. A clearing header would let
     any site end a sign-in in progress with a junk link (landings are
     cross-site by nature).
   - A cookie left from an earlier link still reads as that link's own state.
   - `Location` never carries the token, selector, verifier or confirmation
     value.
2. The page `GET`s the flow-state route. This route:
   - reads only the confirm cookie
   - requires exactly `Sec-Fetch-Site: same-origin`
   - sends no CORS headers, and sends
     `Cross-Origin-Resource-Policy: same-origin` plus the landing's security
     headers
   - is throttled per selector like the landing, and never writes
   - answers `{ "usable": true, "account": …, "confirmation": … }`, or
     `{ "usable": false }` (clearing the cookie) for anything unusable; an
     outage is the constant `503`
3. The page posts `{ confirmation }` same-origin to the confirmation route,
   exactly as the server-rendered mode's form does.

The confirm cookie's `Path` must cover the flow-state route and the
confirmation route; configuration refuses it otherwise.

The static page holds the account and the confirmation value, so it follows
the landing page's rules:

- A strict CSP: scripts only from the same origin; no third-party scripts,
  styles, fonts or analytics; no error beacons that send page content;
  `frame-ancestors 'none'`.
- `Referrer-Policy: strict-origin` and `Cache-Control: no-store`.
- No shared navigation or session scripts. It shows the account and posts
  the confirmation, nothing else. On `{ "usable": false }` it offers "request
  a new link"; on `503` it asks the user to retry later.

### Email language and Reply-To

- The email language comes from `MagicLinkServiceConfig::locales`, an
  app-configured `LocaleAllowlist`. A request may carry a locale hint; the
  service resolves it to an allowed locale or the default. The renderer only
  sees the resolved `Locale`, never request text, and the locale is not
  stored.
- Reply-To is set only in the outbox configuration
  (`SesMagicLinkOutbox::with_reply_to`), never per request. A request-chosen
  Reply-To would let anyone send our genuine login emails with their own
  reply address: phishing from our domain.

## HTTP response contract

One supported mapping, not configurable. Clients act on it; nothing else
about a refusal is public.

| Response | Meaning | Client action |
| --- | --- | --- |
| `401` + `WWW-Authenticate: DD-PoW` | The proof of work is missing, invalid or expired, its per-solve budget is used up, or a posted solution failed. | Solve a challenge, retry once. A new solve buys a fresh budget. |
| `401` + `WWW-Authenticate: DD-Session` | The session is missing, invalid, expired or revoked. The response clears the cookie. | Sign in again. |
| `400`, one generic body | A shape error that leaks nothing: bad JSON, an invalid email address, wrong content type, oversize body, an unusable magic link (`MagicLinkUnavailable`). | Fix the request; do not retry. |
| `503`, one constant body, `no-store` | Everything security-sensitive or failed: rate limits, quotas, dependency or server faults. | Back off with equal jitter and retry. Never retry without jitter. |
| `403` | Never sent by the library. It is the app's, for business authorization. | App-defined. |

The library never sends `403`, `500` or `429`.

Exceptions, which reveal nothing either:

- The magic-link request answers the same generic `200` whether it sent,
  throttled or dropped the email.
- The landing answers the same page for every link state.
- The confirmation answers one human page on failure.

Rules:

- The `503` body, status and `Cache-Control: no-store` are byte-identical for
  every reason, across `datadeft-magic-link-axum` and `datadeft-pow-axum`. A
  route may add its own fixed security headers (the flow-state route sends
  the landing's headers on every answer). Within one route every `503` is
  byte-identical, so no reason is distinguishable.
- Log and count the internal reason; never send it. The typed reasons are
  `MagicLinkHttpError`, `ProofRejection`, `SessionRejectionKind`, and, for
  the request endpoint whose public answer is always `200`,
  `RequestMagicLinkOutcome` (`Sent` or `Throttled(RequestThrottle)`). Each has
  a stable `reason()` label for metrics, with no identifiers, emails or token
  material.
- Alert on the reason counts, not on raw `5xx` rates: a bot flood is many
  `503`s by design. Point load-balancer health checks at a dedicated health
  endpoint.
- A non-leaking `4xx` is fine only where it reveals nothing about accounts,
  links, limits or quotas.

## Rate limiting and abuse controls

| Owner | Controls |
| --- | --- |
| Magic-link | Normalized-email request and outbox limits; selector landing and consume limits |
| Consuming app or edge | IP, network-source and global fanout limits; malformed-request admission; PoW admission |

Starting thresholds:

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

## One supported way

Do not add legacy support unless the project approves a versioned path. No
dual-read, dual-write, compatibility fallback, old token parser branch or
deprecated alias.

Forward version markers are fine. They name the one current format:

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
- Run `cargo deny` or `cargo audit` before release; the dependency audit is
  part of `mise run verify`.

## Security checklist

Before phase acceptance, confirm:

1. Source, docs, tests and examples contain no secret values.
2. `Debug` redacts sensitive types, and errors expose no sensitive values.
3. Tests cover tamper, replay, expiry, malformed-token and unknown-key cases.
4. Token parsers reject non-canonical encodings.
5. Replay stores key on `Jti` or an equivalent identity.
6. Entropy generation meets the minimums.
7. Magic-link consume tests prove one-time use.
8. Scanner flow tests prove `GET` does not consume and `POST` requires bound
   state.
9. Confirmation pages prevent framing.
10. A `Rejected` confirmation clears the confirm cookie, `Unavailable`
    preserves it, and clearing on `Internal` is optional.
11. Redirects stay fixed or allowlisted.
12. Cookie helpers use secure defaults.
13. Logout revokes server state before clearing the cookie.
14. Key rotation tests cover active, verify-only and retired keys.
15. PoW tests cover the difficulty floor, challenge entropy and replay
    limits.
16. Rate-limit tests cover the email and selector domains.
17. URL handling scrubs token material.
18. Email input tests cover invalid structures.
19. Timing review covers dummy work.
20. Core code has no IO sources.
21. Adapter errors map to safe public errors.
22. Solve-timing consumers gate on fast deltas only; slow deltas stay soft.
23. The dependency audit passes before release.

# 0.5.0 release notes (for the release PR)

release-please generates the `CHANGELOG.md` entry from the commit messages.
Merge this text into that entry in the release PR. The commits do not give the
upgrade summary or the "Security fixes" section. The full consumer checklist
is "Upgrading from 0.4" in `docs/integration.md`. The plan is
`docs/plan-0.5.0.md`.

## Upgrade summary

0.5.0 is a breaking release. To upgrade, you need a **fresh auth table and a
fresh secret document**, and **every 0.4 session ends**. The ids changed form,
and the session cookie body carries the session id. The project gives no
migration tools (pre-1.0, no production deployments).

Consumer actions:

- Ids are `usr-`, `sid-`, `aid-`, `evt-`, `sess-` plus lowercase hex. Update
  validators, fixtures, and API schemas.
- Secret document:
  - Add `pow_challenge_secret_b64` and `pow_proof_cookie_root_b64`.
  - Rename `aws_storage_hmac_b64` to `storage_hmac_b64`.
  - Use a distinct value in every key field.
  - Keep `kid` at 12 bytes or fewer.
  - Make `AWSPREVIOUS` 0.5-shaped, or unset it.
- Cookie configs: use `secure(..)` or `insecure_local(..)`. The getter is
  `is_secure()`.
- Email: remove app-side normalization. The library normalizes with
  `NormalizedEmail::normalize`. Use `from_normalized` where you used `parse`.
- `RateLimiter` implementations: add `check_lifetime_limit`.
- `AuthAdminRepository::set_user_disabled_audited` takes
  `expected_version: Option<u64>`:
  - Pass `None` for a disable. A disable is unconditional and bumps
    `admin_version`.
  - Pass `Some(version)` for an enable. The enable is fenced on that version.
  - Handle `AdminError::Conflict` from `enable_user`.
- `CountryPolicy::pin` returns `Option<&str>`:
  - It returns `None` (fail closed) under any policy when the request country
    is `EU` or an ISO user-assigned code.
  - Such a code is an edge pseudo-code, never the country of a viewer.
  - Make sure that each group tag is `EU` or a user-assigned code other than
    `XX` and `XK`.
  - Make sure that group tags are unique (`DuplicateTag`).
- `RequestMagicLinkOutcome` is `Sent` or `Throttled(..)`. Count it.
- `MagicLinkEmail` and `MagicLinkRequestJson` gain `locale`.
  `MagicLinkServiceConfig` gains `country_policy` and `locales`.
  `MagicLinkConfigError` gains `InvalidCountryPolicy`.
- 0.5.0 removes `MagicLinkHttpError::Forbidden`. `MagicLinkUnavailable`
  answers with the generic `400` body. The `reason()` labels have namespaces
  (`magic_link_*`, `session_*`, `pow_*`).
- Adopt the HTTP status contract (`docs/security.md`):
  - `401` with `WWW-Authenticate: DD-PoW` for a missing proof or a used-up
    per-solve budget.
  - `401` with `WWW-Authenticate: DD-Session`.
  - `400` for shape errors.
  - One constant `503`.
  - No library `403` or `500`.
- Alert on reason counts, not on raw `5xx`.
- Add a load-balancer health endpoint.
- Optional: adopt these features when you need them:
  - the redirect landing mode for static confirm pages
  - country groups (`CountryPolicy::eu27()`)
  - the locale allowlist
  - Reply-To
  - the per-solve budget for PoW (`admit_proof`)
  - `protectedFetch` in the browser

## Security fixes

These bugs affect 0.4.0 and 0.4.1. Upgrade before you rotate storage keys or
use disable/enable in production.

- **Duplicate accounts during storage-key rotation.** First, a sign-up ran on a
  node with the new key. Then a login ran on a node that still used the old
  key. This created a second account for the same email. Sign-up now claims
  the email row under both keys. (`spec/tla/KeyRotation.tla`, finding ROT-F1.)
- **A re-enabled user could get an old session back** when host clocks
  disagree. `enable_user` now revokes every live session before it re-enables.
  (`spec/tla/Session.tla`, finding SES-F1.)
- **Concurrent admin actions were last-write-wins.** A delayed enable could
  undo a later disable and revive a session whose revocation failed. A disable
  now always writes and bumps the profile version. An enable is conditional on
  the version it read. An enable that loses a race returns
  `AdminError::Conflict`. (`spec/tla/AdminRace.tla`, finding ADM-F1.)
- **Keyed-lookup framing:** a NUL byte in a domain or prefix could make two
  distinct inputs frame identically. The library now refuses a NUL byte there.
- **A previous storage key equal to the current one** made every sign-up fail
  against DynamoDB. The cause was two writes to one item in a transaction. The
  library now ignores such a key. (0.5.0 development introduced and fixed this
  bug. 0.4 does not have it.)

## Changelog cleanup

Apply these changes to the generated 0.5.0 entry in the release PR. Do this as
the last step before merge, because release-please rewrites the PR on every
push to main.

1. Insert "Upgrade summary" and "Security fixes" from above under the 0.5.0
   heading.
2. In "Breaking changes", merge the two `set_user_disabled_audited` entries
   into one entry. The merged entry states these facts:
   - It takes `expected_version: Option<u64>` (`None` for a disable, `Some`
     for an enable).
   - `UserSummary` has `admin_version`.
   - `AdminError` has `Conflict`.
3. In "Breaking changes", find the secret-document entry. Replace
   "(pre-1.0, no deployments)" with "(pre-1.0, no migration tooling)".
4. In "Bug fixes", remove `classify sign-up cancellations…` (e5825e0). It fixed
   a regression that never shipped.
5. In "Bug fixes", merge a5aca66 and 9778517 into one line: "disables are
   unconditional and fence concurrent enables. Only enables are
   version-fenced".
6. In "Bug fixes", move `ignore a previous storage key equal to the current one`
   (7ac9a05) under "Security fixes". Mark it as 0.5.0-only.

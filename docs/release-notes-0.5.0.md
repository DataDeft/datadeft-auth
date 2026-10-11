# 0.5.0 release notes (for the release PR)

release-please generates the `CHANGELOG.md` entry from the commit messages.
Merge this text into it in the release PR: the upgrade summary and the
"Security fixes" section are not derivable from commits. The full consumer
checklist is "Upgrading from 0.4" in `docs/integration.md`; the plan is
`docs/plan-0.5.0.md`.

## Upgrade summary

0.5.0 is a breaking release. Upgrading means a **fresh auth table and a fresh
secret document**, and **every 0.4 session ends**: ids changed form, and the
session cookie body carries the session id. No migration tools are provided
(pre-1.0, no production deployments).

Consumer actions:

- Ids are `usr-`, `sid-`, `aid-`, `evt-`, `sess-` plus lowercase hex; update
  validators, fixtures and API schemas.
- Secret document: add `pow_challenge_secret_b64` and
  `pow_proof_cookie_root_b64`; rename `aws_storage_hmac_b64` to
  `storage_hmac_b64`; use a distinct value in every key field; keep `kid` at 12
  bytes or fewer. `AWSPREVIOUS` must be 0.5-shaped or unset.
- Cookie configs: `secure(..)` / `insecure_local(..)`; getter `is_secure()`.
- Email: drop app-side normalization; the library normalizes
  (`NormalizedEmail::normalize`); `parse` is `from_normalized`.
- `RateLimiter` implementations add `check_lifetime_limit`.
- `AuthAdminRepository::set_user_disabled_audited` takes the expected
  `admin_version`; handle `AdminError::Conflict`.
- `RequestMagicLinkOutcome` is `Sent` / `Throttled(..)`; count it.
- `MagicLinkEmail` and `MagicLinkRequestJson` gain `locale`;
  `MagicLinkServiceConfig` gains `country_policy` and `locales`, and
  `MagicLinkConfigError` gains `InvalidCountryPolicy`.
- `MagicLinkHttpError::Forbidden` is removed; `MagicLinkUnavailable` answers
  the generic `400` body. `reason()` labels are namespaced (`magic_link_*`,
  `session_*`, `pow_*`).
- Adopt the HTTP status contract (`docs/security.md`): `401` with
  `WWW-Authenticate: DD-PoW` (missing proof or used-up per-solve budget) or
  `DD-Session`, `400` for shape errors, one
  constant `503`, no library `403`/`500`. Alert on reason counts, not raw
  `5xx`; add a load-balancer health endpoint.
- Optional: the redirect landing mode for static confirm pages, country groups
  (`CountryPolicy::eu27()`), the locale allowlist, Reply-To, the per-solve PoW
  budget (`admit_proof`), and `protectedFetch` in the browser.

## Security fixes

These affect 0.4.0 and 0.4.1. Upgrade before rotating storage keys or using
disable/enable in production.

- **Duplicate accounts during storage-key rotation.** A sign-up on a node with
  the new key, followed by a login on a node still on the old key, created a
  second account for the same email. Sign-up now claims the email row under
  both keys. (`spec/tla/KeyRotation.tla`, finding ROT-F1.)
- **A re-enabled user could get an old session back** when host clocks
  disagree. `enable_user` now revokes every live session before it re-enables.
  (`spec/tla/Session.tla`, finding SES-F1.)
- **Concurrent admin actions were last-write-wins.** A delayed enable could
  undo a later disable and revive a session whose revocation failed. Admin
  writes are now conditional on the profile version; a lost race is
  `AdminError::Conflict`. (`spec/tla/AdminRace.tla`, finding ADM-F1.)
- **Keyed-lookup framing:** a NUL byte in a domain or prefix could make two
  distinct inputs frame identically; it is now refused.
- **A previous storage key equal to the current one** made every sign-up fail
  against DynamoDB (two writes to one item in a transaction). It is now
  ignored. (Introduced and fixed during 0.5.0 development; not in 0.4.)

## Changelog cleanup

- Drop the generated entry for `fix(aws): classify sign-up cancellations…`
  (e5825e0): it fixed a regression that never shipped.
- Move `fix(aws): ignore a previous storage key equal to the current one`
  under "Security fixes" above, noted as 0.5.0-only.

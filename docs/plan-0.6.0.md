# 0.6.0 plan (draft)

Status: draft. This plan lists the work for 0.6.0. 0.6.0 is a breaking
pre-1.0 release, like 0.5.0. Consumers test it through a git ref. The project
publishes no release candidates.

## 1. Scope

| Id | Item | Priority | Source |
| --- | --- | --- | --- |
| V06-001 | GDPR erasure (`erase_user`) | Must | CeleraTax #11, deferred from 0.5.0 |
| V06-002 | Optional `aud` claim in session and confirm cookies | Should | CeleraTax |
| V06-003 | Locale-keyed confirm pages in redirect landing mode | Should | CeleraTax |
| V06-004 | Finer internal reasons for landing and confirm failures | Should | CeleraTax |
| V06-005 | Docs: `Referrer-Policy` `strict-origin` compared with `no-referrer` | Should | CeleraTax |
| V06-006 | Reference log probe in the example | Should | CeleraTax (file pending) |
| V06-007 | Fuzzing past the MAC checks, and fuzzing in CI | Should | 0.5.0 review |
| V06-008 | Branch protection and CI publishing | Should | 0.5.0 release |
| V06-009 | Remove `remove_legacy_session_ttl` | Should | 0.5.0 docs audit |
| V06-010 | Decide on the `__Host-` prefix for the session cookie | Should | 0.5.0 docs audit |

## 2. Work items

### V06-001 GDPR erasure

Today, account deletion is `disable_user`. The normalized email stays stored,
and the same address can never sign up again.

Add an audited `erase_user` admin operation to the DynamoDB adapter and to the
fake. `spec/tla/Erasure.tla` and its mutants already check the design.

The atomic step does these things:

1. Remove the email lookup under every storage key, current and previous.
2. Replace the stored email with a non-deliverable placeholder.
3. Delete the pending magic links of the user.
4. Mark the user as erased. Validation rejects an erased owner at once.
5. Write an audit event that holds no personal data.

After the atomic step, a separate retry-safe step revokes every session.

Acceptance:

- The same email signs up again as a new user with a new user id.
- A repeated `erase_user` is safe and returns the same result.
- A link requested before the erasure never creates an account.
- Admin listings never show the erased email.
- Tests cover the fake, DynamoDB Local, and the model replay.
- `docs/security.md` "Retention" and `docs/formal-methods.md` (ERASE-INV-001
  to 005) say "implemented".

### V06-002 Optional `aud` claim

An app with more than one audience (for example an API and an admin site) can
bind a cookie to one audience. A cookie for one audience then fails on the
other.

- Add an optional audience to the session and confirm cookie bodies.
- Without a configured audience, the behavior stays as in 0.5.0.
- A configured audience is checked in constant time and fails closed.
- Tests: match, mismatch, missing, and a tamper test.

Open question: per-cookie audience string, or a keyring-level audience in the
HKDF info. The keyring-level form needs no new body field.

### V06-003 Locale-keyed confirm pages

In redirect landing mode, one configured page serves every link. Apps with
per-locale static pages (for example `/hu/login/confirm`) need one page per
locale.

- Map an allowlisted locale to a validated same-origin page.
- The landing chooses the page from the locale that the link was sent in, or
  from a fixed default.
- `Location` still carries no token material.

Open question: the landing has no locale today. The locale must come from the
link record (stored at request time) or from a query value that the app signs.

### V06-004 Finer internal reasons

`MagicLinkUnavailable` covers missing, expired, consumed, throttled and
wrong-verifier links. The public answer stays the same. Add an internal reason
for logs and metrics, like `RequestMagicLinkOutcome::Throttled(..)`.

- Add a typed reason to the landing, flow-state and confirm failures.
- Never send it. Tests prove that the public responses stay byte-identical.

### V06-005 Referrer-Policy docs

Explain the choice between `strict-origin` and `no-referrer` for the landing,
the confirm page and the static page. Keep the current defaults unless the
docs show a reason to change them.

### V06-006 Reference log probe

Add a log probe to `examples/axum-magic-link`. It sends a real token through
the router and searches every captured `tracing` line. It runs in its own
process. Use the CeleraTax probe as the base when the file arrives.

### V06-007 Fuzzing

- Generate valid cookies and challenges, then mutate fields, so that fuzzing
  reaches past the AEAD and HMAC checks.
- Add HTTP body and DynamoDB item decoding targets.
- Keep regression corpora in the repository.
- Run a short campaign in CI. Keep the long campaign manual.

### V06-008 Release operations

- Turn on branch protection for `main` with two approvals.
- Optional: enable CI publishing (trusted publishing on crates.io and npm,
  the `registry-release` environment, `REGISTRY_PUBLISH_ENABLED`). This
  removes the manual token step and adds npm provenance.

### V06-009 Remove `remove_legacy_session_ttl`

`DynamoDbAuthStore::remove_legacy_session_ttl` removes a `ttl` attribute that
old versions set on session rows. 0.5.0 needs a fresh table, so no such rows
exist. The "one supported way" rule says to remove compatibility paths.

- Remove the method and its tests from datadeft-magic-link-aws.
- This is a breaking API change. Name it in the changelog.

### V06-010 `__Host-` prefix for the session cookie

The `__Host-` prefix makes the browser refuse the cookie unless it is
`Secure`, has `Path=/` and has no `Domain`. A sibling subdomain then cannot
set or overwrite it. The session cookie meets these conditions. The confirm
cookie cannot use the prefix, because it needs a narrow path.

Open question: rename the session cookie to `__Host-dd_session` by default,
or offer the prefix as an option. A rename ends every live session once.
`insecure_local(..)` cannot use the prefix, because it is not `Secure`.

## 3. Candidates (take only when they fix a real problem)

These came from the 0.5.0 reviews. They are not planned work.

- `BatchGetItem` or bounded concurrency for admin session reads.
- Shared cookie building in datadeft-auth-token-core.
- One `RateLimiter::check_counter`.
- `ConstantTimeEq` for `LookupHmacKey`.
- A datadeft-pow-core test-support solver.
- One in-progress solve shared across `protectedFetch` calls.
- Country policies that are valid by construction.
- Kani proofs for expiry arithmetic and country difficulty monotonicity.

## 4. Out of scope

- Country-aware PoW difficulty (MVP-013). It needs a trusted country source
  first.

## 5. Release

1. Implement on `main`. Each item ships with tests and docs.
2. CeleraTax tests a git revision on core-dev.
3. Merge the release PR and publish (docs/releasing.md).

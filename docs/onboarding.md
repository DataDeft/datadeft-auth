# Onboarding

**Status:** Released as `v0.1.0` (2026-08-02). Bug fixes only from here.

## Can a customer use this today?

| Surface | Status | Customer action |
| --- | --- | --- |
| Magic-link core | Ready | Supply clock, CSPRNG, keyrings, repository, limiter, and outbox. |
| Axum helpers | Ready | Configure origin, redirects, cookies, body limits, and token-safe logs. |
| In-memory fakes | Ready for tests | Use `FakeDynamoDbAuthStore` and `FakeMagicLinkOutbox`. |
| DynamoDB and SES | Ready for test deployment | Provision table, IAM, TTL, encryption, SES identity, and live tests. |
| Session validation | Ready | Validate protected requests. Revoke server state on logout. |
| PoW Rust admission | Ready | Wire the `dd-pow-axum` challenge and validate glue into your routes. Build the browser path. |
| Browser PoW client | Ready | Serve the built worker and call `protect()` from your login page. |
| Country-aware PoW | Not ready | Build upstream policy. Never lower below the floor. |
| Example app | Ready | Start with `examples/axum-magic-link`. |
| Published crates | Tagged | Pin to the `v0.1.0` tag or a Git revision. crates.io publish deferred. |

Do not use fake secrets, fake clocks, or fake entropy in production.

To wire the libraries into your application, follow [integration.md](integration.md).

## Production checklist

A magic-link deployment can run in production after the app completes this list.

1. Use an OS CSPRNG.
2. Use separate production secrets for each purpose.
3. Configure active and verify-only keyrings.
4. Follow the retention rules in [security.md](security.md).
5. Provide app-owned email templates.
6. Use a token-safe email URL.
7. Implement the repository contract atomically.
8. Use the DynamoDB transaction shape for AWS.
9. Configure DynamoDB TTL, encryption, backups, and IAM.
10. Use strong reads for session and authentication records.
11. Confirm inline SES delivery fits your service level.
12. Use a durable outbox if inline delivery is not acceptable.
13. Configure exact same-origin confirmation.
14. Configure fixed or same-origin redirects.
15. Configure production-secure cookies.
16. Validate sessions on protected routes.
17. Scrub token-bearing request targets from logs.
18. Scrub cookies and confirmation values from logs.
19. Test replay, concurrent confirmation, rollback, and logout.
20. Test post-revocation visibility.
21. Follow the normalized-email storage controls in [security.md](security.md).
22. Run `mise run verify`.
23. Run the consuming app integration tests.
24. Pin an immutable commit or tag.

PoW is optional app admission. Complete the PoW backlog before you require PoW.

## Implementation backlog

| ID | Priority | Status | Work |
| --- | --- | --- | --- |
| MVP-001 | P0 | Done | Keep the fake-backed Axum example runnable. |
| MVP-002 | P0 | Per deployment | Attest token-safe logging. |
| MVP-003 | P0 | AWS users | Validate live DynamoDB behavior. |
| MVP-004 | P0 | Done | `v0.1.0` tag cut. Consume by the `v0.1.0` tag or a Git revision. crates.io publish deferred. |
| MVP-005 | P1 | Done | Trait futures require `+ Send`, static dispatch only (no `dyn`). |
| MVP-006 | P1 | Decided | Inline SES delivery accepted. Implement the `MagicLinkOutbox` trait against a durable queue only if a deployment needs it. |
| MVP-007 | P1 | Decided | Store the normalized email at rest, protected by DynamoDB KMS and IAM. No app-side field encryption. |
| MVP-010 | PoW | Done | `dd-protect-client` ships the worker and client, vector-tested against `dd-pow-core`. |
| MVP-011 | PoW | Ready | Wire the `dd-pow-axum` challenge and validate glue into routes. |
| MVP-012 | PoW | Done | Ship the `dd_pow` proof cookie (`dd-pow-core`, `dd-pow-axum`). Stateless, reusable within its TTL. |
| MVP-013 | PoW | Not ready | Define trusted country source and difficulty policy. |
| MVP-014 | P1 | Done | Keep session country as an opportunistic lock. |
| MVP-020 | Assurance | Done | TLA+ safety models gated in CI (`formal-spec` job, `mise run spec`). Fairness-based liveness needs a checker with `WF` support. |
| MVP-021 | Assurance | Future | Add simulation, fuzzing, and bounded checks. |

## PoW decisions

Define these values before you implement MVP-013 (country-aware PoW). The
shipped defaults already set the challenge lifetime (2 minutes), the
proof-cookie lifetime (3 hours), and stateless replay behavior. See the backlog
and [security.md](security.md).

1. Select the trusted country source.
2. Select behavior when country is absent.
3. Define country risk classes.
4. Set required difficulty for each class.
5. Decide when difficulty becomes fixed.
6. Define generic public errors.
7. Define challenge issuance controls.
8. Set browser performance targets.
9. Define accessibility fallback.

Use this minimum invariant.

```text
effective_difficulty >= production_floor
effective_difficulty >= configured_base_difficulty
country policy may increase difficulty
country policy must not decrease difficulty
```

## Integration order

1. Pin an immutable repository revision.
2. Wire service, Axum helpers, and fakes.
3. Start from `examples/axum-magic-link`.
4. Replace fakes with selected adapters.
5. Add session authentication.
6. Add server-side logout.
7. Complete logging checks.
8. Complete live storage checks.
9. Add independent PoW admission if required.
10. Run all integration and release checks.

See [architecture.md](architecture.md) for flows. See [formal-methods.md](formal-methods.md) for future assurance work.

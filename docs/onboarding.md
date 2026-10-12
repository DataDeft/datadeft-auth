# Onboarding

**Status:** pre-1.0. The latest version on crates.io and npm is `0.5.0`.

To integrate the libraries into your application, follow
[integration.md](integration.md) step by step. See
[architecture.md](architecture.md) for the flows and
[formal-methods.md](formal-methods.md) for future assurance work.

## Can a customer use this today?

| Surface | Status | Customer action |
| --- | --- | --- |
| Magic-link core | Ready | Supply a clock, a CSPRNG, keyrings, a repository, a limiter, and an outbox. |
| Axum helpers | Ready | Configure the origin, redirects, cookies, body limits, and token-safe logs. |
| In-memory fakes | Ready for tests | Use `FakeDynamoDbAuthStore` and `FakeMagicLinkOutbox`. |
| DynamoDB and SES | Ready for test deployment | Provision the table, IAM, TTL, encryption, SES identity, and live tests. |
| Session validation | Ready | Validate protected requests. Revoke server state on logout. |
| PoW Rust admission | Ready | Add the `datadeft-pow-axum` challenge and validate glue to your routes. Build the browser path. |
| Browser PoW client | Ready | Serve the built worker and call `protect()` from your login page. |
| Country-aware PoW | Not ready | Build an upstream policy. Never lower the difficulty below the floor. |
| Example app | Ready | Start with `examples/axum-magic-link`. |
| Published crates | Done | `0.5.0` is on crates.io and npm ([releasing.md](releasing.md)). |

Never use fake secrets, fake clocks, or fake entropy in production.

## Production checklist

A magic-link deployment is production-ready when the app completes this list.

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
11. Confirm that inline SES delivery fits your service level.
12. If inline delivery is not acceptable, use a durable outbox.
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
23. Run the integration tests of the consuming app.
24. Pin the crate version from crates.io and commit your lockfiles.

The library ships PoW admission. The project recommends it. Only
country-aware difficulty (MVP-013) is open.

## Implementation backlog

| ID | Priority | Status | Work |
| --- | --- | --- | --- |
| MVP-002 | P0 | Per deployment | Attest token-safe logging. |
| MVP-003 | P0 | AWS users | Validate live DynamoDB behavior. |
| MVP-006 | P1 | Decided | The project accepts inline SES delivery. Implement `MagicLinkOutbox` against a durable queue only if a deployment needs it. |
| MVP-007 | P1 | Decided | Store the normalized email at rest. DynamoDB KMS and IAM protect it. Do not add app-side field encryption. |
| MVP-013 | PoW | Not ready | Define the trusted country source and difficulty policy. |
| MVP-021 | Assurance | Future | Add simulation and bounded checks. Fuzz targets exist (`mise run fuzz`). |
| V06-001 | 0.6 | Planned | GDPR erasure (`erase_user`). The model is ready: `spec/tla/Erasure.tla`. |
| V06-002 | 0.6 | Planned | Optional `aud` claim in session and confirm cookies. |
| V06-003 | 0.6 | Planned | Locale-keyed confirm pages in redirect landing mode. |
| V06-004 | 0.6 | Planned | Finer internal reasons for landing and confirm failures (expired, consumed, throttled, wrong verifier). |
| V06-005 | 0.6 | Done | Docs: `Referrer-Policy` `strict-origin` compared with `no-referrer` ([security.md](security.md#magic-link-url-handling)). |
| V06-006 | 0.6 | Planned | Reference log probe in the example (CeleraTax offered theirs). |

## PoW decisions

Before you implement MVP-013 (country-aware PoW), decide these items. The
shipped defaults already set the challenge lifetime (2 minutes), the proof
cookie lifetime (3 hours), and the stateless replay behavior. See
[TTL baseline](security.md#ttl-baseline).

1. Select the trusted country source.
2. Select the behavior when the country is absent.
3. Define country risk classes.
4. Set the required difficulty for each class.
5. Decide when difficulty becomes fixed.
6. Define generic public errors.
7. Define challenge issuance controls.
8. Set browser performance targets.
9. Define an accessibility fallback.

Keep this minimum invariant:

```text
effective_difficulty >= production_floor
effective_difficulty >= configured_base_difficulty
country policy may increase difficulty
country policy must not decrease difficulty
```

# Datadeft auth documentation

## Start here

- [Integration](integration.md): wire the libraries into your application.
- [Architecture](architecture.md): current parts, flows, and limits.
- [Onboarding](onboarding.md): production checklist and backlog.
- [Security rules](security.md): required security behavior.
- [Formal assurance](formal-methods.md): planned model checks and fuzzing.

## Libraries

| Library | Purpose |
| --- | --- |
| `datadeft-pow-core` | Pure proof-of-work challenge mint and verify code. |
| `datadeft-auth-token-core` | Token, keyring, session, and cookie primitives. |
| `datadeft-magic-link-core` | Magic-link token and HMAC primitives. |
| `datadeft-magic-link-service` | Request, confirmation, session, and repository logic. |
| `datadeft-magic-link-axum` | Optional Axum HTTP helpers. |
| `datadeft-magic-link-aws` | Optional DynamoDB and SES adapters. |
| `dd-protect-client` | Browser PoW client. |

## Contributor documents

- [Rust standards](rust-standards.md)
- [Operating model](operating.md)

- [Registry release runbook](releasing.md)

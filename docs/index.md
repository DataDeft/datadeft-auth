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
| `dd-pow-core` | Pure proof-of-work challenge mint and verify code. |
| `dd-auth-token-core` | Token, keyring, session, and cookie primitives. |
| `dd-magic-link-core` | Magic-link token and HMAC primitives. |
| `dd-magic-link-service` | Request, confirmation, session, and repository logic. |
| `dd-magic-link-axum` | Optional Axum HTTP helpers. |
| `dd-magic-link-aws` | Optional DynamoDB and SES adapters. |
| `dd-protect-client` | Browser PoW client. |

## Contributor documents

- [Rust standards](rust-standards.md)
- [Operating model](operating.md)

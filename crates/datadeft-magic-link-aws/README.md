# datadeft-magic-link-aws

AWS adapters for
[`datadeft-magic-link-service`](https://crates.io/crates/datadeft-magic-link-service).

```toml
[dependencies]
datadeft-magic-link-aws = { version = "0.3", features = ["aws"] }
```

| Build | Provides |
| --- | --- |
| default | In-memory fakes for every service trait (`FakeDynamoDbAuthStore`, `FakeMagicLinkOutbox`). No AWS SDK. |
| `aws` feature | `DynamoDbAuthStore`, `SesMagicLinkOutbox`, and Secrets Manager loading via `resolve_auth_secrets`. |

Secrets come from AWS Secrets Manager. `AWSCURRENT` maps to the active key and
`AWSPREVIOUS` to verify-only for cookie keys. See "Rotation cadence" in the
security policy for which keys can rotate.

Row keys are HMACs of selectors, emails, and session IDs, and raw tokens are
never stored. The normalized email is stored as an attribute on user and
magic-link records so the application can send mail. Protect the table with
encryption at rest and least-privilege IAM.

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT.

# datadeft-magic-link-aws

AWS adapters for
[`datadeft-magic-link-service`](https://crates.io/crates/datadeft-magic-link-service).

```toml
[dependencies]
datadeft-magic-link-aws = { version = "0.4", features = ["aws"] }
```

| Build | Provides |
| --- | --- |
| default | In-memory fakes for every service trait (`FakeDynamoDbAuthStore`, `FakeMagicLinkOutbox`). No AWS SDK. |
| `aws` feature | `DynamoDbAuthStore`, `SesMagicLinkOutbox`, and Secrets Manager loading via `resolve_auth_secrets`. |

Secrets come from AWS Secrets Manager. `AWSCURRENT` is active and `AWSPREVIOUS`
is kept during rotation: cookie keys become verify-only, and the HMAC keys
serve as read fallback. Every key can rotate without logging users out or
splitting accounts; follow "Rotating the HMAC keys" in the security policy,
including `rekey_email_lookups` before dropping the previous secret.

`DynamoDbAuthStore` also implements the admin API (`AuthAdminRepository`).
Every admin mutation is one `TransactWriteItems` with its audit event; nothing
is deleted. IAM for the admin role needs `dynamodb:GetItem`, `Query`, `Scan`,
and `TransactWriteItems` on the table; `rekey_email_lookups` needs `Scan` and
`PutItem`.

Row keys are HMACs of selectors, emails, and session IDs, and raw tokens are
never stored. The normalized email is stored as an attribute on user and
magic-link records so the application can send mail. Protect the table with
encryption at rest and least-privilege IAM.

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT.

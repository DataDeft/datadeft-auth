# datadeft-magic-link-service

Framework-neutral magic-link login orchestration for the
[datadeft-auth](https://github.com/DataDeft/datadeft-auth/blob/main/README.md) libraries.

```toml
[dependencies]
datadeft-magic-link-service = "0.2"
```

It covers the magic-link request, the scanner-safe landing
(`begin_magic_link_landing`), explicit confirmation
(`confirm_magic_link_flow`), session validation, and revocation. Every
dependency is a trait: storage, rate limiting, users, sessions, the email
outbox, the clock, and randomness. Public errors are generic and
non-enumerating.

No Axum, Tokio, AWS SDK, filesystem, environment, network, or logging
dependency.

## Getting started

The usual setup adds two adapters:

- [`datadeft-magic-link-axum`](https://crates.io/crates/datadeft-magic-link-axum) for HTTP
  handlers. Its crate docs contain a compiling quickstart.
- [`datadeft-magic-link-aws`](https://crates.io/crates/datadeft-magic-link-aws) for
  DynamoDB and SES (`aws` feature). Its default build ships in-memory fakes for
  every trait.

To write a non-AWS backend, start from the trait contracts in `traits`,
especially the atomic-commit contract on `MagicLinkAuthenticationRepository`.
The full runnable integration is
[`examples/axum-magic-link`](https://github.com/DataDeft/datadeft-auth/blob/main/examples/axum-magic-link).

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT OR Apache-2.0.

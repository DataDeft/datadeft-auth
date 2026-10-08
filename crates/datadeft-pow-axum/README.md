# datadeft-pow-axum

Axum HTTP glue for the [`datadeft-pow-core`](https://crates.io/crates/datadeft-pow-core)
proof-of-work admission gate.

```toml
[dependencies]
datadeft-pow-axum = "0.3"
```

The crate is headless. It validates and mints, and returns structured values
and `Set-Cookie` headers. Your application owns the router, body limits,
`Content-Type`, and origin checks.

## Wiring

- `POST /…/pow/create` → `mint_pow_challenge`, then serialize the
  `PowChallengeResponse` as JSON.
- `POST /…/pow/validate` → deserialize a `PowSolutionRequest`, call
  `verify_pow_solution`, and on success append `PowAdmission::set_cookie`.
  Map `PowFlowError::Rejected` to `403` and `PowFlowError::Internal` to
  `500`.
- Record `PowAdmission::mint_to_verify_ms` in your metrics. Count `None`
  separately.

The browser side is the npm package
[`@datadeft/protect-client`](https://www.npmjs.com/package/@datadeft/protect-client).

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT OR Apache-2.0.

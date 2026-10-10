# datadeft-pow-axum

Axum HTTP glue for the [`datadeft-pow-core`](https://crates.io/crates/datadeft-pow-core)
proof-of-work admission gate.

```toml
[dependencies]
datadeft-pow-axum = "0.5"
```

The crate is headless. It validates and mints, and returns structured values
and `Set-Cookie` headers. Your application owns the router, body limits,
`Content-Type`, and origin checks.

## Wiring

- `POST /…/pow/create` → `mint_pow_challenge`, then serialize the
  `PowChallengeResponse` as JSON.
- `POST /…/pow/validate` → deserialize a `PowSolutionRequest`, call
  `verify_pow_solution`, and on success append `PowAdmission::set_cookie`.
  On failure return the `PowFlowError`: it renders `401` +
  `WWW-Authenticate: DD-PoW` for a rejected solution and the constant `503`
  for a fault.
- Every gated route → `admit_proof` with a `ProofBudget` over a shared
  counter: it verifies the `dd_pow` cookie and spends one unit of its solve's
  budget. Return the `ProofRejection` on failure: `401` + `DD-PoW` without a
  usable proof, the constant `503` once the budget is spent.
- Record `PowAdmission::mint_to_verify_ms` in your metrics. Count `None`
  separately.

The browser side is the npm package
[`@datadeft/protect-client`](https://www.npmjs.com/package/@datadeft/protect-client).

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT.

# datadeft_auth — Elixir 0.8 implementation in progress

Native Elixir server implementation of datadeft-auth, compatible with Rust 0.7.
This package is incomplete and is not ready for authentication or production use.
The repository version stays aligned at 0.7.0 until the 0.8 release is prepared.

## Development

```sh
mise -C hex/datadeft_auth run verify
```

Implemented slices: Rust-compatible email identity, keyed account lookup through
DynamoDB profiles, storage-HMAC keying, fixed-window limits and shared lifetime
PoW budgets. Authentication commits, cookies, HTTP integration and production
AWS IO are not implemented yet. See [the checklist](IMPLEMENTATION.md).

Production has no Hex dependencies, Rust components or application processes.
Only OTP's standard crypto application is started. Tests use Jason for DynamoDB
JSON and OTP's HTTP client against a disposable loopback-only DynamoDB Local.
The production DynamoDB IO boundary is injected, not implicitly configured.

Compatibility fixtures live in `spec/compatibility/`; repository-level parity
checks use the Rust reference. Package-local tests must also work without those
repository fixtures. See `docs/elixir-0.8-plan.md` for scope and approval.

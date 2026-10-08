# datadeft-magic-link-core

IO-free magic-link primitives for the [datadeft-auth](https://github.com/DataDeft/datadeft-auth/blob/main/README.md) libraries.

```toml
[dependencies]
datadeft-magic-link-core = "0.3"
```

- Token grammar: independent CSPRNG selector and verifier, parsing,
  generation, and redacted `Debug`.
- `NormalizedEmail`: a validated, exact-match email boundary. No provider
  alias rules.
- Keyed HMAC lookup and verifier-hash helpers. Storage holds only keyed lookup
  material, never raw token parts or raw emails.
- The scanner-safe confirmation cookie, which binds selector, verifier proof,
  account, expiry, and an independent confirmation nonce.

The crate receives entropy and key material as inputs and never reads the
clock, environment, filesystem, network, or OS RNG.

Most applications use
[`datadeft-magic-link-service`](https://crates.io/crates/datadeft-magic-link-service),
which re-exports the types they need.

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT OR Apache-2.0.

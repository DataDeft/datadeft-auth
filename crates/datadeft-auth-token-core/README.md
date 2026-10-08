# datadeft-auth-token-core

Low-level token, keyring, and cookie primitives for the
[datadeft-auth](https://github.com/DataDeft/datadeft-auth/blob/main/README.md) libraries. IO-free and deterministic.

```toml
[dependencies]
datadeft-auth-token-core = "0.3"
```

- `base62`: radix-62 encoding with canonicality checks.
- `branca`: Branca-compatible XChaCha20-Poly1305 tokens with caller-injected
  entropy and canonical decoding.
- `keyring`: root secrets, HKDF-SHA256 purpose/`kid` derivation, typed
  keyrings, active and verify-only rotation windows, redacted and zeroized key
  material.
- `cookie`: `v1.{kid}.{token}` cookie wrappers with `typ`/`kid` binding
  inside the encrypted payload and mandatory idle and absolute freshness checks.
- `TokenError`: typed errors that never carry token bytes or key material.

Most applications use this crate indirectly through
[`datadeft-magic-link-service`](https://crates.io/crates/datadeft-magic-link-service) or
[`datadeft-pow-core`](https://crates.io/crates/datadeft-pow-core).

## Determinism

The crate never reads the clock, environment, filesystem, network, or an RNG on
its own. Callers pass `now_unix`, TTLs, loaded keyrings, and a
`rand_core::CryptoRng`. Production callers must pass an OS-backed CSPRNG.

## The `test-support` feature

`test-support` exposes fixed-nonce Branca encoding and deterministic RNG
fixtures. **Never enable it outside `[dev-dependencies]`.** A fixed nonce
reuses `(key, nonce)` pairs and breaks the encryption. The repository CI
rejects any crate that enables it as a normal dependency.

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT OR Apache-2.0.

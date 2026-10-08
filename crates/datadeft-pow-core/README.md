# datadeft-pow-core

Pure, IO-free proof-of-work challenge mint and verify, plus the encrypted
`dd_pow` proof cookie that records a successful solve. Part of the
[datadeft-auth](https://github.com/DataDeft/datadeft-auth/blob/main/README.md) libraries.

```toml
[dependencies]
datadeft-pow-core = "0.3"
```

The browser solver is the npm package
[`@datadeft/protect-client`](https://www.npmjs.com/package/@datadeft/protect-client).

```rust,ignore
use datadeft_pow_core::{PowSecret, UnixMillis, mint_challenge, verify_solution};

let secret = PowSecret::new(secret_bytes); // 32 bytes, loaded from your secret store
let challenge = mint_challenge(&secret, 5, UnixMillis::from_millis(now_ms), entropy)?;
// ... send challenge JSON, receive the client's Solution ...
let verified = verify_solution(&secret, &solution, UnixMillis::from_millis(now_ms), 120, 5)?;
// verified.tid: replay-safe identity; verified.mint_to_verify_ms: solve timing
```

## Notes

- The caller injects the clock, entropy, difficulty, max age, and secret. The
  crate never logs, reads the clock, or generates randomness.
- Difficulty 1–3 is for tests only. Production usually starts at 5–6 leading
  zero hex characters (about 1–3 s in a browser).
- `Verified::mint_to_verify_ms` is a soft solve-timing signal. It is `None`
  when the verifying clock is behind the minting clock. See "Solve-timing
  signal" in the security policy before acting on it.

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT.

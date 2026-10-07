# Migrate consumers to registry packages

Apply this to CeleraTax and Panzerotti **after the first registry release is
published**. The release-preparation PR does not modify either consumer repo.

## Rust names and imports

| Previous crate | Registry crate | Rust import prefix |
| --- | --- | --- |
| `dd-auth-token-core` | `datadeft-auth-token-core` | `datadeft_auth_token_core` |
| `dd-pow-core` | `datadeft-pow-core` | `datadeft_pow_core` |
| `dd-pow-axum` | `datadeft-pow-axum` | `datadeft_pow_axum` |
| `dd-magic-link-core` | `datadeft-magic-link-core` | `datadeft_magic_link_core` |
| `dd-magic-link-service` | `datadeft-magic-link-service` | `datadeft_magic_link_service` |
| `dd-magic-link-axum` | `datadeft-magic-link-axum` | `datadeft_magic_link_axum` |
| `dd-magic-link-aws` | `datadeft-magic-link-aws` | `datadeft_magic_link_aws` |

Replace git/tag/revision and vendored path dependencies with registry versions:

```toml
[dependencies]
datadeft-pow-core = "0.2"
```

Use the same version range for the other crates you need. Update Rust imports,
feature references, and `cargo -p` commands. Regenerate and commit Cargo.lock.
Remove authentication setup that existed solely to fetch this private git
repository. The minimum supported Rust version is 1.88; update CI as needed.

No compatibility aliases are introduced. Cookie names (`dd_pow`, `dd_session`,
`dd_auth_confirm`), HMAC/HKDF domains, stored keys, and wire formats remain the
same. Renaming packages does not require deleting sessions or migrating data.
For pre-0.2 consumers, also apply [migration-v0.2.0.md](migration-v0.2.0.md),
substituting the new crate names when following its historical examples.

## Browser client

```sh
bun add @datadeft/protect-client
```

Replace vendored imports with `import { protect } from
"@datadeft/protect-client"`. Remove vendored copies of the client and worker,
and commit Bun's updated lockfile. The package ships compiled ES modules and
declarations, and has no runtime or peer dependencies or install hooks.

Bundle a worker entry containing `import "@datadeft/protect-client/worker"`
into your application's served static assets. Pass its resulting same-origin
URL as `workerUrl` to `protect`. The client starts a **module** worker, so retain
module-compatible response MIME/CSP and bundler settings. Do not put the worker
entry into the main page bundle. See the
[client README](../packages/dd-protect-client/README.md) for a complete example.

## CeleraTax clock skew (NFR-SEC-012)

Default calls still permit 60 seconds. Opt into 30 seconds explicitly:

```rust,ignore
let verified = datadeft_pow_core::verify_solution_with_clock_skew(
    &secret, &solution, now, 120, minimum_difficulty, 30,
)?;
let proof = datadeft_pow_core::verify_pow_proof_cookie_with_clock_skew(
    cookie, &keyring, now_unix, proof_ttl_secs, 30,
)?;
```

Axum challenge callers use
`PowPolicy::new(difficulty, 120)?.with_clock_skew_secs(30)`. Set the proof-cookie
verification bound separately as shown above. Low-level token consumers can
use `mint_bound_cookie_with_clock_skew` and
`parse_bound_cookie_with_clock_skew`, each with a final seconds argument.
Magic-link service wrappers keep their existing 60-second default.

The bound only permits a future timestamp; it does not extend TTL. Zero is
supported. Thirty seconds is accepted exactly, and the next millisecond is
rejected for PoW challenges (cookie timestamps have whole-second precision).

## Consumer acceptance checks

Run each application's full CI without datadeft-auth git credentials. Test
worker asset loading under production CSP, solve/create/validate flows,
30-second boundaries, cookie validation and logout, and magic-link confirmation
where used. Keep consumer changes in their own reviewed PRs.

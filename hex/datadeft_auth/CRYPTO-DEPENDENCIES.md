# Crypto reuse: approved tiny Rust NIF

Owner approval: implementation conversation, "approved, keep it extremely small
and lean". Supersedes the no-Rust/native-dependency requirement and the earlier
unapproved b3/JOSE proposal. Services, storage, HTTP and IO integrations stay in
Elixir. Do not restore the Port or introduce a generic Rust service bridge.

## Six-question justification

1. Problem: Elixir cookies and PoW must match the existing Rust 0.7.0 crypto
   exactly, without maintaining another cipher/hash implementation.
2. Existing support: the Rust token and PoW core crates already implement the
   required formats, checks and cryptography.
3. Gap: OTP does not directly supply XChaCha20-Poly1305 or BLAKE3. BEAM packages
   would add another implementation to review and keep compatible. Doing nothing
   leaves the authentication package incomplete.
4. Smallest solution: Rustler glue calling existing core functions only. Add
   operations as needed, not a generic crypto facade. First slice: Branca encode
   and decode. No resources, native key store, callbacks, processes, solver,
   async runtime, AWS SDK or new authentication implementation.
5. Cost: Rustler dependency, source-build Rust toolchain and native artifact
   release/platform maintenance. A native fault can crash BEAM; Rustler is not
   process isolation. BEAM copies cannot promise zeroization. Existing native
   core buffers retain their own best-effort zeroization behavior.
6. Proof: existing Rust fixed-input vectors through the boundary, round trips,
   malformed/tampered/noncanonical/wrong-key inputs, independent CSPRNG nonces,
   explicit input limits, dependency/API guards, source builds and full verify.
   Clean Hex-archive consumers, precompiled artifacts and the platform matrix
   remain acceptance gates before release, not assumptions of this first slice.

## Boundary and safety contract

- Native source: `native/datadeft_auth_nif/`; an unpublished workspace member.
- Use the existing token core's production `branca::encode` / `branca::decode`.
  Never enable `test-support` in the production dependency or expose fixed-nonce
  minting. Native encode supplies OsRng; timestamp is an explicit u32 input.
- Exactly two initial calls: encode returns a token binary; decode returns
  `{timestamp, nonce, plaintext}`. Decode authenticates but intentionally does
  not establish expiry, purpose, account or session validity. Higher cookie/core
  APIs must impose those checks before any authentication use.
- Key: exactly 32 bytes. Plaintext: at most 1024 bytes. Token: at most 1437 bytes,
  matching the existing core caps. Check before copying or core work.
- Both calls run on dirty CPU schedulers. No unbounded input, solving loop,
  network, clock, environment reads, logging or application callbacks. The only
  IO is the OS entropy draw for encode, outside the deterministic core.
- Decode arguments explicitly and return fixed error atoms; do not stringify
  Rust/provider errors, keys, tokens or plaintext. Allocation failure fails closed.
- No project-authored unsafe code. Rustler owns the established FFI machinery;
  core crates retain their existing unsafe prohibition. No panic/unwrap/expect
  in adapter production code. This does not guarantee native crash containment.
- Borrow input binaries; do not retain them or introduce shared native state.
  Return explicit binary copies only where the caller needs the result. Do not
  claim deterministic zeroization in BEAM or for all intermediate native copies.
- Fail closed on NIF load failure. No silent BEAM crypto/algorithm fallback.

## Build and release

The first slice builds from the repository with Rustler and the pinned workspace
Rust toolchain, reusing local core path dependencies. No artifact is published by
this work. Before release, produce checksummed precompiled artifacts for the
supported targets and test clean source-archive/source-build fallback consumers.
Do not publish an archive with broken repository-relative path dependencies.
The initial local build is not proof of a working Hex distribution or of Linux
minimum-runtime compatibility. Native artifact downloads and cross-compilation
infrastructure are deliberately deferred until this bounded source slice passes.

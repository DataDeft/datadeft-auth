# Crypto dependency decision — approval requested

Status: investigation only. No proposed dependency has been added to mix.exs.
The approved 0.8 plan separately gates crypto dependency selection.

## Proposed choice

- `b3 == 0.2.1`: pure Elixir BLAKE3, Apache-2.0, no runtime dependencies.
- `jose == 1.11.13`, `runtime: false`: use only its exported, deterministic
  `jose_jwa_xchacha20:subkey_and_nonce/2` path, which calls the pure Erlang
  HChaCha20 implementation. Use OTP `:crypto` for ChaCha20-Poly1305 itself.
  MIT, no runtime dependencies. Do not start JOSE, use its global algorithm
  selection, or enable optional native backends.
- Continue using OTP for HMAC/SHA-256, HKDF's HMAC operations, CSPRNG and
  constant-time secret-derived comparisons.

This preserves the exact Rust algorithms without project-authored cipher code,
Rust, Rustler, libsodium or custom NIFs. These candidates are not yet certified
for this project: approval authorizes a bounded parity implementation and tests,
not production readiness or a security-review waiver.

## Six questions

1. Problem: mixed Rust/Elixir servers need byte-identical BLAKE3 PoW computations and
   XChaCha20-Poly1305 cookies; OTP does not expose these directly.
2. Existing support: Rust already supplies both. OTP supplies the underlying
   ChaCha20-Poly1305 but not XChaCha's subkey derivation. The inspected Hex
   releases provide the missing BEAM implementations.
3. Gap: switching hashes or AEAD would break parity. A Rust wrapper would add
   native build/deployment work before it has been shown necessary.
4. Smallest solution: two pinned BEAM dependencies, behind internal wrappers,
   with Rust vectors and bidirectional interoperability checks. No generic crypto
   facade, extra processes, alternate wire formats or fallback algorithms.
5. Cost: review and maintain two dependencies; JOSE is broader than the tiny API
   we need and the low-level exported API must be pinned/tested. BEAM arithmetic,
   memory handling and GC do not promise native constant-time execution or
   deterministic zeroization. Secret-derived equality still uses OTP hash_equals.
   Validate Elixir 1.16 / OTP 26 before accepting either dependency. Keep keys out
   of errors, telemetry and Inspect, including dependency failures.
6. Proof: official HChaCha/BLAKE3 vectors, Rust Branca and HKDF vectors, exact
   fixed-input cookie bytes, Rust-to-Elixir and Elixir-to-Rust verification,
   tamper/canonicality/expiry/rotation tests and clean no-Rust consumer builds.
   Independent security review remains a merge gate.

## Alternatives investigated

- `blake3 1.0.2`: Rust binding; not needed if pure B3 passes parity/review.
- `branca 0.3.0`: depends on native libsalty2; adds a native build and older stack.
- `branca_erl 0.3.0`: pins enacl 1.1.1, also native.
- `kryptos 1.6.0`: offers XChaCha over OTP but requires OTP 27 and adds a Gleam
  build/dependency surface, conflicting with the current OTP 26 floor.
- `chacha20 1.0.4`: pure Elixir but no complete XChaCha AEAD; its undocumented
  round helpers would leave more security implementation to this project.
- Hand-written HChaCha/BLAKE3: unnecessary new cipher/hash maintenance.
- Tiny wrapper over existing Rust libraries: reconsider only if the BEAM choices
  fail compatibility, runtime-floor or security review; requires separate scope
  approval for transport/scheduler/build/safety implications.

Investigation used published Hex metadata and release source archives. Candidate
source was inspected under ignored `_build/research/`; none is vendored or used
by the production package.

Approval: pending owner decision in the implementation conversation.

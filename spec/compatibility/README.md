# Rust / Elixir compatibility contract

Reference: Rust 0.7.0. All fixture inputs are synthetic public test material,
never credentials or production/customer data.

Run `mise run compatibility-test` from the repository root. It requires Rust and
Elixir, but the Elixir library itself does not require Rust.

## Vectors

UTF-8 TSV with a comment header, one case per line. Binary and string inputs use
lowercase hexadecimal so whitespace and NUL cannot be lost in parsing.

- `vectors/storage_hmac.tsv`: 32-byte synthetic key, prefix, UTF-8 input,
  expected prefixed HMAC. Pins the AWS storage domain and exact framing.
- `vectors/email.tsv`: UTF-8 input, normalized UTF-8 output (or `-` for
  rejection), and whether the original input is valid as already-normalized
  storage data. Includes Rust's Unicode White_Space trim set and length edges.

Both implementations must assert these outputs, not just load the fixtures.
The first storage cases reproduce the existing Rust pins. Additional cases are
independently computed fixtures verified against the existing Rust implementation.
The old-style session-id string in one pin tests HMAC framing only; it is not an
accepted current session identifier.

## Parity checklist

- [ ] All public Rust workflows inventoried.
- [x] Storage HMAC and lifetime-counter keys.
- [x] Email normalization.
- [x] Elixir resolves the same account/profile created by Rust.
- [ ] Elixir account creation and cross-language identity contention.
- [ ] Exact DynamoDB record attributes and strict decoding.
- [ ] Mixed-language account creation and atomic consume races.
- [ ] Shared session lookup, revocation and administration.
- [x] Shared fixed-window limits and lifetime counters, including a cross-language race.
- [ ] Full PoW proof/admission policy over the shared counters.
- [ ] Rotation, email rekeying and rolling deployment.
- [ ] Magic-link grammar and lookup HMACs.
- [ ] Branca/Base62, cookie framing and key derivation.
- [ ] PoW challenge/proof/browser interoperability.
- [ ] Locale and country policy.
- [ ] HTTP parsing, cookie policy, CSRF and refusal behavior.

Unit/vector checks do not establish shared-table transaction correctness. Do not
mark storage interoperability complete until DynamoDB Local race tests pass.

# Rust / Elixir compatibility contract

Reference: Rust 0.7.0. All fixture inputs are synthetic public test material,
never credentials or production/customer data.

Run `mise run compatibility-test` from the repository root. It requires Rust and
Elixir. Package source builds now require Rust for the owner-approved tiny
crypto NIF. No Rust executable or compiler is needed in a bundled Mix release;
precompiled Hex consumer builds remain a release gate.

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
- [x] Rust reads Elixir-created accounts and sessions.
- [x] Exact challenge/profile attributes and strict decoding.
- [x] Mixed-language atomic consume/create race on one challenge.
- [x] Distinct-challenge account creation race in Elixir.
- [ ] Distinct-challenge cross-language identity contention; remaining record codecs.
- [ ] Shared session lookup, revocation and administration.
- [x] Shared fixed-window limits and lifetime counters, including a cross-language race.
- [ ] Full PoW proof/admission policy over the shared counters.
- [x] Previous-key account lookup, conditional migration and paginated email rekeying.
- [ ] Full keyring rotation and rolling-deployment flows.
- [x] Magic-link grammar and lookup HMACs.
- [ ] Branca/Base62, cookie framing and key derivation.
- [ ] PoW challenge/proof/browser interoperability.
- [ ] Locale and country policy.
- [ ] HTTP parsing, cookie policy, CSRF and refusal behavior.

## Storage key distinctions

Do not confuse the authoritative `USERID#<user id> / PROFILE` with the email
lookup `USER#emh_<digest> / PROFILE` or the audit index
`USER#<user id> / SESSION#<created timestamp>#sih_<digest>`. Session records live
at `SESSION#sih_<digest> / SESSION`. Session/profile/index rows have no cleanup
TTL. Challenge rows use `ML#mlh_<digest> / CHALLENGE`, contain keyed verifier
material only and retain the Rust expiry-plus-cleanup-grace TTL.

The mixed test calls existing Rust repository/service APIs; it does not carry a
parallel Rust implementation. A shared start barrier races transaction admission
and lifetime counters, and Rust validates Elixir-written account/session rows.

Unit/vector checks do not establish shared-table transaction correctness. Do not
mark storage interoperability complete until DynamoDB Local race tests pass.

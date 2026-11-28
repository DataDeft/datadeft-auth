# Live session persistence parity

Owner approval: “ok please proceed with all”, following the explicit plan for
session reads, owner-status checks, revocation and cross-language tests.

1. **Problem:** an authentic cookie must not authorize an expired or revoked
   session, or a disabled or re-enabled account's pre-enable session.
2. **Existing support:** Rust `SessionRepository` and DynamoDB adapter define
   validity, key rotation, the owner watermark, and revocation conditions.
3. **Gap:** Elixir can write sessions atomically but cannot yet read or revoke
   them through the same contract. Cookie verification alone is insufficient.
4. **Smallest solution:** three adapter calls, reusing existing key derivation,
   consistent reads and strict item decoding. No NIF or schema change.
5. **Cost:** session and owner reads on validation, one conditional revocation
   write, and bounded previous-key fallback. Storage outages must fail closed.
6. **Proof:** strict shape/failure tests, inclusive expiry and watermark tests,
   and Rust/Elixir reads and revocation of each other's sessions in DynamoDB Local.

# Purpose-bound cookie parity

Owner approval: the implementation conversation, “ok please proceed with all”,
after the next slice was explicitly scoped to HKDF purpose/key-ID separation,
confirm/session cookies, expiry, skew, rotation and Rust↔Elixir checks. This is
part of [PR #45](https://github.com/DataDeft/datadeft-auth/pull/45).

1. **Problem:** Elixir must read Rust-issued cookies and vice versa without
   authorizing stale state or accepting a cookie for the wrong purpose.
2. **Existing support:** Rust token core already defines the bound envelope,
   HKDF info and key windows. Rust magic-link core/service define the bodies.
   The two-call Rustler boundary already provides exact Branca AEAD.
3. **Gap:** Branca alone does not bind purpose or key ID, enforce freshness, or
   validate session/confirmation state. It is not sufficient for login.
4. **Smallest solution:** keep the two native calls unchanged; use OTP HMAC for
   the single-block HKDF and Elixir binary patterns for the exact Rust framing.
   No new formats, dependencies, global key state or native operations.
5. **Cost:** the thin Elixir framing and policy need parity tests and review;
   keys and plaintext reside in BEAM memory without a zeroization guarantee.
   Cookie validation still does not authorize access without service/storage
   checks. No storage migration.
6. **Proof:** pinned Rust HKDF and cookie goldens; inspect newly minted bytes
   through the existing Rust decoder; test cross-purpose/key-ID rejection,
   key rotation, exact freshness edges, malformed inputs and confirmation binding.
   Run full workspace verification before pushing.

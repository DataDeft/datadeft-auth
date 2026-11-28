# Framework-neutral session service parity

Owner approval: “ok please proceed with all”, following the explicit plan to
complete live session validation, refresh/logout and country policy in #45.

1. **Problem:** login cookies need a server-side admission check, an explicit
   sliding refresh, and a logout path that can revoke idle-expired copies.
2. **Existing support:** Rust service semantics, compatible Elixir cookie codec,
   and an Elixir session repository sharing the Rust table.
3. **Gap:** applications cannot safely authorize from cookie verification alone;
   duplicating this policy in HTTP handlers would risk inconsistencies.
4. **Smallest solution:** framework-neutral service with an injected repository
   and clock, exact/grouped trusted-edge country pinning, and separate normal
   and logout validation results. No native calls beyond existing Branca.
5. **Cost:** two repository reads per validation, redacted state to anchor
   same-request refresh, and explicit freshness/rotation policy. App/HTTP owns
   trusted edge headers, CSRF, and cookie clearing only after revocation.
6. **Proof:** parity tests for country pinning, clock/age boundaries, inactive
   owners, dependency failures, original-issue retention and logout/refresh
   separation. Run full workspace verification.

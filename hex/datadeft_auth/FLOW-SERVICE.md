# Scanner-safe magic-link flow service parity

Scope: the project owner approved completing the scanner-safe 0.8 flow and
session services in draft #45.

1. **Problem:** an Elixir app must allow email scanners to open links without
   signing in, and require an explicit confirmation for the displayed account.
2. **Existing support:** Rust's canonical flow, Elixir confirm/session codecs,
   keyed reads, and shared atomic challenge/account/session commits.
3. **Gap:** the codecs and repository alone do not check the live state,
   enforce nonce/account proof, or retain the same plan on ambiguous commits.
4. **Smallest solution:** a framework-neutral landing/read/confirm service with
   Rust's limiter and rotation policy, a masked account default, and bounded
   commit replay/replanning. HTTP origin, framing and cookies remain adapter
   responsibilities; no native, storage format or HTTP changes in this slice.
5. **Cost:** reads and limiter accounting on GET; a successful confirmation
   additionally reads the owner and commits a transaction. Failure reasons
   are internal only, and an ambiguous outcome can leave a session with no
   returned cookie. Old lookup keys support landing during rotation, not
   grandfathering already-minted confirmation cookies.
6. **Proof:** test no GET writes, proof/account/consent/expiry rejection,
   conditional-only replan versus identical ambiguous replay, country policy,
   and actual request-to-logout on DynamoDB Local.

# Magic-link request service parity

Scope: the owner approved completing the agreed 0.8 authentication services
in draft #45; this slice is limited to the Rust request path.

1. **Problem:** an Elixir app needs to initiate login without translating bearer,
   consent, or keyed limiter policy in its handler.
2. **Existing support:** Rust `MagicLinkRequestService`, Elixir token and lookup
   primitives, and Elixir DynamoDB challenge/limiter operations.
3. **Gap:** these operations do not establish ordering or send a delivery
   request. Leaving that to each app risks sending an unpersisted token or
   applying different quotas during a mixed deployment.
4. **Smallest solution:** one framework-neutral request service with injected
   clock/repository/limiter/outbox, Rust limiter names/defaults and bounded
   locale allowlist. The email renderer and public HTTP contract stay outside.
5. **Cost:** four limiter calls per request (independent and concurrent); all
   quotas are charged even on denial. No new dependencies, storage shapes, or
   native calls. An outbox failure can leave an unused expiring challenge.
6. **Proof:** assert exact limiter keys/defaults/all-bucket charging, error
   precedence, no writes on denial, persist-before-delivery, exact consent,
   locale selection and redaction, and exercise the request on DynamoDB Local.

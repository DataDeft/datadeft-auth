# Software architecture

**Status:** Current implementation. This document describes what exists in the repository today and labels planned work explicitly.

The repository provides reusable authentication libraries. A consuming application owns its router, deployment policy, secrets loading, email templates, observability, and any upstream proof-of-work (PoW) admission.

![Components and infrastructure](diagrams/components-infrastructure.svg)

## Components

| Component | Responsibility | Status |
| --- | --- | --- |
| `dd-pow-core` | Pure challenge minting and solution verification | Implemented and tested |
| `dd-auth-token-core` | XChaCha20-Poly1305 token/cookie primitives and purpose-separated keyrings | Implemented and tested |
| `dd-magic-link-core` | Magic-link token grammar, email validation, HMAC lookup/verifier primitives | Implemented and tested |
| `dd-magic-link-service` | Request, scanner-safe confirmation, atomic authentication, session validation/revocation | Implemented and tested |
| `dd-magic-link-axum` | Bounded HTTP parsing, same-origin confirmation, cookie and response helpers | Implemented and tested |
| `dd-magic-link-aws` | DynamoDB, SES, and faithful in-memory adapters | Implemented; live AWS validation remains deployment work |
| Consuming application | Routes, trusted edge metadata, PoW admission, secrets, templates, logging, deployment | Required integration |
| `dd-protect-client` | Browser PoW solver | **Planned; skeleton only** |
| Example application | End-to-end integration reference | **Available** — [`examples/axum-magic-link`](../examples/axum-magic-link/src/main.rs): request, landing, confirmation, session, logout on the shipped in-memory fakes |

Dependency direction is intentionally one-way:

```text
dd-auth-token-core      -> (no workspace crates)
dd-magic-link-core     -> dd-auth-token-core
dd-magic-link-service  -> dd-magic-link-core, dd-auth-token-core
dd-magic-link-axum     -> dd-magic-link-service
dd-magic-link-aws      -> dd-magic-link-service

consuming application  -> adapters and services it selects
PoW admission          -> dd-pow-core (independent of magic-link)
```

## Magic-link protocol

![Magic-link sequence](diagrams/magic-link-sequence.svg)

1. The request service validates consent and the normalized email, applies keyed-email request/outbox limits, creates independent 128-bit selector and 256-bit verifier values, stores only keyed material, and sends the bearer link through the application outbox.
2. `GET` landing parses the token, applies a keyed-selector limit, performs a strongly consistent read and constant-time verifier comparison (dummy work on miss), and mints a five-minute encrypted flow cookie.
3. Flow state authenticates the selector, verifier proof, exact account, expiry, and an independent confirmation nonce. `GET` does not consume the challenge or create a session.
4. The page identifies the account and submits an explicit same-origin `POST` containing only the confirmation value. The raw token is not rendered into HTML.
5. Confirmation revalidates flow state and repository state, then executes one atomic authentication commit. DynamoDB uses a fixed five-action transaction to consume the challenge and create/update user and session records without partial authentication.
6. The browser receives the encrypted session-cookie value and a fixed, same-origin `303` redirect. Session validation checks both cookie freshness and strongly consistent server-side state; logout/revocation updates server state before cookie clearing.

The security rules and required deployment behavior are normative in [security.md](security.md).

## PoW protocol and country policy

![PoW sequence](diagrams/pow-sequence.svg)

### Implemented now

`dd-pow-core` is deterministic and IO-free. It can:

- mint a challenge from a server secret, difficulty, RFC3339 time, and 128 bits of caller-supplied entropy;
- authenticate `(domain, challenge, difficulty, time)` with HMAC-SHA-256;
- verify freshness, the current minimum difficulty, and SHA-256 work;
- return a stable, non-secret replay identifier (`tid`) for an upstream replay store.

### Target architecture — not implemented in this repository

The consuming application or edge will own country-aware PoW admission. Country may increase required work and must never decrease it:

```text
effective_difficulty = max(
    production_floor,
    configured_base_difficulty,
    country_required_difficulty
)
```

The authenticated challenge already binds its selected difficulty, and verification applies a current minimum, preventing client-side downgrade. Missing or invalid country input must use at least the base production floor.

The following are **not complete system components today**:

- country-to-difficulty policy and trusted country extraction;
- challenge HTTP endpoint;
- upstream PoW admission middleware;
- proof-cookie and replay lifecycle;
- production browser worker (`dd-protect-client` is a skeleton);
- end-to-end PoW application integration.

PoW is independent of magic-link. Magic-link does not carry a PoW result, IP identity, or generic client key. The current confirmation/session API can carry an optional two-letter country as session context; that field is not trusted PoW policy input and is not connected to `dd-pow-core`. Country-based PoW belongs upstream, and any future removal or separation of the session-country field is tracked in onboarding.

## Trust boundaries

| Boundary | Untrusted input | Required control |
| --- | --- | --- |
| Browser to edge/application | Email, token, cookies, confirmation, PoW solution, body/header metadata | Bounds, canonical parsing, generic errors, TLS |
| Edge to origin | Request target, IP/country metadata | Trusted overwrite rules, direct-origin blocking where required, token-safe logging |
| Application to libraries | Clock, CSPRNG, keyrings, redirects, templates, policy | Purpose-separated secrets and validated configuration |
| Service to storage/outbox | Repository and delivery results | Typed errors, atomic repository contract, generic public failures |
| AWS/provider | DynamoDB/SES behavior | IAM, encryption, TTL/schema, strong reads, transaction and deployment tests |
| Email channel | Bearer magic-link token | Short TTL, scanner-safe GET, explicit POST, one-time atomic consume |

## Security algorithms

| Purpose | Current algorithm or mechanism |
| --- | --- |
| Session and flow-cookie encryption | XChaCha20-Poly1305, 256-bit key, 192-bit nonce, authenticated header |
| Key derivation | HKDF-SHA-256 with purpose and key-ID separation |
| Magic-link lookup/verifier storage | Domain-separated HMAC-SHA-256 |
| Magic-link entropy | Independent 128-bit selector and 256-bit verifier from caller-supplied CSPRNG |
| Flow state | AEAD-authenticated fixed 133-byte body plus independent confirmation nonce |
| PoW challenge identity | BLAKE3 over time and 128-bit entropy |
| PoW challenge authenticity | Domain-separated HMAC-SHA-256 over challenge, difficulty, and timestamp |
| PoW work | SHA-256 of challenge plus decimal nonce; leading zero hexadecimal nibbles |
| PoW replay identity | BLAKE3 of challenge; identifier only, never a credential |
| Constant-time comparisons | `subtle::ConstantTimeEq` for verifier/tag/hash material |
| One-time authentication | DynamoDB conditional five-action transaction or equivalent repository implementation |
| Session revocation visibility | Strongly consistent server-side session reads |
| Sensitive memory handling | Redacted `Debug` and `zeroize` for owned sensitive values |
| Wire encoding | Canonical lowercase hex and Base62; encoding is not cryptographic protection |

The system relies on established cryptographic crates. It does not claim to prove the underlying XChaCha20-Poly1305, SHA-256, BLAKE3, HMAC, or HKDF implementations.

## Critical-path complexity

Input sizes are bounded before expensive work. Let `n` be bounded input length and `d` the number of required leading zero hexadecimal nibbles.

| Operation | Time | Additional memory | Operational note |
| --- | ---: | ---: | --- |
| PoW challenge mint | `O(n)` | `O(n)` current formatting | Bounded timestamp and fixed entropy |
| PoW solution verification | `O(n)` | `O(n)` current formatting/hex buffers | Bounded fields; one HMAC, timestamp parse, and SHA-256 |
| Browser PoW solve | Expected `O(16^d)` SHA-256 trials | `O(1)` | `d=5`: about 1,048,576 expected trials; `d=6`: about 16,777,216 |
| Magic-link generation | `O(1)` | `O(1)` | Fixed 48 bytes of entropy |
| Magic-link parse/HMAC check | `O(n)` | `O(n)` owned text, `O(1)` crypto state | Fixed/bounded token grammar |
| Flow/session AEAD | `O(n)` | `O(n)` | Flow body is fixed at 133 bytes |
| Branca Base62 encode/decode | `O(n²)` current conversion | `O(n)` | Strictly bounded token sizes |
| Request path | `O(1)` bounded local work | `O(1)` | Remote limiter/storage/delivery latency dominates |
| Landing path | `O(1)` bounded local work | `O(1)` | Selector limit plus one strongly consistent candidate read |
| Confirmation path | `O(1)` bounded local work | `O(1)` | Repository reads plus fixed atomic transaction dominate |
| Session validation | `O(n)` cookie work | `O(n)` | One strongly consistent session read |

Production PoW difficulty must be selected from browser benchmarks, not asymptotic complexity alone.

## Related documents

- [Customer onboarding and implementation status](onboarding.md)
- [Security requirements](security.md)
- [Formal assurance roadmap](formal-methods.md)
- [Operating model](operating.md)

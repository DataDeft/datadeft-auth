# Verified production fix plan

Review basis: `docs/review.md`, current workspace at `b2a6d38`, the repository security/phase contracts, direct code inspection, a compile probe for the async-trait contract, and six independent crate-scoped reviews.

This document is the final fix scope. It is a plan only; no source fix is implemented here.

## Decision summary

The review is substantially legitimate, but several rows overstate evidence or propose a remedy that is unsafe under the current API. The release-blocking items are:

1. fail-open parsing of the DynamoDB `disabled` control (review 4);
2. unredacted `Debug` on bearer/PII DTOs (22);
3. missing bound scanner-safe flow state (23);
4. consume/session non-atomicity, including consent-version burn and the production verifier-comparison contract (24, 28, 32);
5. no complete session-validation entrypoint, with unenforced lifetime policy, wrong error vocabulary, and an expiry-inaccurate fake (8, 9, 26, 27);
6. unvalidated production configuration (5).

These are P0 because they violate the repository's own required behavior, not because of speculation: redacted `Debug` and atomic consumption are required by `AGENTS.md:54-62`; flow-state binding is required by `AGENTS.md:62-69`; constant-time verifier comparison and atomic consume/session creation are required by `docs/security.md:106-120`; scanner-safe flow behavior is required by `docs/security.md:291-315`; and phase acceptance requires atomic consume/session creation and bound flow state at `docs/plan.md:367-385`.

**Release gate:** do not represent the current scanner-safe magic-link and server-revocable session surfaces as production-ready until the P0 rows below are implemented and verified. This statement is limited to those surfaces; no deployment topology or consuming application was available for review.

## Ratings

| Field | Meaning |
|---|---|
| Severity | Impact if the affected path is used: High, Medium, or Low. |
| P0 | Required before the affected production path ships. |
| P1 | Fix before public API/storage contract freeze or explicitly accept and document the risk. |
| P2 | Confirmed follow-up after correctness/security work. |
| P3 | Low-risk documentation or regression guard. |
| Complexity | Expected implementation size: Small, Moderate, or Large. |

## `dd-auth-token-core`

| Fix | Review | Severity | Priority | Complexity | Evidence and files to change | Suggested approach |
|---|---:|---|---|---|---|---|
| Purpose-separated temporary flow cookie | 23 | High | P0 | Moderate | Existing purposes and hard lifetime caps are in `crates/dd-auth-token-core/src/keyring.rs:61-97`; bound cookies already require explicit freshness in `crates/dd-auth-token-core/src/cookie.rs:47-77,265-297`. If encrypted cookie state is used, change `keyring.rs`, `cookie.rs`, exports, and their tests. | First write the required cross-crate API proposal. Add a separate flow-cookie purpose and short hard cap; carry authenticated selector, verifier proof, exact account, explicit expiry, and independent nonce state in the encrypted body. Do not reuse session or PoW keys. Keep raw token material out of HTML and redact/zeroize the body. |
| Session policy remains enforced through existing primitives | 8, 27 | High | P0 | Small | `MaxAge` already enforces idle and absolute freshness in `crates/dd-auth-token-core/src/cookie.rs:47-77,267-288`; `SessionCookie::MAX_ABSOLUTE_AGE_SECS` already exists at `crates/dd-auth-token-core/src/keyring.rs:81-86`. | Do not add another lifetime constant here. Service/Axum/AWS changes must consume these existing primitives and cap. Change core only if a narrowly required public export is missing. |

## `dd-pow-core`

No production source change is justified by the reviewed findings.

| Fix | Review | Severity | Priority | Complexity | Evidence and files to change | Suggested approach |
|---|---:|---|---|---|---|---|
| No accepted source change | 17, 19 | — | — | None | PoW allocations are bounded and late-path at `crates/dd-pow-core/src/ops.rs:99-149`; its skew constant already equals cookie skew at `ops.rs:19-22` and `crates/dd-auth-token-core/src/cookie.rs:39-42`. | Keep current behavior. Treat allocation work as benchmark-gated and do not add a cross-crate dependency solely to pin two equal constants. |

## `dd-magic-link-core`

No mandatory core implementation change is needed: the token prefix is already exported (`crates/dd-magic-link-core/src/lib.rs:22-24`), and constant-time verifier comparison already exists (`crates/dd-magic-link-core/src/hmac_lookup.rs:79-103`). The required changes are in service/Axum/AWS consumers.

| Fix | Review | Severity | Priority | Complexity | Evidence and files to change | Suggested approach |
|---|---:|---|---|---|---|---|
| Preserve verifier comparison contract through adapter redesign | 32 | Low | P0 | Large | Core helper: `crates/dd-magic-link-core/src/hmac_lookup.rs:89-103`; production bypasses it through a DynamoDB condition at `crates/dd-magic-link-aws/src/dynamodb.rs:215-236`. Core source should normally remain unchanged. | Reuse the existing helper in the AWS consume redesign. Do not weaken or duplicate the core API. |

## `dd-magic-link-service`

| Fix | Review | Severity | Priority | Complexity | Evidence and files to change | Suggested approach |
|---|---:|---|---|---|---|---|
| Complete session validation and one lifetime policy | 5, 8, 9, 26, 27 | High | P0 | Moderate | Config is public/unvalidated at `crates/dd-magic-link-service/src/config.rs:7-29,57-81`; `session_idle_secs` has no runtime reader. Session-body failures use `MagicLinkUnavailable` at `session_body.rs:36-71`. Cookie parse/body decode/session lookup are composed only in tests at `service_tests.rs:385-394`. Change `config.rs`, `error.rs`, `session_body.rs`, `service.rs` or a new session module, `lib.rs`, and tests. | Add validated config construction/use; reject zero limits/windows/TTLs, idle greater than absolute, and absolute above `SessionCookie::MAX_ABSOLUTE_AGE_SECS`. Add one `validate_session` operation: clock -> `MaxAge` -> `parse_bound_cookie` -> body decode -> `find_session`. Return a session-specific result/error. Test malformed, idle-expired, absolute-expired, missing, revoked, and storage-expired sessions. Do not imply sliding refresh unless touch/re-mint semantics are separately designed. |
| Atomic consume, consent check, local constant-time verification, and session creation | 24, 28, 32 | High | P0 | Large | Current order is consume, post-burn consent validation, user handling, then session write at `crates/dd-magic-link-service/src/service.rs:253-296`; `service_tests.rs:708-786` proves a session failure leaves the token burned. The consume trait lacks expected consent versions at `traits.rs:26-33`. Change `traits.rs`, `types.rs`, `service.rs`, exports, and service tests. | Replace the split transition with one transactional repository command, or a fully specified idempotent reserve/commit protocol. Pass expected terms/privacy versions into the transition. For the current constant-time policy, read by keyed selector, perform dummy/local constant-time verifier work, then commit with non-secret version/unconsumed conditions and session creation atomically. Preserve disabled-user handling, generic public errors, and concurrent replay safety. Do not use a naive fetch-then-unconditional-update flow. |
| Bound scanner-safe landing flow | 23 | High | P0 | Large | Service has no landing/flow-state operation; public operations are request/consume/revoke in `crates/dd-magic-link-service/src/service.rs:82-149,227-317`. Change service traits/types/orchestration and tests. | Add a begin-flow/confirm-flow contract with keyed-selector landing/consume limits, bounded dummy work on miss, short expiry, and AEAD-authenticated binding to selector, verifier proof, exact account, expiry, and independent nonce. POST must validate state before the atomic consume transition. Keep public failures generic and make terminal/success outcomes tell Axum to clear temporary state. |
| Async dependency futures must have an explicit `Send` contract; dyn stance must be documented | 1 | High API impact | P1 | Moderate | Every RPITIT method lacks `+ Send` at `crates/dd-magic-link-service/src/traits.rs:20-94`. A direct compile probe failed both a generic `Send` assertion and `&dyn MagicLinkRepository`. Change `traits.rs`, all implementations/tests, and API docs. | Decide static-only versus dyn-safe APIs explicitly. At minimum, require `+ Send` futures for production multithreaded use and update non-`Sync` `RefCell` test fakes. Adding `Send` alone does not make traits dyn-safe; do not claim that it does. |
| Durable outbox semantics | 3 | Medium | P1 | Large | Quota checks precede challenge write/send at `crates/dd-magic-link-service/src/service.rs:107-146`; SES is inline in `crates/dd-magic-link-aws/src/ses.rs:101-143`. Change `traits.rs`, `service.rs`, tests, and AWS implementation. | Prefer an atomic challenge + durable outbox write and an asynchronous sender. If inline send is explicitly retained, document failure/quota behavior and design reservation/refund or separate limiter commit semantics. Do **not** merely move the current mutating limiter check after SES; that cannot suppress the already-sent message. |
| Upstream abuse-control boundary | 6 | — | Removed | None | Superseded by the approved pre-release API decision. Magic-link retains keyed normalized-email request/outbox limits and keyed-selector landing/consume limits only. | No magic-link fix remains. PoW, IP, global fanout, and malformed-request controls are independent application/edge concerns; do not restore a generic source identifier to magic-link APIs. |
| Exhaustive token error mapping | 10 | Medium | P1 | Small | Wildcard conversion is at `crates/dd-magic-link-service/src/error.rs:83-93`; it catches mint/config faults such as `BadKeyLength` and `EncryptFailed` from `crates/dd-auth-token-core/src/error.rs:16-44`. Change `error.rs` and mapping tests. | Exhaustively map every current `TokenError`. Verification-shaped failures go to a generic session/magic-link failure as appropriate; mint/config/invariant failures go to `Internal` or `Unavailable`. No wildcard arm. |
| Trusted country enforcement contract | 29 | Medium when enforcement is enabled | P1 | Moderate | Service enforcement checks only presence/shape at `crates/dd-magic-link-service/src/service.rs:492-503`; Axum accepts provenance-free header/body values. Change enforcement inputs/config and tests. | Separate trusted enforcement input from client input. Enforced country must come from an explicitly trusted adapter extractor; client body country must not satisfy enforcement. Do not add a cross-crate country newtype solely to deduplicate the currently matching two-letter checks. |
| Owned per-call RNG API | 31 | Medium API impact | P2 | Moderate | Both service structs retain long-lived `&mut Rng` at `crates/dd-magic-link-service/src/service.rs:30-48,153-183`. Change service structs/inputs/methods and construction tests/examples. | Retain the intentional request/consume split, but remove RNG from stored inputs and borrow it per call (or define a reviewed entropy-provider trait). Do not collapse both services merely to reduce type count. |
| Re-export the existing magic-link version marker for Axum | 14 | Medium maintenance risk | P2 | Small | Core already exports the constant, but service does not at `crates/dd-magic-link-service/src/lib.rs:17-33`. Change `lib.rs`. | Re-export the existing constant or expose a narrow token-detection predicate; do not duplicate grammar. |
| Remove dead magic-link `user_id` field | 33 | Low | P3 | Small | Request always sets `None` at `crates/dd-magic-link-service/src/service.rs:122-132`; DTOs carry it at `types.rs:127-166`; `ensure_user` ignores it at `service.rs:519-565`. Change types/service/tests and AWS storage/fake. | Remove the field rather than wiring it through. Wiring it would add unreviewed account-binding semantics and a request-path user lookup. |

## `dd-magic-link-axum`

| Fix | Review | Severity | Priority | Complexity | Evidence and files to change | Suggested approach |
|---|---:|---|---|---|---|---|
| Redact bearer and PII DTO `Debug` | 22 | High | P0 | Small | Unredacted derives are on `MagicLinkRequestJson`, `MagicLinkConsumeBody`, and `MagicLinkLandingPage` at `crates/dd-magic-link-axum/src/lib.rs:136-175,554-561`. Change `lib.rs` and `lib_tests.rs`. | Remove `Debug` where not required or implement manual redacted output. Add sentinel tests proving email, raw token, and account label do not appear. |
| Replace raw-token hidden form with bound flow state | 23 | High | P0 | Large | Landing owns/embeds the raw token at `crates/dd-magic-link-axum/src/lib.rs:554-580`; account label is optional at `571-575`; tests expect token HTML at `lib_tests.rs:328-354`. Change landing/consume APIs, cookie helpers, and tests. | GET obtains service flow state, sets a short-lived `HttpOnly`/secure/host-only/narrow-path cookie, requires safe account-identifying copy, and renders only a CSRF/state handle. POST validates same-origin-bound state before consume and clears magic-link flow cookies on success and terminal failure. Preserve existing no-store/no-referrer/anti-frame headers at `lib.rs:591-602`. |
| Session authentication helper with 401 + cookie clearing | 8, 9, 27 | High | P0 | Moderate | Axum only sets/clears cookies at `crates/dd-magic-link-axum/src/lib.rs:427-475`; current generic mapping makes `MagicLinkUnavailable` HTTP 400 with magic-link copy at `56-104`. Change error/handler or extractor/cookie tests. | Delegate incoming-cookie validation to the new service entrypoint. Map invalid/expired/missing/revoked sessions to a generic 401 and append the clearing cookie. Derive browser `Max-Age` from validated service session policy rather than the independent literal at `lib.rs:32-33`. |
| Trusted country extraction | 29 | Medium | P1 | Moderate | CloudFront country is syntax-checked but provenance-free at `crates/dd-magic-link-axum/src/lib.rs:409-419`; absent header falls back to an untrusted request-body country at `169-174,190-192,544-548`. Change extractor/config/DTO tests. | Require application-provided trusted extractor output for country enforcement. Ignore body values for enforcement. Document proxy/edge overwrite and direct-origin blocking requirements; a configurable header name alone is insufficient. |
| Owned consume closure input | 25 | Medium API impact | P2 | Small | Public/inner helpers require `FnOnce(&str, ...)` at `crates/dd-magic-link-axum/src/lib.rs:512-536`; the test clones immediately at `lib_tests.rs:274-289`. Change helper signatures/tests. | Pass an owned redacted consume input or owned token string into the async closure. Prefer the typed service command if malformed-token limiter behavior remains intact. |
| Version-coupled redirect scrub | 14 | Medium maintenance risk | P2 | Small | Axum hardcodes `"mlv1."` at `crates/dd-magic-link-axum/src/lib.rs:669-675`, and its test hardcodes the same at `lib_tests.rs:154-177`. | Use the service re-export/predicate and derive the test input from it so a version change fails compilation/tests instead of silently weakening the scrub. |

## `dd-magic-link-aws`

| Fix | Review | Severity | Priority | Complexity | Evidence and files to change | Suggested approach |
|---|---:|---|---|---|---|---|
| Fail closed on malformed `disabled` | 4 | High | P0 | Small | `item_to_user` defaults a wrong-typed or absent value to false at `crates/dd-magic-link-aws/src/dynamodb.rs:127-137`; `optional_bool` conflates both at `552-555`. Change `dynamodb.rs` and feature-gated parser tests. | Return `Result<Option<bool>, AwsAdapterError>`: absence may retain the documented default, but a present non-boolean must return `Internal`. Add malformed-attribute tests. The review's claim that every other optional parser already fails closed is false (`optional_s` also collapses wrong type), but that does not weaken this security-control finding. |
| Transactional consume/session transition with pre-burn consent and local CT verification | 24, 28, 32 | High | P0 | Large | Consume is one `UpdateItem` at `crates/dd-magic-link-aws/src/dynamodb.rs:215-242`; session creation is a later transaction at `335-382`; consent condition checks only attribute existence at `229-233`; production equality is delegated to DynamoDB while the fake uses local CT at `crates/dd-magic-link-aws/src/fake.rs:178-183`. Change `dynamodb.rs`, `fake.rs`, error mapping, and tests. | Implement the service transactional command with `TransactWriteItems` or the approved reserve/commit design. Compare expected consent versions before state changes. To meet the current CT policy, perform bounded dummy/local constant-time verifier work after keyed-selector read, then transact on non-secret record version/unconsumed/consent conditions plus session creation. Add concurrent race, stale-consent-no-burn, wrong-verifier, dependency-failure, and atomicity tests. |
| Validated lifetime config and expiry-faithful fake | 5, 8, 26 | High test/contract impact | P0 | Moderate | Dynamo config accepts arbitrary values at `crates/dd-magic-link-aws/src/dynamodb.rs:23-46,58-85`; real lookup rejects expiry at `389-417`; fake computes expiry only for its index, ignores `now_unix`, and checks only revocation at `crates/dd-magic-link-aws/src/fake.rs:232-267`. Change config, fake storage shape, and fake tests. | Validate adapter config, consume the service's validated absolute lifetime, store expiry with fake session records, and use the exact production `< now_unix` boundary. Add boundary and expired-session parity tests. |
| Redact rendered email `Debug` | 22 | High | P0 | Small | `RenderedMagicLinkEmail` derives `Debug` over recipient and complete message bodies at `crates/dd-magic-link-aws/src/ses.rs:11-18`. Change `ses.rs` and `ses_tests.rs`. | Remove `Debug` or implement a manual redacted form; add negative sentinel tests for recipient, subject, text, HTML, and token-shaped content. |
| Durable outbox implementation | 3 | Medium | P1 | Large | `SesMagicLinkOutbox::enqueue_magic_link` sends inline at `crates/dd-magic-link-aws/src/ses.rs:101-143`; service writes challenge first. Change SES/DynamoDB adapters, manifest, and integration tests. | Persist a durable outbox item atomically with the challenge, then send from a retrying worker with idempotent state. Keep provider errors scrubbed. Do not claim the current direct SES call is an outbox. |
| Structured AWS error classification | 11 | Medium | P1 | Small | Get/put/update/transaction/SES mappers inspect formatted `Debug` at `crates/dd-magic-link-aws/src/error.rs:68-130,165-172`; there are no production-feature mapper tests. Change `error.rs` and add AWS-feature tests. | Classify only `SdkError` variants, `as_service_error`, cancellation reasons, and stable provider codes. Unknown cases become dependency unavailable. Never grep `Debug`. |
| Explicit plaintext-email storage decision | 30 | Medium | P1 | Small if documented; Large if encrypted | Plaintext `email_normalized` is written to challenge, user, lookup, and session items at `crates/dd-magic-link-aws/src/dynamodb.rs:194,296-317,351-352`, despite HMAC partition keys at `92-124`. Change adapter docs/config; change `dynamodb.rs` and key loading only if encryption is required. | Before launch, document plaintext schema plus required KMS/IAM/export/backup controls. If confidentiality from logical table reads is required, add adapter-owned authenticated envelope encryption under a purpose-separated loaded key while retaining HMAC lookup keys. Do not call DynamoDB platform encryption equivalent to application-level PII confidentiality. |
| AWS-local storage-policy parity | 12 | Medium test reliability | P2 | Small | Window/prefix logic is duplicated at `crates/dd-magic-link-aws/src/dynamodb.rs:108-124,497-506` and `fake.rs:108-123,310-316`. Production HMACs `key:window_index` before hashing, while fake hashes key then appends index at `fake.rs:297-299`. Change `dynamodb.rs`, `fake.rs`, `hmac_key.rs`, and tests. | Add a non-feature-gated AWS-local module for named prefixes, fixed-window calculation, and rate-storage-key construction. Do not broaden magic-link-core's private HMAC helper; AWS uses a deliberately different domain. |
| Remove dead stored `user_id` | 33 | Low | P3 | Small | Optional decode/store is at `crates/dd-magic-link-aws/src/dynamodb.rs:140-152,205-207`; fake propagates it at `fake.rs:186-193`; service never uses it. | Remove it from current schema writes/DTOs/fake. No dual-read or compatibility fallback unless explicitly approved, consistent with `docs/security.md:352-372`. |

## Findings excluded from fix scope

These observations are partly factual but are not justified production changes under the instruction to avoid unnecessary work.

| Review | Verdict | Evidence-based reason for exclusion |
|---:|---|---|
| 2 | Confirmed serialization, deferred pending quota semantics and latency evidence | Request/consume calls are sequential (`crates/dd-magic-link-service/src/service.rs:96-146,267-296`), but the stated RTT count mixes SES and DynamoDB. Concurrent mutating limiter checks are not behavior-preserving. Define SLO and denial accounting before a batch redesign. |
| 7 | Confirmed fixed-window behavior; accepted/documented design | Windowing is `now / window_secs` at `crates/dd-magic-link-aws/src/dynamodb.rs:497-503`, and the boundary is already tested. No algorithm change is justified. |
| 13 | Partly confirmed | The extra canonical re-encode and quadratic loops exist (`crates/dd-auth-token-core/src/branca.rs:250-268`; `base62.rs:131-148,198-220`), but the claimed operation count is unbenchmarked and cookie paths have tighter derived caps (`cookie.rs:309-319`). No canonicality bypass exists. Benchmark before replacing the security backstop. |
| 15 | Superseded by API removal | The historical count included limiter domains removed by the approved pre-release decision. Reinspect only the remaining keyed-email and keyed-selector paths before considering cleanup. |
| 16 | Confirmed duplication without current drift | Service and Axum currently enforce the same two-uppercase-letter rule (`crates/dd-magic-link-service/src/types.rs:413-419`; `crates/dd-magic-link-axum/src/lib.rs:409-419`). A public cross-crate newtype is not justified solely for deduplication; fix trusted provenance under review 29 instead. |
| 17 | Partly confirmed | The listed allocations/reinitializations exist, but frequency/impact is unmeasured; the PoW allocations are bounded and occur late (`crates/dd-pow-core/src/ops.rs:99-149,159-176`). Keep only as benchmark candidates. |
| 18 | Partly confirmed | Manual zeroization and duplicate private checks exist at `crates/dd-auth-token-core/src/cookie.rs:243-256,389-397`, but no current path skips wiping and tests intentionally use the private `typ` flexibility. No release defect is established. |
| 19 | No current mismatch | Both skew constants equal 60 (`crates/dd-pow-core/src/ops.rs:19-22`; `crates/dd-auth-token-core/src/cookie.rs:39-42`). Adding a new dev-dependency solely for an equality assertion is not justified for this production fix scope. |
| 20 | Partly confirmed | Fixtures are similar, not all byte-for-byte identical; impact is test maintenance only. No production change. |
| 21 | Partly confirmed | The mechanical observations are mostly real, but they are behavior-neutral and some proposed removals weaken explicit generic-error boundaries or enlarge public API for a tiny helper. Excluded as code-golf/cleanup scope. |

## Corrections to `docs/review.md`

- Review 2: serialized network calls are confirmed, but “8+ DynamoDB RTTs” is imprecise because SES is not DynamoDB and user lookup itself performs two reads.
- Review 4: the fail-open `disabled` issue is confirmed; the assertion that every other optional malformed attribute maps to `Internal` is false.
- Review 5: a zero DynamoDB window does not prove literal permanent denial because TTL deletion is asynchronous; it does create one non-rotating bucket until deletion. A zero TTL remains valid at the exact boundary because consume accepts `expires_at_unix >= now`.
- Review 9: wrong vocabulary is confirmed, but no current Axum every-request session handler exists.
- Review 12: AWS real/fake already share `StorageHmacKey::hmac`; the legitimate issue is remaining AWS-local policy duplication and a real rate-key-shape mismatch.
- Review 14: core already exports the prefix; service/Axum fail to consume it.
- Review 15: the historical repeated-call count is superseded by removal of the obsolete limiter domains; recount only the current keyed-email and keyed-selector paths.
- Review 19: both constants currently match and service does not depend on `dd-pow-core`; no new dependency/test is accepted in this production fix scope.
- Review 20: fixtures are substantially similar, not all byte-for-byte identical.
- Review 23: existing no-store/no-referrer/anti-frame headers are correct; the missing account-bound flow state remains a blocker.
- Review 28: this is not a one-line DynamoDB fix because the current consume trait does not receive expected consent versions.
- Review 29: `enforce_country` already defaults to false and values are syntax-checked, but provenance is untrusted; client body fallback makes enabled enforcement spoofable.
- Review 32: code cannot prove DynamoDB's internal equality is non-constant-time. It proves only that production does not use the repository's application-controlled CT helper and therefore cannot substantiate the current uniform contract.

## Verification performed

- `mise run verify` passed on the current workspace: format check, Clippy with `-D warnings`, all-feature workspace tests, docs, and dependency audit.
- A standalone compile probe against `dd-magic-link-service` failed as expected when requiring the generic repository future to be `Send`, and separately failed to construct `&dyn MagicLinkRepository`; this directly verifies review 1.
- Six crate-scoped reviews and one final adversarial synthesis independently inspected the listed findings. No reviewer edited source files.
- Limitation: the repository has no live AWS integration environment or production DynamoDB/SES behavior tests. AWS-feature code compiled, but transaction/error-expression remedies must receive dedicated tests during implementation.

## Required validation for implementation

Each implementation packet must use one crate owner at a time and follow the cross-crate proposal protocol before public API changes. At minimum:

- targeted unit tests for every changed parser/error mapping;
- scanner-flow tests for GET no-consume, selector/verifier/account/expiry/nonce binding, keyed-selector dummy work/limits, POST mismatch, same-origin confirmation, and temporary-cookie clearing;
- transactional tests for wrong verifier, stale consent without burn, session failure without burn, replay, and concurrent consume races against fake and AWS-backed behavior;
- session tests for idle/absolute expiry, missing/revoked/storage-expired records, 401 mapping, and cookie clearing;
- AWS-feature tests for SDK error classification and DynamoDB expression/transaction construction;
- `mise run verify` after all crate-local validations.

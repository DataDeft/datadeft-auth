# Feature assessments

This applies the [feature-justification lens](feature-justification.md) to the
remaining work in implementation PRs #9 and #10 and draft plan #6.
Recommendations are not approvals, implementation claims, or promises to ship.
Unverified deployment assumptions and product decisions remain open.

## PR #9

### Localized confirmation pages (V06-003)

- **Problem:** The existing Axum example resolves English/Hungarian email
  language, but its static confirmation page was English-only. The confirmation
  instructions should be understandable in the selected language.
- **Existing support:** `LocaleAllowlist`, `MagicLinkEmail::locale`, renderer-owned
  URLs and per-route `with_redirect_landing` already supply the necessary pieces.
- **Gap:** Example wiring and translated page/status text, not an absent library
  capability. Confirm the consuming application's actual language requirements.
- **Smallest solution:** Fixed localized routes and pages in the example, using
  existing APIs. No locale persistence, authenticated claim or new library API.
- **Cost:** Maintaining translations, route mappings and example tests. No storage
  migration or authentication-policy change.
- **Proof:** English, Hungarian, default and unknown-locale router flows; identical
  valid/invalid-link redirect status and Location; no token exposure; unchanged
  same-origin POST, no-store and frame protections. Consumer validates wording.

**Recommendation:** Keep the narrow example/docs integration, subject to consumer
UX approval. Do not expand it into a new locale mechanism.

### Opt-in host-prefixed cookies (V06-010)

- **Problem:** A sibling subdomain can attempt to plant a parent-domain cookie
  with the same name. The browser-enforced `__Host-` rules reduce this cookie
  planting/shadowing threat. Its relevance to the actual deployment is unverified.
- **Existing support:** Secure, HttpOnly, host-only cookies, explicit paths,
  authenticated values and duplicate-cookie rejection already exist. These do not
  by themselves forbid a sibling from attempting to set a parent-domain cookie.
- **Gap:** No supported browser-enforced host-prefixed naming policy. We have not
  established that a consuming deployment needs this additional protection.
- **Smallest solution:** If needed, opt in through the existing name builder and
  validate Secure/root-path constraints. Otherwise retain current behavior.
- **Cost:** Extra policy validation and errors, a source compatibility change to
  error matching, and a cookie-name/reauthentication migration when enabled.
  Root-path confirmation cookies also widen their usual narrow scope.
- **Proof:** Exact name and prefix checks, both builder orders, Secure/Path=/,
  no Domain, set/clear parity, duplicate refusal and no alternate-name reads.
  A browser acceptance/rejection test is desirable; header tests alone do not
  prove browser prefix enforcement.

**Recommendation:** Defer adoption until the owner accepts the threat model and
migration cost. Do not rename defaults or widen confirmation-cookie paths.
Whether the library option belongs in this release needs explicit approval.

## Other draft 0.6.0 work (PR #6)

### Account erasure (V06-001)

- **Problem:** Disabling an account retains identifying data and prevents the
  same email from signing up again. The draft cites a consuming-app erasure need;
  the required deletion/retention contract still needs owner confirmation.
- **Existing support:** Disable/revoke/admin transactions and an erasure formal
  model exist. Disabling is not erasure; a model is not an implementation.
- **Gap:** No approved end-to-end erasure workflow with explicit retention rules.
- **Smallest solution:** Define those rules, then add one audited erasure workflow
  using existing transactions and a retry-safe revocation step.
- **Cost:** Irreversible data changes, concurrency handling, adapter/service APIs,
  audit/privacy tradeoffs and updates to retention documentation.
- **Proof:** Repeated erasure, concurrent login, stale links, anonymized listings,
  re-signup as a new user, DynamoDB Local and model replay. Legal compliance is
  not established by tests alone.

**Recommendation:** Conditional priority; approve the product/retention contract
before implementation. A roadmap's "Must" label is not that approval.

### Finer internal failure reasons (V06-004)

- **Problem:** Operators may need to distinguish failure causes without exposing
  them publicly. No specific unanswered operational question is documented yet.
- **Existing support:** Typed errors, `reason()` labels and request throttle
  outcomes already provide diagnostics; sensitive failures share public responses.
- **Gap:** Must identify the exact missing diagnostic before adding more variants.
- **Smallest solution:** First use current labels; add only a demonstrated missing
  internal reason, not a new public failure taxonomy.
- **Cost:** Propagation and matching changes, more metrics labels, possible API
  compatibility impact and accidental information-disclosure risk.
- **Proof:** Tests distinguish the intended internal cause while public status,
  headers and body remain byte-identical and labels contain no sensitive values.

**Recommendation:** Defer until an operational gap is demonstrated.

### Referrer-policy explanation (V06-005)

- **Problem:** Changing to `no-referrer` can interfere with same-origin confirmation
  checks; maintainers need to understand why `strict-origin` was chosen.
- **Existing support:** `docs/security.md` already explains this choice and the
  current scanner-safe headers. Onboarding marks this documentation done.
- **Gap:** No new behavior or missing mechanism has been demonstrated.
- **Smallest solution:** Retain and link the existing explanation; correct it if
  browser tests reveal an error. Do not change policy just to add a feature.
- **Cost:** Documentation maintenance; any behavioral change would need a separate
  threat/compatibility review.
- **Proof:** Check the documented behavior against browser confirmation flows and
  existing header/same-origin tests.

**Recommendation:** Treat as existing documentation, not new implementation work.

### Token-safe logging probe (V06-006)

- **Problem:** A future tracing change could disclose bearer material even while
  functional auth tests pass. This is a concrete preventive security test need.
- **Existing support:** Redacted types, fixed reason labels and router tests exist;
  they do not establish that every captured logging path remains token-safe.
- **Gap:** End-to-end assertions over actual emitted logs.
- **Smallest solution:** An isolated test process capturing the example's tracing
  output during success and refusal flows, using synthetic data. Reuse a supplied
  consuming-app probe only after inspecting it.
- **Cost:** Test/fixture maintenance and capture isolation; no production telemetry
  subsystem or new runtime logging requirement.
- **Proof:** Assert no fixture tokens, cookies or other sensitive fields appear;
  demonstrate that a deliberately leaking test fixture makes the probe fail.

**Recommendation:** Keep as narrowly scoped test hardening, not a runtime feature.

### Authenticated-path fuzzing (part of V06-007)

- **Problem:** Random cookie strings overwhelmingly fail authentication before
  exercising authenticated payload handling.
- **Existing support:** Current `bound_cookie_parse`, `confirm_cookie` and
  `pow_proof_cookie` targets accept arbitrary strings. `session_body` already
  fuzzes decoded framing directly, and `request_json` already covers JSON parsing.
- **Gap:** Structured inputs reaching verification-success paths and subsequent
  semantic checks; not a total absence of body/HTTP fuzzing.
- **Smallest solution:** Extend existing targets with synthetic valid inputs and
  test-key-authenticated malformed payloads. Add targets only for uncovered paths.
- **Cost:** Harness/generator maintenance and campaign compute. Never add a
  production authentication bypass just to reach a parser.
- **Proof:** Demonstrate coverage beyond MAC/AEAD rejection, retain regressions,
  and test tamper/expiry/canonical framing as appropriate.

**Recommendation:** Keep the targeted coverage improvement; avoid duplicating
existing fuzz targets or adding an open-ended fuzzing framework.

### Fuzzing in CI (part of V06-007)

- **Problem:** Manual fuzz targets can stop building or stop being exercised.
- **Existing support:** `mise run fuzz` already runs each target for a bounded
  manual campaign. Ordinary verification does not run that campaign.
- **Gap:** Automated harness health and a recurring, affordable campaign.
- **Smallest solution:** First add a build/smoke gate; propose a bounded scheduled
  campaign separately if its cost and ownership are accepted.
- **Cost:** Nightly/toolchain maintenance, compute, corpus storage and triage.
- **Proof:** A broken harness fails the gate; seeded regressions reproduce; time
  and artifact bounds are enforced.

**Recommendation:** Approve an explicit CI budget before implementation; no long
campaign on every PR by default.

### Branch protection (part of V06-008)

- **Problem:** Merging without required review/checks can bypass the agreed process.
- **Existing support:** CI and PR review exist; the draft's proposed protection
  settings are not evidence of the currently configured GitHub rules.
- **Gap:** Inspect actual repository rules first. There may be nothing to add.
- **Smallest solution:** Configure only missing required checks/review rules that
  the owner approves. Do not invent a new release service.
- **Cost:** Administrative access, reviewer availability and an emergency procedure.
- **Proof:** Inspect effective rules and demonstrate an unreviewed/failing PR cannot
  merge through the normal contributor path.

**Recommendation:** Inspect first; any repository-setting change needs approval.

### Automatic registry publishing (part of V06-008)

- **Problem:** Automating publication may reduce manual release work. No current
  release bottleneck establishes that this is necessary now.
- **Existing support:** Release-please, release tasks, registry checks and a release
  runbook already exist.
- **Gap:** A demonstrated operational problem and explicit publication authorization.
- **Smallest solution:** Keep the existing release path unless that gap is confirmed.
- **Cost:** Registry permissions, environment/trust configuration, supply-chain risk
  and failure/partial-publication recovery.
- **Proof:** Approved dry run, correct artifact ordering/versioning and refusal
  without the required release/environment approval.

**Recommendation:** Defer. No publishing or credential/configuration changes are
implied by an implementation PR.

### Remove the unused TTL compatibility helper (V06-009)

- **Problem:** `remove_legacy_session_ttl` preserves maintenance work for an obsolete
  session storage shape despite the 0.5.0 fresh-table upgrade contract.
- **Existing support:** The helper still exists in the AWS adapter; 0.5.0 docs
  already require a fresh table and reject the older token/storage shape.
- **Gap:** Unnecessary compatibility API remains, subject to confirming no supported
  consuming project still depends on it.
- **Smallest solution:** Remove that method, its obsolete tests and references.
- **Cost:** A public API removal requiring a breaking-release note and consumer
  compile checks. No new storage migration should be introduced.
- **Proof:** Search supported consumers, compile them, run AWS tests and confirm
  current session expiry/revocation behavior remains unchanged.

**Recommendation:** Remove in the approved breaking release after the consumer
check, not as an unannounced patch change.

## Elixir delivery (PR #10 and separately gated follow-ups)

The explicit requirements are recorded in `docs/elixir-bindings-plan.md`:
framework-independent high-level auth and PoW, existing Rust DynamoDB/SES
execution, a separate process rather than a NIF, and source builds initially.
Those requirements do not authorize every implementation mechanism.

### Bounded service execution and explicit initialization (P2)

- **Problem:** AWS calls must not block Port lifecycle processing or admit
  unbounded work; authentication must not run before its configured keys are ready.
- **Existing support:** The merged Port foundation handles framing, deadlines,
  pending-call bounds and restart supervision, but not service/AWS execution.
- **Gap:** Bounded asynchronous delegation and validated startup initialization.
- **Smallest solution:** One worker with capped jobs, one reply writer, explicit
  initialization and fail-closed readiness. Higher concurrency needs measurement;
  no general worker-pool framework or new network service.
- **Cost:** Executor dependency, lifecycle state, backpressure and shutdown rules.
- **Proof:** Slow jobs do not stall control processing; overload is bounded;
  pre-init calls fail; EOF, job failure, owner death and stale replies are handled.

**Recommendation:** Required infrastructure for the agreed AWS binding; keep it
bounded and minimal rather than adding speculative throughput machinery.

### Magic-link/session APIs with AWS execution (P3)

- **Problem:** An Elixir application needs the existing authentication workflows
  without reimplementing security policy or depending on Phoenix/Plug.
- **Existing support:** Rust service, DynamoDB transactions, SES delivery, secret
  loading and key rotation exist. The transport foundation alone exposes no auth.
- **Gap:** A typed high-level Elixir/Port adapter to those existing operations.
- **Smallest solution:** Delegate request, landing, flow-state, confirmation,
  validation/refresh and logout to Rust; applications own HTTP and authorization.
  No generic crypto API, callback storage bridge or additional backend.
- **Cost:** Private protocol, explicit config/result types, packaging and end-to-end
  tests. Rust is required at build time, not on deployed source-built releases.
- **Proof:** Fake and DynamoDB Local flows, exactly-once consume under contention,
  rotation, revocation, logout, refresh/lifetime bounds, redaction and source-release
  consumer builds. Green CI alone is not evidence that recovery is complete.

**Recommendation:** Keep the approved binding scope; review actual behavior before
calling it production-ready. Admin/erasure parity is not included by default.

### Independent PoW operations (P4)

- **Problem:** The agreed Elixir integration needs the same browser-compatible
  PoW controls, including shared lifetime admission across nodes.
- **Existing support:** Rust challenge/proof verification and DynamoDB-backed
  counters already exist; a local Elixir counter would weaken that contract.
- **Gap:** High-level binding operations, not another PoW algorithm or store.
- **Smallest solution:** Delegate challenge, solution verification and proof
  admission; keep PoW independent of magic-link policy.
- **Cost:** Protocol/API surface, policy configuration and cross-process tests.
- **Proof:** Browser vectors, challenge binding, configured difficulty, expiry,
  cross-node budget exhaustion, rotation stability and fail-closed storage errors.

**Recommendation:** Keep as explicitly requested binding functionality; do not add
PoW solving or node-local production admission.

### Ambiguous-commit recovery (P2 production gate)

- **Problem:** Rust/BEAM can die after DynamoDB commits but before Elixir receives
  the result. Timeout does not reveal whether authentication committed.
- **Existing support:** Atomic Rust storage commits and no automatic Port replay
  prevent treating a failed reply as a rollback, but process-local state cannot
  establish restart-durable recovery. PR #10 lists this gate as incomplete.
- **Gap:** Proving the agreed recovery contract across process restarts.
- **Smallest solution:** Propose the minimum recoverable attempt/commit boundary
  before changing service APIs. If the owner instead accepts fail-closed,
  indeterminate outcomes, explicitly revise that requirement; do not silently
  claim recovery or blindly retry a new login operation.
- **Cost:** Potential persistent sensitive state, retention, reconciliation and
  cross-crate API complexity. A general transaction/journal framework is not
  justified merely by this gate.
- **Proof:** Fault injection before/after commit and response, Rust/BEAM restarts,
  identical-attempt reconciliation, no duplicate session and no secret leakage.

**Recommendation:** Block production-readiness claims until the contract is
resolved and proved. The recovery mechanism itself still needs a reviewed proposal.

### Source-release readiness (P5)

- **Problem:** A locally working binding may omit native sources or fail on a clean
  consumer/release host without Rust installed at runtime.
- **Existing support:** Source-build compiler, isolated archive/consumer/release
  checks and Linux baseline/current runtime CI exist from the foundation.
- **Gap:** Keeping those checks valid as auth/AWS dependencies and vendored sources
  expand, plus completing documented security/recovery gates.
- **Smallest solution:** Extend existing package checks and accurate documentation;
  no new distribution system or automatic publication.
- **Cost:** CI/build time and maintaining the supported runtime/platform matrix.
- **Proof:** Build/install from the actual source archive, exercise the release
  executable, check runtime compatibility and verify no source/dependency omission.

**Recommendation:** Required delivery validation, not an excuse to broaden scope.
Publication remains separately authorized.

### Standalone Phoenix example (P6)

- **Problem:** HTTP consumers need a reference for cookies, CSRF, headers and routes;
  those security responsibilities remain outside the framework-independent library.
- **Existing support:** The Rust Axum example and Elixir high-level API provide
  reference behavior, but not a runnable Phoenix integration.
- **Gap:** A Phoenix-specific example only if the intended consumer uses that stack.
- **Smallest solution:** A separate fake-backed example; no library Plug/Phoenix
  dependency, generated router or reusable middleware framework.
- **Cost:** Example dependencies, HTTP tests and maintenance across framework releases.
- **Proof:** Full browser/HTTP contract, one-time consume and revoke-before-clear,
  while the library still builds without the example's dependencies.

**Recommendation:** Separately gated after the core binding; confirm the consumer
stack and example need before beginning work.

### Prebuilt executable distribution (P7)

- **Problem:** Some build environments may lack Rust. No current initial-release
  requirement demands supporting those environments.
- **Existing support:** The approved initial source-build path includes the native
  executable in the deployed release; production hosts need no Rust compiler.
- **Gap:** Only a demonstrated inability or unacceptable cost to build from source.
- **Smallest solution:** Keep source builds until that gap is established.
- **Cost:** Cross-platform artifacts, ABI coverage, integrity/provenance verification,
  release ordering and download failure handling.
- **Proof:** Reproducible supported-target artifacts, verified install and mismatch/
  tamper refusal, plus clean consumer tests without build-time Rust.

**Recommendation:** Defer; not an automatically approved follow-up PR.

# 0.6.0 authentication improvements (implementation)

This implementation PR covers V06-002, V06-003 and V06-010 from draft PR #6.
It does not implement account erasure or promise a complete 0.6.0 release.
The user authorized a separate implementation PR/branch; the isolated worktree
must not modify the concurrent Elixir authentication work.

## Design decisions and public API proposals

The implementation orchestrator records these proposals before changing the
producer APIs. They remain subject to review in this draft implementation PR.

### V06-002: audience-scoped keyrings

- Producer: `datadeft-auth-token-core`.
- Consumers: `datadeft-magic-link-aws`, and applications injecting keyrings into
  the existing service APIs.
- Proposed API: validated `keyring::Audience`, and consuming
  `KeyRing::with_audience(&Audience)`.
- Adapter API: `LoadedAuthSecrets::with_audience(&Audience)` scopes both session
  and confirmation rings together, including verify-only slots.
- Reason: isolate cookies between application contexts without adding an `aud`
  field, a second token parser, or per-request configuration reads.
- Construction: derive each slot's audience key using HKDF-SHA256 over its
  existing purpose/kid-derived key. Pin a new versioned domain plus explicit
  length framing for purpose, kid and audience. Keep mint/verify windows and
  slot status unchanged. Reject rebinding a ring rather than silently stacking
  scopes. Replaced key bytes and temporary output retain best-effort zeroization.
- Security: no unscoped or alternate-audience verification fallback. Different
  audiences fail the existing constant-time AEAD authentication. Audience is
  trusted startup configuration, never a claim accepted from a request. This
  does not isolate a compromised application that holds the shared root secret,
  replace authorization, or isolate use of a stolen raw email-link token.
- Migration: unconfigured rings keep their existing keys and wire format.
  Enabling/changing an audience invalidates existing session and confirm cookies;
  apply the same configuration on every node, including refresh and logout.
  Do not retain unscoped verification as a migration shortcut.
- Tests: input validation, deterministic independent HKDF vector, scope/purpose/
  kid separation, scoped/unscoped and cross-audience refusal in both directions,
  tamper refusal, active/previous rotation, expiry and rebinding refusal. Exercise
  both real session and confirmation purposes through the AWS loaded-secrets API.

### V06-003: locale-specific confirmation routes

- Producer: existing service locale and Axum redirect APIs; initially no new API.
- Consumers: email renderer and consuming application's route configuration.
- Current support: `MagicLinkEmail::locale` already contains the allowlisted,
  resolved locale; the outbox owns URL construction. A renderer can choose a
  configured locale-specific landing path. Each landing route can already use
  its own `MagicLinkScannerFlowConfig::with_redirect_landing` page.
- Proposed implementation: document and test this route-based integration first,
  rather than add locale storage or signed-query machinery without a demonstrated
  need. The application owns translations and static pages.
- Security: choose the locale/page from a fixed allowlisted route before link
  validation. A valid and invalid link on that route must have the same status
  and Location. Never choose the page from a successful record lookup: doing so
  would make the redirect a link-validity oracle. Language is presentation, not
  authorization. Keep a fixed default route, no arbitrary redirects, no token
  material in Location, and the existing no-store/frame/referrer protections.
- Tests: multiple configured locale pages and a default, same-target redirects
  for usable/unusable links, safe cookie paths and absence of token material.
- Follow-up gate: exercise this pattern in the consuming application's renderer
  and routes. If it cannot express the real integration, propose the smallest
  missing API before changing storage shapes.

### V06-010: opt-in host-prefixed session cookies

- Producer/consumer: `datadeft-magic-link-axum`; consuming app uses existing
  `SessionCookieConfig::with_name("__Host-dd_session")`.
- Proposed API change: accept the exact case-sensitive `__Host-` prefix for
  session-cookie names, retaining lower snake_case suffixes and the total name
  cap. Add typed errors for insecure or non-root-path prefixed policies.
- Reason: browser-enforced protection against sibling-subdomain cookie planting.
- Security: require Secure, explicit Path=/ and host-only scope. Check every
  name/path builder order; set and clear headers must retain identical policy.
  Confirm-cookie names remain unprefixed with their narrow auth paths.
- Migration: opt-in, not a silent default rename. Existing default `dd_session`
  and explicit local HTTP behavior stay unchanged. Insecure local configuration
  must reject host-prefixed names. A deployment enabling the new name requires
  reauthentication and should expire its old cookie separately in application
  migration code. Do not add dual cookie reads to the library.
- Tests: set/clear parity, secure/root/host-only requirements, builder order,
  malformed prefix/suffix/case, length cap, local refusal, and existing defaults.

## Implementation tracking

- [ ] Audience-scoped core keyrings and vectors.
- [ ] AWS startup binding for both session and confirmation rings.
- [ ] Locale-route integration guide and regression tests.
- [ ] Host-prefixed session cookie validation and tests.
- [ ] Workspace verification and minimum-compiler checks.
- [ ] Consuming-application integration and review of migration choices.

No publishing, version bump, live secret access or production configuration
changes are authorized by this PR. The draft release plan remains in PR #6.

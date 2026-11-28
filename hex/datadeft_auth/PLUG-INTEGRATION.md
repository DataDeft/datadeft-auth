# Plug magic-link adapter and Bandit example

Approval: Project owner's “ok continue” after the #45 update named the runnable
Plug/Bandit example and tested browser login/logout as the next review checkpoint.
This implements that already-approved part of the 0.8 plan, not a production
transport or a PoW replacement.

1. **Problem:** a consuming Elixir web app needs to turn existing service calls
   into a safe browser flow. A scanner may visit a link, a foreign site may
   submit forms, and a browser or proxy may cache or send referrers.
2. **What exists:** the Rust Axum adapter and example define the browser-facing
   behavior; Elixir already provides request, read-only flow and session services
   and a shared transactional repository.
3. **Gap:** with no Plug integration, each consumer would need to reproduce the
   body/header bounds and duplicate handling, cookie lifetimes/clearing,
   non-reflective failures, origin checks and revocation ordering.
4. **Smallest solution:** optional Plug helpers over the existing services. Apps
   mount routes, render HTML, choose their fixed redirects and configure a
   canonical public origin. A single Bandit consumer demonstrates redirect
   landing, flow state, confirmation, protected pages and logout on loopback
   using isolated in-memory state and a private development mailbox file. PoW
   will plug in independently with the existing shared browser client; it is
   not mocked here. No database schema, wire-token or native changes.
5. **Cost:** optional Plug dependency (floor 1.20.4, supporting Elixir 1.16;
   Hex reports no advisories for 1.20.4 at selection); existing Jason is also
   needed at runtime to decode the bounded JSON body and reject duplicate keys.
   Bandit is an example-only dependency. A consuming app owns delivery, logging
   exclusions, proxy trust, edge admission and rendering. Local HTTP must be
   explicitly selected and is restricted to loopback origins.
6. **Proof:** compare Rust-equivalent HTTP bodies, cookies, status and headers;
   test malformed/duplicate input, cross-origin rejection, cookie preservation on
   outage, and terminal-state clearing. In a real browser against Bandit, prove
   scanner opens don't consume, the confirmation page has no bearer in its URL
   or scripts, explicit confirmation creates one session, logout revokes before
   clearing, and replay is rejected.

The real Chromium smoke passed on macOS/AArch64 (Playwright 1.65.1). Also
passed: workspace verification, mixed Rust/Elixir DynamoDB Local, a bundled
Mix release and a separate consumer that builds without Plug. The demo smoke
does not prove production delivery, cross-language HTTP/PoW, or Hex archive
consumption.

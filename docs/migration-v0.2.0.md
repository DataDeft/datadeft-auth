# Migrating a consumer to datadeft-auth v0.2.0

> This describes the historical git-tag migration. For registry packages and
> renamed imports, also follow "Upgrading from the git-tag crates" in
> [integration.md](integration.md).

This document is written to be handed to an implementation agent working on
an application that consumes datadeft-auth (for example `pz-api`). It is
self-contained: follow it top to bottom.

## Task

Migrate the application from datadeft-auth v0.1.x to v0.2.0 (tag `v0.2.0`).
The release is breaking at compile time for `dd-pow-core` / `dd-pow-axum`
call sites and wire-compatible with everything deployed: already-minted
challenges, `dd_pow` proof cookies, and the `dd-protect-client` browser
worker all keep working. No browser or client changes.

Do steps 1–4 now. Step 5 (solve classification) is a deliberate later change;
wire the hook as a no-op and stop.

## 1. Pin the dependency

Pin `dd-pow-core` / `dd-pow-axum` (and the rest of the workspace crates you
use) at v0.2.0. Build once and let the compiler list the affected call
sites: every break below is a type or arity error, never a silent behavior
change.

## 2. Switch the PoW clock to `UnixMillis`

Every PoW mint/verify call now takes `dd_pow_core::UnixMillis` instead of
unix seconds or an RFC3339 string:

```rust
use dd_pow_core::UnixMillis;

let now = UnixMillis::from_millis(
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?,
);
```

Rules:

- The value must genuinely be milliseconds. The newtype prevents passing a
  bare `u64`, but it cannot detect seconds wrapped in `from_millis`. Do not
  multiply an existing seconds value by 1000 at the call site as a shortcut;
  take milliseconds from the clock source so sub-second precision is real.
- Delete any code that formats a timestamp for `mint_challenge` /
  `mint_pow_challenge`. Mint formats `tim` itself (RFC3339, millisecond
  precision). If the app previously built the RFC3339 string from whole
  seconds, that code path is exactly the bug this release fixes.
- Seconds-resolution APIs (proof-cookie TTLs, replay tables) take
  `now.as_secs()`.

## 3. Update `verify_pow_solution` call sites (dd-pow-axum)

The function gained a final `classify_solve` parameter and now returns
`PowAdmission` instead of a bare `HeaderValue`:

```rust
let admission = verify_pow_solution(
    &secret,
    policy,
    &request,
    &keyring,
    &cookie_config,
    &mut rng,
    now,        // UnixMillis
    |_ms| None, // classify_solve: start as a no-op
)?;
response
    .headers_mut()
    .append(SET_COOKIE, admission.set_cookie);
```

Direct `dd-pow-core` users instead see:

- `verify_solution(...)` returns `Verified { tid, mint_to_verify_ms }`.
- `mint_pow_proof_cookie(tid, solve_class, keyring, rng, now_unix)` has a
  new second argument; pass `None` for current behavior (v1 body,
  byte-identical to 0.1.x cookies).

## 4. Record the solve-timing signal

`admission.mint_to_verify_ms` is the server-derived mint→verify delta in
milliseconds. From day one, record it into a per-difficulty histogram or
metric (label by the policy difficulty). This is the field data that later
picks thresholds and tunes difficulty.

Consumption rules (from `docs/security.md`, "Solve-timing signal" — read it
before wiring anything beyond a metric):

- The delta is inflatable but not deflatable. Only implausibly *fast*
  values are evidence (native-speed solver). Slow or human-looking values
  must stay soft: tag or triage, never block.
- Do not set any threshold in this migration. Real cohorts mix device
  speeds, so theory-derived floors misfire; thresholds come from the
  collected histogram later.
- Treat the delta as including network round trips and client-side
  queueing, not pure solve time.
- With more than one instance, the delta is only as accurate as clock
  synchronization between the minting and verifying instances. From v0.3.0
  the field is `Option<u64>` and is `None` when the verifying clock is
  behind the mint time; v0.2.0 reports `0` in that case, so do not read a
  v0.2.0 `0` as a fast solve.

## 5. Later (not now): solve classification

Once a histogram exists and a quantization is chosen, return `Some(byte)`
from `classify_solve`. The byte is stamped into the encrypted `dd_pow` v2
cookie body and comes back at later gate checks via
`VerifiedPowProof::solve_class()` (`None` means a v1 cookie or no class).
The byte is opaque to the library; the app owns the encoding. This replaces
any planned app-side `tid → delta` side table. Constraint: proof-cookie
keyring kids stay at most 12 bytes (unchanged from v1).

Rolling upgrades: a class byte produces a v2 cookie body, which 0.1.x nodes
reject (they accept only the v1 body and a 64-byte body budget). Return
`Some(byte)` only after every node verifying `dd_pow` cookies runs v0.2.0 or
later, and do not roll back below v0.2.0 while v2 cookies are live (up to the
proof-cookie TTL, 3 hours by default).

## Do not

- Parse `tim` anywhere. It may now carry a fractional second; it is an
  opaque string the client echoes byte-for-byte.
- Gate, block, or step-up on a *slow* delta.
- Log the delta joined to identifying material beyond the app's normal
  metrics policy.
- Change `dd-protect-client` or anything browser-side; nothing is needed.

## Verify

1. The workspace builds with no remaining references to the old signatures.
2. Existing PoW integration tests pass; if the app has a mint→solve→verify
   test, assert `mint_to_verify_ms` is present and plausible (≥ 0, below
   the challenge max age in ms).
3. A `dd_pow` cookie minted by the *old* version still verifies (v1 bodies
   are unchanged); if the app has no such fixture, note it rather than
   fabricating one.
4. The per-difficulty timing metric is visible in the app's metrics output
   for a locally-driven solve.

## References in this repository

- `CHANGELOG.md`, section 0.2.0 — the authoritative change list.
- `docs/integration.md` — consumer wiring overview.
- `docs/security.md`, "Solve-timing signal" — trust argument and
  consumption rules.
- `crates/dd-pow-axum/src/handlers_tests.rs` — a working end-to-end
  mint→solve→verify→cookie example including a classifier.

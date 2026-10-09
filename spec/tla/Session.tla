----------------------------- MODULE Session -----------------------------
(*
 Session validation, refresh, revocation, and disable/enable, with clock skew.

 Code: crates/datadeft-magic-link-service/src/session.rs (validate_session,
 refresh_session_cookie), crates/datadeft-auth-token-core/src/cookie.rs and
 cookie/freshness.rs (parse_bound_cookie), the SessionRepository adapters
 (find_session, is_session_owner_active), and AuthAdminService
 (disable_user, enable_user, revoke_all_sessions).

 Time. "now" is true time. Every node reads its own clock: a reading is
 now + off with off in 0..Skew, so two readings at one true time differ by at
 most Skew. Tol is CLOCK_SKEW_TOLERANCE_SECS, the code's future-date
 tolerance. The deployment must keep Skew <= Tol.

 Cookie. A session cookie carries iat (first issue, absolute bound) and ts (the
 Branca timestamp, last activity, idle bound). Login mints iat = ts = the login
 node's reading, and the server row stores the same reading as created_at.
 Refresh keeps iat and moves ts.

 Server row. exists, created (login node reading), revoked. Storage expiry is
 created + Abs (expires_at_unix); find_session hides a row with
 expires_at < now.

 Owner. disabled, and the enable watermark wm (sessions_valid_after_unix).
 is_session_owner_active = ~disabled /\ (no watermark \/ created > wm).

 Teeth. Each accept records ghost flags computed from true time and true event
 order, never from the guard's own clock readings. The invariants read the
 ghosts. spec/tla/mutants lists one mutant per invariant that must fail.
*)
EXTENDS Integers, FiniteSets

CONSTANTS
    Sessions,       \* session ids, e.g. {s1, s2}
    Idle,           \* idle lifetime (MaxAge.idle_secs)
    Abs,            \* absolute lifetime (MaxAge.absolute_secs)
    Tol,            \* CLOCK_SKEW_TOLERANCE_SECS
    Skew,           \* real bound on the clock difference of any two nodes
    MaxTime,        \* bound on true time
    RevokeMayFail,  \* revoke_all may stop part way (dependency error)
    WatermarkSlack, \* enable stores wm = reading + WatermarkSlack.
                    \* 0 is the current code. Tol is the candidate fix.
    WithAdmin,      \* explore disable / revoke_all / enable
    WithRefresh,    \* explore refresh_session_cookie
    EnableRevokesFirst \* enable_user revokes every live session before it
                       \* re-enables, and revoke_all keeps sessions within Tol
                       \* of expiry. FALSE is the 0.4.1 code, TRUE the fix.

None == "none"

\* u64::saturating_sub
Sat(a, b) == IF a > b THEN a - b ELSE 0

\* A node reads now + off. Any two readings at one true time differ by at
\* most Skew.
Offsets == 0..Skew

VARIABLES
    now,          \* true time
    rec,          \* [Sessions -> [exists, created, revoked]]
    cookie,       \* [Sessions -> [iat, ts, tm]]: the browser's current cookie;
                  \* tm is its true mint time (ghost)
    pending,      \* [Sessions -> [tv, off] or None]: an accepted validation of
                  \* the request in flight (true time, validator clock offset)
    disabled,     \* owner disabled flag
    hasWm,        \* a watermark is stored
    wm,           \* sessions_valid_after_unix
    ra,           \* revoke_all pc: "idle" | "list" | "run"
    raMode,       \* what revoke_all serves: "disable" | "enable"
    todo,         \* sessions revoke_all still has to revoke
    \* ghosts (audit, never read by a guard)
    bornAt,       \* [Sessions -> true login time]
    preEnable,    \* [Sessions -> existed at some enable]
    accRevoked, accPastAbs, accPastIdle, accDisabled, accWatermark,
    accPreEnable, refreshStale

vars == << now, rec, cookie, pending, disabled, hasWm, wm, ra, raMode, todo,
           bornAt, preEnable, accRevoked, accPastAbs, accPastIdle,
           accDisabled, accWatermark, accPreEnable, refreshStale >>

ghosts == << accRevoked, accPastAbs, accPastIdle, accDisabled, accWatermark,
             accPreEnable, refreshStale >>

Init ==
    /\ now = 0
    /\ rec = [s \in Sessions |-> [exists |-> FALSE, created |-> 0, revoked |-> FALSE]]
    /\ cookie = [s \in Sessions |-> [iat |-> 0, ts |-> 0, tm |-> 0]]
    /\ pending = [s \in Sessions |-> None]
    /\ disabled = FALSE
    /\ hasWm = FALSE
    /\ wm = 0
    /\ ra = "idle"
    /\ raMode = "disable"
    /\ todo = {}
    /\ bornAt = [s \in Sessions |-> 0]
    /\ preEnable = [s \in Sessions |-> FALSE]
    /\ accRevoked = FALSE
    /\ accPastAbs = FALSE
    /\ accPastIdle = FALSE
    /\ accDisabled = FALSE
    /\ accWatermark = FALSE
    /\ accPreEnable = FALSE
    /\ refreshStale = FALSE

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED << rec, cookie, pending, disabled, hasWm, wm, ra, raMode, todo,
                    bornAt, preEnable >>
    /\ UNCHANGED ghosts

\* Magic-link commit: the transaction checks the profile is not disabled, then
\* writes the row with created_at = the login node's reading. The cookie is
\* minted from the same reading (iat = ts = created).
Login(s) ==
    /\ ~rec[s].exists
    /\ ~disabled
    /\ \E off \in Offsets :
         LET l == now + off IN
         /\ rec' = [rec EXCEPT ![s] = [exists |-> TRUE, created |-> l, revoked |-> FALSE]]
         /\ cookie' = [cookie EXCEPT ![s] = [iat |-> l, ts |-> l, tm |-> now]]
    /\ bornAt' = [bornAt EXCEPT ![s] = now]
    /\ UNCHANGED << now, pending, disabled, hasWm, wm, ra, raMode, todo, preEnable >>
    /\ UNCHANGED ghosts

\* Logout, or a single admin revoke: condition "not revoked yet".
Revoke(s) ==
    /\ rec[s].exists
    /\ ~rec[s].revoked
    /\ rec' = [rec EXCEPT ![s].revoked = TRUE]
    /\ UNCHANGED << now, cookie, pending, disabled, hasWm, wm, ra, raMode, todo,
                    bornAt, preEnable >>
    /\ UNCHANGED ghosts

\* disable_user: set_disabled first (AlreadyInState tolerated), then
\* revoke_all_sessions. A retry on an already disabled user goes straight to
\* revoke_all.
Disable ==
    /\ WithAdmin
    /\ ra = "idle"
    /\ disabled' = TRUE
    /\ ra' = "list"
    /\ raMode' = "disable"
    /\ UNCHANGED << now, rec, cookie, pending, hasWm, wm, todo, bornAt, preEnable >>
    /\ UNCHANGED ghosts

\* revoke_all lists the sessions whose status at the admin's reading is Active:
\* not revoked and expires_at >= reading. With the fix the bound is
\* expires_at + Tol >= reading, so an admin clock that runs ahead cannot skip a
\* session a slower validator still accepts.
ListSlack == IF EnableRevokesFirst THEN Tol ELSE 0

RevokeAllList ==
    /\ ra = "list"
    /\ \E off \in Offsets :
         todo' = { s \in Sessions :
                     /\ rec[s].exists
                     /\ ~rec[s].revoked
                     /\ rec[s].created + Abs + ListSlack >= now + off }
    /\ ra' = "run"
    /\ UNCHANGED << now, rec, cookie, pending, disabled, hasWm, wm, raMode, bornAt, preEnable >>
    /\ UNCHANGED ghosts

\* One revoke_session_audited. ConditionalWriteFailed (already revoked) is
\* tolerated: the session just leaves the to-do set.
RevokeAllStep(s) ==
    /\ ra = "run"
    /\ s \in todo
    /\ rec' = [rec EXCEPT ![s].revoked = TRUE]
    /\ todo' = todo \ {s}
    /\ UNCHANGED << now, cookie, pending, disabled, hasWm, wm, ra, raMode, bornAt, preEnable >>
    /\ UNCHANGED ghosts

\* A dependency error stops revoke_all part way. The caller may retry. An
\* enable that fails here leaves the user disabled.
RevokeAllFail ==
    /\ RevokeMayFail
    /\ ra \in {"list", "run"}
    /\ ra' = "idle"
    /\ raMode' = "disable"
    /\ todo' = {}
    /\ UNCHANGED << now, rec, cookie, pending, disabled, hasWm, wm, bornAt, preEnable >>
    /\ UNCHANGED ghosts

\* The conditional write that re-enables the user and stores the watermark:
\* the admin node's reading plus WatermarkSlack.
EnableWrite ==
    /\ \E off \in Offsets : wm' = now + off + WatermarkSlack
    /\ disabled' = FALSE
    /\ hasWm' = TRUE
    /\ preEnable' = [s \in Sessions |-> preEnable[s] \/ rec[s].exists]

RevokeAllDone ==
    /\ ra = "run"
    /\ todo = {}
    /\ ra' = "idle"
    /\ raMode' = "disable"
    /\ IF raMode = "enable"
         THEN EnableWrite
         ELSE UNCHANGED << disabled, hasWm, wm, preEnable >>
    /\ UNCHANGED << now, rec, cookie, pending, todo, bornAt >>
    /\ UNCHANGED ghosts

\* enable_user. 0.4.1: one conditional write, nothing waits for revoke_all.
\* Fix: revoke every live session first, and write only if that finished.
Enable ==
    /\ WithAdmin
    /\ disabled
    /\ IF EnableRevokesFirst
         THEN /\ ra = "idle"
              /\ ra' = "list"
              /\ raMode' = "enable"
              /\ UNCHANGED << disabled, hasWm, wm, preEnable >>
         ELSE /\ EnableWrite
              /\ UNCHANGED << ra, raMode >>
    /\ UNCHANGED << now, rec, cookie, pending, todo, bornAt >>
    /\ UNCHANGED ghosts

----------------------------------------------------------------------------
\* validate_session at a validator reading v.

\* parse_bound_cookie: idle bound on ts, absolute bound on iat, future-date
\* tolerance on both, iat <= ts.
CookieFresh(c, v) ==
    /\ c.ts <= v + Tol
    /\ Sat(v, c.ts) <= Idle
CookieAbs(c, v) ==
    /\ c.iat <= c.ts
    /\ c.iat <= v + Tol
    /\ Sat(v, c.iat) <= Abs

\* find_session hides a row with expires_at < now.
StorageLive(s, v) == ~(rec[s].created + Abs < v)
\* created_at <= now + skew, and now - created_at <= absolute.
ServerAbs(s, v) ==
    /\ rec[s].created <= v + Tol
    /\ Sat(v, rec[s].created) <= Abs
NotRevoked(s) == ~rec[s].revoked
\* is_session_owner_active
OwnerEnabled == ~disabled
AfterWatermark(s) == ~hasWm \/ rec[s].created > wm

Validate(s) ==
    /\ rec[s].exists
    /\ \E off \in Offsets :
         LET v == now + off
             c == cookie[s]
         IN
         /\ CookieFresh(c, v)
         /\ CookieAbs(c, v)
         /\ StorageLive(s, v)
         /\ NotRevoked(s)
         /\ ServerAbs(s, v)
         /\ OwnerEnabled
         /\ AfterWatermark(s)
         /\ pending' = [pending EXCEPT ![s] = [tv |-> now, off |-> off]]
         \* ghosts: ground truth at the accept
         /\ accRevoked' = (accRevoked \/ rec[s].revoked)
         /\ accPastAbs' = (accPastAbs \/ (now - bornAt[s] > Abs + Skew))
         /\ accPastIdle' = (accPastIdle \/ (now - c.tm > Idle + Skew))
         /\ accDisabled' = (accDisabled \/ disabled)
         /\ accWatermark' = (accWatermark \/ (hasWm /\ rec[s].created <= wm))
         /\ accPreEnable' = (accPreEnable \/ preEnable[s])
    /\ UNCHANGED << now, rec, cookie, disabled, hasWm, wm, ra, raMode, todo, bornAt,
                    preEnable, refreshStale >>

\* refresh_session_cookie, success branch. It reads the cookie fields the
\* validation authenticated (ValidatedSession). The same node reads its clock
\* again, so the reading is now + the validation's offset. Refusal and
\* Ok(None) change nothing, so they are not separate actions.
SameRequest(v, r) == r >= v /\ r - v <= Tol
RefreshDue(c, r) == ~(c.iat > r) /\ ~(Sat(r, c.ts) < Idle \div 2)
BeforeAbs(c, r) == ~(Sat(r, c.iat) >= Abs)

Refresh(s) ==
    /\ WithRefresh
    /\ pending[s] # None
    /\ LET p == pending[s]
           c == cookie[s]
           v == p.tv + p.off
           r == now + p.off
       IN /\ SameRequest(v, r)
          /\ RefreshDue(c, r)
          /\ BeforeAbs(c, r)
          /\ cookie' = [cookie EXCEPT ![s] = [iat |-> c.iat, ts |-> r, tm |-> now]]
          /\ refreshStale' = (refreshStale \/ (now - p.tv > Tol))
    /\ pending' = [pending EXCEPT ![s] = None]
    /\ UNCHANGED << now, rec, disabled, hasWm, wm, ra, raMode, todo, bornAt, preEnable,
                    accRevoked, accPastAbs, accPastIdle, accDisabled,
                    accWatermark, accPreEnable >>

\* The request ends without a refresh.
DropPending(s) ==
    /\ pending[s] # None
    /\ pending' = [pending EXCEPT ![s] = None]
    /\ UNCHANGED << now, rec, cookie, disabled, hasWm, wm, ra, raMode, todo, bornAt, preEnable >>
    /\ UNCHANGED ghosts

Next ==
    \/ Tick
    \/ Disable
    \/ RevokeAllList
    \/ RevokeAllFail
    \/ RevokeAllDone
    \/ Enable
    \/ \E s \in Sessions :
         \/ Login(s)
         \/ Revoke(s)
         \/ RevokeAllStep(s)
         \/ Validate(s)
         \/ Refresh(s)
         \/ DropPending(s)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* SES-INV-001: a revoked session never validates.
Inv_NoAcceptRevoked == ~accRevoked

\* SES-INV-002: no session validates past its absolute lifetime. In true time
\* the bound is Abs + Skew: the login node and the validator may disagree by
\* Skew. Tol does not widen it.
Inv_NoAcceptPastAbsolute == ~accPastAbs

\* SES-INV-003: no cookie validates past its idle lifetime, measured from the
\* true time the presented cookie was minted, plus Skew.
Inv_NoAcceptPastIdle == ~accPastIdle

\* SES-INV-004: a session of a disabled owner never validates.
Inv_NoAcceptDisabledOwner == ~accDisabled

\* SES-INV-005: a session created at or before the enable watermark never
\* validates (stored values, strict >).
Inv_NoAcceptAtOrBeforeWatermark == ~accWatermark

\* SES-INV-006: refresh never changes iat. Every cookie of a session carries
\* the session row's created_at as iat.
Inv_RefreshKeepsIat ==
    \A s \in Sessions : rec[s].exists => cookie[s].iat = rec[s].created

\* SES-INV-007: refresh never mints a cookie at or past the absolute lifetime.
Inv_RefreshNeverPastAbsolute ==
    \A s \in Sessions : cookie[s].ts - cookie[s].iat < Abs

\* SES-INV-008: refresh only runs from a validation of the same request: the
\* true time between them is at most Tol.
Inv_RefreshOnlyFromFreshValidation == ~refreshStale

\* SES-INV-009: no session that existed at an enable validates afterwards
\* (true event order, independent of clocks). Checked in SessionAdmin.cfg.
\* With EnableRevokesFirst = FALSE (0.4.1) it fails once Skew > 0: a login
\* node whose clock runs ahead stamps created_at past the admin's watermark,
\* and an enable that does not wait for revocation lets the session back in.
Inv_NoPreEnableSurvivor == ~accPreEnable
==========================================================================

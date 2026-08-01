----------------------------- MODULE Session -----------------------------
(*
 Abstract model of datadeft-auth session validation.

 Checks SES-INV-001 from docs/formal-methods.md: a revoked or expired session
 never validates.

 Abstraction. The Branca cookie, keyring, and crypto are not modeled. The
 model tracks the server-side lifecycle (create, revoke via logout, expire by
 time) and interleaves validation with those transitions. Validation reads the
 current server state (a strong read).

 Teeth. The ValidateAccept guard is the validation logic. The ghost
 acceptedInvalid audits ground truth at accept time with a separate
 expression. If the guard drops the revoked or the expiry check, the audit
 flags the accept and SES-INV-001 fails.
*)
EXTENDS Naturals

CONSTANTS TTL, MaxTime

VARIABLES
    exists,           \* a session record was created
    revoked,          \* logout or compromise revoked it
    createdAt,        \* creation time (absolute-TTL anchor)
    now,              \* current time
    lastOutcome,      \* "None" | "Accepted" | "Rejected"
    acceptedInvalid   \* ghost: a validate accepted a revoked or expired session

vars == << exists, revoked, createdAt, now, lastOutcome, acceptedInvalid >>

Aged == exists /\ (now > createdAt + TTL)

TypeOK ==
    /\ exists \in BOOLEAN
    /\ revoked \in BOOLEAN
    /\ createdAt \in 0..MaxTime
    /\ now \in 0..MaxTime
    /\ lastOutcome \in {"None", "Accepted", "Rejected"}
    /\ acceptedInvalid \in BOOLEAN

Init ==
    /\ exists = FALSE
    /\ revoked = FALSE
    /\ createdAt = 0
    /\ now = 0
    /\ lastOutcome = "None"
    /\ acceptedInvalid = FALSE

Create ==
    /\ ~exists
    /\ exists' = TRUE
    /\ createdAt' = now
    /\ revoked' = FALSE
    /\ UNCHANGED << now, lastOutcome, acceptedInvalid >>

\* Logout or compromise. Server-side revocation is monotonic.
Revoke ==
    /\ exists
    /\ ~revoked
    /\ revoked' = TRUE
    /\ UNCHANGED << exists, createdAt, now, lastOutcome, acceptedInvalid >>

AdvanceTime ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED << exists, revoked, createdAt, lastOutcome, acceptedInvalid >>

\* Validation accepts only a live, unrevoked, unexpired session.
ValidateAccept ==
    /\ exists
    /\ ~revoked
    /\ ~Aged
    /\ lastOutcome' = "Accepted"
    /\ acceptedInvalid' = (acceptedInvalid \/ revoked \/ Aged)
    /\ UNCHANGED << exists, revoked, createdAt, now >>

ValidateReject ==
    /\ exists
    /\ (revoked \/ Aged)
    /\ lastOutcome' = "Rejected"
    /\ UNCHANGED << exists, revoked, createdAt, now, acceptedInvalid >>

Next ==
    \/ Create
    \/ Revoke
    \/ AdvanceTime
    \/ ValidateAccept
    \/ ValidateReject

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* SES-INV-001: a revoked or expired session never validates.
Inv001_NoInvalidAccept == ~acceptedInvalid
==========================================================================

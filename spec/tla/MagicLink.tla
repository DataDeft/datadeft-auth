---------------------------- MODULE MagicLink ----------------------------
(*
 Abstract model of the datadeft-auth magic-link authentication flow.

 Scope: one magic-link challenge and one browser session.
 Checks the safety invariants ML-INV-001..003 from docs/formal-methods.md.

 Abstraction. The token, selector, verifier, HMAC, and crypto are not
 modeled. The model assumes the crypto checks are correct and models the
 control flow and the atomic transaction. "landed" means the side-effect-free
 GET landing ran and set the confirm cookie. "Confirm" is the same-origin
 POST that atomically consumes the challenge and creates the session.
*)
EXTENDS Naturals

CONSTANT MaxTime

VARIABLES
    challenge,       \* "Absent" | "Issued" | "Consumed" | "Expired"
    session,         \* "None" | "Active" | "Revoked"
    landed,          \* the GET landing ran
    consumedByPost,  \* the consume happened via the same-origin POST
    userDisabled,
    sessionsCreated, \* count of sessions minted for this challenge
    time

vars == << challenge, session, landed, consumedByPost, userDisabled,
           sessionsCreated, time >>

TypeOK ==
    /\ challenge \in {"Absent", "Issued", "Consumed", "Expired"}
    /\ session \in {"None", "Active", "Revoked"}
    /\ landed \in BOOLEAN
    /\ consumedByPost \in BOOLEAN
    /\ userDisabled \in BOOLEAN
    /\ sessionsCreated \in 0..2
    /\ time \in 0..MaxTime

Init ==
    /\ challenge = "Absent"
    /\ session = "None"
    /\ landed = FALSE
    /\ consumedByPost = FALSE
    /\ userDisabled = FALSE
    /\ sessionsCreated = 0
    /\ time = 0

RequestLink ==
    /\ challenge = "Absent"
    /\ challenge' = "Issued"
    /\ UNCHANGED << session, landed, consumedByPost, userDisabled,
                    sessionsCreated, time >>

\* GET landing. Side-effect-free on auth state. It never consumes.
Landing ==
    /\ challenge = "Issued"
    /\ landed' = TRUE
    /\ UNCHANGED << challenge, session, consumedByPost, userDisabled,
                    sessionsCreated, time >>

\* Same-origin POST. Atomic consume plus session creation.
Confirm ==
    /\ challenge = "Issued"
    /\ landed
    /\ ~userDisabled
    /\ challenge' = "Consumed"
    /\ session' = "Active"
    /\ consumedByPost' = TRUE
    /\ sessionsCreated' = sessionsCreated + 1
    /\ UNCHANGED << landed, userDisabled, time >>

\* A disabled user cannot authenticate. The challenge is not burned.
ConfirmDisabledFails ==
    /\ challenge = "Issued"
    /\ landed
    /\ userDisabled
    /\ UNCHANGED vars

\* Retry after an ambiguous result. The commit is idempotent. No second session.
AmbiguousRetry ==
    /\ challenge = "Consumed"
    /\ UNCHANGED vars

Expire ==
    /\ challenge = "Issued"
    /\ time >= MaxTime
    /\ challenge' = "Expired"
    /\ UNCHANGED << session, landed, consumedByPost, userDisabled,
                    sessionsCreated, time >>

Disable ==
    /\ ~userDisabled
    /\ userDisabled' = TRUE
    /\ UNCHANGED << challenge, session, landed, consumedByPost,
                    sessionsCreated, time >>

Revoke ==
    /\ session = "Active"
    /\ session' = "Revoked"
    /\ UNCHANGED << challenge, landed, consumedByPost, userDisabled,
                    sessionsCreated, time >>

AdvanceTime ==
    /\ time < MaxTime
    /\ time' = time + 1
    /\ UNCHANGED << challenge, session, landed, consumedByPost,
                    userDisabled, sessionsCreated >>

Next ==
    \/ RequestLink
    \/ Landing
    \/ Confirm
    \/ ConfirmDisabledFails
    \/ AmbiguousRetry
    \/ Expire
    \/ Disable
    \/ Revoke
    \/ AdvanceTime

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* Safety invariants. See docs/formal-methods.md.

\* ML-INV-001: a consumed challenge was consumed by a POST, never a GET.
Inv001_LandingNeverConsumes ==
    (challenge = "Consumed") => consumedByPost

\* ML-INV-002: at most one session per challenge.
Inv002_AtMostOneSession ==
    sessionsCreated <= 1

\* ML-INV-003: consume and session creation are one atomic pair.
Inv003_SessionImpliesConsumed ==
    (session \in {"Active", "Revoked"}) => (challenge = "Consumed")

Inv003_ConsumedImpliesSession ==
    (challenge = "Consumed") => (session \in {"Active", "Revoked"})
==========================================================================

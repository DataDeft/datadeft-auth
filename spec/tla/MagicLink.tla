---------------------------- MODULE MagicLink ----------------------------
(*
 Abstract model of the datadeft-auth magic-link authentication flow.

 Scope: one magic-link challenge and one browser session.
 Checks the safety invariants ML-INV-001..005 from docs/formal-methods.md.

 Abstraction. The token, selector, verifier, HMAC, and crypto are not
 modeled. The model assumes the crypto checks are correct and models the
 control flow and the atomic transaction. "landed" means the side-effect-free
 GET landing ran and set the confirm cookie. "Confirm" is the same-origin
 POST that atomically consumes the challenge and creates the session.

 Bindings. The confirm cookie binds the selector, the verifier proof, and the
 account. Confirmation must present all three correctly. "ConfirmCorrect"
 presents a matching triple. "ConfirmWrongBinding" presents a mismatch in the
 selector, the verifier, or the account. The flow-cookie check rejects a
 mismatch before any consume, so a wrong binding neither authenticates nor
 burns the challenge.

 Disabled user. A confirm by a disabled user fails and does not consume the
 challenge. The user may be re-enabled, and the same challenge still works.
*)
EXTENDS Naturals

CONSTANT MaxTime

VARIABLES
    challenge,               \* "Absent" | "Issued" | "Consumed" | "Expired"
    session,                 \* "None" | "Active" | "Revoked"
    landed,                  \* the GET landing ran
    consumedByPost,          \* the consume happened via the same-origin POST
    authenticated,           \* a correct-binding POST created the session
    userDisabled,
    sessionsCreated,         \* count of sessions minted for this challenge
    rejectedWrongBinding,    \* a mismatched-binding confirm was rejected
    disabledConfirmAttempted,\* a confirm by a disabled user was rejected
    time

vars == << challenge, session, landed, consumedByPost, authenticated,
           userDisabled, sessionsCreated, rejectedWrongBinding,
           disabledConfirmAttempted, time >>

TypeOK ==
    /\ challenge \in {"Absent", "Issued", "Consumed", "Expired"}
    /\ session \in {"None", "Active", "Revoked"}
    /\ landed \in BOOLEAN
    /\ consumedByPost \in BOOLEAN
    /\ authenticated \in BOOLEAN
    /\ userDisabled \in BOOLEAN
    /\ sessionsCreated \in 0..2
    /\ rejectedWrongBinding \in BOOLEAN
    /\ disabledConfirmAttempted \in BOOLEAN
    /\ time \in 0..MaxTime

Init ==
    /\ challenge = "Absent"
    /\ session = "None"
    /\ landed = FALSE
    /\ consumedByPost = FALSE
    /\ authenticated = FALSE
    /\ userDisabled = FALSE
    /\ sessionsCreated = 0
    /\ rejectedWrongBinding = FALSE
    /\ disabledConfirmAttempted = FALSE
    /\ time = 0

RequestLink ==
    /\ challenge = "Absent"
    /\ challenge' = "Issued"
    /\ UNCHANGED << session, landed, consumedByPost, authenticated,
                    userDisabled, sessionsCreated, rejectedWrongBinding,
                    disabledConfirmAttempted, time >>

\* GET landing. Side-effect-free on auth state. It never consumes.
Landing ==
    /\ challenge = "Issued"
    /\ landed' = TRUE
    /\ UNCHANGED << challenge, session, consumedByPost, authenticated,
                    userDisabled, sessionsCreated, rejectedWrongBinding,
                    disabledConfirmAttempted, time >>

\* Same-origin POST with a matching selector, verifier, and account binding.
\* Atomic consume plus session creation.
ConfirmCorrect ==
    /\ challenge = "Issued"
    /\ landed
    /\ ~userDisabled
    /\ challenge' = "Consumed"
    /\ session' = "Active"
    /\ consumedByPost' = TRUE
    /\ authenticated' = TRUE
    /\ sessionsCreated' = sessionsCreated + 1
    /\ UNCHANGED << landed, userDisabled, rejectedWrongBinding,
                    disabledConfirmAttempted, time >>

\* Same-origin POST with a mismatched selector, verifier, or account binding.
\* The flow-cookie check rejects it. No consume, no session.
ConfirmWrongBinding ==
    /\ challenge = "Issued"
    /\ landed
    /\ rejectedWrongBinding' = TRUE
    /\ UNCHANGED << challenge, session, landed, consumedByPost, authenticated,
                    userDisabled, sessionsCreated, disabledConfirmAttempted,
                    time >>

\* A disabled user cannot authenticate. The challenge is not burned.
ConfirmDisabledFails ==
    /\ challenge = "Issued"
    /\ landed
    /\ userDisabled
    /\ disabledConfirmAttempted' = TRUE
    /\ UNCHANGED << challenge, session, landed, consumedByPost, authenticated,
                    userDisabled, sessionsCreated, rejectedWrongBinding, time >>

Expire ==
    /\ challenge = "Issued"
    /\ time >= MaxTime
    /\ challenge' = "Expired"
    /\ UNCHANGED << session, landed, consumedByPost, authenticated,
                    userDisabled, sessionsCreated, rejectedWrongBinding,
                    disabledConfirmAttempted, time >>

Disable ==
    /\ ~userDisabled
    /\ userDisabled' = TRUE
    /\ UNCHANGED << challenge, session, landed, consumedByPost, authenticated,
                    sessionsCreated, rejectedWrongBinding,
                    disabledConfirmAttempted, time >>

\* Re-enable a disabled user. The same challenge still works afterwards.
Enable ==
    /\ userDisabled
    /\ userDisabled' = FALSE
    /\ UNCHANGED << challenge, session, landed, consumedByPost, authenticated,
                    sessionsCreated, rejectedWrongBinding,
                    disabledConfirmAttempted, time >>

Revoke ==
    /\ session = "Active"
    /\ session' = "Revoked"
    /\ UNCHANGED << challenge, landed, consumedByPost, authenticated,
                    userDisabled, sessionsCreated, rejectedWrongBinding,
                    disabledConfirmAttempted, time >>

AdvanceTime ==
    /\ time < MaxTime
    /\ time' = time + 1
    /\ UNCHANGED << challenge, session, landed, consumedByPost, authenticated,
                    userDisabled, sessionsCreated, rejectedWrongBinding,
                    disabledConfirmAttempted >>

Next ==
    \/ RequestLink
    \/ Landing
    \/ ConfirmCorrect
    \/ ConfirmWrongBinding
    \/ ConfirmDisabledFails
    \/ Expire
    \/ Disable
    \/ Enable
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

\* ML-INV-004: only a correct selector, verifier, and account binding can
\* authenticate. A session exists only after a correct-binding confirm.
Inv004_SessionNeedsCorrectBinding ==
    (session \in {"Active", "Revoked"}) => authenticated

Inv004_ConsumeNeedsCorrectBinding ==
    (challenge = "Consumed") => authenticated

\* ML-INV-005: a disabled-user confirm does not burn the challenge. Until a
\* correct confirm authenticates, a rejected disabled attempt leaves the
\* challenge reusable (Issued) or, by time alone, Expired. It never consumes.
Inv005_DisabledAttemptDoesNotBurn ==
    (disabledConfirmAttempted /\ ~authenticated) =>
        (challenge \in {"Issued", "Expired"})
==========================================================================

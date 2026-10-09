----------------------------- MODULE Liveness -----------------------------
(*
 Progress (liveness) model for the magic-link happy path.

 tla-checker 0.3.9 supports the leads-to operator (~>) but not raw <>, [], or
 WF fairness. So this model checks progress with leads-to: the flow always
 reaches a session, and it does so even when a commit returns an ambiguous
 result and the client must retry.

 This is happy-path progress. It has no expiry and no disable. Conditional
 liveness under those obstacles needs fairness assumptions and a checker that
 supports WF, which is future work.
*)
VARIABLES
    challenge,   \* "Absent" | "Issued" | "Consumed"
    landed,      \* the GET landing ran
    pending,     \* a commit applied but returned an ambiguous result
    session      \* "None" | "Active"

vars == << challenge, landed, pending, session >>

Init ==
    /\ challenge = "Absent"
    /\ landed = FALSE
    /\ pending = FALSE
    /\ session = "None"

Request ==
    /\ challenge = "Absent"
    /\ challenge' = "Issued"
    /\ UNCHANGED << landed, pending, session >>

Land ==
    /\ challenge = "Issued"
    /\ ~landed
    /\ landed' = TRUE
    /\ UNCHANGED << challenge, pending, session >>

\* Commit with a definite success. Consume and create the session.
ConfirmDirect ==
    /\ challenge = "Issued"
    /\ landed
    /\ ~pending
    /\ challenge' = "Consumed"
    /\ session' = "Active"
    /\ UNCHANGED << landed, pending >>

\* Commit that applied but returned an ambiguous result. The session is not
\* known yet. The client must retry.
ConfirmAmbiguous ==
    /\ challenge = "Issued"
    /\ landed
    /\ ~pending
    /\ challenge' = "Consumed"
    /\ pending' = TRUE
    /\ UNCHANGED << landed, session >>

\* The exact retry resolves the ambiguous commit into a known session.
Retry ==
    /\ challenge = "Consumed"
    /\ pending
    /\ session' = "Active"
    /\ pending' = FALSE
    /\ UNCHANGED << challenge, landed >>

\* The flow is over once a session exists. Making success an explicit
\* self-loop means every other end state is a deadlock: the model runs
\* without --allow-deadlock, so a state where the flow gets stuck fails the
\* check. The checker evaluates leads-to on cycles only, and this graph has
\* none besides Done, so the deadlock check is what gives progress teeth.
Done ==
    /\ session = "Active"
    /\ UNCHANGED vars

Next ==
    \/ Done
    \/ Request
    \/ Land
    \/ ConfirmDirect
    \/ ConfirmAmbiguous
    \/ Retry

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* Safety: a session implies the challenge was consumed.
Inv_SessionImpliesConsumed ==
    (session = "Active") => (challenge = "Consumed")

\* Progress: the flow always reaches a session, including via retry.
Live_ReachesSession == (challenge = "Absent") ~> (session = "Active")
Live_LandedReachesSession == landed ~> (session = "Active")
==========================================================================

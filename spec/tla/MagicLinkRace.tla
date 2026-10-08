--------------------------- MODULE MagicLinkRace ---------------------------
(*
 Concurrency model: two confirmations race over ONE magic-link challenge,
 including an ambiguous transaction result and an exact-command retry.

 Checks ML-INV-002 under interleaving: at most one session per challenge, even
 when two attempts race and one sees an ambiguous commit result and retries.
 This models the atomic DynamoDB transaction and the retry contract in
 datadeft-magic-link-service (the MagicLinkAuthenticationRepository doc comment).

 The atomic commit is one TLA+ action, which models the conditional
 transaction. Only one attempt can move the challenge from Issued to Consumed.
 The loser sees a conflict. An ambiguous result means the server may or may not
 have applied the commit. The client retries the identical command, and the
 retry is idempotent.
*)
EXTENDS Naturals, FiniteSets

CONSTANT Attempts

VARIABLES
    challenge,      \* "Issued" | "Consumed"
    consumedBy,     \* the attempt that consumed the challenge, or "none"
    sessions,       \* set of attempts that hold a session
    clientStatus    \* [Attempts -> Statuses]

vars == << challenge, consumedBy, sessions, clientStatus >>

Statuses == {"pending", "committed", "conflict", "ambiguous"}

TypeOK ==
    /\ challenge \in {"Issued", "Consumed"}
    /\ consumedBy \in (Attempts \cup {"none"})
    /\ sessions \subseteq Attempts
    /\ clientStatus \in [Attempts -> Statuses]

Init ==
    /\ challenge = "Issued"
    /\ consumedBy = "none"
    /\ sessions = {}
    /\ clientStatus = [a \in Attempts |-> "pending"]

\* Attempt a finds the challenge Issued and atomically consumes it.
CommitSucceeds(a) ==
    /\ clientStatus[a] \in {"pending", "ambiguous"}
    /\ challenge = "Issued"
    /\ challenge' = "Consumed"
    /\ consumedBy' = a
    /\ sessions' = sessions \cup {a}
    /\ clientStatus' = [clientStatus EXCEPT ![a] = "committed"]

\* Attempt a finds the challenge already consumed by another attempt.
CommitConflict(a) ==
    /\ clientStatus[a] \in {"pending", "ambiguous"}
    /\ challenge = "Consumed"
    /\ consumedBy # a
    /\ clientStatus' = [clientStatus EXCEPT ![a] = "conflict"]
    /\ UNCHANGED << challenge, consumedBy, sessions >>

\* Attempt a retries after an ambiguous result and finds its own commit applied.
\* Idempotent success. No second session.
CommitIdempotent(a) ==
    /\ clientStatus[a] = "ambiguous"
    /\ challenge = "Consumed"
    /\ consumedBy = a
    /\ clientStatus' = [clientStatus EXCEPT ![a] = "committed"]
    /\ UNCHANGED << challenge, consumedBy, sessions >>

\* Attempt a's commit returns an ambiguous result. The server may or may not
\* have applied it. Either way the client sees "ambiguous" and must retry.
CommitAmbiguous(a) ==
    /\ clientStatus[a] = "pending"
    /\ challenge = "Issued"
    /\ clientStatus' = [clientStatus EXCEPT ![a] = "ambiguous"]
    /\ \/ /\ challenge' = "Consumed"
          /\ consumedBy' = a
          /\ sessions' = sessions \cup {a}
       \/ /\ UNCHANGED << challenge, consumedBy, sessions >>

Next ==
    \E a \in Attempts :
        \/ CommitSucceeds(a)
        \/ CommitConflict(a)
        \/ CommitIdempotent(a)
        \/ CommitAmbiguous(a)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* ML-INV-002 under concurrency: no double-spend.
Inv_AtMostOneSession == Cardinality(sessions) <= 1

\* A session exists only for the attempt that consumed the challenge.
Inv_SessionOnlyForConsumer ==
    sessions \subseteq (IF consumedBy = "none" THEN {} ELSE {consumedBy})

\* Consume and the recorded consumer agree.
Inv_ConsumedIffConsumer ==
    (challenge = "Consumed") <=> (consumedBy # "none")

\* A conflicted attempt never holds a session.
Inv_ConflictNoSession ==
    \A a \in Attempts : (clientStatus[a] = "conflict") => (a \notin sessions)
============================================================================

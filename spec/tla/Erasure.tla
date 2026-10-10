----------------------------- MODULE Erasure -----------------------------
(*
 GDPR erasure of one user (CeleraTax request #11, planned for 0.5.0).

 One email address E. Its lookup rows exist per storage key (K0 previous,
 K1 current, during a rotation). Magic-link records (ML# rows) hold E until
 they are consumed. Sessions belong to a user.

 erase_user is one atomic write (profile email -> placeholder, every lookup
 row for the user removed, an audit event) followed by a retry-safe second
 step that revokes the user's sessions one by one and can stop part way
 (DynamoDB transactions are bounded, so session revocation cannot share the
 atomic write).

 Design switches (TRUE is the planned design; each FALSE is a mutant):
   ErasePendingLinks   - the atomic write also deletes pending ML# rows for E
   ErasedIsInactive    - session validation rejects an erased owner at once,
                         like a disabled one, without waiting for revocation
   EraseAllKeys        - the atomic write removes lookup rows under every
                         storage key, not only the current one
*)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Users,              \* user ids, e.g. {u1, u2}
    Links,              \* magic links for E, e.g. {l1, l2}
    ErasePendingLinks,
    ErasedIsInactive,
    EraseAllKeys

None == "none"
Keys == {"K0", "K1"}

VARIABLES
    lookup,       \* [Keys -> Users \cup {None}]: E's lookup row per storage key
    created,      \* users that exist
    email,        \* [Users -> {"E", "erased"}]
    erased,       \* [Users -> BOOLEAN]
    link,         \* [Links -> {"none", "pending", "consumed", "deleted"}]
    session,      \* [Links -> [owner, revoked]]: the session a consumed link made
    revoking,     \* users whose session revocation step is still running
    \* ghosts
    eraseCount,   \* number of erasures so far
    linkEpoch,    \* [Links -> erasure count when the link was requested]
    accErased,    \* a session of an erased user validated
    resurrected   \* a link requested before an erasure created an account after it

vars == << lookup, created, email, erased, link, session, revoking,
           eraseCount, linkEpoch, accErased, resurrected >>

TypeOK ==
    /\ lookup \in [Keys -> Users \cup {None}]
    /\ created \subseteq Users
    /\ erased \in [Users -> BOOLEAN]
    /\ link \in [Links -> {"none", "pending", "consumed", "deleted"}]

\* Start mid-rotation: u1 exists, its lookup row still only under the previous
\* key K0 (rekey has not run yet).
Init ==
    /\ lookup = [k \in Keys |-> IF k = "K0" THEN "u1" ELSE None]
    /\ created = {"u1"}
    /\ email = [u \in Users |-> "E"]
    /\ erased = [u \in Users |-> FALSE]
    /\ link = [l \in Links |-> "none"]
    /\ session = [l \in Links |-> [owner |-> None, revoked |-> FALSE]]
    /\ revoking = {}
    /\ eraseCount = 0
    /\ linkEpoch = [l \in Links |-> 0]
    /\ accErased = FALSE
    /\ resurrected = FALSE

\* find_user_for_authentication: current key first, then the previous one.
Found == IF lookup["K1"] # None THEN lookup["K1"] ELSE lookup["K0"]

Request(l) ==
    /\ link[l] = "none"
    /\ link' = [link EXCEPT ![l] = "pending"]
    /\ linkEpoch' = [linkEpoch EXCEPT ![l] = eraseCount]
    /\ UNCHANGED << lookup, created, email, erased, session, revoking,
                    eraseCount, accErased, resurrected >>

\* Confirm: consume the link and sign in the found user, or create a new one
\* (with lookup rows under both keys, as during a rotation).
Consume(l) ==
    /\ link[l] = "pending"
    /\ link' = [link EXCEPT ![l] = "consumed"]
    /\ IF Found # None
         THEN /\ session' = [session EXCEPT ![l] = [owner |-> Found, revoked |-> FALSE]]
              /\ UNCHANGED << lookup, created, resurrected >>
         ELSE \E u \in Users \ created :
                /\ created' = created \cup {u}
                /\ lookup' = [k \in Keys |-> u]
                /\ session' = [session EXCEPT ![l] = [owner |-> u, revoked |-> FALSE]]
                /\ resurrected' = (resurrected \/ linkEpoch[l] < eraseCount)
    /\ UNCHANGED << email, erased, revoking, eraseCount, linkEpoch, accErased >>

\* erase_user, atomic part.
Erase(u) ==
    /\ u \in created
    /\ ~erased[u]
    /\ erased' = [erased EXCEPT ![u] = TRUE]
    /\ email' = [email EXCEPT ![u] = "erased"]
    /\ lookup' = [k \in Keys |->
                    IF lookup[k] = u /\ (EraseAllKeys \/ k = "K1") THEN None ELSE lookup[k]]
    /\ link' = IF ErasePendingLinks
                 THEN [l \in Links |-> IF link[l] = "pending" THEN "deleted" ELSE link[l]]
                 ELSE link
    /\ revoking' = revoking \cup {u}
    /\ eraseCount' = eraseCount + 1
    /\ UNCHANGED << created, session, linkEpoch, accErased, resurrected >>

\* The revocation step: one session at a time; it may stop at any point (a
\* dependency error) and be retried.
RevokeStep(l) ==
    /\ session[l].owner \in revoking
    /\ ~session[l].revoked
    /\ session' = [session EXCEPT ![l].revoked = TRUE]
    /\ UNCHANGED << lookup, created, email, erased, link, revoking,
                    eraseCount, linkEpoch, accErased, resurrected >>

RevokeDone(u) ==
    /\ u \in revoking
    /\ \A l \in Links : session[l].owner = u => session[l].revoked
    /\ revoking' = revoking \ {u}
    /\ UNCHANGED << lookup, created, email, erased, link, session,
                    eraseCount, linkEpoch, accErased, resurrected >>

\* validate_session for the session a link made.
Validate(l) ==
    /\ session[l].owner # None
    /\ ~session[l].revoked
    /\ ErasedIsInactive => ~erased[session[l].owner]
    /\ accErased' = (accErased \/ erased[session[l].owner])
    /\ UNCHANGED << lookup, created, email, erased, link, session, revoking,
                    eraseCount, linkEpoch, resurrected >>

Next ==
    \/ \E l \in Links : Request(l) \/ Consume(l) \/ RevokeStep(l) \/ Validate(l)
    \/ \E u \in Users : Erase(u) \/ RevokeDone(u)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* ERASE-INV-001: no lookup row leads to an erased user, under any key.
Inv_NoLookupToErased ==
    \A k \in Keys : lookup[k] = None \/ ~erased[lookup[k]]

\* ERASE-INV-002: an erased profile no longer holds the address.
Inv_ErasedEmailGone == \A u \in Users : erased[u] => email[u] # "E"

\* ERASE-INV-003: no session of an erased user validates, even while its
\* revocation is still running or has failed.
Inv_NoSessionForErased == ~accErased

\* ERASE-INV-004: a link requested before an erasure never creates an account
\* after it.
Inv_NoResurrection == ~resurrected

\* ERASE-INV-005: signing up again after erasure creates a new user: no
\* session made after an erasure belongs to an erased user.
Inv_NewUserAfterErase ==
    \A l \in Links :
        (link[l] = "consumed" /\ session[l].owner # None /\ linkEpoch[l] = eraseCount
         /\ eraseCount > 0)
            => ~erased[session[l].owner]
==========================================================================

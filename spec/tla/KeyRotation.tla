--------------------------- MODULE KeyRotation ---------------------------
(*
 Storage-HMAC key rotation and first signup for one email address.

 Code: crates/datadeft-magic-link-aws/src/hmac_key.rs (StorageHmacKeys),
 dynamodb/authentication.rs (find_user_for_authentication,
 authentication_transaction_request), dynamodb/rotation.rs
 (rekey_email_lookups), and the fake mirror in fake/authentication.rs.

 The email lookup row's key is HMAC(storage key, email), so the same email
 has one row position per storage key. idx[k] is the user id stored at the
 position for key k, or None.

 Nodes. During a rolling rotation two configurations serve traffic at once:
   "old": current = K0, no previous key
   "new": current = K1, previous = K0
 A signup runs on one node: find_user_for_authentication reads the current
 position, then the previous one (and copies a previous-key hit to the
 current position), and the commit transaction either checks the existing
 user's row (Existing) or creates the user (Create).

 Create writes the current-key row with attribute_not_exists. 0.4.1 writes
 only that row. The fix (DualWrite) also writes the previous-key row with
 attribute_not_exists when a previous key is configured, so a concurrent
 create on a node of the other configuration hits a condition either way.
*)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Procs,      \* concurrent signups for the same email, e.g. {p1, p2}
    DualWrite   \* FALSE is the 0.4.1 code, TRUE the fix

None == "none"
Keys == {"K0", "K1"}
Nodes == {"old", "new"}
Current(n) == IF n = "old" THEN "K0" ELSE "K1"
HasPrevious(n) == n = "new"
Previous(n) == "K0"

VARIABLES
    idx,      \* [Keys -> Procs \cup {None}]: email lookup row per key position
    users,    \* user ids (one per creating signup) with a profile row
    pc,       \* [Procs -> "start" | "found" | "done" | "conflict"]
    node,     \* [Procs -> Nodes \cup {None}]
    seen      \* [Procs -> Procs \cup {None}]: the user id find returned

vars == << idx, users, pc, node, seen >>

TypeOK ==
    /\ idx \in [Keys -> Procs \cup {None}]
    /\ users \subseteq Procs
    /\ pc \in [Procs -> {"start", "found", "done", "conflict"}]
    /\ node \in [Procs -> Nodes \cup {None}]
    /\ seen \in [Procs -> Procs \cup {None}]

Init ==
    /\ idx = [k \in Keys |-> None]
    /\ users = {}
    /\ pc = [p \in Procs |-> "start"]
    /\ node = [p \in Procs |-> None]
    /\ seen = [p \in Procs |-> None]

\* find_user_for_authentication on node n. A previous-key hit is copied to
\* the current position (put_email_lookup_if_absent).
Find(p) ==
    /\ pc[p] = "start"
    /\ \E n \in Nodes :
         LET cur == Current(n)
             hit == IF idx[cur] # None THEN idx[cur]
                    ELSE IF HasPrevious(n) THEN idx[Previous(n)] ELSE None
         IN /\ node' = [node EXCEPT ![p] = n]
            /\ seen' = [seen EXCEPT ![p] = hit]
            /\ idx' = IF hit # None /\ idx[cur] = None
                        THEN [idx EXCEPT ![cur] = hit]
                        ELSE idx
    /\ pc' = [pc EXCEPT ![p] = "found"]
    /\ UNCHANGED users

\* The commit transaction (one atomic step).
CreateConditionsHold(n) ==
    /\ idx[Current(n)] = None
    /\ (DualWrite /\ HasPrevious(n)) => idx[Previous(n)] = None

Commit(p) ==
    /\ pc[p] = "found"
    /\ LET n == node[p] IN
       IF seen[p] = None
         THEN \* Create: profile put + email row put(s), all conditional.
              IF CreateConditionsHold(n)
                THEN /\ users' = users \cup {p}
                     /\ idx' = IF DualWrite /\ HasPrevious(n)
                                 THEN [idx EXCEPT ![Current(n)] = p,
                                                  ![Previous(n)] = p]
                                 ELSE [idx EXCEPT ![Current(n)] = p]
                     /\ pc' = [pc EXCEPT ![p] = "done"]
                ELSE /\ pc' = [pc EXCEPT ![p] = "conflict"]
                     /\ UNCHANGED << users, idx >>
         ELSE \* Existing: condition check on the current-key row.
              /\ pc' = [pc EXCEPT ![p] = IF idx[Current(n)] = seen[p]
                                            THEN "done" ELSE "conflict"]
              /\ UNCHANGED << users, idx >>
    /\ UNCHANGED << node, seen >>

\* A conflict surfaces as UserConflict; the user retries from the start.
Retry(p) ==
    /\ pc[p] = "conflict"
    /\ pc' = [pc EXCEPT ![p] = "start"]
    /\ UNCHANGED << idx, users, node, seen >>

\* rekey_email_lookups on a "new" node: copy every profile's email row to the
\* current (K1) position if absent.
Rekey ==
    /\ \E u \in users :
         /\ idx["K1"] = None
         /\ idx' = [idx EXCEPT !["K1"] = u]
    /\ UNCHANGED << users, pc, node, seen >>

Next ==
    \/ Rekey
    \/ \E p \in Procs : Find(p) \/ Commit(p) \/ Retry(p)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* ROT-INV-001: one email never has two accounts.
Inv_OneAccountPerEmail == Cardinality(users) <= 1

\* ROT-INV-002: every signup that completed is signed in to the one account
\* that exists.
Inv_CompletedSignupsAgree ==
    \A p, q \in Procs :
        (pc[p] = "done" /\ pc[q] = "done") =>
            (IF seen[p] = None THEN p ELSE seen[p])
              = (IF seen[q] = None THEN q ELSE seen[q])
=============================================================================

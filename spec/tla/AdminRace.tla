----------------------------- MODULE AdminRace -----------------------------
(*
 Concurrent admin actions on one user (ADM-F1, fixed in 0.5.0).

 Each admin reads the user, then later writes the opposite state (disable or
 enable). Between the read and the write, other admins may act. The write is
 a DynamoDB conditional update: it requires the state the admin read (the
 existing `disabled = :current` condition) and, with Versioned, the profile
 version it read; it then bumps the version.

 Design switch (TRUE is the shipped design; FALSE is the 0.4 mutant):
   Versioned - the write is also conditional on the version read
*)
EXTENDS Naturals

CONSTANTS
    Admins,     \* e.g. {a1, a2}
    MaxActs,    \* actions per admin
    Versioned

VARIABLES
    disabled,   \* the stored flag
    version,    \* the stored admin version
    pc,         \* [Admins -> {"idle", "read"}]
    seenVer,    \* [Admins -> Nat]: version at the admin's read
    seenDis,    \* [Admins -> BOOLEAN]: flag at the admin's read
    acts,       \* [Admins -> Nat]: completed actions
    stale       \* ghost: a write applied although the user changed after its read

vars == << disabled, version, pc, seenVer, seenDis, acts, stale >>

Init ==
    /\ disabled = FALSE
    /\ version = 0
    /\ pc = [a \in Admins |-> "idle"]
    /\ seenVer = [a \in Admins |-> 0]
    /\ seenDis = [a \in Admins |-> FALSE]
    /\ acts = [a \in Admins |-> 0]
    /\ stale = FALSE

Read(a) ==
    /\ pc[a] = "idle"
    /\ acts[a] < MaxActs
    /\ pc' = [pc EXCEPT ![a] = "read"]
    /\ seenVer' = [seenVer EXCEPT ![a] = version]
    /\ seenDis' = [seenDis EXCEPT ![a] = disabled]
    /\ UNCHANGED << disabled, version, acts, stale >>

\* The conditional write of the opposite state; it either applies or fails
\* (Conflict / AlreadyInState), and the admin is done with this action.
Write(a) ==
    /\ pc[a] = "read"
    /\ LET ok == disabled = seenDis[a] /\ (Versioned => version = seenVer[a])
       IN IF ok
            THEN /\ disabled' = ~seenDis[a]
                 /\ version' = version + 1
                 /\ stale' = (stale \/ version # seenVer[a])
            ELSE UNCHANGED << disabled, version, stale >>
    /\ pc' = [pc EXCEPT ![a] = "idle"]
    /\ acts' = [acts EXCEPT ![a] = acts[a] + 1]
    /\ UNCHANGED << seenVer, seenDis >>

Next == \E a \in Admins : Read(a) \/ Write(a)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* ADM-INV-001: no admin write applies on top of a change it did not see.
Inv_NoStaleWrite == ~stale
==========================================================================

----------------------------- MODULE AdminRace -----------------------------
(*
 Concurrent admin actions on one user (ADM-F1, fixed in 0.5.0).

 Each admin reads the user, then later writes a disable or an enable. Between
 the read and the write, other admins may act. The write is a DynamoDB
 conditional update that bumps the profile version. An enable requires the
 user to be disabled; with Versioned it also requires the version read.

 Design switches (TRUE is the shipped design; each FALSE is a mutant):
   Versioned           - writes are conditional on the version read
   DisableAlwaysWrites - a disable of an already-disabled user still writes
                         (bumping the version), instead of succeeding as a
                         no-op that fences nothing
   RetryOnRace         - a disable whose version went stale while the user
                         stayed disabled re-reads and writes again, instead
                         of reporting success without having written
*)
EXTENDS Naturals

CONSTANTS
    Admins,     \* e.g. {a1, a2}
    MaxActs,    \* actions per admin
    Versioned,
    DisableAlwaysWrites,
    RetryOnRace,
    MaxRetries

VARIABLES
    disabled,   \* the stored flag
    version,    \* the stored admin version
    tick,       \* logical time
    pc,         \* [Admins -> {"idle", "read"}]
    wantsOff,   \* [Admins -> BOOLEAN]: TRUE = this action disables
    seenVer,    \* [Admins -> Nat]: version at the admin's read
    readAt,     \* [Admins -> Nat]: tick of the admin's read
    acts,       \* [Admins -> Nat]: completed actions
    retries,    \* [Admins -> Nat]: re-reads within the current action
    lastAck,    \* tick of the last disable reported as successful
    stale,      \* ghost: a write applied over a version it did not read
    lost        \* ghost: an enable undid a disable acknowledged after its read

vars == << disabled, version, tick, pc, wantsOff, seenVer, readAt, acts,
           retries, lastAck, stale, lost >>

Init ==
    /\ disabled = FALSE
    /\ version = 0
    /\ tick = 1
    /\ pc = [a \in Admins |-> "idle"]
    /\ wantsOff = [a \in Admins |-> FALSE]
    /\ seenVer = [a \in Admins |-> 0]
    /\ readAt = [a \in Admins |-> 0]
    /\ acts = [a \in Admins |-> 0]
    /\ retries = [a \in Admins |-> 0]
    /\ lastAck = 0
    /\ stale = FALSE
    /\ lost = FALSE

Read(a) ==
    /\ pc[a] = "idle"
    /\ acts[a] < MaxActs
    /\ \E off \in BOOLEAN : wantsOff' = [wantsOff EXCEPT ![a] = off]
    /\ pc' = [pc EXCEPT ![a] = "read"]
    /\ seenVer' = [seenVer EXCEPT ![a] = version]
    /\ readAt' = [readAt EXCEPT ![a] = tick]
    /\ retries' = [retries EXCEPT ![a] = 0]
    /\ tick' = tick + 1
    /\ UNCHANGED << disabled, version, acts, lastAck, stale, lost >>

VersionOk(a) == Versioned => version = seenVer[a]

\* Finish the admin's action.
Done(a) ==
    /\ pc' = [pc EXCEPT ![a] = "idle"]
    /\ acts' = [acts EXCEPT ![a] = acts[a] + 1]
    /\ UNCHANGED << wantsOff, seenVer, readAt, retries >>

\* A disable applies if the version holds (and, in the mutant, only if the
\* user is enabled). It is reported as successful only when it applied, or,
\* without DisableAlwaysWrites, when the user was already disabled (a no-op);
\* without RetryOnRace, also when it lost the version race but the user is
\* still disabled. With RetryOnRace it re-reads and tries again instead.
Disable(a) ==
    LET applies == VersionOk(a) /\ (DisableAlwaysWrites \/ ~disabled)
        noop    == ~DisableAlwaysWrites /\ disabled /\ VersionOk(a)
        raced   == ~applies /\ ~noop /\ disabled
    IN IF raced /\ RetryOnRace /\ retries[a] < MaxRetries
         THEN \* Re-read and write again (a fresh read of the version).
              /\ seenVer' = [seenVer EXCEPT ![a] = version]
              /\ retries' = [retries EXCEPT ![a] = retries[a] + 1]
              /\ UNCHANGED << disabled, version, stale, lastAck, lost, pc, acts,
                              wantsOff, readAt >>
         ELSE /\ disabled' = (disabled \/ applies)
              /\ version' = IF applies THEN version + 1 ELSE version
              /\ stale' = (stale \/ (applies /\ version # seenVer[a]))
              /\ lastAck' = IF applies \/ noop \/ (raced /\ ~RetryOnRace)
                               THEN tick ELSE lastAck
              /\ UNCHANGED lost
              /\ Done(a)

\* An enable: applies only to a disabled user whose version holds.
Enable(a) ==
    LET applies == disabled /\ VersionOk(a)
    IN /\ disabled' = (disabled /\ ~applies)
       /\ version' = IF applies THEN version + 1 ELSE version
       /\ stale' = (stale \/ (applies /\ version # seenVer[a]))
       /\ lost' = (lost \/ (applies /\ lastAck > readAt[a]))
       /\ UNCHANGED lastAck
       /\ Done(a)

Write(a) ==
    /\ pc[a] = "read"
    /\ IF wantsOff[a] THEN Disable(a) ELSE Enable(a)
    /\ tick' = tick + 1

Next == \E a \in Admins : Read(a) \/ Write(a)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* ADM-INV-001: no admin write applies on top of a change it did not see.
Inv_NoStaleWrite == ~stale

\* ADM-INV-002: an enable never undoes a disable that was reported as
\* successful after the enable read the user.
Inv_NoLostDisable == ~lost
==========================================================================

---------------------------- MODULE PowBudget ----------------------------
(*
 Per-solve PoW budget (CeleraTax request #8, planned for 0.5.0).

 One solved proof (one `tid`) is presented to any of several nodes while it is
 valid (Lifetime ticks from its issue). Each admission spends one unit of the
 proof's budget. The limiter can be unavailable.

 Design switches (TRUE is the planned design; each FALSE is a mutant):
   Shared          - one budget counter for all nodes (the shared limiter),
                     not one per node
   OverLifetime    - the budget is counted over the proof's whole lifetime,
                     not per fixed window that refills while the proof lives
   FailClosed      - an unavailable limiter denies; it never admits uncounted
*)
EXTENDS Naturals

CONSTANTS
    Nodes,      \* e.g. {n1, n2}
    Budget,     \* admissions per proof
    Lifetime,   \* ticks the proof is valid
    Window,     \* window length when OverLifetime = FALSE
    Shared,
    OverLifetime,
    FailClosed

VARIABLES
    now,        \* ticks since the proof was issued
    counter,    \* [Nodes -> Nat]: per-node counters (only node n1's is used when Shared)
    windowOf,   \* [Nodes -> Nat]: the window each counter belongs to
    down,       \* the limiter is unavailable
    admitted    \* ghost: admissions with this proof, across all nodes

vars == << now, counter, windowOf, down, admitted >>

\* The counter a node consults.
Slot(n) == IF Shared THEN CHOOSE m \in Nodes : TRUE ELSE n
CurrentWindow == IF OverLifetime THEN 0 ELSE now \div Window
Spent(n) == IF windowOf[Slot(n)] = CurrentWindow THEN counter[Slot(n)] ELSE 0

Init ==
    /\ now = 0
    /\ counter = [n \in Nodes |-> 0]
    /\ windowOf = [n \in Nodes |-> 0]
    /\ down = FALSE
    /\ admitted = 0

Tick ==
    /\ now < Lifetime
    /\ now' = now + 1
    /\ UNCHANGED << counter, windowOf, down, admitted >>

LimiterFlip ==
    /\ down' = ~down
    /\ UNCHANGED << now, counter, windowOf, admitted >>

\* A request with the proof reaches node n while the proof is valid.
Admit(n) ==
    /\ now < Lifetime
    /\ IF down
         THEN \* Fail open admits without counting; fail closed admits nothing.
              /\ ~FailClosed
              /\ admitted' = admitted + 1
              /\ UNCHANGED << counter, windowOf >>
         ELSE /\ Spent(n) < Budget
              /\ counter' = [counter EXCEPT ![Slot(n)] = Spent(n) + 1]
              /\ windowOf' = [windowOf EXCEPT ![Slot(n)] = CurrentWindow]
              /\ admitted' = admitted + 1
    /\ UNCHANGED << now, down >>

Next == Tick \/ LimiterFlip \/ \E n \in Nodes : Admit(n)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* POW-INV-004: one solve buys at most Budget admissions, across all nodes and
\* its whole lifetime, whatever the limiter's availability.
Inv_BudgetPerSolve == admitted <= Budget
==========================================================================

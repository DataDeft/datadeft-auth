------------------------------- MODULE Pow -------------------------------
(*
 Abstract model of the datadeft-auth proof-of-work admission difficulty.

 Checks POW-INV-001 and POW-INV-002 from docs/formal-methods.md.

 Key property: the difficulty is bound into the challenge at mint time. A
 country or policy change after mint cannot lower the bar for that challenge.
 The server verifies a solution against the bound difficulty, never against
 the current effective difficulty.
*)
EXTENDS Naturals

CONSTANTS Floor, Base, MaxDiff

Max2(a, b) == IF a >= b THEN a ELSE b
Max3(a, b, c) == Max2(Max2(a, b), c)

VARIABLES
    challenge,    \* "Absent" | "Issued" | "Expired"
    countryReq,   \* 0..MaxDiff, policy can raise or lower it for new challenges
    mintedDiff,   \* difficulty bound into the challenge at mint (immutable)
    admission,    \* "Pending" | "Accepted"
    acceptedWork  \* leading-zero work of the accepted solution

vars == << challenge, countryReq, mintedDiff, admission, acceptedWork >>

Effective == Max3(Floor, Base, countryReq)

TypeOK ==
    /\ challenge \in {"Absent", "Issued", "Expired"}
    /\ countryReq \in 0..MaxDiff
    /\ mintedDiff \in 0..MaxDiff
    /\ admission \in {"Pending", "Accepted"}
    /\ acceptedWork \in 0..MaxDiff

Init ==
    /\ challenge = "Absent"
    /\ countryReq = 0
    /\ mintedDiff = 0
    /\ admission = "Pending"
    /\ acceptedWork = 0

\* Country/policy update. It may raise or lower the requirement for new mints.
PolicyUpdate ==
    /\ countryReq' \in 0..MaxDiff
    /\ UNCHANGED << challenge, mintedDiff, admission, acceptedWork >>

\* Mint binds the current effective difficulty into the challenge.
Mint ==
    /\ challenge = "Absent"
    /\ challenge' = "Issued"
    /\ mintedDiff' = Effective
    /\ UNCHANGED << countryReq, admission, acceptedWork >>

\* Verify a solution against the BOUND minted difficulty. A later policy change
\* cannot lower this bar. The server accepts only work >= mintedDiff.
SolveVerify ==
    /\ challenge = "Issued"
    /\ admission = "Pending"
    /\ \E w \in 0..MaxDiff :
         /\ w >= mintedDiff
         /\ acceptedWork' = w
    /\ admission' = "Accepted"
    /\ UNCHANGED << challenge, countryReq, mintedDiff >>

Expire ==
    /\ challenge = "Issued"
    /\ challenge' = "Expired"
    /\ UNCHANGED << countryReq, mintedDiff, admission, acceptedWork >>

Next ==
    \/ PolicyUpdate
    \/ Mint
    \/ SolveVerify
    \/ Expire

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* POW-INV-001: an accepted proof met the production floor.
Inv001_AcceptedMeetsFloor ==
    (admission = "Accepted") => (acceptedWork >= Floor)

\* POW-INV-002: an accepted proof met the difficulty bound into its challenge.
\* This is the monotonicity guard. A policy decrease after mint cannot lower it.
Inv002_AcceptedMeetsMint ==
    (admission = "Accepted") => (acceptedWork >= mintedDiff)

\* Every minted challenge sits at or above the production floor.
Inv002_MintMeetsFloor ==
    (challenge # "Absent") => (mintedDiff >= Floor)
==========================================================================

------------------------------- MODULE Pow -------------------------------
(*
 Abstract model of datadeft-auth proof-of-work admission difficulty, with
 country risk classes.

 Checks POW-INV-001 and POW-INV-002 from docs/formal-methods.md.

 Each country has a required difficulty (its risk class), which the policy can
 raise or lower over time. A challenge minted for a country binds the effective
 difficulty at mint time. The server verifies a solution against that bound
 difficulty, never against the current effective difficulty. A later policy
 change, up or down, cannot lower the bar for an already-minted challenge.
*)
EXTENDS Naturals

CONSTANTS Floor, Base, MaxDiff, Countries

Max2(a, b) == IF a >= b THEN a ELSE b
Max3(a, b, c) == Max2(Max2(a, b), c)

VARIABLES
    countryDiff,  \* [Countries -> 0..MaxDiff], the risk class per country
    challenge,    \* "Absent" | "Issued" | "Expired"
    mintCountry,  \* country the challenge was minted for, or "none"
    mintedDiff,   \* difficulty bound into the challenge at mint (immutable)
    admission,    \* "Pending" | "Accepted"
    acceptedWork

vars == << countryDiff, challenge, mintCountry, mintedDiff, admission,
           acceptedWork >>

Effective(c) == Max3(Floor, Base, countryDiff[c])

TypeOK ==
    /\ countryDiff \in [Countries -> 0..MaxDiff]
    /\ challenge \in {"Absent", "Issued", "Expired"}
    /\ mintCountry \in (Countries \cup {"none"})
    /\ mintedDiff \in 0..MaxDiff
    /\ admission \in {"Pending", "Accepted"}
    /\ acceptedWork \in 0..MaxDiff

Init ==
    /\ countryDiff = [c \in Countries |-> 0]
    /\ challenge = "Absent"
    /\ mintCountry = "none"
    /\ mintedDiff = 0
    /\ admission = "Pending"
    /\ acceptedWork = 0

\* Policy update. Raise or lower one country's required difficulty.
PolicyUpdate ==
    /\ \E c \in Countries, v \in 0..MaxDiff :
         countryDiff' = [countryDiff EXCEPT ![c] = v]
    /\ UNCHANGED << challenge, mintCountry, mintedDiff, admission, acceptedWork >>

\* Mint binds the effective difficulty for the chosen country at mint time.
Mint ==
    /\ challenge = "Absent"
    /\ \E c \in Countries :
         /\ challenge' = "Issued"
         /\ mintCountry' = c
         /\ mintedDiff' = Effective(c)
    /\ UNCHANGED << countryDiff, admission, acceptedWork >>

\* Verify a solution against the BOUND minted difficulty. A later policy change
\* cannot lower this bar.
SolveVerify ==
    /\ challenge = "Issued"
    /\ admission = "Pending"
    /\ \E w \in 0..MaxDiff :
         /\ w >= mintedDiff
         /\ acceptedWork' = w
    /\ admission' = "Accepted"
    /\ UNCHANGED << countryDiff, challenge, mintCountry, mintedDiff >>

Expire ==
    /\ challenge = "Issued"
    /\ challenge' = "Expired"
    /\ UNCHANGED << countryDiff, mintCountry, mintedDiff, admission, acceptedWork >>

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
\* A policy change after mint, for any country, cannot lower this bar.
Inv002_AcceptedMeetsMint ==
    (admission = "Accepted") => (acceptedWork >= mintedDiff)

\* Every minted challenge sits at or above the production floor.
Inv003_MintMeetsFloor ==
    (challenge # "Absent") => (mintedDiff >= Floor)
==========================================================================

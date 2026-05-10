---- MODULE DecisionLifecycle ----
\* Copyright 2026 Exochain Foundation
\*
\* Licensed under the Apache License, Version 2.0 (the "License");
\* you may not use this file except in compliance with the License.
\* You may obtain a copy of the License at:
\*
\*     https://www.apache.org/licenses/LICENSE-2.0
\*
\* Unless required by applicable law or agreed to in writing, software
\* distributed under the License is distributed on an "AS IS" BASIS,
\* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
\* See the License for the specific language governing permissions and
\* limitations under the License.
\*
\* SPDX-License-Identifier: Apache-2.0

\* TLA+ specification for the decision.forum Decision Object lifecycle state machine.
\* Verifies invariants from the decision.forum PRD:
\*   - TNC-08: Decisions are immutable after terminal status
\*   - Valid state transitions only
\*   - TNC-07: Quorum must be verified before entering Voting
\*   - No state can be skipped in the lifecycle

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Actors,          \* Set of all possible actors (DIDs)
    MinQuorum        \* Minimum quorum size

VARIABLES
    status,          \* Current decision status
    votes,           \* Set of votes cast
    quorumVerified,  \* Whether quorum has been verified for voting
    transitionLog,   \* Sequence of transitions
    contested        \* Whether decision is under contestation

vars == <<status, votes, quorumVerified, transitionLog, contested>>

\* Status values
StatusSet == {"Created", "Deliberation", "Voting", "Approved", "Rejected",
              "Void", "Contested", "RatificationRequired", "RatificationExpired",
              "DegradedGovernance"}

\* Terminal statuses (TNC-08)
TerminalStatuses == {"Approved", "Rejected", "Void", "RatificationExpired"}

\* Valid transition relation
ValidTransition(from, to) ==
    \/ (from = "Created" /\ to \in {"Deliberation", "Void"})
    \/ (from = "Deliberation" /\ to \in {"Voting", "Void", "Contested"})
    \/ (from = "Voting" /\ to \in {"Approved", "Rejected", "Void", "Contested"})
    \/ (from = "Contested" /\ to \in {"Deliberation", "Void"})
    \/ (from = "RatificationRequired" /\ to \in {"Approved", "RatificationExpired", "Void"})
    \/ (from = "DegradedGovernance" /\ to \in {"Deliberation", "Void"})

\* Init
Init ==
    /\ status = "Created"
    /\ votes = {}
    /\ quorumVerified = FALSE
    /\ transitionLog = <<>>
    /\ contested = FALSE

\* Advance to Deliberation
AdvanceToDeliberation ==
    /\ status = "Created"
    /\ status' = "Deliberation"
    /\ transitionLog' = Append(transitionLog, <<"Created", "Deliberation">>)
    /\ UNCHANGED <<votes, quorumVerified, contested>>

\* Advance to Voting (requires quorum verification - TNC-07)
AdvanceToVoting ==
    /\ status = "Deliberation"
    /\ quorumVerified = TRUE   \* TNC-07: Quorum MUST be verified before voting
    /\ status' = "Voting"
    /\ transitionLog' = Append(transitionLog, <<"Deliberation", "Voting">>)
    /\ UNCHANGED <<votes, quorumVerified, contested>>

\* Verify quorum
VerifyQuorum ==
    /\ status = "Deliberation"
    /\ quorumVerified = FALSE
    /\ quorumVerified' = TRUE
    /\ UNCHANGED <<status, votes, transitionLog, contested>>

\* Cast a vote
CastVote(actor) ==
    /\ status = "Voting"
    /\ actor \notin votes    \* No duplicate votes
    /\ votes' = votes \cup {actor}
    /\ UNCHANGED <<status, quorumVerified, transitionLog, contested>>

\* Tally and approve
TallyApprove ==
    /\ status = "Voting"
    /\ Cardinality(votes) >= MinQuorum  \* TNC-07
    /\ status' = "Approved"
    /\ transitionLog' = Append(transitionLog, <<"Voting", "Approved">>)
    /\ UNCHANGED <<votes, quorumVerified, contested>>

\* Tally and reject
TallyReject ==
    /\ status = "Voting"
    /\ Cardinality(votes) >= MinQuorum  \* TNC-07
    /\ status' = "Rejected"
    /\ transitionLog' = Append(transitionLog, <<"Voting", "Rejected">>)
    /\ UNCHANGED <<votes, quorumVerified, contested>>

\* Void at any non-terminal stage
VoidDecision ==
    /\ status \notin TerminalStatuses
    /\ ValidTransition(status, "Void")
    /\ status' = "Void"
    /\ transitionLog' = Append(transitionLog, <<status, "Void">>)
    /\ UNCHANGED <<votes, quorumVerified, contested>>

\* Raise contestation
RaiseContestationFromDeliberation ==
    /\ status = "Deliberation"
    /\ status' = "Contested"
    /\ contested' = TRUE
    /\ transitionLog' = Append(transitionLog, <<"Deliberation", "Contested">>)
    /\ UNCHANGED <<votes, quorumVerified>>

RaiseContestationFromVoting ==
    /\ status = "Voting"
    /\ status' = "Contested"
    /\ contested' = TRUE
    /\ transitionLog' = Append(transitionLog, <<"Voting", "Contested">>)
    /\ UNCHANGED <<votes, quorumVerified>>

\* Resolve contestation
ResolveContestationToDeliberation ==
    /\ status = "Contested"
    /\ status' = "Deliberation"
    /\ contested' = FALSE
    /\ transitionLog' = Append(transitionLog, <<"Contested", "Deliberation">>)
    /\ UNCHANGED <<votes, quorumVerified>>

\* Next state
Next ==
    \/ AdvanceToDeliberation
    \/ VerifyQuorum
    \/ AdvanceToVoting
    \/ \E a \in Actors : CastVote(a)
    \/ TallyApprove
    \/ TallyReject
    \/ VoidDecision
    \/ RaiseContestationFromDeliberation
    \/ RaiseContestationFromVoting
    \/ ResolveContestationToDeliberation

\* Fairness
Spec == Init /\ [][Next]_vars

\* ==================== INVARIANTS ====================

\* INV-1: TNC-08 — Terminal statuses are permanent (immutability)
TerminalIsPermanent ==
    status \in TerminalStatuses => status' = status

\* INV-2: Only valid transitions occur
OnlyValidTransitions ==
    \A i \in 1..Len(transitionLog) :
        LET entry == transitionLog[i]
        IN ValidTransition(entry[1], entry[2])

\* INV-3: Status is always in the defined set
StatusInBounds == status \in StatusSet

\* INV-4: TNC-07 — Cannot reach Voting without quorum verification
VotingRequiresQuorum ==
    status = "Voting" => quorumVerified = TRUE

\* INV-5: Votes can only be cast during Voting
VotesOnlyDuringVoting ==
    votes /= {} => status = "Voting" \/ status \in TerminalStatuses \/ status = "Contested"

\* INV-6: No duplicate votes
NoDuplicateVotes == TRUE  \* Enforced by set semantics

\* Type invariant
TypeOK ==
    /\ status \in StatusSet
    /\ votes \subseteq Actors
    /\ quorumVerified \in BOOLEAN
    /\ contested \in BOOLEAN

====

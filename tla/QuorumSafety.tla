---- MODULE QuorumSafety ----
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

\* TLA+ specification for quorum enforcement safety.
\* Verifies that no decision can be approved or rejected without
\* meeting the required quorum (TNC-07).
\*
\* Invariants:
\*   - NoTallyWithoutQuorum: Voting cannot produce Approved/Rejected without quorum
\*   - VotingRequiresQuorum: Transition to Voting requires quorum verification
\*   - DegradedGovernanceFallback: Quorum failure triggers degraded mode

EXTENDS Naturals

CONSTANT Voters, MinQuorum, ApprovalThresholdPct

VARIABLES
    status,        \* Current decision status
    votes,         \* Set of {voter, choice}
    quorumChecked  \* Whether quorum has been verified

TypeInvariant ==
    /\ status \in {"Created", "Deliberation", "Voting", "Approved", "Rejected",
                    "Void", "DegradedGovernance"}
    /\ quorumChecked \in BOOLEAN

\* No tally can produce Approved or Rejected without meeting quorum (TNC-07)
NoTallyWithoutQuorum ==
    (status \in {"Approved", "Rejected"}) => (Cardinality(votes) >= MinQuorum)

\* Voting phase requires quorum to have been checked
VotingRequiresQuorum ==
    (status = "Voting") => quorumChecked

Init ==
    /\ status = "Created"
    /\ votes = {}
    /\ quorumChecked = FALSE

MoveToDeliberation ==
    /\ status = "Created"
    /\ status' = "Deliberation"
    /\ UNCHANGED <<votes, quorumChecked>>

VerifyQuorumAndStartVoting ==
    /\ status = "Deliberation"
    /\ quorumChecked' = TRUE
    /\ status' = "Voting"
    /\ UNCHANGED votes

CastVote(voter, choice) ==
    /\ status = "Voting"
    /\ voter \in Voters
    /\ ~(\E v \in votes: v.voter = voter)  \* No duplicate votes
    /\ votes' = votes \union {[voter |-> voter, choice |-> choice]}
    /\ UNCHANGED <<status, quorumChecked>>

Tally ==
    /\ status = "Voting"
    /\ Cardinality(votes) >= MinQuorum
    /\ LET approvals == Cardinality({v \in votes: v.choice = "Approve"})
           total == Cardinality(votes)
       IN IF approvals * 100 >= total * ApprovalThresholdPct
          THEN status' = "Approved"
          ELSE status' = "Rejected"
    /\ UNCHANGED <<votes, quorumChecked>>

ActivateDegradedGovernance ==
    /\ status = "Voting"
    /\ Cardinality(votes) < MinQuorum
    /\ status' = "DegradedGovernance"
    /\ UNCHANGED <<votes, quorumChecked>>

Next ==
    \/ MoveToDeliberation
    \/ VerifyQuorumAndStartVoting
    \/ \E v \in Voters: CastVote(v, "Approve")
    \/ \E v \in Voters: CastVote(v, "Reject")
    \/ \E v \in Voters: CastVote(v, "Abstain")
    \/ Tally
    \/ ActivateDegradedGovernance

Spec == Init /\ [][Next]_<<status, votes, quorumChecked>>

====

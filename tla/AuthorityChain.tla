---- MODULE AuthorityChain ----
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

\* TLA+ specification for authority chain verification in decision.forum.
\* Verifies invariants from the decision.forum PRD:
\*   - TNC-01: Every action requires verified authority chain (no bypass)
\*   - TNC-02: Human gate for certain decision classes
\*   - TNC-05: Immediate delegation expiry (no grace period)
\*   - TNC-09: AI agent delegation ceiling

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Actors,          \* Set of all actors
    HumanActors,     \* Subset of human actors
    AiActors,        \* Subset of AI actors
    MaxDepth,        \* Maximum delegation chain depth
    CurrentTime      \* Current timestamp for expiry checking

VARIABLES
    delegations,     \* Set of active delegations
    actionLog,       \* Log of attempted actions
    verified         \* Whether current action was verified

vars == <<delegations, actionLog, verified>>

\* A delegation record
\* [delegator: Actor, delegatee: Actor, scope: STRING, expiresAt: Nat, revoked: BOOLEAN]

\* Decision classes
DecisionClasses == {"Operational", "Strategic", "Constitutional", "Emergency"}

\* Classes requiring human gate (TNC-02)
HumanGateClasses == {"Strategic", "Constitutional", "Emergency"}

\* Actions forbidden for AI (TNC-09)
AiForbiddenActions == {"AmendConstitution", "GrantDelegation"}

\* Init
Init ==
    /\ delegations = {}
    /\ actionLog = <<>>
    /\ verified = FALSE

\* Grant a delegation
GrantDelegation(delegator, delegatee, scope, expiresAt) ==
    /\ delegator \in Actors
    /\ delegatee \in Actors
    /\ delegator /= delegatee
    /\ expiresAt > CurrentTime
    /\ delegations' = delegations \cup
        {[delegator |-> delegator, delegatee |-> delegatee,
          scope |-> scope, expiresAt |-> expiresAt, revoked |-> FALSE]}
    /\ UNCHANGED <<actionLog, verified>>

\* Revoke a delegation
RevokeDelegation(delegator, delegatee) ==
    /\ \E d \in delegations :
        /\ d.delegator = delegator
        /\ d.delegatee = delegatee
        /\ d.revoked = FALSE
        /\ delegations' = (delegations \ {d}) \cup
            {[d EXCEPT !.revoked = TRUE]}
    /\ UNCHANGED <<actionLog, verified>>

\* TNC-01: Attempt an action (MUST go through verification)
AttemptAction(actor, action, decisionClass) ==
    /\ \* Check if actor has valid delegation chain
       \E d \in delegations :
        /\ d.delegatee = actor
        /\ d.revoked = FALSE
        /\ d.expiresAt > CurrentTime     \* TNC-05: strict expiry
        /\ d.scope = decisionClass
    /\ \* TNC-02: Human gate check
       (decisionClass \in HumanGateClasses => actor \in HumanActors)
    /\ \* TNC-09: AI ceiling check
       (actor \in AiActors => action \notin AiForbiddenActions)
    /\ verified' = TRUE
    /\ actionLog' = Append(actionLog, [actor |-> actor, action |-> action,
                                        class |-> decisionClass, verified |-> TRUE])
    /\ UNCHANGED delegations

\* Attempt an action WITHOUT verification (should never succeed in correct system)
AttemptUnverifiedAction(actor, action, decisionClass) ==
    /\ verified' = FALSE
    /\ actionLog' = Append(actionLog, [actor |-> actor, action |-> action,
                                        class |-> decisionClass, verified |-> FALSE])
    /\ UNCHANGED delegations

\* Next state
Next ==
    \/ \E d1, d2 \in Actors, s \in DecisionClasses, t \in (CurrentTime+1)..(CurrentTime+100) :
        GrantDelegation(d1, d2, s, t)
    \/ \E d1, d2 \in Actors : RevokeDelegation(d1, d2)
    \/ \E a \in Actors, act \in {"CreateDecision", "CastVote", "AmendConstitution", "GrantDelegation"},
         c \in DecisionClasses :
        AttemptAction(a, act, c)

Spec == Init /\ [][Next]_vars

\* ==================== INVARIANTS ====================

\* INV-1: TNC-01 — Every logged action was verified (no bypass)
AllActionsVerified ==
    \A i \in 1..Len(actionLog) :
        actionLog[i].verified = TRUE

\* INV-2: TNC-02 — No AI actor performs human-gated actions
HumanGateIntegrity ==
    \A i \in 1..Len(actionLog) :
        actionLog[i].class \in HumanGateClasses =>
            actionLog[i].actor \in HumanActors

\* INV-3: TNC-09 — AI actors never perform forbidden actions
AiCeilingRespected ==
    \A i \in 1..Len(actionLog) :
        actionLog[i].actor \in AiActors =>
            actionLog[i].action \notin AiForbiddenActions

\* INV-4: TNC-05 — No delegation is used after expiry
NoExpiredDelegationsUsed ==
    \A i \in 1..Len(actionLog) :
        actionLog[i].verified = TRUE =>
            \E d \in delegations :
                /\ d.delegatee = actionLog[i].actor
                /\ d.expiresAt > CurrentTime
                /\ d.revoked = FALSE

\* Type invariant
TypeOK ==
    /\ verified \in BOOLEAN
    /\ \A d \in delegations :
        /\ d.delegator \in Actors
        /\ d.delegatee \in Actors
        /\ d.expiresAt \in Nat
        /\ d.revoked \in BOOLEAN

====

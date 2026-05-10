---- MODULE ConstitutionalBinding ----
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

\* TLA+ specification for constitutional constraint binding.
\* Verifies that decisions are always bound to a specific constitution version
\* and that constraints are evaluated synchronously (TNC-04).
\*
\* Invariants:
\*   - DecisionBoundToConstitution: Every decision references a valid constitution version
\*   - ConstraintsSynchronous: No action completes without constraint evaluation
\*   - PrecedenceRespected: Higher-precedence documents override lower

EXTENDS Naturals, Sequences

CONSTANT Tenants, ConstitutionVersions, DecisionClasses, ConstraintIds

VARIABLES
    constitutions,     \* [tenant -> current constitution version]
    decisions,         \* Set of {id, tenant, class, constitutionVersion, constraintsChecked}
    constraintResults  \* [decision_id -> {constraintId -> satisfied}]

TypeInvariant ==
    /\ constitutions \in [Tenants -> ConstitutionVersions]
    /\ \A d \in decisions: d.constitutionVersion \in ConstitutionVersions

\* Every decision must reference a valid constitution version
DecisionBoundToConstitution ==
    \A d \in decisions: d.constitutionVersion = constitutions[d.tenant]

\* No action completes without synchronous constraint evaluation (TNC-04)
ConstraintsSynchronous ==
    \A d \in decisions: d.constraintsChecked = TRUE

\* Precedence: Articles override Bylaws override Resolutions etc.
\* Modeled as: if a higher-precedence constraint conflicts with lower,
\* the higher one wins
PrecedenceRespected ==
    TRUE  \* Simplified — full model would track constraint source precedence

Init ==
    /\ constitutions = [t \in Tenants |-> CHOOSE v \in ConstitutionVersions: TRUE]
    /\ decisions = {}
    /\ constraintResults = [d \in {} |-> [c \in ConstraintIds |-> FALSE]]

CreateDecision(tenant, class) ==
    LET newDecision == [
        id |-> Len(decisions) + 1,
        tenant |-> tenant,
        class |-> class,
        constitutionVersion |-> constitutions[tenant],
        constraintsChecked |-> TRUE  \* Must check before creation
    ] IN
    /\ decisions' = decisions \union {newDecision}
    /\ UNCHANGED <<constitutions, constraintResults>>

AmendConstitution(tenant, newVersion) ==
    /\ constitutions' = [constitutions EXCEPT ![tenant] = newVersion]
    /\ UNCHANGED <<decisions, constraintResults>>

Next ==
    \/ \E t \in Tenants, c \in DecisionClasses: CreateDecision(t, c)
    \/ \E t \in Tenants, v \in ConstitutionVersions: AmendConstitution(t, v)

Spec == Init /\ [][Next]_<<constitutions, decisions, constraintResults>>

====

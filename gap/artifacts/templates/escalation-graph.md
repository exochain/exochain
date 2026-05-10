<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Template: Escalation Graph

*Instructions for Artifact Builder: Define the human-in-the-loop routing logic. Provide a clear DAG topology for fallback behaviors.*

## 1. Trigger Conditions
*What causes an escalation?*
- Trigger 1: [e.g., Policy Gate FIN-01 Failure (Transaction > $10k)]
- Trigger 2: [e.g., Agent confidence score falls below 70%]
- Trigger 3: [e.g., External API timeout 3x consecutively]

## 2. The Graph (Node/Edge Format)
*Map the routing flow.*

**Node A: [Agent encounters Trigger 1]**
   |
   +-- (Edge 1: Immediate alert) --> **Node B: [Primary Human (e.g., CFO)]**
   
**Node B: [Primary Human]**
   |
   +-- (If Approved) --> **Node C: [Execute Action & Anchor]**
   |
   +-- (If Denied) --> **Node D: [Halt Action & Anchor]**
   |
   +-- (If Timeout > 15 mins) --> **Node E: [Fallback Routing]**

**Node E: [Fallback Routing]**
   |
   +-- (Edge: Notify) --> **Node F: [Secondary Human (e.g., Operations VP)]**
   |
   +-- (Edge: System Action) --> **Node G: [Fail-Safe Auto-Reject]**

## 3. Timeout Rules
*Strict definitions for how long the system waits for a human.*
- T0 Operations: No wait, auto-execute.
- T1 Operations: Wait 1 hour. If no response, escalate to Secondary.
- T2 Operations (Critical): Wait indefinitely. System halts until explicitly resolved.

## 4. Human Gate Placement
*Where are the hard stops?*
- [e.g., Between Draft and Submit phases for all external communications.]

---
**Approval Block**
- Prepared by: `artifact-builder`
- Council Status: `[Draft / Governed]`
- CEO Signature: `[Pending]`
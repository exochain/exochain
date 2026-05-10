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

# Council Configuration

This configuration defines the rules of engagement for the 5-panel Decision Forum within the `gap/` incubator.

## Panel Composition
The Forum consists of five distinct panels, representing the core ExoChain operational disciplines:
1. **Governance (4-16)**: Evaluates democratic legitimacy and delegation bounds.
2. **Legal (4-18)**: Evaluates compliance, liability, and regulatory alignment.
3. **Architecture (4-20)**: Evaluates structural integrity, Syntaxis validity, and DAG integration.
4. **Security (4-17)**: Evaluates cryptographic boundaries, threat vectors, and access controls.
5. **Operations (4-19)**: Evaluates execution feasibility, latency, and real-world impact.

## Quorum and Confidence Rules
- **Quorum**: All 5 panels must register a vote (Approve, Reject, or Abstain) for a resolution to be valid.
- **T1 Confidence Threshold**: Standard GAP deliverables require a 4/5 approval ratio to achieve the `Governed` state.
- **T2 Confidence Threshold**: Self-Development modifications (Syntaxis patches) require a unanimous 5/5 approval ratio.

## Escalation Paths
- **Deadlock**: If a proposal fails to reach the required threshold after 3 revision attempts, it is flagged as `Escalated`.
- **Resolution**: Deadlocked operational proposals are escalated directly to the CEO for executive override. Deadlocked self-development (system) proposals are escalated to the human ExoChain engineering team.

## Special Rules: CEO-as-Client Scenarios
In the incubator, the client (CEO) holds ultimate veto power. 
- If the Council rejects a proposal that the CEO strongly desires, the CEO can exercise an `Executive Override`. 
- However, if the override violates a core Constitutional Invariant (e.g., bypassing cryptographic dual-control), the system will record the override on the DAG but mark the engagement as `Non-Compliant/High-Risk`, significantly altering the terms of the eventual MeshCore SaaS handoff.
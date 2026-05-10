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

# Playbook: GAP Delivery

This playbook outlines the orchestration sequence for the full 4-8 week GAP engagement, managed by the Engagement Lead.

## Objective
Produce, govern, and finalize the 6 core GAP deliverables, culminating in a successful pilot and transition to MeshCore SaaS readiness.

## Week-by-Week Execution

### Weeks 1-2: Mapping and Authority
- **Deliverable 1: Workflow Control Map (`holons/`)**
  - *Action*: Artifact Builder drafts the topological map of the client's autonomous systems based on ACRC data.
  - *Gate*: CEO reviews and adjusts the map.
- **Deliverable 2: Authority Matrix (`authority/`)**
  - *Action*: Draft cryptographic role boundaries. Who can authorize what?
  - *Gate*: Midpoint Council Review. The Decision Forum evaluates Phase 1 and 2 outputs for structural integrity. CEO signs off.

### Weeks 3-4: Constraints and Evidence
- **Deliverable 3: Policy Gate Library (`policies/`)**
  - *Action*: Artifact Builder translates human rules into machine-readable conditional logic (Syntaxis/NemoClaw ready).
- **Deliverable 4: Evidence Schema (`evidence/`)**
  - *Action*: Define exactly what data must be anchored to the DAG for every critical transaction.
  - *Gate*: CEO reviews the constraints. Are they too tight? Too loose?

### Week 5: Fallbacks
- **Deliverable 5: Escalation Graph (`escalations/`)**
  - *Action*: Map the human-in-the-loop triggers. If an agent fails a policy gate, who gets pinged? What is the timeout?
  - *Gate*: Final Council Review. The 5 panels review all 5 deliverables comprehensively. Must reach `Governed` state.

### Weeks 6-8: The Pilot
- **Action**: Engagement Lead runs a dry-run or limited-scope live pilot of the defined architecture.
- **Deliverable 6: Pilot Outcome Memo (`pilots/`)**
  - *Action*: Artifact Builder summarizes what worked, what broke, and what surprised the team.
  - *Gate*: Final CEO Approval.

## Quality Gates and Handoff
No phase begins until the previous phase is cryptographically signed by the CEO. 

Upon completion of Week 8:
1. The Engagement Lead presents the full, finalized GAP package.
2. The CEO applies their final signature.
3. The Council Liaison ensures the entire package is anchored to the ExoChain DAG.
4. The Facilitation Team spins down, and the client transitions to the MeshCore SaaS onboarding flow.
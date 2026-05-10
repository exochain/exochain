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

# Architecture of the GAP Layer

The `gap/` directory operates as a governed front-end layer situated directly inside the `exochain` repository (`exochain/exochain/gap`). It is the orchestration point where CEO intent, agentic execution, and cryptographic governance converge. This architecture ensures that all operational and advisory actions are strictly governed, traceable, and continuously improving.

## Integration with ExoChain Crates

The GAP layer does not reinvent core infrastructure; it orchestrates the existing robust ExoChain crates to enforce governance during the advisory engagement.

1. **`exo-governance`**: Serves as the foundational rule engine. All constitutional invariants and Syntaxis protocols defined within `gap/` are parsed and enforced by this crate. It ensures that no agentic action violates the defined bounds of the engagement.
2. **`exo-gatekeeper`**: Acts as the enforcement boundary. When the CEO interacts with the system or when a workflow reaches an approval phase, `exo-gatekeeper` handles identity resolution, cryptographic signatures, and access control.
3. **`exo-dag`**: The immutable ledger of the engagement. Every state change, council resolution, and approved artifact is anchored to the ExoChain DAG via the AI-IRB mechanism. This provides the cryptographically secure Evidence Schema.
4. **`decision-forum`**: The deliberative engine. The GAP layer relies heavily on this crate to process T1+ proposals through the 5-panel council, ensuring multi-disciplinary review before execution.

## Syntaxis Protocol Composition

Doctrine and workflows within the GAP layer are entirely encoded as machine-readable Syntaxis YAML protocols (`gap/syntaxis/`). These protocols compose governance pipelines by defining discrete nodes of execution, evaluation, and transition. 

- **Pipelines**: A protocol strings together intake, assessment, review, and reporting nodes. 
- **Transitions**: State changes within a protocol strictly follow the BCTS (Belief-Choice-Truth-State) state machine. A protocol cannot move an artifact from `Draft` to `Approved` without passing through `Governed` and `Verified` states.
- **Council Hooks**: Protocols natively integrate with the Decision Forum, automatically pausing execution to route through the 5-panel review when thresholds are met.

## Team Architecture and the Organization

The organizational structure within the incubator is divided into two distinct but collaborating team typologies:

### 1. Facilitation/Onboarding Teams
These are the turnkey, client-facing teams. They map to the operational edge of the engagement.
- **Trigger**: Activated immediately upon CEO check-in.
- **Function**: They execute the Syntaxis protocols for ACRC assessments and GAP delivery. They interact with the CEO, build the 6 core deliverables, and present findings to the council.

### 2. Self-Development Teams
These are the introspective, infrastructure teams. They map to the core engineering and quality assurance functions.
- **Trigger**: Activated by performance metrics, system anomalies, or scheduled Continuous Quality Improvement (CQI) cycles.
- **Function**: They monitor the platform's health and the effectiveness of the Facilitation Teams. When they identify a degradation or optimization opportunity, they formulate a proposal and interface with **ExoForge** to compile and deploy system improvements autonomously, under council oversight.

## CEO Dashboard Connection

The CEO dashboard is the visual materialization of the `gap/` state. It connects to the backend via secure RPC channels authenticated by `exo-gatekeeper`.
- **Read Path**: The dashboard queries `exo-dag` for historical context and reads the current active Syntaxis nodes to display engagement progress.
- **Write Path**: When the CEO issues an approval or directive, the dashboard signs the payload and submits it to the `decision-forum` or directly to a waiting Syntaxis node.

## Data Flows

1. **Intake**: CEO inputs data → Facilitation Agent parses data → Syntaxis `intake` node initializes.
2. **Execution**: Facilitation Agent drafts an artifact (e.g., Workflow Control Map) → Artifact is submitted to BCTS state `Draft`.
3. **Governance**: Syntaxis protocol triggers Council Review → `decision-forum` crate activates 5-panel review → Council approves → State moves to `Governed`.
4. **Anchoring**: `exo-dag` writes the transition to the immutable ledger.
5. **Continuous Improvement**: Governance Monitor agent detects a bottleneck in step 3 → Triggers CQI cycle → ExoForge generates an optimized Syntaxis YAML → Council approves → System self-updates.
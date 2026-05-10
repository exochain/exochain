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

# GAP Deliverables

The ultimate goal of the GAP incubator engagement is the production, validation, and executive approval of six core artifacts. These deliverables constitute a complete, production-grade governance architecture.

## The 6 Deliverables

1. **Workflow Control Map (`holons/`)**
   - *What it is*: A comprehensive topological map of the organization's autonomous systems, outlining how nodes interact and where boundaries lie.
   - *Who produces it*: The Artifact Builder agent, based on CEO context and ACRC data.
   - *Enables*: Clear visibility into system complexity and risk surface area.

2. **Authority Matrix (`authority/`)**
   - *What it is*: The definitive ledger of cryptographic delegations. It explicitly defines which agent, human, or panel has the right to execute specific state changes.
   - *Who produces it*: The Artifact Builder, heavily scrutinized by the Legal and Governance panels.
   - *Enables*: The "Delegation Governance" invariant. Prevents unauthorized agentic overreach.

3. **Policy Gate Library (`policies/`)**
   - *What it is*: A collection of machine-readable constraints (formatted for Syntaxis and NemoClaw) that dictate the exact operational boundaries for agents.
   - *Who produces it*: The Artifact Builder, validated by the Architecture panel.
   - *Enables*: Hardcoded safety limits and automated compliance.

4. **Evidence Schema (`evidence/`)**
   - *What it is*: The structural definition of what data must be written to the ExoChain DAG during operations. 
   - *Who produces it*: The Artifact Builder, validated by the Security panel.
   - *Enables*: The "Transparency & Accountability" invariant. Ensures auditability.

5. **Escalation Graph (`escalations/`)**
   - *What it is*: The routing logic for human-in-the-loop interventions. Defines who gets alerted, under what conditions, and what the fallback behavior is if the human is unavailable.
   - *Who produces it*: The Artifact Builder, validated by the Operations panel.
   - *Enables*: The "Dual Control" and "Existential Safeguard" invariants.

6. **Pilot Outcome Memo (`pilots/`)**
   - *What it is*: The final executive summary produced after dry-running the proposed architecture. Details successes, failures, and required adjustments.
   - *Who produces it*: The Engagement Lead and Artifact Builder collaboratively.
   - *Enables*: The transition to MeshCore SaaS, providing the CEO with the confidence to deploy.

## Mapping to MeshCore
These artifacts are not static PDFs. They are designed as configurations. When the GAP engagement concludes, these files are ingested directly into the MeshCore SaaS environment, instantly configuring the live operational governance engine to match the structure defined in the incubator.
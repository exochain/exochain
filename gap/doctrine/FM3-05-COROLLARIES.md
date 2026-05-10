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

# FM 3-05 Corollaries in the GAP Layer

The Special Operations principles outlined in FM 3-05 provide a profound doctrinal foundation for managing advanced, semi-autonomous systems. Within the `gap/` incubator, we translate three specific corollaries into rigid engineering constraints and behavioral mandates for our agentic teams.

---

## 1. Partnership (FM 3-05, 4-3)

**Principle Text:**
"Special Operations Forces must establish and maintain effective partnerships. Success depends on the ability to work by, with, and through others, maintaining mutual trust and shared objectives."

**Engineering Constraint:**
Agents within the GAP layer cannot act as unilateral black-box problem solvers. Every Syntaxis workflow must expose its internal state, its assumptions, and its pending actions to the CEO. The system must fundamentally operate *by, with, and through* the human executive.

**Enforcement Mechanism:**
The `ceo-onboarding` and `gap-engagement` Syntaxis protocols require mandatory `consent-verify` and `approval-gate` nodes. An agent cannot advance a deliverable from `Draft` to `Governed` without cryptographic confirmation that the human partner has reviewed and agreed to the direction.

**gap/ Application:**
The Facilitation Team (specifically the Engagement Lead) is designed to cultivate this partnership. Instead of simply generating the *Workflow Control Map* independently, the Artifact Builder agent co-creates it with the CEO, prompting for strategic input and validating structural assumptions before finalization.

---

## 2. Integration (FM 3-05, 4-5)

**Principle Text:**
"SOF operations must be fully integrated with conventional forces and interagency partners. Isolated operations rarely achieve decisive strategic results."

**Engineering Constraint:**
The GAP incubator cannot operate as an isolated silo. Its outputs must be directly interoperable with the broader organizational architecture, the underlying ExoChain crates, and eventual MeshCore SaaS deployments. Information must flow seamlessly across panel boundaries.

**Enforcement Mechanism:**
The 5-panel Decision Forum is the primary enforcement engine for integration. The `council-review.yaml` Syntaxis protocol forces every major proposal to be evaluated not just for technical feasibility (Architecture Panel), but for Legal, Governance, Security, and Operational compliance simultaneously. 

**gap/ Application:**
When the Self-Development team proposes a CQI improvement, it isn't just an isolated code change. The `exoforge-dispatch` node ensures the change is integrated into the overarching Syntaxis registry and verified against the existing `exo-governance` framework, ensuring the whole system moves forward coherently.

---

## 3. Persistence (FM 3-05, 4-8)

**Principle Text:**
"Persistence in the operational environment allows SOF to build relationships, understand complex dynamics, and capitalize on fleeting opportunities. It requires sustained commitment."

**Engineering Constraint:**
Governance is not a point-in-time check; it is a continuous, enduring state. The GAP environment must actively monitor, record, and iteratively improve its own compliance and operational health long after initial deployment.

**Enforcement Mechanism:**
The ExoChain DAG and the AI-IRB serve as the persistent memory of the engagement. Furthermore, the `cqi-self-improvement.yaml` protocol enforces a mandatory, recurring loop of measurement, analysis, and self-correction. 

**gap/ Application:**
The Self-Development Team embodies persistence. The Governance Monitor agent operates continuously in the background. If a specific policy gate in the *Policy Gate Library* fails repeatedly, the system persistently analyzes the failure, proposes a Syntaxis update via ExoForge, and refines the architecture, ensuring the governance model outlives the initial advisory engagement.
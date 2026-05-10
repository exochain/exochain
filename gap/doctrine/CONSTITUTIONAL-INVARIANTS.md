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

# Constitutional Invariants in GAP

The 10 Constitutional Invariants are the non-negotiable bedrock of ExoChain governance. Within the `gap/` incubator, these invariants are aggressively monitored and enforced to ensure the CEO remains firmly in control of the advisory engagement and all resulting deliverables.

---

### 1. Democratic Legitimacy
- **Definition:** Authority must derive from the explicit consent and mandate of the governed or the designated authority (the CEO).
- **GAP Manifestation:** The entire engagement only begins after the CEO cryptographically signs the ACRC intake and explicitly activates the Facilitation Team. 
- **Violation:** An agent initiating a workflow or defining a policy gate without an upstream mandate.
- **Enforcement:** `exo-gatekeeper` verifies the presence of a valid, signed CEO mandate token before any Syntaxis protocol can execute.

### 2. Delegation Governance
- **Definition:** The transfer of authority to autonomous systems must be explicit, bounded, and revocable.
- **GAP Manifestation:** Central to the creation of the *Authority Matrix* deliverable. The CEO defines exactly what agents can and cannot do.
- **Violation:** An agent exceeding its defined scope or attempting to delegate its own authority unilaterally.
- **Enforcement:** The `authority/` constraints are actively checked by the `exo-governance` crate during every BCTS state transition.

### 3. Dual Control
- **Definition:** High-stakes actions require multi-party or multi-factor authorization. No single entity (human or agent) can unilaterally execute a critical change.
- **GAP Manifestation:** Foundational to the Decision Forum. All T1+ proposals require multi-panel sign-off and, ultimately, CEO approval.
- **Violation:** A single agent or panel attempting to finalize a GAP deliverable without peer or executive review.
- **Enforcement:** Syntaxis `council-review` nodes will physically fail to progress without cryptographic signatures from at least 3 of 5 panels plus the client.

### 4. Human Oversight
- **Definition:** A human must remain in the loop or securely on the loop for all substantive autonomous operations.
- **GAP Manifestation:** The core promise of the incubator. The CEO acts as Executive Chair, reviewing all outputs. The *Escalation Graph* explicitly maps these human-in-the-loop triggers.
- **Violation:** An autonomous workflow executing a state-changing operation without alerting or requesting human validation where required.
- **Enforcement:** Mandatory `ceo-report` and `approval-gate` nodes in the Syntaxis YAML.

### 5. Transparency & Accountability
- **Definition:** All agentic decisions, rationale, and state changes must be legible, auditable, and immutable.
- **GAP Manifestation:** Realized through the *Evidence Schema* deliverable and the ExoChain DAG. Every action taken by the Facilitation Team is logged.
- **Violation:** "Black box" processing or an agent failing to provide BCTS rationale for a decision.
- **Enforcement:** The AI-IRB mechanism ensures no state transitions occur without a corresponding, structured DAG entry.

### 6. Conflict Adjudication
- **Definition:** A clear, pre-defined mechanism must exist to resolve disputes between agents, panels, or human operators.
- **GAP Manifestation:** The Decision Forum serves as the primary adjudicator. If the Architecture panel and Security panel disagree on a GAP deliverable, the protocol forces deliberation.
- **Violation:** Deadlock without escalation, or unauthorized out-of-band resolution.
- **Enforcement:** Syntaxis `error_strategy` and BCTS `Escalated` state routing automatically trigger dispute resolution workflows.

### 7. Technological Humility
- **Definition:** Systems must operate within known limits and gracefully degrade or escalate when facing uncertainty.
- **GAP Manifestation:** The ACRC Facilitator agent scoring systems honestly. Agents must admit when a client's context falls outside their operational parameters.
- **Violation:** An agent confidently generating a *Policy Gate Library* for a domain it does not understand (hallucination/overreach).
- **Enforcement:** Confidence thresholds in the `decision-forum` config. If confidence falls below the threshold, the system halts and escalates to the human.

### 8. Existential Safeguard
- **Definition:** The system must possess immutable "kill switches" to halt catastrophic or runaway behaviors.
- **GAP Manifestation:** The CEO dashboard features an overriding global halt command that instantly freezes all `gap/` execution.
- **Violation:** A workflow continuing execution after a halt command is issued, or attempting to disable the halt mechanism.
- **Enforcement:** Hardcoded interrupts at the `exo-governance` level that bypass all Syntaxis logic to freeze operations.

### 9. Doctrinal Compliance
- **Definition:** All operations must align with the established ideological and strategic doctrine (e.g., FM 3-05 corollaries).
- **GAP Manifestation:** The *Pilot Outcome Memo* must evaluate not just efficiency, but how well the pilot adhered to the organization's stated doctrine.
- **Violation:** Creating an *Authority Matrix* that optimizes for speed by violating the principle of Integration.
- **Enforcement:** The `doctrine-triad-check` node in the council review process specifically scans proposals for doctrinal violations.

### 10. Capability Alignment
- **Definition:** The capabilities granted to an autonomous system must be strictly commensurate with the task assigned and the trust verified.
- **GAP Manifestation:** The Self-Development Team only has access to ExoForge capabilities relevant to the specific CQI issue identified.
- **Violation:** An agent requesting broader network access or elevated permissions beyond what is required to draft a specific artifact.
- **Enforcement:** The `node-registry.json` strictly maps Syntaxis nodes to specific, limited underlying crate capabilities.
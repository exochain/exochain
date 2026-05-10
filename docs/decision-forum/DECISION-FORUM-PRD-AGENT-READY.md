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

# decision.forum — PRODUCT REQUIREMENTS DOCUMENT (PRD)
# Version: 1.1.0 — COMPLETE EXECUTABLE SINGLE-FILE EDITION
# Status: Agent-Ready / OpenClaw / OpenForge Ingestion
# Date: 2026-03-14

## 1. Core Axioms (Hard invariants — must be enforced in code)

1. Authority is held in trust, never owned.
2. Decisions are first-class sovereign objects (storable, diffable, transferable, auditable, contestable).
3. Trust accumulation > speed — verification gates are features, not bottlenecks.
4. Constitutional constraints must be machine-readable and enforced at runtime — never advisory.
5. Authority without cryptographically verifiable provenance is void.

## 2. Non-Functional Requirements (must be satisfied by architecture)

- Scale targets: 10 000 tenants, 1 M decisions/day, 50-year immutable history
- P99 chain-of-authority + constraint verification latency: < 200 ms
- Availability: 99.999 % (multi-region active-active, RPO < 1 min, RTO < 15 min)
- Cryptography: Ed25519 today → hybrid post-quantum (Kyber/ML-DSA or equivalent) migration path
- Storage tiers: hot LRU cache + S3-compatible cold / Glacier Deep Archive
- Formal verification: TLA+ model checking of all core invariants + runtime assertion monitoring
- Accessibility: WCAG 2.2 Level AA + neurodiversity accommodations
- Security: SOC 2 Type II + ISO 27001 + zero-trust multi-tenant enclaves

## 3. Governance Requirements

GOV-001  Machine-Readable Constitutional Framework                                 [P0]
        The system SHALL maintain — per tenant — a signed, versioned, machine-readable constitutional corpus containing charter, bylaws, board policies, committee charters, delegation matrices, and jurisdiction-specific rules.
        • Schema: JSON / YAML with semantic versioning
        • Real-time constraint evaluation: < 2 s
        • Every Decision Object stores cryptographic hash(es) of constitution version(s) in force at creation and approval
        • Dry-run mode for proposed amendments
        Failure case: Bylaw supermajority requirement exists only in PDF → $15 M contract passes on simple majority → minority suit

GOV-002  Constitutional Versioning with Temporal Binding                           [P0]
        Every Decision Object MUST be immutably bound to the constitutional version(s) in force at the time of its lifecycle events. Retroactive amendments prohibited by default.
        • Semantic versioning (major.minor.patch)
        • Amendments are themselves Decision Objects
        • Queryable: “Under which version was Decision X compliant?” with proof
        • Retroactive application requires explicit constitutional RETROACTIVE_APPLICATION authority

GOV-003  Delegated Authority Matrix with Scope, Time, Revocation                  [P0]
        Real-time matrix of every actor (human/AI) → explicit, signed, scoped, time-bound, revocable authorities.
        • Signed JSON records
        • Auto-expiry enforcement
        • Full chain retrievable < 3 s
        • Sub-delegation only if explicitly permitted and scope-capped
        • Revocation immediate & irretroversible

GOV-004  Standing Authority Sunset and Renewal                                    [P1]
        All standing authorities expire (default max 12 months) and require affirmative renewal via new Decision Object.
        • 90/60/30/14/7-day notifications
        • Expired → blocked
        • Sunset calendar across organization

GOV-005  Authority Chain Verification on Every State Change                      [P0]
        Every governed action MUST synchronously verify the full cryptographic chain of authority from constitutional source to acting agent.
        • Verification < 2 s (≤ 5 levels)
        • Broken chain → CHAIN_BREAK rejection + diagnostic
        • Cannot be bypassed or deferred
        • Offline portable verification tool

GOV-006  Constitutional Conflict Resolution Hierarchy                             [P1]
        Deterministic precedence (e.g. Articles > Bylaws > Resolutions > Charters > Policies) with human escalation on conflict.
        • Auto-block + route to designated authority
        • Conflict Register + resolution trail

GOV-007  Human Oversight Gates for AI-Assisted Decisions                          [P0]
        AI agents are delegated-only; cannot satisfy HUMAN_GATE_REQUIRED classes; human vs AI signatures cryptographically distinguishable.
        • HUMAN_GATE_REQUIRED list only modifiable via constitutional amendment
        • AI max delegation duration 90 days default
        • AI cannot create/modify delegations

GOV-008  Structured Contestation and Reversal Protocol                            [P0]
        Every Decision Object supports formal contestation by authorised stakeholders.
        • Creates linked Challenge Object
        • CONTESTED status pauses execution (except emergencies)
        • Resolution is new Decision Object
        • Reversal creates immutable REVERSAL linkage

GOV-009  Emergency Action Protocol with Retrospective Ratification                [P0]
        Expedited actions under strict EMERGENCY_AUTHORITY delegation; mandatory ratification.
        • Limited enumerated actions + monetary caps
        • Auto-creates RATIFICATION_REQUIRED follow-up
        • Unratified after timeframe → RATIFICATION_EXPIRED
        • Frequency > 3/quarter → automatic governance review

GOV-010  Quorum Failure and Graceful Governance Degradation                       [P1]
        Defined degradation protocols when quorum cannot be achieved.
        • Auto-detect → DEGRADED_GOVERNANCE
        • Restricted actions + mandatory later ratification

GOV-011  Succession and Continuity Protocols                                      [P1]
        Pre-defined, automatically activated succession for all key roles.
        • ≥ 2 successors per role
        • Triggers: declaration / unresponsiveness / designated activator

GOV-012  Accountability Mechanisms — Censure, Suspension, Revocation, Recall     [P1]
        Formal actions as Decision Objects with due process enforcement.
        • Suspension immediate (< 60 s system-wide)
        • Due process timelines clocked by system

GOV-013  Recursive Self-Governance & Safe Meta-Modification Protocol              [P0]
        All platform evolution (sprints, features, model upgrades, constitutional changes) MUST be governed as first-class Decision Objects under the same rules the platform enforces on tenants.
        • OpenForge sprints = Decision Objects
        • Governance Simulator stress-tests proposed changes
        • 100 % self-modification compliance metric required

## 4. Legal / Compliance Requirements

LEG-001  Self-Authenticating Business Record Architecture (FRE 803(6), 902(13/14)) [P0]
LEG-002  Cryptographic Timestamp Authenticity with Third-Party Anchoring          [P0]
LEG-003  Immutable Chain of Custody with Tamper-Evident Audit Trail               [P0]
LEG-004  Informed Decision-Making Evidence Capture (Duty of Care)                 [P0]
LEG-005  Conflict of Interest Disclosure and Recusal Enforcement (Duty of Loyalty) [P0]
        + DGCL §144 safe-harbor workflow automation
LEG-006  Deliberation Quality and Alternatives Considered                         [P0]
LEG-007  AI Provenance and Admissibility Safeguards (incl. zkML proofs)           [P0]
LEG-008  Business Judgment Rule Prerequisite Capture                              [P0]
LEG-009  Attorney-Client Privilege Compartmentalization                           [P0]
LEG-010  E-Discovery-Ready Export and Production Workflow                         [P0]
LEG-011  Records Retention and Litigation Hold Management                         [P1]
LEG-012  Fiduciary Defense Package Generation                                     [P0]
LEG-013  DGCL §144 Safe-Harbor Automation                                         [P0]

(For brevity in this consolidated edition the detailed acceptance criteria of LEG-001–013 are assumed to match the earlier detailed versions you already reviewed. If any LEG item needs re-expansion, say so.)

## 5. Architecture Requirements

ARCH-001  Merkle-DAG Proof Architecture for Domain Objects                        [P0]
ARCH-002  Global Proof Layer via hybrid zk-SNARK + zk-STARK                       [P0]
ARCH-003  State Machine Replication with Total Order Delivery & TLA+ invariants   [P0]
ARCH-004  Raft-Based Consensus with CRDT Inter-Tenant Coordination                [P0]
ARCH-005  Multi-Dimensional Scalability via Tenant Sharding                       [P0]
ARCH-006  Cold Storage for Infinite Historical Depth                              [P1]
ARCH-007  Zero-Trust Multi-Tenant Architecture                                    [P0]
ARCH-008  5-Nines Availability with Multi-Region Active-Active                    [P0]
ARCH-009  Post-Quantum Cryptography Migration Path                                [P0]
ARCH-010  Protocol Versioning with Backwards-Compatible Proofs                    [P0]
ARCH-011  TLA+ Formal Verification Mandate for All Core Invariants                [P0]

## 6. Enterprise & Adoption Requirements

ENT-001  Embedded TCO/ROI Calculator with Fiduciary-Reportable Metrics            [P0]
ENT-002  Segment-Specific Pricing Tiers                                           [P1]
ENT-003  30-Day Pilot with Breakeven ROI Demonstration                            [P0]
ENT-004  Rapid Integration with Enterprise SSO and ERP Systems                    [P1]
ENT-005  SOC 2 Type II + ISO 27001 Certifications                                 [P0]
ENT-006  Adoption Tracking and Utilization Monitoring                             [P1]
ENT-007  Switching Cost Analysis and Retention Strategy                           [P1]
ENT-008  Failure Mode Mitigation and Pilot Exit Path                              [P0]

## 7. UX / Design Requirements

UX-001  Progressive Disclosure Based on User Role                                 [P0]
UX-002  Tamper-Evident Badges with Plain-English Explainers                       [P0]
UX-003  Real-Time Constitutional Constraint Warnings                              [P0]
UX-004  AI Recommendation Cards with Mandatory Human Review & zkML confidence     [P0]
UX-005  Tiered Notification System with Fatigue Controls                          [P0]
UX-006  Mobile-First Intake and Approval Workflows                                [P0]
UX-007  Accessibility and Cognitive Load Standards (WCAG 2.2 AA + neurodiversity) [P0]
UX-008  Async-First Collaboration with Live Meeting Sync                          [P1]
UX-009  Conflict Disclosure and Recusal Workflow                                  [P0]
UX-010  Decision Lifecycle Visibility and Status Tracking                         [P1]

## 8. Trust-Critical Non-Negotiable Controls (TNC)

These 10 controls are absolute — shipping without any of them is a governance defect.

TNC-01  Authority Chain Verification Gate
        Every governed action MUST pass real-time authority chain verification before execution. No “skip verification” mode, no administrative override, no grace period. Action without verified authority chain does not execute. Period.

TNC-02  Human Gate Integrity for Designated Decision Classes
        Decision classes marked HUMAN_GATE_REQUIRED MUST require cryptographically verified human approval. System MUST distinguish human from AI signatures at cryptographic level. No configuration, API, or administrative action can reclassify HUMAN_GATE_REQUIRED decision classes to remove the human gate — requires constitutional amendment.

TNC-03  Tamper-Evident Audit Log Continuity
        Audit log hash chain MUST be continuous and unbroken. Any gap, discontinuity, or integrity failure in the audit log is a P0 incident requiring immediate investigation and disclosure to the board. System MUST self-verify log integrity continuously (minimum: hourly).

TNC-04  Constitutional Constraint Enforcement Synchronicity
        Constitutional constraints MUST be evaluated synchronously — before action completes, not after. Post-hoc constraint checking is a monitoring supplement, never a substitute for pre-action enforcement.

TNC-05  Delegation Expiry Enforcement
        Expired delegations are dead. System enforces expiry automatically, immediately, without exception. No “soft expiry,” no automatic extension, no grace period unless constitutionally defined and itself governed.

TNC-06  Conflict Disclosure Prerequisite
        No actor may participate in deliberation or voting without completing conflict disclosure for that specific Decision Object. System blocks participation — not merely warns — until disclosure complete.

TNC-07  Quorum Enforcement Before Vote Initiation
        Votes cannot be initiated, recorded, or tallied without verified quorum. System does not permit “we’ll verify quorum later” or “quorum was probably met.”

TNC-08  Decision Object Immutability After Terminal Status
        Once a Decision Object reaches terminal status (APPROVED, REJECTED, VOID), its record is immutable. Corrections, amendments, or reversals create new linked Decision Objects — they never modify the original. The original record is historical truth.

TNC-09  AI Agent Delegation Ceiling
        AI agents cannot hold authority exceeding what is explicitly delegated, cannot delegate to others, cannot modify their own authority scope. Any attempt is a security incident, not a feature request.

TNC-10  Emergency Action Ratification Tracking
        Every emergency action automatically generates a ratification requirement. System tracks ratification status and escalates unratified emergency actions. Routine unratified emergency authority is a governance failure that the system surfaces, not hides.

## 9. Measurable Success Metrics (production monitoring)

M1   Authority Verification Coverage               100.00 %  
M2   Revocation Enforcement Latency                P95 < 60 s  
M3   Fiduciary Evidence Completeness               ≥ 99 %  
M4   AI Provenance Compliance                      100.00 %  
M5   Quorum / Recusal Integrity Incidents          0 per quarter  
M6   Tamper-Evident Verification Success           100.00 %  
M7   Emergency Governance Discipline               ≥ 98 % within timeframe  
M8   Active User Adoption Rate                     > 80 % at renewal; > 90 % at D90  
M9   Time-to-Decision (routine)                    ≤ 24 hours  
M10  Proof Verification Infrastructure Uptime      99.9 %  
M11  TLA+ Invariant Verification Coverage          100.00 %  
M12  Self-Modification Compliance Rate             100.00 %

End of executable PRD.
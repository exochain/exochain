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

# National AI Policy Framework Crosswalk (March 2026)

Mapping EXOCHAIN capabilities against the headings of the March 2026 National Policy Framework for Artificial Intelligence.

**Assessment date**: 2026-03-20
**Assessed by**: Repository audit
**Methodology**: Code inspection, documentation review, CI artifact review

---

## Crosswalk Table

| Policy Area | Current EXOCHAIN Capability | Evidence | Status | Recommended Next Step | Owner | Notes / Caveats |
|---|---|---|---|---|---|---|
| **Protecting Children and Empowering Parents** | No age-assurance or parental-control features implemented | N/A | **Gap** | Define `AgeAssuranceHook` extension interface in `exo-identity`; document parental-control policy surface in `exo-consent` | Identity / Legal panels | EXOCHAIN is an infrastructure substrate, not a consumer-facing application. Child safety controls would be implemented by downstream applications using EXOCHAIN's consent and identity primitives. |
| **Safeguarding and Strengthening American Communities** | Constitutional governance framework with human oversight invariant; escalation workflows; audit trail | `crates/exo-governance/`, `crates/exo-escalation/`, `HumanOversight` invariant | **Architectural Affordance** | Document community safety extension surfaces; add ADR for content moderation hook | Governance / Security panels | The governance framework provides infrastructure for community safeguarding rules but does not implement specific content moderation or community safety features. |
| **Respecting Intellectual Property Rights and Supporting Creators** | Provenance tracking via DAG; audit trail with HLC timestamps; cryptographic evidence chain | `crates/exo-dag/`, `crates/exo-legal/`, `exo-core::events` | **Architectural Affordance** | Define `CreatorRightsEvidence` intake flow; document provenance chain as IP attribution surface | Legal / Architecture panels | The immutable DAG and provenance chain provide infrastructure for IP attribution and evidence, but no creator-specific workflows exist. |
| **Preventing Censorship and Protecting Free Speech** | No censorship or content filtering implemented; governance is purely structural | Constitutional governance model; `ConflictAdjudication` invariant; contestation mechanism | **Architectural Affordance** | Document the contestation mechanism as a redress pathway; add ADR for user appeal flow | Governance / Legal panels | EXOCHAIN's governance model inherently supports contestation and appeal via the BCTS lifecycle and escalation workflows. No content-level censorship exists. |
| **Enabling Innovation and Ensuring American AI Dominance** | Open-source constitutional governance substrate; Apache-2.0 license; extensible via MCP rules and Syntaxis workflows | `LICENSE` (Apache-2.0), `crates/exo-gatekeeper/src/mcp.rs`, ExoForge integration | **Partial** | Publish first release to crates.io; improve developer onboarding; add sandbox/playground mode | Architecture / Operations panels | The open-source, composable design supports innovation. First release and improved documentation will lower the barrier to adoption. |
| **Educating Americans and Developing an AI-Ready Workforce** | Demo platform with 23 widgets, AI help menus, and contextual documentation | `demo/web/`, AI help context per widget, `docs/` | **Partial** | Add tutorial workflows; create learning-path documentation; document ExoForge as an AI development teaching tool | Operations panel | The demo platform with embedded AI help provides educational value but is not specifically designed as a workforce training tool. |
| **Establishing a Federal Policy Framework** | Constitutional governance model with 8 invariants, 10 TNC controls, 5-panel council review | `EXOCHAIN_Specification_v2.2.pdf`, governance artifacts, `deny.toml`, CI quality gates | **Implemented (Framework Level)** | Map EXOCHAIN invariants to specific regulatory requirements as they are published; add ADR for regulatory sandbox mode | Governance / Legal panels | EXOCHAIN provides a governance framework that can encode and enforce policy. It does not implement specific federal regulations but provides the substrate for doing so. |
| **Preemption / Minimally Burdensome National Standard** | Multi-tenant architecture with per-tenant governance configuration | `crates/exo-tenant/`, `exo-governance` per-tenant constitution | **Architectural Affordance** | Document multi-jurisdiction governance configuration; add test cases for overlapping policy domains | Legal / Operations panels | The multi-tenant design allows different governance configurations per jurisdiction, supporting a minimally burdensome approach where tenants configure only applicable rules. |

## Extension Surfaces (Not Yet Implemented)

The following are documented as future control surfaces. They are **not implemented** in code but are architecturally supported by EXOCHAIN's design:

### 1. Age-Assurance Integration Hook

**Where**: `crates/exo-identity/`
**Design**: Add an `AgeAssurance` trait and `AgeVerification` type to the identity crate. Downstream applications would implement age verification via the identity verification flow, gating consent operations for minors through the `exo-consent` bailment system.
**Status**: Not implemented. Requires ADR.

### 2. Parental-Control Policy Hook

**Where**: `crates/exo-consent/`
**Design**: Extend the consent policy system with a `ParentalConsentPolicy` that requires guardian DID authorization for subjects below a configurable age threshold.
**Status**: Not implemented. Requires ADR.

### 3. Digital Replica Complaint/Intake Flow

**Where**: `crates/exo-legal/`
**Design**: Add a `DigitalReplicaComplaint` type and intake workflow that creates a governed BCTS decision for adjudication of unauthorized digital replicas.
**Status**: Not implemented. Requires ADR.

### 4. Creator-Rights Evidence Intake

**Where**: `crates/exo-legal/`, `crates/exo-dag/`
**Design**: Leverage the existing provenance DAG to record timestamped evidence of creator attribution. Add a `CreatorEvidence` event type that anchors IP claims in the immutable ledger.
**Status**: Not implemented. Existing DAG provides the infrastructure.

### 5. User Redress and Appeal Pathway

**Where**: `crates/exo-escalation/`
**Design**: The escalation and contestation mechanisms already provide the infrastructure for appeal workflows. A dedicated `UserRedress` flow would formalize the pathway from complaint to council review to resolution.
**Status**: Partially supported by existing escalation primitives. Full flow not implemented.

### 6. Regulatory Sandbox Mode

**Where**: `crates/exo-tenant/`, `crates/exo-governance/`
**Design**: Add a `SandboxTenant` configuration that relaxes certain governance constraints for testing and evaluation purposes, with clear labeling and audit trail entries marking all actions as sandbox-mode.
**Status**: Not implemented. Multi-tenant architecture provides the foundation.

### 7. Workforce/Education Onboarding

**Where**: `demo/web/`, `docs/`
**Design**: The demo platform's widget grid and AI help system provide a foundation for educational onboarding. Structured learning paths would guide users through governance concepts using the interactive configurator.
**Status**: Demo platform exists. Structured learning paths not yet created.

---

## Summary

| Status | Count |
|--------|-------|
| Implemented (Framework Level) | 1 |
| Partial | 2 |
| Architectural Affordance | 4 |
| Gap | 1 |

EXOCHAIN is an infrastructure substrate, not a consumer-facing application. Most policy areas are addressed at the architectural level — EXOCHAIN provides the governance primitives (consent, identity, audit, escalation, multi-tenancy) that downstream applications use to implement specific policy requirements. Where gaps exist, extension surfaces are documented above with recommended ADRs.

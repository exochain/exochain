---
title: "Council Resolution CR-001: AEGIS, SYBIL, Authentic Plurality, and Constitutional Enforcement"
status: draft
created: 2026-03-18
tags: [council-resolution, aegis, sybil, governance, constitutional]
links:
  - "[[EXOCHAIN-REFACTOR-PLAN]]"
  - "[[COUNCIL_STATUS]]"
---

# Resolution of the EXOCHAIN Council on AEGIS, SYBIL, Authentic Plurality, and Constitutional Enforcement

**Resolution ID:** CR-001
**Status:** DRAFT — Pending Council Ratification
**Date:** 2026-03-18

---

## Section 1. Purpose

The purpose of this Resolution is to eliminate ambiguity in the constitutional meaning of AEGIS and SYBIL within EXOCHAIN, to establish the governing document hierarchy by which those terms shall be interpreted, to bind those terms to concrete implementation surfaces in the repository, and to require release-blocking evidence that EXOCHAIN preserves legitimate plurality rather than counterfeit plurality.

---

## Section 2. Findings

The Council finds that EXOCHAIN is organized as a constitutional trust fabric with privacy-preserving identity adjudication, bailment-conditioned consent, deterministic finality, judicial invariant enforcement, and governance artifacts for traceability, threats, and quality gates. The Council further finds that the repository presently reflects both architectural maturity and governance incompleteness: the constitutional direction is explicit, but many traceability and threat-test items remain planned rather than ratified by passing evidence.

The Council further finds that AEGIS is already treated in the platform specification as the constitutional framework for AI governance, that the CGR Kernel is already treated as the immutable judicial branch, and that EXOCHAIN's invariant layer already contemplates separation of powers, consent-before-access, prohibition on capability self-grant, human override preservation, and kernel immutability.

The Council further finds that the repo already treats false plurality as a governance threat, not merely a networking threat, because the repository addresses Sybil conditions in the threat material, Mesh Sybil in the platform threat list, provenance rules for synthetic opinions, quorum-based legitimacy computation, and challenge rights for authority-chain and quorum violations.

---

## Section 3. Governing Document Hierarchy

The Council hereby establishes the following order of interpretive authority until amended by later Council act:

1. **First:** Any Council Resolution expressly ratified by Council vote.
2. **Second:** The then-current EXOCHAIN Specification designated by version number as normative.
3. **Third:** The EXOCHAIN Fabric Platform document, which shall be treated as engineering-operational elaboration except where expressly ratified as normative text.
4. **Fourth:** Repository governance artifacts, including traceability matrices, threat matrices, quality gates, and sub-agent charters, which shall be treated as implementation-control documents rather than superior sources of constitutional meaning.

If two documents conflict, the higher-ranked document shall govern. If a lower-ranked document contains broader implementation detail that does not conflict, that detail may be adopted as controlling engineering guidance.

**Immediate Order:** SPEC_GUARDIAN SHALL produce, before any next ratified release candidate, a one-page "Authority of Text ADR" that identifies the current normative specification by exact filename and version, states whether EXOCHAIN-FABRIC-PLATFORM.md is normative or explanatory, and lists every repository artifact that inherits authority from that source. The Council SHALL not permit further definitional drift between the v2.2 PDF track and the v2.1 platform-markdown track.

---

## Section 4. Canonical Definition of EXOCHAIN AEGIS

> **EXOCHAIN AEGIS** means the **Autonomous Entity Governance & Invariant System** of EXOCHAIN: the constitutional governance, adjudication, and enforcement framework by which identity, consent, custody, capability, deliberation, quorum, and state transition are rendered legitimate only when attributable, role-valid, policy-compliant, provenance-verifiable, and judicially admissible under the CGR Kernel and the governing invariants of the system.

AEGIS is not merely a security layer and not merely an AI-governance layer. It is the constitutional trust fabric that binds the legislative function of policy and schema, the executive function of human and Holon action, and the judicial function of invariant verification into one enforceable system of admissibility.

**No action, approval, access, delegation, capability change, or state transition shall be recognized as valid within EXOCHAIN unless it satisfies all applicable authority-chain requirements, consent requirements, clearance requirements, provenance requirements, and invariant-preservation requirements.**

---

## Section 5. Canonical Definition of EXOCHAIN SYBIL

> **EXOCHAIN SYBIL** means any adversarial, negligent, synthetic, or concealed-control condition in which one underlying actor, controller, beneficial interest, control plane, or materially coordinated cluster is made to appear as two or more independent humans, DIDs, Holons, validators, stewards, reviewers, panelists, delegates, or mesh peers, thereby manufacturing counterfeit plurality within EXOCHAIN.

A Sybil condition includes, without limitation:
- Counterfeit identity multiplicity
- Counterfeit reviewer multiplicity
- Counterfeit model plurality
- Mesh-peer inflation
- Delegation-chain inflation
- Trust-score gaming
- Coordinated quorum manipulation
- Undisclosed common control across approvers
- Presentation of synthetic or coordinated opinions as if they were independent human judgment

For avoidance of doubt, EXOCHAIN SYBIL is not limited to networking, blockchain wallets, or node discovery. It includes any falsification of independence capable of distorting clearance, challenge, crosscheck, authority, consent, custody, audit, governance, or finality.

---

## Section 6. Constitutional Relationship Between the Two

The Council hereby declares the following canonical relationship:

> **AEGIS preserves legitimate plurality.**
> **SYBIL counterfeits plurality.**

Accordingly, the existence of multiple signatures, multiple agents, multiple DIDs, multiple reviewers, multiple peers, or multiple opinions SHALL NOT by itself constitute valid plurality, valid quorum, valid clearance, valid crosscheck, valid consent, or valid delegated authority. **Numerical multiplicity without attributable independence is theater, not legitimacy.**

---

## Section 7. Binding Implementation Interpretation

For implementation purposes, the Council interprets the present repository as assigning AEGIS-adjacent constitutional force across at least the following surfaces:

| Surface | Crate/Module | Constitutional Role |
|---------|-------------|-------------------|
| Invariants & judicial enforcement | `exo-gatekeeper` | Judicial branch |
| Identity & RiskAttestation | `exo-identity` | Identity adjudication |
| Bailment, policy, consent | `exo-consent` | Consent enforcement |
| Legitimacy & quorum | `exo-governance` | Legislative legitimacy |
| Escalation & HITL triage | `exo-escalation` | Operational nervous system |
| Traceability, threats, QG | Governance artifacts | Implementation control |

The Council further interprets the present repository as already signaling that Sybil must be addressed across at least identity, threat modeling, mesh discovery, synthetic-opinion provenance, quorum legitimacy, and challenge/reversal pathways.

---

## Section 8. Mandatory Work Orders to Close Current Gaps

### 8.1 Spec Harmonization
**Owner:** SPEC_GUARDIAN
Reconcile the v2.2 specification track and the v2.1 platform-markdown track into an explicit constitutional hierarchy. Enumerate every AEGIS-related and SYBIL-related clause that is normative, explanatory, or pending.

### 8.2 Threat Expansion
**Owner:** SECURITY_THREATS_AGENT
Replace any narrow interpretation of "Sybil Attack" with a layered threat family:

| Sub-Threat | Attack Surface | Status |
|-----------|---------------|--------|
| Identity Sybil | DID/credential layer | TODO |
| Review Sybil | Clearance/approval pipelines | TODO |
| Quorum Sybil | Governance voting | TODO |
| Delegation Sybil | Authority chains | TODO |
| Mesh Sybil | Peer discovery/networking | TODO |
| Synthetic-Opinion Sybil | AI-generated review plurality | TODO |

Each sub-threat SHALL state mitigations, detection signals, downgrade behavior, and test plan.

### 8.3 Provenance Enforcement
Governance surfaces accepting plural input SHALL require provenance metadata sufficient to distinguish human from synthetic, independent from coordinated, and first-order review from derivative or echoed review. Synthetic voices SHALL never be counted as distinct humans.

### 8.4 Clearance Hardening
ClearancePolicy SHALL be extended so that quorum means not only enough approvals, but enough **independent** approvals from permitted roles, under a disclosed policy, with valid signatures, and with no unresolved challenge to independence.

### 8.5 Challenge Path Hardening
Any credible allegation of concealed common control, coordinated manipulation, quorum contamination, or synthetic-human misrepresentation SHALL be admissible as a formal challenge ground and the contested action SHALL be pause-eligible pending review.

### 8.6 Escalation Pathway
EXOCHAIN SHALL establish a named Sybil adjudication path within its escalation subsystem: detection → triage → quarantine → evidentiary review → clearance downgrade → reinstatement rules → permanent audit logging.

### 8.7 Traceability Completion
**Owner:** QA_TDD_AGENT + SPEC_GUARDIAN
Update the traceability matrix so that every AEGIS-relevant and SYBIL-relevant requirement is mapped to code, tests, and status. "Planned" SHALL not be sufficient for Council-ratified release on constitutional controls.

### 8.8 Release Gating
**Owner:** DEVOPS_RELEASE_AGENT
No release may be represented as Council-ratified unless quality gates pass AND the AEGIS/SYBIL acceptance set passes: build, test, coverage, lint, audit, cross-implementation consistency, fuzz smoke, and Sybil control evidence.

### 8.9 No-Admin Preservation
Any implementation shortcut creating a de facto admin bypass of AEGIS SHALL be prohibited. "No admins" is ratified as a definitional guardrail.

---

## Section 9. Release-Blocking Acceptance Standard

Until superseded by later Council act, the following SHALL be release-blocking for any release claiming constitutional readiness:

- [ ] One unambiguous normative definition source for AEGIS and SYBIL
- [ ] Threat matrix includes full Sybil family with mitigations and tests
- [ ] Traceability matrix maps each requirement to implementation and tests
- [ ] Plural-governance paths enforce provenance and independence-aware counting
- [ ] Challenge and escalation flows can pause contested decisions
- [ ] Quality gates pass without exception

If any is absent, the release MAY continue as experimental but SHALL NOT be presented as constitutionally complete.

---

## Section 10. Reporting Requirement

Before the next Council vote on readiness, responsible agents SHALL submit:

- [ ] Authority-of-text ADR
- [ ] Updated definition and threat taxonomy
- [ ] Updated traceability matrix
- [ ] Updated threat matrix
- [ ] Automated test results
- [ ] CI quality-gate results
- [ ] Constitutional attestation on legitimate vs counterfeit plurality

---

## Section 11. Ratification Effect

Upon adoption, this Resolution shall serve as the canonical Council interpretation of AEGIS and SYBIL unless and until amended by later Resolution or Constitutional Amendment.

---

## Implementation Tracking

| Work Order | Owner | Status | Evidence |
|-----------|-------|--------|----------|
| 8.1 Spec harmonization | SPEC_GUARDIAN | 🟡 PARTIAL | `docs/adr/ADR-001-authority-of-text.md`; Basalt R2 keeps CR-001 draft until ratification evidence exists. |
| 8.2 Threat expansion | SECURITY_THREATS_AGENT | 🟡 PARTIAL | `governance/threat_matrix.md`; `docs/architecture/THREAT-MODEL.md`; Basalt R3 will reconcile registry truth. |
| 8.3 Provenance enforcement | Council | 🟡 PARTIAL | Provenance surfaces exist across governance and legal crates, but recent Council waves still found unsigned trust-boundary paths. |
| 8.4 Clearance hardening | Council | 🟡 PARTIAL | Independence-aware quorum/clearance code exists, but open governance-bypass work remains tracked outside this resolution. |
| 8.5 Challenge path hardening | Council | 🟡 PARTIAL | Challenge paths exist in `exo-governance` and `exo-escalation`; end-to-end auth/admissibility review remains open. |
| 8.6 Escalation pathway | Council | 🟡 PARTIAL | `exo-escalation` implements the pathway shape; Clause-expansion left residual authority-chain evidence questions. |
| 8.7 Traceability completion | QA_TDD_AGENT + SPEC_GUARDIAN | 🟡 PARTIAL | Current matrix is 83 implemented / 1 partial / 2 planned rows. |
| 8.8 Release gating | DEVOPS_RELEASE_AGENT | ✅ IMPLEMENTED | `.github/workflows/ci.yml` defines 20 numbered gates plus the required aggregator. |
| 8.9 No-admin preservation | Council | 🟡 PARTIAL | `docs/audit/WO-009-no-admin-bypass-audit.md`; design-deferred governance-bypass initiative remains open. |

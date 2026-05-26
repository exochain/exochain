# CyberMedica 2.0 — Seven-Layer Master PRD and Systems Architecture for Sandy

**Product title:** CyberMedica 2.0: Exochained Clinical Research Site Quality Management System  
**Audience:** Sandy, CyberMedica leadership, clinical research quality leaders, CRO/sponsor diligence stakeholders, architecture/build teams  
**Source fidelity:** This artifact restructures the original CyberMedica 2.0 master PRD without intentionally removing any source requirement, policy, procedure, object, role, rule, dashboard, acceptance criterion, or open question. The original content has been reorganized under the seven-layer prompt discipline and supplemented with crosswalks, architecture implications, documentation expectations, and implementation framing.  
**Seven-layer discipline:** Doctrine → Domain → Data → Doors → Documentation → Deployment → Drift  
**Status:** Sandy-ready restructuring draft. Implementation phases and commercial packaging should still be derived after review.

---

## 0. Sandy Brief

CyberMedica 2.0 should be understood as a **clinical research quality trust operating system**, not a document repository, generic QMS, CTMS add-on, or AI review gadget. Its value is that it turns site quality standards into governed controls; controls into required evidence; evidence into reviewable and custody-tracked objects; decisions into authorized, contestable, auditable records; and readiness claims into sponsor/CRO-ready trust artifacts.

The earlier master PRD was intentionally exhaustive and non-phased. This version keeps that fidelity but restructures it so Sandy can evaluate the product through seven lenses:

1. **Doctrine** — the rules that must never be violated.
2. **Domain** — the clinical research site quality world the product must model.
3. **Data** — the objects, boundaries, permissions, evidence, and provenance the product must preserve.
4. **Doors** — the role-specific entry points, workflows, dashboards, gates, and decisions through which users experience the system.
5. **Documentation** — the manuals, contextual help, SOP crosslinks, AI orientation, training artifacts, and exportable guidance that make the product usable and auditable.
6. **Deployment** — the implementation, security, integration, scalability, Exochain, and operational architecture that makes the system real.
7. **Drift** — the continuous improvement, CQI, monitoring, risk, acceptance, open-question, and governance loops that prevent the product from decaying into static compliance theater.

The central reframing is this:

> CyberMedica is a governed quality execution fabric for clinical research sites. It should continuously answer: **Is this site ready, competent, authorized, ethical, controlled, evidenced, and improving — and can every material assertion be proven without overexposing protected content?**

---

## 0.1 Seven-Layer Fidelity Crosswalk

| Seven-layer discipline | Preserved source content | Added/advanced framing for Sandy |
|---|---|---|
| **1. Doctrine** | Product title, document status, executive summary, product vision, strategic premise, product scope, product principles, 40 core policies, 15 governance rules, AI governance, Exochain-specific requirements. | Declares non-negotiable design law: participant protection, data integrity, human authority, default-deny governance, evidence before assertion, privacy-preserving receipts, no AI final authority. |
| **2. Domain** | Target users/stakeholders and all 15 product modules: control library, QMS passport, protocol readiness, AI review, Decision Forum, evidence/custody, risk, CQI, deviations/CAPA, workforce/delegation, ethics, participant protection, information management, facilities/equipment/product, evaluation/audit/reporting. | Treats clinical research site quality as a living system of people, protocols, facilities, evidence, obligations, risks, and decisions. |
| **3. Data** | Permission model and data model overview, plus object schemas embedded throughout modules. | Makes PHI/PII, sponsor-confidential data, evidence, authority chains, receipts, and access policies first-class architecture concerns. |
| **4. Doors** | Core procedures and dashboards. | Recasts procedures as role-specific “doors” into the operating system: site leader, PI, coordinator, quality manager, CRO, sponsor, auditor, Decision Forum, AI reviewer. |
| **5. Documentation** | Policies, procedures, controlled documents, SOP inventory, training objects, reports, export packets. | Adds an explicit product documentation layer: right-side manual, contextual crosslinks, role manuals, admin/support/security runbooks, AI orientation, and inquiry-to-CQI conversion. |
| **6. Deployment** | Functional requirements, nonfunctional requirements, integrations, APIs, security, privacy, Exochain requirements. | Adds architecture posture: repository source of truth, workflow definitions, CI gates, deployment checks, observability, and release derivation. |
| **7. Drift** | CQI module, KPI module, acceptance criteria, open questions, closing thesis. | Establishes continuous improvement, evidence aging, AI-assisted gap detection, Decision Forum governance, acceptance tests, and future roadmap loops. |

---

## 0.2 The Seven-Layer Prompt Discipline, Advanced for CyberMedica

### Doctrine

Prompt the system first for the law of the product: what the system must protect, forbid, require, prove, and preserve. For CyberMedica, doctrine includes participant protection, data integrity, human authority, privacy by design, contestability, recusal, conflict disclosure, evidence before assertion, and AI as assistance rather than authority.

### Domain

Prompt the system next for the world it must model. CyberMedica’s world is not “documents”; it is clinical research site execution: mission, leadership, staff, training, delegation, protocols, consent, product handling, facilities, information management, deviations, CAPA, risk, audits, ethics, sponsors, CROs, monitors, IRBs, and diligence.

### Data

Prompt for every thing that must exist, who owns it, who may see it, what state it can occupy, what evidence supports it, what may be exported, what must be retained, what may be corrected, and what can only be hash-anchored. Data is where trust either survives or collapses.

### Doors

Prompt for role-specific doors and gates. A site leader, PI, coordinator, quality manager, CRO, sponsor viewer, auditor, Decision Forum member, and AI reviewer should not experience the same product. Each should have the right door, the right dashboard, the right tasks, and the right limits.

### Documentation

Prompt for documentation as a product surface. The manuals, right-side guidance drawer, contextual help, crosslinked SOP/control/procedure references, AI orientation, training guidance, and admin runbooks are not afterthoughts. They are the operating interface of a regulated product.

### Deployment

Prompt for the system that can actually be stood up: repository structure, architecture, security, integrations, object storage, DB schema, Exochain receipts, workflows, CI/CD, observability, access controls, backup/restore, and launch-blocking checks.

### Drift

Prompt for how the system gets better and does not go stale: evidence aging, CQI, KPIs, feedback, concern reporting, CAPA, Decision Forum review, AI gap detection, product friction, audit findings, sponsor feedback, open questions, and roadmap derivation.

---

## 0.3 Sandy-Ready Master Build Prompt

Use the following prompt when asking an implementation agent, architecture agent, ExoForge workflow, or internal team to act on this document:

```text
You are acting as the founding systems architect, clinical research quality strategist, regulated-workflow designer, AI governance analyst, and implementation planner for CyberMedica 2.0.

Your task is to build from the CyberMedica Seven-Layer Master PRD without reducing fidelity.

Do not treat CyberMedica as an eTMF, CTMS, document repository, generic QMS, or AI reviewer. Treat it as a governed clinical research site quality execution fabric.

Use the seven-layer discipline:

1. Doctrine: preserve participant protection, data integrity, default-deny governance, human authority, privacy, evidence before assertion, contestability, and AI non-finality.
2. Domain: model the complete clinical research site quality ecosystem: controls, QMS passport, protocol readiness, risk, consent, deviations, CAPA, training, delegation, facilities, product handling, audits, sponsors, CROs, IRBs, and inspectors.
3. Data: define every object, permission boundary, custody state, receipt, version, retention rule, confidentiality class, PHI/PII status, evidence relationship, and export rule.
4. Doors: create role-specific experiences and gates for site leaders, PIs, coordinators, quality managers, CROs, sponsors, auditors, Decision Forum members, and AI reviewers.
5. Documentation: implement a contextual, crosslinked, role-aware manual system and admin/support/regulatory runbooks as first-class product surfaces.
6. Deployment: design the repository, APIs, DB, object storage, Exochain receipt layer, workflow engine, integrations, CI gates, security controls, monitoring, backup/restore, and deployment checks.
7. Drift: implement CQI, evidence aging, risk reassessment, AI gap detection, concern reporting, CAPA, audit findings, Decision Forum governance, KPI trends, and product feedback loops.

Do not put raw PHI/PII, sponsor-confidential content, privileged content, or clinical records on broadly accessible ledgers. Exochain may store privacy-preserving hashes, receipts, manifests, timestamps, authority records, consent records, governance outcomes, and audit proofs.

AI may analyze, summarize, compare, detect gaps, identify contradictions, recommend escalation, and draft review materials. AI may not be final authority for launch, enrollment, consent, deviation closure, CAPA closure, ethics approval, protocol amendment approval, clinical trial product release, risk acceptance, or participant-affecting decisions.

Every implementation decision must map back to a requirement, control, policy, procedure, role, data object, or governance rule in the PRD.

Produce implementation artifacts that include architecture, schema, APIs, workflow definitions, access-control tests, documentation artifacts, dashboards, acceptance tests, and launch-blocking controls.
```

---


## 1. Doctrine Layer — Non-Negotiable Product Law

The Doctrine Layer defines what CyberMedica must protect and prove before any feature is considered complete. In a clinical research quality system, doctrine is not a philosophy section; it is the operating law of the product. It determines whether a workflow may proceed, whether an assertion can be trusted, whether AI is allowed to assist, whether evidence can support readiness, whether a user has valid authority, and whether protected content remains protected.

### 1.0 Doctrine Operating Rules

1. Participant protection is paramount.
2. Data integrity is non-negotiable.
3. Human authority remains explicit.
4. AI may assist but not finally authorize regulated, ethical, clinical, enrollment, consent, deviation, CAPA, product-release, or launch decisions.
5. Every quality assertion needs evidence or must be marked unsupported, stale, waived, contested, pending, or not applicable.
6. Standards become controls with owners, evidence, review cadence, authority, risk class, and audit trails.
7. Access defaults to deny.
8. Delegation must be valid, scoped, trained, competent, time-bound, and revocable.
9. Conflict disclosure, recusal, contestability, dissent, escalation, and retrospective emergency review are product capabilities, not governance niceties.
10. Exochain receipts must preserve proof without exposing PHI/PII, sponsor-confidential, participant, or privileged content.

### Product title

**CyberMedica 2.0: Exochained Clinical Research Site Quality Management System**

### Document status

Master Product Requirements Document. This document is intentionally comprehensive and non-phased. It defines the full target product, operating model, governance model, policies, procedures, controls, roles, rules, responsibilities, evidence objects, and system requirements. Implementation phases, release increments, and commercial packaging should be scoped from this master document after review.

### Executive summary

CyberMedica 2.0 is a governed clinical research quality management platform that converts clinical research site quality standards into operational controls, auditable evidence, authority-gated workflows, AI-assisted oversight, and sponsor/CRO-ready readiness artifacts.

The product is designed for clinical research sites, site networks, contract research organizations, academic medical centers, sponsors, ethics committees, quality leaders, and diligence teams that need reliable, verifiable, and operationally usable evidence that a clinical research site can conduct trials safely, ethically, consistently, and in conformance with defined quality requirements.

CyberMedica 2.0 is not merely an electronic document repository, electronic trial master file, electronic quality management system, or workflow tool. It is a governed quality execution fabric. It treats quality assertions as evidence-backed, role-authorized, policy-controlled, time-bound, reviewable, contestable, and auditable objects.

CyberMedica 2.0 operationalizes the quality management of clinical research sites through a combination of:

1. A standards-derived control library.
2. Site QMS self-assessment and readiness management.
3. Protocol-specific feasibility and startup risk governance.
4. AI-assisted quality review and evidence analysis.
5. Human-governed decision forums.
6. Authority, consent, delegation, recusal, conflict, and escalation gates.
7. Evidence receipts and chain-of-custody records.
8. Continuous quality improvement workflows.
9. Sponsor/CRO diligence exports and trust views.
10. Exochain-backed audit, provenance, custody, and governance primitives.

The intended outcome is to reduce quality uncertainty, startup friction, diligence burden, site variability, audit anxiety, and sponsor acquisition friction by giving all authorized stakeholders a governed view of whether a site is ready, competent, ethically aligned, documented, controlled, and continuously improving.

### Product vision

CyberMedica 2.0 will become the trusted clinical research site quality operating layer where standards, evidence, people, processes, risks, authorizations, and oversight converge into a single governed system of record.

The product vision is to transform clinical research quality from episodic paper compliance into living operational trust.

A clinical research site should be able to demonstrate, at any moment, not merely that it has documents, but that it has the right mission, policies, leadership controls, ethical framework, delegated authorities, trained workforce, risk processes, consent safeguards, protocol controls, clinical trial product controls, facility controls, monitoring evidence, deviation handling, CAPA discipline, and improvement loops to perform research safely and reliably.

A CRO should be able to deploy CyberMedica 2.0 across sites and provide sponsors with a defensible quality readiness layer that accelerates site selection, startup, monitoring, corrective action, audit preparation, and portfolio governance.

A sponsor or large-cap pharmaceutical company should be able to review CyberMedica outputs during diligence or business development and see whether a site, site network, CRO, asset, or trial execution environment is operationally good-to-go, what risks remain, what evidence supports readiness, and what decisions have been escalated or authorized.

### Strategic premise

Clinical research quality failures are rarely caused by the absence of a document alone. They arise when people, process, authority, training, risk awareness, consent, data integrity, ethics, and accountability are not operating as a coherent system.

CyberMedica 2.0 is built on the premise that clinical research quality is a governance problem as much as a documentation problem. Therefore, the system must make the following continuously visible and enforceable:

1. Who is responsible.
2. Who is authorized.
3. Who delegated authority.
4. Whether the delegation is valid.
5. What standard or control applies.
6. What evidence exists.
7. Whether the evidence is current.
8. Whether the evidence has been reviewed.
9. Whether the review had conflicts.
10. Whether risks were identified.
11. Whether mitigations were implemented.
12. Whether human oversight occurred.
13. Whether deviations were managed.
14. Whether participants were protected.
15. Whether data integrity was preserved.
16. Whether sponsor/CRO/site obligations were met.
17. Whether decisions were contestable.
18. Whether audit records are complete.
19. Whether quality improved.
20. Whether the organization is keeping its promises.

### Product scope

CyberMedica 2.0 covers the quality management of clinical research site operations and protocol execution readiness. It focuses on site-level quality, governance, evidence, risk, training, documentation, participant protections, facility readiness, protocol implementation, communications, clinical trial product control, evaluation, assessment, audit, and continuous improvement.

CyberMedica 2.0 does not replace the scientific design of the clinical trial protocol, sponsor clinical development strategy, statistical design, regulatory submission strategy, medical judgment, IRB/IEC legal authority, or statutory/regulatory obligations. Instead, it helps ensure that site-level execution, governance, and quality controls are fit for the protocol and supported by evidence.

### Product principles

#### Principle 1: Default-deny governance

No quality-critical action should proceed merely because a user can access a screen. Actions affecting participant safety, consent, protocol implementation, clinical trial product handling, evidence release, delegation, or sponsor-facing claims require valid authorization, applicable policy, current evidence, and appropriate oversight.

#### Principle 2: Human authority remains explicit

AI may analyze, recommend, summarize, compare, triage, and escalate. AI may not silently grant ethical approval, replace investigator responsibility, override participant rights, authorize enrollment, approve protocol deviations requiring human review, or certify readiness without accountable human authorization.

#### Principle 3: Evidence before assertion

Every readiness claim, quality claim, compliance claim, training claim, facility claim, protocol claim, consent claim, and risk mitigation claim should be backed by traceable evidence or explicitly marked as unsupported, stale, pending, waived, not applicable, or contested.

#### Principle 4: Standards become controls

Normative requirements are to be represented as control objects with owners, roles, evidence, review frequency, applicability, risk class, decision gates, dependencies, and audit trails.

#### Principle 5: Quality is continuous

The platform must not treat readiness as a one-time attestation. Evidence ages, staff change, protocols amend, risks emerge, deviations occur, facilities degrade, and stakeholder expectations evolve. Readiness must be continuously monitored and refreshed.

#### Principle 6: Participant protection is paramount

All workflows must prioritize the rights, safety, well-being, privacy, dignity, and informed participation of clinical trial participants.

#### Principle 7: Data integrity is non-negotiable

The platform must preserve ALCOAC-style expectations: attributable, legible, contemporaneous, original, accurate, and complete records, including secure retention, access control, version history, correction history, and audit trails.

#### Principle 8: Contestability and recourse are built in

Material quality decisions must be reviewable and contestable. Users must be able to raise concerns, appeal, request clarification, disclose conflicts, recuse, document dissent, and escalate urgent risks.

#### Principle 9: Privacy by design

The platform must minimize exposure of PHI, PII, commercially sensitive information, and sponsor-confidential protocol information. Exochain anchoring should use hashes, receipts, attestations, and proofs rather than public disclosure of protected content.

#### Principle 10: Interoperability without loss of governance

CyberMedica must interoperate with CTMS, eTMF, eISF, EDC, eConsent, LMS, HRIS, QMS, IRB systems, document management systems, identity providers, and sponsor portals while preserving its own control, evidence, and audit semantics.

### Core policies

#### Policy 1: Quality Management Policy

CyberMedica shall require each site to define and maintain a quality management policy stating its commitment to participant protection, reliable data, ethical conduct, risk mitigation, continuous improvement, staff competence, document control, protocol conformance, and stakeholder accountability.

The policy shall be approved by site leadership, reviewed at least annually, communicated to staff, linked to site strategy, and supported by evidence.

#### Policy 2: Mission, Vision, and Values Policy

Each site shall document its mission, vision, and values in consultation with stakeholders. The values shall be people-centered, ethical, quality-oriented, and supportive of innovation and improvement. CyberMedica shall require evidence of stakeholder communication, leadership approval, and review cadence.

#### Policy 3: Site Strategy Policy

Each site shall maintain a documented strategy covering mission/vision/values realization, organizational structure, stakeholder expectations, quality management scope, resource needs, technology needs, budgets, and supporting policies.

CyberMedica shall require annual review, lessons learned, resource planning, and linkage to quality objectives.

#### Policy 4: Ethical Framework Policy

Each site shall maintain an ethical framework including an ethical statement, code of conduct, societal responsibility statement, open/inclusive leadership policy, conflict disclosure policy, recusal policy, concern reporting procedure, and non-retaliation protection.

#### Policy 5: Independent Ethics Review Policy

Each clinical research trial shall have documented review and approval by an independent ethics committee or institutional review board, as applicable. CyberMedica shall track approval status, approved materials, amendments, consent forms, continuing review dependencies, and required notifications.

CyberMedica shall not represent AI review as IEC/IRB approval.

#### Policy 6: Communication Policy

Each site shall maintain internal and external communication processes for staff, stakeholders, sponsors, CROs, monitors, auditors, IEC/IRB, and regulators. Communications shall include strategy updates, regulatory changes, protocol requirements, AE/SAE lessons learned, deviations, feedback, safety/governance updates, and quality improvement results.

#### Policy 7: Concern Reporting and No-Blame Culture Policy

CyberMedica shall support confidential and anonymous reporting of concerns regarding maladministration, questionable practice, poor practice, ethical concerns, regulatory issues, participant safety, data integrity, staff well-being, or retaliation.

Concern workflows shall support acknowledgement, investigation, documentation, escalation, closure, and non-retaliation safeguards.

#### Policy 8: Protocol Control Policy

The site shall conduct each trial in accordance with the approved protocol and amendments. CyberMedica shall enforce protocol version control, IEC/IRB approval tracking, staff communication, deviation management, document security, and training updates.

#### Policy 9: Trial Acceptance and Feasibility Policy

Prior to trial acceptance, the site shall complete feasibility review, financial review, risk review, protocol review, product information review, resource review, regulatory requirement identification, and acceptance criteria documentation.

#### Policy 10: Clinical Trial Agreement Review Policy

Clinical trial agreements shall be reviewed before execution for duties, functions, financial requirements, QA/QC requirements, reporting procedures, termination/suspension requirements, document retention, data access, monitoring, inspection, and audit rights.

#### Policy 11: Delegation and Authority Policy

Responsibilities shall be delegated only to qualified, competent, trained individuals. Delegation shall be documented, scoped, time-bound, revocable, and linked to authority verification.

No action requiring authorization may proceed without valid authority.

#### Policy 12: Document Control Policy

All controlled documents shall be uniquely identified, versioned, approved, effective-dated, access-controlled, review-scheduled, superseded when obsolete, retained according to policy, and linked to applicable controls and evidence records.

#### Policy 13: Deviation and Nonconformance Policy

All protocol deviations, nonconformities, errors, near misses, and quality defects shall be recorded, assessed for participant safety and data integrity impact, reported as required, investigated, corrected, prevented, trended, and closed with evidence.

#### Policy 14: CAPA Policy

Corrective and preventive actions shall include root cause analysis, risk assessment, selected corrective action, recurrence prevention, owner, due date, verification, effectiveness check, and closure approval.

#### Policy 15: Continuous Quality Improvement Policy

Sites shall continually assess and improve current and future services through self-assessment, audit, nonconformity reporting, complaint management, stakeholder feedback, staff feedback, analysis, innovation, training, and lessons learned.

#### Policy 16: Risk Management Policy

Each site shall implement a risk management framework including risk identification, assessment, treatment, control, criteria, staff training, safety planning, mitigation tracking, and escalation.

#### Policy 17: Startup Risk Assessment Policy

Before trial initiation and recruitment, the site shall document risk assessment and analysis of impacts, consequences, and benefits to participants, including protection of rights, safety, well-being, claims exposure, insurance, malpractice, and negligence controls.

#### Policy 18: AE/SAE/SUSAR Reporting Policy

The site shall maintain procedures for reporting, managing, investigating, and following up adverse events, serious adverse events, SUSARs, and protocol-defined safety events within required timescales.

#### Policy 19: People-Centered Workforce Policy

The site shall promote a people-centered culture covering ethics, inclusivity, societal responsibility, knowledge sharing, teamwork, teambuilding, and problem solving.

#### Policy 20: Skill-Mix Review Policy

Each site and study shall complete a skill-mix review to determine required staff numbers, roles, competencies, qualifications, and responsibilities.

#### Policy 21: Qualifications and Competency Policy

The site shall identify qualifications, experience, and training required for each role and maintain evidence of staff qualifications, competence, experience, and training.

#### Policy 22: Orientation and Integration Policy

New staff shall complete orientation and integration covering site policies, procedures, processes, access methods, rights, concern reporting, innovation participation, and role expectations.

#### Policy 23: Training Policy

The site shall assess training needs and maintain a training plan based on protocol requirements, previous training evaluations, staff requests, performance reviews, IT systems, equipment, new technologies, risk/CQI needs, legislation, resources, constraints, and evaluation methods.

#### Policy 24: Leadership Development Policy

Sites shall maintain leadership development programs for clinical leads, quality managers, and other leaders responsible for effective delivery, risk management, CQI, staff communication, and succession.

#### Policy 25: Performance Review Policy

Sites shall perform documented performance reviews at defined frequency. Reviews shall support competence, development, quality culture, recognition, and improvement.

#### Policy 26: Staff Well-Being Policy

Sites shall protect staff health, safety, and well-being through risk assessment, proactive well-being programs, no-blame culture, complaint mechanisms, communication processes, and confidential concern management.

#### Policy 27: Participant Rights Policy

Participants shall have rights to informed consent, privacy, withdrawal, non-coercion, updated information, data sharing control, post-termination resources where applicable, and protection of safety, well-being, dignity, and legal rights.

#### Policy 28: Informed Consent Policy

Informed consent shall be obtained and documented according to approved procedures, applicable regulations, IEC/IRB-approved forms, participant capacity, legally authorized representative requirements, witness requirements, emergency exceptions, vulnerable population safeguards, and reconsent triggers.

#### Policy 29: Participant Data Sharing Consent Policy

The site shall obtain and document participant consent before sharing information with other interested parties, subject to applicable privacy and retention regulations.

#### Policy 30: Information Management Policy

Each trial shall maintain an information management plan defining milestones, source data traceability, participant codes, required records, reporting, discrepancies, urgent changes, SAE/AE/SUSAR handling, DSMB reporting, document list, ALCOAC rules, corrections, security, retention, access, review, final report, and distribution.

#### Policy 31: Electronic System Validation and Security Policy

Electronic systems used for clinical trial-related data shall have validation and verification evidence, safeguards against unauthorized use, tampering, and data loss, and documented compliance with applicable data protection regulations.

#### Policy 32: Business Continuity and Disaster Recovery Policy

Information systems shall have documented backup, recovery, maintenance, availability, business continuity, and disaster recovery procedures.

#### Policy 33: Facility Readiness Policy

Sites shall determine and provide the space, work environment, resources, infrastructure, and facility controls necessary to conduct each trial safely and in accordance with the protocol.

#### Policy 34: Medical Equipment Policy

Medical equipment requiring calibration or checks shall be listed, scheduled, assigned, traceable, documented, and prevented from use when defective until deemed fit for purpose.

#### Policy 35: Clinical Trial Product Policy

Clinical trial product receipt, storage, transport, management, dispensing, blinding, access, stock control, expiration, disposal, return, and reconciliation shall be controlled and documented.

#### Policy 36: Key Performance Objective Policy

Sites shall define, implement, measure, monitor, analyze, report, evaluate, and use key performance objectives in decision making.

#### Policy 37: Audit and Assessment Policy

Sites shall conduct internal audits, self-assessments, monitoring reviews, and external assessments as applicable. Findings shall be documented, risk-rated, assigned, corrected, trended, and closed with evidence.

#### Policy 38: Evidence Retention Policy

Evidence shall be retained according to protocol, sponsor, regulatory, legal, institutional, and system requirements. Retention conflicts shall default to the longest applicable retention period unless legal counsel or governing authority determines otherwise.

#### Policy 39: Access Control Policy

Access to protected data, controlled documents, trial records, participant information, sponsor-confidential information, and quality evidence shall be role-based, least-privilege, time-bound, auditable, revocable, and tied to valid identity and authority.

#### Policy 40: Exochain Evidence Anchoring Policy

CyberMedica shall anchor evidence receipts, decision receipts, authority receipts, consent receipts, and audit hashes without exposing PHI/PII or confidential content on public or broadly accessible ledgers. Protected content shall remain in controlled repositories; hashes and metadata shall be minimized according to privacy classification.

### Governance rules

#### Rule 1: Enrollment cannot proceed without active authorization

A participant may not be enrolled unless the protocol is active, the site launch gate is approved, the consent form version is active, required staff training is complete, delegated staff are authorized, and no active blocking risk exists.

#### Rule 2: Superseded consent forms are blocked

Once a new consent form version becomes effective, superseded forms must be blocked from use unless a documented, approved exception applies.

#### Rule 3: Untrained staff cannot perform controlled tasks

A staff member may not perform a protocol-controlled task unless the training matrix, competency evidence, and delegation record permit the action.

#### Rule 4: Delegation expires automatically

Delegated authority expires at its end date, upon role removal, upon training expiration, upon license/certification expiration, upon protocol closure, or upon revocation by authorized leadership.

#### Rule 5: Critical findings require escalation

Critical participant safety, data integrity, ethical, consent, product handling, or unauthorized access findings must be escalated immediately to the required roles and, where applicable, the Decision Forum.

#### Rule 6: Evidence aging affects readiness

Evidence with expired freshness windows cannot support active readiness claims unless explicitly revalidated, replaced, or formally waived.

#### Rule 7: AI cannot be final approver

AI may not be the final approver for launch, enrollment, consent, deviation closure, CAPA closure, risk acceptance, ethics approval, protocol amendment approval, or clinical trial product release.

#### Rule 8: Conflict disclosure is mandatory

Decision participants must disclose conflicts before participating in material decisions. The system must support recusal and record disclosure status.

#### Rule 9: Emergency actions require retrospective review

Emergency actions taken to protect participants or prevent harm may proceed when prior approval is impracticable, but must be recorded, justified, reported as required, and retrospectively reviewed.

#### Rule 10: Protected content must not be exposed through receipts

Exochain receipts must not expose PHI, PII, sponsor-confidential, or privileged content. Receipts must use minimal metadata, hashes, identifiers, and access-controlled references.

#### Rule 11: Document corrections must be attributable

Corrections to controlled documents and records must preserve original content, correction reason, actor, timestamp, and approval where required.

#### Rule 12: CAPA cannot close without evidence

CAPA closure requires objective evidence of completion and effectiveness criteria or documented rationale for why effectiveness cannot yet be determined.

#### Rule 13: Launch gate cannot pass with unresolved blockers

Trial launch authorization cannot pass if there are unresolved critical blockers in protocol approval, consent readiness, training, delegation, facility, product handling, risk mitigation, or required agreements.

#### Rule 14: Audit trail is immutable

System audit trail entries must be append-only and tamper-evident. Users may supplement, correct, supersede, or annotate records but may not silently delete or rewrite historical evidence.

#### Rule 15: Access is least privilege

Users receive the minimum access needed to perform authorized roles. Access must be revoked upon role change, delegation expiration, study closure, termination, or policy violation.

### AI governance requirements

1. AI shall not make final regulated, ethical, clinical, or enrollment-authorizing decisions.
2. AI shall operate under explicit scope and permissions.
3. AI shall identify the evidence used in its analysis.
4. AI shall state confidence and limitations.
5. AI shall flag missing evidence.
6. AI shall flag contradictions.
7. AI shall flag possible participant safety risks.
8. AI shall flag data integrity risks.
9. AI shall flag privacy risks.
10. AI shall flag conflicts or recusal issues where apparent.
11. AI shall not access data outside its authorization scope.
12. AI shall not export protected content without human authorization.
13. AI reviews shall be logged.
14. AI prompts and outputs for material decisions shall be retained as evidence.
15. AI model/version shall be recorded where applicable.
16. AI recommendations shall be contestable.
17. AI-generated summaries shall be marked as AI-generated.
18. AI shall not silently overwrite human-entered evidence.
19. AI shall preserve source references.
20. AI use shall be governed by tenant policy.

### Exochain-specific requirements

CyberMedica shall use Exochain primitives to provide identity, authority, consent, evidence, legal provenance, governance, and audit guarantees.

Required Exochain capabilities include:

1. Decentralized or verifiable identity linkage for authorized actors.
2. Authority chain verification.
3. Delegation scope validation.
4. Consent/bailment policy enforcement.
5. Default-deny access decisions for protected actions.
6. Tamper-evident evidence hashing.
7. Chain-of-custody records.
8. Hash-chained governance audit logs.
9. Decision receipts.
10. Evidence receipts.
11. Consent receipts.
12. Revocation logs.
13. Records retention metadata.
14. Conflict disclosure evidence.
15. Human oversight gate receipts.
16. Contestation/reversal records.
17. Emergency action records.
18. Tenant isolation.
19. Privacy-preserving anchors.
20. Sponsor/CRO export receipts.


## 2. Domain Layer — The Clinical Research Quality World CyberMedica Must Model

The Domain Layer translates clinical research site quality into a complete operating environment. CyberMedica should not ask merely, “Is there a document?” It should ask whether the right person, with the right authority, under the right policy, with the right evidence, reviewed at the right cadence, can safely and ethically execute the relevant clinical research activity.

### 2.0 Domain Architecture Summary

CyberMedica’s domain includes:

1. Clinical research sites and site networks.
2. CRO and sponsor oversight.
3. Site leadership, investigators, coordinators, quality managers, regulatory coordinators, data managers, monitors, auditors, ethics bodies, and Decision Forum members.
4. Standards-derived controls.
5. Site QMS Passport readiness.
6. Protocol feasibility and launch readiness.
7. AI-assisted but human-governed quality review.
8. Evidence and chain-of-custody.
9. Risk, deviations, nonconformance, CAPA, CQI, and audit.
10. Workforce, training, competency, and delegation.
11. Ethical framework and concern reporting.
12. Participant protection and informed consent.
13. Information management and ALCOAC-style data integrity.
14. Facilities, infrastructure, equipment, and clinical trial product accountability.
15. KPI, audit, assessment, reporting, sponsor/CRO diligence, and trust views.

### Target users and stakeholders

#### Primary users

##### Clinical Research Site Leaders

Clinical research site leaders are responsible for site mission, vision, values, strategy, resource allocation, ethical culture, quality commitment, risk posture, workforce capability, facility readiness, and stakeholder communications. They require dashboards, policy controls, review workflows, risk reports, readiness scores, staff competency views, and audit evidence.

##### Principal Investigators and Investigators

Principal investigators and investigators are responsible for the conduct of clinical research at the site. They require protocol readiness views, delegation logs, training evidence, consent process controls, participant safety escalations, deviation reports, SAE/AE workflows, protocol amendments, and study conduct dashboards.

##### Clinical Research Coordinators and Site Staff

Clinical research coordinators and site staff execute study activities. They require role-based task queues, protocol-specific procedures, training requirements, checklists, consent workflows, visit/procedure reminders, specimen handling procedures, document access, deviation reporting, concern reporting, and evidence upload tools.

##### Quality Managers and Quality Leads

Quality managers are responsible for QMS operation, quality planning, risk management, nonconformity handling, CAPA, internal audits, document control, KPI monitoring, continuous improvement, and audit readiness. They require full control libraries, evidence status, risk registers, CAPA workflows, audit plans, training gap views, quality reports, and cross-site benchmarking.

##### CRO Operations Teams

CRO operations teams manage site startup, monitoring, training, performance, issue escalation, sponsor reporting, and portfolio delivery. They require multi-site views, site readiness comparisons, monitoring findings, corrective action tracking, sponsor-facing exports, study startup status, site feasibility evidence, and exception escalation.

##### Sponsor Quality and Clinical Operations Teams

Sponsors require visibility into whether sites and CROs can execute the protocol safely and reliably. They need controlled access to site readiness evidence, risk assessments, quality metrics, monitoring findings, deviations, consent controls, CAPA status, audit records, and study execution readiness.

##### Independent Ethics Committees and IRBs

IRBs and IECs retain their independent legal/ethical role. CyberMedica supports them by exposing appropriate protocol-related evidence, consent process artifacts, investigator/site suitability evidence, facility evidence, participant protection evidence, amendment/deviation workflows, and approved materials.

##### Surveyors, Auditors, Monitors, and Inspectors

Surveyors, auditors, monitors, and inspectors require evidence traceability, document version history, access logs, chain-of-custody, decision rationale, issue history, corrective actions, staff training records, role delegation records, and exportable inspection/audit packets.

##### AI-IRB / AI Quality Review Agents

AI review agents assist with pre-screening, evidence completeness, risk identification, standards mapping, inconsistency detection, missing artifact detection, protocol-to-site fit analysis, consent readability review, trend detection, and decision support. They do not replace authorized human judgment.

##### Decision Forum Members

Decision Forum members participate in governance reviews, escalations, contested decisions, protocol readiness authorizations, quality exception approvals, urgent risk decisions, policy amendments, and cross-stakeholder deliberations.

#### Secondary stakeholders

Secondary stakeholders include clinical trial participants, legally authorized representatives, patient advocacy organizations, hospital administrators, academic research offices, data safety monitoring boards, regulatory authorities, technology vendors, laboratories, pharmacies, imaging providers, logistics providers, data management vendors, and acquisition/diligence teams.

### Product modules

#### 1. Standards and Control Library

The Standards and Control Library stores machine-readable controls derived from the clinical research site QMS standard and related operating requirements. Controls must support mapping to clauses, subclauses, policies, procedures, evidence types, risk categories, owners, roles, review frequency, and applicability conditions.

Each control must include:

1. Control identifier.
2. Control title.
3. Source standard or policy reference.
4. Normative statement.
5. Plain-language explanation.
6. Applicability criteria.
7. Required owner role.
8. Required approver role.
9. Required reviewer role.
10. Required evidence artifacts.
11. Optional supporting evidence.
12. Evidence freshness rules.
13. Review frequency.
14. Trigger events requiring reassessment.
15. Risk criticality.
16. Participant safety relevance.
17. Data integrity relevance.
18. Sponsor diligence relevance.
19. IRB/IEC relevance.
20. CRO oversight relevance.
21. Site operational relevance.
22. AI review prompts.
23. Human review gates.
24. Waiver rules.
25. Escalation rules.
26. CAPA linkage.
27. Audit export mapping.
28. Status.
29. Version.
30. Effective date.
31. Retirement date.
32. Change history.
33. Control dependencies.
34. Crosswalk mappings to other frameworks.

#### 2. Site QMS Passport

The Site QMS Passport is a living trust profile for a clinical research site. It summarizes whether a site has the quality system, people, policies, controls, evidence, and performance capacity necessary to conduct clinical research.

The Site QMS Passport must include:

1. Site identity.
2. Legal entity.
3. Ownership and corporate structure.
4. Site locations.
5. Facility types.
6. Therapeutic areas.
7. Investigator roster.
8. Principal investigator qualifications.
9. Staff roster.
10. Role definitions.
11. Delegation logs.
12. Competency records.
13. Training records.
14. Quality manager designation.
15. Ethical framework.
16. Mission, vision, and values.
17. Site strategy.
18. Organizational chart.
19. Communication plan.
20. Quality plan.
21. Risk management framework.
22. Document control status.
23. SOP inventory.
24. Equipment inventory.
25. Calibration records.
26. Facility readiness evidence.
27. Clinical trial product handling readiness.
28. Informed consent process readiness.
29. Vulnerable population safeguards.
30. SAE/AE reporting readiness.
31. Deviation/CAPA readiness.
32. Internal audit status.
33. Performance objectives.
34. KPI trends.
35. Open findings.
36. Closed findings.
37. Sponsor-facing evidence summary.
38. CRO-facing oversight summary.
39. Regulatory/inspection history, if provided.
40. Readiness status.
41. Quality risk level.
42. Evidence completeness score.
43. Evidence freshness score.
44. Open critical gaps.
45. Open major gaps.
46. Open minor gaps.
47. Last review date.
48. Next review due date.
49. Decision Forum determinations.
50. Exochain evidence receipt references.

#### 3. Protocol Readiness and Trial Startup Governance

This module assesses whether a site is ready to accept and initiate a specific clinical research trial.

The module must support:

1. Protocol intake.
2. Investigator brochure intake.
3. Sponsor-provided materials intake.
4. Clinical trial agreement intake.
5. Site feasibility review.
6. Financial feasibility review.
7. Resource review.
8. Staffing review.
9. Skill-mix review.
10. Facility requirement review.
11. Equipment requirement review.
12. Clinical trial product handling review.
13. Recruitment feasibility review.
14. Participant population review.
15. Vulnerable population safeguards review.
16. Informed consent process review.
17. Data collection requirements review.
18. Information management plan review.
19. SAE/AE reporting requirements review.
20. DSMB reporting requirements review.
21. Vendor/subcontractor review.
22. Laboratory review.
23. Imaging review.
24. Pharmacy review.
25. Logistics review.
26. Risk assessment.
27. Benefit-risk documentation.
28. Insurance/malpractice/negligence protections checklist.
29. Regulatory requirement identification.
30. Industry standard identification.
31. IEC/IRB approval dependency tracking.
32. Sponsor approval dependency tracking.
33. Site authorization gate.
34. Trial launch gate.
35. Enrollment authorization gate.
36. Readiness decision record.
37. Escalation path for unresolved gaps.
38. Sponsor-facing readiness packet.
39. CRO operations readiness packet.
40. Exochain anchored readiness receipt.

#### 4. AI-IRB / AI Quality Review Layer

The AI Quality Review Layer performs structured, explainable, controlled analysis over site evidence, protocols, consent materials, policies, procedures, deviations, CAPAs, training records, and QMS gaps.

AI review functions must include:

1. Clause-to-evidence mapping.
2. Evidence completeness analysis.
3. Evidence freshness analysis.
4. Evidence contradiction detection.
5. Policy/procedure gap detection.
6. Protocol-to-site fit analysis.
7. Consent readability analysis.
8. Consent required-element analysis.
9. Vulnerable population safeguard review.
10. Recruitment ethics review.
11. Risk assessment adequacy review.
12. SAE/AE procedure completeness review.
13. Deviation procedure completeness review.
14. Information management plan review.
15. ALCOAC support review.
16. Training gap detection.
17. Delegation mismatch detection.
18. Qualification mismatch detection.
19. Facility/equipment readiness review.
20. Clinical trial product control review.
21. Communication plan adequacy review.
22. Open finding prioritization.
23. CAPA root cause quality review.
24. CAPA effectiveness check suggestions.
25. KPI trend anomaly detection.
26. Sponsor diligence summary generation.
27. Audit packet assembly recommendations.
28. Decision Forum brief generation.
29. Escalation recommendations.
30. Human review prompt generation.

AI outputs must be labeled as assistance, not final authority. Every AI recommendation must include the evidence used, confidence level, limits of analysis, unresolved assumptions, potential conflicts, and recommended human reviewer role.

#### 5. Empowered Decision Forum

The Empowered Decision Forum is the human-governed review and decision layer for material quality, risk, readiness, policy, and exception decisions.

Decision Forum functions must include:

1. Create decision matter.
2. Define decision type.
3. Attach evidence bundle.
4. Attach AI analysis.
5. Identify applicable controls.
6. Identify required quorum.
7. Identify required voting roles.
8. Identify conflicts of interest.
9. Require disclosures.
10. Support recusal.
11. Support abstention.
12. Support approve, approve with conditions, defer, reject, escalate, contest, emergency authorize, and revoke decisions.
13. Capture rationale.
14. Capture minority views.
15. Capture dissent.
16. Capture conditions.
17. Capture expiration of decision.
18. Capture required follow-up actions.
19. Capture CAPA linkage.
20. Capture sponsor/CRO notification requirement.
21. Capture IRB/IEC notification requirement.
22. Capture regulatory notification requirement.
23. Trigger evidence receipts.
24. Trigger audit entries.
25. Trigger authority checks.
26. Trigger revocation or suspension where required.
27. Support appeal or contestation.
28. Support emergency escalation.
29. Support retrospective review of emergency actions.
30. Produce decision certificate.

#### 6. Evidence and Chain-of-Custody Layer

The Evidence Layer manages artifacts supporting quality claims and decisions. Evidence may include documents, attestations, signatures, screenshots, system exports, SOPs, training certificates, logs, calibration records, policies, procedures, reports, meeting minutes, consent forms, review records, audit findings, CAPA records, communications, and external certifications.

Evidence objects must include:

1. Evidence identifier.
2. Evidence type.
3. Title.
4. Description.
5. Source system.
6. Creator.
7. Uploader.
8. Current custodian.
9. Owner role.
10. Linked control.
11. Linked site.
12. Linked protocol.
13. Linked study.
14. Linked participant status, if applicable and permitted.
15. Linked staff member, if applicable and permitted.
16. Linked equipment, if applicable.
17. Linked facility, if applicable.
18. Linked vendor, if applicable.
19. Linked decision matter.
20. Hash.
21. Version.
22. Effective date.
23. Expiration date.
24. Review status.
25. Approval status.
26. Confidentiality classification.
27. PHI/PII classification.
28. Sponsor confidentiality classification.
29. Retention rule.
30. Access policy.
31. Disclosure policy.
32. Chain-of-custody record.
33. Admissibility status.
34. Review history.
35. Signature history.
36. Correction history.
37. Supersession history.
38. Linked audit log entries.
39. Exochain receipt.
40. Export eligibility.

#### 7. Risk Management Module

The Risk Management Module implements a clinical research site risk framework.

Risk objects must include:

1. Risk identifier.
2. Risk title.
3. Risk description.
4. Source.
5. Risk category.
6. Participant safety impact.
7. Data integrity impact.
8. Ethical impact.
9. Regulatory impact.
10. Operational impact.
11. Financial impact.
12. Sponsor impact.
13. CRO impact.
14. Probability.
15. Severity.
16. Detectability.
17. Overall risk rating.
18. Risk owner.
19. Linked control.
20. Linked protocol.
21. Linked site process.
22. Linked evidence.
23. Mitigation plan.
24. Safety plan, if applicable.
25. Preventive action.
26. Corrective action.
27. Monitoring metric.
28. Review frequency.
29. Trigger conditions.
30. Escalation threshold.
31. Decision Forum linkage.
32. Residual risk.
33. Acceptance rationale.
34. Approver.
35. Review history.
36. Closure evidence.
37. Exochain receipt.

The system must support risk identification, risk assessment, risk treatment, risk control, risk reporting, and continuous reassessment.

#### 8. Quality Planning and Continuous Quality Improvement Module

The CQI module manages quality planning, improvements, innovation projects, lessons learned, stakeholder feedback, staff feedback, internal audits, self-assessments, complaints, nonconformity reporting, CAPA, and effectiveness checks.

CQI objects must include:

1. Improvement identifier.
2. Improvement source.
3. Problem statement.
4. Related control.
5. Related process.
6. Related risk.
7. Related deviation.
8. Related complaint.
9. Root cause analysis.
10. Proposed change.
11. Expected benefit.
12. Potential risk.
13. Required resources.
14. Owner.
15. Approver.
16. Implementation plan.
17. Due date.
18. Training impact.
19. SOP impact.
20. Technology impact.
21. Budget impact.
22. Stakeholder impact.
23. Evidence requirement.
24. Verification method.
25. Effectiveness check.
26. Decision Forum linkage.
27. Closure status.
28. Lessons learned.
29. Exochain receipt.

#### 9. Deviation, Nonconformance, and CAPA Module

This module manages deviations from protocol, nonconformities, errors, unplanned deviations, planned deviations, corrective actions, preventive actions, and effectiveness checks.

Deviation objects must include:

1. Deviation identifier.
2. Study/protocol link.
3. Site link.
4. Date/time discovered.
5. Discoverer.
6. Discovery method.
7. Description.
8. Planned or unplanned.
9. Immediate participant risk.
10. Immediate action taken.
11. Protocol section impacted.
12. Consent impact.
13. Data integrity impact.
14. Randomization impact.
15. Blinding impact.
16. SAE/AE linkage.
17. Sponsor reporting requirement.
18. IRB/IEC reporting requirement.
19. Regulatory reporting requirement.
20. Root cause.
21. Corrective action.
22. Preventive action.
23. Owner.
24. Due date.
25. Status.
26. Verification evidence.
27. Effectiveness check.
28. Closure approver.
29. Decision Forum escalation, if required.
30. Exochain receipt.

CAPA objects must include:

1. CAPA identifier.
2. CAPA type.
3. Source event.
4. Root cause category.
5. Root cause narrative.
6. Corrective action plan.
7. Preventive action plan.
8. Responsible owner.
9. Required resources.
10. Due dates.
11. Impacted policies.
12. Impacted SOPs.
13. Impacted training.
14. Impacted systems.
15. Verification method.
16. Effectiveness criteria.
17. Follow-up date.
18. Evidence package.
19. Closure decision.
20. Reopen conditions.
21. Exochain receipt.

#### 10. Workforce, Training, Competency, and Delegation Module

This module manages people-centered workforce requirements, skill-mix review, qualifications, competencies, training, orientation, integration, performance review, leadership development, rights, well-being, and delegation.

Staff profile objects must include:

1. Staff identifier.
2. Name.
3. Role.
4. Title.
5. Department.
6. Site.
7. Employment or contract status.
8. Qualifications.
9. Licenses.
10. Certifications.
11. Experience.
12. Training records.
13. Competency attestations.
14. Role requirements.
15. Protocol assignments.
16. Delegated responsibilities.
17. Start date.
18. End date.
19. Access rights.
20. System privileges.
21. Training gaps.
22. Competency gaps.
23. Performance review status.
24. Well-being concern status, if applicable and permitted.
25. Conflict disclosures.
26. Recusal records.
27. Exochain identity/authority linkage.

Training objects must include:

1. Training identifier.
2. Training title.
3. Training type.
4. Required roles.
5. Required protocols.
6. Required controls.
7. Required frequency.
8. Training material.
9. Training provider.
10. Completion evidence.
11. Assessment score.
12. Competency verification.
13. Expiration.
14. Refresher requirement.
15. Supervisor approval.
16. External body reporting eligibility.
17. Exochain receipt.

Delegation objects must include:

1. Delegation identifier.
2. Delegator.
3. Delegate.
4. Role delegated.
5. Scope.
6. Protocol linkage.
7. Site linkage.
8. Start date.
9. End date.
10. Required qualifications.
11. Required training.
12. Verification status.
13. Limitations.
14. Revocation conditions.
15. Delegation approval.
16. Linked authority chain.
17. Audit record.
18. Exochain receipt.

#### 11. Ethical Framework and Concern Reporting Module

This module manages the site ethical framework, code of conduct, societal responsibility, open/inclusive leadership policy, anonymous concerns, no-blame culture, complaint handling, and staff rights.

Ethics framework must include:

1. Ethical statement.
2. Code of conduct.
3. Societal responsibility statement.
4. Open and inclusive leadership policy.
5. Conflict of interest policy.
6. Recusal policy.
7. Concern reporting policy.
8. Anonymous reporting process.
9. Non-retaliation policy.
10. No-blame culture policy.
11. Complaint handling procedure.
12. Investigation procedure.
13. Escalation procedure.
14. Decision Forum linkage.
15. Training requirement.
16. Evidence requirements.
17. Review cadence.
18. Audit trail.

Concern objects must include:

1. Concern identifier.
2. Reporter identity or anonymous marker.
3. Date/time.
4. Concern type.
5. Description.
6. Site.
7. Study/protocol linkage, if applicable.
8. Participant safety impact.
9. Ethical impact.
10. Data integrity impact.
11. Retaliation risk.
12. Immediate escalation flag.
13. Assigned investigator.
14. Investigation status.
15. Findings.
16. Corrective action.
17. Communication record.
18. Closure decision.
19. Reporter notification status, if permitted.
20. Exochain receipt.

#### 12. Participant Protection and Informed Consent Module

This module manages informed consent policies, participant communications, consent documentation, assent, reconsent, legally authorized representatives, vulnerable populations, withdrawal, early termination, suspension, data sharing consent, and participant rights.

Consent process objects must include:

1. Consent process identifier.
2. Protocol linkage.
3. Approved consent form version.
4. IEC/IRB approval record.
5. Consent language/readability review.
6. Required consent elements.
7. Known risks statement.
8. Unknown risks statement.
9. Privacy compliance statement.
10. Non-waiver of legal rights check.
11. Non-release from negligence check.
12. Alternative procedures disclosure.
13. Confidentiality assurance.
14. Financial consideration disclosure.
15. Question opportunity procedure.
16. Non-coercion disclaimer.
17. Time-to-review procedure.
18. Private setting procedure.
19. Witness requirement.
20. LAR requirement.
21. Assent requirement.
22. Vulnerable population safeguards.
23. Emergency consent exception process.
24. Waiver of documentation process.
25. Reconsent trigger rules.
26. Updated information dissemination rules.
27. Participant copy delivery evidence.
28. Withdrawal process.
29. Lost-to-follow-up process.
30. Data sharing consent evidence.
31. Exochain consent/bailment linkage.

Participant protection workflows must enforce:

1. No enrollment without applicable consent authorization, unless a documented emergency/waiver process applies.
2. No use of superseded consent forms after effective date of new approved version.
3. No consent collection by untrained staff.
4. No recruitment of vulnerable populations without applicable safeguards.
5. No continuation after material new information without documented communication/reconsent determination.
6. No participant-facing material distribution without IEC/IRB approval where required.
7. No coercive language or waiver of legal rights in participant materials.
8. No unauthorized data sharing beyond documented consent.

#### 13. Information Management and Data Integrity Module

This module manages clinical trial information management plans, record lists, source data traceability, document control, CRF media, discrepancy reporting, urgent reporting, SAE/AE/SUSAR reporting, DSMB reporting, document version history, ALCOAC support, correction records, safe-keeping, access, retention, final report requirements, and distribution.

Information management plan objects must include:

1. Plan identifier.
2. Protocol linkage.
3. Sponsor linkage.
4. Site linkage.
5. Milestones.
6. Deadlines.
7. Source data definition.
8. Source data traceability.
9. Participant code rules.
10. Required records.
11. CRF media.
12. Data elements to report.
13. Discrepancy reporting procedure.
14. Urgent change reporting procedure.
15. SAE reporting procedure.
16. AE reporting procedure.
17. SUSAR reporting procedure.
18. DSMB reporting requirement.
19. Sponsor reporting frequency.
20. Document inventory.
21. Version history.
22. Approval dates.
23. ALCOAC requirements.
24. Correction rules.
25. Document storage rules.
26. Document security rules.
27. Retention period.
28. Access permissions.
29. Review frequency.
30. Final report requirements.
31. Distribution rules.
32. Staff communication evidence.

Electronic systems must support:

1. Validation evidence.
2. Verification evidence.
3. Regulatory compliance mapping.
4. Unauthorized use protection.
5. Tampering protection.
6. Data loss protection.
7. Data protection regulation checks.
8. Setup/installation/use procedures.
9. Confidentiality procedures.
10. Integrity procedures.
11. Availability procedures.
12. Backup procedures.
13. Recovery procedures.
14. Maintenance procedures.
15. Business continuity procedures.
16. Disaster recovery procedures.
17. Authorized access list.
18. Access start date.
19. Access removal date.
20. Monitor/auditor/IEC/regulator access controls.

#### 14. Facility, Infrastructure, Equipment, and Clinical Trial Product Module

This module manages physical environment, facility readiness, infrastructure, equipment, calibration, defective equipment handling, clinical trial product receipt/storage/transport/dispensing/access/disposal, stock control, and product accountability.

Facility readiness objects must include:

1. Facility identifier.
2. Location.
3. Trial-specific requirements.
4. Work environment assessment.
5. Participant environment assessment.
6. Staff well-being assessment.
7. Health and safety assessment.
8. Accessibility assessment.
9. Equipment list.
10. Infrastructure list.
11. Maintenance program.
12. Required utilities.
13. Required storage.
14. Required security.
15. Required privacy.
16. Monitoring evidence.
17. Readiness status.
18. Gap list.
19. Approval status.
20. Exochain receipt.

Equipment objects must include:

1. Equipment identifier.
2. Equipment type.
3. Manufacturer.
4. Serial number.
5. Location.
6. Protocol linkage.
7. Calibration required flag.
8. Calibration frequency.
9. Calibration responsible party.
10. Calibration standard traceability.
11. Last calibration date.
12. Next calibration due.
13. Calibration evidence.
14. Check-before-use requirement.
15. Defect status.
16. Quarantine status.
17. Return-to-service approval.
18. Maintenance record.
19. Exochain receipt.

Clinical trial product objects must include:

1. Product identifier.
2. Protocol linkage.
3. Sponsor linkage.
4. Product type.
5. Batch/serial number.
6. Expiration date.
7. Quantity received.
8. Receipt record.
9. Storage requirement.
10. Storage location.
11. Temperature/control evidence.
12. Access permissions.
13. Dispensing responsibility.
14. Blinding responsibility.
15. Transport requirements.
16. Transit integrity controls.
17. Unique code number linkage.
18. Participant administration/prescription records.
19. Stock reconciliation.
20. Expired product management.
21. Damaged/contaminated product management.
22. Return/disposal record.
23. Nonconformity linkage.
24. Exochain receipt.

#### 15. Evaluation, Assessment, Audit, KPI, and Reporting Module

This module manages key performance objectives, monitoring progress, data collection, self-assessment, internal audit, external audit, surveyor review, sponsor monitoring, findings, reporting, dashboards, and export packets.

KPI objects must include:

1. KPI identifier.
2. KPI name.
3. Source strategy/control.
4. Definition.
5. Numerator.
6. Denominator.
7. Collection method.
8. Frequency.
9. Owner.
10. Threshold.
11. Target.
12. Alert rule.
13. Risk linkage.
14. Quality objective linkage.
15. Reporting audience.
16. Trend.
17. Decision use.
18. Exochain receipt.

Audit objects must include:

1. Audit identifier.
2. Audit type.
3. Scope.
4. Site.
5. Study/protocol linkage.
6. Auditor.
7. Auditor independence status.
8. Date.
9. Controls reviewed.
10. Evidence reviewed.
11. Findings.
12. Severity.
13. CAPA linkage.
14. Report.
15. Management response.
16. Closure evidence.
17. Follow-up requirement.
18. Export eligibility.
19. Exochain receipt.

Assessment objects must include:

1. Assessment identifier.
2. Assessment type.
3. Standard/control set.
4. Site.
5. Candidate status.
6. Submitted evidence.
7. Reviewer assignments.
8. Comments.
9. Recommendations.
10. Approvals.
11. Conditions.
12. Assessment manager.
13. Close assessment status.
14. Locked report.
15. Final recommendation.
16. Decision Forum linkage.
17. Exochain receipt.

### Roles and responsibilities

#### Site Executive Sponsor

Responsible for ensuring the site maintains leadership commitment, resources, strategy, ethical framework, quality policy, accountability, and overall QMS support.

Responsibilities:

1. Approve site mission, vision, and values.
2. Approve site strategy.
3. Ensure resources for QMS.
4. Ensure quality leadership is appointed.
5. Review major quality risks.
6. Support open and inclusive leadership.
7. Review major sponsor/CRO diligence outputs.
8. Approve major policy changes.
9. Participate in Decision Forum when required.

#### Clinical Research Site Leader

Responsible for operational execution of the site QMS.

Responsibilities:

1. Maintain site QMS Passport.
2. Ensure role assignments.
3. Ensure communication plan.
4. Ensure ethical framework implementation.
5. Ensure staff training and competency.
6. Ensure risk management.
7. Ensure quality planning.
8. Ensure stakeholder communication.
9. Review open findings.
10. Support audits and assessments.

#### Principal Investigator

Responsible for conduct of the clinical research trial at the site.

Responsibilities:

1. Confirm protocol understanding.
2. Confirm delegation log.
3. Confirm staff qualifications.
4. Confirm participant protection procedures.
5. Confirm consent process.
6. Manage participant safety obligations.
7. Review SAEs/AEs as required.
8. Manage protocol deviations.
9. Ensure data integrity.
10. Sign investigator readiness.
11. Participate in launch authorization.

#### Quality Manager

Responsible for QMS controls, quality planning, risk management, audit, CAPA, and continuous improvement.

Responsibilities:

1. Maintain control library applicability.
2. Maintain document control process.
3. Manage self-assessment.
4. Manage internal audit.
5. Manage nonconformance process.
6. Manage CAPA process.
7. Maintain risk register.
8. Review quality metrics.
9. Approve quality evidence.
10. Recommend readiness decisions.
11. Escalate critical gaps.

#### Clinical Lead / Study Manager

Responsible for day-to-day operational study management.

Responsibilities:

1. Manage study startup checklist.
2. Coordinate staff assignments.
3. Coordinate training completion.
4. Coordinate sponsor/CRO communication.
5. Track protocol milestones.
6. Track monitoring actions.
7. Track deviations.
8. Ensure staff communication.
9. Support participant visit readiness.
10. Maintain study information management plan.

#### Clinical Research Coordinator

Responsible for executing assigned study activities.

Responsibilities:

1. Complete required training.
2. Execute delegated tasks.
3. Document source data and study records.
4. Support informed consent process if delegated.
5. Report deviations and concerns.
6. Support participant communications.
7. Maintain required logs.
8. Support monitoring visits.
9. Follow protocol-specific procedures.

#### Regulatory Coordinator

Responsible for regulatory document readiness and submission support.

Responsibilities:

1. Maintain regulatory document inventory.
2. Track IEC/IRB approvals.
3. Track protocol amendments.
4. Track consent form approvals.
5. Track continuing reviews.
6. Maintain investigator documents.
7. Support sponsor/regulatory exports.
8. Manage document versioning.

#### Training Manager

Responsible for training matrix, training assignments, competency records, and training evidence.

Responsibilities:

1. Maintain role-based training requirements.
2. Assign required training.
3. Track completion.
4. Track expiration.
5. Verify competency evidence.
6. Report training gaps.
7. Block delegation where training is missing.

#### Facility Manager

Responsible for facility readiness, infrastructure, equipment, safety, maintenance, and environmental controls.

Responsibilities:

1. Maintain facility inventory.
2. Maintain infrastructure evidence.
3. Maintain equipment lists.
4. Track calibration.
5. Quarantine defective equipment.
6. Provide readiness evidence.
7. Support audits and inspections.

#### Pharmacy / Investigational Product Manager

Responsible for clinical trial product receipt, storage, dispensing, accountability, access control, expiration, return, and destruction.

Responsibilities:

1. Record product receipt.
2. Maintain storage controls.
3. Maintain access controls.
4. Track batch/serial/expiration.
5. Manage stock reconciliation.
6. Manage dispensing records.
7. Manage return/disposal.
8. Report nonconformities.

#### Data Manager

Responsible for data collection, data integrity, discrepancy handling, source traceability, and information management plan execution.

Responsibilities:

1. Maintain source data traceability.
2. Track CRF requirements.
3. Manage data discrepancy workflows.
4. Support ALCOAC expectations.
5. Maintain data access controls.
6. Support final report data requirements.

#### Monitor / CRA

Responsible for sponsor/CRO monitoring activities.

Responsibilities:

1. Review site records.
2. Review source/CRF consistency.
3. Review protocol adherence.
4. Review consent records.
5. Review safety reporting.
6. Issue findings.
7. Track action items.
8. Support sponsor/CRO oversight.

#### Auditor

Responsible for independent audit review.

Responsibilities:

1. Define audit scope.
2. Review evidence.
3. Conduct interviews.
4. Identify findings.
5. Classify severity.
6. Recommend CAPA.
7. Produce audit report.
8. Verify closure.

#### Decision Forum Chair

Responsible for governing material decision proceedings.

Responsibilities:

1. Confirm matter scope.
2. Confirm required quorum.
3. Confirm required roles.
4. Confirm conflict disclosure.
5. Manage deliberation.
6. Ensure rationale capture.
7. Close decision.
8. Ensure follow-up actions.
9. Ensure receipt generation.

#### AI Quality Reviewer

Responsible for assisting with structured analysis under human oversight.

Responsibilities:

1. Map evidence to controls.
2. Identify missing evidence.
3. Identify contradictions.
4. Identify risk signals.
5. Draft review summaries.
6. Recommend escalation.
7. Provide confidence and limitations.
8. Preserve evidence references.
9. Never act as final authority.

#### System Administrator

Responsible for tenant setup, access control, integrations, configuration, and security operations.

Responsibilities:

1. Configure tenant.
2. Configure roles.
3. Configure access policies.
4. Configure integrations.
5. Manage identity provider settings.
6. Monitor security logs.
7. Support backup/recovery.
8. Enforce access revocation.

#### Sponsor Viewer

Responsible for reviewing authorized sponsor-facing evidence and status.

Responsibilities:

1. Review readiness packets.
2. Review open findings.
3. Review CAPA status.
4. Review risk summaries.
5. Request clarification.
6. Receive authorized exports.
7. Respect access limitations.

#### CRO Portfolio Manager

Responsible for cross-site oversight and sponsor reporting.

Responsibilities:

1. Monitor site readiness across portfolio.
2. Compare sites.
3. Track startup status.
4. Track findings and CAPAs.
5. Manage sponsor reports.
6. Escalate systemic risk.
7. Identify training and quality trends.


## 3. Data Layer — Objects, Boundaries, Evidence, Authority, and Receipts

The Data Layer defines the durable substrate of CyberMedica. Data in this product is not merely stored; it is classified, permissioned, versioned, reviewed, linked to authority, tied to evidence, monitored for freshness, and, where appropriate, represented by privacy-preserving Exochain receipts.

### 3.0 Data Architecture Commitments

1. Every object that supports readiness, safety, participant protection, data integrity, sponsor diligence, or quality assurance must have ownership, status, evidence linkage, review rules, and auditability.
2. Protected content must be classified by confidentiality, PHI/PII status, sponsor confidentiality, participant linkage, export eligibility, retention rule, and access policy.
3. Evidence objects must preserve custody, correction, version, review, signature, supersession, and receipt history.
4. Authority-bearing actions must validate role, delegation, training, competence, site/study/protocol scope, expiration, and conflict/recusal state.
5. Exochain anchors should store receipts, manifests, hashes, attestations, timestamps, and decision records — not raw protected content.
6. Readiness, assessment, launch, enrollment, delegation, consent, deviation closure, CAPA closure, audit finalization, and sponsor export are data-state transitions requiring explicit authority and audit evidence.

### 3.1 Core Data Classes

| Data class | Examples | Default posture |
|---|---|---|
| Public / non-sensitive | Approved public product description, non-confidential marketing copy. | Public or broadly visible only after approval. |
| Tenant operational | Site names, roles, dashboard states, workflow tasks. | Tenant-scoped. |
| Sponsor/CRO confidential | Protocol material, diligence packets, sponsor requirements, CTA terms. | Access-controlled by study, sponsor, CRO, and disclosure policy. |
| Participant-linked / PHI / PII | Participant code linkages, consent evidence, AE/SAE details, records that may identify individuals. | Minimized, encrypted, strictly permissioned, never broadly anchored. |
| Quality evidence | SOPs, training, calibration, CAPA, audit, consent process, product accountability, facility records. | Versioned, evidence-linked, freshness-scored, receipt-capable. |
| Decision/governance | Decision Forum matters, votes, rationales, dissent, recusal, emergency review. | Auditable, contestable, receipt-capable. |
| Immutable receipts | Evidence hashes, decision hashes, authority/consent receipts, export manifests. | Minimal metadata, privacy-preserving, tamper-evident. |

### Permission model

The system shall implement role-based access control, attribute-based access control, authority-chain validation, least privilege, time-bound access, tenant isolation, study-level isolation, sponsor-visible view constraints, and revocation.

Permission dimensions shall include:

1. Tenant.
2. Site.
3. Study.
4. Protocol.
5. Role.
6. Delegation.
7. Sponsor visibility.
8. CRO visibility.
9. Confidentiality classification.
10. PHI/PII classification.
11. Evidence type.
12. Decision matter.
13. Action type.
14. Emergency access.
15. Expiration.

Actions requiring explicit authority include:

1. Site QMS Passport approval.
2. Control library publication.
3. Policy approval.
4. SOP approval.
5. Trial acceptance.
6. Trial launch authorization.
7. Enrollment authorization.
8. Consent form activation.
9. Delegation approval.
10. Deviation closure.
11. CAPA closure.
12. Critical risk acceptance.
13. Audit report finalization.
14. Sponsor export release.
15. Evidence disclosure.
16. Emergency override.
17. Access to sensitive participant-linked evidence.
18. Clinical trial product release/use authorization.

### Data model overview

Core data entities shall include:

1. Tenant.
2. Organization.
3. Site.
4. Facility.
5. Study.
6. Protocol.
7. Protocol amendment.
8. Clinical trial agreement.
9. Sponsor.
10. CRO.
11. IEC/IRB.
12. User.
13. Role.
14. Responsibility.
15. Delegation.
16. Authority chain.
17. Staff profile.
18. Training requirement.
19. Training completion.
20. Competency attestation.
21. Policy.
22. Procedure.
23. SOP.
24. Controlled document.
25. Control.
26. Control assessment.
27. Evidence object.
28. Evidence receipt.
29. Chain-of-custody record.
30. Risk.
31. Risk assessment.
32. Mitigation.
33. Safety plan.
34. Deviation.
35. Nonconformance.
36. CAPA.
37. Complaint.
38. Concern.
39. AE/SAE/SUSAR.
40. Consent form.
41. Consent process.
42. Participant code.
43. Data sharing consent.
44. Information management plan.
45. Equipment.
46. Calibration record.
47. Clinical trial product.
48. Product accountability record.
49. Audit.
50. Finding.
51. KPI.
52. Decision matter.
53. Decision vote.
54. Decision rationale.
55. Conflict disclosure.
56. Recusal.
57. AI review.
58. Export packet.
59. Disclosure log.
60. Audit log entry.
61. Exochain anchor.


## 4. Doors Layer — Role-Specific Journeys, Gates, Procedures, and Dashboards

The Doors Layer makes the product operational. A clinical research site leader, PI, coordinator, quality manager, CRO portfolio manager, sponsor viewer, auditor, Decision Forum chair, and AI quality reviewer should not enter the same door. Each role needs the right dashboard, tasks, controls, evidence visibility, decision gates, and support paths.

### 4.0 Door Design Rules

1. Each door must expose only the controls and evidence the role is permitted to see.
2. Each dashboard must show readiness, blockers, duties, due dates, evidence gaps, risks, and pending decisions relevant to that role.
3. Each procedure must be executable as a workflow with typed inputs, outputs, approvals, receipts, and audit events.
4. Critical actions must fail closed when training, delegation, consent, site launch, protocol approval, evidence freshness, or authority state is invalid.
5. Sponsor/CRO and auditor views must support diligence and inspection without overexposing protected content.

### Core procedures

#### Procedure 1: Create and Approve Site QMS Profile

1. Create site record.
2. Enter legal entity and site identity data.
3. Assign site leadership.
4. Assign quality manager.
5. Upload mission, vision, and values.
6. Upload strategy.
7. Upload ethical framework.
8. Upload organization chart.
9. Upload communication plan.
10. Upload quality policy.
11. Upload risk management framework.
12. Upload SOP index.
13. Upload training matrix.
14. Upload facility evidence.
15. Upload equipment inventory.
16. Upload document control procedure.
17. Upload deviation/CAPA procedure.
18. Run AI evidence completeness review.
19. Resolve critical gaps.
20. Submit to quality review.
21. Quality reviewer approves, approves with conditions, or rejects.
22. Decision receipt is generated.
23. Site QMS Passport status is updated.

#### Procedure 2: Convert Standard Requirement to Control

1. Identify normative requirement.
2. Assign control identifier.
3. Draft control title.
4. Enter source reference.
5. Enter requirement text.
6. Define applicability.
7. Define owner.
8. Define reviewer.
9. Define approver.
10. Define evidence requirements.
11. Define evidence freshness.
12. Define review frequency.
13. Define risk category.
14. Define escalation triggers.
15. Define waiver rules.
16. Define AI review prompt.
17. Define decision gate, if applicable.
18. Map crosswalks.
19. Submit for governance review.
20. Approve through Decision Forum if material.
21. Publish active control version.

#### Procedure 3: Conduct Site Self-Assessment

1. Select site.
2. Select control set.
3. Generate assessment workspace.
4. Assign control owners.
5. Assign reviewers.
6. Upload required evidence.
7. Mark control applicability.
8. Identify not-applicable rationale where used.
9. Run AI evidence review.
10. Resolve missing evidence.
11. Reviewer evaluates each control.
12. Findings are generated.
13. Findings are severity-rated.
14. CAPAs are opened where required.
15. Assessment manager closes review.
16. Assessment report is locked.
17. Site passport updates.
18. Evidence receipts are generated.

#### Procedure 4: Conduct Protocol Feasibility Review

1. Intake protocol.
2. Intake investigator brochure or equivalent product documentation.
3. Intake sponsor/CRO feasibility questionnaire.
4. Intake known regulatory requirements.
5. Review participant population.
6. Review recruitment feasibility.
7. Review staffing needs.
8. Review training needs.
9. Review facility needs.
10. Review equipment needs.
11. Review clinical trial product handling needs.
12. Review vendor/subcontractor needs.
13. Review budget and financial feasibility.
14. Review insurance/claims protections.
15. Review privacy/data requirements.
16. Review reporting requirements.
17. Run AI protocol-to-site fit review.
18. Generate risk assessment.
19. Generate gap list.
20. Escalate critical unresolved gaps.
21. Site leadership decides acceptance readiness.
22. Record decision and rationale.
23. Generate protocol feasibility receipt.

#### Procedure 5: Conduct Trial Startup Risk Assessment

1. Create startup risk assessment.
2. Link to protocol.
3. Link to site.
4. Identify participant safety risks.
5. Identify rights/well-being risks.
6. Identify consent risks.
7. Identify data integrity risks.
8. Identify facility risks.
9. Identify product handling risks.
10. Identify staffing risks.
11. Identify vendor risks.
12. Identify regulatory risks.
13. Identify operational risks.
14. Assess probability, severity, detectability.
15. Define mitigations.
16. Define safety plan if required.
17. Define monitoring metrics.
18. Assign risk owners.
19. Submit for quality review.
20. Escalate unacceptable residual risks.
21. Approve, approve with conditions, defer, or reject startup readiness.
22. Generate risk receipt.

#### Procedure 6: Authorize Trial Launch

1. Confirm protocol approval status.
2. Confirm IEC/IRB approval status.
3. Confirm clinical trial agreement execution.
4. Confirm information management plan.
5. Confirm site feasibility approval.
6. Confirm startup risk assessment approval.
7. Confirm staff training completion.
8. Confirm delegation log completion.
9. Confirm consent form version readiness.
10. Confirm facility readiness.
11. Confirm equipment readiness.
12. Confirm product handling readiness.
13. Confirm SAE/AE reporting readiness.
14. Confirm monitoring arrangements.
15. Confirm document inventory.
16. Confirm sponsor/CRO required approvals.
17. Run AI launch gate review.
18. Quality manager signs readiness recommendation.
19. PI signs investigator readiness.
20. Authorized representative approves launch.
21. Enrollment authorization becomes active.
22. Launch receipt is generated.

#### Procedure 7: Manage Informed Consent Materials

1. Upload consent form.
2. Link to protocol.
3. Enter version/date.
4. Enter IEC/IRB approval evidence.
5. Run AI required-element review.
6. Run AI readability review.
7. Run privacy/non-waiver/non-negligence release review.
8. Identify vulnerable population requirements.
9. Assign consent process owner.
10. Approve consent form for site use.
11. Publish active version.
12. Retire superseded versions.
13. Notify staff of changes.
14. Trigger reconsent review if material information changes.
15. Generate evidence receipt.

#### Procedure 8: Obtain and Document Participant Consent

1. Confirm active approved consent form.
2. Confirm staff member is trained and delegated.
3. Confirm participant or legally authorized representative status.
4. Confirm private/confidential setting.
5. Provide written information.
6. Allow questions.
7. Allow sufficient review time.
8. Confirm understanding of risks.
9. Confirm voluntariness.
10. Document assent where applicable.
11. Obtain signatures and dates.
12. Provide copy to participant.
13. Record consent evidence.
14. Record data sharing consent.
15. Anchor consent receipt if applicable.
16. Enable enrollment only after consent gate passes.

#### Procedure 9: Manage Protocol Deviation

1. Create deviation record.
2. Identify discovery date/time.
3. Identify discoverer.
4. Link to protocol and site.
5. Describe deviation.
6. Classify planned/unplanned.
7. Assess immediate participant risk.
8. Take immediate safety action if required.
9. Assess data integrity impact.
10. Assess consent impact.
11. Assess randomization/blinding impact.
12. Determine sponsor reporting requirement.
13. Determine IEC/IRB reporting requirement.
14. Determine regulatory reporting requirement.
15. Notify required parties.
16. Conduct root cause analysis.
17. Define corrective action.
18. Define preventive action.
19. Assign owner and due date.
20. Verify completion.
21. Conduct effectiveness check.
22. Close with approval.
23. Generate deviation/CAPA receipt.

#### Procedure 10: Manage AE/SAE/SUSAR

1. Create safety event record.
2. Classify AE, SAE, SUSAR, or other protocol-defined event.
3. Record participant unique identifier.
4. Record event details.
5. Record relatedness.
6. Record severity.
7. Record onset/resolution dates.
8. Attach laboratory, autopsy, medical, or other relevant reports.
9. Initiate required clinical response.
10. Determine sponsor reporting timeline.
11. Determine IEC/IRB reporting timeline.
12. Determine regulatory reporting timeline.
13. Notify required parties.
14. Investigate if appropriate.
15. Track follow-up reports.
16. Link to deviations/CAPA where applicable.
17. Close when reporting and follow-up are complete.
18. Generate safety event receipt.

#### Procedure 11: Manage CAPA

1. Open CAPA from finding, deviation, audit, complaint, concern, or trend.
2. Classify CAPA.
3. Assign owner.
4. Conduct root cause analysis.
5. Document cause/effect.
6. Assess risk.
7. Define corrective action.
8. Define preventive action.
9. Define impacted policies/SOPs/training.
10. Define verification method.
11. Define effectiveness criteria.
12. Approve CAPA plan.
13. Implement actions.
14. Upload evidence.
15. Verify completion.
16. Perform effectiveness check.
17. Close or reopen.
18. Generate CAPA receipt.

#### Procedure 12: Conduct Internal Audit

1. Create audit plan.
2. Define scope.
3. Select controls.
4. Assign independent auditor.
5. Schedule audit.
6. Collect evidence.
7. Conduct interviews if applicable.
8. Review documents.
9. Review records.
10. Record findings.
11. Classify severity.
12. Create CAPAs where required.
13. Draft audit report.
14. Obtain management response.
15. Approve final report.
16. Track closure.
17. Generate audit receipt.

#### Procedure 13: Manage Staff Training Gap

1. System identifies role/training requirement.
2. Compare requirement to training record.
3. Create gap.
4. Notify staff member and supervisor.
5. Assign training.
6. Complete training.
7. Complete assessment, if required.
8. Supervisor or trainer verifies competence.
9. Update training record.
10. Remove gap.
11. Generate training receipt.
12. Update delegation eligibility.

#### Procedure 14: Manage Delegation

1. Create delegation request.
2. Identify delegator.
3. Identify delegate.
4. Define responsibility.
5. Define scope.
6. Link protocol/site.
7. Verify delegate qualifications.
8. Verify training.
9. Verify competence.
10. Define start/end date.
11. Define limitations.
12. Approve delegation.
13. Activate authority.
14. Monitor expiration.
15. Revoke or renew as required.
16. Generate delegation receipt.

#### Procedure 15: Raise and Investigate Concern

1. Submit concern, anonymously or identified.
2. Classify concern.
3. Triage severity.
4. Acknowledge receipt where possible.
5. Protect confidentiality.
6. Assign investigator.
7. Escalate immediate participant safety or ethical risks.
8. Conduct investigation.
9. Record evidence.
10. Determine findings.
11. Define corrective action.
12. Communicate outcome where permitted.
13. Close or escalate.
14. Generate concern receipt.

#### Procedure 16: Produce Sponsor/CRO Diligence Packet

1. Select site, protocol, study, or network scope.
2. Select audience.
3. Apply access policy.
4. Exclude restricted PHI/PII unless authorized.
5. Include QMS Passport.
6. Include control status.
7. Include evidence summary.
8. Include open findings.
9. Include CAPA status.
10. Include risk register summary.
11. Include training summary.
12. Include delegation summary.
13. Include facility/equipment readiness.
14. Include consent process readiness.
15. Include deviation trends.
16. Include audit history.
17. Include Decision Forum determinations.
18. Include evidence receipt index.
19. Generate packet.
20. Log disclosure.
21. Generate export receipt.

### Reporting and dashboards

#### Site Leader Dashboard

Must show:

1. Site QMS Passport status.
2. Critical gaps.
3. Open risks.
4. Open CAPAs.
5. Training gaps.
6. Upcoming reviews.
7. Audit status.
8. Protocol startup status.
9. Decision Forum matters.
10. Sponsor/CRO requests.

#### Quality Manager Dashboard

Must show:

1. Control status.
2. Evidence completeness.
3. Evidence freshness.
4. Findings by severity.
5. CAPA aging.
6. Deviation trends.
7. Audit schedule.
8. Risk register.
9. Document review queue.
10. Training gap trends.

#### PI Dashboard

Must show:

1. Protocol readiness.
2. Delegation log.
3. Training completion.
4. Consent form status.
5. Active deviations.
6. Safety events.
7. Participant protection tasks.
8. Launch/enrollment gate status.
9. Required approvals.
10. Study action items.

#### Coordinator Dashboard

Must show:

1. Assigned tasks.
2. Training requirements.
3. Protocol procedures.
4. Active consent version.
5. Deviation reporting shortcut.
6. Participant visit requirements.
7. Document access.
8. Upcoming due dates.
9. Concern reporting.

#### CRO Portfolio Dashboard

Must show:

1. Sites by readiness status.
2. Studies by startup status.
3. Site gaps.
4. Critical findings.
5. CAPA aging.
6. Training coverage.
7. Risk heatmap.
8. Sponsor exports.
9. Monitoring findings.
10. Cross-site trends.

#### Sponsor Viewer Dashboard

Must show:

1. Authorized site readiness view.
2. Evidence summary.
3. Open critical/major gaps.
4. CAPA status.
5. Training summary.
6. Facility/equipment status.
7. Consent readiness.
8. Deviation trends.
9. Audit/assessment reports.
10. Decision certificates.

#### Decision Forum Dashboard

Must show:

1. Pending matters.
2. Required quorum.
3. Conflict disclosures.
4. Evidence bundles.
5. AI review summaries.
6. Votes.
7. Conditions.
8. Dissent.
9. Decisions.
10. Follow-up actions.


## 5. Documentation Layer — Manuals, Contextual Help, SOP Crosslinks, and AI Orientation

The Documentation Layer is added explicitly because a clinical research quality system cannot depend on tribal knowledge. The original source already contains policies, procedures, dashboards, roles, controls, reports, and evidence definitions. This layer turns those materials into a product surface: role-aware, contextual, searchable, crosslinked, AI-assisted, versioned, printable, and continuously improved.

### 5.1 Documentation Product Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|---|---|---:|---|
| DOC-001 | CyberMedica must include a right-side contextual manual drawer available from every major page, dashboard, control, evidence object, and workflow. | MUST | Opening help from a control, procedure, dashboard card, evidence object, or decision matter lands on the relevant manual section. |
| DOC-002 | Manuals must be role-aware for site leaders, PIs, coordinators, quality managers, CRO users, sponsor viewers, auditors, Decision Forum members, AI reviewers, tenant admins, and system admins. | MUST | Users see guidance that matches their role, permissions, and current workflow context. |
| DOC-003 | Manuals must crosslink controls, policies, procedures, data objects, evidence requirements, dashboards, acceptance tests, and governance rules. | MUST | A user can move from a control to required evidence, procedure steps, policy basis, and dashboard location. |
| DOC-004 | The documentation system must include high-level orientation plus step-by-step operating instructions. | MUST | Each major workflow has “what this is,” “who owns it,” “when to use it,” “step-by-step,” “evidence needed,” “approval required,” “common failure modes,” and “audit/export result.” |
| DOC-005 | Documentation must include an AI orientation assistant that uses the user role, tenant context, active object, workflow state, and available manuals to answer orientation questions. | SHOULD | AI responses are labeled as guidance, not policy authority, and cite linked manual/control/procedure sources where possible. |
| DOC-006 | The AI orientation assistant must be a mandated reporter of confusion, missing documentation, friction, and product gaps. | SHOULD | User inquiries can be converted into CQI/friction items with context, section, role, and suggested improvement category. |
| DOC-007 | Documentation must support governance, versioning, effective date, author, reviewer, approver, and rollback. | MUST | Documentation changes can be audited and linked to Decision Forum review when material. |
| DOC-008 | Manuals must be exportable as PDF/Word/Markdown and printable for audit/training use. | SHOULD | Authorized users can generate manual packets by role or workflow. |
| DOC-009 | Documentation must not create unapproved regulatory, compliance, accreditation, or clinical claims. | MUST | High-risk manual sections require quality/legal/regulatory review before publication. |

### 5.2 Required Documentation Artifacts for Sandy Review

1. CyberMedica User Manual.
2. Clinical Research Site Leader Manual.
3. PI/Investigator Manual.
4. Coordinator/Site Staff Manual.
5. Quality Manager Manual.
6. CRO Portfolio Manual.
7. Sponsor Viewer Manual.
8. Auditor/Monitor/Inspector Manual.
9. Decision Forum Manual.
10. AI Quality Review Manual.
11. Tenant Administrator Manual.
12. System Administrator Manual.
13. Evidence and Chain-of-Custody Manual.
14. Protocol Readiness and Launch Gate Manual.
15. Consent and Participant Protection Manual.
16. Deviation/CAPA Manual.
17. Training and Delegation Manual.
18. Clinical Trial Product Accountability Manual.
19. Exochain Receipts and Privacy-Preserving Anchoring Guide.
20. Support Access, Break-Glass, and Emergency Action Runbook.
21. Sponsor/CRO Diligence Packet Guide.
22. Audit/Inspection Packet Guide.
23. AI Governance and Model Use Policy.
24. Deployment, Backup, Recovery, and Incident Response Runbook.

### 5.3 Documentation-to-Control Crosslink Model

Every manual section should be able to link to:

1. Source control.
2. Applicable policy.
3. Required procedure.
4. Required evidence objects.
5. Required roles and authority.
6. Relevant dashboard.
7. Relevant workflow.
8. AI review prompts.
9. Decision Forum escalation rules.
10. Audit/export implications.
11. Exochain receipt type.
12. Acceptance tests.
13. Current version and effective date.
14. Known open questions or tenant-specific configuration notes.

### 5.4 Documentation Drift Loop

Documentation should update through the same CQI posture as quality controls:

1. User asks for help.
2. AI/manual detects missing or confusing guidance.
3. Inquiry is captured as documentation friction.
4. Quality/admin owner triages friction.
5. Documentation update is drafted.
6. High-risk content is reviewed.
7. Approved version is published.
8. Manual crosslinks are refreshed.
9. Evidence of change is retained.
10. Material documentation change can generate a receipt.


## 6. Deployment Layer — Buildable Architecture, Requirements, Security, and Operations

The Deployment Layer makes the PRD buildable. It turns doctrine, domain, data, doors, and documentation into software architecture, implementation requirements, security controls, integrations, tests, observability, and release planning. Because the original document is intentionally comprehensive and non-phased, this layer should be treated as a derivation framework rather than a reduction of scope.

### 6.0 Deployment Architecture Posture

CyberMedica should be implemented as a configurable, tenant-isolated, governed platform with:

1. Web application surfaces for site, investigator, coordinator, quality, CRO, sponsor, auditor, Decision Forum, and admin users.
2. Application database for mutable operational state.
3. Encrypted object storage for raw evidence, documents, reports, and sensitive artifacts.
4. Workflow engine for policies, procedures, gates, approvals, CAPA, deviations, risk, launch, enrollment, consent, audits, and exports.
5. AI review service with scoped prompts, evidence references, tenant policy, and human review gates.
6. Documentation/manual service with contextual links and AI orientation.
7. Exochain adapter for privacy-preserving evidence, decision, consent, authority, audit, and export receipts.
8. Integration layer for identity providers, CTMS, eTMF, EDC, eConsent, LMS, HRIS, QMS, document systems, IRB systems, sponsor portals, data warehouses, and APIs.
9. Observability, health, audit, security monitoring, backup/recovery, and incident response.
10. CI/CD quality gates that block insecure, unscoped, undocumented, or untested releases.

### 6.1 Recommended Repository / Artifact Structure

```text
cybermedica/
├── README.md
├── PRD.md
├── docs/
│   ├── architecture.md
│   ├── seven-layer-discipline.md
│   ├── manuals/
│   ├── policies/
│   ├── procedures/
│   ├── controls/
│   ├── evidence/
│   ├── exochain-receipts.md
│   ├── ai-governance.md
│   ├── deployment-runbook.md
│   └── audit-inspection-guide.md
├── schemas/
│   ├── controls.schema.json
│   ├── evidence.schema.json
│   ├── risk.schema.json
│   ├── capa.schema.json
│   ├── consent.schema.json
│   └── workflows.schema.json
├── workflows/
│   ├── site-qms-passport.yaml
│   ├── protocol-feasibility.yaml
│   ├── launch-gate.yaml
│   ├── enrollment-gate.yaml
│   ├── consent-version-control.yaml
│   ├── deviation-capa.yaml
│   ├── evidence-intake.yaml
│   ├── decision-forum.yaml
│   └── diligence-export.yaml
├── app/
├── api/
├── packages/
│   ├── controls/
│   ├── evidence/
│   ├── workflows/
│   ├── ai-review/
│   ├── exochain-adapter/
│   └── reports/
├── migrations/
├── tests/
│   ├── access-control/
│   ├── workflow-gates/
│   ├── evidence/
│   ├── ai-governance/
│   ├── exochain-receipts/
│   └── e2e/
└── ops/
    ├── ci.md
    ├── backup-restore.md
    ├── incident-response.md
    └── monitoring.md
```

### 6.2 Launch-Blocking Engineering Controls

1. Tenant isolation tests.
2. Role and authority-chain validation tests.
3. Delegation expiration tests.
4. Training-blocks-delegation tests.
5. Launch gate blocker tests.
6. Enrollment gate blocker tests.
7. Superseded consent block tests.
8. AI-not-final-authority tests.
9. Evidence hash/custody tests.
10. Exochain receipt privacy tests.
11. Export access-control tests.
12. Audit append-only tests.
13. PHI/PII classification tests.
14. Sponsor/CRO visibility boundary tests.
15. Emergency action retrospective review tests.
16. Documentation context tests.
17. Backup/restore tests.
18. Integration fail-closed tests.

### Functional requirements

#### FR-001: Tenant and organization management

The system shall support multiple tenants, each with isolated organizations, sites, studies, users, roles, controls, evidence, and configuration.

#### FR-002: Site creation and profile management

The system shall allow authorized users to create, maintain, review, and approve site profiles.

#### FR-003: Standards-derived control library

The system shall maintain a configurable library of standards-derived controls.

#### FR-004: Control applicability determination

The system shall allow controls to be marked applicable, not applicable, conditionally applicable, deferred, waived, or superseded with rationale and approval.

#### FR-005: Evidence upload and linking

The system shall allow evidence upload, linking, classification, versioning, hashing, chain-of-custody, review, and approval.

#### FR-006: Evidence completeness scoring

The system shall compute evidence completeness by control, site, study, protocol, and diligence packet.

#### FR-007: Evidence freshness scoring

The system shall compute evidence freshness and flag stale evidence.

#### FR-008: AI control review

The system shall run AI-assisted review on controls and evidence with human-readable findings and confidence levels.

#### FR-009: Site QMS Passport generation

The system shall generate a site QMS Passport summarizing readiness, evidence, risks, findings, CAPAs, KPIs, and approvals.

#### FR-010: Protocol intake

The system shall support intake of protocol documents, amendments, sponsor materials, investigator brochures, and trial agreements.

#### FR-011: Protocol-to-site feasibility analysis

The system shall support structured feasibility review and AI-assisted protocol-to-site fit analysis.

#### FR-012: Trial startup risk assessment

The system shall support creation, review, approval, and monitoring of trial startup risk assessments.

#### FR-013: Launch gate workflow

The system shall enforce a launch gate requiring required approvals, evidence, training, delegation, consent readiness, facility readiness, product readiness, and risk controls.

#### FR-014: Enrollment gate workflow

The system shall enforce enrollment gate readiness before participant enrollment.

#### FR-015: Informed consent management

The system shall manage consent form versions, approval status, readability review, required element review, activation, supersession, and reconsent triggers.

#### FR-016: Consent process documentation

The system shall allow authorized staff to document consent process completion, participant copy delivery, questions, signatures, dates, LAR/witness/assent status, and data sharing consent.

#### FR-017: Participant code management

The system shall support participant unique code numbers without exposing unnecessary identifiers.

#### FR-018: Withdrawal and lost-to-follow-up management

The system shall support documented withdrawal, refusal to provide reason, and lost-to-follow-up process tracking.

#### FR-019: AE/SAE/SUSAR workflow

The system shall support event reporting, classification, investigation, notifications, follow-up, and closure.

#### FR-020: Deviation workflow

The system shall support planned and unplanned deviations, immediate action, reporting, root cause, CAPA, and closure.

#### FR-021: CAPA workflow

The system shall support CAPA creation, approval, implementation, verification, effectiveness check, closure, and reopening.

#### FR-022: Training matrix

The system shall maintain role/protocol/control-based training requirements.

#### FR-023: Training gap detection

The system shall detect and report training gaps.

#### FR-024: Competency records

The system shall store and manage competency attestations and qualification evidence.

#### FR-025: Delegation log

The system shall maintain protocol-specific delegation logs with authority verification.

#### FR-026: Concern reporting

The system shall support identified and anonymous concern reporting.

#### FR-027: Conflict disclosure

The system shall collect conflict disclosures for decision participants and reviewers.

#### FR-028: Recusal management

The system shall support recusal from decisions and reviews.

#### FR-029: Decision Forum matters

The system shall support creation, review, deliberation, vote, rationale, closure, contestation, and receipts for decision matters.

#### FR-030: Emergency action workflow

The system shall allow emergency action records with retrospective review requirements.

#### FR-031: Document control

The system shall manage controlled documents, versions, effective dates, approval workflows, supersession, review cycles, and access controls.

#### FR-032: Information management plan

The system shall support trial-specific information management plans and associated procedures.

#### FR-033: Electronic system validation evidence

The system shall store validation and verification evidence for electronic systems used in trial data collection.

#### FR-034: Facility readiness

The system shall support facility requirement review, evidence, gaps, approval, and monitoring.

#### FR-035: Equipment calibration

The system shall track equipment requiring calibration/checks, due dates, evidence, defects, and quarantine.

#### FR-036: Clinical trial product accountability

The system shall track clinical trial product receipt, storage, dispensing, access, stock, expiration, return, disposal, and reconciliation.

#### FR-037: KPI management

The system shall define, collect, monitor, analyze, report, and trend KPIs.

#### FR-038: Internal audit management

The system shall support audit planning, execution, findings, reports, management response, CAPA, and closure.

#### FR-039: Assessment management

The system shall support self-assessment, external assessment, reviewer assignment, comments, recommendations, close assessment, and locked reports.

#### FR-040: Sponsor/CRO diligence packet

The system shall generate controlled diligence packets with configurable audience access and disclosure logging.

#### FR-041: Export controls

The system shall enforce privacy, confidentiality, and access rules during exports.

#### FR-042: Exochain anchoring

The system shall generate evidence receipts, decision receipts, consent receipts, authority receipts, and audit anchors.

#### FR-043: Audit logs

The system shall maintain immutable, append-only, tamper-evident audit logs.

#### FR-044: Chain-of-custody

The system shall track custody transfers for evidence.

#### FR-045: Notifications and alerts

The system shall notify users of assignments, due dates, expirations, critical risks, findings, decisions, approvals, and escalations.

#### FR-046: Search and retrieval

The system shall support advanced search across controls, evidence, documents, risks, CAPAs, decisions, audits, and sites subject to access restrictions.

#### FR-047: Dashboards

The system shall provide dashboards for site leaders, quality managers, CRO portfolio managers, sponsor viewers, investigators, coordinators, and auditors.

#### FR-048: Integrations

The system shall support integrations with identity providers, CTMS, eTMF, EDC, eConsent, LMS, HRIS, QMS, document systems, IRB systems, sponsor portals, and data warehouses.

#### FR-049: API access

The system shall expose governed APIs for authorized integration and reporting.

#### FR-050: Reporting

The system shall support standard and custom reports for QMS status, site readiness, training, deviations, CAPA, risk, audit, consent readiness, equipment, product accountability, and sponsor diligence.

### Nonfunctional requirements

#### NFR-001: Security

The system shall implement encryption in transit, encryption at rest, secrets management, role-based access control, attribute-based access control, least privilege, multi-factor authentication support, identity provider integration, session controls, audit logging, and security monitoring.

#### NFR-002: Privacy

The system shall support HIPAA, GDPR, and other applicable privacy configurations, including data minimization, access restrictions, consent tracking, retention, disclosure logging, and protected data classification.

#### NFR-003: Availability

The system shall support high availability appropriate for clinical operations, with monitored uptime, backups, recovery procedures, and disaster recovery plans.

#### NFR-004: Data integrity

The system shall preserve attributable, legible, contemporaneous, original, accurate, and complete records.

#### NFR-005: Auditability

The system shall provide complete audit trails for authentication, access, evidence, decisions, approvals, document changes, exports, delegations, and privileged actions.

#### NFR-006: Tamper evidence

The system shall provide tamper-evident receipts and hash-chained records for critical governance and evidence actions.

#### NFR-007: Interoperability

The system shall provide APIs, webhooks, import/export formats, and connectors to common clinical research systems.

#### NFR-008: Configurability

The system shall allow tenant-specific control sets, workflows, roles, SOP mappings, evidence requirements, review frequencies, and reporting templates.

#### NFR-009: Scalability

The system shall scale across sites, networks, CRO portfolios, sponsors, studies, evidence volumes, and decision records.

#### NFR-010: Usability

The system shall provide role-specific views, guided workflows, clear status indicators, evidence checklists, plain-language explanations, and accessible design.

#### NFR-011: Explainability

AI outputs shall include evidence references, reasoning summaries, confidence, limitations, unresolved assumptions, and recommended human reviewers.

#### NFR-012: Reliability

The system shall be resilient to partial failures, integration failures, interrupted uploads, duplicate submissions, and retry scenarios.

#### NFR-013: Data portability

The system shall support structured export of site data, evidence indexes, audit records, and diligence packets subject to access policy.

#### NFR-014: Legal defensibility

The system shall preserve evidence provenance, custody, timestamps, access logs, decision rationale, and version history in a manner designed to support audit, inspection, dispute resolution, and diligence.


## 7. Drift Layer — Continuous Improvement, Acceptance, Open Questions, and Product Evolution

The Drift Layer is the answer to the most dangerous failure mode in quality systems: the system looks complete but silently goes stale. CyberMedica must be designed so that evidence aging, staff changes, protocol amendments, sponsor expectations, deviations, CAPA trends, training gaps, equipment expiration, consent supersession, AI findings, concerns, audits, and stakeholder feedback all generate visible, owned, and reviewable change.

### 7.0 Drift Management Rules

1. Evidence aging changes readiness.
2. Training expiration changes authority.
3. Delegation expiration changes allowed actions.
4. Protocol amendment changes required review.
5. Consent version supersession changes enrollment readiness.
6. Audit findings change QMS status.
7. CAPA effectiveness changes closure state.
8. AI gap detection creates reviewable recommendations, not hidden conclusions.
9. User friction and documentation confusion become CQI inputs.
10. Sponsor/CRO requests become controlled work items and disclosure events.
11. Open questions remain visible until closed by accountable governance.
12. Every release should improve the system’s ability to preserve trust, not merely add surface area.

### 7.1 Drift-to-Improvement Loop

1. Signal arises: evidence stale, risk triggered, concern filed, audit finding, user friction, AI gap, sponsor request, protocol amendment, incident, or KPI trend.
2. Signal is classified by risk, affected controls, participant safety impact, data integrity impact, sponsor/CRO impact, and urgency.
3. Owner is assigned.
4. Required evidence and review path are identified.
5. Decision Forum is invoked if material.
6. CAPA, CQI, documentation update, workflow change, training update, or system change is created.
7. Implementation is tracked.
8. Effectiveness is checked.
9. Passport/readiness/quality state is updated.
10. Receipt/audit record is created where required.

### Acceptance criteria

CyberMedica 2.0 shall be considered complete against this master PRD when the system can support the following end-to-end outcomes:

1. A site can create and maintain a complete QMS Passport.
2. A standards-derived control library can be managed, versioned, and reviewed.
3. A site can complete self-assessment against controls.
4. Evidence can be uploaded, classified, linked, reviewed, versioned, hashed, and anchored.
5. AI can analyze evidence against controls and generate review findings.
6. Human reviewers can approve, reject, condition, contest, and escalate.
7. A protocol can be ingested and assessed for site feasibility.
8. A trial startup risk assessment can be completed and approved.
9. A trial launch gate can block or authorize launch based on evidence.
10. An enrollment gate can block or authorize enrollment readiness.
11. Consent form versions can be controlled and superseded versions blocked.
12. Consent process evidence can be documented and governed.
13. Training and competency requirements can block delegation and controlled actions.
14. Delegation logs can be authorized, scoped, expired, and revoked.
15. Deviations can be reported, investigated, corrected, prevented, and closed.
16. CAPAs can be managed through effectiveness check.
17. AE/SAE/SUSAR workflows can be documented and tracked.
18. Facility readiness and equipment calibration can be tracked.
19. Clinical trial product accountability can be maintained.
20. Internal audits and assessments can be performed and locked.
21. KPIs can be defined, monitored, and used in decisions.
22. Sponsor/CRO diligence packets can be generated with access controls.
23. Protected content can be excluded from unauthorized exports.
24. Chain-of-custody can be maintained for evidence.
25. Hash-chained audit logs can be generated and verified.
26. Decision receipts can be generated.
27. Evidence receipts can be generated.
28. Consent and authority receipts can be generated.
29. Emergency actions can be documented and retrospectively reviewed.
30. All material actions are attributable, time-stamped, auditable, and governed.

### Open questions for scoping and legal review

1. What exact legal rights exist to use the SASI-QMS text, derivative control library, title, marks, and accreditation-related language?
2. Should the CyberMedica offering avoid the term “accreditation” unless a separate accredited body is established?
3. Should the first commercial form be sold to CROs, site networks, sponsors, academic medical centers, or diligence teams?
4. Should the initial control library include only SASI-QMS-derived controls or also crosswalks to ISO 9001, ICH E6 R3, HIPAA, GDPR, 21 CFR Part 11, and internal sponsor SOPs?
5. What is the preferred system-of-record posture: CyberMedica as primary QMS, overlay QMS, or evidence/governance wrapper around existing systems?
6. Which data types should be explicitly prohibited from Exochain anchoring metadata?
7. Which Exochain deployment model is preferred for regulated life sciences customers: public anchor, private tenant chain, consortium chain, or internal ledger with exportable proofs?
8. What level of sponsor visibility should be standard versus negotiated?
9. Should CROs be allowed to white-label CyberMedica?
10. Should sites have portable passports across CROs/sponsors?
11. What commercial claim is safest: “QMS-ready,” “good-to-go oversight,” “audit-ready evidence,” “site quality passport,” or “standard-aligned governance fabric”?
12. What role should the AI-IRB have in public-facing language to avoid confusion with legally constituted IRBs/IECs?
13. Who has final authority over control library amendments?
14. Should Decision Forum panels be tenant-specific, sponsor-specific, CRO-specific, or independent?
15. Should evidence retention policies be tenant-configurable or centrally enforced?
16. Should CyberMedica include participant-facing features or remain site/CRO/sponsor-facing?
17. Should the product include eConsent execution or integrate with existing eConsent providers?
18. Should the product include CTMS functions or strictly govern CTMS evidence?
19. Should clinical trial product accountability be native or integrated with pharmacy systems?
20. Should the product support inspection mode for regulators and auditors?

### Closing product thesis

CyberMedica 2.0 is the exochained QMS for clinical research. It transforms standards into controls, controls into evidence, evidence into receipts, decisions into governed records, and sites into trusted execution nodes.

Its value is not merely better documentation. Its value is reduced trust friction.

For sites, it provides a path to operational maturity. For CROs, it provides a differentiated quality deployment model. For sponsors, it provides faster diligence and better oversight. For participants, it strengthens protection. For the clinical research ecosystem, it offers a practical route from fragmented compliance toward accountable, verifiable, continuously improving clinical research execution.


---

## Appendix A — Seven-Layer Implementation Backlog Skeleton

This backlog skeleton is not a phase plan and does not reduce the master PRD. It gives Sandy a way to turn the seven-layer document into buildable workstreams.

### Doctrine Backlog

1. Finalize non-negotiable doctrine statements.
2. Approve AI non-final-authority rules.
3. Approve privacy-preserving Exochain receipt policy.
4. Approve sponsor/CRO visibility defaults.
5. Approve participant protection and data integrity gate definitions.

### Domain Backlog

1. Build standards/control library foundation.
2. Build Site QMS Passport.
3. Build protocol feasibility/startup module.
4. Build evidence/custody module.
5. Build risk/CAPA/deviation module.
6. Build training/delegation module.
7. Build consent and participant protection module.
8. Build audit/assessment/reporting module.

### Data Backlog

1. Create entity schemas.
2. Create confidentiality and PHI/PII classification model.
3. Implement RBAC/ABAC/authority-chain checks.
4. Implement evidence hash, version, custody, and retention state.
5. Implement Exochain receipt abstraction.
6. Implement export eligibility rules.

### Doors Backlog

1. Site Leader Dashboard.
2. Quality Manager Dashboard.
3. PI Dashboard.
4. Coordinator Dashboard.
5. CRO Portfolio Dashboard.
6. Sponsor Viewer Dashboard.
7. Decision Forum Dashboard.
8. Auditor/Inspector Mode.
9. AI Quality Review Workbench.

### Documentation Backlog

1. Build right-side contextual manual drawer.
2. Create role manuals.
3. Crosslink controls, evidence, procedures, workflows, and policies.
4. Add AI orientation assistant.
5. Add inquiry-to-friction/CQI reporting.
6. Version and govern manuals.

### Deployment Backlog

1. Repository scaffold.
2. Database migrations.
3. Object storage.
4. Workflow engine.
5. AI provider abstraction.
6. Exochain adapter.
7. CI/CD gates.
8. Health and observability.
9. Backup and recovery.
10. Integration stubs.

### Drift Backlog

1. Evidence aging engine.
2. KPI trends.
3. CQI queue.
4. Concern reporting.
5. CAPA effectiveness checks.
6. Documentation friction queue.
7. AI gap recommendation queue.
8. Decision Forum escalation engine.
9. Open-question register.
10. Release-readiness acceptance matrix.

---

## Appendix B — Sandy Review Questions

1. Is CyberMedica being positioned as a primary QMS, overlay QMS, readiness passport, diligence fabric, or configurable combination?
2. Which customer should anchor the first commercial deployment: sites, site networks, CROs, sponsors, academic medical centers, or diligence/acquisition teams?
3. Which standard/control source has clear legal permission for use and derivative control generation?
4. Should “AI-IRB” remain as internal language only, given risk of confusion with legally constituted IRB/IEC authority?
5. What is the safest public claim: QMS Passport, site readiness fabric, audit-ready evidence, standard-aligned governance layer, or exochained clinical research QMS?
6. Should participant-facing functionality be excluded from MVP to reduce PHI and clinical-risk exposure?
7. Which content must undergo legal/regulatory review before use in sales materials?
8. Which Exochain deployment model is most appropriate for regulated clinical research customers?
9. Should sponsors receive direct portal views, controlled packets only, or both by tenant configuration?
10. What is the minimum viable control library for the first build?

---

## Appendix C — One-Page Product Thesis for Sandy

CyberMedica 2.0 is an exochained clinical research site quality operating layer. It transforms clinical research standards into controls; controls into required evidence; evidence into reviewed, classified, custody-tracked artifacts; decisions into authorized, contestable records; and readiness into sponsor/CRO-diligence packets with privacy-preserving provenance receipts.

The product’s purpose is not to create more compliance paperwork. Its purpose is to reduce trust friction across the clinical research ecosystem by making site quality continuously visible, evidence-backed, authority-gated, ethically governed, and audit-ready.

CyberMedica is complete only when a clinical research site can demonstrate not merely that it has documents, but that it has the people, controls, authority, training, consent safeguards, data integrity processes, participant protections, facilities, equipment, product handling discipline, risk management, deviation/CAPA process, audit records, and continuous improvement loops necessary to conduct trials safely and reliably.

The first implementation should not be a thin demo. It should be the first configured instance of a platform that can later support site networks, CROs, sponsors, diligence teams, academic medical centers, and regulated life-sciences quality operations without rewriting the trust architecture.

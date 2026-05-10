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

# decision.forum User Manual

## Constitutional Governance for the Age of Superintelligence

**Version:** 2.0.0
**Date:** 2026-03-19
**Classification:** Public -- For Authorized Users
**Publisher:** EXOCHAIN Foundation

---

## How to Use This Manual

This manual is written for board directors, general counsel, compliance officers, chief information officers, and governance professionals who will operate decision.forum in their organizations. It assumes no technical background in cryptography or distributed systems. Where technical concepts are essential, they are explained in plain language with references to the Glossary in Appendix A.

Throughout this manual, key terms appear in **bold** on first use and are defined in the Glossary. Cross-references to other sections are provided as clickable links.

---

## Table of Contents

- [Chapter 1: Welcome to decision.forum](#chapter-1-welcome-to-decisionforum)
  - [1.1 What Is decision.forum?](#11-what-is-decisionforum)
  - [1.2 Who Is It For?](#12-who-is-it-for)
  - [1.3 The Promise](#13-the-promise)
  - [1.4 Quick Start: Your First Decision in Five Minutes](#14-quick-start-your-first-decision-in-five-minutes)
- [Chapter 2: Understanding Decisions](#chapter-2-understanding-decisions)
  - [2.1 What Is a Decision Object?](#21-what-is-a-decision-object)
  - [2.2 The Fourteen States of a Decision](#22-the-fourteen-states-of-a-decision)
  - [2.3 Decision Classes](#23-decision-classes)
  - [2.4 The Receipt Chain](#24-the-receipt-chain)
- [Chapter 3: Your Constitutional Framework](#chapter-3-your-constitutional-framework)
  - [3.1 What Is a Constitution in decision.forum?](#31-what-is-a-constitution-in-decisionforum)
  - [3.2 Document Hierarchy](#32-document-hierarchy)
  - [3.3 How Constitutional Constraints Are Enforced in Real Time](#33-how-constitutional-constraints-are-enforced-in-real-time)
  - [3.4 Amending Your Constitution](#34-amending-your-constitution)
  - [3.5 Dry-Run Mode: Test Before You Commit](#35-dry-run-mode-test-before-you-commit)
- [Chapter 4: Authority and Delegation](#chapter-4-authority-and-delegation)
  - [4.1 Understanding the Authority Matrix](#41-understanding-the-authority-matrix)
  - [4.2 How Delegation Works](#42-how-delegation-works)
  - [4.3 Sub-Delegation](#43-sub-delegation)
  - [4.4 The Sunset Calendar](#44-the-sunset-calendar)
  - [4.5 Revoking Authority](#45-revoking-authority)
- [Chapter 5: Making Decisions](#chapter-5-making-decisions)
  - [5.1 Step by Step: Creating a New Decision](#51-step-by-step-creating-a-new-decision)
  - [5.2 Attaching Evidence and Deliberation Materials](#52-attaching-evidence-and-deliberation-materials)
  - [5.3 Quorum](#53-quorum)
  - [5.4 Voting](#54-voting)
  - [5.5 Approval Workflows](#55-approval-workflows)
  - [5.6 The Human Gate](#56-the-human-gate)
- [Chapter 6: Challenging and Contesting Decisions](#chapter-6-challenging-and-contesting-decisions)
  - [6.1 Your Right to Challenge](#61-your-right-to-challenge)
  - [6.2 Filing a Formal Contestation](#62-filing-a-formal-contestation)
  - [6.3 What Happens When a Decision Is Challenged](#63-what-happens-when-a-decision-is-challenged)
  - [6.4 The Resolution Process](#64-the-resolution-process)
  - [6.5 Reversals](#65-reversals)
- [Chapter 7: Emergency Governance](#chapter-7-emergency-governance)
  - [7.1 When to Invoke Emergency Authority](#71-when-to-invoke-emergency-authority)
  - [7.2 The Guardrails](#72-the-guardrails)
  - [7.3 Mandatory Ratification](#73-mandatory-ratification)
  - [7.4 Frequency Monitoring](#74-frequency-monitoring)
- [Chapter 8: Accountability](#chapter-8-accountability)
  - [8.1 Accountability Actions](#81-accountability-actions)
  - [8.2 Due Process Requirements](#82-due-process-requirements)
  - [8.3 Immediate Suspension](#83-immediate-suspension)
  - [8.4 The Accountability Trail](#84-the-accountability-trail)
- [Chapter 9: Conflict of Interest Management](#chapter-9-conflict-of-interest-management)
  - [9.1 Disclosure Requirements](#91-disclosure-requirements)
  - [9.2 Recusal](#92-recusal)
  - [9.3 The System Blocks Participation Until Disclosure Is Complete](#93-the-system-blocks-participation-until-disclosure-is-complete)
  - [9.4 DGCL Section 144 Safe Harbor](#94-dgcl-section-144-safe-harbor)
- [Chapter 10: AI Agents in Your Governance](#chapter-10-ai-agents-in-your-governance)
  - [10.1 What AI Agents Can and Cannot Do](#101-what-ai-agents-can-and-cannot-do)
  - [10.2 The Delegation Ceiling](#102-the-delegation-ceiling)
  - [10.3 AI Cannot Create or Modify Delegations](#103-ai-cannot-create-or-modify-delegations)
  - [10.4 Distinguishing AI Actions from Human Actions](#104-distinguishing-ai-actions-from-human-actions)
  - [10.5 The Six MCP Enforcement Rules](#105-the-six-mcp-enforcement-rules)
- [Chapter 11: Legal and Compliance](#chapter-11-legal-and-compliance)
  - [11.1 Self-Authenticating Business Records](#111-self-authenticating-business-records)
  - [11.2 Chain of Custody](#112-chain-of-custody)
  - [11.3 E-Discovery Readiness](#113-e-discovery-readiness)
  - [11.4 Fiduciary Defense Packages](#114-fiduciary-defense-packages)
  - [11.5 Records Retention](#115-records-retention)
- [Chapter 12: Reporting and Metrics](#chapter-12-reporting-and-metrics)
  - [12.1 The Governance Metrics Dashboard](#121-the-governance-metrics-dashboard)
  - [12.2 Authority Verification Coverage](#122-authority-verification-coverage)
  - [12.3 Revocation Latency](#123-revocation-latency)
  - [12.4 Evidence Completeness](#124-evidence-completeness)
  - [12.5 How to Interpret the Metrics](#125-how-to-interpret-the-metrics)
- [Chapter 13: Administration](#chapter-13-administration)
  - [13.1 Setting Up Your Organization's Constitution](#131-setting-up-your-organizations-constitution)
  - [13.2 Managing Users and Roles](#132-managing-users-and-roles)
  - [13.3 Configuring Decision Classes](#133-configuring-decision-classes)
  - [13.4 Setting Up the Authority Matrix](#134-setting-up-the-authority-matrix)
  - [13.5 Customizing Notification Preferences](#135-customizing-notification-preferences)
  - [13.6 Multi-Tenant Isolation](#136-multi-tenant-isolation)
- [Chapter 14: Security and Trust](#chapter-14-security-and-trust)
  - [14.1 How Your Data Is Protected](#141-how-your-data-is-protected)
  - [14.2 Zero-Trust Architecture](#142-zero-trust-architecture)
  - [14.3 Cryptographic Guarantees](#143-cryptographic-guarantees)
  - [14.4 The Tamper-Evident Audit Log](#144-the-tamper-evident-audit-log)
  - [14.5 Post-Quantum Readiness](#145-post-quantum-readiness)
- [Chapter 15: Troubleshooting](#chapter-15-troubleshooting)
  - [15.1 Common Issues and Solutions](#151-common-issues-and-solutions)
  - [15.2 Authority Chain Verification Failed](#152-authority-chain-verification-failed)
  - [15.3 Quorum Not Met](#153-quorum-not-met)
  - [15.4 Human Gate Required](#154-human-gate-required)
  - [15.5 Constitutional Constraint Violation](#155-constitutional-constraint-violation)
  - [15.6 Getting Help](#156-getting-help)
- [Appendix A: Glossary](#appendix-a-glossary)
- [Appendix B: Decision Lifecycle Quick Reference](#appendix-b-decision-lifecycle-quick-reference)
- [Appendix C: Authority Matrix Template](#appendix-c-authority-matrix-template)
- [Appendix D: Constitutional Template](#appendix-d-constitutional-template)
- [Index](#index)

---

## Chapter 1: Welcome to decision.forum

### 1.1 What Is decision.forum?

decision.forum is a constitutional governance platform that makes every organizational decision legally defensible, constitutionally compliant, and cryptographically provable.

At its core, decision.forum does three things:

1. **Records every decision** your organization makes as a tamper-proof, self-authenticating business record that meets the evidentiary standards of the Federal Rules of Evidence.

2. **Enforces your governance rules** in real time. Your bylaws, board resolutions, committee charters, and policies are encoded as machine-readable constraints. When someone proposes a decision that violates your rules, the system blocks it before it can take effect.

3. **Proves what happened** to any auditor, regulator, or court. Every action in the system is cryptographically signed, timestamped, and chained into an immutable record. You can prove who authorized what, when they did it, what information they reviewed, and which constitutional provision governed the action.

decision.forum was designed for an era in which artificial intelligence participates in organizational decision-making. It provides the governance infrastructure to ensure that human authority remains supreme, that AI actions are bounded and auditable, and that every delegation of authority -- whether to a person or a machine -- has clear limits, clear provenance, and clear accountability.

### 1.2 Who Is It For?

decision.forum serves five primary audiences:

**Board Directors** use decision.forum to make governance decisions with confidence that the process will withstand legal scrutiny. Every vote, every deliberation, and every resolution is recorded with the evidence a court would need to confirm that the board acted in good faith, on an informed basis, and in the best interest of the organization.

**General Counsel** use decision.forum to manage fiduciary risk. The platform automates compliance with the Delaware General Corporation Law (including Section 144 safe-harbor for interested transactions), generates litigation-ready evidence packages, and maintains chain-of-custody records that satisfy Federal Rules of Evidence requirements.

**Compliance Officers** use decision.forum to enforce policies without relying on human memory or good intentions. Constitutional constraints are checked at the moment of action, not after the fact. Conflict-of-interest disclosures are required before participation, not requested retroactively.

**Chief Information Officers** use decision.forum to govern AI deployment. The platform's authority model ensures that AI agents operate within defined boundaries, that their actions are distinguishable from human actions, and that certain categories of decisions always require human approval.

**Governance Professionals** use decision.forum as the authoritative system of record for organizational governance. It replaces scattered board portals, email chains, and shared documents with a single, cryptographically secured platform where the complete history of every governance action is preserved and verifiable.

### 1.3 The Promise

decision.forum is built on five axioms that define its approach to governance:

**Axiom 1: Authority is held in trust, never owned.** Every delegation of authority in the system is time-bounded, scope-limited, and revocable. No one "has" authority -- they hold it temporarily on behalf of the organization, and the system enforces the terms of that trust.

**Axiom 2: Decisions are first-class sovereign objects.** A decision in decision.forum is not an email approval or a checked box. It is a structured record that is storable, auditable, transferable, contestable, and cryptographically sealed. It exists as a permanent artifact of organizational governance.

**Axiom 3: Trust accumulation matters more than speed.** Verification gates -- the checks that ensure a decision is constitutionally valid -- are features, not obstacles. The system is designed so that doing things correctly is the path of least resistance.

**Axiom 4: Constitutional constraints are machine-readable and enforced at runtime.** Your governance rules are not aspirational statements in a policy manual. They are executable code that the system evaluates every time someone takes a governed action. A constraint violation blocks the action before it happens.

**Axiom 5: Authority without cryptographic provenance is void.** If a delegation cannot be traced through a verified chain of cryptographic signatures back to its constitutional source, the system treats it as if it does not exist. There are no exceptions.

### 1.4 Quick Start: Your First Decision in Five Minutes

This walkthrough shows you the basic flow of creating, deliberating on, and approving a decision. Each step is explained in detail in later chapters.

**Step 1: Log in and identify yourself.**
When you log in to decision.forum, the system resolves your identity through your organization's identity provider. Your **Decentralized Identifier (DID)** -- a unique cryptographic identity -- is verified, and the system confirms your active roles and delegations. This happens automatically.

**Step 2: Create a new decision.**
From the dashboard, select "New Decision." Choose the appropriate **Decision Class** (Routine, Operational, Strategic, Constitutional, or Emergency) based on the nature of what you are deciding. Enter a title, description, and the proposed action.

**Step 3: Attach supporting materials.**
Upload any documents, analyses, or reports that decision-makers should review before voting. These become part of the decision's permanent evidence record. The system creates an **Information Package** and tracks who opens it and when.

**Step 4: File your conflict disclosure.**
Before you can participate in the decision, you must file a conflict-of-interest disclosure. If you have no conflicts, you attest to that. If you do, you describe them. The system will not let you proceed until this step is complete.

**Step 5: Open deliberation.**
Once the minimum number of eligible participants have filed disclosures and reviewed the Information Package, deliberation opens. Participants discuss, ask questions, and evaluate the proposal. At least two alternatives must be documented, including the "no action" option.

**Step 6: Cast votes.**
Each eligible participant casts a vote (For, Against, or Abstain). Against and Abstain votes require a written rationale. The system verifies that the voter reviewed the materials and filed a disclosure before accepting the vote.

**Step 7: Close and seal.**
When voting concludes and **quorum** is met, the decision is closed. The system runs a complete verification: it checks the authority chain, evaluates constitutional constraints, verifies quorum and independence requirements, and computes a **Merkle root** over all evidence. If everything passes, the decision is sealed as an immutable record.

**Step 8: Review the receipt.**
The system generates a cryptographic receipt proving the decision was made, who voted, what they reviewed, and which constitutional provisions were satisfied. This receipt is your organization's permanent, legally defensible record of the action.

You have just completed a fully governed decision. The entire process is recorded, verifiable, and ready to be presented to any auditor, regulator, or court.

---

## Chapter 2: Understanding Decisions

### 2.1 What Is a Decision Object?

A **Decision Object** is the fundamental unit of governance in decision.forum. It is a structured, self-contained record that captures everything about a decision: what was proposed, who was involved, what evidence was considered, how people voted, which constitutional rules applied, and what the outcome was.

Every Decision Object contains:

- **Identity:** A unique identifier and the authority chain showing who created it and under what delegation.
- **Substance:** The proposal, its classification, and any attached evidence or supporting materials.
- **Process:** The complete audit log of every action taken on the decision, from creation through terminal status.
- **Constitutional binding:** The specific version of your organization's constitution that was in force when the decision was made, identified by a cryptographic hash.
- **Cryptographic seal:** A Merkle root computed from all evidence, an authority chain verified through Ed25519 signatures, and a tamper-evident hash chain linking every action in sequence.

A Decision Object has five essential properties. It is **storable** (it can be serialized and preserved indefinitely). It is **auditable** (every modification is logged with actor, timestamp, and reason). It is **transferable** (authority over it can be reassigned through the delegation system). It is **contestable** (any stakeholder can challenge it through formal procedures). And it is **diffable** (any two versions can be compared to show exactly what changed).

Once a Decision Object reaches a terminal state (Approved, Rejected, or Void), its content becomes immutable. No field can be modified. If a correction is needed, a new Decision Object is created and linked to the original. The original record is never altered.

### 2.2 The Fourteen States of a Decision

Every decision in decision.forum moves through a defined lifecycle. There are fourteen possible states, and the system enforces which transitions are valid. A decision can only move forward through legitimate governance actions -- it cannot skip states or move backward except through formal reversal.

**1. Draft**
The decision has been created but is not yet ready for consideration. The proposer can still edit the content, attach materials, and refine the proposal. No governance checks have been applied. Think of this as the working document stage.

**2. Proposed**
The decision has been formally submitted for consideration. The proposer has declared it ready for review. From this point forward, the proposal content is locked -- any changes require creating a new version. The system verifies that the proposer has the authority to make this kind of proposal.

**3. Under Review**
The decision is being evaluated by designated reviewers. This may involve legal review, compliance review, financial analysis, or other assessments depending on the decision class. Reviewers can attach findings as evidence.

**4. Deliberating**
The decision has been placed before the appropriate decision-making body for discussion. Participants are reviewing the Information Package, asking questions, and debating the merits. Conflict disclosures must be filed before participation.

**5. Pending**
All deliberation is complete and the decision is awaiting formal action. Quorum has been verified. The necessary approvals are pending. The system has confirmed that all prerequisites are satisfied.

**6. Approved**
The decision has been approved by the appropriate authority with sufficient votes, meeting quorum and independence requirements. Constitutional constraints have been evaluated and passed. This is a terminal state -- the Decision Object is sealed and immutable.

**7. Rejected**
The decision has been formally rejected. This is a terminal state. The record of why it was rejected, including all votes and rationale, is permanently preserved.

**8. Contested**
A formal challenge has been filed against this decision. When a decision enters the Contested state, all execution of the decision is automatically paused. No further action can be taken on the underlying decision until the challenge is resolved. See [Chapter 6](#chapter-6-challenging-and-contesting-decisions) for details.

**9. Void**
The decision has been voided -- declared null. This can happen because a challenge was sustained, because a constitutional violation was discovered after approval, or because the decision was superseded. This is a terminal state. The record remains, but the decision has no legal effect.

**10. Superseded**
A newer decision has replaced this one. The original decision remains in the record, but it is marked as no longer current. The new decision contains a link to the one it replaces.

**11. Ratification Required**
This decision was made under emergency authority or involves a policy matter that requires ratification by a broader body. The decision is provisionally in effect, but if ratification does not occur within the specified deadline, the decision automatically voids. See [Chapter 7](#chapter-7-emergency-governance).

**12. Escalated**
The decision has been referred to a higher authority for review. This can happen automatically when constitutional constraints are triggered, when quorum cannot be met, or when an emergency protocol is invoked.

**13. Withdrawn**
The proposer has withdrawn the decision before it reached a terminal state. The record is preserved, including the reason for withdrawal, but the decision has no effect.

**14. Expired**
The decision had a time limit and that limit has passed without the decision reaching a terminal state. The system automatically transitions it to Expired. The record is preserved.

### 2.3 Decision Classes

Not all decisions are created equal. decision.forum categorizes decisions into five classes, each with different requirements for who can participate, what approvals are needed, and whether AI involvement is permitted.

**Routine**
Day-to-day operational decisions that fall within established policies. These require standard quorum and can be processed quickly. AI agents may participate in Routine decisions within their delegated authority. Examples: approving a vendor invoice within budget, scheduling a regular meeting, filing a routine report.

**Operational**
Decisions that affect ongoing operations but do not set new strategic direction. These require conflict-of-interest disclosure from all participants. Examples: hiring a senior employee, approving a significant contract, changing an operational procedure.

**Strategic**
Decisions that set organizational direction or involve significant commitment of resources. These require a **Human Gate** -- an AI agent cannot approve a Strategic decision. Higher quorum thresholds apply, and more rigorous evidence requirements are enforced. Examples: entering a new market, acquiring another company, major capital expenditure.

**Constitutional**
Decisions that modify the organization's governance framework itself -- amending bylaws, changing the authority matrix, modifying decision class definitions. These require the highest level of quorum, supermajority approval, and human-only authorization. AI agents are completely excluded from Constitutional decisions.

**Emergency**
Decisions made under time pressure to address an urgent threat. These bypass some normal procedures but are subject to strict guardrails: monetary caps, enumerated permitted actions, hard time limits, and mandatory ratification after the fact. See [Chapter 7](#chapter-7-emergency-governance).

### 2.4 The Receipt Chain

Every action in decision.forum generates a cryptographic **receipt**. A receipt is a signed, timestamped record that proves an action occurred. Receipts are linked together in a chain -- each receipt includes the hash of the previous receipt, creating a tamper-evident sequence.

If anyone attempts to alter a receipt, insert a new one, or delete one, the chain breaks. The hash of the modified receipt will not match what the next receipt expected, and the tampering is immediately detectable.

The receipt chain serves three purposes:

1. **Non-repudiation.** The actor who signed the receipt cannot later deny taking the action. The cryptographic signature ties their identity to the specific action at the specific time.

2. **Ordering.** The chain establishes an unambiguous sequence of events. There is no dispute about what happened first.

3. **Completeness.** Any gap in the chain is immediately visible. If a receipt is missing, the chain is broken, and the system flags it as a potential integrity issue.

Your receipt chain is your organization's definitive record of governance activity. It is designed to meet the standards required for self-authenticating business records under the Federal Rules of Evidence.

---

## Chapter 3: Your Constitutional Framework

### 3.1 What Is a Constitution in decision.forum?

In decision.forum, a **constitution** is the machine-readable encoding of your organization's governance rules. It is not a metaphor -- it is a structured document that the system reads, interprets, and enforces in real time.

Your constitution defines what decisions your organization can make, who has the authority to make them, what process must be followed, and what constraints must be satisfied. When someone proposes a decision, the system evaluates it against your constitution before allowing it to proceed.

Every constitution in decision.forum is:

- **Versioned.** Each modification creates a new version with a semantic version number (e.g., 1.0.0, 1.1.0, 2.0.0). The system tracks which version was in force when every decision was made.

- **Hashed.** The complete constitutional text is run through a Blake3 cryptographic hash function. This hash is embedded in every Decision Object, permanently binding the decision to the exact constitutional text that governed it.

- **Signed.** Authorized signatories cryptographically sign the constitution. The system verifies these signatures before applying any constitutional constraint.

- **Per-tenant.** Each organization (tenant) in decision.forum has its own independent constitution. Organization A's rules have no effect on Organization B's decisions.

### 3.2 Document Hierarchy

Your constitutional corpus consists of five types of documents, arranged in a strict precedence hierarchy. When two provisions conflict, the higher-ranking document prevails.

**Level 5 (Highest): Articles of Incorporation / Charter**
The foundational document of your organization. Articles define the entity's purpose, authorized activities, and fundamental governance structure. In decision.forum, Articles-level provisions override everything below them. These provisions are evaluated first, and a violation at this level halts the action before any lower-level evaluation occurs.

**Level 4: Bylaws**
The operating rules of your organization. Bylaws define board composition, officer roles, meeting procedures, quorum requirements, and standing authorities. Bylaw provisions are enforced after Articles provisions and override any conflicting Resolutions, Charters, or Policies.

**Level 3: Resolutions**
Formal decisions made by the board or other authorized bodies. Resolutions may establish policies, authorize specific actions, or delegate authority. They operate within the bounds set by Articles and Bylaws.

**Level 2: Committee Charters**
Documents that define the authority, composition, and responsibilities of specific committees (Audit Committee, Compensation Committee, Governance Committee, etc.). Charters operate within the bounds set by Resolutions and higher documents.

**Level 1 (Lowest): Policies**
Operational policies and procedures that govern day-to-day activities. Policies are the most frequently updated level of the hierarchy and have the narrowest scope of authority.

When the system evaluates constitutional constraints, it processes them in precedence order -- Articles first, then Bylaws, then Resolutions, then Charters, then Policies. If a constraint at the Articles level blocks an action, the system stops immediately. It does not evaluate lower-level provisions because the highest-ranking prohibition controls.

If provisions at the same level conflict, the system records both in a **Conflict Register** and applies the more restrictive interpretation. The conflict is surfaced to administrators for resolution.

### 3.3 How Constitutional Constraints Are Enforced in Real Time

Constitutional constraints are expressed as machine-readable rules that the system evaluates synchronously -- that is, at the exact moment an action is attempted, before the action takes effect.

There are seven types of constraint expressions:

1. **Require Quorum.** Specifies the minimum number of eligible, independent participants required for a decision.
2. **Require Supermajority.** Specifies a voting threshold above simple majority (e.g., two-thirds or three-quarters).
3. **Require Human Gate.** Specifies that the decision must be approved by a verified human, not an AI agent.
4. **Require Clearance.** Specifies the minimum security clearance level required to participate.
5. **Require Cross-Branch Verification.** Specifies that approval from multiple organizational branches is required.
6. **Monetary Cap.** Sets a maximum financial commitment that can be authorized at a given level.
7. **Custom Constraint.** A user-defined rule expressed as a predicate. Custom constraints default to deny -- if the system cannot evaluate a custom constraint, the action is blocked.

When a governed action is attempted, the system:

1. Loads the current constitutional version for the organization.
2. Identifies all constraints that apply to the action based on its decision class, the actor's role, and the subject matter.
3. Evaluates each constraint in precedence order.
4. If any constraint with a **Block** failure action is violated, the action is halted and the violation is recorded.
5. If a constraint with a **Warn** failure action is violated, the action may proceed but the violation is logged and flagged for review.

This evaluation is not optional and cannot be bypassed. It runs on every state transition of every Decision Object, not just at the final approval stage.

### 3.4 Amending Your Constitution

Because your constitution is a living governance document, decision.forum provides a formal amendment process. The key principle: **amending the constitution is itself a governed decision.**

To amend your constitution, you create a Decision Object with the class set to Constitutional. This means the amendment is subject to all the protections that apply to Constitutional-class decisions: the highest quorum requirements, supermajority thresholds, human-only authorization, and complete evidence documentation.

The amendment process works as follows:

1. **Propose the amendment.** Create a Constitutional-class Decision Object describing the proposed change, including the exact text to be added, modified, or removed.

2. **Evaluate impact.** Use the dry-run mode (see [Section 3.5](#35-dry-run-mode-test-before-you-commit)) to assess how the amendment would affect in-flight decisions, existing delegations, and current constraints.

3. **Deliberate.** Follow the full deliberation process with Information Package, conflict disclosures, and structured discussion.

4. **Vote.** Meet the enhanced quorum and supermajority requirements for Constitutional decisions.

5. **Seal.** Upon approval, the new constitutional version takes effect. The old version is preserved, and all decisions made under it remain bound to it. The amendment does not retroactively change the constitutional basis of prior decisions.

This approach ensures that your governance framework evolves deliberately and transparently, with full accountability for every change.

### 3.5 Dry-Run Mode: Test Before You Commit

Before enacting a constitutional amendment, you can use **dry-run mode** to simulate its effects without changing anything. Dry-run mode evaluates the proposed amendment against your existing decisions, delegations, and constraints and produces an impact report.

The impact report shows:

- Which existing constraints would be modified, added, or removed.
- Which in-flight decisions (those not yet in terminal status) would be affected.
- Which delegations would need to be updated to comply with new requirements.
- Whether any new conflicts would be introduced between provisions at different precedence levels.

Dry-run mode does not modify the constitution, does not affect any Decision Object, and does not create any binding commitment. It is purely an analysis tool. The results are preserved as evidence attached to the proposed amendment, demonstrating that the organization evaluated the impact before acting -- a key element of the duty-of-care defense.

---

## Chapter 4: Authority and Delegation

### 4.1 Understanding the Authority Matrix

The **authority matrix** is a comprehensive mapping of who can do what within your organization's governance structure. It answers the question: for any given action, who has the authority to take it, and where did that authority come from?

In decision.forum, all authority flows from the constitutional root -- the foundational document of your organization. Authority is then delegated downward through a chain of signed delegations. Each link in the chain specifies:

- **Delegator:** Who is granting the authority (identified by their DID).
- **Delegatee:** Who is receiving the authority.
- **Scope:** What actions the delegatee is authorized to perform. Scope is expressed as a structured permission set that is machine-readable and machine-enforceable.
- **Duration:** When the delegation starts and when it expires. All delegations must have an expiry date, with a maximum of twelve months for standing authority.
- **Sub-delegation permission:** Whether the delegatee may further delegate this authority to others.
- **Monetary cap:** The maximum financial commitment the delegatee can authorize under this delegation.
- **Decision class ceiling:** The highest class of decision the delegatee may participate in.

The authority matrix is queryable in real time. At any moment, you can ask: "What authority does person X currently hold?" and receive a complete, signed answer showing every active delegation and its chain back to the constitutional root.

### 4.2 How Delegation Works

Delegation in decision.forum follows the trust model expressed in Axiom 1: authority is held in trust, never owned. When you delegate authority to someone, you are not giving them a piece of your power. You are temporarily entrusting them with a defined scope of action, subject to your oversight and revocable at your discretion.

Creating a delegation requires:

1. **You must hold the authority you are delegating.** You cannot delegate what you do not have. The system verifies this by walking your own authority chain back to the constitutional root.

2. **The scope must narrow or remain the same.** A delegation can never widen scope. If you have authority to approve contracts up to $100,000, you can delegate authority to approve contracts up to $50,000 -- but not up to $200,000. The system enforces this through a formal subset check on the scope descriptors.

3. **You must sign the delegation.** Your Ed25519 cryptographic signature binds your identity to the delegation record. This signature is verified every time anyone exercises the delegated authority.

4. **You must set an expiry.** Every delegation has a hard expiry date, after which it is immediately dead. There is no grace period, no soft expiry, and no automatic renewal. When a delegation expires, all actions that depend on it are immediately blocked.

The delegation is recorded as a link in an **authority chain**. When the delegatee takes a governed action, the system builds the complete chain from their delegation back to the constitutional root, verifies every signature at every link, checks that no link has expired, and confirms that scope has only narrowed (never widened) at each step. This verification happens synchronously on every governed action.

### 4.3 Sub-Delegation

Sub-delegation occurs when a delegatee further delegates authority they received. This is permitted only when the original delegation explicitly allows it, by setting the sub-delegation permission to true.

When sub-delegation is permitted, it is subject to a **scope cap**: the sub-delegation cannot exceed the scope defined in the original delegation. The system enforces this by computing the intersection of the parent delegation's scope and the requested sub-delegation scope. If the sub-delegation requests any authority beyond the parent scope, the request is rejected.

The system also enforces a maximum **chain depth** of five links. A delegation chain of Root -> A -> B -> C -> D -> E is valid (five links). A chain of Root -> A -> B -> C -> D -> E -> F is rejected because it exceeds the maximum depth. This prevents authority chains from becoming so long that they are difficult to audit.

**Circular delegation** -- where A delegates to B and B delegates back to A -- is detected and rejected. The system performs cycle detection on the delegation graph before accepting any new delegation.

### 4.4 The Sunset Calendar

The **sunset calendar** is a dashboard view that shows all active delegations sorted by expiry date. It answers the question: "What is about to expire, and when?"

decision.forum generates notification events at the following intervals before delegation expiry:

- 90 days before expiry
- 60 days before expiry
- 30 days before expiry
- 14 days before expiry
- 7 days before expiry

These notifications go to both the delegator and the delegatee, ensuring neither is surprised when authority lapses.

The sunset calendar also displays:

- Delegations that have expired within the last 30 days (for audit purposes).
- Delegations that have been revoked (with the revocation timestamp and reason).
- The percentage of authority coverage -- how much of the organization's authority matrix has current, valid delegations versus expired or missing ones.

All standing delegations are capped at a maximum duration of twelve months. If you need someone to hold authority for longer, you must create a new delegation. This mandatory renewal ceremony ensures that authority allocations are periodically reviewed and reaffirmed.

### 4.5 Revoking Authority

Revocation in decision.forum is immediate and irreversible. When you revoke a delegation:

1. The revocation takes effect instantly. Any in-progress action that depends on the revoked delegation will fail its next authority chain verification.

2. The revocation is permanent. Once revoked, the delegation cannot be restored. If the same authority is needed again, a new delegation must be created through the normal delegation process.

3. The revocation is recorded. The revocation event is appended to the tamper-evident audit log with your identity, the timestamp, the reason for revocation, and a cryptographic signature.

4. All downstream delegations are also invalidated. If you revoke authority that someone sub-delegated, the sub-delegations become invalid because they depend on a chain that now includes a revoked link.

The system targets a **revocation latency** of less than sixty seconds -- from the moment you initiate revocation to the moment the revoked delegation is rejected everywhere in the system.

---

## Chapter 5: Making Decisions

### 5.1 Step by Step: Creating a New Decision

Creating a decision in decision.forum follows the **Syntaxis workflow** -- a defined sequence of verification steps that every governed action must pass through. The workflow is designed so that by the time a decision reaches its terminal state, every legal and governance requirement has been satisfied.

Here is what happens at each step:

**Identity Resolution.** The system resolves your DID and verifies that your cryptographic key is active (not rotated, revoked, or expired). This confirms you are who you claim to be.

**Consent Check.** The system verifies that the required consents are in place for the action you are about to take. This follows a default-deny model: without explicit consent, the action is blocked.

**Authority Check.** The system builds your authority chain, verifying every link from your delegation back to the constitutional root. Real Ed25519 signature verification is performed against each grantor's public key.

**Signer Type Binding.** The system cryptographically binds your signer type (Human or AI) to the action. This binding is embedded in the signed payload itself, not a self-declared flag. A human signature cannot be replayed as an AI signature, and vice versa.

**Constitutional Evaluation.** The system evaluates all applicable constitutional constraints synchronously. Blocking constraints halt the action. Warning constraints are logged.

**Quorum Verification.** For decisions that require collective action, the system verifies that sufficient eligible, independent participants are available.

**Conflict Detection.** The system checks for conflicts of interest, cross-referencing the standing conflict register and the current decision's parties.

**Action Execution.** The governance action is performed -- the Decision Object is created in Draft status.

**Proof Generation.** The system generates cryptographic proofs: a Merkle proof for inclusion in the directed acyclic graph (DAG), an optional zero-knowledge proof for privacy-preserving verification.

**DAG Append.** The action is appended to the immutable governance log with a typed node and an anchor receipt binding it to an external timestamp.

**Audit Record.** An audit entry is created with a verified timestamp (never a placeholder or zero value) and chained to the previous audit entry.

**Evidence Creation.** A litigation-grade evidence record is created with a real timestamp, and the chain of custody is initialized.

You, as the user, experience this as a simple form submission. The verification steps happen automatically in the background.

### 5.2 Attaching Evidence and Deliberation Materials

Before a decision can move from Proposed to Deliberating, an **Information Package** must be created. The Information Package contains all materials that decision-makers should review before casting their votes.

The Information Package may include:

- Financial analyses and projections.
- Legal opinions and compliance assessments.
- Risk assessments for the proposed action and alternatives.
- Historical precedent -- how similar decisions were handled previously.
- Expert reports and third-party evaluations.
- Any other materials relevant to an informed decision.

Once attached, each document is hashed and included in the decision's evidence record. The hash ensures that the documents cannot be modified after the fact without detection.

The system tracks engagement with the Information Package at the individual level:

- When each participant opened the package.
- How long they spent reviewing it.
- Which specific documents they accessed.

This engagement tracking serves the duty of care. If a decision is later challenged, you can demonstrate that decision-makers actually reviewed the materials, not merely that the materials were made available. This directly addresses the precedent from *Smith v. Van Gorkom*, which established that directors must inform themselves of all material information reasonably available before making a business decision.

### 5.3 Quorum

**Quorum** is the minimum number of eligible participants required for a decision to be valid. In decision.forum, quorum is not just a head count. It is an **independence-aware** computation that distinguishes between genuine independent judgment and mere numerical presence.

The quorum calculation considers:

- **Total eligible participants.** Everyone with the authority and clearance to participate in this decision class.
- **Minimum vote threshold.** The percentage of eligible participants who must cast votes.
- **Independence requirement.** The minimum number of voters who must be independently verified -- meaning they have no shared control, no coordinated action patterns, and verified independent identity.

Independence is verified through the **crosscheck** system, which analyzes:

- Whether voters share cryptographic signing keys (which would indicate shared control).
- Whether voters share attestation roots or organizational affiliations.
- Whether voting patterns suggest coordination (e.g., identical votes cast within milliseconds of each other).

A quorum that consists entirely of voters from the same controlling entity is not a valid quorum, even if the head count is sufficient. As the system's quorum module states: numerical multiplicity without attributable independence is not legitimacy.

If quorum cannot be achieved, the decision enters a degraded governance mode where only safety-critical actions are permitted, and any actions taken are flagged for mandatory ratification once quorum is restored.

### 5.4 Voting

Voting in decision.forum is a structured, evidence-rich process. Each vote consists of:

- **Position.** For, Against, or Abstain.
- **Reasoning.** A hash-linked reference to the voter's written rationale. For Against and Abstain votes, a written explanation is mandatory and must be at least twenty characters in length. This requirement ensures that dissent is documented, which strengthens the organization's governance record.
- **Information attestation.** Before casting a vote, the participant must attest that they have reviewed the Information Package. This attestation is cryptographically linked to the specific version of the package they reviewed.
- **Conflict disclosure reference.** The vote is linked to the voter's conflict disclosure for this decision.

Votes are cryptographically signed by the voter's DID key, providing non-repudiation. The system verifies that each voter is eligible (has the required authority and clearance), has filed a conflict disclosure, and has attested to reviewing the Information Package.

Duplicate votes from the same identity are detected and rejected using cryptographic identity matching, not simple string comparison.

### 5.5 Approval Workflows

Different decision classes have different approval requirements. decision.forum enforces these workflows automatically based on the constitutional provisions for each class.

A typical approval workflow for a Strategic decision might require:

1. Proposal by an authorized proposer.
2. Legal review and compliance sign-off.
3. Financial review with risk assessment.
4. Committee recommendation (e.g., from the Audit Committee or Governance Committee).
5. Full board deliberation with independence-aware quorum.
6. Supermajority vote (e.g., two-thirds approval).
7. Constitutional constraint evaluation at each step.

The system tracks where each decision is in its workflow and notifies participants when their action is required. It also enforces ordering: a decision cannot proceed to the board vote if the committee recommendation has not been completed.

### 5.6 The Human Gate

The **Human Gate** is one of the most important governance controls in decision.forum. For certain categories of decisions -- Strategic, Constitutional, and Emergency -- the system requires that approval come from a verified human being, not an AI agent.

The Human Gate is enforced cryptographically. Human and AI signatures use different key type prefixes embedded in the signed payload itself. A human signature embeds a `0x01` prefix byte; an AI signature embeds a `0x02` prefix byte. This binding is part of the signature verification, not a self-declared flag. An AI agent physically cannot produce a valid human signature because the prefix byte would not match, and the signature verification would fail.

The Human Gate serves as the ultimate check on AI autonomy in governance. No matter how sophisticated an AI agent becomes, it cannot approve a strategic acquisition, amend the organization's bylaws, or invoke emergency powers. Those decisions require a human being who has reviewed the materials, considered the alternatives, and made a judgment that they are willing to defend.

The list of decision classes that require the Human Gate is stored as part of the constitutional corpus. Removing a class from the Human Gate list is itself a Constitutional-class decision, requiring the highest level of governance oversight. This prevents gradual erosion of human oversight through incremental policy changes.

---

## Chapter 6: Challenging and Contesting Decisions

### 6.1 Your Right to Challenge

Any stakeholder with standing may challenge a decision in decision.forum. The right to challenge is fundamental to the platform's governance model -- it ensures that no decision is final merely because it was approved through the normal process.

A challenge may be filed on any of six grounds:

1. **Procedural Error.** The decision did not follow the required process -- for example, quorum was miscounted, a required review was skipped, or the wrong decision class was applied.

2. **Constitutional Violation.** The decision conflicts with a provision in the organization's constitutional corpus.

3. **Authority Exceeded.** The decision-maker acted outside the scope of their delegated authority.

4. **Undisclosed Conflict.** A participant had a material conflict of interest that was not disclosed before they participated.

5. **Evidence Insufficiency.** The decision was made without adequate consideration of material information.

6. **Bad Faith.** The decision-makers acted with improper motives or in disregard of their fiduciary duties.

### 6.2 Filing a Formal Contestation

To file a challenge, you create a **Challenge Object** specifying:

- The Decision Object being challenged (identified by its unique ID).
- The ground(s) for the challenge.
- Supporting evidence and argumentation.
- The remedy you are seeking (reversal, modification, or procedural redo).

The Challenge Object is itself a governed record, subject to the same cryptographic sealing, audit logging, and evidence requirements as any other Decision Object.

### 6.3 What Happens When a Decision Is Challenged

When a valid challenge is filed, the following occurs automatically:

1. **The decision is paused.** The challenged Decision Object transitions to the Contested state. Any execution of the decision is immediately suspended. This ensures that a potentially flawed decision does not continue to operate while the challenge is being resolved.

2. **A Pause Order is issued.** The system generates a formal Pause Order linked to the Challenge Object, documenting the suspension of the decision.

3. **Parties are notified.** All participants in the original decision, as well as any affected stakeholders, are notified of the challenge and the pause.

4. **A review body is convened.** Depending on the nature of the challenge and the organization's constitutional provisions, the challenge may be reviewed by a designated committee, the full board, or an independent arbiter.

### 6.4 The Resolution Process

The challenge proceeds through a structured resolution process:

**Under Review.** The designated review body examines the challenge, the original decision, and all supporting evidence. Additional evidence may be requested from either side.

**Adjudication.** The review body renders a decision on the challenge. There are three possible outcomes:

- **Sustained.** The challenge is upheld. The original decision is voided and a reversal record is created. See [Section 6.5](#65-reversals).
- **Overruled.** The challenge is denied. The original decision is reinstated and transitions back to its prior status.
- **Withdrawn.** The challenger withdraws the challenge. The original decision is reinstated.

The adjudication itself is recorded as a new Decision Object, providing the same audit trail, evidence requirements, and cryptographic sealing as any other decision.

### 6.5 Reversals

When a challenge is sustained and a decision is reversed, the system creates a **reversal linkage** between the original decision and the reversal record. This linkage is immutable -- it cannot be removed from either the original Decision Object or the reversal record.

The original decision is not modified. It remains in the record exactly as it was at the time of its approval. The reversal is a new record that documents:

- What was reversed and why.
- Who authorized the reversal.
- What the consequence of the reversal is (e.g., unwinding a transaction, restoring a prior policy).

This approach preserves the integrity of the historical record while ensuring that the governance system can correct errors. Courts and auditors can see both the original decision and the reversal, along with the complete challenge and adjudication record.

---

## Chapter 7: Emergency Governance

### 7.1 When to Invoke Emergency Authority

Emergency authority exists for situations where the normal governance process is too slow to address an urgent threat. The constitutional corpus defines the circumstances under which emergency authority may be invoked, the roles authorized to invoke it, and the scope of actions permitted.

Typical grounds for invoking emergency authority include:

- Imminent financial loss that would materially harm the organization.
- Cybersecurity breach requiring immediate response.
- Regulatory action requiring immediate compliance.
- Safety hazard requiring immediate mitigation.

Emergency authority is not a shortcut for convenience. It is a governed exception to normal procedures, and the system enforces strict guardrails to prevent abuse.

### 7.2 The Guardrails

Every emergency action is subject to the following constraints:

**Monetary Cap.** Emergency actions cannot commit the organization beyond a specified financial threshold without normal governance approval.

**Enumerated Actions.** Emergency authority permits only the actions explicitly listed in the constitutional emergency provisions. Actions outside the declared scope are rejected, even under emergency authority. If an emergency is declared for financial operations, a personnel action will be blocked.

**Time Limit.** Emergency authority has a hard time-to-live of seventy-two hours. After seventy-two hours, the authority expires automatically and cannot be renewed except through the normal governance process. Actions attempted after the time limit are rejected.

**Scope Enforcement.** The scope of the emergency is declared at the time of invocation and is machine-readable. The system enforces the scope boundary -- actions outside the declared emergency scope are blocked.

### 7.3 Mandatory Ratification

Every decision made under emergency authority automatically generates a **Ratification Required** Decision Object. This ratification decision must be completed within seven days.

If ratification occurs, the emergency decision is confirmed and achieves permanent standing.

If the seven-day ratification deadline passes without ratification, the emergency decision automatically voids. Any actions taken under the voided decision must be unwound to the extent possible.

Ratification requires the same quorum and voting standards as the original decision class would have required under normal governance. The ratifying body has access to the full record of the emergency action, including the stated justification, the actions taken, and their outcomes.

### 7.4 Frequency Monitoring

decision.forum tracks the frequency of emergency invocations per quarter. If the number of emergency actions exceeds three in a single quarter, the system automatically triggers a governance review.

The governance review is itself a Decision Object that examines whether the frequency of emergencies indicates a systemic governance problem -- for example, inadequate standing authority, unrealistic timelines in normal processes, or a pattern of using emergency powers to circumvent normal governance.

Per-actor limits are also enforced. A single individual is limited to one emergency invocation per quarter. This prevents any individual from using emergency powers as their default operating mode.

---

## Chapter 8: Accountability

### 8.1 Accountability Actions

decision.forum provides four formal accountability mechanisms, each escalating in severity:

**Censure** is a formal expression of disapproval. It is recorded permanently in the governance record and may affect the individual's eligibility for future delegations. Censure does not remove any existing authority.

**Suspension** temporarily removes an individual from governance participation. During suspension, the individual cannot create, vote on, or approve any Decision Objects. All of their active delegations are paused (not revoked) for the duration of the suspension.

**Revocation** permanently removes specific authority. Unlike suspension, revocation is targeted -- it removes designated delegations while potentially leaving others intact. Revocation is irreversible; new delegations must be explicitly created if the authority is later needed.

**Recall** removes an individual from their governance role entirely. Recall requires a supermajority quorum and is the most severe accountability action. It voids all of the individual's delegations and removes them from all governance bodies.

### 8.2 Due Process Requirements

Every accountability action is itself a Decision Object, subject to the same governance standards as any other decision. The subject of the action is entitled to:

- Notice of the proposed action and the grounds for it.
- An opportunity to respond, including the right to present evidence and argument.
- A decision by an impartial body (no one who filed the accountability complaint may vote on the action).
- A written record of the reasoning for the decision.

The system clocks all due-process deadlines. If a deadline passes without the required action being taken, the system auto-escalates to the next level of review.

### 8.3 Immediate Suspension

In cases involving potential fraud, active data breach, or imminent irreversible harm, the system permits immediate suspension pending investigation. Immediate suspension:

- Takes effect at the moment of issuance.
- Requires authorization by a role with explicit emergency-suspension authority.
- Automatically generates a formal accountability proceeding that must be completed within a defined timeline.
- Is temporary -- if the formal proceeding is not completed within the required timeframe, the suspension is automatically lifted.

Even immediate suspension generates a complete audit record with the authorizing identity, the reason, and the timestamp.

### 8.4 The Accountability Trail

Every accountability action is recorded in the same tamper-evident audit log as every other governance action. The accountability trail includes:

- Who initiated the accountability action and when.
- The specific grounds cited with supporting evidence.
- The subject's response.
- The deliberation record of the deciding body.
- The final determination with reasoning.
- Any sanctions applied and their duration.

This trail is available to auditors, regulators, and courts to demonstrate that your organization takes accountability seriously and follows a defined process.

---

## Chapter 9: Conflict of Interest Management

### 9.1 Disclosure Requirements

Before participating in any decision at the Operational level or above, every participant must file a conflict-of-interest disclosure. This requirement is absolute and enforced at the system level -- not by asking participants to self-police, but by blocking participation until disclosure is complete.

A conflict disclosure includes:

- **Declarant identity.** The participant's DID.
- **Conflict status.** Whether a conflict exists (positive disclosure) or does not exist (negative disclosure).
- **Nature of the conflict.** For positive disclosures, a description of the relationship, interest, or circumstance that creates the conflict.
- **Related parties.** The identities or entities involved in the conflict.
- **Severity assessment.** The system classifies conflicts into three levels:
  - **Advisory:** A minor potential conflict that does not require recusal but should be noted.
  - **Material:** A significant conflict that may require recusal depending on the circumstances.
  - **Disqualifying:** A conflict so direct that the participant must recuse themselves from the decision.

Disclosures are maintained in a **Standing Conflict Register** that persists across decisions. If you disclosed a conflict with Company X in one decision, the system will automatically flag that conflict when Company X is involved in a subsequent decision. You do not need to re-disclose a known conflict -- the system remembers.

### 9.2 Recusal

When a conflict is classified as Disqualifying, the system enforces **recusal** -- the participant is blocked from voting, approving, or otherwise participating in the decision. This is not a recommendation; it is a hard block. The participant's vote will be rejected if they attempt to cast one.

When a participant recuses themselves, the quorum denominator is adjusted accordingly. If the board has seven members and one recuses, quorum is calculated against six, not seven.

The recusal is recorded in the Decision Object's conflict disclosure record, providing a permanent record that the conflict was identified and managed appropriately.

### 9.3 The System Blocks Participation Until Disclosure Is Complete

This principle bears repeating because it is central to the platform's conflict management approach: **the system blocks, it does not warn.**

If you attempt to cast a vote without filing a conflict disclosure, the system rejects the vote with an error. It does not display a warning that you can dismiss. It does not allow you to proceed with a note in the log. It stops the action.

This design choice reflects a governance philosophy: the cost of a missed disclosure (potential liability, voided decisions, personal fiduciary exposure) is so high that the system should make compliance the only path forward. Filing a disclosure takes less than a minute. Failing to disclose can cost millions in litigation and personal liability.

### 9.4 DGCL Section 144 Safe Harbor

For organizations incorporated in Delaware (or applying Delaware law by analogy), decision.forum implements the **DGCL Section 144 safe-harbor** workflow. Section 144 provides that a transaction involving an interested director is not voidable solely because of the interest if certain conditions are met.

decision.forum supports all three safe-harbor paths defined in the statute:

**Path 1: Board Approval (Section 144(a)(1)).** The material facts of the director's interest and the transaction are disclosed to the board, and the board authorizes the transaction by a vote of the disinterested directors. decision.forum automates this by:
- Tracking the disclosure filing.
- Requiring each non-conflicted board member to acknowledge receipt of the disclosure.
- Recording the disinterested director vote separately from the general vote.
- Verifying that a majority of disinterested directors approved.

**Path 2: Shareholder Approval (Section 144(a)(2)).** The material facts are disclosed to shareholders and the transaction is approved by a vote of the disinterested shareholders. decision.forum supports this through a separate shareholder voting workflow with the same disclosure and acknowledgment requirements.

**Path 3: Fairness (Section 144(a)(3)).** The transaction is fair to the corporation at the time it is authorized. decision.forum supports this by allowing attachment of a fairness opinion (from an independent financial advisor or internal analysis) as evidence, with the fairness determination recorded as part of the decision record.

Upon completion of any safe-harbor path, the system generates a **Section 144 Certificate** -- a signed record documenting that the statutory requirements were met. This certificate can be presented to a court as evidence of compliance.

The system maintains a **Section 144 Register** per tenant, listing all interested transactions and their safe-harbor status. This provides a single view of all related-party transactions and their governance treatment.

---

## Chapter 10: AI Agents in Your Governance

### 10.1 What AI Agents Can and Cannot Do

AI agents in decision.forum operate exclusively under delegated authority. They do not have original authority of their own. Everything an AI agent does must trace back to a human delegation through a verified authority chain.

**AI agents can:**
- Create Draft and Proposed Decision Objects within their delegated scope.
- Attach evidence and analysis to decisions.
- Participate in Routine-class decisions (voting, recommending).
- Execute automated workflows within their delegated authority.
- Generate reports and analyses.

**AI agents cannot:**
- Approve Strategic, Constitutional, or Emergency decisions (the Human Gate blocks this).
- Create, modify, or revoke delegations (this is reserved for humans).
- Modify the authority matrix or constitutional corpus.
- Override human decisions.
- Expand their own scope of authority (any attempt is a security incident).
- Exceed their delegation ceiling class.

### 10.2 The Delegation Ceiling

Every AI agent has a **delegation ceiling** -- the highest decision class it is permitted to participate in. This ceiling is set by the human delegator at the time of delegation and is cryptographically bound to the delegation record with the delegator's signature.

If an AI agent with an Operational ceiling attempts to participate in a Strategic decision, the system rejects the action immediately. The ceiling is not self-declared by the AI -- it is derived from the delegation chain and verified against the delegator's signature.

AI delegations are also subject to a maximum duration of 90 days. This is shorter than the 12-month maximum for human delegations, reflecting the principle that AI authority should be reviewed more frequently.

### 10.3 AI Cannot Create or Modify Delegations

This is one of the most important constraints in the system. An AI agent cannot grant authority to anyone -- human or AI. An AI agent cannot modify its own delegation record. An AI agent cannot revoke another entity's delegation.

Any attempt by an AI agent to perform a delegation action is treated as a security incident. The attempt is logged, the action is blocked, and the incident is surfaced for review. Depending on the organization's constitutional provisions, repeated attempts may trigger automatic delegation revocation review for the offending AI agent.

This constraint ensures that the authority structure of the organization remains under exclusive human control, regardless of how capable AI agents become.

### 10.4 Distinguishing AI Actions from Human Actions

Every action in decision.forum is cryptographically tagged with the signer type. The tagging mechanism uses prefix bytes embedded in the signed payload:

- Human signatures embed a `0x01` prefix byte.
- AI signatures embed a `0x02` prefix byte.

This prefix is part of the data that is signed. It is not a metadata flag that can be changed after the fact. If an AI agent signs a payload, the `0x02` prefix is permanently embedded in the signature. If anyone tries to present that signature as human, the verification will fail because the prefix bytes will not match.

This means:
- An AI action can never be disguised as a human action.
- A human action can never be replayed as an AI action.
- The provenance of every action is permanently and unforgettably bound to the signer type.

In reporting and audit views, AI actions are visually distinguished from human actions, allowing governance professionals to immediately see the proportion of AI involvement in any decision.

### 10.5 The Six MCP Enforcement Rules

The **Model Context Protocol (MCP)** defines six rules that constrain all AI agent behavior in decision.forum. These rules are enforced by the system's gatekeeper on every AI action, with no exceptions.

**Rule 1: BCTS Scope (Bounded Context Trust Scope).** An AI agent may only act within the scope defined in its delegation. Any action outside the declared scope is rejected. The scope is defined at delegation time and cannot be expanded by the AI.

**Rule 2: No Self-Escalation.** An AI agent cannot expand its own capabilities, request additional authority, or modify the terms of its delegation. Any attempt to do so is blocked and logged as a security incident.

**Rule 3: Provenance Required.** Every AI action must carry verifiable provenance -- the complete chain of delegation, the identity of the acting agent, and the timestamp. Actions without provenance are rejected.

**Rule 4: No Forgery.** An AI agent cannot forge, modify, or misrepresent identity, authority, or evidence. The cryptographic binding of signer type makes identity forgery mathematically infeasible.

**Rule 5: Distinguishable.** AI-generated output must be identifiable as such. The system marks all AI-originated content with provenance metadata that cannot be removed or obscured.

**Rule 6: Consent Boundaries.** AI agents must operate within the consent boundaries defined for the data and systems they access. If an AI agent's delegation does not include consent to access a particular dataset, access is denied regardless of whether the AI "needs" the data for its task.

---

## Chapter 11: Legal and Compliance

### 11.1 Self-Authenticating Business Records

decision.forum is designed to produce records that qualify as **self-authenticating business records** under the Federal Rules of Evidence, specifically FRE 803(6) (business records exception to hearsay) and FRE 902(13)-(14) (certified records of regularly conducted activity).

What this means in practice: when your organization's decision records are presented in court, they should not require a live witness to testify about how they were created. The records authenticate themselves because they contain sufficient embedded provenance to establish their reliability.

For a record to be self-authenticating, it must demonstrate:

- **It was made at or near the time of the event.** decision.forum binds every record to a verified timestamp at creation, anchored to at least two independent time sources (an RFC 3161 Timestamp Authority and a blockchain anchor).

- **It was made by a person with knowledge.** The authority chain embedded in each Decision Object traces the action to a specific, identified individual through cryptographic signatures.

- **It was kept in the ordinary course of business.** The system maintains a System Description Document explaining that decision.forum is the organization's regular practice for governance record-keeping.

- **It was made as a regular practice of the organization.** The constitutional framework itself establishes that all governance actions are processed through decision.forum.

The system auto-generates an **FRE 902(11) certification template** for terminal Decision Objects. This template contains the declarant placeholder, the record hash, the custody chain digest, and the system description -- everything needed for an authorized person to certify the record under Rule 902(11) without requiring extensive testimony.

### 11.2 Chain of Custody

Every Decision Object maintains a complete **chain of custody** -- a hash-linked sequence of custody events recording every access to and modification of the record.

Custody events include:

- **Create.** The record was created.
- **View.** The record was accessed for reading (with the viewer's identity and timestamp).
- **Edit.** The record was modified (with the nature of the modification).
- **Approve/Reject.** A governance action was taken on the record.
- **Export.** The record was exported (e.g., for e-discovery production).
- **Status Change.** The record's lifecycle state changed.

Each custody event is linked to the previous one by a cryptographic hash, creating a tamper-evident chain. If any event is modified, inserted, or deleted, the chain breaks and the tampering is detectable.

The chain of custody satisfies the requirements of FRE 901(b)(9) (system integrity) and FRCP 37(e) (obligations regarding electronically stored information). It provides the foundation for demonstrating that records have not been spoliated, altered, or improperly handled.

### 11.3 E-Discovery Readiness

When litigation arises, decision.forum provides the tools needed for efficient and defensible e-discovery production.

**Search and Collection.** The system supports search by date range, custodian (the person responsible for the records), decision class, content terms, and other metadata. Search results include both the matching records and a privilege log for any records excluded on privilege grounds.

**Privilege Protection.** Privileged records (attorney-client communications, work product) are maintained in a technically separate privilege compartment with independent encryption keys. The e-discovery search function automatically excludes privileged documents from production and generates FRCP 26(b)(5)-compliant privilege log entries describing each withheld document.

**Production Format.** Records can be exported in PDF/A-3 format (for human review) with accompanying EDRM XML load files (for litigation support platform ingestion). Each produced document receives a unique production number (Bates stamp).

**Collection Certification.** Every production includes a signed Collection Certification attesting to the methodology, completeness, and any known gaps in the collection.

**Deduplication.** Identical documents appearing across multiple custodians are deduplicated with multi-custodian attribution, reducing production volume without losing information about who held copies.

### 11.4 Fiduciary Defense Packages

When a Decision Object reaches terminal status (Approved, Rejected, or Void), the system generates a **Fiduciary Defense Package** within sixty seconds. This package is a self-contained, cryptographically sealed artifact that provides the evidence a board member would need to defend their decision under the Business Judgment Rule.

The package is structured around the four prongs of the Business Judgment Rule:

**Prong 1: Disinterestedness.** The package includes the conflict disclosure register excerpt, all recusal records, and a board composition analysis showing the proportion of disinterested decision-makers. A decision where the majority of participants were disinterested scores highly on this prong.

**Prong 2: Informed Basis.** The package includes the Information Package manifest, per-participant engagement metrics (who reviewed what, for how long), and materials review attestations. A decision where all voters reviewed the materials thoroughly scores highly on this prong.

**Prong 3: Good Faith.** The package includes deliberation records, alternatives considered (including the "no action" alternative), dissent records, and a process compliance timeline. A decision that followed all required procedures and considered alternatives scores highly on this prong.

**Prong 4: Rational Basis.** The package includes the selected alternative's rationale, the risk assessment, and supporting evidence. A decision with a clearly articulated rationale supported by evidence scores highly on this prong.

Each prong receives a score from 0.0 to 1.0, and an overall BJR defensibility score is computed. The package is designed to be self-verifiable: it contains all the cryptographic proofs needed to independently confirm every claim.

### 11.5 Records Retention

decision.forum implements a configurable records retention system with automatic lifecycle management.

Records move through four disposition stages:

- **Active.** The record is in regular use and stored in the hot tier for immediate access.
- **Retention Hold.** The record is subject to a litigation hold or regulatory preservation requirement. It cannot be destroyed regardless of its retention schedule.
- **Pending Destruction.** The retention period has expired and all holds have been released. The record is queued for destruction.
- **Destroyed.** The record has been destroyed in accordance with the retention policy. A destruction certificate is generated and retained as the final custody event.

**Litigation holds** are first-class objects in the system. A hold specifies the legal matter, the issuing authority, the scope of records covered, and the custodians affected. Multiple holds can overlap on the same record, and the record cannot be destroyed until every hold has been released.

Attempted destruction of a held record generates a **spoliation risk alert** and is blocked by the system. The hold release process requires signed authorization and creates a custody event with the releasing authority's identity and the matter reference.

Retention periods are configurable by record classification and regulatory context. The system supports standard retention schedules (e.g., seven years for financial records under SOX) and custom schedules defined in the organization's constitutional corpus.

---

## Chapter 12: Reporting and Metrics

### 12.1 The Governance Metrics Dashboard

decision.forum provides a comprehensive governance metrics dashboard that gives real-time visibility into the health of your organization's governance practices. The dashboard tracks twelve key metrics across four categories: authority, process, evidence, and compliance.

**Authority Metrics:**
1. Authority Verification Coverage
2. Revocation Latency
3. Delegation Expiry Compliance
4. Authority Chain Depth Distribution

**Process Metrics:**
5. Decision Cycle Time (by class)
6. Quorum Achievement Rate
7. Challenge Frequency and Outcomes
8. Emergency Invocation Frequency

**Evidence Metrics:**
9. Evidence Completeness Score
10. Information Package Engagement Rate
11. Conflict Disclosure Compliance Rate

**Compliance Metrics:**
12. Constitutional Constraint Violation Rate

### 12.2 Authority Verification Coverage

This metric measures the percentage of governed actions that successfully passed authority chain verification. The target is 100%. Any action that failed authority verification is a potential governance gap.

An authority verification coverage of less than 100% means that some actions were attempted without valid authority chains. While the system blocks these actions, the attempts themselves may indicate misconfigured delegations, expired authority, or unauthorized access attempts.

Monitor this metric for trends. A sudden increase in verification failures may indicate a need to review and update delegations, or it may signal an attempted security breach.

### 12.3 Revocation Latency

This metric measures the time from when a revocation is initiated to when the revoked delegation is rejected everywhere in the system. The target is less than sixty seconds.

Revocation latency matters because a revoked delegation that is still being honored represents a governance gap. The shorter the latency, the smaller the window of exposure.

If revocation latency exceeds the target, it may indicate a caching issue, a replication delay, or a system performance problem that should be investigated.

### 12.4 Evidence Completeness

This metric measures the percentage of terminal Decision Objects that have a complete evidence record: non-empty evidence attached, complete chain of custody, verified Merkle root, and timestamp anchoring. The target is 99% or greater.

Evidence completeness is directly tied to the legal defensibility of your decisions. A decision without complete evidence may not qualify as a self-authenticating business record and may require live testimony to establish its provenance -- which defeats much of the value proposition of the platform.

### 12.5 How to Interpret the Metrics

The governance metrics dashboard is designed to surface problems early, before they become crises. Here are guidelines for interpreting the key metrics:

**Green zone (healthy):** Authority verification at 100%, revocation latency under 60 seconds, evidence completeness above 99%, conflict disclosure compliance at 100%, zero constitutional violations.

**Yellow zone (attention needed):** Authority verification below 100%, revocation latency between 60 and 300 seconds, evidence completeness between 95% and 99%, disclosure compliance below 100%, occasional constraint violations.

**Red zone (action required):** Revocation latency above 300 seconds, evidence completeness below 95%, repeated constitutional violations, emergency invocations exceeding the quarterly threshold, or degraded governance mode activation.

When a metric enters the yellow or red zone, investigate the root cause promptly. The dashboard provides drill-down capabilities to identify which specific decisions, delegations, or actors are contributing to the issue.

---

## Chapter 13: Administration

### 13.1 Setting Up Your Organization's Constitution

When you first deploy decision.forum, the most important configuration step is encoding your organization's governance framework as a constitutional corpus.

Begin with your existing governance documents: articles of incorporation, bylaws, board resolutions, committee charters, and policies. For each document:

1. **Assign a precedence level.** Map the document to one of the five levels in the hierarchy (Articles, Bylaws, Resolutions, Charters, Policies).

2. **Identify constraints.** Extract the rules that should be machine-enforced. For example, "A majority vote of the board is required to approve transactions exceeding $1 million" becomes a constraint combining a monetary cap, a quorum requirement, and a decision class assignment.

3. **Encode the constraints.** Express each constraint using the system's constraint expression format (Require Quorum, Require Supermajority, Require Human Gate, Require Clearance, Require Cross-Branch Verification, Monetary Cap, or Custom Constraint).

4. **Sign the constitution.** Authorized signatories (typically the board chair and general counsel) cryptographically sign the constitutional corpus, establishing it as the authoritative governance framework.

5. **Test with dry-run.** Before activating the constitution, use dry-run mode to verify that sample decisions are correctly evaluated against the constraints. Ensure that valid decisions are permitted and invalid decisions are blocked.

6. **Activate.** Deploy the constitution as the active governance framework. All subsequent decisions will be evaluated against it.

### 13.2 Managing Users and Roles

Each user in decision.forum is identified by a **Decentralized Identifier (DID)** -- a globally unique, cryptographically verifiable identity. Users are assigned roles that determine their baseline capabilities.

Common roles include:

- **Governor.** Full governance authority as defined in the constitutional corpus.
- **Director.** Board member with voting rights on decisions within their committee scope.
- **Officer.** Executive with operational authority as defined by their delegation.
- **Counsel.** Legal advisor with review and advisory capabilities.
- **Compliance Officer.** Authority to monitor, audit, and flag governance issues.
- **Observer.** Read-only access to governance records within their clearance level.
- **AI Agent.** An artificial intelligence operating under delegated authority with defined ceiling and scope.

Roles are configured in the authority matrix and mapped to delegation scopes. A user's effective authority is the intersection of their role-based permissions and their specific delegations.

Key management follows a strict lifecycle: keys are Active, then may be Rotated (a new key replaces the old, with both linked in the DID document), and eventually Revoked or Expired. Revoked and expired keys are retained in the record for historical verification but cannot be used for new actions.

### 13.3 Configuring Decision Classes

Each organization can customize the requirements for each decision class. Configuration options include:

- **Quorum threshold.** The minimum percentage of eligible participants required.
- **Approval threshold.** The percentage of votes required for approval (simple majority, two-thirds, three-quarters, unanimity).
- **Independence requirement.** The minimum number of independently verified voters.
- **Human Gate.** Whether the class requires human approval (cannot be set to false for Constitutional class).
- **Required reviews.** Which review steps must be completed before the decision can proceed to voting.
- **Maximum AI participation.** The maximum percentage of AI signers permitted (system maximum is 49%).
- **Challenge window.** How long after approval a challenge may be filed.
- **Evidence requirements.** Minimum evidence attachments, Information Package requirements, and engagement thresholds.

These configurations are stored as part of the constitutional corpus and are themselves subject to governance controls. Changing a decision class configuration requires a decision at the same or higher class level.

### 13.4 Setting Up the Authority Matrix

The authority matrix is configured by creating delegations that map roles and individuals to specific governance authorities. A typical setup process:

1. **Define the root authority.** The board of directors (or equivalent governing body) holds root authority, derived directly from the articles of incorporation.

2. **Create board-level delegations.** The board delegates specific authorities to committees (Audit Committee, Compensation Committee, Governance Committee) and officers (CEO, CFO, General Counsel).

3. **Create officer-level delegations.** Officers delegate operational authority to their direct reports within defined scopes.

4. **Create AI delegations.** Authorized humans delegate bounded authority to AI agents for routine tasks.

5. **Verify the matrix.** Use the authority matrix query tool to verify that every required authority is covered and that no unintended gaps or overlaps exist.

6. **Set the sunset calendar.** Review all delegation expiry dates and configure notification preferences for upcoming expirations.

### 13.5 Customizing Notification Preferences

decision.forum generates notifications for governance events. Administrators can configure:

- **Notification channels.** Email, in-app notification, webhook, or API callback.
- **Notification triggers.** Which events generate notifications (new decisions, votes needed, challenges filed, delegation expiring, quorum issues, etc.).
- **Escalation rules.** Automatic escalation when notifications are not acknowledged within a specified timeframe.
- **Digest frequency.** Whether notifications are delivered immediately, hourly, or daily.

For delegation expiry notifications, the system follows the standard schedule (90, 60, 30, 14, and 7 days before expiry) with both delegator and delegatee receiving notifications.

### 13.6 Multi-Tenant Isolation

decision.forum operates in a multi-tenant architecture where each organization is a separate, isolated tenant. Tenant isolation is enforced at every layer of the system:

**Data isolation.** Each tenant's data is stored in a separate namespace with tenant-specific encryption keys. A query from Tenant A's session cannot access Tenant B's data, even at the database level.

**Constitutional isolation.** Each tenant has its own independent constitution. Tenant A's constraints have no effect on Tenant B's decisions.

**Authority isolation.** Delegations are tenant-scoped. A delegation in Tenant A's authority matrix has no meaning in Tenant B's context.

**Audit isolation.** Each tenant has its own audit log. Cross-tenant references, when they exist (e.g., a joint venture), are implemented as cryptographic hash pointers that are independently validated by each tenant's governance engine.

**Rate limiting.** Each tenant has independent rate limits, ensuring that one tenant's activity cannot degrade service for another.

Administrators cannot access other tenants' data, configurations, or records. System-level operations that span tenants (such as platform upgrades) are themselves governed by the platform's own governance framework.

---

## Chapter 14: Security and Trust

### 14.1 How Your Data Is Protected

decision.forum employs defense in depth -- multiple independent layers of security, each designed to protect your data even if another layer is compromised.

**At rest.** All data is encrypted with tenant-specific keys. Privileged data (attorney-client communications, work product) uses a separate key hierarchy accessible only to privilege-designated actors.

**In transit.** All communications use mutual TLS (mTLS) with tenant-specific certificates. There is no unencrypted communication path.

**In processing.** Sensitive computations occur within hardware security enclaves (Trusted Execution Environments) where the data is protected even from the infrastructure operator. TEE attestation verifies that the enclave is running the expected code on genuine hardware.

**Key management.** Cryptographic keys follow a strict lifecycle (Active, Rotated, Revoked, Expired). Secret keys are zeroized (overwritten with zeros) immediately upon leaving scope, preventing them from lingering in memory where they could be extracted.

### 14.2 Zero-Trust Architecture

decision.forum follows a zero-trust security model: no action is trusted by default, regardless of where it originates or who initiates it.

Every action must pass through the governance gateway, which enforces:

1. **Identity verification.** Is the actor who they claim to be? (DID resolution and key verification.)
2. **Consent verification.** Does the actor have consent to perform this action? (Default deny -- without explicit consent, the action is blocked.)
3. **Authority verification.** Does the actor have a valid, unrevoked, unexpired delegation for this action? (Full authority chain verification with real cryptographic signature checks.)
4. **Constitutional compliance.** Does this action comply with all applicable constitutional constraints? (Synchronous evaluation of all blocking constraints.)
5. **Audit recording.** Is this action being recorded in the tamper-evident log? (No action can bypass audit.)

If any check fails, the action is denied. There is no override, no bypass, and no escalation path that skips verification. Even emergency actions pass through the governance gateway -- they are subject to emergency-specific constraints rather than no constraints.

### 14.3 Cryptographic Guarantees

decision.forum uses the following cryptographic primitives:

**Ed25519 signatures** for identity binding, delegation signing, and action attribution. Ed25519 provides 128-bit security against classical computers and is widely audited and trusted.

**Blake3 hashing** for content integrity, hash chaining, and Merkle tree construction. Blake3 is a cryptographic hash function that is both secure and fast.

**Hybrid Logical Clocks (HLC)** for causal ordering of events. HLC provides a monotonically increasing timestamp that respects causality -- if event A caused event B, A's timestamp is always earlier than B's.

**Merkle DAG (Directed Acyclic Graph)** for tamper-evident storage. Every record is a node in a graph where each node references its parent(s) by hash. Modifying any node changes its hash, which breaks all references from child nodes, making tampering detectable.

**Sparse Merkle Tree (SMT)** for efficient state membership proofs. Given any record, the system can produce a compact proof that the record is (or is not) part of the current state, verifiable in logarithmic time.

**Merkle Mountain Range (MMR)** for append-only accumulation. The MMR provides compact proofs of historical inclusion -- proving that a record existed at a specific point in time.

### 14.4 The Tamper-Evident Audit Log

The audit log in decision.forum is not a conventional log file. It is a hash-chained, append-only data structure where each entry includes the cryptographic hash of the previous entry, creating a chain that is mathematically impossible to modify without detection.

Properties of the audit log:

- **Append-only.** New entries can be added. Existing entries cannot be modified or deleted.
- **Hash-chained.** Each entry includes the hash of the previous entry. Modifying any entry changes its hash, which breaks the chain at the next entry.
- **Timestamped.** Each entry carries a verified HLC timestamp. Placeholder or zero timestamps are rejected.
- **Signed.** Each entry is signed by the actor who performed the action, providing non-repudiation.
- **Self-verifying.** The system automatically verifies audit chain integrity on a regular schedule. Any gap, modification, or inconsistency generates a security incident.
- **Externally anchored.** Periodic checkpoints are anchored to external time sources and blockchain, providing independent proof of the log's state at specific points in time.

### 14.5 Post-Quantum Readiness

decision.forum is designed with a migration path to post-quantum cryptography. This matters because quantum computers, once sufficiently powerful, will be able to break the elliptic curve cryptography that underlies Ed25519 signatures. Given the platform's 50-year retention commitment, records signed today must remain verifiable decades from now.

The system's approach to post-quantum readiness:

**Variable-length signatures.** The signature format supports multiple algorithms, including Ed25519 (64 bytes), post-quantum algorithms like ML-DSA/Dilithium (2,420+ bytes), and hybrid signatures combining both.

**Phased migration.** The transition to post-quantum signatures follows three phases:
- Phase 1: Both classical and post-quantum signatures are produced; either is accepted for verification.
- Phase 2: Both signatures are produced; both are required for verification.
- Phase 3: Only post-quantum signatures are produced and accepted.

Each phase transition is recorded as a governance decision in the system.

**Hash-based archival proofs.** The STARK (Scalable Transparent Argument of Knowledge) proof system used for archival proofs is already quantum-resistant because it relies solely on hash functions, not elliptic curves. Historical records anchored with STARK proofs remain secure against quantum attack.

**Historical re-anchoring.** Records signed with classical-only cryptography will be re-anchored with quantum-resistant proofs, providing a cryptographic bridge from the pre-quantum to the post-quantum era.

---

## Chapter 15: Troubleshooting

### 15.1 Common Issues and Solutions

This section addresses the most frequently encountered issues and provides guidance on resolution.

### 15.2 Authority Chain Verification Failed

**What you see:** An error indicating that authority chain verification failed when attempting a governed action.

**What it means:** The system could not verify a complete, valid chain of cryptographic signatures from your delegation back to the constitutional root.

**Common causes and solutions:**

- **Expired delegation.** Your delegation (or one of the intermediate delegations in the chain) has expired. Check the sunset calendar for your delegation's expiry date. If expired, request a new delegation from your delegator.

- **Revoked delegation.** A delegation in your chain has been revoked. Contact the delegator to understand why the revocation occurred and whether a new delegation will be issued.

- **Key rotation.** If a delegator rotated their cryptographic key, delegations signed with the old key may need to be re-issued. Contact your system administrator.

- **Chain depth exceeded.** Your authority chain has more than five links. This typically occurs with deep sub-delegation. The solution is to restructure the delegation chain so that it does not exceed the maximum depth.

- **Scope mismatch.** The action you are attempting falls outside the scope of your delegation. Review your delegation's scope descriptor and confirm that the action is within bounds.

### 15.3 Quorum Not Met

**What you see:** An error indicating that quorum was not met for a decision.

**What it means:** The decision did not receive enough eligible, independent votes to satisfy the quorum requirements.

**Common causes and solutions:**

- **Insufficient voters.** Not enough eligible participants cast votes. Ensure all eligible participants are notified and have adequate time to participate.

- **Independence not met.** Votes were cast but insufficient independent voters participated. The system requires a minimum number of voters who are independently verified. If voters share control or organizational affiliations, they may not count toward the independence threshold.

- **Recusals reduced the pool.** If multiple participants recused due to conflicts of interest, the eligible pool may have shrunk below the quorum threshold. Consider whether the decision can be restructured to reduce conflicts, or whether additional independent decision-makers should be added.

- **Disclosure not filed.** Participants who have not filed conflict disclosures cannot vote. Remind all participants to file disclosures (even negative ones) before the voting deadline.

### 15.4 Human Gate Required

**What you see:** An error indicating that a Human Gate is required and the action was blocked because the signer is an AI agent.

**What it means:** The decision class (Strategic, Constitutional, or Emergency) requires human approval, and an AI agent attempted to approve it.

**Solutions:**

- Ensure that the decision is reviewed and approved by a human with appropriate authority.
- If you believe the decision class is incorrect, it can be reclassified -- but reclassification itself may require governance approval depending on the circumstances.
- Review whether the AI agent's delegation scope and ceiling class are correctly configured.

### 15.5 Constitutional Constraint Violation

**What you see:** An error indicating that a constitutional constraint was violated.

**What it means:** The proposed action conflicts with one or more provisions in your organization's constitutional corpus. The system blocked the action to prevent a governance violation.

**Common causes and solutions:**

- **Monetary cap exceeded.** The financial commitment exceeds the limit authorized for the decision class or the actor's delegation. Either reduce the commitment to within the cap or escalate the decision to a class with a higher authorization level.

- **Supermajority not achieved.** The vote met simple majority but not the supermajority threshold required for this decision class. Additional affirmative votes are needed.

- **Clearance insufficient.** The actor does not have the clearance level required for this type of decision. Contact the system administrator about clearance assignments.

- **Custom constraint failed.** A custom constraint defined in the constitutional corpus was violated. Review the constraint definition and the specific violation details in the error message. If the constraint appears to be blocking a legitimate action, consult with the administrator who configured it.

### 15.6 Getting Help

If you encounter an issue that is not addressed in this chapter:

1. **Check the audit log.** The detailed audit trail often contains specific error messages and context that explain what went wrong.

2. **Review the governance dashboard.** The metrics dashboard may show systemic issues (e.g., elevated constraint violations across multiple users) that indicate a configuration problem rather than a user error.

3. **Contact your organization's administrator.** Most configuration issues (expired delegations, incorrect scopes, missing clearances) are resolved by the administrator who manages your organization's decision.forum instance.

4. **Contact support.** For platform issues (performance problems, unexpected errors, system behavior that does not match documentation), contact the EXOCHAIN support team.

---

## Appendix A: Glossary

**AEGIS** -- The collective name for the security and anti-Sybil analysis subsystems in decision.forum, encompassing independence verification, coordination detection, and behavioral analysis.

**Authority Chain** -- An ordered sequence of cryptographically signed delegation links from an acting entity back to the constitutional root of the organization. The chain is verified on every governed action.

**BCTS (Bounded Context Trust Scope)** -- The principle that every AI agent operates within a strictly defined context. The scope is declared at delegation time and enforced at runtime. Actions outside the scope are rejected.

**Bailment** -- A legal concept applied to authority delegation: the delegatee holds authority as a bailee (temporary custodian) rather than an owner, reflecting Axiom 1.

**Blake3** -- The cryptographic hash function used throughout decision.forum for content integrity, hash chaining, and Merkle tree construction. Blake3 produces 256-bit hashes and is designed for both security and performance.

**CGR Kernel (Constitutional Governance Runtime Kernel)** -- The immutable core of the governance engine that evaluates constitutional constraints, enforces invariants, and cannot be modified except through a constitutional amendment process.

**Challenge Object** -- A formal contestation record filed against a Decision Object. The Challenge Object specifies the grounds, evidence, and requested remedy. Filing a challenge automatically pauses the challenged decision.

**Clearance** -- A hierarchical access level assigned to actors and required by certain decision classes. Higher clearance levels grant access to more sensitive governance activities.

**Combinator** -- A composable logic element used to build complex governance rules from simpler primitives. For example, a quorum requirement and a supermajority requirement can be combined to create a compound constraint.

**Consent Gate** -- A verification checkpoint in the Syntaxis workflow that confirms explicit consent exists before allowing an action to proceed. Follows a default-deny model.

**Constitutional Corpus** -- The complete set of governance documents (Articles, Bylaws, Resolutions, Charters, Policies) encoded in decision.forum for a specific tenant, along with their machine-readable constraints.

**Crosscheck** -- The inter-party verification mechanism that validates independence claims by analyzing shared signing keys, shared attestation roots, shared control metadata, and behavioral coordination patterns.

**Decision Object** -- The fundamental governance primitive in decision.forum. A structured, cryptographically sealed record that captures every aspect of a governance decision: proposal, evidence, deliberation, votes, constitutional binding, and outcome.

**Delegation Matrix** -- A comprehensive mapping of all active authority delegations in an organization, showing who holds what authority, where it came from, and when it expires.

**Deterministic Map** -- An ordered map data structure (implemented as BTreeMap) that guarantees identical iteration order across all nodes, ensuring byte-level state determinism.

**DID (Decentralized Identifier)** -- A globally unique, cryptographically verifiable identifier for every actor in decision.forum. DIDs are not controlled by a central authority and are bound to the actor's cryptographic key pair.

**Dry-Run Mode** -- A simulation mode for constitutional amendments that evaluates the impact of a proposed change without modifying any state. Used for impact analysis before committing to governance changes.

**Ed25519** -- The elliptic curve digital signature algorithm used for identity binding, delegation signing, and action attribution. Provides 128-bit security against classical computers.

**Emergency Authority** -- Governance power that can be invoked to bypass normal procedures under time-critical circumstances. Subject to strict guardrails: scope limits, monetary caps, time limits (72 hours), and mandatory ratification within 7 days.

**Fiduciary** -- A person who holds a position of trust and is legally obligated to act in the best interest of another. In decision.forum, all authority holders are treated as fiduciaries.

**Fiduciary Defense Package** -- A self-contained, cryptographically sealed evidence package generated automatically when a decision reaches terminal status. Structured around the four prongs of the Business Judgment Rule.

**Governance Simulator** -- A tool for modeling the impact of proposed governance changes (constitutional amendments, delegation restructuring, process modifications) before implementing them. See Dry-Run Mode.

**Hash Chain** -- A sequence of data blocks where each block includes the cryptographic hash of the previous block, creating a tamper-evident chain. Used for audit logs and receipt chains.

**HLC (Hybrid Logical Clock)** -- A clock mechanism that combines wall-clock time with logical counters to provide monotonically increasing timestamps that respect causal ordering. Used throughout decision.forum for event ordering.

**Holon** -- A sandboxed execution context for AI agents within the governance engine. Each holon is subject to per-step kernel adjudication, and a denied action terminates the holon immediately.

**Human Gate** -- A constitutional constraint that requires a verified human (not an AI agent) to approve a decision. Applied to Strategic, Constitutional, and Emergency decision classes. Enforced cryptographically via signer type prefix bytes.

**Independence-Aware Counting** -- The quorum computation method that counts not just the number of votes but the number of independently verified voters. Votes from actors under shared control count as a single independent voice.

**Invariant** -- A governance property that must always hold true. Invariants are checked on every governed action and cannot be overridden. Examples: authority chains must be valid, audit logs must be continuous, the kernel must be immutable.

**Kernel** -- See CGR Kernel. The immutable judicial branch of the governance engine.

**MCP (Model Context Protocol)** -- The set of six rules that constrain all AI agent behavior in decision.forum: BCTS Scope, No Self-Escalation, Provenance Required, No Forgery, Distinguishable, and Consent Boundaries.

**Merkle DAG (Directed Acyclic Graph)** -- A graph data structure where nodes reference their parents by cryptographic hash, creating a tamper-evident, append-only structure for governance records.

**MMR (Merkle Mountain Range)** -- An append-only accumulator data structure that provides compact proofs of historical inclusion. Used to prove that a record existed at a specific point in time.

**PACE (Provenance, Accountability, Compliance, Evidence)** -- The four pillars of decision.forum's governance model, each representing a category of requirements that every governance action must satisfy.

**Post-Quantum** -- Cryptographic algorithms that are resistant to attack by quantum computers. decision.forum supports a migration path from classical (Ed25519) to post-quantum (ML-DSA/Dilithium) signatures.

**Provenance** -- The complete origin and history of a record, including who created it, when, under what authority, and what has happened to it since. Provenance is cryptographically verified in decision.forum.

**Quorum** -- The minimum number of eligible, independent participants required for a decision to be valid. Quorum in decision.forum is independence-aware, not merely a head count.

**Receipt Chain** -- The hash-linked sequence of cryptographic receipts generated by every action in decision.forum. Each receipt proves an action occurred and links to the previous receipt, creating a tamper-evident timeline.

**Recusal** -- The mandatory withdrawal of a participant from a decision due to a disqualifying conflict of interest. Enforced at the system level -- the system blocks the participant's vote, not merely advises recusal.

**Reversal** -- A governance action that voids a prior decision and creates an immutable linkage between the original decision and the reversal record. The original decision is never modified.

**Safe Harbor** -- A legal defense that protects a transaction from being voided. In the DGCL Section 144 context, it protects interested director transactions that have been properly disclosed and approved.

**Scope Narrowing** -- The principle that each link in a delegation chain can only narrow (never widen) the scope of authority. If A delegates "contracts up to $100K" to B, B cannot sub-delegate "contracts up to $200K" to C.

**SignerType** -- An enumeration embedded in every cryptographic signature that identifies whether the signer is Human (0x01 prefix) or AI (0x02 prefix). The prefix is part of the signed payload, making it unforgeable.

**SMT (Sparse Merkle Tree)** -- A Merkle tree over a large key space (2^256) that efficiently supports both inclusion proofs and non-inclusion proofs. Used for state membership verification.

**SNARK (Succinct Non-Interactive Argument of Knowledge)** -- A type of zero-knowledge proof that produces compact proofs verifiable in constant time. Used for per-decision proofs in decision.forum.

**STARK (Scalable Transparent Argument of Knowledge)** -- A type of zero-knowledge proof that requires no trusted setup and relies only on hash functions, making it quantum-resistant. Used for archival proofs.

**Succession** -- The protocol for transferring governance authority when a role holder becomes unavailable. Triggered by voluntary declaration, unresponsiveness exceeding a threshold, or activation by a designated activator.

**Sunset Calendar** -- A dashboard view showing all active delegations sorted by expiry date, with notification schedules for upcoming expirations.

**Sybil** -- An attack in which a single entity creates multiple fake identities to gain disproportionate influence. decision.forum's independence-aware quorum and crosscheck systems are designed to detect and neutralize Sybil attacks.

**TEE (Trusted Execution Environment)** -- A hardware-enforced secure enclave (such as Intel SGX or AMD SEV) that protects code and data even from the infrastructure operator. Used for sensitive governance computations.

**Temporal Binding** -- The practice of permanently associating a governance action with the constitutional version, timestamp, and authority chain that were in force at the time of the action. Prevents retroactive reinterpretation.

**TNC (Trust-Critical Non-Negotiable Control)** -- One of ten governance invariants that are always enforced, without exception: authority chain verification, human gate integrity, audit continuity, constitutional binding, delegation expiry, conflict disclosure, quorum enforcement, terminal immutability, AI ceiling, and ratification tracking.

**Trust-Critical** -- A designation for governance components that, if compromised, would undermine the entire trust model. Trust-critical components are subject to additional verification, immutability constraints, and audit requirements.

**Verification Gate** -- A checkpoint in the governance workflow where specific conditions must be satisfied before processing continues. Verification gates are synchronous -- the action cannot proceed until the gate passes.

**ZKML (Zero-Knowledge Machine Learning)** -- A proof system that binds an AI model's identity (architecture, weights, version) to its output, providing verifiable evidence that a specific model produced a specific result.

---

## Appendix B: Decision Lifecycle Quick Reference

### State Transition Diagram

```
 [Draft] --propose--> [Proposed] --review--> [Under Review]
    |                                              |
    |                                          evaluate
    |                                              |
    |                                              v
    +--withdraw--> [Withdrawn]             [Deliberating]
                                                |
                                            conclude
                                                |
                                                v
                                           [Pending]
                                          /    |     \
                                   approve   reject   expire
                                      |        |        |
                                      v        v        v
                                [Approved] [Rejected] [Expired]
                                      |
                                  challenge
                                      |
                                      v
                                 [Contested]
                                  /       \
                            sustain     overrule
                              |            |
                              v            v
                           [Void]    [Approved]*
                                     (reinstated)
```

*Additional transitions not shown for clarity:*
- Any pre-terminal state may transition to [Withdrawn] via withdrawal.
- Any pre-terminal state may transition to [Expired] if a deadline passes.
- [Approved] may transition to [Superseded] when replaced by a newer decision.
- [Ratification Required] is entered from Emergency decisions and transitions to [Approved] (if ratified) or [Void] (if deadline passes).
- [Escalated] is entered when conditions require higher-authority review and transitions back to [Under Review] at the higher level.

### All 14 States at a Glance

| # | State | Terminal? | Trigger | Can Be Challenged? |
|---|-------|-----------|---------|---------------------|
| 1 | Draft | No | Creation | No |
| 2 | Proposed | No | Proposer submits | No |
| 3 | Under Review | No | Review process begins | No |
| 4 | Deliberating | No | Review complete, deliberation opens | No |
| 5 | Pending | No | Deliberation complete, awaiting action | No |
| 6 | Approved | Yes | Sufficient votes, all checks pass | Yes |
| 7 | Rejected | Yes | Insufficient votes or explicit rejection | Yes |
| 8 | Contested | No | Challenge filed against approved/rejected decision | N/A |
| 9 | Void | Yes | Challenge sustained or constitutional violation found | No |
| 10 | Superseded | No | Newer decision replaces this one | No |
| 11 | Ratification Required | No | Emergency or policy decision needs ratification | No |
| 12 | Escalated | No | Higher authority review required | No |
| 13 | Withdrawn | Yes | Proposer withdraws before terminal state | No |
| 14 | Expired | Yes | Deadline passed without resolution | No |

---

## Appendix C: Authority Matrix Template

The following template illustrates a typical authority matrix for a corporation. Adapt it to your organization's structure and governance requirements.

### Board of Directors (Root Authority)

| Authority | Scope | Delegation Allowed | Monetary Cap | Decision Class |
|-----------|-------|--------------------|-------------|----------------|
| All corporate actions | Full corporate scope | Yes, with board resolution | Unlimited | Constitutional |
| Strategic direction | Business strategy | Yes, to CEO | Per resolution | Strategic |
| Officer appointment | All officer roles | No | N/A | Strategic |
| Bylaw amendment | Full bylaws | No | N/A | Constitutional |
| Dividend declaration | Shareholder distributions | No | Per resolution | Strategic |

### Audit Committee (Delegated from Board)

| Authority | Scope | Delegation Allowed | Monetary Cap | Decision Class |
|-----------|-------|--------------------|-------------|----------------|
| External auditor selection | Audit engagement | No | $500,000 | Operational |
| Internal audit oversight | Audit program | Yes, to Internal Audit Director | $100,000 | Operational |
| Financial reporting review | All financial statements | No | N/A | Operational |
| Whistleblower oversight | Investigation authority | Yes, to General Counsel | $250,000 | Operational |

### CEO (Delegated from Board)

| Authority | Scope | Delegation Allowed | Monetary Cap | Decision Class |
|-----------|-------|--------------------|-------------|----------------|
| Operational management | Day-to-day operations | Yes, to direct reports | $1,000,000 | Operational |
| Contract approval | Business contracts | Yes, to SVPs | $500,000 | Operational |
| Personnel decisions | Hiring, termination | Yes, to VPs | $200,000 | Routine |
| Vendor selection | Non-strategic vendors | Yes, to department heads | $100,000 | Routine |

### CFO (Delegated from CEO)

| Authority | Scope | Delegation Allowed | Monetary Cap | Decision Class |
|-----------|-------|--------------------|-------------|----------------|
| Financial operations | Treasury, accounting | Yes, to Finance Directors | $500,000 | Operational |
| Budget approval | Operating budgets | Yes, to department heads | $250,000 | Operational |
| Tax filing | Tax compliance | No | N/A | Operational |
| Investment management | Short-term investments | No | $5,000,000 | Operational |

### AI Agent: Invoice Processor (Delegated from CFO)

| Authority | Scope | Delegation Allowed | Monetary Cap | Decision Class Ceiling |
|-----------|-------|--------------------|-------------|----------------------|
| Invoice approval | Recurring vendor invoices matching purchase orders | No | $10,000 | Routine |
| Payment scheduling | Approved invoices only | No | $10,000 | Routine |

*Note: AI delegation expires in 90 days. Human Gate required for any action above Routine class. AI cannot approve invoices that do not match an existing purchase order.*

---

## Appendix D: Constitutional Template

The following template provides a starting structure for encoding your organization's governance framework in decision.forum. Each section should be customized to reflect your actual governance documents.

### Article I: Purpose and Authority

```
Document: Articles of Incorporation
Precedence: Level 5 (Articles)

Section 1.1 -- Corporate Purpose
  The corporation is organized for the purpose of [description].

Section 1.2 -- Governing Authority
  The business and affairs of the corporation shall be managed by
  its Board of Directors, which holds the constitutional root
  authority for all governance actions.

Constraints:
  - Type: RequireHumanGate
    Applies to: Constitutional class decisions
    Failure action: Block
    Description: "All amendments to Articles require human approval"
```

### Article II: Board Composition and Quorum

```
Document: Bylaws
Precedence: Level 4 (Bylaws)

Section 2.1 -- Board Size
  The Board shall consist of no fewer than 5 and no more than 15
  directors.

Section 2.2 -- Quorum
  A majority of the total number of directors then in office shall
  constitute a quorum for the transaction of business.

Section 2.3 -- Independence
  At least a majority of directors must be independent as defined
  by applicable listing standards.

Constraints:
  - Type: RequireQuorum
    Threshold: 0.51
    Independence minimum: 3
    Applies to: Strategic, Constitutional class decisions
    Failure action: Block
    Description: "Board quorum requires majority with at least 3
                  independent directors"
```

### Article III: Delegation of Authority

```
Document: Bylaws
Precedence: Level 4 (Bylaws)

Section 3.1 -- Delegation Framework
  The Board may delegate authority to committees, officers, and
  agents subject to the following constraints:
  (a) All delegations must have a defined expiry not exceeding
      12 months.
  (b) Scope may only narrow through successive delegations.
  (c) Sub-delegation is permitted only when explicitly authorized.
  (d) AI agents may not hold delegations exceeding 90 days or
      above the Operational decision class.

Constraints:
  - Type: Custom
    Predicate: delegation.expires_at <= delegation.created_at + 12months
    Failure action: Block
    Description: "Maximum delegation duration is 12 months"

  - Type: Custom
    Predicate: if signer_type == AI then delegation.expires_at <=
              delegation.created_at + 90days
    Failure action: Block
    Description: "AI delegation maximum is 90 days"
```

### Article IV: Decision Classes

```
Document: Board Resolution BR-2026-001
Precedence: Level 3 (Resolutions)

Section 4.1 -- Classification
  Routine: day-to-day actions within policy, < $50,000
  Operational: actions affecting ongoing operations, < $1,000,000
  Strategic: direction-setting actions, acquisitions, > $1,000,000
  Constitutional: governance framework changes
  Emergency: time-critical response to threats

Section 4.2 -- Approval Requirements
  Routine: Simple majority, standard quorum
  Operational: Simple majority, enhanced quorum, conflict disclosure
  Strategic: Two-thirds supermajority, Human Gate, full board
  Constitutional: Three-quarters supermajority, Human Gate,
                  full board, 30-day notice
  Emergency: Authorized role, 72-hour TTL, mandatory ratification

Constraints:
  - Type: RequireSupermajority
    Threshold: 0.67
    Applies to: Strategic class decisions
    Failure action: Block

  - Type: RequireSupermajority
    Threshold: 0.75
    Applies to: Constitutional class decisions
    Failure action: Block

  - Type: RequireHumanGate
    Applies to: Strategic, Constitutional, Emergency class decisions
    Failure action: Block
```

### Article V: Conflict of Interest

```
Document: Board Policy GOV-POL-003
Precedence: Level 1 (Policies)

Section 5.1 -- Mandatory Disclosure
  All participants must file a conflict-of-interest disclosure
  before participating in any Operational or higher-class decision.

Section 5.2 -- DGCL Section 144 Safe Harbor
  Interested transactions must satisfy at least one safe-harbor
  path before receiving approval.

Constraints:
  - Type: Custom
    Predicate: actor.has_filed_disclosure(decision_id) == true
    Applies to: Operational, Strategic, Constitutional decisions
    Failure action: Block
    Description: "Conflict disclosure required before participation"
```

---

## Index

**A**

- Accountability actions, [Chapter 8](#chapter-8-accountability)
- AI agents, [Chapter 10](#chapter-10-ai-agents-in-your-governance)
- AI ceiling, [Section 10.2](#102-the-delegation-ceiling)
- AI delegation maximum (90 days), [Section 10.2](#102-the-delegation-ceiling)
- Alternatives considered, [Section 5.2](#52-attaching-evidence-and-deliberation-materials)
- Amendment process, [Section 3.4](#34-amending-your-constitution)
- Approved (state), [Section 2.2](#22-the-fourteen-states-of-a-decision)
- Audit log, tamper-evident, [Section 14.4](#144-the-tamper-evident-audit-log)
- Authority chain, [Section 4.1](#41-understanding-the-authority-matrix)
- Authority matrix, [Section 4.1](#41-understanding-the-authority-matrix), [Appendix C](#appendix-c-authority-matrix-template)
- Authority matrix template, [Appendix C](#appendix-c-authority-matrix-template)

**B**

- BCTS (Bounded Context Trust Scope), [Section 10.5](#105-the-six-mcp-enforcement-rules)
- Blake3, [Section 14.3](#143-cryptographic-guarantees)
- Business Judgment Rule, [Section 11.4](#114-fiduciary-defense-packages)
- Bylaws (precedence level), [Section 3.2](#32-document-hierarchy)

**C**

- Censure, [Section 8.1](#81-accountability-actions)
- Chain depth maximum, [Section 4.3](#43-sub-delegation)
- Chain of custody, [Section 11.2](#112-chain-of-custody)
- Challenge grounds, [Section 6.1](#61-your-right-to-challenge)
- Challenge Object, [Section 6.2](#62-filing-a-formal-contestation)
- Circular delegation, [Section 4.3](#43-sub-delegation)
- Clearance, [Section 3.3](#33-how-constitutional-constraints-are-enforced-in-real-time)
- Conflict disclosure, [Section 9.1](#91-disclosure-requirements)
- Conflict of interest, [Chapter 9](#chapter-9-conflict-of-interest-management)
- Consent gate, [Section 14.2](#142-zero-trust-architecture)
- Constitutional amendment, [Section 3.4](#34-amending-your-constitution)
- Constitutional constraints, [Section 3.3](#33-how-constitutional-constraints-are-enforced-in-real-time)
- Constitutional corpus, [Section 3.1](#31-what-is-a-constitution-in-decisionforum)
- Constitutional template, [Appendix D](#appendix-d-constitutional-template)
- Contested (state), [Section 2.2](#22-the-fourteen-states-of-a-decision)
- Crosscheck, [Section 5.3](#53-quorum)
- Cryptographic guarantees, [Section 14.3](#143-cryptographic-guarantees)

**D**

- Decision classes, [Section 2.3](#23-decision-classes)
- Decision lifecycle, [Section 2.2](#22-the-fourteen-states-of-a-decision), [Appendix B](#appendix-b-decision-lifecycle-quick-reference)
- Decision Object, [Section 2.1](#21-what-is-a-decision-object)
- Degraded governance mode, [Section 5.3](#53-quorum)
- Delegation, [Section 4.2](#42-how-delegation-works)
- Delegation ceiling, [Section 10.2](#102-the-delegation-ceiling)
- DGCL Section 144, [Section 9.4](#94-dgcl-section-144-safe-harbor)
- DID (Decentralized Identifier), [Section 1.4](#14-quick-start-your-first-decision-in-five-minutes)
- Disclosure requirements, [Section 9.1](#91-disclosure-requirements)
- Dry-run mode, [Section 3.5](#35-dry-run-mode-test-before-you-commit)
- Due process, [Section 8.2](#82-due-process-requirements)

**E**

- E-discovery, [Section 11.3](#113-e-discovery-readiness)
- Ed25519, [Section 14.3](#143-cryptographic-guarantees)
- Emergency authority, [Chapter 7](#chapter-7-emergency-governance)
- Emergency guardrails, [Section 7.2](#72-the-guardrails)
- Evidence completeness metric, [Section 12.4](#124-evidence-completeness)
- Expired (state), [Section 2.2](#22-the-fourteen-states-of-a-decision)

**F**

- Federal Rules of Evidence, [Section 11.1](#111-self-authenticating-business-records)
- Fiduciary defense package, [Section 11.4](#114-fiduciary-defense-packages)
- FRE 803(6), [Section 11.1](#111-self-authenticating-business-records)
- FRE 902(11), [Section 11.1](#111-self-authenticating-business-records)
- Frequency monitoring (emergencies), [Section 7.4](#74-frequency-monitoring)

**G**

- Glossary, [Appendix A](#appendix-a-glossary)
- Governance dashboard, [Chapter 12](#chapter-12-reporting-and-metrics)
- Governance metrics, [Section 12.1](#121-the-governance-metrics-dashboard)

**H**

- Hash chain, [Section 2.4](#24-the-receipt-chain)
- Human Gate, [Section 5.6](#56-the-human-gate)
- Hybrid Logical Clock (HLC), [Section 14.3](#143-cryptographic-guarantees)

**I**

- Immutability (terminal decisions), [Section 2.1](#21-what-is-a-decision-object)
- Independence-aware quorum, [Section 5.3](#53-quorum)
- Information Package, [Section 5.2](#52-attaching-evidence-and-deliberation-materials)

**K**

- Key management lifecycle, [Section 13.2](#132-managing-users-and-roles)

**L**

- Litigation hold, [Section 11.5](#115-records-retention)

**M**

- MCP rules, [Section 10.5](#105-the-six-mcp-enforcement-rules)
- Merkle DAG, [Section 14.3](#143-cryptographic-guarantees)
- Merkle root, [Section 2.1](#21-what-is-a-decision-object)
- Metrics interpretation, [Section 12.5](#125-how-to-interpret-the-metrics)
- Multi-tenant isolation, [Section 13.6](#136-multi-tenant-isolation)

**N**

- Notification preferences, [Section 13.5](#135-customizing-notification-preferences)

**P**

- Pause Order, [Section 6.3](#63-what-happens-when-a-decision-is-challenged)
- Post-quantum readiness, [Section 14.5](#145-post-quantum-readiness)
- Precedence hierarchy, [Section 3.2](#32-document-hierarchy)
- Privilege compartmentalization, [Section 11.3](#113-e-discovery-readiness)
- Provenance, [Section 2.4](#24-the-receipt-chain)

**Q**

- Quick start, [Section 1.4](#14-quick-start-your-first-decision-in-five-minutes)
- Quorum, [Section 5.3](#53-quorum)
- Quorum not met (troubleshooting), [Section 15.3](#153-quorum-not-met)

**R**

- Ratification, [Section 7.3](#73-mandatory-ratification)
- Receipt chain, [Section 2.4](#24-the-receipt-chain)
- Recall, [Section 8.1](#81-accountability-actions)
- Records retention, [Section 11.5](#115-records-retention)
- Recusal, [Section 9.2](#92-recusal)
- Reversal, [Section 6.5](#65-reversals)
- Revocation (authority), [Section 4.5](#45-revoking-authority)
- Revocation latency metric, [Section 12.3](#123-revocation-latency)
- Roles, [Section 13.2](#132-managing-users-and-roles)

**S**

- Safe harbor (DGCL 144), [Section 9.4](#94-dgcl-section-144-safe-harbor)
- Scope narrowing, [Section 4.2](#42-how-delegation-works)
- Section 144 Certificate, [Section 9.4](#94-dgcl-section-144-safe-harbor)
- Section 144 Register, [Section 9.4](#94-dgcl-section-144-safe-harbor)
- Self-authenticating records, [Section 11.1](#111-self-authenticating-business-records)
- Signer type prefix bytes, [Section 10.4](#104-distinguishing-ai-actions-from-human-actions)
- Spoliation risk alert, [Section 11.5](#115-records-retention)
- Standing Conflict Register, [Section 9.1](#91-disclosure-requirements)
- Sub-delegation, [Section 4.3](#43-sub-delegation)
- Succession, [Appendix A](#appendix-a-glossary)
- Sunset calendar, [Section 4.4](#44-the-sunset-calendar)
- Supermajority, [Section 3.3](#33-how-constitutional-constraints-are-enforced-in-real-time)
- Suspension, [Section 8.1](#81-accountability-actions)
- Syntaxis workflow, [Section 5.1](#51-step-by-step-creating-a-new-decision)

**T**

- Tamper-evident audit log, [Section 14.4](#144-the-tamper-evident-audit-log)
- TEE (Trusted Execution Environment), [Section 14.1](#141-how-your-data-is-protected)
- TNC (Trust-Critical Non-Negotiable Controls), [Appendix A](#appendix-a-glossary)
- Troubleshooting, [Chapter 15](#chapter-15-troubleshooting)
- Trust accumulation, [Section 1.3](#13-the-promise)

**V**

- Verification gate, [Section 14.2](#142-zero-trust-architecture)
- Void (state), [Section 2.2](#22-the-fourteen-states-of-a-decision)
- Voting, [Section 5.4](#54-voting)

**W**

- Withdrawn (state), [Section 2.2](#22-the-fourteen-states-of-a-decision)

**Z**

- Zero-trust architecture, [Section 14.2](#142-zero-trust-architecture)
- ZKML, [Appendix A](#appendix-a-glossary)

---

*End of Document*

*decision.forum User Manual v2.0.0 -- Copyright 2026 EXOCHAIN Foundation. All rights reserved.*

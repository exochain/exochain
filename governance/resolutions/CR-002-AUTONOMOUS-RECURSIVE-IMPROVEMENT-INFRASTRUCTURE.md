---
title: "Council Resolution CR-002: Autonomous Recursive Self-Improvement Governance and Deployment"
status: draft
created: 2026-04-25
tags: [council-resolution, self-improvement, ai-council, ai-irb, deployment, railway]
links:
  - "[[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]]"
  - "[[quality_gates]]"
  - "[[threat_matrix]]"
---

# Resolution of the EXOCHAIN Council on Autonomous Recursive Self-Improvement

**Resolution ID:** CR-002  
**Status:** DRAFT — Pending Council Ratification  
**Date:** 2026-04-25

---

## Section 1. Purpose

This Resolution defines a **code-grounded** constitutional plan for autonomous recursive improvement with explicit escalation:

1. 5x5 AI-Council adjudication,
2. AI-IRB review for elevated risk,
3. human IRB Chair override (Bob Stewart) as final authority.

It also establishes the initial distributed deployment model across local and Railway environments while preserving deterministic behavior and constitutional safeguards.

---

## Section 2. Repository-Verified Baseline (Authoritative)

The following execution surfaces are confirmed in this repository and SHALL be treated as source-of-truth for implementation planning:

### 2.1 Governance kernel and invariant engine

- `crates/exo-gatekeeper/src/invariants.rs` defines 8 constitutional invariants:
  - SeparationOfPowers
  - ConsentRequired
  - NoSelfGrant
  - HumanOverride
  - KernelImmutability
  - AuthorityChainValid
  - QuorumLegitimate
  - ProvenanceVerifiable

### 2.2 Decision and human-gate controls

- `crates/decision-forum/src/human_gate.rs` enforces human approval for strategic/constitutional classes and AI delegation ceilings.
- `crates/decision-forum/src/lib.rs` exposes governance modules for contestation, quorum, emergency, self-governance, and TNC enforcement.

### 2.3 ExoForge automation substrate

- `exoforge/bin/` contains autonomous workflow CLIs:
  - `exoforge-triage`
  - `exoforge-council-review`
  - `exoforge-implement`
  - `exoforge-validate`
  - `exoforge-monitor`
- `exoforge/lib/panels.js` defines five standing review panels (Governance, Legal, Architecture, Security, Operations).

### 2.4 Control plane and tenant exemplars

- `command-base/` exists as a Node/SQLite control plane with governance routes and receipts.
- Tenant exemplar apps currently present under `demo/apps/` include:
  - `crosschecked`
  - `vitallock`
  - `livesafe`
- Additional tenant brands (`exoforge.ai`, `decision.forum`, `commandbase.ai`) are treated as product domains mapped to existing repository modules and services.

### 2.5 Deployment primitives

- `railway.json` provides Railway deployment wiring and health checks.
- `docker-compose.multinode.yml` defines a 3-node local validator smoke-test topology.

No implementation claim in this Resolution may contradict these observed code surfaces.

---

## Section 3. Scope

This policy governs recursive improvement for the following tenant constellation and control surfaces:

- `exoforge.ai`
- `decision.forum`
- `crosschecked.ai`
- `vitallock.com`
- `livesafe.ai`
- `commandbase.ai` (control plane; repo path presently `command-base/`)

Each tenant SHALL be treated as an `exo-tenant` governed workload with tenant-scoped policies, secrets, and rollback controls.

---

## Section 4. Constitutional Guardrails (Binding)

All recursive-improvement workflows SHALL satisfy:

1. **Absolute Determinism** in governance logic and adjudication.
2. **No Unsafe Code** and no bypass of typed error surfaces.
3. **All Eight Constitutional Invariants** enforced pre/post action.
4. **No direct production mutation** without Council evidence and policy gates.
5. **HumanOverride preservation** at every escalation tier.

Any workflow that cannot produce verifiable evidence artifacts SHALL be rejected.

---

## Section 5. Governance Loop Architecture

### 5.1 Escalation loop

```text
Signal Intake
  -> Triage + Evidence Bundle
    -> 5x5 AI-Council Deliberation
      -> (low/medium risk) Constitutional Gate + Merge Queue
      -> (high/novel risk) AI-IRB Review
         -> (critical/contested) IRB Chair Decision (Bob Stewart)
            -> Controlled Rollout (Railway/local)
               -> Telemetry + Outcome Audit
                  -> Learning Capture -> Next Iteration
```

### 5.2 Council matrix definition

Every change SHALL be evaluated by the 5 panels and artifact properties:

- Panels: Governance, Legal, Architecture, Security, Operations
- Properties: Storable, Diffable, Transferable, Auditable, Contestable

Approval requires explicit evidence for all required panel/property intersections.

### 5.3 Escalation criteria

Escalate to AI-IRB when any condition is true:

- impacts HumanOverride, ConsentRequired, or NoSelfGrant pathways,
- touches identity/authority/consent/escalation modules,
- alters cross-tenant privilege boundaries,
- raises blast radius beyond one tenant,
- expands autonomy outside ratified policy.

Escalate to IRB Chair (Bob Stewart) when:

- AI-IRB deadlocks,
- critical risk threshold is exceeded,
- constitutional interpretation conflicts,
- emergency intervention is required.

---

## Section 6. Distributed Deployment Blueprint (Railway + Local)

### 6.1 Environment model

- **Local Sovereign Stack:** deterministic replay and integration testing.
- **Railway Staging:** externally reachable pre-production validation.
- **Railway Production:** tenant-isolated deployment with immutable artifacts.

### 6.2 Plane mapping

1. **Control Plane (`command-base/`)**
   - governance orchestration,
   - escalation state tracking,
   - policy-gate operational dashboard.

2. **Governance Plane (`crates/decision-forum`, `web/`)**
   - proposal lifecycle,
   - quorum and contestation,
   - constitutional records.

3. **Execution Plane (`exoforge/`, runtime services)**
   - triage, implementation, validation automation,
   - tenant-targeted release actions.

4. **Evidence Plane (`exo-proofs`, receipts, audit routes)**
   - provenance bundles,
   - chain verification,
   - post-deploy accountability artifacts.

### 6.3 Release gates (non-negotiable)

Before Railway production rollout:

- `cargo build --workspace --release`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --all -- --check`
- `cargo doc --workspace --no-deps`
- `./tools/cross-impl-test/compare.sh`
- council evidence bundle attached to release record

---

## Section 7. Safe Self-Improvement Operating Pattern

### 7.1 Required stages

1. Observe
2. Propose
3. Deliberate
4. Adjudicate
5. Implement
6. Verify
7. Escalate
8. Deploy
9. Retrospect

### 7.2 Required artifacts per iteration

- constitutional requirement mapping
- threat delta statement
- test and quality-gate outputs
- provenance bundle (`who/what/when/why`)
- escalation record (if triggered)
- post-deploy outcome memo

### 7.3 Explicit prohibitions

- No autonomous self-merging without approved governance decision.
- No autonomous privilege self-grant.
- No bypass of human gate for strategic or constitutional decisions.
- No tenant boundary crossing without explicit policy and evidence.

---

## Section 8. Decision Rights

- 5x5 AI-Council may approve low/medium-risk changes within ratified policy.
- AI-IRB may approve/reject high-risk proposals and define guardrails.
- IRB Chair (Bob Stewart) retains final emergency override authority.
- Any constitutional challenge renders affected action pause-eligible.

---

## Section 9. 90-Day Delivery Plan (Code-First)

### Phase 1 (Days 1–30): Governance wiring

- Integrate ExoForge panel output into evidence schema.
- Bind decision-class and human-gate checks to escalation policy.
- Register mandatory artifact checklist in review workflow.

### Phase 2 (Days 31–60): Deployment wiring

- Define Railway service group topology per tenant boundary.
- Add local-to-Railway reproducibility and healthcheck parity checks.
- Establish immutable artifact promotion flow (local -> staging -> prod).

### Phase 3 (Days 61–90): Recursive optimization

- Add constitutional KPI dashboard (latency, rejection causes, override rates).
- Allow safe auto-remediation only for pre-approved low-risk defect classes.
- Propose ratification amendments from observed operational evidence.

---

## Section 10. Ratification Effect

Upon ratification, CR-002 becomes binding policy for autonomous recursive improvement and distributed deployment governance in EXOCHAIN until amended or superseded by later Council action.

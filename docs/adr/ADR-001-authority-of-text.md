---
title: "ADR-001: Authority of Text — Normative Specification Hierarchy"
status: accepted
created: 2026-03-30
authors: [Governance/Constitutional Engineer]
tags: [adr, normative, aegis, sybil, spec-harmonization]
mandated-by: "CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY §3 (Immediate Order)"
---

# ADR-001: Authority of Text — Normative Specification Hierarchy

## Decision

EXOCHAIN adopts a four-tier document hierarchy. In any conflict the higher tier governs. Where a lower-tier document adds implementation detail without conflicting, that detail remains controlling engineering guidance.

| Rank | Document | Filename / Identifier | Role |
|------|----------|-----------------------|------|
| **1** | Council Resolutions | `governance/resolutions/CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY.md` (and any future ratified resolutions) | Highest constitutional authority |
| **2** | EXOCHAIN Specification v2.2 | `EXOCHAIN_Specification_v2.2.pdf` | **Normative specification** — the reference all implementation code MUST cite |
| **3** | EXOCHAIN Fabric Platform v2.1 | `EXOCHAIN-FABRIC-PLATFORM.md` | **Engineering-operational elaboration** — authoritative for implementation detail that does not conflict with tiers 1–2 |
| **4** | Repository governance artifacts | `governance/quality_gates.md`, `docs/architecture/THREAT-MODEL.md`, `docs/architecture/ARCHITECTURE.md`, `docs/proofs/CONSTITUTIONAL-PROOFS.md`, traceability matrices | Implementation-control documents; no superior constitutional meaning |

## Status of EXOCHAIN-FABRIC-PLATFORM.md

`EXOCHAIN-FABRIC-PLATFORM.md` version 2.1 labels itself *"Authoritative Source of Truth"* and states it *"Supersedes all prior EXOCHAIN documentation."* That self-description was correct before the ratification of CR-001. **After CR-001 it is incorrect as a constitutional claim.** The document is retained as the authoritative engineering elaboration (tier 3) but is NOT a normative constitutional source. Code comments and documentation MUST NOT cite it as the normative authority for AEGIS, SYBIL, or invariant definitions.

## Artifacts That Inherit Authority from the Normative Spec (Tier 2)

All implementation crates claim conformance to the v2.2 specification. The following inherit authority from it:

| Artifact | Kind | Notes |
|----------|------|-------|
| `crates/exo-gatekeeper/` | Judicial branch — CGR Kernel, invariants, combinators | Eight constitutional invariants implemented in `src/invariants.rs` |
| `crates/exo-governance/` | Legislative branch — quorum, clearance, challenge, deliberation | AEGIS governance surfaces |
| `crates/exo-escalation/` | Operational nervous system — Sybil adjudication pipeline | 7-stage pipeline per CR-001 §8.6 |
| `crates/exo-legal/` | Legal compliance layer | Regulatory surfaces |
| `crates/decision-forum/` | Application governance layer | Wraps kernel + governance |
| `crates/exo-core/` | Shared types, HLC, events | `HolonLifecycleEvent` variants defined per spec §3A |
| `crates/exo-dag/` | BFT DAG, checkpoints, HLC append | Checkpoint preimage per spec §9.4 |
| `docs/architecture/THREAT-MODEL.md` | Threat taxonomy | Normative threat family per CR-001 §8.2 |
| `docs/proofs/CONSTITUTIONAL-PROOFS.md` | Formal proofs | Proof of invariant properties |
| `governance/quality_gates.md` | CI quality gates | Release-blocking gates per CR-001 §8.8 |

## AEGIS Clauses — Status

AEGIS = *Autonomous Entity Governance & Invariant System* (canonical definition: CR-001 §4).

| Clause | Location | Status |
|--------|----------|--------|
| Canonical constitutional definition of AEGIS | CR-001 §4 | **Normative** (tier 1) |
| AEGIS as constitutional framework overview | `EXOCHAIN-FABRIC-PLATFORM.md` §3A.1 | **Explanatory** (tier 3) |
| Separation of Powers model (Legislative / Executive / Judicial) | Platform §3A.2; Architecture §2 | **Explanatory** — implementation detail for normative CR-001 §6 |
| Constitutional governance flow diagram | Platform §3A.2.4 | **Explanatory** |
| CGR Kernel architecture and INV-001 through INV-008 invariants | Platform §3A.3; `exo-gatekeeper/src/invariants.rs` | **Normative in code** (`invariants.rs` is authoritative implementation) |
| Constitutional Amendment Process | Platform §3A.3.2 | **Pending** — process described, not yet tested end-to-end (CR-001 §8 gap) |
| AEGIS surface mapping (crate assignments) | CR-001 §7 | **Normative** (tier 1) |
| INV-008 kernel + registry immutability | Platform §2.1 refinement; `exo-gatekeeper/src/invariants.rs` | **Normative in code** |
| NIST AI RMF alignment | `NIST_AI_RMF_MAPPING.toml` | **Explanatory** |

## SYBIL Clauses — Status

SYBIL = adversarial/synthetic condition manufacturing counterfeit plurality (canonical definition: CR-001 §5).

| Clause | Location | Status |
|--------|----------|--------|
| Canonical constitutional definition of SYBIL | CR-001 §5 | **Normative** (tier 1) |
| Six Sybil sub-threat family (Identity, Review, Quorum, Delegation, Mesh, Synthetic-Opinion) | `docs/architecture/THREAT-MODEL.md` §Sybil Family (Threats 1–6) | **Normative** — aligned with CR-001 §8.2 |
| Anti-Sybil architecture overview | `docs/architecture/ARCHITECTURE.md` §6 | **Explanatory** |
| Independence-aware quorum computation | `exo-governance/src/quorum.rs` | **Normative in code** |
| `OpinionProvenance` enforcement | `exo-governance/src/crosscheck.rs` | **Normative in code** |
| Sybil adjudication 7-stage escalation path | `exo-escalation/src/escalation.rs` | **Normative in code** |
| Provenance-tagged review opinions | `exo-governance/src/crosscheck.rs` | **Normative in code** |
| Challenge path for Sybil allegations | `exo-governance/src/challenge.rs` | **Normative in code** |
| Sybil-related threat mitigations in Threat Model | `docs/architecture/THREAT-MODEL.md` | **Normative** |
| No-admin bypass prohibition | CR-001 §8.9; pending WO-009 | **Pending** — [APE-49](/APE/issues/APE-49) |
| Clearance independence-awareness | CR-001 §8.4; pending WO-004 | **Pending** — [APE-44](/APE/issues/APE-44) |
| Formal challenge path hardening | CR-001 §8.5; pending WO-005 | **Pending** — [APE-45](/APE/issues/APE-45) |
| Sybil escalation pathway (named path) | CR-001 §8.6; pending WO-006 | **Pending** — [APE-46](/APE/issues/APE-46) |

## Definitional Drift Found — v2.2 vs v2.1

| Location | Drift | Required Fix |
|----------|-------|--------------|
| `EXOCHAIN-FABRIC-PLATFORM.md` header | Self-describes as "Authoritative Source of Truth" and "Supersedes all prior documentation" | Acknowledged and resolved by this ADR; no file edit required unless platform doc is republished |
| `crates/exo-core/src/events.rs` lines 142, 208 | Cites `"spec v2.1 Section 3A"` | Must cite v2.2 spec §3A (Holon lifecycle); reference `EXOCHAIN_Specification_v2.2.pdf` |
| `crates/exo-core/src/event.rs` line 81 | Cites `"spec v2.1 Section 3A"` | Same fix as above |
| `crates/exo-dag/src/checkpoint.rs` line 50 | Cites `"Spec 9.4"` with no version | Must cite `EXOCHAIN_Specification_v2.2.pdf §9.4` |
| `crates/exo-dag/src/append.rs` lines 8, 31 | Unversioned `"normative"` reference | Must cite `EXOCHAIN_Specification_v2.2.pdf` |
| Five owned crates (exo-gatekeeper, exo-governance, exo-escalation, exo-legal, decision-forum) | No inline spec version citations found | **No drift** — these crates implement invariants from `invariants.rs` without pinning to a platform version |

> **Status of code-level drift:** `exo-core` and `exo-dag` contain references to v2.1. These are owned by the Architecture crate owner. This ADR records the canonical fix: update all inline spec citations to `EXOCHAIN_Specification_v2.2.pdf §<section>`. Cross-crate edits are tracked in [APE-41](/APE/issues/APE-41).

## Harmonization Instructions for Crate Authors

When writing or reviewing code comments that cite the specification:

```
// Per EXOCHAIN Specification v2.2 §<section>
```

Do **not** write:
```
// Per spec v2.1 Section X     ← wrong version
// Per Spec 9.4                ← unversioned, ambiguous
// Per EXOCHAIN-FABRIC-PLATFORM.md  ← tier-3 source, not normative
```

For AEGIS or SYBIL constitutional definitions, cite the Council Resolution:
```
// Per CR-001 §4 (AEGIS) / §5 (SYBIL)
```

## Consequence

This ADR satisfies CR-001 §3 Immediate Order. It does not supersede the platform document; it subordinates it within the hierarchy. Future specification updates must increment the version in `EXOCHAIN_Specification_v2.2.pdf` (or a successor file) and update this ADR's tier-2 entry.

---

*Authored by the Governance/Constitutional Engineer under [APE-41](/APE/issues/APE-41) (WO-001: Spec Harmonization).*
*Mandated by [CR-001](/APE/issues/APE-39) §3 Immediate Order.*

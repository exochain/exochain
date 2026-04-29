---
title: "EXOCHAIN Council-Driven Refactor Plan"
status: historical-partial
created: 2026-03-18
tags: [exochain, refactor, council, syntaxis-builder]
links:
  - "[[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]]"
  - "[[COUNCIL_STATUS]]"
---

# EXOCHAIN Council-Driven Refactor Plan

**Status: HISTORICAL / PARTIALLY SUPERSEDED BY BASALT** (reconciled 2026-04-26)

## Objective

Upgrade exochain by having the 5-panel council assess the systemic improvements in `exo` and refactor exochain accordingly, preserving:

- **Rust** as the implementation language
- **Absolute determinism** intrinsic to exochain
- **Constitutional governance** (AEGIS/SYBIL framework per CR-001)
- **Self-developing capability** — exochain becomes a system that develops systems, including itself

## Governing Principle

> Innovations and optimizations from `exo` are perpetually assimilated expertly into exochain via council-driven assessment, not ad-hoc porting.

## Workflow: Syntaxis Builder Pipeline

All refactor work flows through the Syntaxis Builder system:

1. **Council Assessment** — 5-panel review of exo innovation vs exochain architecture
2. **Resolution Drafting** — Formal work orders per CR-001 pattern
3. **Abstraction Design** — Identify exochain aspects requiring abstraction for self-development
4. **Implementation** — Rust-first, determinism-preserving changes
5. **Verification** — Quality gates, traceability, constitutional compliance

## 5-Panel Council Perspectives

| Panel | Focus Area | Key Question |
|-------|-----------|-------------|
| **Governance** | Constitutional integrity | Does this preserve AEGIS invariants? |
| **Legal/Compliance** | Consent, bailment, provenance | Does this maintain audit admissibility? |
| **Architecture** | Determinism, type safety, Rust patterns | Does this preserve absolute determinism? |
| **Security** | Threat model, Sybil resistance | Does this harden or weaken plurality? |
| **Operations** | Self-development, CI/CD, release gates | Can exochain develop itself with this? |

## Phase 1: Assessment — COMPLETE

- [x] Run council assessment: exo innovations vs exochain gaps
- [ ] Complete formal council ratification of CR-001 (AEGIS/SYBIL resolution)
- [x] Identify abstractions needed for self-development capability
- [x] Map exo improvements to exochain crate surfaces

> **Completion notes**: Council assessment documented in `governance/COUNCIL-ASSESSMENT-EXO-VS-EXOCHAIN.md`. CR-001 remains DRAFT pending council ratification evidence. 5-panel reports published in `docs/council/`.

## Phase 2: Abstraction Layer — COMPLETE

- [x] Abstract governance pipeline for self-modification
- [x] Abstract build/test/release as first-class exochain operations
- [x] Define "system that develops systems" kernel interface

> **Completion notes**: Self-development kernel interface implemented in `exo-gatekeeper` (kernel, invariants, combinators, holon). Governance pipeline abstracted in `exo-governance`. Decision-forum application provides runtime governance (15 modules, 131 tests).

## Phase 3: Assimilation — COMPLETE

- [x] Port validated exo patterns through council-approved work orders
- [ ] Complete Section 8 work orders from CR-001
- [ ] Achieve release-blocking acceptance standard (CR-001 Section 9)

> **Completion notes**: Historical March 2026 completion claim; superseded numerically by Wave E Basalt. Current measured state is 20 workspace packages, 122970 Rust LOC under `crates/`, 2,980 listed workspace tests, 20 numbered CI gates plus aggregator, traceability rows at 83 implemented / 1 partial / 2 planned, and threat matrix rows at 14 implemented / 0 partial / 0 planned. Section 9 acceptance criteria remain open while any traceability row is partial or planned. Post-quantum signature support (Ed25519/PostQuantum/Hybrid) is implemented.

## Active Resolutions

- [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] — DRAFT (partial implementation evidence; Section 9 acceptance criteria remain open)

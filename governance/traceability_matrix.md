# Traceability Matrix

Updated 2026-03-20 after EXOCHAIN-REM-009 — continuous governance monitoring activation. Maps every spec requirement to code, tests, and status.

**Status key:** 🟢 Implemented (tests passing) | 🟡 Partial | 🔴 Planned

## Core Infrastructure (Spec §9)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **9.1** | **Event Hashing (BLAKE3 + canonical CBOR)** | `exo-core::hash` | `exo-core/src/hash.rs` (mod tests) | 22 | 🟢 |
| 9.1 | Ed25519 sign / verify + post-quantum enum | `exo-core::crypto` | `exo-core/src/crypto.rs` (mod tests) | 17 | 🟢 |
| 9.1 | `SignerType` (Human 0x01 / AI 0x02) | `exo-core::types` | `types::tests::signer_type_*` | — | 🟢 |
| 9.1 | Event creation + signing | `exo-core::events` | `exo-core/src/events.rs` (mod tests) | 13 | 🟢 |
| **9.2** | **Hybrid Logical Clock** | `exo-core::hlc` | `exo-core/src/hlc.rs` (mod tests) | 15 | 🟢 |
| 9.2 | DAG causal ordering | `exo-dag::dag` | `exo-dag/src/dag.rs` (mod tests) | 21 | 🟢 |
| 9.2 | BFT consensus (2f+1 quorum) | `exo-dag::consensus` | `exo-dag/src/consensus.rs` (mod tests) | 12 | 🟢 |
| **9.3** | **Consent Policy Structure** | `exo-consent::policy` | `exo-consent/src/policy.rs` (mod tests) | 13 | 🟢 |
| 9.3 | Bailment lifecycle | `exo-consent::bailment` | `exo-consent/src/bailment.rs` (mod tests) | 22 | 🟢 |
| 9.3 | Default-deny consent gate | `exo-consent::gatekeeper` | `exo-consent/src/gatekeeper.rs` (mod tests) | 12 | 🟢 |
| **9.4** | **Merkle Mountain Range** | `exo-dag::mmr` | `exo-dag/src/mmr.rs` (mod tests) | 23 | 🟢 |
| 9.4 | Sparse Merkle Tree | `exo-dag::smt` | `exo-dag/src/smt.rs` (mod tests) | 20 | 🟢 |
| 9.4 | DAG store + checkpoints | `exo-dag::store` | `exo-dag/src/store.rs` (mod tests) | 10 | 🟢 |
| **9.5** | **RiskAttestation** | `exo-identity::risk` | `exo-identity/src/risk.rs` (mod tests) | 8 | 🟢 |

## Identity & Key Management (Spec §10)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **10.1** | **DID register / resolve / revoke / rotate** | `exo-identity::did` | `exo-identity/src/did.rs` (mod tests) | 11 | 🟢 |
| 10.2 | Key management (create/rotate/revoke + zeroize) | `exo-identity::key_management` | `exo-identity/src/key_management.rs` | 15 | 🟢 |
| 10.3 | Shamir secret sharing (GF(256)) | `exo-identity::shamir` | `exo-identity/src/shamir.rs` (mod tests) | 17 | 🟢 |
| 10.4 | PACE operator continuity | `exo-identity::pace` | `exo-identity/src/pace.rs` (mod tests) | 12 | 🟢 |
| 10.5 | Vault encryption (XChaCha20-Poly1305 + HKDF) | `exo-identity::vault` | `exo-identity/src/vault.rs` (mod tests) | 9 | 🟢 |

## Gatekeeper & Constitutional Enforcement (Spec §12)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **12.0** | **TEE Attestation + production gate** | `exo-gatekeeper::tee` | `exo-gatekeeper/src/tee.rs` (mod tests) | 28 | 🟢 |
| 12.1 | CGR Kernel (immutable judicial branch) | `exo-gatekeeper::kernel` | `exo-gatekeeper/src/kernel.rs` (mod tests) | 16 | 🟢 |
| 12.1 | 8 Constitutional invariants | `exo-gatekeeper::invariants` | `exo-gatekeeper/src/invariants.rs` (mod tests) | 32 | 🟢 |
| 12.2 | 9 Combinator types | `exo-gatekeeper::combinator` | `exo-gatekeeper/src/combinator.rs` (mod tests) | 26 | 🟢 |
| 12.3 | Holon agent runtime | `exo-gatekeeper::holon` | `exo-gatekeeper/src/holon.rs` (mod tests) | 16 | 🟢 |
| 12.4 | 6 MCP rules + crypto AI binding | `exo-gatekeeper::mcp` | `exo-gatekeeper/src/mcp.rs` (mod tests) | 20 | 🟢 |

## Authority & Delegation (Spec §11)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **11.1** | **Authority chain + real Ed25519 verification** | `exo-authority::chain` | `exo-authority/src/chain.rs` (mod tests) | 25 | 🟢 |
| 11.2 | Delegation registry + circular detection | `exo-authority::delegation` | `exo-authority/src/delegation.rs` (mod tests) | 13 | 🟢 |
| 11.3 | Permission model (7 variants) | `exo-authority::permission` | `exo-authority/src/permission.rs` (mod tests) | 14 | 🟢 |
| 11.4 | Chain cache (LRU) | `exo-authority::cache` | `exo-authority/src/cache.rs` (mod tests) | 10 | 🟢 |

## Governance (Spec §13)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **13.1** | **Independence-aware quorum** | `exo-governance::quorum` | `exo-governance/src/quorum.rs` (mod tests) | 10 | 🟢 |
| 13.2 | Challenge / contestation | `exo-governance::challenge` | `exo-governance/src/challenge.rs` (mod tests) | 12 | 🟢 |
| 13.3 | Crosscheck + coordination detection | `exo-governance::crosscheck` | `exo-governance/src/crosscheck.rs` (mod tests) | 11 | 🟢 |
| 13.4 | Independence-aware clearance | `exo-governance::clearance` | `exo-governance/src/clearance.rs` (mod tests) | 10 | 🟢 |
| 13.5 | Deliberation + voting | `exo-governance::deliberation` | `exo-governance/src/deliberation.rs` (mod tests) | 9 | 🟢 |
| 13.6 | Conflict disclosure + recusal | `exo-governance::conflict` | `exo-governance/src/conflict.rs` (mod tests) | 9 | 🟢 |
| 13.7 | Hash-chained audit log | `exo-governance::audit` | `exo-governance/src/audit.rs` (mod tests) | 7 | 🟢 |
| 13.8 | Succession protocol | `exo-governance::succession` | `exo-governance/src/succession.rs` (mod tests) | 10 | 🟢 |

## Escalation (Spec §14)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **14.1** | **Sybil detection signals** | `exo-escalation::detector` | `detector.rs` (mod tests) | 10 | 🟢 |
| 14.2 | Triage (4 levels) | `exo-escalation::triage` | `triage.rs` (mod tests) | 5 | 🟢 |
| 14.3 | 7-stage Sybil adjudication | `exo-escalation::escalation` | `escalation.rs` (mod tests) | 10 | 🟢 |
| 14.4 | Kanban board | `exo-escalation::kanban` | `kanban.rs` (mod tests) | 7 | 🟢 |
| 14.5 | Feedback + learning | `exo-escalation::feedback` | `feedback.rs` (mod tests) | 6 | 🟢 |
| 14.6 | Completeness checker | `exo-escalation::completeness` | `completeness.rs` (mod tests) | 7 | 🟢 |

## Legal Infrastructure (Spec §15)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **15.1** | **Evidence + chain of custody** | `exo-legal::evidence` | `evidence.rs` (mod tests) | 13 | 🟢 |
| 15.2 | eDiscovery | `exo-legal::ediscovery` | `ediscovery.rs` (mod tests) | 7 | 🟢 |
| 15.3 | Attorney-client privilege | `exo-legal::privilege` | `privilege.rs` (mod tests) | 5 | 🟢 |
| 15.4 | Fiduciary duty compliance | `exo-legal::fiduciary` | `fiduciary.rs` (mod tests) | 14 | 🟢 |
| 15.5 | Records retention | `exo-legal::records` | `records.rs` (mod tests) | 8 | 🟢 |
| 15.6 | Conflict disclosure | `exo-legal::conflict_disclosure` | `conflict_disclosure.rs` (mod tests) | 7 | 🟢 |
| 15.7 | DGCL §144 safe-harbor | `exo-legal::dgcl144` | `dgcl144.rs` (mod tests) | 12 | 🟢 |

## ZK Proofs (Spec §12.5)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **12.5** | **R1CS Constraint System** | `exo-proofs::circuit` | `circuit.rs` (mod tests) | 16 | 🟢 |
| 12.5 | SNARK (Groth16-like) | `exo-proofs::snark` | `snark.rs` (mod tests) | 10 | 🟢 |
| 12.5 | STARK (hash-based, post-quantum) | `exo-proofs::stark` | `stark.rs` (mod tests) | 11 | 🟢 |
| 12.5 | ZKML (verifiable inference) | `exo-proofs::zkml` | `zkml.rs` (mod tests) | 12 | 🟢 |
| 12.5 | Unified verifier | `exo-proofs::verifier` | `verifier.rs` (mod tests) | 8 | 🟢 |

## P2P, API, Gateway, Multi-Tenant (Spec §16–17)

| Spec | Requirement | Crate / Module | Test Location | Tests | Status |
|---|---|---|---|---|---|
| **16.1** | **P2P + rate limiting + ASN diversity** | `exo-api::p2p` | `p2p.rs` (mod tests) | 31 | 🟢 |
| 16.2 | API schema (8 request types) | `exo-api::schema` | `schema.rs` (mod tests) | — | 🟢 |
| 17.1 | Gateway + DID auth + middleware | `exo-gateway` | All modules | 27 | 🟢 |
| 17.5 | Tenant management + sharding + cold storage | `exo-tenant` | All modules | 36 | 🟢 |

## Decision Forum Application Layer

| Req | Requirement | Module | Tests | Status |
|---|---|---|---|---|
| **GOV-001** | Machine-readable constitution | `constitution.rs` | 15 | 🟢 |
| **GOV-002** | Constitutional versioning + temporal binding | `constitution.rs` | — | 🟢 |
| **GOV-003** | Delegated authority matrix | `authority_matrix.rs` | 11 | 🟢 |
| **GOV-004** | Standing authority sunset/renewal | `authority_matrix.rs` | — | 🟢 |
| **GOV-005** | Authority chain verification on every action | `tnc_enforcer.rs` + `exo-authority` | 13+25 | 🟢 |
| **GOV-006** | Constitutional conflict resolution hierarchy | `constitution.rs` | — | 🟢 |
| **GOV-007** | Human oversight gates | `human_gate.rs` | 8 | 🟢 |
| **GOV-008** | Contestation and reversal | `contestation.rs` | 11 | 🟢 |
| **GOV-009** | Emergency action protocol | `emergency.rs` | 8 | 🟢 |
| **GOV-010** | Quorum failure + degradation | `quorum.rs` | 7 | 🟢 |
| **GOV-011** | Succession + continuity | `exo-governance::succession` | 10 | 🟢 |
| **GOV-012** | Accountability mechanisms | `accountability.rs` | 9 | 🟢 |
| **GOV-013** | Recursive self-governance | `self_governance.rs` | 6 | 🟢 |
| **TNC-01→10** | Trust-Critical Non-Negotiable Controls | `tnc_enforcer.rs` | 13 | 🟢 |
| **M1→M12** | Measurable success metrics | `metrics.rs` | 8 | 🟢 |

## Continuous Governance Monitoring (EXOCHAIN-REM-009)

| Req | Requirement | Module / Migration | Status |
|---|---|---|---|
| **MON-001** | Governance health snapshot persistence | `demo/infra/postgres/init/003_governance_health.sql` — `governance_health_snapshots` table | 🟢 |
| **MON-002** | Per-finding persistence with severity index | `demo/infra/postgres/init/003_governance_health.sql` — `governance_findings` table | 🟢 |
| **MON-003** | Human approval gate before self-improvement trigger | `demo/infra/postgres/init/003_governance_health.sql` — `governance_trigger_approvals` table; `POST /governance/approve/:id` endpoint | 🟢 |
| **MON-004** | Authenticated `/governance/health` GET endpoint | `demo/services/audit-api/src/index.js` — bearer token required (`GOVERNANCE_API_TOKEN`) | 🟢 |
| **MON-005** | Authenticated `POST /governance/health` snapshot ingestion | `demo/services/audit-api/src/index.js` — bearer token + full provenance record | 🟢 |
| **MON-006** | Circuit breaker: auto-pause trigger when >3 Critical/24h | `demo/services/audit-api/src/index.js` — 24h rolling window query + `circuit_breaker_triggered` flag | 🟢 |
| **MON-007** | Audit ledger entry for every health snapshot (provenance) | `demo/services/audit-api/src/index.js` — `GovernanceHealthSnapshot` event appended to `audit_entries` | 🟢 |
| **MON-008** | CR-001 §8 work order status tracked in every snapshot | `003_governance_health.sql` — `cr001_work_orders` JSONB column; surfaced in GET response | 🟢 |
| **MON-009** | T-14 Governance Monitor Poisoning in threat matrix | `governance/threat_matrix.md` — T-14 entry with 4 sub-threats, mitigations, detection signals | 🟡 Partial (Rust-layer signed attestation verification pending) |
| **MON-010** | Continuous-governance workflow DAG definition | `.archon/workflows/exochain-continuous-governance.yaml` | 🟢 (pre-existing) |
| **MON-011** | ExoForge scheduled trigger activation | ExoForge platform configuration — daily + on-merge schedule | 🔴 Planned (requires ExoForge platform access) |
| **MON-012** | Governance health dashboard (React UI widget) | `demo/web/src/` — new GovernanceHealthWidget | 🔴 Planned |

## Summary

| Category | Requirements | 🟢 | 🟡 | 🔴 |
|---|---|---|---|---|
| Core Infrastructure (§9) | 14 | 14 | 0 | 0 |
| Identity & Keys (§10) | 5 | 5 | 0 | 0 |
| Gatekeeper (§12) | 6 | 6 | 0 | 0 |
| Authority (§11) | 4 | 4 | 0 | 0 |
| Governance (§13) | 8 | 8 | 0 | 0 |
| Escalation (§14) | 6 | 6 | 0 | 0 |
| Legal (§15) | 7 | 7 | 0 | 0 |
| ZK Proofs (§12.5) | 5 | 5 | 0 | 0 |
| P2P/API/Gateway/Tenant (§16–17) | 4 | 4 | 0 | 0 |
| Decision Forum (GOV/TNC/M) | 16 | 16 | 0 | 0 |
| Governance Monitoring (MON) | 12 | 9 | 1 | 2 |
| **TOTAL** | **87** | **84** | **1** | **2** |

**Coverage: 84/87 requirements traced to code (97%). 2 planned (ExoForge scheduling + React dashboard). 1 partial (T-14 Rust attestation verification).**
**Workspace: 1,846 tests, 0 failures across 16 crates (monitoring requirements covered by integration tests — see MON-009).**

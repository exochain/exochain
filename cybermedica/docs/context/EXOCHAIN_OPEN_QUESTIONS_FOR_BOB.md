# Exochain Open Questions Submitted for Council Review

These questions were submitted to the Exochain council-style review process for development disposition. Do not treat this file as the current Bob escalation list. Use `docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md` for council consensus defaults and `docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md` for the narrowed Bob-facing escalation register.

These questions do not block baseline development of CyberMedica domain models, service contracts, adapter interfaces, deterministic fixtures, contract tests, inactive trust-state UI, or fail-closed behavior.

## Root Authority and Production Activation

| ID | Question | Why it matters | Source basis | Blocked claim |
|---|---|---|---|---|
| ROOT-001 | Who are the 13 rostered independent certifiers for the institutional root authority bootstrap? | Root genesis config requires exactly 13 unique certifiers. | `crates/exo-root/src/ceremony.rs` | root-backed production authority |
| ROOT-002 | Where will the root genesis DKG transcript, roster, signed envelopes, and final root trust bundle be stored? | Production evidence must be reviewable and reproducible. | `crates/exo-root/src/dkg.rs`, `portal.rs`, `bundle.rs` | production trust activation |
| ROOT-003 | What concrete event activates CyberMedica production trust claims after the 7/13 bootstrap? | Development can proceed, but claims must remain inactive until activation. | user 7/13 instruction, `crates/exo-root/src/signing.rs` | root-backed CyberMedica claims |
| ROOT-004 | Which deployment will CyberMedica query to verify the root trust bundle? | A code path is not deployment evidence. | `crates/exo-node/src/root_genesis.rs`, `Dockerfile`, `deploy/entrypoint.sh` | deployed root readiness |
| ROOT-005 | Who owns root ceremony incident response and rollback/disablement? | Root failures affect all downstream authority claims. | `AGENTS.md`, `crates/exo-root/*` | production operations claim |

## Identity, Human Gate, and Clinical Roles

| ID | Question | Why it matters | Source basis | Blocked claim |
|---|---|---|---|---|
| ID-001 | What identity proofing source makes a user an externally verified human for Decision Forum human gates? | Self-declared human actors are insufficient. | `crates/decision-forum/src/human_gate.rs` | human-approved clinical gate |
| ID-002 | What CyberMedica actors require Exochain DID identities: PI, sub-I, CRC, QA, sponsor monitor, CRO monitor, auditor, support engineer, AI agent, admin? | Actor taxonomy must map to DID/auth/authority. | `crates/exo-identity/src/did.rs`, `crates/exo-gateway/src/auth.rs` | verified actor identity |
| ID-003 | Which clinical roles map to Exochain `Role` values and which map only to `Permission` values? | Governance roles and operational permissions are different. | `crates/exo-governance/src/quorum.rs`, `crates/exo-authority/src/permission.rs` | role-based authority |
| ID-004 | What are the allowed delegation chains for site staff, sponsor/CRO oversight, support access, and AI assistants? | Authority chains must be attenuated, non-cyclic, signed, and revocable. | `crates/exo-authority/src/chain.rs`, `delegation.rs` | delegation-backed workflow |
| ID-005 | Which actions require quorum and which require only authority/consent? | Quorum is governance, not generic RBAC. | `crates/exo-governance/src/quorum.rs`, `crates/exo-gatekeeper/src/invariants.rs` | governance decision claim |

## Consent, Bailment, Custody, and Privacy

| ID | Question | Why it matters | Source basis | Blocked claim |
|---|---|---|---|---|
| CONSENT-001 | Which CyberMedica consent concepts map to Exochain bailment: participant informed consent, site data custody, support access, sponsor export, AI review? | Bailment is not a generic checkbox. | `crates/exo-consent/src/bailment.rs`, `contract.rs` | consent-backed QMS control |
| CONSENT-002 | What makes a participant consent receipt legally meaningful in the CyberMedica domain? | Exochain can hash/sign records; clinical validity needs domain rules. | `crates/exo-consent/src/policy.rs`, `crates/exo-core/src/types.rs` | participant consent receipt |
| CONSENT-003 | What revocation behavior is required for participant consent, support access, and sponsor/CRO export grants? | Revocation must fail closed and be auditable. | `crates/exo-consent/src/gatekeeper.rs` | revocation enforcement |
| PRIV-001 | Which fields are prohibited from immutable receipts, DAG payloads, provenance endpoints, logs, telemetry, health, and exports? | Hash-only does not automatically eliminate metadata risk. | `crates/exo-node/src/provenance.rs`, `crates/exo-legal/src/evidence.rs` | PHI/PII-safe anchoring |
| PRIV-002 | What is the CyberMedica minimum metadata policy for evidence anchors and diligence exports? | Sponsor/CRO exports can leak sensitive operational data. | `crates/exo-legal/src/evidence.rs`, `crates/exo-core/src/types.rs` | privacy-preserving export |

## Decision Forum, Council, and Review Bodies

| ID | Question | Why it matters | Source basis | Blocked claim |
|---|---|---|---|---|
| DF-001 | Which CyberMedica decisions are Routine, Operational, Strategic, or Constitutional? | Decision class controls AI ceiling and human gate policy. | `crates/decision-forum/src/decision_object.rs`, `human_gate.rs` | governed decision class |
| DF-002 | Which clinical gates require Decision Forum: QMS control approval, protocol readiness, launch gate, enrollment gate, CAPA closure, consent policy change, support access policy? | CyberMedica must not overuse or bypass governance. | `crates/decision-forum/src/workflow.rs`, `tnc_enforcer.rs` | Decision Forum-backed workflow |
| DF-003 | What is the relationship between Exochain council review and clinical IRB-like review in CyberMedica? | Source docs mention council/AI-IRB-like process, but implementation boundary is ambiguous. | `governance/*`, `docs/guides/ARCHON-INTEGRATION.md` | IRB-like governance claim |
| DF-004 | Who can file, review, sustain, overrule, or withdraw a challenge in CyberMedica? | Challenges can pause or block actions. | `crates/exo-governance/src/challenge.rs` | contestable governance |
| DF-005 | Which evidence bundle fields are mandatory before a clinical decision can close? | TNC evidence completeness controls closure. | `crates/decision-forum/src/tnc_enforcer.rs` | evidence-complete approval |

## Runtime, Adapters, and Deployment

| ID | Question | Why it matters | Source basis | Blocked claim |
|---|---|---|---|---|
| RT-001 | Which Exochain runtime is canonical for CyberMedica: gateway REST, node API, SDK, WASM, or internal service boundary? | Adapter tests and security posture depend on the selected path. | `crates/exo-gateway/*`, `crates/exo-node/*`, `crates/exochain-sdk/*`, `crates/exochain-wasm/*` | Exochain-backed runtime claim |
| RT-002 | Where will CyberMedica store operational state versus immutable Exochain receipts? | Operational DB state is not the same as receipt finality. | `crates/exo-node/src/store.rs`, `crates/exo-core/src/types.rs` | immutable audit claim |
| RT-003 | What is the production health/readiness model for trust fabric dependencies? | Process health must be separate from trust readiness. | `Dockerfile`, `deploy/entrypoint.sh`, `crates/exo-gateway/src/server.rs` | production readiness |
| RT-004 | What secrets exist for CyberMedica adapters and how are they scoped apart from Exochain bootstrap/root keys? | Adjacent surfaces must not share core bootstrap or signing keys. | `AGENTS.md`, `SECURITY.md` | secure adjacent deployment |
| RT-005 | Which CI gates are mandatory before CyberMedica can use Exochain-backed language in UI or exports? | Trust claims need enforcement evidence. | `.github/workflows/ci.yml`, user TDD instruction | release gate |

## Adjacent Surfaces and Tooling

| ID | Question | Why it matters | Source basis | Blocked claim |
|---|---|---|---|---|
| ADJ-001 | Is CommandBase in scope for CyberMedica, and if so, is it only a cockpit or a runtime adapter? | CommandBase is adjacent unless proven otherwise. | `AGENTS.md`, `README.md` | CommandBase enforcement |
| ADJ-002 | Is ExoForge/Archon allowed to generate CyberMedica implementation work, and what human review gates apply? | Agent workflow outputs are untrusted until validated. | `AGENTS.md`, `docs/guides/ARCHON-INTEGRATION.md` | AI workflow authority |
| ADJ-003 | Is Syntaxis a design-time generator only or a product-facing workflow surface? | Registry drift could create false enforcement assumptions. | `tools/syntaxis/*` | Syntaxis-backed workflow |
| ADJ-004 | Should CyberMedica expose the Exochain web Decision Forum UI or build its own regulated surface around Decision Forum APIs? | UI code was not inventoried in this seed. | `web/*`, `crates/decision-forum/*` | production governance UI |
| ADJ-005 | Is AVC part of CyberMedica MVP for AI assistant provenance? | AVC is implemented, but clinical governance needs a bounded role. | `crates/exo-avc/*` | AI provenance claim |

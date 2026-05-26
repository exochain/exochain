# CyberMedica Adjacent Surface Decisions

CyberMedica is a governed clinical research site QMS adjacent to Exochain. It is not Exochain core, does not alter Exochain core, and cannot claim Exochain constitutional enforcement unless a verified runtime path calls Exochain core or a verified core runtime adapter and tests prove the boundary.

## Path Classification

| Path or Surface | Classification | Decision | Evidence basis | Required proof before trust claims |
|---|---|---|---|---|
| `/Users/bobstewart/dev/exochain/exochain` | EXOCHAIN core source repository | Read-only source of truth for this pre-seed. Do not modify. | User instruction, `AGENTS.md` | Local repo truth commands and tests |
| `/Users/bobstewart/dev/exochain/cybermedica` | Adjacent surface | CyberMedica product repository. It holds context artifacts and baseline service-contract code for QMS controls, quality objectives, evidence receipts, governed actions, and inactive trust-state UI. | User instruction, `AGENTS.md`, `package.json`, `src/*`, `tests/*` | Adjacent intake, adapter tests, CI gates |
| `docs/context/*` in CyberMedica | Adjacent surface documentation | Stores pre-seed, glossary, integration map, questions, decisions, blockers. | User request | Review against current Exochain code |
| `github.com/bob-stewart/cybermedica` | Adjacent private repository target | Document creation instructions if missing; repository creation not required in this pass. | User request | Private repo, branch protection, CI |
| Exochain `crates/*` | EXOCHAIN core or core runtime adapter | Use as source only. Do not edit for this CyberMedica pre-seed. | `Cargo.toml`, `AGENTS.md` | Source path plus passing tests |
| Exochain `web/*` | Adjacent/unknown surface | Do not rely on for CyberMedica until inventoried. | README/required inventory | UI code review and fail-closed tests |
| Exochain `command-base/*` | Adjacent surface | Do not rely on for CyberMedica enforcement. | `AGENTS.md` | intake record and adapter proof |
| Exochain `exoforge/*`, `.archon/*` | Adjacent/tooling | Treat workflow output as untrusted until validated. | `AGENTS.md`, `docs/guides/ARCHON-INTEGRATION.md` | bounded loop and source guard tests |
| Exochain `tools/syntaxis/*` | Tooling/core runtime adapter candidate | Design-time only until registry-to-code drift is resolved. | `tools/syntaxis/node_registry.json`, `generate_workflow.py` | generated workflows compile and map to current modules |

## Adjacent Surface Intake Record

| Field | CyberMedica decision |
|---|---|
| Owner and accountable maintainer | Bob Stewart until delegated in writing. |
| Release status | `prototype`; baseline development may proceed. Not production. |
| Constitutional trust claims allowed now | No production trust claims. Development artifacts may state source mappings, contract assumptions, inactive trust states, and activation gates. |
| Can read/write Exochain core state | No direct write path is authorized by this pre-seed. Read-only source inspection only. |
| Can read/write signatures, credentials, governance outcomes, consent records, provenance records | Development may define interfaces and tests for these records. Production read/write behavior requires a selected adapter and fail-closed tests. |
| Exact trust boundary | CyberMedica owns regulated QMS workflow and operational state. Exochain owns constitutional trust primitives and receipts. CyberMedica may request Exochain decisions/receipts through verified adapters only. |
| Surface-specific test command | `npm test` runs `node --test tests/*.test.mjs`; `npm run test:coverage` runs `node --experimental-test-coverage --test tests/*.test.mjs`. |
| CI gate | `npm run quality` is the current baseline service-contract gate. Before any Exochain-backed UI/export language is active, this gate must remain green and the production activation gates must prove adapter fail-closed behavior, PHI/PII non-anchoring, tenant isolation, consent revocation, authority/RBAC, Decision Forum human gate, receipt determinism, dependency audit, and secret scan. |
| Secrets inventory | Baseline service contracts require no runtime secrets. CyberMedica must not share Exochain bootstrap/root/signing keys. Production adapter credentials must live in a CyberMedica-only secret scope and missing or malformed values must fail closed. |
| Runtime configuration source | Baseline tests are deterministic and environment-free. Production runtime configuration must come from the selected CyberMedica deployment configuration and secret manager; missing, malformed, or unverified trust-fabric configuration leaves trust state inactive or denied. |
| Rollback/disablement path | Trust-claim features must be feature-gated and disable Exochain-backed language when root/gateway/node/receipt dependencies are unavailable. |

## Decisions

| ID | Decision | Rationale | Source basis | Status |
|---|---|---|---|---|
| ASD-001 | CyberMedica remains adjacent to Exochain core. | Regulated QMS concerns should not expand the Exochain trusted computing base. | `AGENTS.md` | Adopted |
| ASD-002 | Exochain repository is read-only for this pass. | User explicitly instructed not to change Exochain code. | User instruction | Adopted |
| ASD-003 | CyberMedica may develop service contracts before root activation. | User clarified the verified production backend becomes active upon 7/13 bootstrapping and must not inhibit development. | User instruction, `crates/exo-root/*` | Adopted |
| ASD-004 | Root-backed production trust claims are inactive until root bootstrap evidence is verified. | Root code implements 13-certifier DKG and 7-of-13 signing; deployment evidence is not present in this seed. | `crates/exo-root/src/ceremony.rs`, `dkg.rs`, `signing.rs`, `bundle.rs` | Adopted |
| ASD-005 | CyberMedica must use Exochain primitives only through verified adapters. | No trust claim by proximity. | `AGENTS.md` | Adopted |
| ASD-006 | Decision Forum may support QMS gates only through adjudicated production paths. | Raw transitions are disabled in production path; human gate and TNCs exist. | `crates/decision-forum/src/decision_object.rs`, `human_gate.rs`, `tnc_enforcer.rs` | Adopted |
| ASD-007 | AI is assistant, not final authority. | Decision Forum human gate and AVC ceiling behavior require human approval for higher classes. | `crates/decision-forum/src/human_gate.rs`, `crates/exo-avc/src/validation.rs` | Adopted |
| ASD-008 | CyberMedica must separate operational state from immutable receipts. | Node receipt store and core TrustReceipt are distinct from app database state. | `crates/exo-core/src/types.rs`, `crates/exo-node/src/store.rs` | Adopted |
| ASD-009 | CyberMedica must not expose Exochain root ceremony, raw admin governance, proof, CrossChecked anchor, or 0dentity behavioral axes as product features until verified. | These paths are production-sensitive, default-off, unaudited, or un-inventoried. | `crates/exo-root/*`, `crates/exo-node/src/api.rs`, `crates/exo-proofs/src/lib.rs`, `crates/exo-node/src/zerodentity/*` | Adopted |
| ASD-010 | CyberMedica tests must exceed Exochain's general coverage bar at trust boundaries. | User requires near-100% TDD for >90% build and regulated trust surfaces demand higher assurance. | User instruction, `.github/workflows/ci.yml` | Adopted |
| ASD-011 | Final Exochain/root verification gates production activation, not baseline development. | Waiting for live root evidence before writing CyberMedica would create a chicken-and-egg dependency. | User clarification, `crates/exo-root/*` | Adopted |

## Service Contract Development Before Root Activation

CyberMedica must define interfaces, fake-free contract tests, deterministic fixtures, and adapter failure behavior before production root activation. That work must remain honest about trust state:

| Allowed before root activation | Not allowed before root activation |
|---|---|
| Define adapter interfaces that call Exochain gateway/node/core. | Claim production root-backed governance. |
| Write contract tests against deterministic local Exochain fixtures. | Mint simulated root bundles or production-like root receipts. |
| Build fail-closed behavior for unavailable Exochain services. | Cache or override consent/authority/governance outcomes outside Exochain. |
| Build operational UI that labels trust fabric unavailable when root is inactive. | Display active Exochain-backed authority if root bundle is absent/unverified. |
| Build PHI/PII non-anchoring tests and receipt shape tests. | Anchor raw sensitive clinical content. |
| Build baseline QMS workflows, quality objectives, evidence objects, review states, and export manifests. | Present those workflows as live Exochain-governed production outcomes before runtime verification. |

## GitHub Private Repository Creation Instructions

If `github.com/bob-stewart/cybermedica` does not exist, create it as a private repository and push only CyberMedica-owned files. Do not import Exochain source into the CyberMedica repository.

Recommended repository controls:

1. Private visibility.
2. Branch protection on `main`.
3. Required CI status checks before merge.
4. Secret scanning and dependency alerts enabled.
5. CODEOWNERS for context, app, adapters, security, and deployment.
6. Separate secret scope from any Exochain root/bootstrap/signing material.

## Non-Dilution Rule

The original CyberMedica PRD/context prompt remains controlling. This pre-seed may refine claims based on Exochain evidence, but it must not water down requirements, replace unknowns with invented certainty, or turn gated production claims into soft implementation language. Missing verification remains a gate for production trust claims, not an invitation to imply support.

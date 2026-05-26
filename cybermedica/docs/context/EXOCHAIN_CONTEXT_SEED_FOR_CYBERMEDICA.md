# Exochain Context Seed for CyberMedica

Prepared for CyberMedica pre-seeding on 2026-05-23.

CyberMedica must inherit Exochain's verified trust fabric, not its mythology. This artifact is a conservative, code-first seed for designing CyberMedica as an adjacent regulated clinical research QMS surface. It authorizes baseline CyberMedica development against source-identified service contracts and fail-closed adapters. It does not authorize production trust claims, live root-backed authority, or Exochain-backed marketing claims beyond the verified primitives and activation gates below.

Read-only boundary: Exochain source is evidence for this pass, not an edit target. No Exochain code, workflow, crate, governance file, or adjacent Exochain surface may be changed by the CyberMedica pre-seed.

## 1. Executive Summary

Exochain is a Rust workspace for a constitutional trust fabric: deterministic core types, DID identity, bailment/consent, authority delegation, gatekeeper adjudication, governance quorum, legal evidence custody, DAG/provenance, gateway/node adapters, Decision Forum, SDK/WASM surfaces, AVC, economy scaffolding, and root authority bootstrapping.

The strongest verified substrate for CyberMedica is the Rust core and adapter code around deterministic hashing, DID identity, bailment/consent policy, authority chains, gatekeeper invariants, tenant records, legal evidence custody, trust receipts, DAG provenance, and Decision Forum adjudicated decision paths. These source-verified primitives are enough to begin baseline CyberMedica development now: service contracts, domain models, UI flows, adapter interfaces, fixture-backed contract tests, and fail-closed behavior. Production trust claims remain inactive until the deployed runtime path, root trust bundle, receipts, fail-closed adapters, and tests are verified in the actual production environment.

The root production backend becomes active only on institutional root bootstrapping: 13 rostered independent certifiers, 100% participation for root genesis FROST Ristretto255 DKG, then 7-of-13 threshold signing after genesis. CyberMedica development to service contracts must not be inhibited by that activation condition, but CyberMedica must not claim root-backed production authority before deployment evidence proves the bootstrapped root path.

Development gate: build the CyberMedica system now against explicit contracts, deterministic local fixtures, and inactive trust-claim states. Activation gate: enable production Exochain/root-backed claims only after the live root bundle, deployed adapter path, receipts, privacy boundaries, and fail-closed tests verify.

| Conclusion | Source path | Evidence type | Support level | Confidence | CyberMedica consequence |
|---|---|---:|---|---:|---|
| Exochain workspace declares 23 Rust members. | `Cargo.toml` | Config | Code/config | High | Treat listed crates as repo inventory baseline. |
| Local repo truth script reports 23 crates, 312 Rust source files, 203,671 Rust LOC, 4,566 listed tests, 22 CI gates plus aggregator, 116 implemented traceability items, and 2 planned items. | `tools/repo_truth.sh --json --list-tests` on `/Users/bobstewart/dev/exochain/exochain` | Runtime | Script output | High | Use these counts as the local inventory baseline for this seed. |
| The implemented gatekeeper invariant set has 8 variants. | `crates/exo-gatekeeper/src/invariants.rs`, `AGENTS.md` | Code/Docs | Code and docs agree on names | High | CyberMedica claims must map to these 8, not older doc names. |
| Determinism doctrine is implemented through no unsafe, no float linting, BTree structures, canonical CBOR hashing, HLC timestamps. | `Cargo.toml`, `crates/exo-core/src/lib.rs`, `crates/exo-core/src/hash.rs`, `crates/exo-core/src/types.rs` | Code/Config | Code/config | High | Clinical scoring and receipt material must be deterministic and integer/fixed-point. |
| `exo-proofs` is unaudited and default-off. | `crates/exo-proofs/src/lib.rs`, `.github/workflows/ci.yml` | Code/Workflow | Code and CI | High | No CyberMedica ZK proof claim until a production proof path exists and is tested. |
| Decision Forum production transitions require kernel adjudication, verified quorum, human gate, consent/authority controls, and TNC enforcement. | `crates/decision-forum/src/decision_object.rs`, `workflow.rs`, `human_gate.rs`, `tnc_enforcer.rs` | Code | Code | High | CyberMedica approval workflows may wrap this only through adjudicated paths. |
| Root genesis requires exactly 13 certifiers, 100% DKG completion, and 7-of-13 signing. | `crates/exo-root/src/ceremony.rs`, `dkg.rs`, `signing.rs`, `bundle.rs`, `portal.rs`, `crates/exo-node/src/root_genesis.rs` | Code | Code | High | Production root-backed CyberMedica claims are gated by root trust bundle/deployment evidence; baseline development is not gated by this. |
| CrossChecked receipt anchoring and raw admin governance shortcuts are default-off unaudited features. | `crates/exo-node/src/api.rs` | Code | Code | High | CyberMedica must not build trust claims on these disabled shortcuts. |
| Documentation count and invariant naming drift exists. | `README.md`, `docs/INDEX.md`, `docs/architecture/ARCHITECTURE.md`, `docs/audit/REPO-TRUTH-BASELINE.md` | Docs | Docs drift against code | High | CyberMedica builders must cite code paths for implementation truth. |

## 2. Method and Sources

The Exochain repository was absent at `/Users/bobstewart/dev/exochain/exochain` and was cloned read-only from `https://github.com/exochain/exochain.git` for source verification. The local checkout is on branch `main` at commit `7a4137f74aa2996428c10b85d6e0adc7166df733`, committed `2026-05-20T13:30:20-04:00` with subject `fix(gateway): close 2026-05-20 security scan triage (#665)`; `git status --short` was clean after verification; no tag points at HEAD.

No Exochain files are changed by this pre-seed. CyberMedica context files are the only intended write target.

Commands executed:

```bash
git branch --show-current
git rev-parse HEAD
git status --short
git tag --points-at HEAD
tools/repo_truth.sh --json --list-tests
cargo metadata --format-version 1 --no-deps
cargo metadata --format-version 1 --no-deps | jq -r '.packages[].name'
```

Repo truth output:

```json
{
  "timestamp": "2026-05-23T15:05:53Z",
  "commit": "7a4137f7",
  "crates": 23,
  "rust_source_files": 312,
  "rust_loc": 203671,
  "tla_specs": 5,
  "tests_listed": 4566,
  "ci_gates": { "numbered": 22, "required_aggregator": "All Constitutional Gates" },
  "traceability": { "implemented": 116, "partial": 0, "planned": 2, "total": 118 },
  "threats": { "mitigated": 16, "partial": 0, "planned": 0, "total": 16 },
  "fmt_clean": true
}
```

Commands identified but not run in this pre-seed because the requested pass is source-truth inventory, not a remediation or release gate:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Full workspace test pass/fail remains unverified by this artifact. The repo truth script listed tests successfully with exit code 0; it did not run the full test suite.

Focused term discovery found local file presence for the required concepts. Counts are file counts, not implementation claims: council 158, IRB 25, Syntaxis 76, Decision Forum 56, bailment 176, 0dentity 40, exo-consent 46, exo-authority 44, exo-tenant 23, exo-legal 38, exo-governance 60, exo-gatekeeper 66, exo-escalation 35, exo-messaging 9, exo-avc 13, exo-economy 16, ExoForge 100, Archon 42, CommandBase 69, CGR 61, constitutional 337, proofs 74, receipts 164, CBOR 139, deterministic 288, floating 58, privacy 37, audit 336, traceability 22.

Material sources inspected:

| Source | Path | What was inspected | Evidence type | Confidence |
|---|---|---|---:|---:|
| Workspace manifest | `Cargo.toml` | workspace members, lints, dependencies | Config | High |
| Repo truth script | `tools/repo_truth.sh --json --list-tests` | local inventory counts, listed tests, CI gate count, traceability/threat counts | Runtime | High |
| Cargo metadata | `cargo metadata --format-version 1 --no-deps` | package names, versions, manifests, features, workspace members | Runtime | High |
| Focused term discovery | `rg -i -l --glob '!target/**' ...` | local source/document presence for council, IRB, Syntaxis, Decision Forum, bailment, 0dentity, governance, receipts, CBOR, determinism, privacy, audit, traceability | Runtime | Medium |
| Agent doctrine | `AGENTS.md` | invariants, core/adapter/adjacent rules, no trust claim by proximity | Docs | High |
| README | `README.md` | repo claims, architecture layers, hardening caveats | Docs | Medium |
| Core types | `crates/exo-core/src/*` | HLC, CBOR hashing, signatures, trust receipts, BCTS, events | Code | High |
| Identity | `crates/exo-identity/src/did.rs` | `did:exo` derivation and DID document structure | Code | High |
| Consent | `crates/exo-consent/src/*` | bailment, policy, contract, consent gate, revocation | Code | High |
| Authority | `crates/exo-authority/src/*` | permission sets, delegation chains, signed revocations, audit chain | Code | High |
| Gatekeeper | `crates/exo-gatekeeper/src/invariants.rs`, `kernel.rs` | 8 invariants, adjudication verdicts, BCTS adapter | Code | High |
| Governance | `crates/exo-governance/src/*` | quorum, verified deliberation close, audit, challenges | Code | High |
| Legal | `crates/exo-legal/src/evidence.rs` | evidence records and chain of custody | Code | High |
| DAG | `crates/exo-dag/src/*` | append-only DAG and BFT certificates | Code | High |
| Proofs | `crates/exo-proofs/src/lib.rs` | unaudited/default-off proof skeleton | Code | High |
| Gateway | `crates/exo-gateway/src/*` | REST routes, DID auth, default-deny routing, server hardening | Code | High |
| Tenant | `crates/exo-tenant/src/tenant.rs` | tenant registry and quotas | Code | High |
| Decision Forum | `crates/decision-forum/src/*` | decision object, workflow receipts, human gate, TNCs | Code | High |
| Root | `crates/exo-root/src/*`, `crates/exo-node/src/root_genesis.rs` | 13-certifier DKG, 7-of-13 signing, root portal | Code | High |
| Node | `crates/exo-node/src/api.rs`, `store.rs`, `provenance.rs`, `passport.rs`, `zerodentity/*` | receipts, provenance, disabled shortcuts, passports, 0dentity axes | Code | High |
| SDK/WASM | `crates/exochain-sdk/src/lib.rs`, `crates/exochain-wasm/*` | SDK facade and WASM adapter presence | Code | Medium |
| CI | `.github/workflows/ci.yml`, `tools/test_coverage_policy.sh` | 22 gates, scoped coverage, exclusions | Workflow | High |
| Deployment | `Dockerfile`, `deploy/entrypoint.sh` | build/runtime containers and healthcheck | Runtime/Config | High |
| Syntaxis | `tools/syntaxis/node_registry.json`, `generate_workflow.py` | visual node registry and workflow generation | Spec/Code | Medium |
| Governance docs | `governance/quality_gates.md`, `traceability_matrix.md`, `threat_matrix.md` | quality gates, traceability, threat map | Docs | Medium |

## 3. Repository Inventory

Path classifications use the project rule set: `EXOCHAIN core`, `Core runtime adapter`, `Adjacent surface`, `Imported evidence`, `Third-party/vendor`.

| Area | Path | Classification | What it is | Evidence type | Implementation status | Test status | CyberMedica relevance | Confidence |
|---|---|---|---|---:|---|---|---|---:|
| Workspace | `Cargo.toml` | EXOCHAIN core | Rust workspace with 23 members and deny lints | Config | Implemented | CI references | Inventory source of truth | High |
| Core | `crates/exo-core` | EXOCHAIN core | deterministic types, HLC, CBOR hashing, BCTS, trust receipts | Code | Implemented | Unit tests observed in source | Required | High |
| Identity | `crates/exo-identity` | EXOCHAIN core | DID generation and verification documents | Code | Implemented | Needs local run | Required | High |
| Consent | `crates/exo-consent` | EXOCHAIN core | bailment, policy, active consent, revocation, contracts | Code | Implemented | Tests observed | Required | High |
| Authority | `crates/exo-authority` | EXOCHAIN core | delegation chains, permissions, revocation, audit events | Code | Implemented | Tests observed | Required | High |
| Gatekeeper | `crates/exo-gatekeeper` | EXOCHAIN core | invariant engine and adjudication kernel | Code | Implemented | Tests observed | Required | High |
| Governance | `crates/exo-governance` | EXOCHAIN core | proposals, quorum, deliberation, challenges, audit | Code | Implemented | Tests observed | Required | High |
| Escalation | `crates/exo-escalation` | EXOCHAIN core | escalation and human override support | Code | Partially implemented | Needs local run | Required for regulated controls | Medium |
| Legal | `crates/exo-legal` | EXOCHAIN core | evidence and chain of custody | Code | Implemented | Tests observed | Required | High |
| DAG | `crates/exo-dag` | EXOCHAIN core | append-only DAG and BFT certificates | Code | Implemented with liveness caveats | Tests observed | Required for provenance | High |
| Proofs | `crates/exo-proofs` | EXOCHAIN core | unaudited proof skeleton | Code | Documented default-off | Excluded from coverage | Avoid for claims | High |
| API | `crates/exo-api` | Core runtime adapter | API models/surface | Code | Implemented | Needs local run | Adapter candidate | Medium |
| Gateway | `crates/exo-gateway` | Core runtime adapter | REST routes, DID auth, middleware, server | Code | Partially production-hardened | Coverage excludes runtime DB/server/handlers/graphql | Required through fail-closed tests | High |
| Tenant | `crates/exo-tenant` | EXOCHAIN core | tenant registry and isolation metadata | Code | Implemented | Needs local run | Required | High |
| Decision Forum | `crates/decision-forum` | EXOCHAIN core / app core | adjudicated decision workflow | Code | Implemented | Tests observed | Required for approvals | High |
| WASM | `crates/exochain-wasm` | Core runtime adapter | browser/JS bridge | Code | Implemented | CI build/sync gates | Optional adapter | Medium |
| Node | `crates/exo-node` | Core runtime adapter | node API, receipts, provenance, root portal | Code | Implemented with default-off shortcuts | CI gates | Required for receipts/provenance/root | High |
| Catapult | `crates/exo-catapult` | Adjacent surface | franchise/NewCo incubator logic | Code | Implemented scaffold | Needs local run | Avoid for CyberMedica MVP | Medium |
| Messaging | `crates/exo-messaging` | EXOCHAIN core | encrypted messaging | Code | Implemented | Needs local run | Optional | Medium |
| Consensus | `crates/exo-consensus` | EXOCHAIN core | deterministic model consensus/scoring | Code | Implemented | Tests observed | AI advisory only | Medium |
| SDK | `crates/exochain-sdk` | Core runtime adapter | Rust SDK facade | Code | Implemented | Needs local run | Adapter candidate | Medium |
| AVC | `crates/exo-avc` | EXOCHAIN core | autonomous volition credentials | Code | Implemented | Tests observed | Requires review | Medium |
| Economy | `crates/exo-economy` | Adjacent/core scaffold | quote/settlement scaffolding, zero launch guarantee | Code | Partially implemented | Needs local run | Avoid for QMS claims | Medium |
| Root | `crates/exo-root` | EXOCHAIN core | institutional root ceremony, DKG, signing, bundle | Code | Implemented | CI 100% coverage gates claimed | Production gate | High |
| Syntaxis | `tools/syntaxis` | Core runtime adapter / tooling | visual registry and workflow generator | Code/Spec | Partially implemented | Generator tests need local run | Use only after registry verification | Medium |
| Repo truth | `tools/repo_truth.sh`, `tools/test_repo_truth.sh` | EXOCHAIN core tooling | repo inventory and truth tests | Code | Implemented | Not run in this session | Required for re-verification | High |
| Governance docs | `governance/*` | EXOCHAIN core docs | quality gates, threat and traceability matrices | Docs | Documented | Secondary to code | Reading order | Medium |
| Web | `web/*` | Adjacent surface | Decision Forum or governance UI area per README | Unknown | Unknown | Needs inventory | Requires review | Low |
| CommandBase | `command-base/*` | Adjacent surface | cockpit/adapter per README/AGENTS | Unknown | Unknown | Needs inventory | Do not trust by proximity | Low |
| ExoForge | `exoforge/*`, `docs/guides/ARCHON-INTEGRATION.md` | Adjacent/tooling | validation/factory/Archon workflow docs | Docs/Unknown | Documented partly | Needs inventory | Requires review | Medium |
| Archon workflows | `.archon/*` | Adjacent/tooling | agent commands and workflow YAML, including council/continuous governance/self-improvement workflows | Docs/Config | Documented/configured | Needs loop-bound validation | Process input only | Medium |
| Exochain config | `.exochain/*` | Config | mission economics, provenance, MCP examples, Honorgood config | Config | Documented/configured | Needs inventory | Avoid for CyberMedica claims | Medium |
| Agents | `agents/*/AGENTS.md` | Adjacent/tooling | specialist agent instructions | Docs | Documented | Not runtime tests | Process input only | Medium |
| Demo | `demo/*` | Adjacent surface | demo apps/packages/services/web | Code/Unknown | Unknown in this seed | Needs inventory | Avoid for trust claims | Low |
| Gap program | `gap/*` | Docs/Spec | gap charter, ultraplans, doctrine, onboarding, council tests | Docs/Spec | Documented | Tests are docs unless executable proven | Context only | Medium |
| Packages | `packages/*` | Core runtime adapter / third-party style packages | TypeScript/Python/WASM package surfaces | Code | Implemented partly | Needs package tests | Requires review | Medium |
| Site | `site/*` | Adjacent surface | public/marketing/docs site | Code/Docs | Unknown | Needs inventory | No enforcement claims | Low |
| TLA | `tla/*` | Spec | formal specs reported by repo truth count | Spec | Documented | Model-check status needs verification | Doctrine support | Medium |
| Fuzz | `fuzz/*` | Tests | fuzz targets | Tests | Test scaffold/source | Execution not verified | Assurance signal only | Medium |
| CI | `.github/workflows/ci.yml` | EXOCHAIN core CI | 22 quality gates plus aggregator | Workflow | Implemented | Must run in GitHub/local | Deployment bar | High |
| ExoForge CI | `.github/workflows/exoforge-triage.yml` | Adjacent/tooling workflow | ExoForge triage automation | Workflow | Configured | Not run | Adjacent process only | Medium |
| Release CI | `.github/workflows/release.yml` | EXOCHAIN release workflow | release packaging/signing workflow | Workflow | Configured | Not run | Production posture input | Medium |
| Deployment | `Dockerfile`, `deploy/entrypoint.sh` | Core runtime adapter | container build/run and health | Runtime/Config | Implemented | Needs deploy run | Production posture input | High |

## 4. Doctrine Layer

| Canonical term | Source path | Plain-language meaning | Implementation support | Test support | CyberMedica implication | Unresolved ambiguity | Confidence |
|---|---|---|---|---|---|---|---:|
| Absolute determinism | `AGENTS.md`, `Cargo.toml`, `crates/exo-core/src/lib.rs` | Same input must produce same output across runs/platforms/time. | no unsafe/floats, BTree maps, HLC, CBOR hashing | CI and local test run required | Clinical calculations and receipt payloads must be deterministic. | Hash sorting relies on deterministic structures more than generic key sorting. | High |
| No floating-point arithmetic | `Cargo.toml`, `AGENTS.md` | `f32`/`f64` arithmetic is forbidden. | clippy denies float arithmetic/cmp | CI required | Use integer or fixed-point basis points. | None for core; adjacent JS must add equivalent guards. | High |
| Canonical CBOR hashing | `crates/exo-core/src/hash.rs`, `types.rs` | Structured data is serialized deterministically before hashing/signing. | BLAKE3 over CBOR bytes | Tests observed; local run required | Evidence receipts must hash canonical payloads, not JSON. | Need adapter tests for every CyberMedica payload. | High |
| Identity adjudication | `crates/exo-identity/src/did.rs`, `crates/exo-gateway/src/auth.rs` | Actors are represented by Exochain DIDs and verified signatures. | DID generation and DID-auth verification | Local run required | User/site/sponsor/CRO identity must map to DID-auth or verified adapter. | Human proofing workflow is not fully mapped here. | High |
| Consent required | `crates/exo-consent/src/policy.rs`, `gatekeeper.rs`, `crates/exo-gatekeeper/src/invariants.rs` | Actions fail without active bailment consent when required. | Default-deny policy and invariant | Tests observed | Participant consent/support access must fail closed. | Clinical informed consent semantics need domain mapping. | High |
| Bailment/custody | `crates/exo-consent/src/bailment.rs`, `contract.rs`, `crates/exo-legal/src/evidence.rs` | Custodial authority and evidence custody are structured and revocable. | Bailment records and evidence custody chain | Tests observed | Clinical records/evidence must distinguish custody from immutable receipt. | Terms hash legal adequacy requires founder/legal review. | High |
| Authority chain valid | `crates/exo-authority/src/chain.rs`, `delegation.rs`, `crates/exo-gatekeeper/src/invariants.rs` | Delegated authority must be unbroken, attenuated, non-cyclic, signed, and current. | Registry validates chains/revocation | Tests observed | Role authority and delegation logs must use core authority primitives or adapter. | Exact role taxonomy for clinical research must be mapped. | High |
| Constitutional governance | `crates/exo-governance/src/*`, `crates/exo-gatekeeper/src/kernel.rs` | Governance decisions require quorum, provenance, challenges, and adjudication. | Verified quorum and challenge logic | Tests observed | Launch/enrollment/CAPA gates require human governance evidence. | Council process as human institution needs Bob confirmation. | High |
| Human governance / human gate | `crates/decision-forum/src/human_gate.rs`, `tnc_enforcer.rs` | Human approval is externally verified; self-declared human is insufficient. | Human DID allow-list and TNC enforcement | Tests observed | AI cannot be final authority for regulated QMS decisions. | Human identity proofing source not fully documented. | High |
| Provenance verifiable | `crates/exo-core/src/types.rs`, `crates/exo-dag/src/dag.rs`, `crates/exo-node/src/store.rs` | Actions have receipts, hashes, signatures, DAG nodes, and/or certificates. | TrustReceipt, DAG, receipt store | Tests observed | Exochain-backed claims need concrete receipt path. | Production node availability and deployment evidence pending. | High |
| Tenant isolation | `crates/exo-tenant/src/tenant.rs`, `crates/exo-gateway/src/rest.rs` | Tenants are explicit objects with status and quotas. | Tenant registry and tenant endpoints | Local run required | Sponsor/site boundaries require tenant tests. | Runtime data isolation beyond registry needs verification. | Medium |
| Privacy-preserving anchoring | `crates/exo-node/src/provenance.rs`, `crates/exo-node/src/api.rs`, `crates/exo-legal/src/evidence.rs` | Anchors expose hashes/metadata, not raw payloads; default CrossChecked write path refuses. | Provenance endpoint omits payload; disabled external anchoring | Tests observed for no payload size | No raw PHI/PII/sponsor-confidential content may be anchored. | Need CyberMedica PHI fixture tests. | High |
| Root authority bootstrap | `crates/exo-root/src/ceremony.rs`, `dkg.rs`, `signing.rs`, `bundle.rs`, `portal.rs` | Institutional root is established by 13-certifier DKG and 7-of-13 signing. | FROST Ristretto255 ceremony code | CI claims 100% root coverage; local run required | Production trust claims inactive until root trust bundle verified. | Actual roster, ceremony transcript, and deployment state pending. | High |
| Proof posture | `crates/exo-proofs/src/lib.rs` | ZK-like proofs are pedagogical/default-off. | Feature gate refusal | CI excludes crate from coverage | Do not claim ZK proofs. | Requires real audited proof implementation. | High |

## 5. Domain Layer

| Domain | Canonical name | Related crates/apps/docs | Purpose | Inputs | Outputs | Actors | Decisions | Receipts | CyberMedica usage | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Core deterministic substrate | Exo Core | `crates/exo-core` | shared types, HLC, hashes, receipts, BCTS | structured objects, keys, timestamps | hashes, receipts, events, BCTS states | all services | deterministic state transitions | `TrustReceipt` | Required for MVP | Implemented |
| Identity | Exo DID identity | `crates/exo-identity`, `crates/exo-gateway/src/auth.rs` | identify and authenticate actors | public keys, DID docs, signed auth envelopes | `did:exo:*`, DID docs, auth decisions | users, sites, sponsors, agents | identity verified/denied | auth audit via gateway/core | Required for MVP | Implemented |
| Consent | Bailment consent | `crates/exo-consent` | consent and revocation enforcement | bailments, policies, active consent, action request | allow/deny/escalate, revocation logs | participants, custodians, support users | consent valid/invalid | access logs, revocation logs | Required for MVP | Implemented |
| Authority | Authority delegation | `crates/exo-authority` | permission chains and revocation | delegates, scopes, signatures | authority chains, audit events | site staff, PI, sponsor/CRO, admins | delegation allowed/revoked | hash-chained delegation audit | Required for MVP | Implemented |
| Gatekeeper | Constitutional kernel | `crates/exo-gatekeeper` | enforce 8 invariants | action request + adjudication context | verdict permitted/denied/escalated | every actor | invariant pass/fail | provenance requirement | Required for MVP | Implemented |
| Governance | Constitutional governance | `crates/exo-governance`, `governance/*` | proposals, quorum, challenges, audit | proposals, votes, approvals, evidence | quorum result, audit entry, challenge state | council/governors/reviewers | approve/reject/escalate | audit chain | Required for MVP decisions | Implemented |
| Council | Council review | `governance/*`, `docs/guides/ARCHON-INTEGRATION.md` | human governance assessment | resolutions, review panels, evidence | assessment/recommendation | founder/council/reviewers | accept/reject/escalate | docs/audit entries | Requires review | Documented/process |
| IRB-like review | AI-IRB / council panels | `docs/guides/ARCHON-INTEGRATION.md` | structured ethics/governance review process | change records, evidence | panel findings | human reviewers/AI assistants | proceed/block | docs only | Requires Bob confirmation | Documented only |
| Decision Forum | Decision Forum | `crates/decision-forum`, `web/*` | governed decision workflow | decision object, votes, evidence, authority | state transitions, receipts | humans, AI agents within ceiling | approve/reject/escalate/close | workflow receipts | Required for launch/CAPA gates | Implemented core, UI needs inventory |
| Syntaxis | Syntaxis | `tools/syntaxis/*` | visual workflow to Rust generator | workflow JSON, node registry | Rust module/test scaffolds | builders | valid/invalid workflow | generated tests | Optional after registry verification | Partially implemented |
| ExoForge/Archon | ExoForge / Archon | `docs/guides/ARCHON-INTEGRATION.md`, `exoforge/*`, `.archon/*` | factory/triage/agent workflow process | issues, workflows, council review | generated work products | agents/humans | workflow outcomes | process records | Requires review | Partially documented |
| Tenant | Exo tenant | `crates/exo-tenant`, gateway tenant routes | tenant registration and isolation metadata | tenant id/name/config/status | tenant records | sponsors, sites, CROs | tenant active/suspended/archived | audit through adapter | Required for MVP | Implemented metadata |
| Legal provenance | Legal evidence custody | `crates/exo-legal/src/evidence.rs` | admissibility and custody chain | evidence hash, custodian, timestamp | evidence record, custody digest | custodians/auditors | custody transfer | custody digest | Required for MVP evidence | Implemented |
| Receipts/provenance | Trust receipts + DAG | `crates/exo-core`, `crates/exo-dag`, `crates/exo-node` | immutable action evidence | action hash, signature, DAG payload | receipt, DAG node, provenance response | services/node | commit/query | TrustReceipt | Required for MVP | Implemented, deployment pending |
| Gateway/API | Exo Gateway | `crates/exo-gateway` | REST/DID-auth adapter | HTTP requests, signatures, tenant/auth data | routed decisions, responses | clients/services | accept/reject/default deny | audit middleware | Wrap internally | Partially hardened |
| Node API | Exo Node | `crates/exo-node` | governance/receipt/provenance/root endpoints | API calls, receipts, root envelopes | stored receipts, provenance, root portal | operators/services | store/query/refuse shortcuts | receipt store | Wrap internally | Implemented with disabled shortcuts |
| WASM bridge | Exochain WASM | `crates/exochain-wasm` | browser/JS bridge | JS calls | WASM exports | web apps | adapter decisions | adapter-specific | Optional | Implemented, CI-gated |
| CommandBase | CommandBase | `command-base/*`, README/AGENTS mentions | adjacent cockpit | unknown | unknown | operators | unknown | unknown | Avoid trust claims | Needs inventory |
| AVC | Autonomous Volition Credential | `crates/exo-avc` | delegated operational intent credential | AVC, consent/policy refs, constraints | allow/deny/human/challenge decision | agents/humans | bounded autonomy | AVC receipt | Requires review | Implemented |
| Messaging | Exo messaging | `crates/exo-messaging` | encrypted messaging | messages/keys | encrypted records | users/agents | send/receive | unknown | Optional | Implemented |
| Economy | Exo economy | `crates/exo-economy` | settlement/quotes scaffold | integer amounts | receipts/quotes | payers/payees | settle/quote | economy receipts | Avoid for MVP | Scaffold |
| 0dentity | 0dentity | `crates/exo-node/src/zerodentity/*` | trust/onboarding/passport scoring | identity/device/behavioral inputs | score/passport data | agents/users | score/pass/fail | passport/profile | Avoid behavioral axes | Partially default-off |
| Root | Root genesis | `crates/exo-root`, `crates/exo-node/src/root_genesis.rs` | institutional root authority | 13 certifiers, DKG messages, signatures | root bundle, issuer delegations | certifiers/operators | bootstrapped/not bootstrapped | root artifacts | Production gate | Implemented, deployment evidence pending |

## 6. Data Layer

| Object | Path | Definition | Fields summary | Sensitive? | Immutable? | Versioned? | Receipt-capable? | CyberMedica mapping | Open questions |
|---|---|---|---|---|---|---|---|---|---|
| `TrustReceipt` | `crates/exo-core/src/types.rs` | signed receipt for an adjudicated action | receipt hash, actor DID, authority hash, consent ref, action type/hash, outcome, timestamp, signature, challenge ref | Metadata may be sensitive | Intended immutable | Domain `exo.trust_receipt.v1` | Yes | evidence, CAPA, export, AI review, audit receipts | Which node signs CyberMedica receipts in production? |
| `Hash256` | `crates/exo-core/src/types.rs` | 32-byte hash wrapper | bytes, hex conversion | No by itself | Yes | No explicit schema version | Supports anchors | evidence and document hash anchors | Need payload classification policy. |
| `Timestamp` | `crates/exo-core/src/types.rs` | HLC timestamp | physical_ms, logical | No | Yes | No | Included in receipts | deterministic audit chronology | CyberMedica HLC source. |
| `Bailment` | `crates/exo-consent/src/bailment.rs` | legal consent/custody relationship | id, bailor, bailee, type, terms hash, status, timestamps, signature, key | Yes | Status changes | Domain for terms hash | Indirect | participant consent, support-access grants, custody | Clinical informed consent equivalence. |
| `ConsentPolicy` | `crates/exo-consent/src/policy.rs` | required consent rules | resource, action, requirements, deny default | Yes | Config record | Needs policy versioning | Decision logs | consent revocation, PHI access boundary | Policy authoring authority. |
| `ConsentGateSnapshot` | `crates/exo-consent/src/gatekeeper.rs` | persisted consent gate state | policy, bailments, consents, revoked ids, access/revocation logs, sequences | Yes | Snapshot mutable | Sequence-based | Access/revocation logs | support access and consent audit | Storage encryption and tenant separation. |
| `BailmentContract` | `crates/exo-consent/src/contract.rs` | deterministic legal contract | parties, clauses, data classification, fixed-point monetary values | Yes | Contract hash immutable | Contract version fields need mapping | Hash-capable | consent terms, DPA-like controls | Legal adequacy in clinical context. |
| `AuthorityChain` | `crates/exo-authority/src/chain.rs` | root-to-leaf authority path | links, permissions, expiry, signatures, delegatee kind | Yes | Chain record should be immutable | Domain version | Yes | role authority/delegation logs | Clinical role taxonomy. |
| `DelegationAuditEvent` | `crates/exo-authority/src/delegation.rs` | hash-chained delegation audit | previous hash, action, chain/link ids, timestamp, actor | Metadata sensitive | Append-only | Domain version | Yes | authority audit trail | Retention and disclosure rules. |
| `InvariantContext` | `crates/exo-gatekeeper/src/invariants.rs` | input to invariant checks | actor, roles, bailment, consent, authority, quorum, provenance, permissions | Yes | Per adjudication | Code struct | Produces violations | gate evidence for regulated actions | Adapter payload contract. |
| `ActionRequest` | `crates/exo-gatekeeper/src/kernel.rs` | adjudication request | actor, action, permissions, self-grant flag, kernel modification flag | Yes | Per request | Code struct | Via kernel outcome | all gated workflows | CyberMedica action taxonomy. |
| `QuorumPolicy` / `QuorumResult` | `crates/exo-governance/src/quorum.rs` | verified quorum evaluation | eligible roles, thresholds, approvals, attestations | Yes | Decision evidence immutable | Code struct | Governance audit | Decision Forum approvals | Which clinical boards count as quorum? |
| `Approval` | `crates/exo-governance/src/quorum.rs` | signed approval | actor, role, scope, decision id, signature | Yes | Immutable | Scope enum | Yes | QMS launch/enrollment/CAPA approvals | Human proofing source. |
| `AuditEntry` | `crates/exo-governance/src/audit.rs` | governance audit entry | id, previous hash, actor, action, timestamp, payload hash | Metadata sensitive | Append-only | Domain version | Yes | audit logs | Production audit chain storage. |
| `Challenge` | `crates/exo-governance/src/challenge.rs` | contestation object | ground, status, evidence, filer, timestamps | Yes | State transition record | Code enum | Audit capable | CAPA dispute and governance challenge | Clinical escalation policy. |
| `Evidence` | `crates/exo-legal/src/evidence.rs` | legal evidence record | id, type_tag, hash, creator, timestamp, custody chain, admissibility | Yes | Custody chain append-only | Code struct | Hash/custody digest | evidence objects, site passports, exports | PHI boundary around evidence metadata. |
| `DagNode` | `crates/exo-dag/src/dag.rs` | append-only provenance node | hash, parents, payload_hash, creator, timestamp, signature | Metadata sensitive | Yes | Domain version | Yes | chain of custody and document version receipts | Which payloads are stored vs referenced. |
| `CommitCertificate` | `crates/exo-dag/src/consensus.rs` | BFT commit certificate | node hash, height, votes, signatures | No/metadata | Yes | Domain version | Yes | provenance finality evidence | Production validator set. |
| `DecisionObject` | `crates/decision-forum/src/decision_object.rs` | governed decision matter | id, title, class, constitution hash, state, authority, votes, evidence, receipts, metadata | Yes | Terminal immutable | Code struct | Receipt chain | launch gate, enrollment gate, CAPA closure | UI/source of decision metadata. |
| `WorkflowReceipt` | `crates/decision-forum/src/workflow.rs` | receipt for workflow transition | decision id, stage, actor, timestamp, hash/signature | Yes | Yes | Domain version | Yes | Decision Forum approvals | Adapter to CyberMedica objects. |
| `RootTrustBundle` | `crates/exo-root/src/bundle.rs` | institutional root trust artifact | root artifacts, issuer delegations, signatures | No/limited metadata | Yes | Domain version | Yes | production authority root | Actual bundle, roster, transcript. |
| `AvcTrustReceipt` | `crates/exo-avc/src/receipt.rs` | AVC validation receipt | AVC refs, decision, reason codes, timestamp, hash/signature | Yes | Yes | Domain version | Yes | AI-assistant provenance, bounded autonomy | Whether AVC belongs in MVP. |
| `TenantRegistration` | `crates/exo-tenant/src/tenant.rs` | tenant object | id, name, config, created, status | Yes | Mutable status | Code struct | Adapter audit needed | sponsor/site/CRO tenant boundaries | Runtime isolation beyond metadata. |

## 7. Doors Layer

| Door | User | Purpose | Path | Auth model | Sensitive data exposure | CyberMedica role | Production readiness |
|---|---|---|---|---|---|---|---|
| Rust core crate APIs | services/builders | deterministic trust primitives | `crates/exo-core`, `exo-consent`, `exo-authority`, `exo-gatekeeper` | in-process caller | high if raw objects logged | import/wrap through service adapter | Strongest substrate, tests still must run locally |
| Gateway REST | services/operators | external HTTP adapter | `crates/exo-gateway/src/rest.rs`, `routes.rs`, `auth.rs`, `server.rs` | DID signature/API key/bearer paths | high | call internally through fail-closed adapter | Partially hardened; runtime DB/server/handler coverage excluded |
| Node API | operators/services | governance, receipts, provenance, root portal | `crates/exo-node/src/api.rs`, `store.rs`, `provenance.rs`, `root_genesis.rs` | route-specific, root portal signed envelope | high | receipt/provenance/root integration | Implemented; shortcuts default-off |
| Decision Forum core | governance users | adjudicated decision workflows | `crates/decision-forum/src/*` | kernel/quorum/human gate/TNC inputs | high | wrap for clinical decision gates | Production path must use adjudicated transitions |
| Decision Forum web | human governance | UI for decisions | `web/*` | unverified | high | do not expose until inventoried | Unknown in this seed |
| CLI root genesis | certifiers/operators | root ceremony operations | `crates/exo-root`, root genesis CLI files | signed roster/certifier material | critical key material | production bootstrap only | Implemented; deployment evidence required |
| WASM bridge | web apps | JS/browser adapter | `crates/exochain-wasm` | adapter-defined | high if exposed to PHI | optional, avoid for MVP unless tested | CI build/sync gated |
| SDK | developers | typed Rust facade | `crates/exochain-sdk/src/lib.rs` | local facade/no I/O | depends on caller | adapter contract candidate | Implemented but protocol version beta |
| Syntaxis generator | builders | generate workflow Rust/tests | `tools/syntaxis/*` | local tool | workflow definitions may be sensitive | design-time only after registry verification | Registry drift risk |
| CommandBase | operators | cockpit/adjacent adapter | `command-base/*` | unknown | unknown | avoid direct trust claim | Needs inventory |
| ExoForge/Archon | agents/builders | workflow/factory process | `docs/guides/ARCHON-INTEGRATION.md`, `exoforge/*`, `.archon/*` | workflow/agent controls | high if outputs trusted blindly | process input only | Needs code inventory |
| Docker runtime | operators | production container | `Dockerfile`, `deploy/entrypoint.sh` | network/runtime secrets | high | deployment reference | Needs production health verification |

CyberMedica should expose its own regulated clinical QMS surface. It should call Exochain through narrow service adapters that fail closed, log receipt attempts, protect PHI/PII, and prove behavior with near-100% tests at trust boundaries. It should not expose raw Exochain administrative governance, unaudited CrossChecked anchors, proof APIs, 0dentity behavioral axes, or root genesis operations to normal users.

## 8. Documentation Layer

| Doc | Path | Subject | Currency | Source of truth? | Conflicts | CyberMedica relevance |
|---|---|---|---|---|---|---|
| Agent doctrine | `AGENTS.md` | constitutional constraints, core/adjacent rules | Current enough for this pass | Yes for agent behavior and classifications | `unwrap`/`expect` severity differs from `Cargo.toml` deny | Mandatory |
| Council open-question review | `docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md` | council-style development dispositions and defaults | Current CyberMedica context | Yes for CyberMedica development defaults | Non-binding; not a real constitutional council act | Mandatory |
| Bob escalation register | `docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md` | narrowed decisions that require Bob/root/operator input | Current CyberMedica context | Yes for escalation discipline | None | Mandatory |
| Workspace README | `README.md` | repo overview, claims, hardening caveats | Newer than stale doc counts | Secondary | Count claims require repo truth rerun | Reading order |
| Cargo manifest | `Cargo.toml` | workspace/lint truth | Current code | Yes | None observed | Mandatory |
| Architecture doc | `docs/architecture/ARCHITECTURE.md` | layered architecture | Stale counts/names | No for code truth | Lists 9 named invariants while code has 8 | Read with caution |
| Docs index | `docs/INDEX.md` | docs map | Stale counts | No | count drift | Useful index only |
| Repo truth baseline | `docs/audit/REPO-TRUTH-BASELINE.md` | historical inventory | Stale | No | older branch/crate/test counts | Drift example |
| Quality gates | `governance/quality_gates.md` | gate expectations | Useful | Secondary | numbering/names may drift from CI | CI planning |
| Traceability matrix | `governance/traceability_matrix.md` | requirements mapping | Useful secondary | No for implementation | needs rerun against code | Requirements mapping |
| Threat matrix | `governance/threat_matrix.md` | threat coverage | Useful secondary | No for implementation | assumes implementation status | Threat model seed |
| Archon guide | `docs/guides/ARCHON-INTEGRATION.md` | ExoForge/Archon process | Process doc | No | autonomy language must be bounded by AGENTS | Process review |
| Security policy | `SECURITY.md` | supported versions/release posture | Current enough | Yes for reporting posture | pre-release tags unsigned | Release guardrails |

Canonical reading order for CyberMedica builders:

1. `AGENTS.md`
2. `Cargo.toml`
3. `docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md`
4. `docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md`
5. `crates/exo-core/src/lib.rs`, `types.rs`, `hash.rs`, `bcts.rs`
6. `crates/exo-gatekeeper/src/invariants.rs`, `kernel.rs`
7. `crates/exo-consent/src/*`
8. `crates/exo-authority/src/*`
9. `crates/exo-governance/src/*`
10. `crates/decision-forum/src/*`
11. `crates/exo-legal/src/evidence.rs`
12. `crates/exo-dag/src/*`
13. `crates/exo-node/src/api.rs`, `store.rs`, `provenance.rs`, `root_genesis.rs`
14. `.github/workflows/ci.yml`, `tools/repo_truth.sh`, `tools/test_repo_truth.sh`
15. `crates/exo-root/src/*`

Glossary is maintained in `docs/context/EXOCHAIN_GLOSSARY_FOR_CYBERMEDICA.md`.

Documentation gaps CyberMedica must not paper over:

- runtime deployment state and live root trust bundle;
- exact human identity proofing source for human gates;
- clinical role taxonomy mapped to Exochain permission and quorum roles;
- production-grade ZK proof path;
- CrossChecked anchor verification;
- CommandBase/web/ExoForge code inventory;
- PHI/PII/sponsor-confidential anchoring policy and tests;
- Syntaxis registry drift against current crate modules.

## 9. Deployment Layer

| Capability | Path | Current status | Verified by | CyberMedica implication | Risk |
|---|---|---|---|---|---|
| CI gate set | `.github/workflows/ci.yml` | 22 gates plus aggregator declared | Workflow inspection; not run locally | CyberMedica CI must not be weaker at trust boundaries | Local pass unverified |
| Coverage | `.github/workflows/ci.yml`, `tools/test_coverage_policy.sh` | scoped >=90%; root crates/portal 100%; excludes proofs/WASM/runtime adapter areas | Workflow inspection | CyberMedica target >90%, near-100% for trust boundaries | Exclusions must be explicit |
| Lints | `Cargo.toml` | deny unsafe/floats/unwrap/expect | Config inspection | Mirror no-float/no-unsafe discipline where applicable | JS/TS needs equivalent static checks |
| Security/audit | `SECURITY.md`, `deny.toml`, `.github/workflows/ci.yml` | cargo audit/deny, license/advisory policy, OpenSSL banned | Docs/config | Dependency additions require compliance | Ignored advisories must be reviewed |
| Docker runtime | `Dockerfile`, `deploy/entrypoint.sh` | Rust build image, non-root runtime, health `/ready`, ports 4001/4002/8080 | Config inspection | CyberMedica must define health and readiness separately from trust availability | Runtime not exercised |
| Root genesis deployment | `crates/exo-root`, `crates/exo-node/src/root_genesis.rs` | code path implemented | Code inspection; deployment evidence absent | Production trust claims gated | Ceremony transcript/root bundle absent |
| Receipt persistence | `crates/exo-node/src/store.rs` | SQLite receipt store and sync checks | Code inspection | CyberMedica must prove receipts stored/queryable | DB migration/runtime config unverified |
| Provenance endpoint | `crates/exo-node/src/provenance.rs` | hash-based provenance without payload exposure | Code inspection | Use for non-PHI anchor views | Metadata leakage tests required |
| Railway/cloud posture | guessed `railway.toml`, `docs/deployment/*` | not verified in this seed | Not found in inspected paths | Do not assume Railway readiness | Deployment docs may be elsewhere |

CyberMedica deployment requirements faithful to Exochain:

- TDD-first implementation with scoped coverage above 90%.
- Near-100% coverage for Exochain adapters, root/bootstrap-sensitive gates, PHI/PII boundaries, support access, receipt creation, consent revocation, tenant isolation, authority/RBAC, Decision Forum approvals, and fail-closed paths.
- CI gates for format, lint, test, coverage, dependency audit, secret scan, no-float/no-unsafe equivalent, receipt determinism, PHI/PII non-anchoring, tenant isolation, and adapter unavailability.
- Production feature flags must fail closed when root trust bundle, receipt node, gateway, or Decision Forum backend is unavailable.
- Health endpoints must separate process health from trust-fabric readiness.

## 10. Drift Layer

| Drift Item | Evidence | Risk | CyberMedica consequence | Required decision | Owner |
|---|---|---|---|---|---|
| README/doc count drift | `README.md` vs `docs/INDEX.md`, `docs/audit/REPO-TRUTH-BASELINE.md` | stale inventory can mislead architecture | cite code/repo truth only | rerun `tools/repo_truth.sh` | Exochain maintainer |
| Invariant naming drift | `docs/architecture/ARCHITECTURE.md` vs `crates/exo-gatekeeper/src/invariants.rs` | wrong controls mapped to CyberMedica | use 8 code enum names | update docs or annotate | Exochain maintainer |
| Syntaxis registry drift | `tools/syntaxis/node_registry.json` references modules/traits not verified in current source | generated workflows may not compile or may imply missing enforcement | allow design-time exploration; do not claim Syntaxis-backed enforcement | registry-to-crate verification test | Exochain tooling owner |
| Runtime adapter coverage exclusions | `.github/workflows/ci.yml`, `tools/test_coverage_policy.sh` | gateway/server/DB handlers may be less covered | CyberMedica adapter must add its own tests | define fail-closed adapter harness | CyberMedica owner |
| Default-off proof feature | `crates/exo-proofs/src/lib.rs` | false ZK claims | no ZK claims | require audited implementation | Exochain cryptography owner |
| CrossChecked anchor shortcut disabled | `crates/exo-node/src/api.rs` | external anchor claims unsupported | no CrossChecked-backed claims | verify enabled path and tests | Exochain node owner |
| Admin governance shortcuts disabled | `crates/exo-node/src/api.rs` | raw admin governance bypass risk | do not expose raw admin governance | use adjudicated governance only | Exochain node owner |
| 0dentity behavioral axes disabled | `crates/exo-node/src/zerodentity/*` | identity scoring overclaim | avoid behavioral axes | validate enabled production path | Exochain identity owner |
| Root production state unknown | `crates/exo-root/*`, user 7/13 clarification | root-backed claims premature | develop service contracts only | verify roster/transcript/bundle/deployment | Bob/root operators |
| Adjacent surfaces un-inventoried | `web/*`, `command-base/*`, `exoforge/*`, `.archon/*` | trust by proximity | quarantine as adjacent | perform intake classification | Surface owner |

CyberMedica production-claim and activation gates are maintained in `docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md`.

## 11. CyberMedica Integration Map

The controlling detailed integration matrix is `docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md`.

This seed permits CyberMedica to map these source-identified primitive families into baseline development service contracts now: tenant registry, DID identity, authority chains, bailment/consent, gatekeeper adjudication, verified quorum/governance audit, legal evidence custody, TrustReceipt, DAG/provenance, Decision Forum adjudicated workflow, and root trust bundle verification. Production activation for root-backed authority still requires the 13-certifier DKG and 7-of-13 signing evidence.

This seed does not permit CyberMedica to claim production support from default-off proofs, default-off CrossChecked anchoring, raw admin governance, 0dentity behavioral/device axes, economy settlement, CommandBase, ExoForge, Archon workflows, or any UI surface unless the companion integration map's runtime-path and test requirements are satisfied.

## 12. CyberMedica Guardrails

1. CyberMedica is an adjacent app, not Exochain core.
2. CyberMedica may rely on Exochain primitives only where those primitives are verified by source path, runtime path, and tests.
3. CyberMedica must not claim Exochain provenance where no receipt path exists.
4. CyberMedica must not anchor raw PHI, PII, sponsor-confidential, or privileged content.
5. CyberMedica must distinguish operational database state from immutable receipts.
6. CyberMedica must treat clinical research QMS controls as evidence-backed objects.
7. CyberMedica must use human governance for launch gates, enrollment gates, CAPA closure, consent controls, and Decision Forum decisions.
8. CyberMedica must preserve AI as assistant, not final authority.
9. CyberMedica must support tenant isolation, authority chains, revocation, contestation, and auditability.
10. CyberMedica implementation tasks must trace to PRD IDs, Exochain primitives, tests, and deployment evidence.
11. CyberMedica baseline development must proceed before 7/13 root activation by using explicit service contracts, deterministic fixtures, inactive trust-claim states, and fail-closed adapters.
12. CyberMedica build tasks must be TDD-first, maintain >90% scoped coverage, and target near-100% coverage on trust boundaries.
13. CyberMedica work must preserve the original PRD/context discipline and must not dilute blocked claims into implied support.
14. CyberMedica work must not alter Exochain source code as part of adjacent-surface implementation.
15. Final root verification gates production activation and claims, not baseline product development.

## 13. Open Questions for Bob

The original submitted question register is `docs/context/EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md`. The council-style disposition is `docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md`. The narrowed Bob-facing escalation list is `docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md`.

Future builders must use the council disposition defaults first and escalate only the items listed in `EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md`.

## 14. Production Claim Gate List

The controlled production-claim gate register is `docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md`.

The headline production gates are root-backed production authority, ZK proof claims, CrossChecked anchoring, raw admin governance, Decision Forum approvals without human gate, clinical consent equivalence, tenant isolation beyond registry metadata, PHI/PII-safe anchoring, authority-backed clinical role claims, Syntaxis-generated workflow enforcement, 0dentity behavioral/device axes, economy settlement, CommandBase enforcement, ExoForge/Archon authority, gateway enforcement without adapter tests, node receipt claims without receipt sync tests, and WASM/browser trust paths for PHI workflows.

## 15. Next-Step Build Prompt

Use this for the next CyberMedica baseline architecture/build pass. Do not wait for final root bundle verification to begin baseline development. Final root verification gates production activation, not service-contract design, local implementation, fixture-backed tests, or inactive trust-state UI.

```text
You are GPT-5.5 Pro acting as the CyberMedica adjacent-surface architect.

Use docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md and companion context files as controlling ground truth. Do not rely on memory or marketing terms. CyberMedica is an adjacent regulated clinical research QMS surface, not Exochain core.

Design baseline CyberMedica against source-identified Exochain primitives: deterministic core types, DID identity, authority delegation, bailment/consent, tenant registry, gatekeeper adjudication, governance quorum/challenges/audit, legal evidence custody, TrustReceipt, DAG/provenance, Decision Forum adjudicated workflows, and deployed receipt/root adapters where tests prove fail-closed behavior. Implement inactive trust-state behavior for primitives whose production runtime path is not yet activated.

Do not claim ZK proofs, CrossChecked anchoring, raw admin governance, 0dentity behavioral axes, economy settlement, CommandBase enforcement, or root-backed production authority unless the specific enabled runtime path and tests are verified.

CyberMedica must develop to service contracts now. Production trust claims stay inactive until the institutional root authority bootstrap is verified: 13 rostered independent certifiers, 100% root genesis FROST Ristretto255 DKG participation, and 7-of-13 threshold signing after genesis.

Produce a TDD-first CyberMedica architecture with PRD traceability, >90% scoped coverage, near-100% trust-boundary coverage, PHI/PII non-anchoring tests, adapter fail-closed tests, Decision Forum human approval tests, consent revocation tests, tenant isolation tests, and deployment readiness gates.
```

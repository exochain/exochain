# EXOCHAIN Tier-One Readiness Audit

> Historical readiness audit. Numeric repo facts in this document predate Wave E
> Basalt; use `tools/repo_truth.sh` and `README.md` for current crate, LOC, test,
> and CI-gate counts.

**Date**: 2026-04-04
**Auditor**: ExoForge Council (automated via exochain.io governance API)
**Live Node**: https://exochain.io (consensus round 14,845 at time of audit)
**Repository**: https://github.com/exochain/exochain
**Commit**: 84b9222 (main)

---

## A. COUNCIL VERDICT

### **APPROVE WITH GAPS**

EXOCHAIN has a substantially implemented constitutional trust fabric (51,628 LoC, 1,603 tests, 16 crates, 8 constitutional invariants enforced, live node operational). All 12 trust-critical capabilities exist in library code with real implementations and tests.

However, tier-one status requires that a **neutral third party can independently verify the full agent trust lifecycle at runtime**. Today, the runtime surface (exo-node + exo-gateway) exposes only a fraction of the library-level trust capabilities. The gap is not implementation — it is **wiring**.

**Blocking gaps**: 6 (detailed in Section D)
**Estimated remediation**: 5 workstreams, ~15 PRs
**Constitutional violations**: 0
**Documentation contradictions**: 9

---

## B. REPOSITORY TRUTH MATRIX

### Live Runtime Facts (verified 2026-04-04)

| Metric | Live Value | Source |
|--------|-----------|--------|
| Node status | ok | `GET https://exochain.io/health` |
| Version | 0.1.0-alpha | `GET https://exochain.io/health` |
| Uptime | 60,574s (~16.8h) | `GET https://exochain.io/health` |
| Consensus round | 14,845 | `GET https://exochain.io/api/v1/governance/status` |
| Validator count | 1 | `GET https://exochain.io/api/v1/governance/status` |
| Node DID | did:exo:Aa4K7EQERE5NmV482eG3ozPtxLk1MmqyBy8teado3tsm | Live API |

### Documentation vs Code

| # | Claim | Source | Actual | Status | Corrective Action |
|---|-------|--------|--------|--------|--------------------|
| 1 | "15 crates" | README.md L15 | 16 (exo-node added) | OUTDATED | Update to 16 |
| 2 | "1,116 library tests" | README.md L18 | 1,603 workspace tests | OUTDATED | Update to 1,603 |
| 3 | "10 CI quality gates" | README.md L19 | 16 in ci.yml | OUTDATED | Update to 16 |
| 4 | "Apache-2.0" license | README.md L21 | AGPL-3.0-or-later in Cargo.toml | CONTRADICTED | Resolve: pick one, update all |
| 5 | "80 requirements" | README.md L30 | 87 in traceability_matrix.md | OUTDATED | Update to 87 |
| 6 | "CR-001 RATIFIED" | README.md L92 | DRAFT per CR-001 header | CONTRADICTED | Either ratify or correct claim |
| 7 | "9 quality gates" in CI ref | README.md L88 | 16 in ci.yml | CONTRADICTED | Update to 16 |
| 8 | "8 CI-enforced gates" | quality_gates.md L98 | 16 in ci.yml | OUTDATED | Update |
| 9 | "exo-gateway binary is placeholder" | README.md L72 | Gateway serves 28 endpoints live | OUTDATED | Gateway is operational |

### Verified Truths

| Claim | Status | Evidence |
|-------|--------|----------|
| "No floating-point arithmetic" | TRUE | `#[deny(clippy::float_arithmetic)]` in Cargo.toml |
| "Deterministic — no HashMap" | TRUE | BTreeMap enforced, canonical CBOR |
| "Post-quantum readiness" | TRUE | ML-DSA-65 via ml-dsa crate, hybrid verification methods |
| "Constitutional invariants enforced" | TRUE | 8 invariants in exo-gatekeeper, Kernel.adjudicate() |
| "Zero admin bypass paths" | TRUE | WO-009 audit with 6 verification tests |
| "14 threats mitigated" | TRUE | threat_matrix.md, all marked implemented |
| "Live distributed node" | TRUE | exochain.io operational, consensus round 14,845 |

---

## C. TIER-ONE CAPABILITY MODEL

### Capability 1: Identity

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-core, exo-identity, exo-node |
| **Key files** | identity/did.rs, identity/did_verification.rs, node/identity.rs |
| **Tests** | 102 (exo-identity) + node identity tests |
| **What works** | DID creation, registration, revocation, key rotation, hybrid Ed25519+ML-DSA-65 verification, persistence on node |
| **What's missing for tier-one** | No runtime API to resolve a DID document externally (library only); no `GET /api/v1/identity/:did/passport` on the node |

### Capability 2: Delegation

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-authority |
| **Key files** | authority/delegation.rs, authority/chain.rs |
| **Tests** | 72 |
| **What works** | Authority chains, scope narrowing, circular detection, depth tracking, expiry, delegatee kind (human/AI) |
| **What's missing for tier-one** | Delegation signature uses placeholder `[1u8; 64]` in one path; no runtime API to create/query delegations on node |

### Capability 3: Consent / Bailment

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-consent |
| **Key files** | consent/bailment.rs, consent/gate.rs, consent/policy.rs |
| **Tests** | 54 |
| **What works** | Full bailment lifecycle (Proposed/Active/Suspended/Terminated/Expired), legal terms binding, default-deny policy, ConsentRequired invariant in gatekeeper |
| **What's missing for tier-one** | No runtime API to manage bailments on node |

### Capability 4: Provenance

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-gatekeeper |
| **Key files** | gatekeeper/types.rs (Provenance struct), gatekeeper/kernel.rs (ProvenanceVerifiable invariant) |
| **Tests** | 217 (gatekeeper total) |
| **What works** | Provenance struct with actor DID, timestamp, action hash, signature; ProvenanceVerifiable invariant enforces all actions have provenance |
| **What's missing for tier-one** | Provenance bundles not yet emitted by node runtime actions; no API to query provenance chain |

### Capability 5: Trust Receipts

| Attribute | Value |
|-----------|-------|
| **Status** | Partial |
| **Crates** | decision-forum |
| **Key files** | decision-forum/decision_object.rs (LifecycleReceipt) |
| **Tests** | 148 (decision-forum total) |
| **What works** | LifecycleReceipt with from_state, to_state, actor_did, timestamp, receipt_hash; receipt chain on decisions |
| **What's missing for tier-one** | Receipts are decision-scoped only; no general-purpose trust receipt for arbitrary agent actions; no receipt query API on node |

### Capability 6: Challenge / Dispute

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-governance |
| **Key files** | governance/challenge.rs |
| **Tests** | 155 (governance total) |
| **What works** | 6 challenge grounds, status state machine (Filed/UnderReview/Sustained/Overruled), pause_action(), adjudicate() |
| **What's missing for tier-one** | No runtime API to file or adjudicate challenges on node |

### Capability 7: Sanctions / Quarantine / Revocation

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-identity, exo-consent, exo-escalation |
| **Key files** | identity/did.rs (revocation), consent/bailment.rs (suspension/termination), escalation/detector.rs (quarantine recommendation) |
| **Tests** | 102 + 54 + 57 = 213 |
| **What works** | DID revocation with proof, bailment suspension/termination, escalation quarantine/shutdown recommendations, Sybil challenge hold |
| **What's missing for tier-one** | No unified sanction status on agent passport; no runtime API to check standing |

### Capability 8: Discovery / Registry

| Attribute | Value |
|-----------|-------|
| **Status** | Partial |
| **Crates** | exo-identity, exo-authority, exo-legal |
| **Key files** | identity/did.rs (DidRegistry), authority/delegation.rs (DelegationRegistry) |
| **Tests** | 102 + 72 + 110 = 284 |
| **What works** | DID registry (in-memory), delegation registry (forward/reverse index), eDiscovery workflow |
| **What's missing for tier-one** | No external resolution endpoint; no `GET /api/v1/agents/:did` returning full trust profile on node (gateway has stub, node doesn't) |

### Capability 9: Attestations / Reputation

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-identity |
| **Key files** | identity/risk.rs (RiskAttestation, RiskPolicy) |
| **Tests** | 102 |
| **What works** | Signed risk attestations (Minimal/Low/Medium/High/Critical), policy enforcement, validity periods, TEE attestation in gatekeeper |
| **What's missing for tier-one** | No runtime API to submit/query attestations; no evidence-linked trust score computation |

### Capability 10: Runtime Verification

| Attribute | Value |
|-----------|-------|
| **Status** | Partial |
| **Crates** | exo-node |
| **Key files** | node/network.rs, node/wire.rs, node/reactor.rs |
| **Tests** | 64 |
| **What works** | P2P networking, gossipsub messaging, identify protocol with DID in agent version, consensus votes with signatures |
| **What's missing for tier-one** | Wire message signatures use `blake3::hash` placeholder (not Ed25519); no mutual DID verification between peers; no revocation-aware peer acceptance |

### Capability 11: Operator Oversight

| Attribute | Value |
|-----------|-------|
| **Status** | Implemented |
| **Crates** | exo-gatekeeper, exo-node |
| **Key files** | gatekeeper/kernel.rs (HumanOverride invariant), node/api.rs (governance API), node/holons.rs (kernel adjudication) |
| **Tests** | 217 + 64 = 281 |
| **What works** | HumanOverride invariant, validator management API, Holon actions gated by kernel adjudication, governance monitor with circuit breaker |
| **What's missing for tier-one** | No role-based access on governance API (anyone can call endpoints) |

### Capability 12: Claim Discipline

| Attribute | Value |
|-----------|-------|
| **Status** | FAILING |
| **Evidence** | 9 contradictions in truth matrix above |
| **What's missing** | README contains 9 outdated or contradicted claims; license conflict unresolved; CR-001 ratification status misrepresented |

---

## D. BLOCKING GAPS

### Gap 1: No Agent Passport API (TRUST-CRITICAL)

**What**: Library crates implement identity, delegation, consent, attestations, and sanctions — but the running node exposes none of this via HTTP. A third party cannot resolve an agent's trust profile at runtime.

**Why it blocks**: Tier-one requires "a neutral third party can independently verify who an agent is, what scope it holds, and what trust standing it has."

**Crates**: exo-node (api.rs), drawing from exo-identity, exo-authority, exo-consent

**Scope**: 1 new API module (~300 LoC), 4 endpoints, 8 tests

### Gap 2: No Trust Receipt Emission (TRUST-CRITICAL)

**What**: LifecycleReceipt exists in decision-forum but is scoped to governance decisions only. No general-purpose signed receipt for arbitrary agent actions (e.g., "agent X read data Y under authority Z with consent W").

**Why it blocks**: Tier-one requires "what trust receipts and challenge history exist."

**Crates**: exo-core (new receipt type), exo-node (receipt emission + query API)

**Scope**: 1 new type (~150 LoC), 1 API endpoint, 6 tests

### Gap 3: Wire Protocol Uses Placeholder Signatures (RUNTIME-CRITICAL)

**What**: Consensus votes and governance broadcasts use `blake3::hash` as signature, not Ed25519. Peer identity binding is via libp2p identify only, not DID-verified.

**Why it blocks**: Tier-one requires "no peer-to-peer trust path relies on placeholder signature checks."

**Crates**: exo-node (reactor.rs, wire.rs, network.rs)

**Scope**: Modify 3 files, replace placeholder sign_fn with real Ed25519 in test harnesses, verify production sign_fn uses actual keys

### Gap 4: Documentation Contradictions (CLAIM-CRITICAL)

**What**: 9 contradictions between README and actual code/governance artifacts.

**Why it blocks**: Tier-one requires "no externally visible contradiction between docs, code, and CI."

**Scope**: Update README.md, resolve license conflict, clarify CR-001 status

### Gap 5: No API Authentication (RUNTIME-CRITICAL)

**What**: Governance API endpoints (`/api/v1/governance/propose`, `/validators`) have no authentication. Anyone who can reach the node can submit proposals or modify the validator set.

**Why it blocks**: Tier-one requires "the system prevents impersonation and self-escalation."

**Crates**: exo-node (api.rs)

**Scope**: Add DID-signed request verification middleware, ~200 LoC, 4 tests

### Gap 6: License Conflict (CLAIM-CRITICAL)

**What**: LICENSE file and README say Apache-2.0. Cargo.toml workspace says AGPL-3.0-or-later.

**Why it blocks**: Legal uncertainty undermines external credibility.

**Scope**: Council decision on license, then update all files to match

---

## E. IMPLEMENTATION PLAN

### Workstream 0: Documentation Truth Unification

**Goal**: Eliminate all contradictions between docs, code, and CI.

**Files to modify**:
- `README.md` — update crate count (16), test count (1,603), CI gate count (16), requirement count (87), gateway status, license
- `governance/quality_gates.md` — update gate count
- `docs/architecture/ARCHITECTURE.md` — update LOC, file count, test count

**Files to create**:
- None

**Tests to add**:
- None (documentation only)

**Dependencies**: License decision from council (Gap 6)

**Exit condition**: `grep -c` for old counts returns 0; all numeric claims match `tools/repo_truth.sh` output

---

### Workstream 1: Agent Passport API

**Goal**: External resolution of agent identity, scope, and trust standing via HTTP.

**Files to modify**:
- `crates/exo-node/src/api.rs` — add passport endpoints
- `crates/exo-node/src/main.rs` — wire passport state into NodeApiState

**Files to create**:
- `crates/exo-node/src/passport.rs` — Agent passport model aggregating identity + delegation + consent + attestation + sanction state

**Endpoints to add**:
- `GET /api/v1/agents/:did/passport` — full trust profile
- `GET /api/v1/agents/:did/delegations` — active authority chains
- `GET /api/v1/agents/:did/consent` — active bailments/consent records
- `GET /api/v1/agents/:did/standing` — sanctions, quarantine, revocation status

**Tests to add**:
1. Passport returns identity for known DID
2. Passport returns 404 for unknown DID
3. Delegations endpoint returns authority chain
4. Consent endpoint returns active bailments
5. Standing endpoint returns clean for non-sanctioned agent
6. Standing endpoint returns quarantined for sanctioned agent
7. Passport reflects revoked DID correctly
8. Passport includes attestation summary

**Dependencies**: None (uses existing library crates)

**Exit condition**: `curl https://exochain.io/api/v1/agents/{did}/passport` returns complete trust profile with identity, scope, consent, and standing.

---

### Workstream 2: Trust Receipt Emission

**Goal**: Every material agent action emits a signed, machine-verifiable trust receipt.

**Files to modify**:
- `crates/exo-core/src/types.rs` — add TrustReceipt type
- `crates/exo-node/src/reactor.rs` — emit receipt on commit
- `crates/exo-node/src/api.rs` — add receipt query endpoint

**Files to create**:
- None (types go in exo-core, API goes in existing api.rs)

**Receipt fields**:
- `actor_did: Did`
- `authority_chain_hash: Hash256`
- `consent_reference: Option<Hash256>`
- `action_type: String`
- `action_hash: Hash256`
- `outcome: ReceiptOutcome`
- `timestamp: HybridLogicalClock`
- `signature: Signature`
- `challenge_reference: Option<Hash256>`

**Endpoints to add**:
- `GET /api/v1/receipts/:hash` — retrieve a specific receipt
- `GET /api/v1/receipts?actor={did}&from={ts}&to={ts}` — query receipts by actor/time

**Tests to add**:
1. Receipt creation with valid signature
2. Receipt serialization roundtrip (CBOR)
3. Receipt emitted on node commit
4. Receipt query by hash returns correct receipt
5. Receipt query by actor returns filtered set
6. Receipt includes challengeability reference

**Dependencies**: None

**Exit condition**: `curl https://exochain.io/api/v1/receipts?actor={did}` returns signed receipts for that agent's actions.

---

### Workstream 3: Wire Protocol Cryptographic Verification

**Goal**: Replace placeholder signatures with real Ed25519 in consensus messages.

**Files to modify**:
- `crates/exo-node/src/reactor.rs` — verify vote signatures against voter DID
- `crates/exo-node/src/wire.rs` — add signature verification on deserialization
- `crates/exo-node/src/network.rs` — add DID-based peer verification on identify

**Tests to add**:
1. Vote with invalid signature is rejected
2. Vote with valid signature is accepted
3. Governance event with forged sender is rejected
4. Peer identify with mismatched DID is rejected
5. Replay of old message is detected (nonce/sequence)

**Dependencies**: None

**Exit condition**: Sending a consensus vote with an incorrect signature to the node results in rejection (not acceptance).

---

### Workstream 4: API Authentication

**Goal**: Governance API requires DID-signed requests to prevent unauthorized access.

**Files to modify**:
- `crates/exo-node/src/api.rs` — add auth middleware
- `crates/exo-node/src/main.rs` — apply middleware to governance routes

**Tests to add**:
1. Unauthenticated request to `/propose` returns 401
2. Correctly signed request to `/propose` returns 200
3. Request signed by non-validator to `/validators` returns 403
4. Expired signature is rejected

**Dependencies**: Workstream 3 (same signing infrastructure)

**Exit condition**: `curl -X POST https://exochain.io/api/v1/governance/propose` without auth header returns 401.

---

## F. FIRST THREE PR-SIZED SLICES

### PR 1: Documentation Truth Unification

**Title**: `fix(docs): reconcile all claims with code ground truth`

**Purpose**: Eliminate 9 documented contradictions; establish claim discipline.

**Files touched**:
- `README.md`
- `governance/quality_gates.md`
- `docs/architecture/ARCHITECTURE.md`
- `docs/audit/REPO-TRUTH-BASELINE.md`

**Tests required**: None (docs only)

**Merge gate**: Zero contradictions between README numeric claims and `cargo test --workspace` / `ls crates/` / CI gate count

**Demo**: README accurately reflects crate count (16), test count (1,603+), CI gate count (16)

---

### PR 2: Agent Passport API

**Title**: `feat(api): agent passport resolution endpoint`

**Purpose**: Enable external resolution of agent trust profile — the core tier-one capability.

**Files touched**:
- `crates/exo-node/src/passport.rs` (new)
- `crates/exo-node/src/api.rs`
- `crates/exo-node/src/main.rs`

**Tests required**: 8 tests (listed in Workstream 1)

**Merge gate**: `cargo test -p exo-node` passes; `GET /api/v1/agents/:did/passport` returns valid JSON with identity, scope, consent, standing

**Demo**: `curl https://exochain.io/api/v1/agents/did:exo:Aa4K7EQERE5NmV482eG3ozPtxLk1MmqyBy8teado3tsm/passport` returns the live node's full trust profile

---

### PR 3: Trust Receipt Type and Emission

**Title**: `feat(core): trust receipt type and consensus emission`

**Purpose**: Every committed action produces a signed, queryable trust receipt.

**Files touched**:
- `crates/exo-core/src/types.rs`
- `crates/exo-node/src/reactor.rs`
- `crates/exo-node/src/api.rs`
- `crates/exo-node/src/store.rs`

**Tests required**: 6 tests (listed in Workstream 2)

**Merge gate**: `cargo test --workspace` passes; receipts table populated on commit; `GET /api/v1/receipts/:hash` returns valid receipt

**Demo**: Submit a governance proposal, observe receipt emitted, query it via API

---

## G. DOCUMENTATION CORRECTIONS

### README.md Repo Status Table (replace lines 13-21)

```markdown
| Metric | Value | Source |
|--------|-------|--------|
| Rust crates | 16 | `ls -d crates/*/` |
| Rust source files | 178 | `find crates -name '*.rs'` |
| Rust LOC | ~112,000 | `wc -l` |
| Workspace tests | 1,603 passing, 0 failing | `cargo test --workspace` |
| CI quality gates | 16 | `.github/workflows/ci.yml` |
| Published releases | None (pre-release) | `git tag -l` |
| License | AGPL-3.0-or-later | `Cargo.toml` |
| Live node | https://exochain.io | Fly.io deployment |
```

### README.md Line 30 (replace)

```markdown
- **Traceability matrix** maps 87 requirements — see `governance/traceability_matrix.md`
```

### README.md Line 64 (replace)

```markdown
### Core Crates (16)
```

Add after exochain-wasm row:

```markdown
| `exo-node` | Distributed P2P node: consensus, networking, governance API, dashboard |
```

### README.md Line 88 (replace)

```markdown
* **`.github/workflows/`** — CI pipeline (16 quality gates), release workflow, ExoForge triage
```

### README.md Line 92 (replace with accurate status)

```markdown
This repository is managed under strict **Judicial Build Governance**. All contributions must align with `EXOCHAIN_Specification_v2.2.pdf`. CR-001 (AEGIS/SYBIL/Authentic Plurality) is **DRAFT — pending council ratification**.
```

### README.md Line 98 (replace)

```markdown
* [Quality Gates](governance/quality_gates.md) — 16 CI-enforced gates
```

---

## H. TIER-ONE EXIT CHECKLIST

| # | Criterion | Verification | Pass |
|---|-----------|-------------|------|
| 1 | `cargo test --workspace` passes with 0 failures | Run command | [ ] |
| 2 | `cargo check --workspace` produces 0 warnings | Run command | [ ] |
| 3 | Zero contradictions between README and code | Diff README claims against `tools/repo_truth.sh` | [ ] |
| 4 | License field is consistent across LICENSE, Cargo.toml, README | `grep -r "Apache\|AGPL" LICENSE Cargo.toml README.md` | [ ] |
| 5 | `GET /api/v1/agents/:did/passport` returns identity, scope, consent, standing | `curl https://exochain.io/api/v1/agents/{did}/passport` | [ ] |
| 6 | `GET /api/v1/agents/:did/delegations` returns authority chain | `curl` endpoint | [ ] |
| 7 | `GET /api/v1/agents/:did/standing` returns sanctions/revocation status | `curl` endpoint | [ ] |
| 8 | `GET /api/v1/receipts/:hash` returns a signed trust receipt | `curl` endpoint after commit | [ ] |
| 9 | Trust receipt includes actor, authority chain, consent ref, signature | Inspect receipt JSON fields | [ ] |
| 10 | Consensus vote with invalid signature is rejected by node | Send forged vote, verify rejection in logs | [ ] |
| 11 | Governance API rejects unauthenticated requests | `curl -X POST .../propose` without auth returns 401 | [ ] |
| 12 | Validator set change by non-validator is rejected | `curl -X POST .../validators` without validator auth returns 403 | [ ] |
| 13 | DID revocation is reflected in passport standing | Revoke DID, query passport, verify standing=revoked | [ ] |
| 14 | Delegation scope narrowing is enforced at runtime | Create delegation with narrowed scope, verify via API | [ ] |
| 15 | End-to-end trust lifecycle: create agent → delegate → act → receipt → challenge → ruling | Execute full sequence, verify each step via API | [ ] |
| 16 | All documentation claims match implementation | Automated diff check | [ ] |

---

## I. WHAT IS ALREADY CONSTITUTIONALLY STRONG

These require no remediation — they are production-grade:

1. **Kernel adjudication** — 8 invariants, single codepath, immutable after creation, 217 tests
2. **Default-deny consent** — ConsentRequired invariant, bailment lifecycle, policy engine
3. **No-self-grant** — NoSelfGrant invariant prevents privilege escalation
4. **Determinism** — No floats, no HashMap, canonical CBOR, HLC clocks
5. **Separation of powers** — SeparationOfPowers invariant, three-branch model
6. **Challenge mechanics** — 6 grounds, adjudication, pause orders, verdicts
7. **Provenance model** — Provenance struct with signature verification, ProvenanceVerifiable invariant
8. **Post-quantum readiness** — ML-DSA-65 integrated, hybrid verification methods
9. **Zero admin bypass** — Audited and verified (WO-009, 6 tests)
10. **Live distributed node** — P2P networking, BFT consensus, persistent state, operational at exochain.io

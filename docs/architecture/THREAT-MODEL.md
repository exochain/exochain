---
title: "EXOCHAIN Threat Model"
status: active
created: 2026-03-18
tags: [exochain, security, threat-model, sybil, architecture]
---

# Threat Model

**12-threat taxonomy for the EXOCHAIN constitutional trust fabric, organized per [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] Section 8.2.**

> Cross-references: [[ARCHITECTURE]], [[CRATE-REFERENCE]], [[GETTING-STARTED]], [[CONSTITUTIONAL-PROOFS]]

---

## Overview

EXOCHAIN's threat model is rooted in the AEGIS (Adversarial Exclusion through Governance, Identity, and Sybil-defense) framework defined in [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]]. The model identifies 12 distinct threats across two families:

- **Sybil Family (Threats 1-6):** Attacks exploiting identity multiplication or independence fabrication
- **Structural Threats (Threats 7-12):** Attacks targeting the constitutional architecture itself

Every threat maps to specific crate-level defenses, detection signals, downgrade behaviors (fail-safe to deny), and verified test coverage.

### Design Principles

1. **Default-Deny.** Every operation starts from a posture of denial. Access requires explicit consent (bailment), verified identity, and kernel adjudication.
2. **Defense in Depth.** No single defense is sufficient. Every threat is mitigated by multiple layers.
3. **Fail-Safe Degradation.** When a defense is uncertain, the system downgrades to a more restrictive posture rather than granting access.
4. **Cryptographic Binding.** Every claim is bound to cryptographic evidence. Assertions without proof are rejected.

---

## Sybil Family (Threats 1-6)

### Threat 1: Identity Sybil

**One actor creates multiple DIDs to appear as multiple independent entities.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | DID registration in `exo-identity::did::DidRegistry`. An attacker generates multiple Ed25519 keypairs and registers a DID for each, presenting them as distinct participants. |
| **Mitigations** | (1) `exo-identity::risk` provides signed risk attestations; new DIDs start at elevated risk until they accumulate behavioral history. (2) `exo-identity::shamir` splits verification secrets across multiple independent parties (k-of-n); a single actor cannot fabricate the required threshold of independent shares. (3) `exo-governance::quorum` weights votes by independence attestation; DIDs lacking independence evidence contribute zero weight. (4) `exo-escalation::detector` monitors for behavioral clustering (multiple DIDs exhibiting identical action patterns). |
| **Detection Signals** | Temporal clustering of DID registrations from similar network origins. Identical behavioral patterns across DIDs (same action sequences, timing distributions). Failure to provide independent Shamir shares during crosscheck. Risk attestation scores remaining elevated across multiple assessment cycles. |
| **Downgrade Behavior** | Suspected Sybil DIDs are quarantined by `exo-escalation`. Their votes carry zero weight in `exo-governance::quorum`. Their bailments in `exo-consent` are suspended. The system continues operating with reduced participation rather than accepting potentially fraudulent identities. |
| **Test Coverage** | `exo-identity`: DID registry rejects duplicate DIDs; risk attestation flags new DIDs as elevated. `exo-governance`: quorum computation discounts votes without independence attestation. `exo-escalation`: Sybil adjudication 7-stage pipeline completeness tests. |
| **Defending Crates** | `exo-identity`, `exo-governance`, `exo-escalation` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 9 (Sybil Resistance), [[CRATE-REFERENCE]] Sections 5, 6, 9

---

### Threat 2: Review Sybil

**One actor provides multiple independent-seeming reviews, assessments, or attestations.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-governance::crosscheck` and `exo-governance::quorum`. An attacker controlling multiple DIDs submits apparently independent reviews that are actually coordinated, artificially inflating consensus. |
| **Mitigations** | (1) `exo-governance::crosscheck` requires crosscheck responses from independently attested parties; responses from DIDs with shared independence graphs are merged rather than counted separately. (2) `exo-identity::risk` tracks review history; statistically anomalous agreement patterns trigger elevated risk scores. (3) `exo-governance::audit` maintains a hash-chained log of all reviews; post-hoc analysis can detect coordination. (4) `exo-legal::conflict_disclosure` requires disclosure for actions including "approve" and "adjudicate". |
| **Detection Signals** | Suspiciously high agreement rate among a subset of reviewers. Reviews submitted within narrow time windows. Identical or near-identical review content across different DIDs. Crosscheck responses that arrive in coordination patterns. |
| **Downgrade Behavior** | Crosscheck results are marked as `Disputed` rather than `Confirmed` when independence cannot be verified. The system requires additional independent verifiers before proceeding. Reviews from disputed DIDs are excluded from quorum calculation. |
| **Test Coverage** | `exo-governance`: crosscheck evaluation rejects responses without independence attestation; quorum discounts non-independent votes; audit chain verifies review provenance. `exo-legal`: conflict disclosure tests for approval actions. |
| **Defending Crates** | `exo-governance`, `exo-identity`, `exo-legal` |

> See also: [[CRATE-REFERENCE]] Sections 6, 5, 10

---

### Threat 3: Quorum Sybil

**Manipulating vote counts through fake independence to meet or exceed quorum thresholds.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-governance::quorum`. An attacker attempts to push a proposal past the quorum threshold by casting votes from multiple Sybil DIDs, each claiming independence. |
| **Mitigations** | (1) `exo-governance::quorum::compute_quorum()` performs independence-aware counting: votes without valid `IndependenceAttestation` are not counted toward the threshold. (2) Quorum requires a minimum number of participants (not just a percentage), preventing a small number of colluding actors from meeting quorum alone. (3) `exo-governance::challenge` allows any participant to challenge a quorum decision, triggering re-evaluation with heightened independence scrutiny. (4) `decision-forum::constitution::enforce_constitution()` verifies quorum decisions against the `QuorumLegitimate` invariant before enactment. |
| **Detection Signals** | Quorum reached with minimum possible participants. Large proportion of votes arriving within a narrow time window. Independence attestations referencing the same or overlapping verification chains. Challenge filings from established participants disputing quorum legitimacy. |
| **Downgrade Behavior** | If quorum legitimacy is challenged and cannot be re-verified, the decision reverts to `Deliberating` status. The quorum threshold is temporarily raised (requiring more participants). The matter is escalated to `exo-escalation` with `EscalationPath::Constitutional`. |
| **Test Coverage** | `exo-governance`: quorum computation with and without independence attestation; minimum participant enforcement; challenge lifecycle. `decision-forum`: constitutional enforcement rejects decisions with illegitimate quorum. `exo-gatekeeper`: `QuorumLegitimate` invariant check. |
| **Defending Crates** | `exo-governance`, `decision-forum`, `exo-gatekeeper` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 7 (Quorum Legitimacy), [[CRATE-REFERENCE]] Sections 6, 13, 2

---

### Threat 4: Delegation Sybil

**Inflating authority through circular or fake delegation chains.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-authority::delegation` and `exo-authority::chain`. An attacker creates a circular delegation (A delegates to B, B delegates to C, C delegates to A) or fabricates delegation links to accumulate authority beyond what any single root granted. |
| **Mitigations** | (1) `exo-authority::chain::AuthorityChain::verify()` walks the entire chain from root to leaf, verifying that each link's scope is a strict subset of its parent's scope. Circular chains fail verification because they cannot terminate at a recognized root. (2) `exo-authority::delegation::DelegationRegistry::delegate()` enforces that the granted scope must be a subset of the grantor's current permissions (via `PermissionSet::is_subset_of()`). (3) `exo-gatekeeper::kernel` checks `AuthorityChainValid` and `NoSelfGrant` invariants on every action. (4) `exo-authority::cache::ChainCache` caches verified chains, so re-verification is efficient but re-computed if the chain changes. |
| **Detection Signals** | Chain verification failures during delegation attempts. Delegation requests where the scope is not a strict subset of the grantor's permissions. Chains that exceed a configurable maximum depth. Multiple delegation attempts from the same actor to different grantees with identical scope. |
| **Downgrade Behavior** | Invalid delegation chains cause immediate action denial. The offending delegation is rejected (never stored). If an existing chain becomes invalid (e.g., a link is revoked), all downstream delegations are invalidated. The cache entry is evicted, forcing re-verification. |
| **Test Coverage** | `exo-authority`: chain verification (valid, circular, broken), scope narrowing enforcement, delegation create/revoke, permission subset algebra. `exo-gatekeeper`: `AuthorityChainValid` and `NoSelfGrant` invariant tests. |
| **Defending Crates** | `exo-authority`, `exo-gatekeeper` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 5 (Authority Chain Integrity), [[CRATE-REFERENCE]] Sections 7, 2

---

### Threat 5: Mesh Sybil

**Inflating peer count in the P2P network to gain disproportionate influence over consensus.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-api::p2p::PeerRegistry` and `exo-dag::consensus`. An attacker runs many nodes with distinct peer IDs, inflating the apparent network size. In BFT consensus, this could shift the fault tolerance boundary (f < n/3) by increasing n with attacker-controlled nodes. |
| **Mitigations** | (1) `exo-dag::consensus::ConsensusConfig` defines the validator set explicitly as a `BTreeSet<Did>`. Only validators in the set can propose or vote; adding new validators requires governance approval through `exo-governance`. (2) `exo-api::p2p::PeerRegistry` tracks peer liveness but does not grant consensus participation. Peer registration is separate from validator admission. (3) `exo-identity::risk` applies risk assessment to peer DIDs; high-risk peers are excluded from relay priority. (4) `exo-dag::consensus` requires >2/3 validator votes for finalization; even if the peer count is inflated, only admitted validators influence consensus. |
| **Detection Signals** | Rapid increase in peer registrations from similar network segments. Peers that register but never participate in data relay. Heartbeat patterns suggesting coordinated infrastructure (identical timing). Peer DIDs with elevated risk scores. |
| **Downgrade Behavior** | Peer count inflation has no effect on consensus because the validator set is fixed. Non-validator peers may be rate-limited or deprioritized but cannot affect finalization. If the validator set itself is suspected of compromise, an Emergency escalation (`exo-escalation::EscalationPath::Emergency`) freezes consensus and activates PACE failover. |
| **Test Coverage** | `exo-dag`: consensus quorum requires >2/3 of validators (not peers); vote counting excludes non-validators. `exo-api`: peer registration/heartbeat; peer count does not affect consensus config. `exo-escalation`: emergency path activation. |
| **Defending Crates** | `exo-dag`, `exo-api`, `exo-governance`, `exo-escalation` |

> See also: [[CRATE-REFERENCE]] Sections 3, 14, 6, 9

---

### Threat 6: Synthetic-Opinion Sybil

**AI-generated reviews or assessments presented as independent human judgment.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-governance::crosscheck`, `exo-governance::deliberation`, and any governance process that weighs human opinions. An attacker uses large language models to generate plausible but synthetic reviews, assessments, or deliberation contributions, presenting them as independent human judgment. |
| **Mitigations** | (1) `exo-gatekeeper::mcp` enforces Model Context Protocol rules on all AI model actions. AI-generated content must be labeled as such; unlabeled AI content violates MCP rules. (2) `exo-proofs::zkml` provides zero-knowledge ML verification: an attestation can prove whether content was generated by a specific model without revealing the model weights. (3) `exo-identity::risk` flags DIDs whose contribution patterns are statistically consistent with automated generation (high volume, uniform quality distribution, timing regularity). (4) `exo-governance::crosscheck` requires that at least a configurable minimum of crosscheck verifiers pass human-verification challenges (PACE-authenticated human-in-the-loop). |
| **Detection Signals** | Contributions with statistically uniform quality and style metrics. High-volume review submission from a single DID. MCP audit trail showing AI model interaction preceding review submission. ZKML attestation mismatches (claimed human output but model hash matches known LLM). |
| **Downgrade Behavior** | Content identified as synthetic without disclosure is excluded from deliberation and quorum. The contributing DID's risk level is elevated to Critical. An escalation case is opened with `EscalationPath::SybilAdjudication`, requiring the full 7-stage adjudication pipeline. Human-in-the-loop review is required before the DID can resume participation. |
| **Test Coverage** | `exo-gatekeeper`: MCP rule evaluation detects unlabeled AI content. `exo-proofs`: ZKML attestation verification (valid/invalid model commitments). `exo-identity`: risk elevation for anomalous contribution patterns. `exo-escalation`: Sybil adjudication pipeline completeness for synthetic-opinion cases. |
| **Defending Crates** | `exo-gatekeeper`, `exo-proofs`, `exo-identity`, `exo-escalation` |

> See also: [[CRATE-REFERENCE]] Sections 2, 4, 5, 9

---

## Structural Threats (Threats 7-12)

### Threat 7: Consent Bypass

**Attempting to access resources or perform actions without valid bailment consent.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-consent::gatekeeper::ConsentGate` and `exo-gateway::middleware`. An attacker attempts to reach resource handlers without passing through the consent gate, or presents an expired/suspended/forged bailment. |
| **Mitigations** | (1) `exo-consent` enforces a default-deny posture: `ConsentGate::check()` requires an active bailment (status == `Active`) for the specific actor-resource pair before any action proceeds. (2) `exo-gateway::middleware::GatewayMiddleware::process()` chains auth -> consent -> kernel adjudication; consent is a mandatory middleware step that cannot be skipped. (3) `exo-gatekeeper::kernel` independently checks the `ConsentRequired` invariant during adjudication; even if the middleware is somehow bypassed, the kernel rejects unconsented actions. (4) `exo-consent::bailment` enforces strict lifecycle transitions: a bailment cannot jump from `Proposed` to `Active` without bailor signature, and expired bailments cannot be used. |
| **Detection Signals** | Action requests arriving without associated bailment records. Bailment IDs referencing non-existent or expired agreements. Attempts to use suspended bailments. Patterns of repeated consent check failures from the same DID. |
| **Downgrade Behavior** | Actions without valid consent are immediately denied. No partial access is granted. The denial is recorded in the audit trail with evidence of the consent gap. Repeated failures trigger risk elevation in `exo-identity::risk`. |
| **Test Coverage** | `exo-consent`: bailment lifecycle (all valid/invalid transitions), default-deny enforcement, expired bailment rejection. `exo-gateway`: middleware chain deny tests. `exo-gatekeeper`: `ConsentRequired` invariant check. |
| **Defending Crates** | `exo-consent`, `exo-gateway`, `exo-gatekeeper` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 4 (Consent Completeness), [[CRATE-REFERENCE]] Sections 8, 11, 2

---

### Threat 8: Authority Escalation

**Attempting to widen delegated scope beyond what was granted, or to self-grant permissions.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-authority::delegation` and `exo-authority::chain`. An attacker holding a narrowly-scoped delegation attempts to perform actions outside that scope, or creates a delegation granting themselves broader permissions than they hold. |
| **Mitigations** | (1) `exo-authority::delegation::DelegationRegistry::delegate()` verifies that the new delegation's scope is a subset of the grantor's current permissions using `PermissionSet::is_subset_of()`. A delegation that would widen scope is rejected at creation time. (2) `exo-authority::chain::AuthorityChain::effective_permissions()` computes the intersection of all link permissions, guaranteeing that the effective scope can only narrow along the chain. (3) `exo-gatekeeper::kernel` checks `NoSelfGrant` on every adjudication: an actor cannot create a delegation with themselves as both grantor and grantee. (4) `exo-gatekeeper::kernel` checks `AuthorityChainValid` on every adjudication: the chain must terminate at a recognized root with verified signatures. |
| **Detection Signals** | Delegation creation failures due to scope widening attempts. Actions denied due to authority chain validation failure. Self-delegation attempts (grantor == grantee). Chains that cannot be traced to a recognized root authority. |
| **Downgrade Behavior** | Scope widening attempts are immediately rejected. The existing delegation remains unchanged. The attempt is logged in the audit trail. Repeated attempts trigger risk elevation and potential escalation to `EscalationPath::Constitutional`. |
| **Test Coverage** | `exo-authority`: scope narrowing enforcement (subset check), self-delegation prevention, chain verification with expired/broken links. `exo-gatekeeper`: `NoSelfGrant` and `AuthorityChainValid` invariant tests. |
| **Defending Crates** | `exo-authority`, `exo-gatekeeper` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 5 (Authority Chain Integrity), [[CRATE-REFERENCE]] Sections 7, 2

---

### Threat 9: Kernel Tampering

**Attempting to modify the immutable judicial branch (kernel configuration, invariant definitions, or adjudication logic) after initialization.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-gatekeeper::kernel::Kernel` and `exo-gatekeeper::invariants`. An attacker with code-level access attempts to modify the kernel configuration, disable invariants, or alter the adjudication logic after the kernel has been created. |
| **Mitigations** | (1) `exo-gatekeeper::kernel::KernelConfig` is frozen at creation: the `Kernel` struct stores its configuration immutably, and no public API allows modification after construction. (2) The `KernelImmutability` invariant is self-enforcing: any action that would modify the kernel must be adjudicated by the kernel itself, which checks `KernelImmutability` and rejects the modification. (3) `exo-gatekeeper::invariants::InvariantSet::all()` returns the full set of invariants; there is no `remove()` operation on the kernel's invariant set. (4) At the Rust language level, `unsafe_code = "deny"` prevents memory-unsafe kernel modification, and the absence of interior mutability in the kernel struct prevents runtime mutation. |
| **Detection Signals** | Actions targeting kernel configuration resources are immediately denied. Any adjudication context referencing kernel modification is flagged. Configuration hash mismatches between expected and actual kernel state (if the kernel were somehow modified, its hash would change). |
| **Downgrade Behavior** | Kernel tampering attempts are denied and escalated to `EscalationPath::Constitutional`. The kernel continues operating with its original configuration. There is no "degraded kernel" mode; the kernel is either intact or the system halts. |
| **Test Coverage** | `exo-gatekeeper`: `KernelImmutability` invariant check; kernel construction freezes config; no public API allows post-construction modification; kernel adjudication rejects self-modification actions. |
| **Defending Crates** | `exo-gatekeeper` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 3 (Kernel Immutability), [[CRATE-REFERENCE]] Section 2

---

### Threat 10: Receipt Chain Forgery

**Attempting to tamper with the BCTS transaction history by modifying, inserting, or deleting receipts in the chain.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-core::bcts::BctsTransaction` and `exo-dag`. An attacker attempts to alter the receipt chain to hide a past action, forge a state transition that did not occur, or insert a receipt into someone else's transaction history. |
| **Mitigations** | (1) `exo-core::bcts::BctsReceipt` includes the hash of the previous receipt in the chain. Any modification to a past receipt changes its hash, breaking the chain at the next link. `BctsTransaction::verify_receipt_chain()` detects this. (2) `exo-dag::dag::Dag` stores transactions in an append-only DAG. Nodes cannot be modified or deleted after insertion; the `Dag::append()` method only adds nodes. (3) `exo-dag::smt::SparseMerkleTree` provides authenticated state: the SMT root hash commits to the entire key-value store, so any modification changes the root. (4) `exo-dag::mmr::MerkleMountainRange` provides append-only accumulation with membership proofs. (5) `exo-governance::audit` maintains a parallel hash-chained audit log; `verify_chain()` independently validates the governance audit trail. |
| **Detection Signals** | Receipt chain verification failure (hash mismatch between adjacent receipts). DAG node hash not matching computed hash from contents. SMT proof verification failure against known root. MMR membership proof failure. Audit chain `verify_chain()` returning broken chain errors. |
| **Downgrade Behavior** | Transactions with broken receipt chains are rejected. The `ProvenanceVerifiable` invariant causes the kernel to deny any action whose provenance cannot be cryptographically verified. The system continues operating with verified transactions only; unverifiable transactions are quarantined for investigation. |
| **Test Coverage** | `exo-core`: receipt chain hash-linking, `verify_receipt_chain()` detects tampering, invalid state transition rejection. `exo-dag`: DAG append-only enforcement, SMT proof generation/verification, MMR proof generation/verification. `exo-governance`: audit chain append/verify, broken chain detection. `exo-gatekeeper`: `ProvenanceVerifiable` invariant tests. |
| **Defending Crates** | `exo-core`, `exo-dag`, `exo-governance`, `exo-gatekeeper` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 8 (Provenance Verifiable), [[CRATE-REFERENCE]] Sections 1, 3, 6, 2

---

### Threat 11: Clock Manipulation

**Attempting to exploit Hybrid Logical Clock ordering to reorder events, create future-dated transactions, or cause causal ordering violations.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `exo-core::hlc::HybridClock`. An attacker attempts to forge timestamps with inflated physical clock values (future-dating), manipulate logical counters to reorder events, or present old timestamps to replay past actions. |
| **Mitigations** | (1) `exo-core::hlc::HybridClock::now()` guarantees monotonicity: each call returns a timestamp strictly greater than any prior timestamp on the same node (physical_ms is max of local and prior, logical counter increments). (2) `exo-core::hlc::HybridClock::receive()` merges remote timestamps by taking the maximum physical time and incrementing the logical counter, preventing remote clocks from being used to regress the local clock. (3) `exo-core::types::Timestamp` uses integer arithmetic only (physical_ms: u64, logical: u32, node_id: u16) -- no floating-point clock drift. (4) The BCTS receipt chain provides a secondary ordering mechanism: even if timestamps are manipulated, the receipt hash chain enforces a strict causal order. (5) `exo-dag::consensus` finalizes DAG nodes through BFT voting, providing a third independent ordering that is not susceptible to single-node clock manipulation. |
| **Detection Signals** | Timestamps that jump significantly ahead of the local clock's expectation. Logical counter values that are unexpectedly high. Nodes presenting timestamps that conflict with BFT-finalized ordering. Receipt chain ordering inconsistent with HLC ordering. |
| **Downgrade Behavior** | Transactions with suspicious timestamps are flagged but not immediately rejected (clock skew is normal in distributed systems). However, BFT consensus provides the authoritative ordering. If a node consistently presents anomalous timestamps, it is flagged for investigation by `exo-escalation::detector` and may have its risk score elevated. |
| **Test Coverage** | `exo-core`: HLC monotonicity tests (now() always increases), receive() merge tests (never decreases), timestamp comparison ordering. `exo-core::bcts`: receipt chain ordering tests. `exo-dag`: consensus finalization provides authoritative ordering independent of individual node clocks. |
| **Defending Crates** | `exo-core`, `exo-dag`, `exo-escalation` |

> See also: [[CONSTITUTIONAL-PROOFS]] Proof 1 (Determinism), [[CRATE-REFERENCE]] Sections 1, 3, 9

---

### Threat 12: Supply Chain Attack

**Compromised dependencies introducing non-determinism, backdoors, or vulnerabilities into the trust fabric.**

| Dimension | Detail |
|-----------|--------|
| **Attack Surface** | `Cargo.toml` workspace dependencies and transitive dependency tree. An attacker compromises an upstream crate (or publishes a typosquatting crate) that introduces malicious behavior, non-determinism, or vulnerabilities. |
| **Mitigations** | (1) `deny.toml` enforces strict dependency governance per [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] Section 8.8: only crates.io is allowed as a source (`unknown-registry = "deny"`, `unknown-git = "deny"`), OpenSSL is banned (pure-Rust crypto only), license compliance is enforced (permissive licenses only), and ignored advisories require documented reachability analysis. (2) `cargo audit` runs in CI (Gate 6), denying vulnerabilities by default and denying unsound and unmaintained warnings explicitly via `cargo audit --deny unsound --deny unmaintained`; yanked advisories currently remain warnings unless a separate vulnerability, unsound, or unmaintained advisory is attached. (3) `Cargo.lock` is committed, ensuring reproducible builds with pinned dependency versions. (4) The `[workspace.lints.rust]` section denies `unsafe_code` across the entire workspace, limiting the blast radius of compromised dependencies that attempt to use unsafe code. (5) The workspace keeps a bounded, reviewed direct dependency surface, including canonical serialization and cryptography crates such as `serde`, `ciborium`, `blake3`, and `ed25519-dalek`. (6) `cargo-cyclonedx` generates a CycloneDX SBOM on every release (Gate 10 in CI validates generation on every PR), providing a machine-readable component graph consumable by Dependency-Track, Grype, Trivy, and other supply-chain tooling. (7) SLSA Level 2 build provenance attestation (`actions/attest-build-provenance`) is generated for every release archive, cryptographically signed via GitHub OIDC keyless flow and stored in the Sigstore Rekor transparency log, ensuring that every release binary can be traced to the exact source commit and workflow run that produced it. Downstream consumers verify with `gh attestation verify <archive> --owner exochain`. |
| **Detection Signals** | `cargo deny check` failures (license violations, banned crates, advisories). `cargo audit` findings (known vulnerabilities). Dependency version changes in `Cargo.lock` without corresponding `Cargo.toml` changes. New transitive dependencies appearing unexpectedly. SLSA attestation verification failure (artifact hash mismatch or Rekor log absence). SBOM diff revealing unexpected component additions between releases. |
| **Downgrade Behavior** | CI rejects any PR that introduces an unignored vulnerability, unsound or unmaintained advisory, incompatible license, banned crate, or non-approved source. The codebase cannot be released with a failing `cargo deny check`, `cargo audit`, or SBOM generation step (Gate 10). If a dependency is found to be compromised after release, the affected versions are yanked and a security advisory is issued. The SLSA attestation stored in Rekor is immutable and cannot be retroactively forged, providing permanent evidence for incident investigation. |
| **Test Coverage** | `deny.toml`: tested by CI on every PR (license, advisory, source, ban checks — Gate 7). `cargo audit`: tested by CI on every PR (Gate 6). `cargo-cyclonedx`: tested by CI on every PR (Gate 10, dry-run validation). `Cargo.lock`: committed and verified by reproducible build pipeline. SLSA attestation: generated and verified on every release via `actions/attest-build-provenance`. |
| **Defending Crates** | Workspace-level (`deny.toml`, `Cargo.toml`, CI pipeline) |

> See also: [[GETTING-STARTED]] Section 7 (Quality Gates), [[CRATE-REFERENCE]] Summary Table

---

## Threat Summary Matrix

| # | Threat | Primary Defense | Crates | Invariant | Tests |
|---|--------|----------------|--------|-----------|-------|
| 1 | Identity Sybil | Independence attestation, risk scoring, Shamir sharing | `exo-identity`, `exo-governance`, `exo-escalation` | QuorumLegitimate | DID registry, quorum independence, Sybil pipeline |
| 2 | Review Sybil | Crosscheck independence, audit trails, conflict disclosure | `exo-governance`, `exo-identity`, `exo-legal` | QuorumLegitimate | Crosscheck evaluation, audit chain, disclosure |
| 3 | Quorum Sybil | Independence-weighted voting, minimum participants, challenge | `exo-governance`, `decision-forum`, `exo-gatekeeper` | QuorumLegitimate | Quorum computation, constitutional enforcement |
| 4 | Delegation Sybil | Scope narrowing, chain verification, NoSelfGrant | `exo-authority`, `exo-gatekeeper` | AuthorityChainValid, NoSelfGrant | Chain verification, subset enforcement |
| 5 | Mesh Sybil | Fixed validator set, governance-gated admission | `exo-dag`, `exo-api`, `exo-governance` | QuorumLegitimate | Consensus quorum, peer vs validator separation |
| 6 | Synthetic-Opinion Sybil | MCP enforcement, ZKML attestation, risk scoring | `exo-gatekeeper`, `exo-proofs`, `exo-identity` | ProvenanceVerifiable | MCP rules, ZKML verification, risk elevation |
| 7 | Consent Bypass | Default-deny, middleware chain, ConsentRequired invariant | `exo-consent`, `exo-gateway`, `exo-gatekeeper` | ConsentRequired | Bailment lifecycle, middleware deny, invariant check |
| 8 | Authority Escalation | Scope subset enforcement, NoSelfGrant invariant | `exo-authority`, `exo-gatekeeper` | NoSelfGrant, AuthorityChainValid | Scope narrowing, self-delegation prevention |
| 9 | Kernel Tampering | Immutable config, self-enforcing invariant, no unsafe | `exo-gatekeeper` | KernelImmutability | Config freeze, self-modification rejection |
| 10 | Receipt Chain Forgery | Hash-linked receipts, append-only DAG, Merkle proofs | `exo-core`, `exo-dag`, `exo-governance` | ProvenanceVerifiable | Receipt chain verification, DAG append-only, SMT/MMR |
| 11 | Clock Manipulation | HLC monotonicity, BFT consensus ordering, receipt chains | `exo-core`, `exo-dag`, `exo-escalation` | ProvenanceVerifiable | HLC monotonicity, consensus finalization |
| 12 | Supply Chain Attack | cargo-deny, cargo-audit, CycloneDX SBOM, SLSA L2 attestation, pinned deps, no unsafe | Workspace-level | N/A (build-time) | CI gates (6, 7, 10), SLSA attestation on release, reproducible builds |

---

## Invariant Coverage Map

Each constitutional invariant defends against specific threats:

| Invariant | Threats Defended |
|-----------|-----------------|
| SeparationOfPowers | 3 (Quorum Sybil), 8 (Authority Escalation) |
| ConsentRequired | 7 (Consent Bypass) |
| NoSelfGrant | 4 (Delegation Sybil), 8 (Authority Escalation) |
| HumanOverride | 5 (Mesh Sybil), 6 (Synthetic-Opinion Sybil) |
| KernelImmutability | 9 (Kernel Tampering) |
| AuthorityChainValid | 4 (Delegation Sybil), 8 (Authority Escalation) |
| QuorumLegitimate | 1 (Identity Sybil), 2 (Review Sybil), 3 (Quorum Sybil), 5 (Mesh Sybil) |
| ProvenanceVerifiable | 6 (Synthetic-Opinion Sybil), 10 (Receipt Chain Forgery), 11 (Clock Manipulation) |

---

## Residual Risks

The following risks are acknowledged but considered acceptable given the current mitigations:

1. **Physical coercion of key holders.** EXOCHAIN's cryptographic defenses assume key holders are not physically coerced. PACE operator continuity (`exo-identity::pace`) mitigates single-point compromise but cannot defend against state-level adversaries coercing all PACE operators simultaneously.

2. **Quantum computing.** Ed25519 and BLAKE3 are not quantum-resistant. When post-quantum standards mature, a council resolution should mandate migration to quantum-resistant primitives. The modular cryptographic architecture (`exo-core::crypto`) allows key algorithm substitution.

3. **Side-channel attacks.** While `unsafe_code = "deny"` and pure-Rust crypto reduce the attack surface, constant-time guarantees depend on compiler behavior. The `zeroize` crate is used for secret key material, and `ed25519-dalek` provides constant-time operations, but hardware-level side channels are outside the software's control.

4. **Social engineering of council members.** The governance process depends on council members acting in good faith. Multi-party requirements (quorum, crosscheck, independence attestation) mitigate single-member compromise, but a coordinated social engineering campaign against a majority of council members is outside the threat model.

---

> This threat model is maintained in sync with [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] Section 8.2. For the crate-level API reference see [[CRATE-REFERENCE]]. For formal proofs of constitutional properties see [[CONSTITUTIONAL-PROOFS]]. For contribution guidelines see [[GETTING-STARTED]].

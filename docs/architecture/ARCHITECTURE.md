# EXOCHAIN Architecture

> **Version:** 0.1.0 | **Status:** Living Document | **Last verified:** 2026-03-18
> **Codebase:** 20 workspace packages | 123803 lines of Rust under `crates/` | 266 Rust source files | 2,994 listed tests

---

## 1. Executive Summary

EXOCHAIN is a constitutional trust fabric for safe superintelligence governance. It is not a blockchain, not a smart-contract platform, and not an alignment wish-list. It is an executable constitution: a system where every AI action, every governance decision, and every data access is verified against immutable invariants before it is permitted to take effect.

The problem EXOCHAIN solves is precise. Current AI governance is aspirational. Alignment guidelines are published as PDFs. Ethics boards issue recommendations. None of it is enforceable at the speed at which AI systems operate. EXOCHAIN makes governance mathematically enforceable by reducing every proposed state transition to a combinatory logic proof that either satisfies all constitutional invariants or is rejected with cryptographic evidence of violation.

The key architectural insight: **AEGIS preserves legitimate plurality; SYBIL counterfeits it.** A crosscheck panel of five independent models deliberating on a governance question is genuine plural intelligence. Five sock-puppet accounts controlled by one actor casting five votes is manufactured consensus. EXOCHAIN distinguishes these cases through independence-aware counting, provenance-tagged opinions, and a formal anti-Sybil adjudication pipeline. Numerical multiplicity without attributable independence is theater, not legitimacy.

### What makes EXOCHAIN different

1. **Governance is code, not commentary.** The eight constitutional invariants are compiled Rust functions evaluated on every state transition. They cannot be bypassed, overridden, or suspended.
2. **Proofs, not promises.** Every permitted action produces a `CgrProof` --- a cryptographic certificate recording which invariants were checked, by which kernel version, against which registry hash.
3. **Three-branch separation enforced in type system.** Legislative (constitution and amendments), Executive (Holons operating under constraints), and Judicial (the CGR Kernel that accepts or rejects transitions).
4. **Deterministic execution.** No floating-point, no HashMap, no NTP dependency. The same input always produces the same output, making governance auditable across replicas.

---

## 2. System Architecture Overview

### 2.1 Three-Branch Constitutional Model

EXOCHAIN implements separation of powers as a compile-time architectural constraint, not a policy document:

| Branch | Role | Implementation | Key Crates |
|---|---|---|---|
| **Legislative** | Define constitutional rules, decision classes, amendment process | Constitution documents, `DecisionClass`, amendment lifecycle | `exo-governance`, `decision-forum` |
| **Executive** | Propose and execute actions within constitutional bounds | Holons (AI entities with DID identity), authority delegation chains | `exo-gatekeeper` (holon.rs), `exo-authority`, `exo-identity` |
| **Judicial** | Verify every transition against invariants, issue/deny proofs | CGR Kernel, invariant registry, combinator reduction engine | `exo-gatekeeper` (kernel.rs, invariants.rs, combinator.rs) |

The separation is enforced structurally: the Judicial branch (CGR Kernel) has no mechanism to modify the invariants it evaluates. The Executive branch (Holons) cannot grant capabilities to themselves (INV-002). The Legislative branch (amendment process) is the sole path to modify constitutional rules, and it requires supermajority ratification.

### 2.2 The 16-Crate Dependency Graph

```
                         Layer 5: Binaries & Targets
          ┌──────────────────────────┐  ┌───────────────────────────┐
          │        exo-node          │  │      exochain-wasm        │
          │  (P2P, BFT, state sync,  │  │  (browser & edge bindings │
          │   dashboard, CLI)        │  │   for governance prims)   │
          └──────────┬───────────────┘  └──────────┬────────────────┘
                     │                             │
                         Layer 4: Integration
                    ┌──────────────────────────┐
                    │       exo-gateway         │
                    │  (API surface, routing)   │
                    └──────────┬───────────────┘
                               │
                         Layer 3: Domain
          ┌────────────────────┼────────────────────┐
          │                    │                     │
    ┌─────┴─────┐     ┌───────┴──────┐     ┌───────┴───────┐
    │ exo-legal │     │  exo-tenant  │     │   exo-api     │
    │(compliance│     │  (multi-org  │     │  (GraphQL +   │
    │ evidence) │     │   isolation) │     │   libp2p)     │
    └─────┬─────┘     └──────┬───────┘     └───────┬───────┘
          │                  │                     │
                         Layer 2: Governance
    ┌─────┴──────────────────┼─────────────────────┘
    │                        │
    │  ┌──────────────┐  ┌───┴──────────┐  ┌──────────────┐
    │  │exo-governance│  │exo-authority │  │exo-escalation│
    │  │(decisions,   │  │(delegation   │  │(anomaly      │
    │  │ quorum,      │  │ chains,      │  │ detection,   │
    │  │ crosscheck)  │  │ scope)       │  │ triage)      │
    │  └──────┬───────┘  └──────┬───────┘  └──────────────┘
    │         │                 │
    │  ┌──────┴───────┐  ┌─────┴────────┐  ┌──────────────┐
    │  │decision-forum│  │ exo-consent  │  │exo-gatekeeper│
    │  │(forum proto- │  │ (consent     │  │(CGR Kernel,  │
    │  │ col, voting) │  │  lifecycle)  │  │ invariants,  │
    │  └──────────────┘  └──────────────┘  │ combinators, │
    │                                      │ holons)      │
    │                                      └──────┬───────┘
    │                                             │
                         Layer 1: Cryptographic Foundation
    ┌─────────────────┬──────────────┬────────────┘
    │                 │              │
    │  ┌──────────┐  │  ┌────────┐  │  ┌────────────┐
    │  │exo-proofs│  │  │exo-dag │  │  │exo-identity│
    │  │(SNARK,   │  │  │(SMT,   │  │  │(DID, keys, │
    │  │ STARK,   │  │  │ MMR,   │  │  │ Shamir,    │
    │  │ zkML)    │  │  │ DAG)   │  │  │ risk)      │
    │  └────┬─────┘  │  └───┬────┘  │  └─────┬──────┘
    │       │        │      │       │        │
    │       └────────┴──────┴───────┴────────┘
    │                       │
    │              ┌────────┴────────┐
    │              │    exo-core     │
    │              │ (Blake3, Ed25519│
    │              │  HLC, events,   │
    │              │  CBOR canonical)│
    └──────────────┴─────────────────┘
```

### 2.3 Data Flow: The BCTS Lifecycle

Every governance action follows the Bailment-Conditioned Transaction Set lifecycle:

1. **Propose** --- An actor (human or Holon) creates an `EventEnvelope` with a proposed action.
2. **Authenticate** --- The event is signed with Ed25519 using domain-separated signatures (`EXOCHAIN-EVENT-SIG-v1`). See [[exo-core/src/crypto.rs]].
3. **Gate** --- The CGR Kernel evaluates the `TransitionContext` against all 8 invariants. See [[exo-gatekeeper/src/kernel.rs]].
4. **Prove** --- If all invariants hold, a `CgrProof` is issued. If any fail, the transition is rejected with `InvariantViolation` evidence.
5. **Commit** --- The approved event is appended to the append-only DAG, producing a new state root via the Sparse Merkle Tree.
6. **Anchor** --- The DAG root is periodically anchored to external trust sources via `AnchorReceipt`.
7. **Audit** --- Every state change produces a `LedgerEvent` with HLC timestamp, parent references, and author DID.

---

## 3. The BCTS Innovation

### 3.1 The Decision State Machine

EXOCHAIN governance decisions follow the BCTS lifecycle. The `BctsState`
enum in [[exo-core/src/bcts.rs]] defines the transition graph, and
[[decision-forum/src/decision_object.rs]] binds it to decision objects
with receipt-chain validation. Terminal states are immutable (TNC-08):
once a decision reaches `Closed`, it cannot transition again.

Main success path:

`Draft -> Submitted -> IdentityResolved -> ConsentValidated -> Deliberated -> Verified -> Governed -> Approved -> Executed -> Recorded -> Closed`

Failure/recovery states:

`Denied -> Remediated -> Submitted`

`Escalated -> Deliberated | Denied | Remediated`

The 14 BCTS states are `Draft`, `Submitted`, `IdentityResolved`,
`ConsentValidated`, `Deliberated`, `Verified`, `Governed`, `Approved`,
`Executed`, `Recorded`, `Closed`, `Denied`, `Escalated`, and `Remediated`.

### 3.2 Why Every Action Needs Correlation, Receipt, and Attribution

Every governance action in EXOCHAIN carries three mandatory components:

- **Correlation ID** --- The `event_id` computed as `Blake3(canonical_CBOR(envelope))`. This is deterministic: the same envelope always produces the same ID. See `compute_event_id()` in [[exo-core/src/events.rs]].
- **Receipt chain** --- The `parents` field in `EventEnvelope` establishes DAG causality. Every event references its causal predecessors, creating an unforgeable ordering.
- **Actor attribution** --- The `author` DID and `key_version` fields, combined with the domain-separated Ed25519 signature, cryptographically bind every action to an identified actor.

This triple ensures that no governance action can exist without provenance, no ordering can be forged, and no actor can act anonymously.

---

## 4. Constitutional Enforcement --- The CGR Kernel

The Combinator Graph Reduction Kernel is the judicial branch of EXOCHAIN. It is implemented in [[exo-gatekeeper/src/kernel.rs]] and is structurally immutable: the kernel binary is content-addressed (INV-008) and the invariant registry is content-addressed (INV-009). Modification of either requires a constitutional amendment.

### 4.1 The 5 Constitutional Properties

| Property | Enforcement Mechanism | Invariants |
|---|---|---|
| **Separation of powers** | Three-branch architecture; kernel cannot modify itself; Holons cannot grant self-capabilities | INV-001, INV-002 |
| **Consent before access** | Every data access checked against active, non-expired consent records with matching purpose | INV-003, INV-004 |
| **No self-grant** | `target_did != author_did` enforced on every capability grant | INV-002 |
| **Human override preserved** | `ProposedAction::RemoveHumanOverride` is unconditionally rejected | INV-007 |
| **Kernel immutability** | Kernel binary hash and registry hash verified on every transition | INV-008, INV-009 |

### 4.2 The 8 Constitutional Invariants

Every call to `CgrKernel::verify_transition()` evaluates all 8 invariants. If any fails, the transition is rejected and violation evidence is recorded for the audit trail.

| ID | Name | Formal Specification | Code Reference |
|---|---|---|---|
| INV-001 | `NO_SELF_MODIFY_INVARIANTS` | `forall h:Holon, forall t:Transition, affects(t, h.invariants) AND author(t)=h -> reject(t)` | `check_inv001_no_self_modify` |
| INV-002 | `NO_CAPABILITY_SELF_GRANT` | `forall h:Holon, forall c:Capability, grants(t, h, c) AND author(t)=h -> reject(t)` | `check_inv002_no_self_grant` |
| INV-003 | `CONSENT_PRECEDES_ACCESS` | `forall a:AccessEvent, exists c:ConsentEvent, c.timestamp < a.timestamp AND covers(c, a.resource)` | `check_inv003_consent_precedes_access` |
| INV-004 | `TRAINING_CONSENT_REQUIRED` | `forall t:TrainingEvent, forall d:DataRef in t.data, exists c:ConsentEvent, purpose(c)='training' AND covers(c, d)` | `check_inv004_training_consent` |
| INV-005 | `ALIGNMENT_SCORE_FLOOR` | `forall h:Holon, forall a:Action, h.alignment_score < MIN_ALIGNMENT -> reject(a)` | `check_inv005_alignment_floor` |
| INV-006 | `AUDIT_COMPLETENESS` | `forall s:StateChange, exists e:Event, records(e, s)` | `check_inv006_audit_completeness` |
| INV-007 | `HUMAN_OVERRIDE_PRESERVED` | `forall t:Transition, NOT(removes(t, human_override_capability))` | `check_inv007_human_override` |
| INV-008 | `KERNEL_BINARY_IMMUTABLE` | `forall t:Transition, affects(t, active_kernel.binary) -> requires_constitutional_amendment(t)` | `check_inv008_kernel_immutable` |
| INV-009 | `INVARIANT_REGISTRY_IMMUTABLE` | `forall t:Transition, modifies(t, invariant_registry) -> requires_constitutional_amendment(t)` | `check_inv009_registry_immutable` |

The invariant registry is itself content-addressed: each invariant's definition is hashed with domain separation (`EXOCHAIN-INVARIANT-v1:`), and the registry hash is computed from the concatenation of all invariant hashes. See [[exo-gatekeeper/src/invariants.rs]].

### 4.3 The Proof Lifecycle

When all 8 invariants are satisfied:

1. A `CgrProof` is issued containing the proof ID, the count of invariants checked (always 8), the registry hash, and the kernel binary hash.
2. The proof counter increments monotonically --- proofs are sequentially numbered and cannot be forged retroactively.
3. The proof is attached to the resulting `LedgerEvent` as cryptographic evidence that the transition was constitutionally valid.

When any invariant fails:

1. An `InvariantViolation` record is created with the invariant ID, the actor DID, the attempted action, the failure reason, and the timestamp.
2. All violations from a single transition are accumulated and returned.
3. Violations are appended to the kernel's audit trail for post-hoc review.

See [[exo-gatekeeper/src/kernel.rs]] and [[exo-gatekeeper/src/invariants.rs]].

---

## 5. The Combinator Algebra

The combinator reduction engine in [[exo-gatekeeper/src/combinator.rs]] provides a second enforcement mechanism: constitutional invariants can be encoded as typed combinatory logic expressions and mechanically reduced to `true` or `false`.

### 5.1 Combinator Basis

EXOCHAIN uses a typed combinatory logic with 5 primitive combinators and domain-specific extensions:

**Primitive combinators (Turing-complete basis):**

| Combinator | Semantics | Reduction Rule |
|---|---|---|
| **S** | Composition with sharing | `(S f g x) -> (f x (g x))` |
| **K** | Constant projection | `(K x y) -> x` |
| **I** | Identity | `(I x) -> x` |
| **B** | Function composition | `(B f g x) -> f (g x)` |
| **C** | Argument flip | `(C f x y) -> f y x` |

**Governance-specific combinators:**

| Combinator | Semantics |
|---|---|
| `NOT`, `AND`, `OR`, `IMPLIES` | Propositional logic connectives |
| `FORALL`, `EXISTS` | Bounded quantification over finite domains |
| `EQUALS`, `LESS_THAN`, `GTE` | Comparison operators |
| `LOOKUP` | Context value lookup from `ReductionContext` bindings |

### 5.2 Invariant Encoding

Constitutional invariants are encoded as combinator terms. For example, INV-002 (no self-grant) becomes:

```
NOT(EQUALS(LOOKUP("author_did"), LOOKUP("target_did")))
```

INV-005 (alignment floor) becomes:

```
GTE(LOOKUP("alignment_score"), LOOKUP("min_alignment"))
```

The `encode_invariant()` function translates invariant IDs to combinator terms that, when reduced with the appropriate `ReductionContext` bindings, produce `Reduced(Bool(true))` for satisfaction or `Reduced(Bool(false))` for violation.

### 5.3 Determinism Guarantee

The combinator engine is deterministic by construction:

- **No floating-point** in the reduction path. The `TypedValue` domain uses `u64` for naturals and `bool` for logic.
- **Bounded reduction** via `max_reductions`. The Omega combinator `(S I I)(S I I)` --- a classic non-terminating term --- halts within the step limit.
- **Complete trace** recorded in `ReductionTrace`. Every reduction step records the rule applied, the before/after term, and the step number. This trace constitutes the type-level proof.

---

## 6. Anti-Sybil Architecture

### 6.1 The 6 Sub-Threat Taxonomy

EXOCHAIN identifies six distinct Sybil attack vectors:

| Threat | Description | Mitigation |
|---|---|---|
| **Identity Sybil** | Fabricated DIDs to inflate voting power | DID-bound identity with Shamir-split key recovery; see [[exo-identity/src/shamir.rs]] |
| **Review Sybil** | Multiple synthetic opinions disguised as independent assessments | `OpinionProvenance` with mandatory `agent_kind`, `model`, and `provider` fields; see [[exo-governance/src/crosscheck.rs]] |
| **Quorum Sybil** | Manufactured attendance to meet quorum thresholds | Independence-aware counting in `verify_quorum()`; ineligible voters excluded; see [[exo-governance/src/quorum.rs]] |
| **Delegation Sybil** | Cascading delegations to concentrate power | `max_delegation_depth` cap in `KernelConfig`; delegation expiry timestamps |
| **Mesh Sybil** | Collusive rings of actors coordinating votes | Crosscheck panel multi-provider requirement; `providers()` deduplication |
| **Synthetic-Opinion Sybil** | AI-generated opinions presented as human consensus | `AgentKind` enum distinguishing `Llm`, `Human`, `RuleEngine`, `Specialist`; `verify_provenance_compliance()` rejects LLM opinions without model attribution |

### 6.2 Independence-Aware Counting

Standard governance systems count votes. EXOCHAIN counts *independent* votes. The crosscheck mechanism requires:

1. **Provenance tagging** --- Every `CrosscheckOpinion` carries an `OpinionProvenance` with agent ID, agent kind, model identifier, and provider. LLM opinions without model attribution fail compliance.
2. **Provider diversity** --- The `providers()` method extracts unique provider names, enabling policies like "consensus requires opinions from at least 3 distinct providers."
3. **Dissent preservation** --- Dissenting opinions are first-class objects in the `CrosscheckReport`, not footnotes. The `dissent` vector and `dissenters` list ensure minority views survive synthesis.
4. **Threshold enforcement** --- `meets_threshold(min_panel, min_agreement)` requires both minimum panel size and minimum agreement ratio.

### 6.3 The Crosscheck Mechanism

The `CrosscheckReport` in [[exo-governance/src/crosscheck.rs]] is the plural intelligence artifact:

- **Methods**: QuickCheck (single model), Crosscheck (multi-model panel), Borg (multi-round refinement), Audit (adversarial), DevilsAdvocate, RedTeam, Jury
- **zkML proof**: Optional `zkml_proof` field for cryptographic AI provenance verification (ARCH-002)
- **Content-addressed**: Each report has a `content_hash` for integrity verification
- **HLC-timestamped**: Reports carry `HybridLogicalClock` timestamps for causal ordering

### 6.4 Escalation Pipeline

When Sybil-related anomalies are detected, the escalation policy engine in [[exo-escalation/src/escalation.rs]] routes them through a 5-level pipeline:

| Level | Name | Trigger Example | Actions |
|---|---|---|---|
| L1 | Automated | `QuorumManipulation`, `DelegationCascade`, `TrustScoreAnomaly` | Notify ops-team, create triage item |
| L2 | TeamLead | `AuditGap` | Assign reviewer, create triage item |
| L3 | Governance | `EquivocationAttempt` | Suspend actor, create triage item |
| L4 | Constitutional | `HumanOverrideAttempt` | Trigger governance vote, suspend offending actor |
| L5 | Emergency | `KernelTamper` | Halt system, notify all validators |

Each level has configurable timeout and auto-escalation. KernelTamper escalates immediately to L5 with `timeout_ms: 0` and `auto_escalate: false` --- there is no cooling-off period for constitutional attacks.

---

## 7. Determinism Guarantees

### 7.1 Why Determinism Matters

Constitutional governance requires that two independent validators, given the same input, produce the same output. If governance outcomes depend on floating-point rounding, hash map iteration order, or clock skew, then the constitution is ambiguous. EXOCHAIN eliminates every source of non-determinism.

### 7.2 Enforcement Mechanisms

| Mechanism | What It Prevents | Where Enforced |
|---|---|---|
| **No floating-point in critical paths** | Rounding disagreements between replicas | `TypedValue` uses `u64` for naturals, never `f64` in combinator reduction |
| **BTreeMap only** | HashMap iteration order varies by seed | Governance structures use `Vec` with explicit sorting or `BTreeMap` |
| **HLC ordering** | Wall-clock disagreements | `HybridLogicalClock` provides causal ordering; see [[exo-core/src/hlc.rs]] |
| **Canonical CBOR serialization** | Encoding ambiguity | `serde_cbor::to_vec()` for all canonical forms; event IDs are `Blake3(CBOR(envelope))` |
| **Domain-separated hashing** | Hash confusion across contexts | Every hash computation uses a domain separator: `EXOCHAIN-EVENT-SIG-v1`, `EXOCHAIN-INVARIANT-v1`, `EXOCHAIN-SMT-v1`, `EXOCHAIN-STARK-v1` |

### 7.3 Hybrid Logical Clock

The HLC in [[exo-core/src/hlc.rs]] provides causal ordering without NTP dependency:

```
HLC = (physical_ms: u64, logical: u32)
```

**Ordering rule**: Compare `physical_ms` first; if equal, compare `logical`.

**New event rule** (from `HybridLogicalClock::new_event()`):
- `physical_ms = max(node_time, max(parent_times.physical_ms))`
- If `physical_ms` equals the maximum parent physical time, `logical = max_parent_logical + 1`
- If `physical_ms` advances beyond all parents, `logical = 0`

This ensures causal ordering even when node clocks drift: if a node's clock is behind its parents, the HLC catches up to the parent's physical time and increments the logical counter. The result is a total order over events that respects causality.

---

## 8. Cryptographic Foundation

### 8.1 Core Primitives

| Primitive | Implementation | Purpose |
|---|---|---|
| **Blake3** | `blake3` crate, 32-byte output | Content addressing, event IDs, integrity verification |
| **Ed25519** | `ed25519-dalek` crate | Event signatures, domain-separated with `EXOCHAIN-EVENT-SIG-v1` prefix |
| **Shamir Secret Sharing** | Custom GF(256) over AES/Rijndael polynomial | Key recovery for DID identity; see [[exo-identity/src/shamir.rs]] |

The Shamir implementation uses the irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (0x1b) for GF(256) arithmetic. Each byte of the secret is split independently using a random polynomial of degree `threshold - 1`. Recovery uses Lagrange interpolation over any `threshold`-sized subset.

### 8.2 Zero-Knowledge Proof System

The `exo-proofs` crate ([[exo-proofs/src/lib.rs]]) provides three proof types:

| Proof Type | Module | Properties | Use Case |
|---|---|---|---|
| **zk-SNARK** | `snark.rs` | Succinct, non-interactive, requires trusted setup | Efficient on-chain verification of governance compliance |
| **zk-STARK** | `stark.rs` | Transparent (no trusted setup), post-quantum secure | Public governance transparency proofs |
| **zkML** | `zkml.rs` | AI provenance proofs | Prove that a specific model produced a specific output (ARCH-002) |

STARKs use hash-based commitments (Blake3) rather than elliptic-curve pairings, making them resistant to quantum attacks on discrete-log assumptions. The `StarkProver` uses domain separation (`EXOCHAIN-STARK-v1`) and configurable security bits.

The `UnifiedVerifier` in `verifier.rs` provides a single entry point for verifying any proof type, returning a `VerificationResult`.

### 8.3 Merkle Structures

| Structure | Module | Purpose |
|---|---|---|
| **Sparse Merkle Tree (SMT)** | [[exo-dag/src/smt.rs]] | State root computation. Key-value store with domain-separated leaf hashing (`EXOCHAIN-SMT-v1`). Supports membership and non-membership proofs via `SmtProof`. |
| **Merkle Mountain Range (MMR)** | [[exo-dag/src/mmr.rs]] | Append-only accumulation. Peaks-only representation for efficient append and root computation. Used for the event DAG audit trail. |

The SMT uses `Hash(DOMAIN_SEP || key || value)` for leaf computation, preventing second-preimage attacks across different tree contexts. The MMR maintains only peak hashes, enabling O(log n) append and O(1) root computation.

---

## 9. The Self-Development Kernel

### 9.1 AGENTS.md as Executable Development Instructions

The [[AGENTS.md]] file defines the non-negotiable development principles:

1. Identity before execution
2. Consent before computation
3. Governance before deployment
4. Provenance after execution
5. Human override and auditability for material decisions
6. Security, compliance, and observability as first-class features

These are not guidelines --- they are the acceptance criteria against which every pull request, every agent-generated code change, and every architectural decision is evaluated.

### 9.2 Council-Driven Assessment

EXOCHAIN development follows a council-driven process where AI agents contribute code within constitutional bounds. The Holon lifecycle (Created -> Activated -> Action Cycle -> Suspended/Sunset) applies to development agents as well as production AI:

- **Created**: A development Holon is registered with a sponsor DID and genesis model hash.
- **Activated**: An AI-IRB (Institutional Review Board) equivalent approves the Holon for action.
- **Action Cycle**: The Holon proposes code changes, each verified by the CGR Kernel.
- **Suspended**: If alignment score drops below the floor (INV-005), the Holon is blocked from further actions until remediation.

### 9.3 How EXOCHAIN Becomes a System That Develops Systems

The architectural loop closes when EXOCHAIN's governance primitives are applied to its own development process:

1. **Constitutional constraints** on what code changes are permissible (invariant enforcement).
2. **Crosscheck deliberation** on architectural decisions (multi-model plural intelligence).
3. **Immutable audit trail** of every decision that shaped the system (DAG with HLC ordering).
4. **Formal proofs** that the development process itself satisfies the constitutional invariants.

This is not self-modification --- the kernel remains immutable. It is self-governance: the system enforces its own development standards through the same mechanisms it uses to govern AI actions in production.

---

## 10. Dependency Graph (Detailed)

```
exo-gateway ──┬──► exo-governance
              ├──► exo-authority ──┬──► exo-identity ──► exo-core
              │                    └──► exo-governance
              ├──► exo-legal ──────┬──► exo-core
              │                    └──► exo-governance
              ├──► exo-tenant ─────┬──► exo-core
              │                    └──► exo-dag ────────► exo-core
              ├──► exo-proofs ─────────► exo-core
              └──► exo-gatekeeper ─────► exo-core

exo-api ──────┬──► exo-core
              ├──► exo-identity ───────► exo-core
              └──► exo-dag ────────────► exo-core

exo-governance ┬──► exo-core
               └──► exo-identity ──────► exo-core

exo-authority ─┬──► exo-core
               ├──► exo-identity ──────► exo-core
               └──► exo-governance

exo-consent ───┬──► exo-core
               └──► exo-identity ──────► exo-core

exo-escalation ────► exo-core

exo-legal ─────┬──► exo-core
               └──► exo-governance

exo-tenant ────┬──► exo-core
               └──► exo-dag ──────────► exo-core

decision-forum     (standalone; ed25519 + sha2 + serde)

exo-gatekeeper ────► exo-core
exo-proofs ────────► exo-core
exo-dag ───────────► exo-core
exo-identity ──────► exo-core
exo-core           (leaf node; no internal dependencies)
```

**Key observation**: `exo-core` is the sole leaf dependency. Every crate in the system depends on it, and it depends on nothing internal. This makes `exo-core` the cryptographic and data-model bedrock --- its interfaces are the most stable in the system.

**`exo-gateway` is the integration apex**: it depends on 7 internal crates, stitching together governance, authority, legal compliance, tenant isolation, proofs, and the CGR Kernel into a unified API surface.

---

## 11. Comparison: EXOCHAIN vs Prior Art

### 11.1 EXOCHAIN vs Ethereum

| Dimension | EXOCHAIN | Ethereum |
|---|---|---|
| **Finality** | Deterministic. A transition is accepted or rejected by the CGR Kernel before it enters the DAG. There is no probabilistic confirmation window. | Probabilistic. Transactions are included in blocks that may be reorganized within a finality horizon. |
| **Governance model** | Constitutional. 8 invariants checked on every action. Three-branch separation. | Smart contract autonomy. Governance is application-layer (DAOs, multisigs), not protocol-enforced. |
| **Identity** | DID-native. Every actor has a cryptographic identity with key versioning, Shamir recovery, and human/AI type distinction. | Address-based. No built-in identity layer; ENS and other systems are application-layer. |
| **Consent** | Protocol-level. INV-003 and INV-004 enforce consent-before-access at the kernel level. | No protocol-level consent model. Data access is controlled by smart contract logic. |

### 11.2 EXOCHAIN vs Traditional RBAC

| Dimension | EXOCHAIN | Traditional RBAC |
|---|---|---|
| **Authority model** | Delegation chains with scope narrowing and depth limits. Capabilities are granted by external actors (INV-002 prevents self-grant) with cryptographic attestation and expiry. | Flat role assignments. An admin assigns roles; the admin role can typically grant itself any permission. |
| **Audit** | Every state change produces a signed, HLC-timestamped event in an append-only DAG (INV-006). | Audit logging is typically a side-effect, not a constitutional requirement. Logs can be tampered with. |
| **Human override** | Constitutionally preserved (INV-007). No code path can remove human override capability. | Override depends on implementation. Admin escalation can typically bypass any control. |

### 11.3 EXOCHAIN vs AI Alignment Approaches

| Dimension | EXOCHAIN | Typical Alignment Approaches |
|---|---|---|
| **Enforcement** | Compile-time and runtime invariants. The CGR Kernel rejects non-compliant transitions with cryptographic evidence. | Training-time objectives (RLHF, constitutional AI). No runtime enforcement; alignment is probabilistic. |
| **Verifiability** | Every permitted action has a `CgrProof` with reduction trace. Any auditor can re-derive the proof. | Alignment is inferred from model behavior. No mechanism to prove a specific action was aligned. |
| **Human authority** | Structurally guaranteed (INV-007). The system literally cannot remove human override. | Human oversight is a design goal, not an invariant. Sufficiently capable systems may circumvent oversight. |
| **Plurality** | Built-in plural intelligence via crosscheck panels with provenance-tagged, multi-provider opinions. | Single-model alignment. No mechanism for structured disagreement or minority report preservation. |

---

## 12. Metrics Summary Table

| Crate | LOC | Tests | Files | Primary Responsibility |
|---|---|---|---|---|
| `exo-core` | 3,949 | 191 | 10 | Blake3, Ed25519, HLC, events, canonical CBOR |
| `exo-gatekeeper` | 2,875 | 133 | 9 | CGR Kernel, invariants, combinators, Holons, TEE |
| `exo-dag` | 2,590 | 86 | 7 | SMT, MMR, DAG consensus, checkpoints |
| `exo-proofs` | 1,916 | 61 | 7 | SNARK, STARK, zkML, unified verifier |
| `exo-identity` | 1,533 | 67 | 7 | DID, key management, Shamir, PACE, risk scoring |
| `exo-authority` | 1,235 | 66 | 6 | Delegation chains, scope narrowing, authority proofs |
| `exo-governance` | 1,236 | 69 | 9 | Decisions, quorum, crosscheck, constitution, delegation |
| `exo-consent` | 899 | 54 | 5 | Consent lifecycle, purpose-bound access |
| `exo-escalation` | 824 | 43 | 8 | Anomaly detection, triage, escalation chains |
| `exo-legal` | 583 | 63 | 8 | Compliance evidence, legal hold, jurisdiction |
| `exo-gateway` | 279 | 27 | 6 | API surface, routing, integration apex |
| `exo-tenant` | 268 | 41 | 6 | Multi-org isolation, tenant DAG separation |
| `decision-forum` | 265 | 34 | 6 | Forum protocol, voting, decision lifecycle |
| `exo-api` | 253 | 22 | 5 | GraphQL, libp2p, external API |
| `exo-node` | — | — | — | Single-binary EXOCHAIN node — P2P networking, BFT consensus reactor, state sync, embedded dashboard, and CLI |
| `exochain-wasm` | — | — | — | WASM compilation target — browser and edge bindings for EXOCHAIN governance primitives |
| **Total** | **18,705** | **1,846** | **111** | |

### Test Coverage by Domain

| Domain | Crates | Tests | Coverage Focus |
|---|---|---|---|
| Constitutional enforcement | `exo-gatekeeper` | 133 | All 8 invariants, proof lifecycle, combinator reduction, Holon lifecycle |
| Cryptographic foundation | `exo-core`, `exo-proofs`, `exo-dag` | 338 | Signature roundtrips, domain separation, SMT proofs, MMR append, HLC ordering |
| Governance process | `exo-governance`, `decision-forum`, `exo-authority` | 169 | Decision state machine, quorum verification, crosscheck, delegation chains |
| Identity and consent | `exo-identity`, `exo-consent` | 121 | DID operations, Shamir split/recover, consent lifecycle |
| Operations | `exo-escalation`, `exo-legal`, `exo-tenant`, `exo-gateway`, `exo-api` | 196 | Escalation policies, legal compliance, tenant isolation, API integration |

---

## Appendix: Key Source File Index

| Path | Contents |
|---|---|
| [[exo-core/src/crypto.rs]] | `Blake3Hash`, `compute_signature()`, `verify_signature()`, domain separator |
| [[exo-core/src/events.rs]] | `Event`, `EventType`, `EventPayload`, signed event helpers, `compute_event_id()` |
| [[exo-core/src/hlc.rs]] | `HybridLogicalClock`, `new_event()` with catch-up semantics |
| [[exo-gatekeeper/src/kernel.rs]] | `CgrKernel`, `verify_transition()`, all 8 `check_inv*` methods |
| [[exo-gatekeeper/src/invariants.rs]] | `InvariantRegistry::canonical()`, content-addressed invariant definitions |
| [[exo-gatekeeper/src/combinator.rs]] | `CombinatorTerm`, `CombinatorEngine::reduce()`, `encode_invariant()` |
| [[exo-gatekeeper/src/holon.rs]] | `Holon`, `HolonStatus`, `HolonType`, capability model |
| [[decision-forum/src/decision_object.rs]] | `DecisionObject`, BCTS-backed lifecycle receipts, votes, evidence, authority chain |
| [[exo-governance/src/crosscheck.rs]] | `CrosscheckReport`, `OpinionProvenance`, `verify_provenance_compliance()` |
| [[exo-governance/src/quorum.rs]] | `verify_quorum()`, `DegradedGovernanceConfig` |
| [[exo-escalation/src/escalation.rs]] | `EscalationPolicy`, 5-level escalation, auto-escalation logic |
| [[exo-dag/src/smt.rs]] | Sparse Merkle Tree with domain-separated leaf hashing |
| [[exo-dag/src/mmr.rs]] | Merkle Mountain Range with peaks-only representation |
| [[exo-identity/src/shamir.rs]] | Shamir Secret Sharing over GF(256) |
| [[exo-proofs/src/stark.rs]] | zk-STARK prover with post-quantum security |
| [[exo-proofs/src/zkml.rs]] | zkML prover for AI provenance |

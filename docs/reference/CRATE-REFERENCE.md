---
title: "EXOCHAIN Crate Reference"
status: active
created: 2026-03-18
tags: [exochain, reference, api, crates]
---

# Crate Reference

**API reference for the workspace crates composing the EXOCHAIN constitutional trust fabric.**

20 workspace packages · 120536 lines of Rust under `crates/` · 2,914 listed tests

> Cross-references: [[ARCHITECTURE]], [[GETTING-STARTED]], [[THREAT-MODEL]], [[CONSTITUTIONAL-PROOFS]]

---

## Dependency Graph (Simplified)

```
exo-core (root — all crates depend on this)
├── exo-identity
├── exo-consent
├── exo-dag
├── exo-proofs
├── exo-authority ──────────── depends on exo-identity
├── exo-gatekeeper ─────────── depends on exo-core
├── exo-governance ─────────── depends on exo-identity, exo-consent, exo-authority
├── exo-escalation ─────────── depends on exo-identity, exo-governance
├── exo-legal ──────────────── depends on exo-identity, exo-governance
├── exo-tenant ─────────────── depends on exo-identity
├── exo-api ────────────────── depends on exo-identity
├── exo-gateway ────────────── depends on exo-identity, exo-consent, exo-gatekeeper, exo-governance
├── exo-node ──────────────── depends on exo-core, exo-gateway, exo-dag, exo-governance
├── exochain-wasm ─────────── depends on exo-core, exo-governance
└── decision-forum ─────────── depends on exo-identity, exo-governance, exo-gatekeeper
```

---

## 1. exo-core

| Metric | Value |
|--------|-------|
| LOC | 3,949 |
| Tests | 191 |
| Files | 10 |

### Purpose

Foundational crate for the entire EXOCHAIN constitutional trust fabric. Provides deterministic primitive types, cryptographic operations, the Hybrid Logical Clock (HLC), Bailment-Conditioned Transaction Set (BCTS) state machine, canonical hashing, and the event system. All other crates depend on `exo-core`. Enforces the determinism contract: no floats, no `HashMap`, canonical CBOR serialization, and HLC-only timestamps.

### Dependencies

None (workspace root crate). External: `serde`, `blake3`, `ed25519-dalek`, `uuid`, `chrono`, `thiserror`, `ciborium`, `zeroize`, `indexmap`, `rand`.

### Modules

#### `bcts` — Bailment-Conditioned Transaction Set State Machine

| Item | Kind | Description |
|------|------|-------------|
| `BctsState` | enum | Lifecycle states: Draft, Submitted, IdentityResolved, ConsentValidated, Deliberated, Verified, Governed, Approved, Executed, Recorded, Closed, Denied, Escalated, Remediated |
| `BctsState::valid_transitions()` | fn | Returns valid successor states for any given state |
| `BctsReceipt` | struct | Cryptographic receipt: from/to states, actor DID, timestamp, evidence hash, signature |
| `BctsTransaction` | struct | Full transaction: id, state, receipt chain, correlation ID, timestamps |
| `BctsTransaction::transition()` | fn | Advance state with receipt-chain verification |
| `BctsTransaction::verify_receipt_chain()` | fn | Verify cryptographic integrity of the entire receipt chain |

#### `crypto` — Cryptographic Operations

| Item | Kind | Description |
|------|------|-------------|
| `generate_keypair()` | fn | Generate Ed25519 keypair from OS randomness |
| `sign()` | fn | Sign a byte slice with a secret key |
| `verify()` | fn | Verify a signature against public key and message |

#### `error` — Error Types

| Item | Kind | Description |
|------|------|-------------|
| `ExoError` | enum | Unified error type: InvalidDid, InvalidSignature, InvalidTimestamp, HashMismatch, StateTransitionDenied, SerializationError, InvariantViolation, Internal |
| `Result<T>` | type | Alias for `std::result::Result<T, ExoError>` |

#### `events` — Event System

| Item | Kind | Description |
|------|------|-------------|
| `ExoEvent` | struct | Event envelope: id, event_type, actor, timestamp, payload hash, correlation ID |
| `EventBus` | struct | Ordered event bus with deterministic BTreeMap-based subscriber dispatch |
| `EventHandler` | trait | Handler interface with `handle(&self, event: &ExoEvent) -> Result<()>` |

#### `hash` — Canonical Hashing

| Item | Kind | Description |
|------|------|-------------|
| `hash_bytes()` | fn | BLAKE3 hash of raw bytes |
| `hash_structured()` | fn | Canonical CBOR serialization then BLAKE3 hash (deterministic for any Serialize type) |

#### `hlc` — Hybrid Logical Clock

| Item | Kind | Description |
|------|------|-------------|
| `HybridClock` | struct | HLC implementation: physical ms + logical counter + node ID |
| `HybridClock::now()` | fn | Generate a new timestamp, advancing logical counter |
| `HybridClock::receive()` | fn | Merge with a remote timestamp (max physical + increment logical) |

#### `invariants` — Core Invariant Framework

| Item | Kind | Description |
|------|------|-------------|
| `Invariant` | trait | `fn check(&self, ctx: &InvariantContext) -> Result<()>` |
| `InvariantContext` | struct | Context for invariant evaluation: actor, action, consent state, authority chain |

#### `types` — Foundational Types

| Item | Kind | Description |
|------|------|-------------|
| `Did` | struct | Decentralized Identifier (validated `did:exo:*` format) |
| `Hash256` | struct | 32-byte BLAKE3 hash with `ZERO` constant and `digest()` constructor |
| `PublicKey` | struct | Ed25519 public key (32 bytes) |
| `SecretKey` | struct | Ed25519 secret key (32 bytes, Zeroize on drop) |
| `Signature` | struct | Ed25519 signature (64 bytes) |
| `Timestamp` | struct | HLC timestamp: `physical_ms`, `logical`, `node_id` with `ZERO` constant |
| `Version` | struct | Semantic version triple (major, minor, patch) |
| `CorrelationId` | struct | UUID-based correlation identifier for request tracing |
| `DeterministicMap<K,V>` | type | Alias for `BTreeMap<K,V>` — constitutional requirement |

### Key Invariants Enforced

- `BctsState` transitions are exhaustively defined; invalid transitions return `ExoError::StateTransitionDenied`
- Receipt chains are cryptographically linked; any gap is detected by `verify_receipt_chain()`
- `hash_structured()` always produces identical output for identical input (canonical CBOR)
- HLC monotonicity: `now()` always returns a timestamp strictly greater than any prior timestamp on the same node
- `Did::new()` rejects any string not matching `did:exo:*` format

### Test Coverage Summary

191 tests covering: BCTS state machine transitions (all valid/invalid pairs), receipt chain integrity, crypto sign/verify round-trips, HLC monotonicity and merge, canonical hash determinism, type serialization round-trips, event bus ordering.

> See also: [[ARCHITECTURE]] Section 2 (Core Types), [[CONSTITUTIONAL-PROOFS]] Proof 1 (Determinism)

---

## 2. exo-gatekeeper

| Metric | Value |
|--------|-------|
| LOC | 2,875 |
| Tests | 133 |
| Files | 9 |

### Purpose

The judicial branch of EXOCHAIN. Implements the Constitutional Governance Runtime (CGR): an immutable kernel that adjudicates every operation against the eight constitutional invariants, a combinator algebra for deterministic composition of governance operations, a Holon autonomous agent runtime, Model Context Protocol (MCP) enforcement for AI systems, and Trusted Execution Environment (TEE) attestation verification.

### Dependencies

`exo-core`. External: `serde`, `blake3`, `thiserror`, `uuid`, `tracing`.

### Modules

#### `kernel` — Immutable Adjudicator

| Item | Kind | Description |
|------|------|-------------|
| `Kernel` | struct | Immutable CGR kernel: configuration frozen at creation, adjudicates all actions |
| `KernelConfig` | struct | Frozen configuration: version, invariant set, actor roles, audit settings |
| `ActionRequest` | struct | Request to perform an action: actor, action type, resource, evidence |
| `Verdict` | enum | Allowed, Denied(reasons), Escalated(reasons) |
| `AdjudicationContext` | struct | Full context for adjudication: actor roles, consent state, authority chain |
| `Kernel::adjudicate()` | fn | Core adjudication: checks all invariants, returns Verdict |
| `Kernel::verify_separation_of_powers()` | fn | Ensures no actor holds multiple branch roles simultaneously |

#### `invariants` — Constitutional Invariants

| Item | Kind | Description |
|------|------|-------------|
| `ConstitutionalInvariant` | enum | The eight invariants: SeparationOfPowers, ConsentRequired, NoSelfGrant, HumanOverride, KernelImmutability, AuthorityChainValid, QuorumLegitimate, ProvenanceVerifiable |
| `InvariantEngine` | struct | Engine that evaluates all invariants against a context |
| `InvariantSet` | struct | Collection of enabled invariants with `all()` and `without()` constructors |
| `InvariantViolation` | struct | Detailed violation report: which invariant, evidence, actor, timestamp |
| `InvariantEngine::check_all()` | fn | Evaluate every enabled invariant, collecting all violations |

#### `combinator` — Deterministic Algebra

| Item | Kind | Description |
|------|------|-------------|
| `Combinator` | enum | Terms: Identity, Sequence, Parallel, Choice, Guard, Transform, Retry, Timeout, Checkpoint |
| `CombinatorInput` | struct | Typed input: `BTreeMap<String, String>` fields |
| `CombinatorOutput` | struct | Typed output: fields, trace, and status |
| `Predicate` | struct | Guard predicate: required key, optional expected value |
| `TransformFn` | struct | Output transformation: key/value pair to inject |
| `RetryPolicy` | struct | Retry configuration: max retries, current attempt |
| `CheckpointId` | struct | Resumable checkpoint identifier |
| `reduce()` | fn | Pure reduction: `reduce(combinator, input) -> Result<output>` |

#### `holon` — Autonomous Agent Runtime

| Item | Kind | Description |
|------|------|-------------|
| `Holon` | struct | Autonomous agent: DID identity, state, capabilities, step history |
| `HolonState` | enum | Created, Running, Suspended, Completed, Failed |
| `HolonStep` | struct | A single adjudicated step: action, verdict, timestamp |
| `Holon::execute_step()` | fn | Execute one step through kernel adjudication |
| `Holon::capability_check()` | fn | Verify the holon has permission for an action |

#### `mcp` — Model Context Protocol Enforcement

| Item | Kind | Description |
|------|------|-------------|
| `McpContext` | struct | MCP session context: model ID, session ID, permissions, audit trail |
| `McpRule` | struct | Rule governing AI model behavior: allowed actions, denied patterns |
| `McpViolation` | struct | Record of an MCP rule violation |
| `McpEngine` | struct | Evaluates model actions against MCP rules |
| `McpEngine::evaluate()` | fn | Check whether a model action is permitted |

#### `tee` — Trusted Execution Environment

| Item | Kind | Description |
|------|------|-------------|
| `TeeAttestation` | struct | TEE attestation report: platform, measurements, timestamp, signature |
| `TeePlatform` | enum | SGX, TrustZone, SEV, Simulated |
| `TeePolicy` | struct | Required measurements and minimum platform level |
| `verify_attestation()` | fn | Verify attestation against policy |

### Key Invariants Enforced

- Kernel configuration is immutable after creation (`KernelImmutability`)
- Every `adjudicate()` call checks all eight constitutional invariants
- Combinator reduction is pure: identical inputs always produce identical outputs
- MCP enforcement prevents AI systems from bypassing governance
- Holon steps are individually adjudicated and recorded

### Test Coverage Summary

133 tests covering: kernel adjudication (all 8 invariants individually and combined), combinator reduction (all 9 terms), holon lifecycle, MCP rule evaluation, TEE attestation verification, separation of powers enforcement.

> See also: [[ARCHITECTURE]] Section 3 (Judicial Branch), [[THREAT-MODEL]] Threat 9 (Kernel Tampering), [[CONSTITUTIONAL-PROOFS]] Proof 3 (Kernel Immutability)

---

## 3. exo-dag

| Metric | Value |
|--------|-------|
| LOC | 2,590 |
| Tests | 86 |
| Files | 7 |

### Purpose

Append-only directed acyclic graph with BFT consensus and authenticated data structures. Provides the immutable ledger layer: DAG nodes with parent references and content hashes, a Byzantine fault-tolerant consensus protocol tolerating f < n/3 faults, a Sparse Merkle Tree (SMT) for authenticated key-value storage, a Merkle Mountain Range (MMR) for append-only accumulation, and a pluggable storage abstraction.

### Dependencies

`exo-core`. External: `serde`, `blake3`, `thiserror`, `uuid`.

### Modules

#### `dag` — Append-Only DAG

| Item | Kind | Description |
|------|------|-------------|
| `DagNode` | struct | Node: hash, parents (Vec), payload hash, creator DID, timestamp |
| `Dag` | struct | In-memory DAG with BTreeMap storage and topological ordering |
| `Dag::append()` | fn | Append a node, verifying parent hashes exist |
| `Dag::ancestors()` | fn | Retrieve all ancestors of a node (BFS traversal) |
| `Dag::topological_order()` | fn | Return all nodes in deterministic topological order |

#### `consensus` — DAG-BFT Consensus

| Item | Kind | Description |
|------|------|-------------|
| `ConsensusConfig` | struct | Validator set, fault tolerance, round timeout |
| `Vote` | struct | Validator vote: node hash, voter DID, round, signature |
| `Proposal` | struct | Consensus proposal: node, proposer, round |
| `CommitCertificate` | struct | Commit proof: node hash, votes achieving quorum |
| `ConsensusEngine` | struct | BFT engine: tracks rounds, votes, finalized nodes |
| `ConsensusEngine::propose()` | fn | Submit a proposal for the current round |
| `ConsensusEngine::vote()` | fn | Cast a vote for a proposal |
| `ConsensusEngine::try_finalize()` | fn | Attempt to finalize if quorum reached (>2/3 votes) |

#### `smt` — Sparse Merkle Tree

| Item | Kind | Description |
|------|------|-------------|
| `SparseMerkleTree` | struct | Authenticated key-value store with inclusion/exclusion proofs |
| `MerkleProof` | struct | Proof of inclusion or exclusion for a key |
| `SparseMerkleTree::insert()` | fn | Insert key-value pair, updating root hash |
| `SparseMerkleTree::get_proof()` | fn | Generate a Merkle proof for a key |
| `SparseMerkleTree::verify_proof()` | fn | Verify a proof against a known root |

#### `mmr` — Merkle Mountain Range

| Item | Kind | Description |
|------|------|-------------|
| `MerkleMountainRange` | struct | Append-only accumulator with efficient membership proofs |
| `MmrProof` | struct | Membership proof for an element |
| `MerkleMountainRange::push()` | fn | Append an element, updating peaks |
| `MerkleMountainRange::prove()` | fn | Generate membership proof |
| `MerkleMountainRange::verify()` | fn | Verify membership proof against root |

#### `store` — Storage Abstraction

| Item | Kind | Description |
|------|------|-------------|
| `DagStore` | trait | `get()`, `put()`, `contains()`, `list_roots()` |
| `MemoryStore` | struct | In-memory BTreeMap-backed implementation |

### Key Invariants Enforced

- DAG is append-only: nodes cannot be modified or deleted after insertion
- Parent references must point to existing nodes (no dangling references)
- BFT consensus requires >2/3 validator votes for finalization
- SMT proofs are cryptographically bound to the root hash
- MMR is append-only with deterministic peak computation

### Test Coverage Summary

86 tests covering: DAG append/ancestry/topological ordering, BFT consensus quorum math, vote counting, finalization, SMT insert/proof/verify round-trips, MMR push/prove/verify, storage trait implementations.

> See also: [[ARCHITECTURE]] Section 5 (Ledger Layer), [[THREAT-MODEL]] Threat 10 (Receipt Chain Forgery), [[CONSTITUTIONAL-PROOFS]] Proof 8 (Provenance Verifiable)

---

## 4. exo-proofs

| Metric | Value |
|--------|-------|
| LOC | 1,916 |
| Tests | 61 |
| Files | 7 |

### Purpose

Zero-knowledge proof system for EXOCHAIN. Provides R1CS circuit abstraction for expressing arithmetic circuits, SNARK proof generation and verification, STARK proof generation and verification, a zero-knowledge machine learning (ZKML) verifier for AI model attestation, and a unified proof verifier dispatching across proof types.

### Dependencies

`exo-core`. External: `serde`, `blake3`, `sha2`, `thiserror`, `serde_json`.

### Modules

#### `circuit` — R1CS Constraint System

| Item | Kind | Description |
|------|------|-------------|
| `Variable` | struct | Constraint system variable: index, optional witness value |
| `LinearCombination` | struct | Sum of (coefficient, variable_index) pairs |
| `Constraint` | struct | R1CS constraint: A * B = C (three linear combinations) |
| `ConstraintSystem` | struct | Collection of variables and constraints |
| `Circuit` | trait | `fn synthesize(&self, cs: &mut ConstraintSystem) -> Result<()>` |
| `ConstraintSystem::alloc_variable()` | fn | Allocate a new variable with optional witness |
| `ConstraintSystem::enforce()` | fn | Add an R1CS constraint |
| `ConstraintSystem::verify()` | fn | Check all constraints are satisfied by current witness values |

#### `snark` — SNARK Proof System

| Item | Kind | Description |
|------|------|-------------|
| `SnarkProof` | struct | Proof bytes, circuit hash, public inputs, timestamp |
| `ProvingKey` | struct | Key material for proof generation |
| `VerifyingKey` | struct | Key material for proof verification |
| `setup()` | fn | Generate proving and verifying keys from a circuit |
| `prove()` | fn | Generate a SNARK proof from a circuit and proving key |
| `verify()` | fn | Verify a SNARK proof against a verifying key |

#### `stark` — STARK Proof System

| Item | Kind | Description |
|------|------|-------------|
| `StarkProof` | struct | Transparent proof: trace commitment, query responses, FRI layers |
| `StarkConfig` | struct | Configuration: field size, expansion factor, security level |
| `TraceTable` | struct | Execution trace as a 2D array of field elements |
| `FriLayer` | struct | FRI commitment layer for proof compression |
| `prove()` | fn | Generate a STARK proof from a trace table |
| `verify()` | fn | Verify a STARK proof (no trusted setup required) |

#### `zkml` — Zero-Knowledge ML Verification

| Item | Kind | Description |
|------|------|-------------|
| `ZkmlAttestation` | struct | Model attestation: model hash, input hash, output hash, proof |
| `ModelCommitment` | struct | Commitment to model weights without revealing them |
| `InferenceProof` | struct | Proof that inference was run on committed model |
| `verify_inference()` | fn | Verify that a model output corresponds to given input and committed model |

#### `verifier` — Unified Proof Verifier

| Item | Kind | Description |
|------|------|-------------|
| `ProofType` | enum | Snark, Stark, Zkml |
| `UnifiedProof` | struct | Wraps any proof type with metadata |
| `ProofVerifier` | struct | Multi-backend verifier dispatching to SNARK/STARK/ZKML |
| `ProofVerifier::verify()` | fn | Verify any proof type through unified interface |

### Key Invariants Enforced

- R1CS constraints are satisfied or verification fails (soundness)
- SNARK proofs are zero-knowledge: verifier learns nothing beyond the statement
- STARK proofs require no trusted setup (transparency)
- ZKML attestation cryptographically binds model identity to inference output

### Test Coverage Summary

61 tests covering: circuit constraint synthesis and verification, SNARK setup/prove/verify round-trips, STARK prove/verify, ZKML attestation verification, unified verifier dispatch, proof serialization determinism.

> See also: [[ARCHITECTURE]] Section 6 (Proof System), [[CONSTITUTIONAL-PROOFS]] Proof 10 (Zero-Knowledge Soundness)

---

## 5. exo-identity

| Metric | Value |
|--------|-------|
| LOC | 1,533 |
| Tests | 67 |
| Files | 7 |

### Purpose

Privacy-preserving identity adjudication. Manages Decentralized Identity (DID) documents with registration, resolution, revocation, and key rotation. Provides signed risk attestations with expiry and policy enforcement, Shamir secret sharing over GF(256) for Sybil-defense secret splitting, PACE (Primary/Alternate/Contingency/Emergency) operator continuity escalation, and key lifecycle management.

### Dependencies

`exo-core`. External: `serde`, `blake3`, `ed25519-dalek`, `sha2`, `rand`, `zeroize`, `thiserror`, `uuid`.

### Modules

#### `did` — DID Document Management

| Item | Kind | Description |
|------|------|-------------|
| `DidDocument` | struct | DID document: id, public keys, authentication methods, service endpoints, timestamps, revocation status |
| `DidRegistry` | struct | In-memory registry (BTreeMap) with `resolve()`, `register()`, `revoke()`, `rotate_key()` |
| `AuthenticationMethod` | struct | Named authentication method with public key |
| `ServiceEndpoint` | struct | Named service endpoint with type and URL |
| `RevocationProof` | struct | Signed proof authorizing DID revocation |

#### `risk` — Risk Attestation

| Item | Kind | Description |
|------|------|-------------|
| `RiskAttestation` | struct | Signed risk assessment: subject DID, level, factors, expiry, assessor signature |
| `RiskLevel` | enum | Low, Medium, High, Critical |
| `RiskFactor` | struct | Individual risk factor with weight and evidence |
| `RiskPolicy` | struct | Threshold policy: maximum acceptable risk per operation type |
| `evaluate_risk()` | fn | Evaluate a DID's risk against a policy |

#### `shamir` — Shamir Secret Sharing (GF(256))

| Item | Kind | Description |
|------|------|-------------|
| `Share` | struct | A secret share: x-coordinate, y-values |
| `split()` | fn | Split a secret into n shares with threshold k |
| `reconstruct()` | fn | Reconstruct a secret from k or more shares |
| GF(256) arithmetic | fns | `gf256_add`, `gf256_mul`, `gf256_inv` — constant-time field operations |

#### `pace` — Operator Continuity (PACE)

| Item | Kind | Description |
|------|------|-------------|
| `PaceConfig` | struct | PACE configuration: primary, alternate, contingency, emergency operators |
| `PaceStatus` | enum | Primary, Alternate, Contingency, Emergency |
| `PaceEngine` | struct | Escalation engine tracking current operator and failover state |
| `PaceEngine::escalate()` | fn | Escalate to next operator level |
| `PaceEngine::restore()` | fn | Restore to a previous operator level |

#### `key_management` — Key Lifecycle

| Item | Kind | Description |
|------|------|-------------|
| `KeyRecord` | struct | Key lifecycle record: public key, status, created/rotated/revoked timestamps |
| `KeyStatus` | enum | Active, Rotated, Revoked, Compromised |
| `KeyStore` | struct | Key lifecycle store with `create()`, `rotate()`, `revoke()`, `mark_compromised()` |

### Key Invariants Enforced

- DID registry prevents duplicate registrations
- Revoked DIDs cannot be resolved (filter on `revoked` flag)
- Shamir reconstruction requires exactly threshold shares (k-of-n)
- PACE escalation follows strict ordering: Primary -> Alternate -> Contingency -> Emergency
- Key rotation produces a new key and marks the old key as Rotated (never deleted)

### Test Coverage Summary

67 tests covering: DID registration/resolution/revocation/rotation, risk attestation evaluation against policies, Shamir split/reconstruct for various k-of-n configurations, GF(256) arithmetic properties, PACE escalation ordering, key lifecycle transitions.

> See also: [[ARCHITECTURE]] Section 4 (Identity Layer), [[THREAT-MODEL]] Threat 1 (Identity Sybil), [[CONSTITUTIONAL-PROOFS]] Proof 5 (Authority Chain Integrity)

---

## 6. exo-governance

| Metric | Value |
|--------|-------|
| LOC | 1,236 |
| Tests | 69 |
| Files | 9 |

### Purpose

Legislative legitimacy for the EXOCHAIN trust fabric. Provides quorum computation with independence-aware counting (Sybil-resistant), clearance enforcement mapping roles to permitted actions, crosscheck verification for multi-party validation, challenge mechanisms for disputing governance decisions, deliberation processes for structured decision-making, conflict detection, and hash-chained audit trails.

### Dependencies

`exo-core`, `exo-identity`, `exo-consent`, `exo-authority`. External: `serde`, `blake3`, `thiserror`, `uuid`.

### Modules

#### `quorum` — Independence-Aware Quorum

| Item | Kind | Description |
|------|------|-------------|
| `QuorumConfig` | struct | Configuration: threshold (basis points), minimum participants, independence requirements |
| `QuorumVote` | struct | A vote: voter DID, decision, independence attestation, timestamp |
| `QuorumResult` | enum | Met, NotMet(reason), InvalidVotes(details) |
| `IndependenceAttestation` | struct | Signed attestation of voter independence |
| `compute_quorum()` | fn | Compute quorum with independence-weighted counting |

#### `clearance` — Role-Based Clearance

| Item | Kind | Description |
|------|------|-------------|
| `ClearanceLevel` | enum | Public, Restricted, Confidential, Secret, TopSecret |
| `ClearancePolicy` | struct | Maps roles to clearance levels and permitted actions |
| `check_clearance()` | fn | Verify an actor's clearance for an action |

#### `crosscheck` — Multi-Party Verification

| Item | Kind | Description |
|------|------|-------------|
| `CrosscheckRequest` | struct | Request for independent verification by multiple parties |
| `CrosscheckResponse` | struct | A verifier's response with evidence |
| `CrosscheckResult` | enum | Confirmed, Disputed, Insufficient |
| `evaluate_crosscheck()` | fn | Evaluate crosscheck responses against threshold |

#### `challenge` — Decision Challenge Mechanism

| Item | Kind | Description |
|------|------|-------------|
| `Challenge` | struct | Challenge to a governance decision: challenger, grounds, evidence |
| `ChallengeStatus` | enum | Filed, UnderReview, Upheld, Dismissed |
| `ChallengeEngine` | struct | Manages challenge lifecycle |
| `ChallengeEngine::file()` | fn | File a new challenge |
| `ChallengeEngine::adjudicate()` | fn | Adjudicate a challenge (upheld or dismissed) |

#### `deliberation` — Structured Deliberation

| Item | Kind | Description |
|------|------|-------------|
| `Deliberation` | struct | Deliberation process: proposal, contributions, status, timeline |
| `Contribution` | struct | Participant's contribution: content, evidence, timestamp |
| `DeliberationStatus` | enum | Open, Closed, Decided |
| `Deliberation::add_contribution()` | fn | Add a contribution during open deliberation |
| `Deliberation::close()` | fn | Close deliberation and tally results |

#### `conflict` — Conflict Detection

| Item | Kind | Description |
|------|------|-------------|
| `Conflict` | struct | Detected conflict between governance actions |
| `detect_conflicts()` | fn | Scan a set of actions for conflicts |

#### `audit` — Hash-Chained Audit Log

| Item | Kind | Description |
|------|------|-------------|
| `AuditEntry` | struct | Audit entry: id, timestamp, actor, action, result, evidence hash, chain hash |
| `AuditLog` | struct | Append-only hash-chained log |
| `append()` | fn | Append an entry, verifying chain hash continuity |
| `verify_chain()` | fn | Verify the entire chain from genesis to head |

### Key Invariants Enforced

- Quorum requires independence attestation; non-independent votes are discounted (`QuorumLegitimate`)
- Clearance checks enforce least-privilege access
- Crosscheck requires a minimum number of independent verifiers
- Audit log is hash-chained: any tampering breaks `verify_chain()`
- Challenge mechanism ensures no decision is final without opportunity for dispute

### Test Coverage Summary

69 tests covering: quorum computation with independence weighting, clearance level comparisons, crosscheck threshold evaluation, challenge lifecycle, deliberation open/contribute/close, audit chain append/verify, conflict detection.

> See also: [[ARCHITECTURE]] Section 3 (Legislative Branch), [[THREAT-MODEL]] Threat 3 (Quorum Sybil), [[CONSTITUTIONAL-PROOFS]] Proof 7 (Quorum Legitimacy)

---

## 7. exo-authority

| Metric | Value |
|--------|-------|
| LOC | 1,235 |
| Tests | 66 |
| Files | 6 |

### Purpose

Authority chain verification and delegation management. Tracks delegation of permissions from root to leaf, enforcing the constitutional rule that scope can only narrow through delegation, never widen. Provides an LRU-like cache for resolved chains, a delegation registry, and a permission algebra.

### Dependencies

`exo-core`, `exo-identity`. External: `serde`, `blake3`, `thiserror`.

### Modules

#### `chain` — Authority Chain Verification

| Item | Kind | Description |
|------|------|-------------|
| `AuthorityChain` | struct | Chain of delegation links from root to leaf |
| `AuthorityLink` | struct | Single link: grantor DID, grantee DID, permissions, constraints, expiry |
| `AuthorityChain::verify()` | fn | Verify the chain is valid: each link's scope is a subset of its parent |
| `AuthorityChain::effective_permissions()` | fn | Compute the intersection of all link permissions |

#### `delegation` — Delegation Registry

| Item | Kind | Description |
|------|------|-------------|
| `DelegationRegistry` | struct | Registry of all active delegations (BTreeMap by DID pair) |
| `Delegation` | struct | Delegation record: grantor, grantee, permissions, constraints, timestamps |
| `DelegationRegistry::delegate()` | fn | Create a delegation (scope must be subset of grantor's) |
| `DelegationRegistry::revoke()` | fn | Revoke a delegation |
| `DelegationRegistry::resolve_chain()` | fn | Resolve the full authority chain for a DID pair |

#### `permission` — Permission Algebra

| Item | Kind | Description |
|------|------|-------------|
| `Permission` | struct | Named permission with resource scope |
| `PermissionSet` | struct | Set of permissions with subset/intersection/union operations |
| `PermissionSet::is_subset_of()` | fn | Check if one set is a subset of another |
| `PermissionSet::intersection()` | fn | Compute the intersection of two permission sets |

#### `cache` — Chain Resolution Cache

| Item | Kind | Description |
|------|------|-------------|
| `ChainCache` | struct | LRU-like cache for resolved authority chains |
| `ChainCache::get()` | fn | Retrieve cached chain (updates access timestamp) |
| `ChainCache::insert()` | fn | Insert a resolved chain (evicts oldest if at capacity) |

### Key Invariants Enforced

- Delegation scope can only narrow, never widen (`NoSelfGrant`)
- Authority chains must be unbroken from root to leaf (`AuthorityChainValid`)
- Expired delegations are rejected during chain verification
- Permission sets use deterministic BTreeSet for consistent intersection computation

### Test Coverage Summary

66 tests covering: chain verification (valid/invalid/expired), delegation create/revoke, scope narrowing enforcement, permission set algebra (subset, intersection, union), cache LRU eviction, chain resolution.

> See also: [[ARCHITECTURE]] Section 4 (Authority Layer), [[THREAT-MODEL]] Threat 4 (Delegation Sybil) and Threat 8 (Authority Escalation), [[CONSTITUTIONAL-PROOFS]] Proof 5 (Authority Chain Integrity)

---

## 8. exo-consent

| Metric | Value |
|--------|-------|
| LOC | 899 |
| Tests | 54 |
| Files | 5 |

### Purpose

Bailment-conditioned consent enforcement. Implements the legal foundation of consent in EXOCHAIN: a bailment is a trust relationship where a bailor entrusts property (data or authority) to a bailee under specific terms. No action may proceed without an active bailment. Default posture: DENY.

### Dependencies

`exo-core`. External: `serde`, `blake3`, `thiserror`, `uuid`.

### Modules

#### `bailment` — Bailment Model

| Item | Kind | Description |
|------|------|-------------|
| `Bailment` | struct | Bailment record: id, bailor DID, bailee DID, type, terms hash, timestamps, status, signature |
| `BailmentType` | enum | Custody, Processing, Delegation, Emergency |
| `BailmentStatus` | enum | Proposed, Active, Suspended, Terminated, Expired |
| `BailmentRegistry` | struct | Registry of bailments with lifecycle management |
| `BailmentRegistry::propose()` | fn | Propose a new bailment |
| `BailmentRegistry::activate()` | fn | Activate a proposed bailment (requires bailor signature) |
| `BailmentRegistry::suspend()` | fn | Suspend an active bailment |
| `BailmentRegistry::terminate()` | fn | Terminate a bailment |

#### `gatekeeper` — Consent Gate

| Item | Kind | Description |
|------|------|-------------|
| `ConsentGate` | struct | Gate that checks consent before any action proceeds |
| `ConsentGate::check()` | fn | Verify an active bailment exists for the actor-resource pair |

#### `policy` — Policy Engine

| Item | Kind | Description |
|------|------|-------------|
| `ConsentPolicy` | struct | Policy definition: required bailment types, minimum terms |
| `ConsentRequirement` | struct | Specific requirement for an action type |
| `ConsentDecision` | enum | Granted, Denied(reason) |
| `PolicyEngine` | struct | Evaluates actions against consent policies |
| `PolicyEngine::evaluate()` | fn | Evaluate whether consent is granted for an action |

### Key Invariants Enforced

- Default posture is DENY: no action proceeds without explicit consent (`ConsentRequired`)
- Bailment lifecycle transitions are strictly ordered (Proposed -> Active -> Suspended/Terminated/Expired)
- Terms hash is cryptographically bound to the bailment; terms cannot be changed without a new bailment
- Emergency bailments are time-limited and require explicit justification

### Test Coverage Summary

54 tests covering: bailment lifecycle transitions (all valid/invalid), consent gate enforcement, policy evaluation, default-deny behavior, emergency bailment time limits, terms hash binding.

> See also: [[ARCHITECTURE]] Section 4 (Consent Layer), [[THREAT-MODEL]] Threat 7 (Consent Bypass), [[CONSTITUTIONAL-PROOFS]] Proof 4 (Consent Completeness)

---

## 9. exo-escalation

| Metric | Value |
|--------|-------|
| LOC | 824 |
| Tests | 43 |
| Files | 8 |

### Purpose

Operational nervous system for the EXOCHAIN trust fabric. Provides detection of anomalies and threats, triage and severity classification, escalation paths (including Sybil adjudication with a 7-stage pipeline), kanban workflow tracking, feedback loops for continuous improvement, and completeness checking to ensure all required stages are satisfied.

### Dependencies

`exo-core`, `exo-identity`, `exo-governance`. External: `serde`, `thiserror`, `uuid`.

### Modules

#### `escalation` — Escalation Engine

| Item | Kind | Description |
|------|------|-------------|
| `EscalationCase` | struct | Case: id, path, severity, stages completed, evidence, status |
| `EscalationPath` | enum | Standard, Emergency, Constitutional, SybilAdjudication |
| `CaseStatus` | enum | Open, InProgress, Resolved, Dismissed |
| `SybilStage` | enum | Detection, Triage, Quarantine, EvidentaryReview, ClearanceDowngrade, Reinstatement, AuditLog |

#### `detector` — Anomaly Detection

| Item | Kind | Description |
|------|------|-------------|
| `Detector` | struct | Anomaly detection engine with configurable rules |
| `Anomaly` | struct | Detected anomaly: type, severity, evidence, timestamp |
| `AnomalyType` | enum | Behavioral, Structural, Temporal, Statistical |

#### `triage` — Severity Classification

| Item | Kind | Description |
|------|------|-------------|
| `TriageEngine` | struct | Classifies anomalies by severity |
| `Severity` | enum | Low, Medium, High, Critical |
| `TriageResult` | struct | Classification result with recommended path |

#### `kanban` — Workflow Tracking

| Item | Kind | Description |
|------|------|-------------|
| `KanbanBoard` | struct | Tracks escalation cases through workflow stages |
| `KanbanColumn` | enum | Backlog, InProgress, Review, Done |
| `KanbanBoard::move_card()` | fn | Move a case to a new column |

#### `feedback` — Feedback Loops

| Item | Kind | Description |
|------|------|-------------|
| `FeedbackLoop` | struct | Tracks outcomes for continuous improvement |
| `FeedbackEntry` | struct | Case outcome with effectiveness rating |

#### `completeness` — Completeness Checking

| Item | Kind | Description |
|------|------|-------------|
| `CompletenessResult` | enum | Complete, Incomplete(missing stages) |
| `check_completeness()` | fn | Verify all required stages are completed for a case |

### Key Invariants Enforced

- Sybil adjudication requires all 7 stages to complete (`check_completeness()`)
- Human override is always available via Emergency path (`HumanOverride`)
- Escalation paths cannot be bypassed; every case must follow its designated path
- Evidence is required for every escalation case

### Test Coverage Summary

43 tests covering: escalation path routing, Sybil 7-stage completeness, detector anomaly classification, triage severity assignment, kanban workflow transitions, feedback loop recording, completeness checking for all path types.

> See also: [[ARCHITECTURE]] Section 7 (Escalation), [[THREAT-MODEL]] Threats 1-6 (Sybil Family), [[CONSTITUTIONAL-PROOFS]] Proof 6 (Human Override Availability)

---

## 10. exo-legal

| Metric | Value |
|--------|-------|
| LOC | 583 |
| Tests | 63 |
| Files | 8 |

### Purpose

Litigation-grade legal compliance for the EXOCHAIN trust fabric. Provides evidence chain management with custody tracking and admissibility status, eDiscovery search and production, legal privilege assertions and challenges, fiduciary duty tracking and compliance checking, records management with retention policies and disposition lifecycle, and conflict-of-interest disclosure requirements.

### Dependencies

`exo-core`, `exo-identity`, `exo-governance`. External: `serde`, `blake3`, `thiserror`, `uuid`.

### Modules

#### `evidence` — Evidence Chain Management

| Item | Kind | Description |
|------|------|-------------|
| `Evidence` | struct | Evidence record: id, type tag, hash, creator, timestamp, chain of custody, admissibility |
| `AdmissibilityStatus` | enum | Admissible, Challenged, Excluded, Pending |
| `CustodyTransfer` | struct | Transfer record: from DID, to DID, timestamp, reason |
| `create_evidence()` | fn | Create evidence with BLAKE3 hash of source data |
| `transfer_custody()` | fn | Transfer custody, verifying current holder |
| `verify_chain_of_custody()` | fn | Verify unbroken chain from creator to current holder |

#### `ediscovery` — Electronic Discovery

| Item | Kind | Description |
|------|------|-------------|
| `DiscoveryRequest` | struct | Search request: scope, date range, custodians, search terms |
| `DiscoveryResponse` | struct | Produced documents, privilege log, production hash |
| `search()` | fn | Search corpus by custodian, date range, and terms |

#### `privilege` — Legal Privilege

| Item | Kind | Description |
|------|------|-------------|
| `PrivilegeType` | enum | AttorneyClient, WorkProduct, Deliberative, TradeSecret |
| `PrivilegeAssertion` | struct | Assertion of privilege over evidence |
| `PrivilegeChallenge` | struct | Challenge to a privilege assertion |
| `ChallengeStatus` | enum | Pending, Upheld, Overruled |
| `assert_privilege()` | fn | Assert privilege over a piece of evidence |
| `challenge_privilege()` | fn | Challenge a privilege assertion |

#### `fiduciary` — Fiduciary Duty Tracking

| Item | Kind | Description |
|------|------|-------------|
| `DutyType` | enum | Care, Loyalty, GoodFaith, Disclosure, Confidentiality |
| `FiduciaryDuty` | struct | Duty record: principal, fiduciary, type, scope |
| `ComplianceResult` | enum | Compliant, Violation(reasons) |
| `check_duty_compliance()` | fn | Check actions against a fiduciary duty |
| `create_duty()` | fn | Create a duty (prevents principal == fiduciary) |

#### `records` — Records Management

| Item | Kind | Description |
|------|------|-------------|
| `Record` | struct | Record: id, content hash, classification, retention period, disposition |
| `Disposition` | enum | Active, RetentionHold, PendingDestruction, Destroyed |
| `RetentionPolicy` | struct | Maps classifications to retention periods (days) |
| `apply_retention()` | fn | Apply retention policy to records, marking expired ones |
| `create_record()` | fn | Create a record with BLAKE3 hash |

#### `conflict_disclosure` — Conflict of Interest

| Item | Kind | Description |
|------|------|-------------|
| `Disclosure` | struct | Conflict disclosure: declarant, nature, related parties |
| `require_disclosure()` | fn | Check if an action type requires disclosure |
| `file_disclosure()` | fn | File a disclosure |
| `verify_disclosure()` | fn | Mark a disclosure as verified |

### Key Invariants Enforced

- Chain of custody must be unbroken; custody transfers verify current holder
- eDiscovery production hashes are deterministic (BLAKE3 over document hashes)
- Fiduciary duties prevent principal == fiduciary
- Records on RetentionHold cannot be destroyed by retention policy
- Conflict disclosure is required for vote, approve, fund, transfer, delegate, adjudicate actions

### Test Coverage Summary

63 tests covering: evidence creation/custody transfer/chain verification, eDiscovery search by custodian/date/terms, privilege assertion/challenge lifecycle, fiduciary duty compliance for all 5 duty types, records retention/disposition, conflict disclosure requirements.

> See also: [[ARCHITECTURE]] Section 8 (Legal Layer), [[THREAT-MODEL]] Threat 10 (Receipt Chain Forgery)

---

## 11. exo-gateway

| Metric | Value |
|--------|-------|
| LOC | 279 |
| Tests | 27 |
| Files | 6 |

### Purpose

HTTP gateway server with default-deny pattern. Provides DID-based authentication, consent-aware middleware that gates every request through the consent engine and gatekeeper kernel, route dispatch, and server lifecycle management. Every request is authenticated, consent-checked, and kernel-adjudicated before any handler executes.

### Dependencies

`exo-core`, `exo-identity`, `exo-consent`, `exo-gatekeeper`, `exo-governance`. External: `serde`, `serde_json`, `thiserror`, `uuid`, `tracing`.

### Modules

#### `auth` — DID Authentication

| Item | Kind | Description |
|------|------|-------------|
| `Request` | struct | Authentication request: actor DID, action, body hash, signature, timestamp |
| `AuthenticatedActor` | struct | Verified actor with DID and authentication timestamp |
| `authenticate()` | fn | Verify DID format and signature non-emptiness |

#### `middleware` — Consent and Governance Middleware

| Item | Kind | Description |
|------|------|-------------|
| `GatewayMiddleware` | struct | Middleware chain: auth -> consent -> kernel adjudication |
| `MiddlewareResult` | enum | Proceed, Denied(reason) |
| `GatewayMiddleware::process()` | fn | Run full middleware chain for a request |

#### `routes` — Route Dispatch

| Item | Kind | Description |
|------|------|-------------|
| `Route` | struct | Route definition: path, method, handler, required clearance |
| `Router` | struct | Route table with match and dispatch |

#### `server` — Server Lifecycle

| Item | Kind | Description |
|------|------|-------------|
| `ServerConfig` | struct | Server configuration: bind address, TLS settings |
| `Server` | struct | Gateway server with start/stop lifecycle |

### Key Invariants Enforced

- Default-deny: every request must pass auth, consent, and kernel adjudication
- No request reaches a handler without all three checks passing
- Route clearance levels are enforced before dispatch

### Test Coverage Summary

27 tests covering: DID authentication (valid/invalid/empty signature), middleware chain (pass/deny), route matching, server configuration.

> See also: [[ARCHITECTURE]] Section 9 (Gateway Layer), [[THREAT-MODEL]] Threat 7 (Consent Bypass)

---

## 12. exo-tenant

| Metric | Value |
|--------|-------|
| LOC | 268 |
| Tests | 41 |
| Files | 6 |

### Purpose

Multi-tenant isolation, cold storage, and sharding for the EXOCHAIN trust fabric. Provides tenant identity and lifecycle management, data isolation guarantees, cold storage archival with integrity verification, shard allocation and routing, and a pluggable tenant-scoped storage backend.

### Dependencies

`exo-core`, `exo-identity`. External: `serde`, `blake3`, `thiserror`, `uuid`.

### Modules

#### `tenant` — Tenant Management

| Item | Kind | Description |
|------|------|-------------|
| `Tenant` | struct | Tenant record: id, owner DID, status, shard assignment, config |
| `TenantStatus` | enum | Active, Suspended, Archived |
| `TenantRegistry` | struct | Registry with create/suspend/archive lifecycle |

#### `shard` — Shard Allocation

| Item | Kind | Description |
|------|------|-------------|
| `Shard` | struct | Shard: id, capacity, assigned tenants |
| `ShardRouter` | struct | Routes tenant operations to correct shard |
| `ShardRouter::route()` | fn | Deterministic shard routing by tenant ID |

#### `cold_storage` — Cold Storage Archival

| Item | Kind | Description |
|------|------|-------------|
| `ColdArchive` | struct | Archive record: tenant ID, data hash, archived timestamp |
| `ColdStorage` | struct | Cold storage backend with archive/retrieve operations |
| `ColdStorage::archive()` | fn | Move tenant data to cold storage with integrity hash |
| `ColdStorage::verify()` | fn | Verify cold storage archive integrity |

#### `store` — Tenant-Scoped Storage

| Item | Kind | Description |
|------|------|-------------|
| `TenantStore` | trait | Tenant-scoped `get()`, `put()`, `delete()`, `list()` |
| `MemoryTenantStore` | struct | In-memory implementation |

### Key Invariants Enforced

- Tenant data is isolated: no cross-tenant data access
- Cold storage archives include integrity hashes for tamper detection
- Shard routing is deterministic (same tenant always routes to same shard)
- Suspended tenants cannot perform operations

### Test Coverage Summary

41 tests covering: tenant lifecycle (create/suspend/archive), shard allocation and deterministic routing, cold storage archive/verify, tenant store isolation, cross-tenant access prevention.

> See also: [[ARCHITECTURE]] Section 10 (Tenant Isolation)

---

## 13. decision-forum

| Metric | Value |
|--------|-------|
| LOC | 265 |
| Tests | 34 |
| Files | 6 |

### Purpose

Deliberative decision-making forum with constitutional enforcement. Provides decision objects representing governance proposals, constitutional enforcement ensuring decisions comply with all invariants, terms and conditions management with hash-binding, and forum authority management for controlling who may propose and vote.

### Dependencies

`exo-core`, `exo-identity`, `exo-governance`, `exo-gatekeeper`. External: `serde`, `blake3`, `thiserror`, `uuid`.

### Modules

#### `decision` — Decision Objects

| Item | Kind | Description |
|------|------|-------------|
| `Decision` | struct | Decision: id, proposal, votes, status, evidence, timestamps |
| `DecisionStatus` | enum | Proposed, Deliberating, Approved, Rejected, Enacted, Vetoed |
| `DecisionForum` | struct | Forum managing decision lifecycle |
| `DecisionForum::propose()` | fn | Submit a decision proposal |
| `DecisionForum::vote()` | fn | Cast a vote on a decision |
| `DecisionForum::finalize()` | fn | Finalize a decision based on votes |

#### `constitution` — Constitutional Enforcement

| Item | Kind | Description |
|------|------|-------------|
| `ConstitutionalCheck` | struct | Pre/post check binding a decision to invariant verification |
| `enforce_constitution()` | fn | Verify a decision complies with all constitutional invariants |

#### `terms` — Terms and Conditions

| Item | Kind | Description |
|------|------|-------------|
| `Terms` | struct | Terms document: id, content hash, version, effective date |
| `TermsRegistry` | struct | Registry of terms with versioning |
| `TermsRegistry::publish()` | fn | Publish new terms (content hash is binding) |
| `TermsRegistry::accept()` | fn | Record acceptance of terms by a DID |

#### `authority` — Forum Authority

| Item | Kind | Description |
|------|------|-------------|
| `ForumAuthority` | struct | Authority configuration: who may propose, vote, veto |
| `ForumRole` | enum | Proposer, Voter, Vetoer, Observer |

### Key Invariants Enforced

- Every decision is checked against all constitutional invariants before enactment
- Terms are hash-bound: the content hash in the terms record must match the actual content
- Forum roles enforce separation of powers (a Vetoer cannot also be a Proposer)
- Decision lifecycle follows strict state ordering

### Test Coverage Summary

34 tests covering: decision lifecycle (propose/vote/finalize/enact/veto), constitutional enforcement pass/fail, terms publication/acceptance/hash binding, forum authority role enforcement, separation of powers.

> See also: [[ARCHITECTURE]] Section 11 (Decision Forum), [[THREAT-MODEL]] Threat 3 (Quorum Sybil)

---

## 14. exo-api

| Metric | Value |
|--------|-------|
| LOC | 253 |
| Tests | 22 |
| Files | 5 |

### Purpose

P2P networking and external API types. Provides peer-to-peer protocol message types, network topology management, API schema definitions for external consumers, and shared request/response types used across the gateway and P2P layers.

### Dependencies

`exo-core`, `exo-identity`. External: `serde`, `blake3`, `thiserror`, `uuid`, `ciborium`.

### Modules

#### `p2p` — Peer-to-Peer Protocol

| Item | Kind | Description |
|------|------|-------------|
| `PeerMessage` | enum | Protocol messages: Handshake, Sync, Vote, Proposal, Attestation |
| `PeerId` | struct | Peer identifier (DID-based) |
| `PeerRegistry` | struct | Known peers with connection state tracking |
| `PeerRegistry::register()` | fn | Register a new peer |
| `PeerRegistry::heartbeat()` | fn | Update peer liveness |

#### `schema` — API Schema Definitions

| Item | Kind | Description |
|------|------|-------------|
| `ApiSchema` | struct | Schema definition: endpoints, request/response types, version |
| `Endpoint` | struct | Endpoint definition: path, method, request type, response type |

#### `types` — Shared API Types

| Item | Kind | Description |
|------|------|-------------|
| `ApiRequest` | struct | Generic API request: actor DID, action, payload, correlation ID |
| `ApiResponse` | struct | Generic API response: status, payload, correlation ID |
| `ApiStatus` | enum | Success, Error, Pending |

### Key Invariants Enforced

- P2P messages are serialized with canonical CBOR for deterministic hashing
- Peer registry uses BTreeMap for deterministic ordering
- All API types implement Serialize/Deserialize for cross-platform compatibility

### Test Coverage Summary

22 tests covering: P2P message serialization round-trips, peer registration/heartbeat, API schema validation, request/response type serialization, canonical CBOR determinism.

> See also: [[ARCHITECTURE]] Section 9 (API Layer), [[THREAT-MODEL]] Threat 5 (Mesh Sybil)

---

## Summary Table

| Crate | LOC | Tests | Files | Primary Role |
|-------|-----|-------|-------|-------------|
| exo-core | 3,949 | 191 | 10 | Foundational types, HLC, crypto, BCTS |
| exo-gatekeeper | 2,875 | 133 | 9 | Judicial branch: kernel, invariants, combinators |
| exo-dag | 2,590 | 86 | 7 | Append-only DAG, BFT consensus, Merkle structures |
| exo-proofs | 1,916 | 61 | 7 | ZK proofs: SNARK, STARK, ZKML |
| exo-identity | 1,533 | 67 | 7 | DID management, risk, Shamir, PACE, keys |
| exo-governance | 1,236 | 69 | 9 | Quorum, clearance, crosscheck, challenge, audit |
| exo-authority | 1,235 | 66 | 6 | Authority chains, delegation, permissions |
| exo-consent | 899 | 54 | 5 | Bailment consent, default-deny |
| exo-escalation | 824 | 43 | 8 | Detection, triage, Sybil adjudication, kanban |
| exo-legal | 583 | 63 | 8 | Evidence, eDiscovery, privilege, fiduciary, records |
| exo-gateway | 279 | 27 | 6 | HTTP gateway, auth, consent middleware |
| exo-tenant | 268 | 41 | 6 | Multi-tenant isolation, cold storage, sharding |
| decision-forum | 265 | 34 | 6 | Decision objects, constitutional enforcement |
| exo-api | 253 | 22 | 5 | P2P protocol, API types |
| exo-node | — | — | — | Single-binary EXOCHAIN node — P2P networking, BFT consensus reactor, state sync, embedded dashboard, and CLI |
| exochain-wasm | — | — | — | WASM compilation target — browser and edge bindings for EXOCHAIN governance primitives |
| **Total** | **18,705** | **1,846** | **104** | |

---

> This reference is maintained in sync with the codebase. For architectural context see [[ARCHITECTURE]]. For the threat model see [[THREAT-MODEL]]. For formal proofs see [[CONSTITUTIONAL-PROOFS]].

# PANEL-3: SYSTEMS ARCHITECTURE REVIEW

**Panel:** Systems Architecture
**Discipline:** Distributed Systems, Cryptographic Proof Architecture, Formal Verification, Scale Engineering
**Document Under Review:** decision.forum PRD v1.1.0
**Date:** 2026-03-18
**Reviewer Posture:** Adversarial -- searching for hidden state, broken determinism, specification ambiguity

---

## Preamble: Codebase Baseline

The following review was conducted against the live implementation at `/Users/bobstewart/obsidian/aeon/exochain/crates/`. Every assessment maps to actual Rust source, not aspirational architecture. Where the PRD refers to capabilities that do not exist in code, the gap is flagged with severity.

---

### ARCH-001 -- Merkle-DAG Proof Architecture for Domain Objects

**Architecture Assessment:** Sound, but Underspecified

**Exochain Coverage:**
- `exo-dag/src/dag.rs` -- Append-only DAG with Blake3 hashing, sorted parent canonicalization, cycle detection, signature verification
- `exo-dag/src/smt.rs` -- Sparse Merkle Tree with 256-bit key space, inclusion/non-inclusion proofs, proptest-verified determinism
- `exo-dag/src/mmr.rs` -- Merkle Mountain Range, append-only accumulator with peak-bagging and proof generation
- `exo-dag/src/mmr.rs` -- Merkle Mountain Range proof generation and verification
- `exo-dag/src/store.rs` -- DagStore trait + MemoryStore with BTreeMap (deterministic iteration)
- `exo-dag/src/checkpoint.rs` -- CheckpointPayload with event_root (MMR), state_root (SMT), validator signatures
- `exo-core/src/hash.rs` -- Canonical Blake3 hashing

**Gaps:**
1. **No domain-object binding.** The DAG stores raw `payload_hash` bytes. There is no typed schema enforcement binding Decision, Vote, Amendment, or other domain objects to specific DAG node types. Any bytes can be committed. The requirement says "Domain Objects" but the implementation is type-erased.
2. **No proof composition.** The SMT, MMR, and DAG proofs are independent structures. There is no composite proof type that proves "this decision exists in the DAG AND its state is committed in the SMT AND its position is accumulated in the MMR." The verifier crate dispatches by proof type but cannot verify a multi-layer proof chain.
3. **No deletion-resistance proof.** The `store.rs` trait includes a `tips()` and `mark_committed()` but no mechanism to prove that no node has been deleted between checkpoints.
4. **SMT performance at scale.** The current SMT implementation recomputes the entire tree on every `root()` call by recursively walking all 256 levels. At 1M decisions/day over 50 years (~18B entries), this is computationally infeasible without caching or a persistent Merkle trie.

**Optimized Requirement:**
> Every domain object (Decision, Vote, Amendment, Challenge, Escalation) MUST be committed as a typed DagNode with a schema-version prefix in its payload. The system MUST provide a composite `ChainProof` structure that binds: (a) DAG inclusion via parent-hash chain, (b) state membership via SMT inclusion proof, and (c) historical accumulation via MMR proof. The composite proof MUST be independently verifiable with O(log n) operations and without access to the full DAG. The SMT implementation MUST support incremental root computation with amortized O(log n) insertion cost.

**Test Specification:**
- `test_typed_domain_node_binding`: Append a Decision payload to DAG; verify the payload deserializes to the correct schema version and domain type; reject payloads with unknown schema versions.
- `test_composite_chain_proof`: Create a DAG node, insert its state into SMT, append to MMR; generate a ChainProof; verify it against the three roots independently; tamper with any single layer and confirm verification fails.
- `test_deletion_detection`: Commit 100 nodes, remove one from the store, attempt checkpoint; verify the checkpoint process detects the missing node via MMR gap.
- `test_smt_incremental_root`: Insert 10,000 keys; measure that each subsequent root computation is O(log n), not O(n * 256).

---

### ARCH-002 -- Global Proof Layer via hybrid zk-SNARK + zk-STARK

**Architecture Assessment:** Sound in structure, Overspecified in mechanism choice

**Exochain Coverage:**
- `exo-proofs/src/circuit.rs` -- R1CS constraint system, Variable allocation, LinearCombination, Circuit trait
- `exo-proofs/src/snark.rs` -- Groth16-like structure (pedagogical; hash-based, not elliptic-curve)
- `exo-proofs/src/stark.rs` -- STARK with FRI proof, Fiat-Shamir transform, hash-based post-quantum
- `exo-proofs/src/zkml.rs` -- ZKML inference proof binding model commitment to input/output
- `exo-proofs/src/verifier.rs` -- Unified verifier dispatching to SNARK, STARK, ZKML via ProofType enum

**Gaps:**
1. **Pedagogical implementations only.** Both SNARK and STARK are explicitly marked as "NOT cryptographically hardened." The SNARK uses blake3 hashes in place of elliptic curve pairings. The STARK FRI proof is simulated with iterative hashing rather than actual polynomial commitment. These cannot be used in production.
2. **No recursive/aggregated proofs.** The requirement implies a "Global Proof Layer" aggregating per-tenant proofs into a single verifiable commitment. No aggregation circuit exists. The verifier dispatches to individual proof types but cannot compose them.
3. **No proof size budget.** The STARK proof includes the full config, query values, and layer commitments. At scale (1M decisions/day), proof sizes are unbounded. No succinct proof compression is implemented.
4. **SNARK-STARK hybrid is overspecified.** The PRD prescribes "hybrid zk-SNARK + zk-STARK" but the actual requirement is: succinctness for per-decision proofs (SNARK) + post-quantum safety for archival proofs (STARK). Prescribing the hybrid mechanism constrains implementation unnecessarily.

**Optimized Requirement:**
> The system MUST provide two proof tiers: (a) a succinct per-decision proof verifiable in < 200ms with proof size < 1 KB, and (b) a post-quantum-safe archival proof for checkpoint aggregation. Per-decision proofs MAY use SNARK or equivalent succinct argument. Archival proofs MUST use hash-based arguments (STARK or equivalent) resistant to quantum attack. A recursive aggregation circuit MUST exist that compresses N per-decision proofs into a single batch proof with O(log N) verification cost. All proof implementations MUST pass NIST-equivalent security parameter targets (128-bit classical, 64-bit post-quantum minimum).

**Test Specification:**
- `test_snark_proof_size_budget`: Generate a proof for a decision circuit; assert serialized proof size < 1 KB.
- `test_stark_proof_post_quantum_hash_only`: Verify STARK proof generation and verification use no elliptic curve operations; all primitives are hash-based.
- `test_recursive_aggregation`: Generate 100 individual SNARK proofs; aggregate into a single batch proof; verify the batch proof validates all 100 decisions; verify single-decision tampering invalidates the batch.
- `test_verification_latency_p99`: Verify 1000 proofs; assert P99 latency < 200ms.
- `test_pedagogical_flag_blocks_production`: Ensure the current pedagogical SNARK/STARK implementations cannot be instantiated in production mode (compile-time or runtime feature gate).

---

### ARCH-003 -- State Machine Replication with Total Order Delivery & TLA+ invariants

**Architecture Assessment:** Underspecified -- critical ordering gap

**Exochain Coverage:**
- `exo-dag/src/consensus.rs` -- BFT consensus with >2/3 quorum, round-based voting, duplicate-vote rejection, commit certificates
- `exo-core/src/hlc.rs` -- Hybrid Logical Clock with drift detection, causal ordering, injectable wall clock
- `exo-dag/src/dag.rs` -- Topological sort for deterministic ordering within DAG subsets
- `exo-core/src/invariants.rs` -- Invariant trait, InvariantSet, InvariantContext with severity levels
- `tla/DecisionLifecycle.tla`, `tla/QuorumSafety.tla` -- TLA+ specs exist

**Gaps:**
1. **No total order delivery.** The DAG provides partial order (topological sort) and the consensus provides per-round finalization order, but there is no global totally-ordered log. Two nodes with the same HLC timestamp on different branches have no deterministic ordering beyond BTreeMap hash order. This is partial order, not total order.
2. **No state machine definition.** The requirement says "State Machine Replication" but there is no explicit state machine definition -- no enumerated states, no transition function, no state hashing for replication comparison. The `InvariantContext` provides a `state_hash` but it is caller-provided (Hash256::ZERO in tests).
3. **Consensus is single-instance.** The `ConsensusState` operates on a single in-memory instance. There is no log shipping, no state snapshot transfer, no catchup protocol for replicas that fall behind.
4. **HLC drift tolerance (60s) may be too loose.** At 1M decisions/day (~11.6/second), a 60-second drift window allows ~700 causally-misordered decisions.

**Optimized Requirement:**
> The system MUST implement a totally-ordered, deterministic state machine with the following properties: (a) Every committed decision receives a unique, monotonically increasing sequence number. (b) Given the same initial state and the same ordered sequence of committed decisions, any replica MUST arrive at the identical state hash (byte-level determinism). (c) The state transition function MUST be explicitly defined as `fn apply(state: &mut State, decision: &Decision) -> Result<StateHash>`. (d) HLC drift tolerance MUST be configurable per-deployment and default to <= 5 seconds. (e) A TLA+ specification MUST exist for each property and MUST be model-checked against at least 4 nodes and 2 faults.

**Test Specification:**
- `test_total_order_determinism`: Commit 100 decisions across 3 concurrent DAG branches; finalize via consensus; verify all replicas produce identical ordered sequences and identical final state hashes.
- `test_state_machine_replay`: Record a sequence of 1000 committed decisions; replay on a fresh state machine; verify byte-identical final state hash.
- `test_hlc_drift_rejection_tight`: Set drift tolerance to 5s; inject a timestamp 6s ahead; verify rejection.
- `test_replica_catchup`: Start replica B after replica A has committed 500 decisions; verify B reaches identical state after catchup.
- `test_tla_model_check_total_order`: Run TLC model checker on the total-order spec with N=4, F=1; verify no safety violations in state space.

---

### ARCH-004 -- Raft-Based Consensus with CRDT Inter-Tenant Coordination

**Architecture Assessment:** Architecturally Unsound -- contradicts existing BFT design

**Exochain Coverage:**
- `exo-dag/src/consensus.rs` -- BFT consensus (Byzantine fault tolerant, >2/3 quorum)
- No Raft implementation exists.
- No CRDT implementation exists.

**Gaps:**
1. **CRITICAL: Raft vs. BFT conflict.** The existing consensus is BFT (tolerates Byzantine faults, requires >2/3 honest). Raft tolerates only crash faults and requires a single leader. Adding Raft alongside BFT creates two competing consensus protocols with incompatible failure models. The PRD does not specify which protocol governs which domain.
2. **No CRDTs anywhere.** The codebase uses BTreeMap (strongly consistent) everywhere. CRDTs (Conflict-free Replicated Data Types) are eventual-consistency primitives. Mixing CRDTs with BFT total-order delivery creates a semantic inconsistency: BFT guarantees strong consistency, CRDTs guarantee eventual consistency. Using both for inter-tenant coordination means the same data may have two conflicting consistency guarantees.
3. **Raft leader election creates a single point of failure** incompatible with the 5-nines availability target in ARCH-008.

**Optimized Requirement:**
> Intra-tenant consensus MUST use the existing BFT protocol (>2/3 quorum, Byzantine-tolerant). Cross-tenant coordination MUST NOT introduce a weaker consistency model. Cross-tenant state sharing (e.g., delegation chains, cross-references) MUST be implemented via cryptographic references (hash pointers between tenant DAGs) verified by the recipient tenant's BFT consensus, not by CRDTs or Raft. If a coordination protocol is needed for cluster membership (node join/leave), it MUST be implemented as a separate control plane that does not participate in decision ordering.

**FLAG: ARCHITECTURALLY UNSOUND.** This requirement as written introduces two mutually contradictory consensus protocols. It must be rewritten to specify which consistency guarantee governs which domain, or the Raft/CRDT components must be removed entirely.

**Test Specification:**
- `test_cross_tenant_hash_reference`: Tenant A commits a decision; Tenant B references it by hash; verify B's BFT consensus validates the hash against A's checkpoint root.
- `test_no_consistency_downgrade`: Attempt to read cross-tenant data through an eventually-consistent path; verify the system rejects it or promotes it through BFT validation.
- `test_single_consensus_protocol`: Verify at compile time that only one consensus protocol is instantiated per tenant.

---

### ARCH-005 -- Multi-Dimensional Scalability via Tenant Sharding

**Architecture Assessment:** Sound foundation, Underspecified at scale boundaries

**Exochain Coverage:**
- `exo-tenant/src/sharding.rs` -- ShardStrategy (HashBased, RangeBased, Geographic, Single), deterministic assignment
- `exo-tenant/src/store.rs` -- TenantStore with isolation enforcement (cross-tenant access rejected)
- `exo-tenant/src/tenant.rs` -- Tenant management

**Gaps:**
1. **No shard rebalancing.** The `ShardStrategy::HashBased` uses a fixed `total_shards` count. Adding shards requires rehashing all tenants, which is a distributed coordination problem not addressed in the code.
2. **No shard-level consensus.** Each shard needs its own BFT consensus group, but the current consensus is singleton. No mapping exists from shard_id to consensus group.
3. **Geographic sharding is a stub.** `ShardStrategy::Geographic` always returns shard 0.
4. **No cross-shard transaction protocol.** If a decision references entities in different shards, there is no two-phase commit or saga pattern.
5. **Scale target mismatch.** At 10,000 tenants with HashBased sharding, shard sizes depend on `total_shards`. The PRD does not specify maximum tenants per shard or maximum decisions per shard per second.

**Optimized Requirement:**
> Tenant sharding MUST support: (a) consistent-hash-ring assignment with virtual nodes for load balancing, (b) online shard splitting without downtime (split a shard by reassigning tenants within the ring), (c) per-shard BFT consensus groups with independent validator sets, (d) maximum 1,000 tenants per shard, (e) cross-shard references via hash pointers only (no distributed transactions). The geographic sharding strategy MUST enforce data residency by rejecting operations that would move data outside the designated region.

**Test Specification:**
- `test_consistent_hash_stability`: Assign 10,000 tenants to 16 shards; add a 17th shard; verify < 1/16 of tenants are reassigned.
- `test_shard_isolation`: Attempt to read Tenant A's data via Tenant B's shard; verify rejection.
- `test_geographic_residency`: Assign tenant to region "eu-west-1"; attempt to read from "us-east-1" endpoint; verify rejection.
- `test_max_tenants_per_shard`: Attempt to assign 1,001st tenant to a shard; verify the system triggers a split or rejects the assignment.
- `test_cross_shard_reference`: Tenant A on shard 1 references Tenant B's decision on shard 2 via its hash; verify the reference is validated against shard 2's checkpoint root without requiring cross-shard consensus.

---

### ARCH-006 -- Cold Storage for Infinite Historical Depth

**Architecture Assessment:** Sound, Needs Refinement on proof continuity

**Exochain Coverage:**
- `exo-tenant/src/cold_storage.rs` -- StorageManager with Hot/Warm/Cold/Archive tiers, one-way migration enforcement, BTreeMap tracking
- `exo-dag/src/checkpoint.rs` -- CheckpointPayload with event_root, state_root, frontier hashes

**Gaps:**
1. **No proof continuity across tiers.** When data migrates from Hot to Archive, the proofs (SMT inclusion, MMR position) must remain verifiable. The current implementation only tracks which tier a record is in, not how to verify a proof against archived data.
2. **No retrieval latency SLA per tier.** The tiers are defined but no target retrieval times are specified. Archive tier on Glacier has multi-hour retrieval; the PRD does not address how this affects proof verification.
3. **No compaction or summarization.** 50 years of 1M decisions/day = ~18B records. Even with cold storage, the MMR grows without bound. No summarization protocol exists to compress historical proofs into periodic checkpoints that can serve as trusted roots.
4. **Migration is append-only (correct) but irreversible.** The code rejects promotions (Cold to Hot), which is correct for integrity. However, the PRD NFR implies data must be accessible for audit/litigation. No "warm-up" retrieval path exists.

**Optimized Requirement:**
> Historical data MUST migrate through tiers (Hot -> Warm -> Cold -> Archive) based on configurable age policies. Migration MUST be irreversible at the proof layer (no backdating). Each tier transition MUST produce a TierTransitionCertificate signed by the checkpoint validator set, binding the data hash to both the source tier's final state root and the destination tier's initial state root. Archival data MUST remain proof-verifiable via checkpoint chain: any historical decision MUST be verifiable by presenting (a) its MMR inclusion proof, (b) the checkpoint containing the MMR root, and (c) the chain of checkpoint signatures to the current epoch. A retrieval SLA MUST be defined: Hot < 50ms, Warm < 500ms, Cold < 5s, Archive < 4 hours (with async callback).

**Test Specification:**
- `test_tier_transition_certificate`: Migrate 100 records from Hot to Warm; verify each produces a signed TierTransitionCertificate; verify the certificate binds source and destination state roots.
- `test_archive_proof_verification`: Archive a decision; verify its MMR proof is still valid against the checkpoint that was current at migration time.
- `test_promotion_rejected`: Attempt to move data from Cold to Hot; verify rejection with specific error.
- `test_checkpoint_chain_verification`: Create 10 checkpoints spanning 2 tier transitions; verify a cold-storage decision is verifiable through the checkpoint chain.

---

### ARCH-007 -- Zero-Trust Multi-Tenant Architecture

**Architecture Assessment:** Sound, Underspecified on blast radius

**Exochain Coverage:**
- `exo-tenant/src/store.rs` -- TenantStore with explicit tenant_id isolation, cross-tenant access returns None
- `exo-gateway/src/middleware.rs` -- Consent middleware (default-deny), Governance middleware (Allow/Deny/Escalate), Audit middleware
- `exo-gateway/src/auth.rs` -- DID-based authentication
- `exo-core/src/crypto.rs` -- Ed25519 with zeroize-on-drop for key material
- `exo-identity/src/did.rs`, `exo-identity/src/did_verification.rs`, `exo-identity/src/key_management.rs` -- DID resolution, DID signature verification, key management

**Gaps:**
1. **No tenant key isolation.** All tenants share the same Ed25519 key type. There is no per-tenant key derivation, no tenant-scoped key rotation, and no mechanism to revoke a single tenant's keys without affecting others.
2. **No blast radius containment.** If one tenant's consensus group is compromised, there is no mechanism to prevent the attacker from forging cross-tenant references (since cross-tenant references are currently not validated against independent roots).
3. **Audit middleware uses Timestamp::ZERO.** The audit_middleware function hardcodes `Timestamp::ZERO` instead of using the HLC, making audit logs temporally meaningless.
4. **No rate limiting at tenant level.** The RateLimiter in `exo-api/src/p2p.rs` is per-peer, not per-tenant. A single tenant could exhaust system resources.

**Optimized Requirement:**
> Every tenant MUST operate within a cryptographically isolated security domain: (a) per-tenant key derivation path using a master seed + tenant-id derivation, (b) per-tenant rate limits on all API operations, (c) per-tenant audit logs with HLC timestamps (not hardcoded zeros), (d) blast-radius containment guaranteeing that compromise of tenant A's validator set cannot forge valid proofs for tenant B. Cross-tenant references MUST be validated against the referenced tenant's independently-verified checkpoint root. All middleware MUST use the node's HLC for timestamps.

**Test Specification:**
- `test_per_tenant_key_isolation`: Derive keys for tenants A and B from the same master; verify A's signing key cannot produce valid signatures under B's verification key.
- `test_audit_timestamp_nonzero`: Record an audit entry; verify the timestamp is a valid HLC value (not ZERO).
- `test_tenant_rate_limit`: Send 101 requests from tenant A; verify the 101st is rejected; verify tenant B's requests are unaffected.
- `test_blast_radius`: Compromise tenant A's validator set (forge a commit certificate); attempt to use A's certificate to validate a cross-reference in tenant B; verify rejection.
- `test_default_deny_everything`: Issue a request with no consent, no governance approval; verify it is rejected at the first middleware layer.

---

### ARCH-008 -- 5-Nines Availability with Multi-Region Active-Active

**Architecture Assessment:** Underspecified -- no implementation exists

**Exochain Coverage:**
- No multi-region implementation exists.
- No active-active replication exists.
- `exo-dag/src/consensus.rs` -- Single-instance BFT consensus (no region awareness)
- `exo-api/src/p2p.rs` -- P2P mesh with peer registry (no region topology)

**Gaps:**
1. **CRITICAL: No replication protocol.** The entire codebase operates on single-instance in-memory stores. There is no write-ahead log, no replication stream, no snapshot transfer, and no reconciliation protocol.
2. **Active-active with BFT is a hard problem.** BFT requires >2/3 honest validators. Spreading validators across regions introduces WAN latency into every consensus round, pushing commit latency well beyond the 200ms target.
3. **No failover mechanism.** 5-nines (5.26 minutes/year downtime) requires automated failover. No health checking, leader election for failover, or split-brain resolution exists.
4. **No conflict resolution for active-active.** Active-active implies concurrent writes to multiple regions. With BFT consensus, this requires either a global consensus group (high latency) or local consensus with async reconciliation (consistency violation).

**Optimized Requirement:**
> The system MUST achieve 99.999% availability for read operations via multi-region read replicas with < 500ms staleness. Write availability MUST be 99.99% (52.6 minutes/year planned maintenance permitted). The BFT consensus group MUST be co-located within a single region (< 10ms RTT) to meet the P99 200ms verification target. Cross-region replication MUST be asynchronous with cryptographic consistency verification via checkpoint comparison. Each region MUST independently verify incoming replicated checkpoints against the origin region's validator signatures. Split-brain detection MUST halt writes (fail-safe) rather than allow divergence.

**FLAG: Underspecified.** The 5-nines target is not achievable with the current single-instance architecture. The PRD must specify which operations require which availability level (reads vs. writes) and acknowledge the CAP theorem tradeoff.

**Test Specification:**
- `test_read_replica_staleness`: Commit a decision in the primary region; verify it appears in the read replica within 500ms.
- `test_checkpoint_cross_region_verification`: Replicate a checkpoint from region A to region B; verify B independently validates A's validator signatures.
- `test_split_brain_halt`: Simulate network partition between two regions; verify both regions halt writes rather than diverge.
- `test_write_availability_degraded`: Simulate one region failure; verify the surviving region continues processing writes.
- `test_failover_time`: Simulate primary failure; measure time to resume writes; verify < 30 seconds.

---

### ARCH-009 -- Post-Quantum Cryptography Migration Path

**Architecture Assessment:** Sound foundation, Needs Refinement on transition mechanics

**Exochain Coverage:**
- `exo-core/src/crypto.rs` -- Ed25519 via ed25519-dalek, zeroize on drop
- `exo-proofs/src/stark.rs` -- Hash-based proofs (blake3 only, no elliptic curves), explicitly post-quantum
- `exo-identity/src/key_management.rs` -- Key management structures
- `exo-dag/src/dag.rs` -- Signature as opaque 64-byte array (algorithm-agnostic at the storage layer)

**Gaps:**
1. **No algorithm agility.** The `Signature` type is a fixed `[u8; 64]`. Post-quantum signatures (e.g., Dilithium) are 2,420+ bytes. The type cannot accommodate them without a breaking change.
2. **No dual-signing (hybrid) support.** The migration path requires a period where both Ed25519 and PQ signatures coexist. No node or verification path supports dual signatures.
3. **No key version tracking in DAG nodes.** The `DagNode` contains a `Signature` but no `key_algorithm` or `key_version` field. Historical verification becomes impossible after migration unless the algorithm is embedded.
4. **Checkpoint already has key_version.** The `ValidatorSignature` in `checkpoint.rs` includes `key_version: u64`, showing the pattern exists but is not propagated to DAG nodes.

**Optimized Requirement:**
> All cryptographic signatures MUST include an algorithm identifier and key version. The Signature type MUST be variable-length to accommodate post-quantum algorithms (minimum 4,096 bytes). During migration, every signing operation MUST produce a dual signature (Ed25519 + PQ algorithm). Verification MUST accept either signature individually during the transition period, and MUST require both during the overlap window. The transition timeline MUST be: Phase 1 (dual-sign, verify either), Phase 2 (dual-sign, verify both), Phase 3 (PQ-only sign, verify PQ). Each phase transition MUST be recorded as a governance decision in the DAG. The STARK proof system MUST remain the archival proof layer (already hash-based, already PQ-safe).

**Test Specification:**
- `test_signature_algorithm_agility`: Create a signature with algorithm_id=Ed25519; create another with algorithm_id=Dilithium; verify both are storable and verifiable.
- `test_dual_signature_dag_node`: Sign a DAG node with both Ed25519 and Dilithium; verify both signatures independently; verify the node stores both.
- `test_migration_phase_enforcement`: Set system to Phase 2; submit a node with only Ed25519 signature; verify rejection.
- `test_historical_verification_post_migration`: Create 100 Ed25519-signed nodes; migrate to PQ; verify all historical nodes remain verifiable via their embedded algorithm_id.
- `test_pq_signature_size`: Verify the Signature type accommodates a 2,420-byte Dilithium signature.

---

### ARCH-010 -- Protocol Versioning with Backwards-Compatible Proofs

**Architecture Assessment:** Underspecified -- no versioning exists

**Exochain Coverage:**
- `exo-dag/src/checkpoint.rs` -- Uses domain separator `EXOCHAIN-CHECKPOINT-v1` (version in constant)
- `exo-proofs/src/verifier.rs` -- ProofType enum (Snark, Stark, Zkml) but no version field
- `exo-core/src/types.rs` -- No version field on core types

**Gaps:**
1. **No protocol version in wire format.** Messages, DAG nodes, proofs, and checkpoints do not carry a protocol version number. A node running protocol v2 cannot distinguish v1 messages from v2 messages.
2. **No proof migration.** If the SMT hash function changes from blake3 to a PQ-safe hash, all existing proofs become unverifiable. No proof upgrade or re-anchoring mechanism exists.
3. **The domain separator is a start** but is hardcoded as a constant, not a runtime-negotiated value.
4. **No feature negotiation.** The P2P layer has no capability advertisement. Nodes cannot discover which protocol versions peers support.

**Optimized Requirement:**
> Every serialized structure (DagNode, Proof, Checkpoint, Message) MUST include a 4-byte protocol version prefix. The system MUST support concurrent operation of at most 2 protocol versions (current + previous). Proof verification MUST be version-dispatched: given a proof with version V, the system MUST use the verifier for version V. A proof upgrade mechanism MUST exist that, given a valid proof under version V and the current state, produces an equivalent proof under version V+1 (re-anchoring). The P2P layer MUST negotiate protocol versions during handshake and reject connections from nodes more than 1 version behind.

**Test Specification:**
- `test_version_prefix_present`: Serialize a DagNode; verify the first 4 bytes are the protocol version.
- `test_version_dispatch`: Create a v1 SNARK proof and a v2 STARK proof; verify each is dispatched to the correct verifier.
- `test_proof_reanchoring`: Create a v1 SMT proof; upgrade to v2 (new hash function); verify the re-anchored proof is valid under v2.
- `test_peer_version_rejection`: Connect a v1 peer to a v3 node; verify connection is rejected.
- `test_backwards_compatibility`: Create a v1 proof; verify it remains valid on a v2 node.

---

### ARCH-011 -- TLA+ Formal Verification Mandate for All Core Invariants

**Architecture Assessment:** Sound, Needs Refinement on coverage scope

**Exochain Coverage:**
- `tla/QuorumSafety.tla` -- Quorum safety properties
- `tla/ConstitutionalBinding.tla` -- Constitutional binding invariants
- `tla/DecisionLifecycle.tla` -- Decision state machine
- `tla/AuditLogContinuity.tla` -- Audit log append-only property
- `tla/AuthorityChain.tla` -- Authority delegation chain
- `exo-core/src/invariants.rs` -- Runtime invariant checking (Invariant trait, InvariantSet)

**Gaps:**
1. **No CI integration.** The TLA+ specs exist as files but there is no evidence they are model-checked in CI. Without automated verification, specs drift from implementation.
2. **Missing specs for critical properties:** No TLA+ spec for: (a) total order delivery, (b) cross-tenant isolation, (c) cold storage migration safety, (d) PQ migration phase transitions, (e) shard rebalancing.
3. **No correspondence between TLA+ specs and Rust invariants.** The `invariants.rs` Invariant trait is runtime; the TLA+ specs are design-time. There is no systematic mapping from TLA+ invariant names to Rust Invariant implementations.
4. **No liveness properties.** TLA+ can verify liveness (something good eventually happens). All existing specs likely check only safety (nothing bad happens). Decision finalization liveness (every proposed decision eventually gets committed or rejected) is critical but unverified.

**Optimized Requirement:**
> Every core algorithm MUST have a corresponding TLA+ specification. The specification MUST be model-checked in CI against a configuration of at least N=5, F=1. The following properties MUST be specified and verified: (a) Consensus safety (no two conflicting decisions are finalized), (b) Consensus liveness (every valid proposal is eventually decided), (c) Total order agreement (all honest nodes see the same sequence), (d) Tenant isolation (no tenant can read or forge another tenant's state), (e) Audit continuity (the audit log is append-only and gap-free), (f) Authority chain validity (every delegation is traceable to a constitutional root). Each TLA+ invariant MUST have a named corresponding Rust Invariant implementation. A test MUST verify the mapping is complete (no TLA+ invariant lacks a Rust counterpart).

**Test Specification:**
- `test_tla_ci_integration`: Run `tlc` model checker on all 5 existing specs; verify zero violations; verify this runs in < 5 minutes in CI.
- `test_tla_rust_invariant_mapping`: Parse TLA+ spec names; parse Rust Invariant names; verify 1:1 correspondence.
- `test_liveness_decision_finalization`: Model-check that in a system with N=5, F=1, every valid proposal reaches a committed or rejected state within bounded rounds.
- `test_safety_no_conflicting_finalization`: Model-check that no execution produces two different committed decisions for the same sequence number.

---

## NFR Assessment

### 10,000 tenants, 1M decisions/day, 50-year history

**Assessment:** The current architecture cannot achieve this without fundamental changes.

- **SMT at 18B keys** requires a persistent trie (RocksDB-backed or similar). The in-memory BTreeMap will exhaust RAM.
- **MMR at 18B leaves** produces proofs with ~34 siblings (log2 of 18B). This is feasible but requires disk-backed storage.
- **Consensus at 11.6 decisions/second** is achievable with BFT, but only with co-located validators (< 10ms RTT). WAN BFT will not meet the 200ms P99.
- **Cold storage** must be implemented before year 2 to avoid unbounded Hot tier growth.

### P99 chain verification < 200ms

**Assessment:** Achievable for individual proofs. Not achievable for cross-region BFT.

- SMT proof verification: O(256 hash operations) ~ 3ms
- MMR proof verification: O(34 hash operations) ~ 0.5ms
- SNARK verification: depends on implementation; Groth16 ~ 5ms
- Total single-proof chain: ~10ms (well within budget)
- BFT consensus round-trip with WAN: 100-300ms (exceeds budget)

### 99.999% availability

**Assessment:** Not achievable without multi-region replication, which does not exist. See ARCH-008.

### Ed25519 to hybrid post-quantum migration

**Assessment:** The Signature type must become variable-length before this is possible. See ARCH-009.

### Hot/S3/Glacier storage tiers

**Assessment:** The StorageManager data model is correct. No S3 or Glacier adapters exist. The one-way migration constraint is correctly enforced. Proof continuity across tiers is the critical missing piece.

---

## ARCHITECTURE PANEL VERDICT

**Overall Assessment: CONDITIONALLY APPROVED WITH 4 BLOCKERS**

The exochain codebase demonstrates strong foundational architecture. The DAG, SMT, MMR, consensus, HLC, and proof systems are well-implemented with deterministic guarantees, comprehensive test coverage (including property-based tests), and correct use of BTreeMap for deterministic iteration. The code quality is high.

However, the PRD v1.1.0 contains four architectural issues that must be resolved before approval:

### BLOCKER 1: Raft/CRDT Contradiction (ARCH-004)
The requirement to add Raft and CRDTs contradicts the existing BFT consensus and introduces two incompatible consistency models. **Resolution: Remove Raft and CRDTs. Use hash-pointer cross-references validated by BFT.**

### BLOCKER 2: No Total Order (ARCH-003)
The DAG provides partial order. The consensus provides per-round finalization. No total order exists. Without total order, state machine replication is impossible and determinism cannot be guaranteed across replicas. **Resolution: Add a sequence number assignment protocol as part of BFT commit.**

### BLOCKER 3: No Replication Protocol (ARCH-008)
5-nines availability requires replication. No replication exists. The 99.999% target is unachievable without it. **Resolution: Implement checkpoint-based async replication with split-brain detection. Downgrade write availability target to 99.99%.**

### BLOCKER 4: Fixed-Size Signature (ARCH-009)
The 64-byte Signature type cannot accommodate post-quantum signatures. This is a breaking change that must be addressed before any production deployment. **Resolution: Make Signature variable-length with an algorithm identifier.**

### Non-Blocking Findings (Must Address Before v1.2.0)

| ID | Finding | Severity |
|----|---------|----------|
| NB-1 | Pedagogical SNARK/STARK not production-safe | High |
| NB-2 | SMT O(n*256) root computation | High |
| NB-3 | No protocol versioning in wire format | High |
| NB-4 | Audit middleware uses Timestamp::ZERO | Medium |
| NB-5 | Geographic sharding is a stub | Medium |
| NB-6 | No TLA+ CI integration | Medium |
| NB-7 | No typed domain-object binding in DAG | Medium |
| NB-8 | No composite ChainProof type | Medium |
| NB-9 | No per-tenant rate limiting | Low |
| NB-10 | No proof size budget enforcement | Low |

### Approved As-Is

- ARCH-006 (Cold Storage) -- sound with noted refinements
- ARCH-011 (TLA+ Mandate) -- sound, needs CI and coverage expansion

---

*Panel-3 Architecture Review Complete. Blockers must be resolved before ratification.*

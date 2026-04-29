# Architecture Overview

> **Audience:** Engineers who want the system-level picture without the
> full detail of [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md).
> **Relationship to that document:** ARCHITECTURE.md is the long-form
> reference. This guide is the developer-facing complement: fewer words,
> more concrete data flows and surface-area maps.

If you want the constitutional foundation, read
[`constitutional-model.md`](./constitutional-model.md) first. If you
want to stand something up, read
[`developer-onboarding.md`](./developer-onboarding.md).

---

## 1. The five layers

From the top-level `README.md`, EXOCHAIN is organised in five layers.

```
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 5  ExoForge                    Governance triage/planning tools │
│          (exoforge/)                 Triage → Heuristic Review → Plan │
│                                      → Constitutional Validation      │
├──────────────────────────────────────────────────────────────────────┤
│ Layer 4  Decision Forum              Governance deliberation UI       │
│          (web/)                      React / Vite                     │
├──────────────────────────────────────────────────────────────────────┤
│ Layer 3  CommandBase.ai              Operational hypervisor for       │
│          (command-base/)             cognitiveplane.ai                │
│                                      Express + SQLite + WebSocket     │
├──────────────────────────────────────────────────────────────────────┤
│ Layer 2  WASM Bridge                 141 verified bridge exports      │
│          (packages/exochain-wasm,    Rust → WebAssembly → JS          │
│           crates/exochain-wasm)      Export sync checked in CI        │
├──────────────────────────────────────────────────────────────────────┤
│ Layer 1  CGR Kernel                  Rust, 20 workspace packages      │
│          (crates/)                   Constitutional governance runtime │
│                                      Deterministic, no floats, tests  │
└──────────────────────────────────────────────────────────────────────┘
```

The layers are directional: higher layers depend on lower ones, never
the reverse. Layer 1 (the kernel and its workspace crates) is the load-bearing
substance. The rest are presentation and orchestration surfaces over
the same primitives.

---

## 2. Data flow through a typical governance action

The scenario: an operator creates a decision through the HTTP API, the
network reaches quorum, and the decision is committed. Below is the
end-to-end path through the system.

### 2.1 ASCII sequence

```
Operator                API Gateway              Node (reactor, kernel)           DAG / BFT                 Voters / Peers
  │                         │                             │                           │                           │
  │  POST /api/decisions    │                             │                           │                           │
  ├────────────────────────►│                             │                           │                           │
  │                         │  authenticate (Ed25519),    │                           │                           │
  │                         │  check authority chain      │                           │                           │
  │                         ├────────────────────────────►│                           │                           │
  │                         │                             │  kernel.adjudicate(       │                           │
  │                         │                             │    action=CreateDecision, │                           │
  │                         │                             │    ctx=...)               │                           │
  │                         │                             │──► Verdict::Permitted     │                           │
  │                         │                             │                           │                           │
  │                         │                             │  post DagNode (reactor)   │                           │
  │                         │                             ├──────────────────────────►│                           │
  │                         │                             │                           │  gossipsub broadcast      │
  │                         │                             │                           ├──────────────────────────►│
  │  202 Accepted + id      │                             │                           │                           │
  │◄────────────────────────┤                             │                           │                           │
  │                         │                             │                           │  BFT prepare / commit     │
  │                         │                             │                           │◄──────────────────────────┤
  │                         │                             │                           │  checkpoint finalised     │
  │                         │                             │                           │                           │
  │  POST /api/votes (×N)   │                             │                           │                           │
  ├────────────────────────►│  authenticate, attach       │                           │                           │
  │                         │  provenance (VoiceKind,     │                           │                           │
  │                         │  SignerType prefix)         │                           │                           │
  │                         ├────────────────────────────►│  per-vote kernel adjud.   │                           │
  │                         │                             │  (provenance verify)      │                           │
  │                         │                             ├──────────────────────────►│                           │
  │                         │                             │                           │  ...                      │
  │                         │                             │  check_quorum             │                           │
  │                         │                             │  (CR-001 §8.3: drop       │                           │
  │                         │                             │   synthetic-voiced votes) │                           │
  │                         │                             │                           │                           │
  │                         │                             │  if authentic ≥ threshold │                           │
  │                         │                             │     → Outcome event       │                           │
  │                         │                             ├──────────────────────────►│                           │
  │                         │                             │                           │  BFT checkpoint           │
  │                         │                             │                           │                           │
  │  GET /api/decisions/:id │                             │                           │                           │
  ├────────────────────────►│                             │                           │                           │
  │                         │  verifiable query           │                           │                           │
  │                         │  (inclusion proof vs        │                           │                           │
  │                         │   event_root + state_root)  │                           │                           │
  │                         ├────────────────────────────►│                           │                           │
  │◄────────────────────────┤  200 OK + evidence bundle   │                           │                           │
```

### 2.2 Step-by-step

1. **User creates a decision.** Operator POSTs a decision request to
   `/api/decisions` at the gateway. The request carries the operator's
   DID and an Ed25519 signature over the canonical payload.

2. **Gateway authenticates and checks the authority chain.** The
   gateway verifies the signature using the operator's published
   public key, then evaluates the operator's authority chain against
   the DAG state. If the chain is empty, broken, or unsigned, the
   call is rejected at the gateway. See `exo-authority::chain` and
   `exo-gateway`.

3. **Decision posted to the DAG via the reactor.** The node reactor
   (`crates/exo-node/src/reactor.rs`) builds a `DagNode` representing
   the decision, signs the `EventEnvelope` with the node's identity
   key, and submits it to the DAG store. The reactor first calls
   `Kernel::adjudicate` on the decision action; only a
   `Verdict::Permitted` proceeds.

4. **BFT consensus → checkpoint.** The DAG node is gossiped to peers.
   Validators run the HotStuff-derivative consensus protocol in
   `exo-consensus` until a supermajority attests the checkpoint. The
   checkpoint contains both an `event_root` (Merkle Mountain Range
   over finalised `event_id`s) and a `state_root` (Sparse Merkle Tree
   over derived state).

5. **Voters cast votes.** Each vote is an independent signed event.
   The event carries `Provenance` that includes `VoiceKind::Human`
   or `VoiceKind::Synthetic`, the voter's `SignerType` prefix, and
   the Ed25519 signature of the canonical payload.

6. **Quorum check applied with synthetic-voice exclusion.** The
   kernel's `QuorumLegitimate` invariant (CR-001 §8.3) counts only
   authentic — non-synthetic — approvals when evaluating whether the
   threshold is met. See
   [`constitutional-model.md §3.7`](./constitutional-model.md). Votes
   with no provenance are legacy-compatible and count at face value.

7. **Outcome event committed.** Once the authentic approval count
   meets the threshold, a `DecisionOutcome` event is produced, posted
   to the DAG, and finalised at the next checkpoint. From this point
   the decision is permanent — terminal states are immutable under
   TNC-08.

8. **Evidence bundle is exportable.** A verifiable query to
   `/api/decisions/:id` returns the decision, its votes, all
   provenance, and cryptographic proofs tying the event to the
   current `event_root` and `state_root`. This bundle is the
   court-admissible audit artefact.

---

## 3. The CGR Kernel — deep dive

The kernel lives entirely in `crates/exo-gatekeeper`.

### 3.1 Invariant engine loop

The kernel is composed of:

- A `constitution_hash: [u8; 32]` — the BLAKE3 of the constitution
  bytes at construction, stored for integrity verification.
- An `InvariantEngine` holding an `InvariantSet`.
- The `adjudicate` method, which is the only public entry point.

The loop inside `enforce_all` at
[`crates/exo-gatekeeper/src/invariants.rs:124`](../../crates/exo-gatekeeper/src/invariants.rs)
is deliberately straightforward:

```rust
pub fn enforce_all(
    engine: &InvariantEngine,
    context: &InvariantContext,
) -> Result<(), Vec<InvariantViolation>> {
    let mut violations = Vec::new();
    for invariant in &engine.invariant_set.invariants {
        if let Err(v) = check_invariant(*invariant, context) {
            violations.push(v);
        }
    }
    if violations.is_empty() { Ok(()) } else { Err(violations) }
}
```

All violations are collected, not short-circuited. This matters: a
caller that violates three invariants gets three violations. The
kernel never hides information it has already computed.

### 3.2 Ed25519 signature verification for authority chains

The TNC-01 payload format, implemented at
[`crates/exo-gatekeeper/src/invariants.rs:316–325`](../../crates/exo-gatekeeper/src/invariants.rs):

```
payload = grantor_did_bytes
        ‖ 0x00
        ‖ grantee_did_bytes
        ‖ 0x00
        ‖ (for each permission: permission_bytes ‖ 0x00)

message   = BLAKE3(payload)
signature = Ed25519_sign(grantor_secret_key, message)
```

The check has three failure modes — malformed key (not 32 bytes),
malformed signature (not 64 bytes), or signature-verification
failure — each producing a distinct `InvariantViolation` description.
Links without a `grantor_public_key` fall back to a non-emptiness
check on the signature to preserve backwards compatibility with
legacy events.

### 3.3 Why BLAKE3

- **Speed.** BLAKE3 at SIMD speed is several GB/s on modern CPUs,
  removing hashing from the hot path on both event ingestion and
  proof construction.
- **Collision resistance.** 256-bit output, best-known theoretical
  attacks match the SHA-3 family's bounds. Sufficient for all
  EXOCHAIN uses.
- **Tree-hashing mode.** BLAKE3's tree structure enables parallel
  hashing of large inputs, which matters for checkpoint MMR and SMT
  construction.
- **Determinism.** Same input always produces the same output across
  architectures — essential for the cross-implementation hash
  compatibility gate (`tools/cross-impl-test/`).

### 3.4 Determinism enforcement mechanisms

Determinism is enforced at four layers:

1. **Compiler.** `#[deny(clippy::float_arithmetic, clippy::float_cmp,
   clippy::float_cmp_const)]` at the workspace level. Float usage is a
   compile-time error.
2. **Type system.** `BTreeMap` / `BTreeSet` / `DeterministicMap` are
   the only map/set types in production code. `HashMap` is rejected
   in review.
3. **Serialization.** All hashed data goes through `ciborium` CBOR
   with sorted keys. JSON is never hashed directly.
4. **Time.** `exo_core::hlc` Hybrid Logical Clock replaces
   `SystemTime::now()` / `Instant::now()` everywhere in governance
   logic. Randomness is scoped to key generation only.

### 3.5 Combinator algebra

Every governance operation can be expressed as a combinator
expression. The reducer is pure: `reduce(combinator, input) →
Result<output, error>`.

Available terms, from
[`crates/exo-gatekeeper/src/combinator.rs`](../../crates/exo-gatekeeper/src/combinator.rs):

| Term         | Behaviour                                                 |
|--------------|-----------------------------------------------------------|
| `Identity`   | Pass input through unchanged                              |
| `Sequence`   | Execute terms in order, threading output to input         |
| `Parallel`   | Execute terms independently, merge outputs                |
| `Choice`     | Try in order, first success wins                          |
| `Guard`      | Predicate gate — fail the reduction if predicate fails    |
| `Transform`  | Apply a named transform to output                         |
| `Retry`      | Retry on failure up to N times                            |
| `Timeout`    | Abort if reduction exceeds a budget                       |
| `Checkpoint` | Commit partial reduction to the DAG                       |

The kernel reduces the combinator and checks all applicable
invariants before and after reduction. Any failure rejects the entire
operation with a detailed violation report.

---

## 4. Persistence architecture (GAP-001)

EXOCHAIN persists state in two layers — the ledger (append-only DAG
of events) and derived state (current projections). The crate
responsible is `exo-dag`.

### 4.1 Store backends

| Store              | Use case                                           | Crate location                                 |
|--------------------|----------------------------------------------------|------------------------------------------------|
| `PostgresStore`    | Production. Durable, queryable, multi-node         | `exo-dag::store` (postgres feature)            |
| `SqliteDagStore`   | Single-node development and ExoForge operation    | `exo-dag::store` (sqlite feature, default)     |
| In-memory          | Tests only                                         | `exo-dag::store` (test helpers)                |

### 4.2 Event sourcing pattern

EXOCHAIN is an event-sourced system in the strict sense: **application
state is always a derivative of the event log, and the database is a
projection that can be destroyed and rebuilt from the DAG at any
time**. Consequences:

- Audit reconstruction: the DAG is self-describing.
- State debugging: any past state can be replayed exactly.
- Disaster recovery: a corrupted projection rebuilds from genesis.
- Reproducibility: replication across nodes is determinism by
  construction, not synchronization.

### 4.3 Event → canonical CBOR → BLAKE3 event ID

An event has two parts:

- `EventEnvelope` — the hashable portion (everything except
  `event_id` and `signature`).
- Metadata — `event_id` and `signature`, added after the envelope is
  hashed.

The ID is computed as:

```
event_id = BLAKE3(canonical_cbor(EventEnvelope))
```

The canonical CBOR encoding uses `ciborium` with keys sorted
lexicographically. This is deterministic across Rust, JavaScript, and
Python implementations — the cross-impl gate
(`tools/cross-impl-test/compare.sh`) verifies this.

### 4.4 Checkpoint roots

A checkpoint carries two separate roots:

- `event_root` — a Merkle Mountain Range (MMR) over finalised
  `event_id`s in canonical topological order. Supports
  `EventInclusionProof`.
- `state_root` — a Sparse Merkle Tree (SMT) over derived state —
  active keys, active consents, revocations, credential status. Supports
  `StateProof`.

Both roots are included in the BFT-signed checkpoint. An evidence
bundle can be verified against a checkpoint without replaying the
full history — download the checkpoint, walk the MMR path, verify
the BLAKE3 chain, done.

See `exo-dag::mmr`, `exo-dag::smt`, and `exo-dag::store` for the
implementations.

---

## 5. P2P and consensus

### 5.1 libp2p stack

EXOCHAIN uses libp2p for networking. The protocol set:

| Protocol   | Use                                                        |
|------------|------------------------------------------------------------|
| `gossipsub`| Event gossip, validator vote broadcast                     |
| `kad`      | DHT-based peer discovery and MCP mesh discovery            |
| `mdns`     | Local-network peer discovery (dev environments)            |
| `tcp`/`quic` | Transport                                                |

### 5.2 BFT-HotStuff derivative

The consensus crate is `exo-consensus`. The protocol is a
HotStuff-derivative with three-phase commit (Prepare → PreCommit →
Commit → Decide), view-change on timeout, and checkpoint finality on
decide. Safety: `f < n/3`, i.e. the system tolerates up to one-third
Byzantine validators.

A checkpoint is deterministically final once committed. No
probabilistic "longest chain" ambiguity, no reorganisations, no
rollbacks.

### 5.3 Validator rotation and PACE

- **Validator rotation** is scheduled by the consensus epoch: the
  validator set may be updated at checkpoint boundaries with a
  `ValidatorSetUpdate` event, ratified by the outgoing set.
- **PACE** (Protected Access Control and Escalation) is the
  multi-signature steward protocol for key recovery and dispute
  resolution. Implemented in `exo-identity::pace` with Verifiable
  Secret Sharing (Feldman commitments) and a geographic-distribution
  requirement (no two stewards in the same jurisdiction).
- **Species Quorum** (CR-001 / spec v2.2 §3A): PACE recovery must
  include ≥3 human stewards and ≥1 Holon steward. Single-species
  control is rejected.

---

## 6. The ~40 MCP tools as an API surface

The MCP server in `crates/exo-node/src/mcp/` exposes governance
operations to AI agents. Tools are grouped by domain. The registry at
[`crates/exo-node/src/mcp/tools/mod.rs`](../../crates/exo-node/src/mcp/tools/mod.rs)
dispatches `tools/call` requests to the appropriate handler.

| Domain         | Tool count (approx.) | Primary use case                                                 | Module                                      |
|----------------|----------------------|------------------------------------------------------------------|---------------------------------------------|
| Node           | 3                    | Status, list invariants, list MCP rules                          | `tools/node.rs`                             |
| Identity       | 5                    | Create / resolve DIDs, risk, signature verification, passport    | `tools/identity.rs`                         |
| Consent        | 4                    | Propose / check / list / terminate bailments                     | `tools/consent.rs`                          |
| Governance     | 6                    | Create decision, cast vote, check quorum, status, amendment      | `tools/governance.rs`                       |
| Authority      | 3                    | Delegate, verify chain, check permission                         | `tools/authority.rs`                        |
| Kernel         | 1                    | `exochain_adjudicate_action` — single-call kernel adjudication   | (dispatched to `governance.rs`)             |
| Ledger         | 4                    | Submit event, get event, inclusion proof, get checkpoint         | `tools/ledger.rs`                           |
| Proofs         | 4                    | Evidence envelopes, custody-chain verification, verifier-compatible Merkle proofs, fail-closed CGR proof verifier placeholder | `tools/proofs.rs`                           |
| Legal          | 4                    | eDiscovery, privilege, DGCL §144 safe harbour, fiduciary duty    | `tools/legal.rs`                            |
| Escalation     | 4                    | Evaluate threat, escalate case, triage, feedback                 | `tools/escalation.rs`                       |
| Messaging      | 3                    | Send encrypted, receive encrypted, configure death trigger       | `tools/messaging.rs`                        |

Alongside tools, the MCP server exposes four **prompts**:

| Prompt                    | When the AI should invoke it                             | Module                                                 |
|---------------------------|----------------------------------------------------------|--------------------------------------------------------|
| `governance_review`       | Review a pending decision                                | `mcp/prompts/governance_review.rs`                     |
| `compliance_check`        | Verify an action against the 8 invariants + 6 MCP rules  | `mcp/prompts/compliance_check.rs`                      |
| `evidence_analysis`       | Analyse an evidence bundle for admissibility             | `mcp/prompts/evidence_analysis.rs`                     |
| `constitutional_audit`    | Audit a system state against all 8 invariants            | `mcp/prompts/constitutional_audit.rs`                  |

The detailed AI-side usage is in
[`ai-agent-guide.md`](./ai-agent-guide.md).

---

## 7. Where to go next

- [`constitutional-model.md`](./constitutional-model.md) — the 8
  invariants and 6 MCP rules in full, including line references to
  source.
- [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md)
  — the long-form architecture reference with crate dependency graph
  and BCTS lifecycle detail.
- [`../architecture/THREAT-MODEL.md`](../architecture/THREAT-MODEL.md)
  — the formal threat model against which the architecture is
  defended.
- [`cgr-developer-guide.md`](./cgr-developer-guide.md) — a task-oriented
  guide to interacting with the CGR Kernel from user code.
- [`../../governance/traceability_matrix.md`](../../governance/traceability_matrix.md)
  — 87 requirements mapped to crate → module → test locations. The
  best map of "where is the code for X?".

---

Copyright (c) 2025–2026 EXOCHAIN Foundation. Licensed under the
Apache License, Version 2.0. See [`../../LICENSE`](../../LICENSE).

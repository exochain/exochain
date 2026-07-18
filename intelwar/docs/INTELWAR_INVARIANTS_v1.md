# IntelWar Invariants v1 — CGR-Encodable Specification

**Status:** Canonical for branch `intelwar`  
**Substrate:** EXOCHAIN v0.2.3 CGR Kernel (`exo-gatekeeper`)  
**Implements via:** `InvariantContext` fields + decision-forum human gate + Living Log receipts  
**Companion:** [`INTELWAR_CONSTITUTION.md`](../INTELWAR_CONSTITUTION.md)

These eight IntelWar invariants **overlay** the eight EXOCHAIN constitutional
invariants. They do not replace them. Every Log append MUST pass EXOCHAIN
`InvariantEngine::all()` first, then IntelWar overlay checks encoded in
`intelwar_core::invariants`.

---

## Encoding convention (CGR)

Each IntelWar invariant maps to:

| Field | Meaning |
|-------|---------|
| `id` | Stable kebab-case string (Log + evidence) |
| `cgr_hooks` | EXOCHAIN invariants that must already hold |
| `context_requirements` | `AdjudicationContext` / Log fields required |
| `fail_closed` | Denial condition |
| `decision_forum` | Optional BCTS / human-gate coupling |

CGR adjudication entrypoint for append:

```text
ActionRequest { action: "intelwar.log.append", ... }
  → Kernel::adjudicate (EXOCHAIN 8)
  → IntelWarInvariantEngine::enforce_all (IntelWar 8)
  → Provenance receipt
  → exo_dag::append
```

---

## IW-1 — LivingLogIntegrity

**ID:** `living-log-integrity`  
**CGR hooks:** `ProvenanceVerifiable`, `KernelImmutability`

**Rule:** Every accepted LogEntry is append-only, content-addressed (BLAKE3 over
canonical CBOR), and linked to a prior tip hash (or genesis). Mutation and
silent rewrite are denied.

**Context requirements:**

- `entry.content_hash` = `blake3(cbor(entry.body))`
- `entry.parent_hashes` ⊆ current DAG tips or empty only at genesis
- Receipt binds `dag_node_hash`

**Fail closed:** Missing parent, hash mismatch, or attempted in-place update.

**Decision-forum:** Contestation may *annotate* via challenge entries; never
rewrite the challenged entry.

---

## IW-2 — ConsentBeforeMemory

**ID:** `consent-before-memory`  
**CGR hooks:** `ConsentRequired`

**Rule:** No strategic memory (Log append) without active bailment consent whose
scope covers `log:append` (or a narrower scoped clause that covers the
requested permission).

**Context requirements:**

- `BailmentState::Active { bailee == actor, scope covers log:append }`
- Matching active `ConsentRecord`

**Fail closed:** Absent, revoked, suspended, or scope-mismatched consent.

**Human override note:** Emergency human override MAY deny appends; it MUST NOT
fabricate consent.

---

## IW-3 — AuthorityBoundAppend

**ID:** `authority-bound-append`  
**CGR hooks:** `AuthorityChainValid`, `NoSelfGrant`

**Rule:** The appending actor must terminate a verified authority chain that
includes `log:append`, and must not self-grant that permission.

**Context requirements:**

- Non-empty signed `AuthorityChain` ending at actor
- Trusted grantor keys resolved independently of the link payload
- `is_self_grant == false`

**Fail closed:** Empty chain, broken topology, unverified signature, or self-grant.

---

## IW-4 — MultiIntelligenceTransparent

**ID:** `multi-intelligence-transparent`  
**CGR hooks:** `ProvenanceVerifiable`, `QuorumLegitimate`  
**Primitives:** `VoiceKind`, `IndependenceClaim`, `ReviewOrder`, AVC subject kinds

**Rule:** Every LogEntry and every quorum-relevant opinion MUST declare:

| Field | Allowed values |
|-------|----------------|
| `voice_kind` | `Human` \| `Synthetic` \| `System` |
| `independence` | `Independent` \| `Coordinated` (required for Human) |
| `review_order` | `FirstOrder` \| `Derivative` (required for Human) |
| `agent_attestation` | Required when `voice_kind == Synthetic` |

**Counting rules (aligned with CR-001 §8.3):**

- Synthetic and System voices NEVER count as distinct humans for quorum.
- Unspecified `voice_kind` is fail-closed (never assumed human).
- AI/agent contributions MUST carry explicit attestation (model/session id +
  signature or delegated AVC receipt).

**Fail closed:** Missing taxonomy, synthetic counted as human, or unattested agent prose treated as authority.

**Decision-forum:** `ActorKind::AiAgent` + `enforce_human_gate_with_verified_humans`.

---

## IW-5 — HumanOverrideSacred

**ID:** `human-override-sacred`  
**CGR hooks:** `HumanOverride`

**Rule:** A verified human MAY halt, reverse (via annotated reversal entry), or
escalate any automated IntelWar pipeline. Human override capability cannot be
disabled by AI agents, config drift, or Log policy.

**Semantics:**

1. `human_override_preserved` MUST remain `true` for all append adjudications.
2. Override actions produce a LogEntry with `entry_kind = HumanOverride` and
   `voice_kind = Human`.
3. Override may deny future appends under a scoped hold; it may not erase history
   (see IW-1).

**Fail closed:** Any path that sets `human_override_preserved = false` or that
allows synthetic actors to disable the override channel.

---

## IW-6 — CrossCheckBeforeCommit

**ID:** `crosscheck-before-commit`  
**CGR hooks:** `QuorumLegitimate` (when multi-party), decision-forum contestation

**Rule:** Strategic claims marked `requires_crosscheck = true` MUST attach at
least one `CrossCheckResult` (agree / disagree / abstain with evidence hash)
from a distinct intelligence before commit. Same-actor self-crosscheck is denied.

**Context requirements:**

- `CrossCheckResult.checker_did != author_did`
- Checker provenance satisfies IW-4
- Optional quorum evidence when policy threshold > 1

**Fail closed:** Missing crosscheck when required; self-check; unverified checker.

**.ai extension:** `intelwar/apps/.../ai/crosscheck.js` and future
`crosschecked.ai` adapters plug here — they do not mint constitutional truth
outside the Kernel path.

---

## IW-7 — DebateBeforeDoctrine

**ID:** `debate-before-doctrine`  
**CGR hooks:** SeparationOfPowers + decision-forum workflow

**Rule:** Entries with `entry_kind = Doctrine` or `ConstitutionalAmendment`
MUST reference a closed or quorum-approved `DebateSession` (decision-forum
`DecisionObject` lifecycle) before append.

**BCTS coupling (minimum):**

`Draft → Submitted → ConsentValidated → Deliberated → Approved → Recorded`

Transitions use `transition_adjudicated_at` (kernel-gated). Raw transitions are
denied.

**Fail closed:** Doctrine without debate reference; debate not in approved/closed
state; single-branch capture of legislative+executive+judicial roles.

---

## IW-8 — ProvenanceCompounding

**ID:** `provenance-compounding`  
**CGR hooks:** `ProvenanceVerifiable`  
**Primitives:** `exo-proofs` `ProofEnvelope` (`ExecutionReceipt` / `DagInclusion`),
economy/legal receipt patterns

**Rule:** Each successful append emits a Living Log **receipt** that chains:

```text
previous_receipt_hash → entry_hash → dag_node_hash → proof_envelope_commitment
```

Receipts are themselves Log-addressable. Wisdom compounds because later entries
can cite receipt hashes as evidence without re-litigating prior adjudication.

**Fail closed:** Append without receipt; broken receipt chain; unsigned provenance.

---

## Human override semantics (normative summary)

| Actor | May deny append | May erase Log | May disable override | May attest as Human |
|-------|-----------------|---------------|----------------------|---------------------|
| Verified Human | Yes | No | No | Yes (if true) |
| Synthetic / AI | No (except delegated deny policy under human hold) | No | No | No |
| System | No | No | No | No |

---

## Implementation checklist

- [x] Spec (`this document`)
- [x] Rust enum + engine: `intelwar_core::invariants`
- [x] Append path: `intelwar_core::append_flow`
- [ ] WASM export via `exochain-wasm` / `intelwar/wasm` hooks
- [ ] decision-forum DebateSession persistence
- [ ] Production DAG DB write path (gateway) with fail-closed config

## Versioning

Breaking changes to invariant IDs or fail-closed semantics require a LogEntry
`ConstitutionalAmendment` satisfying IW-7 and a new `INTELWAR_INVARIANTS_vN.md`.

# Living Log Data Model — Canonical CBOR + Receipt Schema

**Status:** Canonical  
**Serialization:** Canonical CBOR via `ciborium` (sorted keys; never hash JSON)  
**Hash:** BLAKE3 (`exo_core::Hash256`)  
**Aligned with:** `exo-proofs` envelopes, gatekeeper `Provenance`, `exo-economy` /
`exo-legal` receipt chaining patterns, `exo-dag` node payload

Rust source of truth: `intelwar/crates/intelwar-core/src/log_entry.rs`.

---

## Domain separator

```text
intelwar.living-log.entry.v1
intelwar.living-log.receipt.v1
intelwar.living-log.append.v1
```

---

## LogEntry (body)

Canonical CBOR map (logical fields):

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | u16 | `1` |
| `entry_id` | string | UUID or ULID string (correlation only; not content address) |
| `entry_kind` | enum string | see below |
| `author_did` | string | `Did` |
| `hlc_timestamp` | `{ physical_ms: u64, logical: u32 }` | `exo_core::Timestamp` |
| `parent_hashes` | `[bstr]` | 32-byte BLAKE3 hashes; empty only at genesis |
| `summary` | string | Human-readable headline |
| `payload` | bstr | Opaque domain payload (itself preferably CBOR) |
| `voice_kind` | enum | `human` \| `synthetic` \| `system` |
| `independence` | enum? | required for human |
| `review_order` | enum? | required for human |
| `agent_attestation` | map? | required for synthetic |
| `requires_crosscheck` | bool | IW-4 |
| `crosscheck_refs` | `[string]` | entry_ids or content hashes of CrossCheckResults |
| `debate_ref` | string? | required for doctrine / amendment (IW-4) |
| `consent_scope` | string | must cover append permission |
| `intelwar_invariants` | `[string]` | invariant IDs claimed satisfied |
| `exochain_invariants` | `[string]` | EXOCHAIN invariant IDs from kernel pass |

### `entry_kind` values

```text
Observation | Analysis | DebateNote | CrossCheck | Doctrine |
ConstitutionalAmendment | HumanOverride | AgentAttestation |
DevelopmentDecision | ReceiptAnchor
```

### `agent_attestation` map

| Field | Type |
|-------|------|
| `model_id` | string |
| `session_id` | string |
| `tool` | string | e.g. `cursor-agent` |
| `attestation_signature` | bstr |
| `avc_receipt_hash` | bstr? |

### Content hash

```text
content_hash = BLAKE3( CBOR( LogEntryBody without content_hash ) )
```

The stored entry includes `content_hash` after hashing the body.

---

## Example LogEntry (JSON illustration only — wire format is CBOR)

```json
{
  "schema_version": 1,
  "entry_id": "018f-example-entry",
  "entry_kind": "DevelopmentDecision",
  "author_did": "did:exo:intelwar-human-1",
  "hlc_timestamp": { "physical_ms": 1752854400000, "logical": 1 },
  "parent_hashes": [],
  "summary": "Adopt Living Log append path via CGR Kernel",
  "payload": { "decision": "bootstrap_intelwar_core", "refs": ["INTELWAR_CONSTITUTION.md"] },
  "voice_kind": "human",
  "independence": "independent",
  "review_order": "first_order",
  "requires_crosscheck": false,
  "crosscheck_refs": [],
  "debate_ref": null,
  "consent_scope": "log:append",
  "intelwar_invariants": [
    "consent-required",
    "provenance-verifiable",
    "multi-intelligence-transparent",
    "evidence-disciplined",
    "human-override-priority",
    "fail-closed-enforcement",
    "strategic-utility",
    "log-integrity"
  ],
  "exochain_invariants": [
    "separation-of-powers",
    "consent-required",
    "no-self-grant",
    "human-override",
    "kernel-immutability",
    "authority-chain-valid",
    "quorum-legitimate",
    "provenance-verifiable"
  ]
}
```

---

## LivingLogReceipt

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | u16 | `1` |
| `receipt_id` | string | |
| `previous_receipt_hash` | bstr? | null at genesis |
| `entry_content_hash` | bstr | |
| `dag_node_hash` | bstr | from `exo_dag` |
| `action_hash` | bstr | hash of append action CBOR |
| `actor_did` | string | |
| `voice_kind` | enum | mirrors entry |
| `provenance` | map | gatekeeper `Provenance` fields |
| `proof_statement_kind` | string | prefer `ExecutionReceipt` or `DagInclusion` |
| `kernel_verdict` | string | `permitted` |
| `intelwar_verdict` | string | `permitted` |
| `signature` | bstr | Ed25519 over receipt payload |

Receipt hash:

```text
receipt_hash = BLAKE3( CBOR( LivingLogReceipt without signature/receipt_hash ) )
```

Chain:

```text
genesis_receipt → r1 → r2 → …  (previous_receipt_hash links)
```

Alignment notes:

- `exo-proofs::ProofEnvelope` may wrap the receipt as `ExecutionReceipt` /
  `DagInclusion` when a proof backend is available; until then the Ed25519
  provenance + DAG inclusion is the production binding (fail closed on missing
  signature).
- Economy/legal receipts similarly chain via `previous_receipt_hash` — Living
  Log reuses that discipline without inventing a parallel economy.

---

## Append flow (normative)

```text
1. Build LogEntryBody (HLC from DeterministicDagClock / HybridClock)
2. Serialize body → CBOR; content_hash = BLAKE3(cbor)
3. Consent check (bailment active, scope covers log:append)
4. Authority chain verify (terminal grantee = actor, permission log:append)
5. Build ActionRequest { action: "intelwar.log.append", ... }
6. Attach signed Provenance (voice taxonomy for IW-3)
7. Kernel::adjudicate → must be Verdict::Permitted
8. IntelWarInvariantEngine::enforce_all → Ok (IW-1…IW-8)
9. If requires_crosscheck: verify CrossCheckResult set (IW-4)
10. If Doctrine/Amendment: verify DebateSession approved (IW-4)
11. exo_dag::append(payload = CBOR(entry), parents = parent_hashes) (IW-8)
12. Mint LivingLogReceipt chaining previous_receipt_hash (IW-2)
13. Optionally append ReceiptAnchor entry citing receipt_hash
```

Fail closed at any step (IW-6); no partial DAG write after kernel denial.

---

## CrossCheckResult (embedded or referenced entry)

| Field | Type |
|-------|------|
| `checker_did` | string |
| `subject_entry_hash` | bstr |
| `verdict` | `agree` \| `disagree` \| `abstain` |
| `evidence_hash` | bstr |
| `voice_kind` | enum |
| `signature` | bstr |

---

## DebateSession (reference)

Maps to decision-forum `DecisionObject` id + BCTS state. IntelWar stores the
Living Log reference (`debate_ref` / `DebateSession`) and accepts terminal
states derived from BCTS `Approved` / `Executed` / `Recorded` / `Closed`.

**PM-003 enforcement:** `Doctrine` and `ConstitutionalAmendment` appends require
a real `DecisionObject` (`AppendRequest.debate_decision`). Bare session claims
without a DecisionObject fail closed. Strategic/Constitutional classes also
require the decision-forum human gate with externally verified human voter DIDs.
`ConstitutionalAmendment` requires `DecisionClass::Constitutional`.

---

## Determinism rules

- `BTreeMap` / sorted arrays only
- No `SystemTime::now()` — HLC only
- No floats
- Hash CBOR, never JSON

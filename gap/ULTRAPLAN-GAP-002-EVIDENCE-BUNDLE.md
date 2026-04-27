# ULTRAPLAN — GAP-002: Evidence Bundle Export

**Status:** Closed — Basalt reconciled 2026-04-26
**Crate:** `exo-legal`  
**File:** `crates/exo-legal/src/bundle.rs`  
**Author:** Aeon (Chief-of-Staff AI)  
**Date:** 2026-04-15  

---

## 1. Bundle Structure

An `EvidenceBundle` is a self-contained, offline-verifiable, forensic-grade artifact that packages a decision's complete evidentiary record. It contains:

- **Subject** — What the bundle is about: a decision, transaction, delegation, identity event, consent action, or emergency action. Identified by type, ID, title, and description.
- **Events** — An ordered sequence of `BundleEvent` records, each with a sequence number, event hash, actor DID, timestamp, payload summary, parent hashes (for causal ordering), and a link to the originating DAG node hash. Events form a causal chain: each event's `parent_hashes` must reference hashes of prior events in the sequence.
- **Evidence Items** — The actual `Evidence` records from `exo-legal::evidence`, each carrying content hash, creator provenance, chain of custody, and admissibility status.
- **Consent Records** — `ConsentSummary` entries for active bailments/consents governing the subject. Each records bailor, bailee, bailment type, terms hash, and status.
- **Contract Summary** — An optional `ContractSummary` capturing the governing bailment contract's ID, hash, template name, parties, and human-readable key terms.
- **FRE 902(11) Certification** — An optional `Cert902_11` artifact providing self-authentication under Federal Rule of Evidence 902(11), generated from `exo-legal::cert_902_11`.
- **DAG Anchor** — A `DagAnchor` linking the bundle to a finalized DAG checkpoint: checkpoint height, MMR event root, SMT state root, validator signatures, and anchor timestamp. This is the bundle's root of trust.
- **Verification Manifest** — A `VerificationManifest` describing the hash algorithm (BLAKE3), format version, and a step-by-step verification protocol. Each `VerificationStep` lists input hashes and expected output, enabling mechanical offline verification.
- **Bundle Hash** — A BLAKE3 root hash computed over all content fields (excluding signatures and the hash field itself). This is the bundle's tamper-evident seal.
- **Signatures** — `BundleSignature` entries from organization officers, validators, and witnesses. Each carries signer DID, role, cryptographic signature, and signing timestamp. Signatures are over the `bundle_hash`, not the raw content — so adding signatures never changes the hash.

## 2. Assembly Flow

Bundle assembly follows a deterministic pipeline:

1. **Collect** — Caller gathers the subject description, events from the DAG, evidence records from `exo-legal::evidence`, consent records from `exo-consent`, contract summaries from `exo-consent::contract`, and the FRE 902(11) cert from `exo-legal::cert_902_11`.
2. **Validate** — The `assemble()` function validates: events must have sequential sequence numbers starting from 0; each event's `parent_hashes` must reference only hashes of preceding events (causal ordering); at least one event is required.
3. **Build Verification Manifest** — Automatically generated from bundle contents. Step 1 verifies the event chain hash. Step 2 verifies the evidence items hash. Step 3 verifies the overall bundle hash. Each step lists its input hashes and expected output.
4. **Compute Root Hash** — `compute_bundle_hash()` feeds all structural fields into a BLAKE3 hasher with a domain separator (`exo:bundle:v1:`). The hash covers: id, version, created_at, subject, events, evidence items, consent records, contract summary, certification, DAG anchor, and verification manifest. Signatures and the hash field itself are excluded.
5. **Stamp** — The computed hash is written to `bundle_hash`. The bundle is now sealed.
6. **Sign** — Organization officers and validators call `sign()` to append `BundleSignature` entries. Signatures attest to the `bundle_hash` and do not alter it.

## 3. Verification Protocol

Offline verification requires zero network access:

1. **Recompute Hash** — Feed all content fields through the same BLAKE3 pipeline. Compare to `bundle_hash`. If mismatch → tampered.
2. **Validate Event Ordering** — Confirm `sequence` numbers are 0, 1, 2, … with no gaps.
3. **Validate Causal Chain** — For each event at position i > 0, confirm all `parent_hashes` appear as `event_hash` values in events at positions < i. Event 0 must have empty `parent_hashes` (genesis).
4. **Check Signatures** — Use `verify_with_signer_keys()` with a `BundleSignerKeyResolver`. For each `BundleSignature`, resolve the signer DID to a public key and verify the Ed25519 signature over the domain-separated canonical CBOR signing payload that binds `bundle_hash`, signer DID, signer role, and signed timestamp. A missing signer key, empty signature, wrong key, replayed signature, or tampered bundle fails closed.
5. **Result** — `VerificationResult` reports `hash_valid`, `event_chain_valid`, `causal_order_valid`, per-signature `SignatureCheck` results, and an `overall` boolean (all checks pass).

## 4. Legal Admissibility Mapping

The bundle structure maps to four key Federal Rules of Evidence:

- **FRE 901 (Authentication)** — The DAG anchor provides cryptographic authentication. The event chain with BLAKE3 hashes establishes that records are what they purport to be. The verification manifest provides a mechanical authentication protocol.
- **FRE 803(6) (Business Records Exception)** — Evidence items carry timestamps proving they were "made at or near the time" of the event. The `Cert902_11` artifact attests to regular business practice. The chain of custody proves unbroken possession.
- **FRE 902(13/14) (Self-Authentication of Electronic Records)** — The bundle hash provides a certified hash matching the original. The verification manifest serves as the "process or system" description. Validator signatures serve as certifying authority.
- **Daubert Standard** — The verification protocol is testable (deterministic BLAKE3 recomputation). The methodology has a known error rate (cryptographic: negligible collision probability). The technique (Merkle-style hash chaining) is generally accepted in the relevant scientific community. The verification manifest is the "peer review" artifact — any party can independently verify.

## 5. Serialization Format

- **Primary:** Canonical JSON via `serde_json` for the `render_json()` function. All types derive `Serialize`/`Deserialize`. JSON is the human-readable companion format.
- **Hash computation:** BLAKE3 over deterministic byte concatenation of fields with domain separators. No CBOR dependency needed for v1 — the hash function operates on raw field bytes in canonical order.
- **Markdown:** `render_markdown_summary()` produces an executive summary suitable for Board Book inclusion, with subject header, event timeline, evidence inventory, and signature attestations.

## 6. Hash Chain Integrity

The bundle hash is computed by `compute_bundle_hash()`:

```
BLAKE3(
  "exo:bundle:v1:"
  || id.bytes
  || version.le_bytes
  || created_at.physical_ms.le_bytes || created_at.logical.le_bytes
  || subject.subject_type || subject.subject_id || subject.title || subject.description
  || for each event: sequence.le || event_hash || event_type || actor || timestamp || payload_summary || parent_hashes || dag_node_hash
  || for each evidence: id.bytes || type_tag || hash || creator || timestamp
  || for each consent: bailment_id || bailor || bailee || bailment_type || terms_hash || status
  || contract_summary (if present): contract_id || contract_hash || template_name || parties || key_terms
  || certification (if present): cert_hash
  || dag_anchor: checkpoint_height || event_root || state_root || anchored_at
  || verification: format_version || hash_algorithm || steps
)
```

Every field is hashed in declaration order. Vectors are length-prefixed (element count as u64 LE). Optional fields use a presence byte (0x00 absent, 0x01 present). This ensures deterministic, canonical hashing regardless of serialization format.

## 7. Integration with Board Book Export

The `render_markdown_summary()` function produces a section suitable for direct inclusion in `decision-forum`'s Board Book:

```markdown
# Evidence Bundle: [Subject Title]
**Bundle ID:** [id]  
**Created:** [timestamp]  
**Subject:** [type] — [description]

## Event Timeline
| # | Type | Actor | Time | Summary |
|---|------|-------|------|---------|
| 0 | ... | ... | ... | ... |

## Evidence Inventory
- [N] evidence items, [M] admissible

## Signatures
- [role]: [DID] at [time]
```

The `decision-forum` crate can call `bundle::render_markdown_summary()` and embed the result in its `FiduciaryPackage` Board Book section. The `EvidenceBundle` struct is `Serialize`/`Deserialize`, so it can also be included as a structured attachment.

---

**Implementation:** `crates/exo-legal/src/bundle.rs` — all types, assembly, structural verification, signer-key verification, rendering, signing, and regression tests for valid signatures, wrong keys, replay, tampering, and empty signatures.

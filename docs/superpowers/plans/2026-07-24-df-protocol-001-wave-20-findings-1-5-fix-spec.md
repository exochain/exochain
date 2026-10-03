# DF-PROTOCOL-001 Wave 20 Findings 1–5 Fix Specification

**Status:** Plan-only repair specification. Does **not** itself make Wave 20 GREEN.
**Applies to plans at:** `21ff7bc75a6884d463366215cb3667247ae4bb1b`
**Target files (to be edited by a local writer after this spec is approved):**
- `docs/superpowers/plans/2026-07-16-df-protocol-001-01-charter-normative-schema.md`
- `docs/superpowers/plans/2026-07-16-df-protocol-001-02-core-protocol-receipt-model.md`
**Constraints:** No production crates. No external shim. No force-push. Plan-only materializer must yield `cargo test --no-run` green.

## Finding 3 — Expand Slice 1 CommitmentScheme 20 → 35

Replace `$defs.CommitmentScheme` with the closed 35-field set (Slice-2 order, `additionalProperties: false`):

```json
"CommitmentScheme": {
  "description": "Closed set of domain-separated hash domains and the final-root normalization rule. Expanded to the full 35-field closed set so a Slice 2 package remains schema-valid against Slice 1.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "protocol_version_domain",
    "protocol_envelope_domain",
    "review_bundle_domain",
    "eligible_set_domain",
    "authorization_target_domain",
    "seat_attestation_signing_payload_domain",
    "seat_attestation_domain",
    "peer_review_signing_payload_domain",
    "council_disposition_signing_payload_domain",
    "ai_irb_disposition_signing_payload_domain",
    "chair_intervention_signing_payload_domain",
    "dissent_signing_payload_domain",
    "investigator_designation_signing_payload_domain",
    "aar_rca_attestation_signing_payload_domain",
    "estop_disposition_signing_payload_domain",
    "estop_authorization_signing_payload_domain",
    "notification_attempt_signing_payload_domain",
    "reset_authorization_signing_payload_domain",
    "phase_promotion_disposition_signing_payload_domain",
    "phase_promotion_signing_payload_domain",
    "prepublication_domain",
    "publication_authorization_domain",
    "final_package_domain",
    "renderer_manifest_domain",
    "artifact_manifest_domain",
    "execution_receipt_domain",
    "execution_receipt_chain_domain",
    "genesis_evidence_bundle_domain",
    "genesis_adoption_receipt_domain",
    "genesis_adoption_signing_payload_domain",
    "historical_act_chronology_entry_domain",
    "historical_act_chronology_domain",
    "historical_artifact_set_commitment_domain",
    "historical_blind_review_coverage_domain",
    "final_root_normalization"
  ],
  "properties": {
    "protocol_version_domain": { "const": "exo.decision_forum.protocol_version.v1" },
    "protocol_envelope_domain": { "const": "exo.decision_forum.protocol_envelope.v1" },
    "review_bundle_domain": { "const": "exo.decision_forum.review_bundle.v1" },
    "eligible_set_domain": { "const": "exo.decision_forum.eligible_set.v1" },
    "authorization_target_domain": { "const": "exo.decision_forum.protocol_authorization_target.v1" },
    "seat_attestation_signing_payload_domain": { "const": "exo.decision_forum.seat_attestation_signing_payload.v1" },
    "seat_attestation_domain": { "const": "exo.decision_forum.seat_attestation.v1" },
    "peer_review_signing_payload_domain": { "const": "exo.decision_forum.peer_review_signing_payload.v1" },
    "council_disposition_signing_payload_domain": { "const": "exo.decision_forum.council_disposition_signing_payload.v1" },
    "ai_irb_disposition_signing_payload_domain": { "const": "exo.decision_forum.ai_irb_disposition_signing_payload.v1" },
    "chair_intervention_signing_payload_domain": { "const": "exo.decision_forum.chair_intervention_signing_payload.v1" },
    "dissent_signing_payload_domain": { "const": "exo.decision_forum.dissent_signing_payload.v1" },
    "investigator_designation_signing_payload_domain": { "const": "exo.decision_forum.investigator_designation_signing_payload.v1" },
    "aar_rca_attestation_signing_payload_domain": { "const": "exo.decision_forum.aar_rca_attestation_signing_payload.v1" },
    "estop_disposition_signing_payload_domain": { "const": "exo.decision_forum.estop_disposition_signing_payload.v1" },
    "estop_authorization_signing_payload_domain": { "const": "exo.decision_forum.estop_authorization_signing_payload.v1" },
    "notification_attempt_signing_payload_domain": { "const": "exo.decision_forum.notification_attempt_signing_payload.v1" },
    "reset_authorization_signing_payload_domain": { "const": "exo.decision_forum.reset_authorization_signing_payload.v1" },
    "phase_promotion_disposition_signing_payload_domain": { "const": "exo.decision_forum.phase_promotion_disposition_signing_payload.v1" },
    "phase_promotion_signing_payload_domain": { "const": "exo.decision_forum.phase_promotion_signing_payload.v1" },
    "prepublication_domain": { "const": "exo.decision_forum.prepublication_package.v1" },
    "publication_authorization_domain": { "const": "exo.decision_forum.publication_authorization_receipt.v1" },
    "final_package_domain": { "const": "exo.decision_forum.peer_reviewed_protocol_package.v1" },
    "renderer_manifest_domain": { "const": "exo.decision_forum.renderer_manifest.v1" },
    "artifact_manifest_domain": { "const": "exo.decision_forum.publication_artifact_manifest.v1" },
    "execution_receipt_domain": { "const": "exo.decision_forum.protocol_execution_receipt.v1" },
    "execution_receipt_chain_domain": { "const": "exo.decision_forum.protocol_execution_receipt_chain.v1" },
    "genesis_evidence_bundle_domain": { "const": "exo.decision_forum.genesis_evidence_bundle.v1" },
    "genesis_adoption_receipt_domain": { "const": "exo.decision_forum.genesis_adoption_receipt.v1" },
    "genesis_adoption_signing_payload_domain": { "const": "exo.decision_forum.genesis_adoption_signing_payload.v1" },
    "historical_act_chronology_entry_domain": { "const": "exo.decision_forum.historical_act_chronology_entry.v1" },
    "historical_act_chronology_domain": { "const": "exo.decision_forum.historical_act_chronology.v1" },
    "historical_artifact_set_commitment_domain": { "const": "exo.decision_forum.historical_artifact_set_commitment.v1" },
    "historical_blind_review_coverage_domain": { "const": "exo.decision_forum.historical_blind_review_coverage.v1" },
    "final_root_normalization": { "const": "replace receipt_manifest.final_package_root with 32 zero bytes" }
  }
}
```

Also update the positive-package `commitment_scheme` fixture object to the same 35 keys/values, and any hard-coded field-count assertions.

## Finding 5 — GenesisAdoptionSignature naming

In Slice 1:
- Rename `$defs.GenesisAdoptionSignature` → `$defs.GenesisAdoptionSignatureV1`
- Update every `$ref` and fixture that points at it.
- Fields and `signed_payload_target: "GenesisAdoptionReceiptV1"` stay unchanged.

## Finding 2 — VerifiedReviewReveal rename

In Slice 2, aspirational genesis verifier signature only (~line 348):
- Change `review_evidence: &VerifiedReviewRevealV1` → `review_evidence: &VerifiedHistoricalReviewRevealV1`
- Do **not** rename the distinct blind-custody `VerifiedReviewRevealV1` (~534).

## Finding 4 — Forbidden-root prose

Replace any overclaim of the form “rejects any historical entry or string/byte field equal to …” with language that matches the real check:

> Semantic validation rejects any of the three selected current-package ProtocolHash256 roots (authorization_target_hash, prepublication_root, final_package_root) appearing in the scanned genesis ProtocolHash256 fields, via the same closed three-root set carried by ForbiddenCurrentGenesisRootsV1 / CurrentPackageCommitments. A closeout-index root is a Slice 10 concept and is not fabricated here.

## Finding 1 — Plan-only compile (leaf types only)

Insert a real (non-ignore) ```rust fence that defines only the missing leaf types referenced by later real fences. Do **not** redefine `ReviewAssignment` under that name.

```rust
/// Leaf types required for plan-only materialization of Wave-20 real fences.
/// These definitions are extracted by the Slice 2 materializer so that
/// `cargo test --no-run` is green with no external diagnostic shim.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sha256Digest(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLockV1 {
    pub tool_name: String,
    pub tool_version: String,
    pub tool_digest: ProtocolHash256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RendererAssetLockV1 {
    pub asset_path_hash: ProtocolHash256,
    pub asset_content_hash: ProtocolHash256,
    pub media_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RendererResourcePolicyV1 {
    pub max_memory_bytes: u64,
    pub max_cpu_milliseconds: u64,
    pub network_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevealCommitmentV1 {
    pub commitment_hash: ProtocolHash256,
    pub opening_hash: ProtocolHash256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindReviewRevealPackageSignatureV1 {
    pub algorithm: String,
    pub signing_key_id: ProtocolHash256,
    pub verification_key: Ed25519VerificationKey,
    pub signature: Ed25519Signature,
    pub signed_payload_hash: ProtocolHash256,
    pub signed_payload_target: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindReviewRevealEntryV1 {
    pub assignment_id: ProtocolUuid,
    pub assignment_opening: BlindAssignmentOpeningV1,
    pub commitment_opening: BlindCommitmentOpeningV1,
    pub seat_id: Did,
    pub seat_attestation_hash: ProtocolHash256,
    pub ephemeral_reviewer_public_key: Ed25519VerificationKey,
    pub seat_ephemeral_key_binding_signature: Ed25519Signature,
    pub sealed_review_hash: ProtocolHash256,
    pub final_custody_head: ProtocolHash256,
}

// Ensure ProtocolHashDomain includes:
// BlindReviewRevealPackageV1,
```

If `BlindAssignmentOpeningV1` / `BlindCommitmentOpeningV1` are also unresolved after materialization, add minimal stubs for them in the same fence. Do not introduce a second `ReviewAssignment`.

## Application sequence (local writer)

1. Apply the five mechanical transforms above to the two plan docs.
2. Recompute SHA-256 of both plan files; record them.
3. Run `slice-2-wave-20-guard.py` → failures=0.
4. Plan-only materialize → `cargo test --no-run`, `clippy -D warnings`, `fmt`, focused genesis mutation tests in a disposable detached worktree; remove worktree after.
5. Fresh independent specification + technical + whole-slice re-review against the new plan hashes.
6. Only if all three approve: update `.superpowers/sdd/progress.md` and PR #809 (no force-push). Then continue Slices 3–10.

Never claim Wave 20 GREEN based on a shim.

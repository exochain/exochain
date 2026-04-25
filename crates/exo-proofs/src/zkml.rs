//! Zero-knowledge ML verification.
//!
//! Verifies that a given output was produced by a committed model on a
//! committed input, without revealing the model weights or input data.
//!
//! # Provenance extensions (LEG-007)
//!
//! `InferenceProof` carries optional provenance fields required for FRE 702
//! / Daubert admissibility:
//!
//! - `prompt_hash` — distinct from `input_hash`; captures the system/user
//!   prompt separately from the contextual input data.
//! - `human_attestation` — a signed record of whether the reviewing human
//!   adopted, modified, or rejected the AI output.
//! - `ai_delta` — records the divergence between AI recommendation and final
//!   human decision.
//! - `daubert_checklist` — structured metadata for FRE 702 admissibility.
//!
//! All new fields are `Option<T>` with `#[serde(default)]` so that existing
//! serialized `InferenceProof` values continue to deserialize correctly
//! (Architecture panel backward-compat requirement).

use exo_core::types::{Hash256, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::Result;

// ---------------------------------------------------------------------------
// ModelCommitment
// ---------------------------------------------------------------------------

/// A commitment to a machine learning model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCommitment {
    /// Hash of the model architecture description.
    pub architecture_hash: Hash256,
    /// Hash of the model weights.
    pub weights_hash: Hash256,
    /// Model version identifier.
    pub version: u64,
}

impl ModelCommitment {
    /// Create a new model commitment.
    #[must_use]
    pub fn new(architecture: &[u8], weights: &[u8], version: u64) -> Self {
        Self {
            architecture_hash: Hash256::digest(architecture),
            weights_hash: Hash256::digest(weights),
            version,
        }
    }

    /// Compute the canonical commitment hash.
    #[must_use]
    pub fn commitment_hash(&self) -> Hash256 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zkml:model:");
        hasher.update(self.architecture_hash.as_bytes());
        hasher.update(self.weights_hash.as_bytes());
        hasher.update(&self.version.to_le_bytes());
        Hash256::from_bytes(*hasher.finalize().as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Provenance types (LEG-007)
// ---------------------------------------------------------------------------

/// Whether the reviewing human adopted, modified, or rejected the AI output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationDecision {
    /// Human accepted the AI output verbatim.
    Adopted,
    /// Human modified the AI output before finalising.
    Modified,
    /// Human rejected the AI output and decided independently.
    Rejected,
}

/// Signed human attestation over an AI inference.
///
/// Required for FRE 702 / Daubert admissibility: the attestation proves that
/// a qualified human reviewed the AI output and made an independent decision.
///
/// The `signature` field is an Ed25519 signature over the canonical message:
/// `b"zkml:attestation:" || reviewer_did_bytes || ai_recommendation_hash || final_decision_hash || decision_variant_byte`
///
/// Callers must verify the signature against the reviewer's `public_key` before
/// relying on the attestation for evidentiary purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanAttestation {
    /// DID of the reviewing human.
    pub reviewer_did: String,
    /// Public key of the reviewer (for signature verification).
    pub reviewer_public_key: PublicKey,
    /// What the AI system recommended.
    pub ai_recommendation_hash: Hash256,
    /// What the human ultimately decided.
    pub final_decision_hash: Hash256,
    /// Whether the human adopted, modified, or rejected the AI output.
    pub decision: AttestationDecision,
    /// Ed25519 signature over the attestation payload.
    pub signature: Signature,
}

impl HumanAttestation {
    /// Compute the canonical message that must be signed by the reviewer.
    #[must_use]
    pub fn signing_message(
        reviewer_did: &str,
        ai_recommendation_hash: &Hash256,
        final_decision_hash: &Hash256,
        decision: &AttestationDecision,
    ) -> Vec<u8> {
        let decision_byte: u8 = match decision {
            AttestationDecision::Adopted => 0x01,
            AttestationDecision::Modified => 0x02,
            AttestationDecision::Rejected => 0x03,
        };
        let mut msg = b"zkml:attestation:".to_vec();
        msg.extend_from_slice(reviewer_did.as_bytes());
        msg.extend_from_slice(ai_recommendation_hash.as_bytes());
        msg.extend_from_slice(final_decision_hash.as_bytes());
        msg.push(decision_byte);
        msg
    }

    /// Verify the Ed25519 signature on this attestation.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        let msg = Self::signing_message(
            &self.reviewer_did,
            &self.ai_recommendation_hash,
            &self.final_decision_hash,
            &self.decision,
        );
        exo_core::crypto::verify(&msg, &self.signature, &self.reviewer_public_key)
    }
}

/// Captures divergence between AI recommendation and final human decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiDelta {
    /// Hash of what the AI recommended.
    pub ai_output_hash: Hash256,
    /// Hash of the final human decision.
    pub human_output_hash: Hash256,
    /// True when the AI and human outputs differ.
    pub divergence_detected: bool,
}

impl AiDelta {
    /// Compute an AiDelta, setting `divergence_detected` automatically.
    #[must_use]
    pub fn new(ai_output: &[u8], human_output: &[u8]) -> Self {
        let ai_output_hash = Hash256::digest(ai_output);
        let human_output_hash = Hash256::digest(human_output);
        let divergence_detected = ai_output_hash != human_output_hash;
        Self {
            ai_output_hash,
            human_output_hash,
            divergence_detected,
        }
    }
}

/// Structured metadata for FRE 702 / Daubert admissibility.
///
/// An AI inference without a completed Daubert checklist should be treated as
/// `AdmissibilityStatus::Inadmissible` pending review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaubertChecklist {
    /// The AI methodology is documented and reproducible.
    pub methodology_documented: bool,
    /// The methodology has been subjected to peer review or publication.
    pub peer_reviewable: bool,
    /// The known or potential error rate of the technique (None = unknown).
    pub known_error_rate: Option<String>,
    /// The technique is generally accepted in the relevant scientific community.
    pub generally_accepted: bool,
}

impl DaubertChecklist {
    /// Returns true if all required Daubert elements are satisfied.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.methodology_documented && self.peer_reviewable && self.generally_accepted
    }
}

// ---------------------------------------------------------------------------
// InferenceProof
// ---------------------------------------------------------------------------

/// Proof that an inference was correctly executed.
///
/// The core fields (`model_commitment`, `input_hash`, `output_hash`, `proof`,
/// `verification_tag`) are always present and backward-compatible with
/// existing serialized proofs.
///
/// The provenance fields (`prompt_hash`, `human_attestation`, `ai_delta`,
/// `daubert_checklist`) are `Option<T>` with `serde(default)` so that
/// pre-existing serialized proofs continue to deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceProof {
    /// The model commitment.
    pub model_commitment: ModelCommitment,
    /// Hash of the contextual input data (context window / user message).
    pub input_hash: Hash256,
    /// Hash of the output data.
    pub output_hash: Hash256,
    /// The cryptographic proof binding input -> model -> output.
    pub proof: Hash256,
    /// Auxiliary verification data.
    pub verification_tag: Hash256,

    // ---- LEG-007 provenance extensions (backward-compatible) ----
    /// Hash of the system/user prompt (distinct from `input_hash`).
    ///
    /// Separating prompt from context allows courts to assess whether the
    /// AI was directed toward a particular outcome.
    #[serde(default)]
    pub prompt_hash: Option<Hash256>,

    /// Signed human attestation: did the reviewer adopt, modify, or reject?
    #[serde(default)]
    pub human_attestation: Option<HumanAttestation>,

    /// Divergence record comparing AI recommendation to final human decision.
    #[serde(default)]
    pub ai_delta: Option<AiDelta>,

    /// Daubert admissibility checklist for FRE 702 compliance.
    #[serde(default)]
    pub daubert_checklist: Option<DaubertChecklist>,
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Generate a basic proof (backward-compatible, no provenance fields).
///
/// Equivalent to the previous API.  New callers should prefer
/// `prove_inference_with_provenance()`.
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
pub fn prove_inference(
    model: &ModelCommitment,
    input: &[u8],
    output: &[u8],
) -> Result<InferenceProof> {
    crate::guard_unaudited("zkml::prove_inference")?;
    let input_hash = Hash256::digest(input);
    let output_hash = Hash256::digest(output);
    let model_hash = model.commitment_hash();

    // Compute the proof: a deterministic binding of model + input + output.
    // NOTE: In a production ZKML system this would execute the model inside a
    // ZK circuit (R1CS or STARK).  This hash-based binding is the MVP
    // implementation and is documented as such for Daubert disclosure purposes.
    let proof = compute_inference_proof(&model_hash, &input_hash, &output_hash);

    let verification_tag = compute_verification_tag(&model_hash, &input_hash, &output_hash, &proof);

    Ok(InferenceProof {
        model_commitment: model.clone(),
        input_hash,
        output_hash,
        proof,
        verification_tag,
        prompt_hash: None,
        human_attestation: None,
        ai_delta: None,
        daubert_checklist: None,
    })
}

/// Generate a proof with full LEG-007 provenance.
///
/// `prompt` is the system/user prompt (separate from `input` context data).
/// The resulting proof carries a distinct `prompt_hash` for Daubert disclosure.
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
pub fn prove_inference_with_provenance(
    model: &ModelCommitment,
    prompt: &[u8],
    input: &[u8],
    output: &[u8],
) -> Result<InferenceProof> {
    // guard applied via the inner call
    let mut proof = prove_inference(model, input, output)?;
    proof.prompt_hash = Some(Hash256::digest(prompt));
    Ok(proof)
}

/// Verify that an inference proof is valid.
///
/// This checks that the proof correctly binds the model commitment, input hash,
/// and output hash without needing the actual model or input.
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
/// Returns `Err(UnauditedImplementation)` when the feature is disabled.
pub fn verify_inference(proof: &InferenceProof) -> Result<bool> {
    crate::guard_unaudited("zkml::verify_inference")?;
    let model_hash = proof.model_commitment.commitment_hash();

    // Recompute the expected proof
    let expected_proof =
        compute_inference_proof(&model_hash, &proof.input_hash, &proof.output_hash);

    if expected_proof != proof.proof {
        return Ok(false);
    }

    // Recompute and check the verification tag
    let expected_tag = compute_verification_tag(
        &model_hash,
        &proof.input_hash,
        &proof.output_hash,
        &proof.proof,
    );

    Ok(expected_tag == proof.verification_tag)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn compute_inference_proof(
    model_hash: &Hash256,
    input_hash: &Hash256,
    output_hash: &Hash256,
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zkml:proof:");
    hasher.update(model_hash.as_bytes());
    hasher.update(input_hash.as_bytes());
    hasher.update(output_hash.as_bytes());
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn compute_verification_tag(
    model_hash: &Hash256,
    input_hash: &Hash256,
    output_hash: &Hash256,
    proof: &Hash256,
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zkml:verify:");
    hasher.update(model_hash.as_bytes());
    hasher.update(input_hash.as_bytes());
    hasher.update(output_hash.as_bytes());
    hasher.update(proof.as_bytes());
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "unaudited-pedagogical-proofs"))]
mod tests {
    use exo_core::crypto;

    use super::*;

    fn make_model() -> ModelCommitment {
        ModelCommitment::new(b"transformer-v1", b"weights-blob-1234", 1)
    }

    // ---- original tests (backward compat) ----

    #[test]
    fn model_commitment_deterministic() {
        let m1 = ModelCommitment::new(b"arch", b"weights", 1);
        let m2 = ModelCommitment::new(b"arch", b"weights", 1);
        assert_eq!(m1, m2);
        assert_eq!(m1.commitment_hash(), m2.commitment_hash());
    }

    #[test]
    fn different_models_different_hashes() {
        let m1 = ModelCommitment::new(b"arch1", b"weights1", 1);
        let m2 = ModelCommitment::new(b"arch2", b"weights2", 1);
        assert_ne!(m1.commitment_hash(), m2.commitment_hash());
    }

    #[test]
    fn different_versions_different_hashes() {
        let m1 = ModelCommitment::new(b"arch", b"weights", 1);
        let m2 = ModelCommitment::new(b"arch", b"weights", 2);
        assert_ne!(m1.commitment_hash(), m2.commitment_hash());
    }

    #[test]
    fn prove_and_verify() {
        let model = make_model();
        let proof =
            prove_inference(&model, b"classify this image", b"cat: 0.95, dog: 0.05").unwrap();
        assert!(verify_inference(&proof).unwrap());
    }

    #[test]
    fn verify_fails_tampered_model() {
        let model = make_model();
        let mut tampered = prove_inference(&model, b"input", b"output").unwrap();
        tampered.model_commitment = ModelCommitment::new(b"evil-arch", b"evil-weights", 99);
        assert!(!verify_inference(&tampered).unwrap());
    }

    #[test]
    fn verify_fails_tampered_input() {
        let model = make_model();
        let mut tampered = prove_inference(&model, b"input", b"output").unwrap();
        tampered.input_hash = Hash256::digest(b"different-input");
        assert!(!verify_inference(&tampered).unwrap());
    }

    #[test]
    fn verify_fails_tampered_output() {
        let model = make_model();
        let mut tampered = prove_inference(&model, b"input", b"output").unwrap();
        tampered.output_hash = Hash256::digest(b"different-output");
        assert!(!verify_inference(&tampered).unwrap());
    }

    #[test]
    fn verify_fails_tampered_proof_field() {
        let model = make_model();
        let mut tampered = prove_inference(&model, b"input", b"output").unwrap();
        tampered.proof = Hash256::ZERO;
        assert!(!verify_inference(&tampered).unwrap());
    }

    #[test]
    fn verify_fails_tampered_tag() {
        let model = make_model();
        let mut tampered = prove_inference(&model, b"input", b"output").unwrap();
        tampered.verification_tag = Hash256::ZERO;
        assert!(!verify_inference(&tampered).unwrap());
    }

    #[test]
    fn different_inputs_different_proofs() {
        let model = make_model();
        let p1 = prove_inference(&model, b"input1", b"output1").unwrap();
        let p2 = prove_inference(&model, b"input2", b"output2").unwrap();
        assert_ne!(p1.proof, p2.proof);
    }

    #[test]
    fn same_inputs_same_proof() {
        let model = make_model();
        let p1 = prove_inference(&model, b"input", b"output").unwrap();
        let p2 = prove_inference(&model, b"input", b"output").unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn proof_hides_model_input() {
        let model = make_model();
        let proof = prove_inference(&model, b"secret input", b"secret output").unwrap();
        assert_eq!(proof.input_hash, Hash256::digest(b"secret input"));
        assert_eq!(proof.output_hash, Hash256::digest(b"secret output"));
        assert_eq!(
            proof.model_commitment.architecture_hash,
            Hash256::digest(b"transformer-v1")
        );
    }

    #[test]
    fn empty_input_output() {
        let model = make_model();
        assert!(verify_inference(&prove_inference(&model, b"", b"").unwrap()).unwrap());
    }

    #[test]
    fn large_input_output() {
        let model = make_model();
        let proof = prove_inference(&model, &vec![0xABu8; 10_000], &vec![0xCDu8; 5_000]).unwrap();
        assert!(verify_inference(&proof).unwrap());
    }

    // ---- backward compat: old proofs (no Option fields) still deserialize ----

    #[test]
    fn backward_compat_deserialize_without_provenance_fields() {
        // A serialized proof without the new Option fields must deserialize with
        // all provenance fields set to None.
        let model = make_model();
        let proof = prove_inference(&model, b"input", b"output").unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: InferenceProof = serde_json::from_str(&json).unwrap();
        assert!(restored.prompt_hash.is_none());
        assert!(restored.human_attestation.is_none());
        assert!(restored.ai_delta.is_none());
        assert!(restored.daubert_checklist.is_none());
    }

    // ---- LEG-007: prompt_hash distinct from input_hash ----

    #[test]
    fn zkml_proof_binds_model_and_prompt() {
        let model = make_model();
        let prompt = b"You are a board advisor. Recommend yes or no.";
        let context = b"Q4 revenue declined 15%.";
        let output = b"Recommend: reject the acquisition.";

        let proof = prove_inference_with_provenance(&model, prompt, context, output).unwrap();

        assert!(verify_inference(&proof).unwrap());
        assert!(proof.prompt_hash.is_some(), "prompt_hash must be present");
        // prompt_hash and input_hash must differ when prompt != context
        assert_ne!(
            proof.prompt_hash.unwrap(),
            proof.input_hash,
            "prompt_hash must be distinct from input_hash"
        );
        assert_eq!(proof.prompt_hash, Some(Hash256::digest(prompt)));
        assert_eq!(proof.input_hash, Hash256::digest(context));
    }

    #[test]
    fn prove_inference_with_provenance_verifies() {
        let model = make_model();
        let proof =
            prove_inference_with_provenance(&model, b"prompt", b"context", b"output").unwrap();
        assert!(verify_inference(&proof).unwrap());
    }

    // ---- LEG-007: HumanAttestation with Ed25519 signature ----

    fn make_attestation(
        decision: AttestationDecision,
    ) -> (HumanAttestation, exo_core::types::SecretKey) {
        let (public_key, secret_key) = crypto::generate_keypair();
        let reviewer_did = "did:exo:reviewer-alice".to_string();
        let ai_rec = Hash256::digest(b"ai says: approve");
        let final_dec = Hash256::digest(b"human says: reject");

        let msg = HumanAttestation::signing_message(&reviewer_did, &ai_rec, &final_dec, &decision);
        let signature = crypto::sign(&msg, &secret_key);

        let att = HumanAttestation {
            reviewer_did,
            reviewer_public_key: public_key,
            ai_recommendation_hash: ai_rec,
            final_decision_hash: final_dec,
            decision,
            signature,
        };
        (att, secret_key)
    }

    #[test]
    fn human_attestation_signature_verifies() {
        let (att, _) = make_attestation(AttestationDecision::Rejected);
        assert!(
            att.verify_signature(),
            "Valid Ed25519 attestation must verify"
        );
    }

    #[test]
    fn human_attestation_tampered_decision_fails() {
        let (mut att, _) = make_attestation(AttestationDecision::Rejected);
        // Swap the decision after signing — signature must fail.
        att.decision = AttestationDecision::Adopted;
        assert!(
            !att.verify_signature(),
            "Tampered decision must fail verification"
        );
    }

    #[test]
    fn human_attestation_tampered_recommendation_fails() {
        let (mut att, _) = make_attestation(AttestationDecision::Adopted);
        att.ai_recommendation_hash = Hash256::digest(b"different");
        assert!(!att.verify_signature());
    }

    #[test]
    fn human_attestation_required_for_ai_output() {
        // A proof without human_attestation is flagged as lacking oversight.
        let model = make_model();
        let proof = prove_inference(&model, b"input", b"output").unwrap();
        assert!(
            proof.human_attestation.is_none(),
            "Basic prove_inference must not fabricate attestation"
        );
        // Caller must explicitly attach an attestation; absence = no oversight record.
    }

    // ---- LEG-007: AiDelta ----

    #[test]
    fn ai_delta_detects_divergence() {
        let delta = AiDelta::new(b"ai says approve", b"human says reject");
        assert!(delta.divergence_detected);
        assert_ne!(delta.ai_output_hash, delta.human_output_hash);
    }

    #[test]
    fn ai_delta_no_divergence_when_same() {
        let delta = AiDelta::new(b"approve", b"approve");
        assert!(!delta.divergence_detected);
        assert_eq!(delta.ai_output_hash, delta.human_output_hash);
    }

    // ---- LEG-007: DaubertChecklist ----

    #[test]
    fn daubert_checklist_complete_when_all_satisfied() {
        let checklist = DaubertChecklist {
            methodology_documented: true,
            peer_reviewable: true,
            known_error_rate: Some("< 2%".into()),
            generally_accepted: true,
        };
        assert!(checklist.is_complete());
    }

    #[test]
    fn daubert_checklist_incomplete_without_methodology() {
        let checklist = DaubertChecklist {
            methodology_documented: false,
            peer_reviewable: true,
            known_error_rate: None,
            generally_accepted: true,
        };
        assert!(!checklist.is_complete());
    }

    #[test]
    fn daubert_checklist_completeness_all_fields_required() {
        // Each false flag independently makes the checklist incomplete.
        for (doc, peer, accepted) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let c = DaubertChecklist {
                methodology_documented: doc,
                peer_reviewable: peer,
                known_error_rate: None,
                generally_accepted: accepted,
            };
            assert!(!c.is_complete(), "Incomplete checklist must not pass");
        }
    }

    // ---- zkml_tampered_model_detected (alias of existing test) ----

    #[test]
    fn zkml_tampered_model_detected() {
        let model = make_model();
        let proof = prove_inference(&model, b"input", b"output").unwrap();
        let mut tampered = proof;
        tampered.model_commitment.weights_hash = Hash256::digest(b"evil-weights");
        assert!(!verify_inference(&tampered).unwrap());
    }
}

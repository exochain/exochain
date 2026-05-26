// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt};

use exo_core::{Did, Hash256, PublicKey, SecretKey, Signature, Timestamp, hash::hash_structured};
use serde::Serialize;
use thiserror::Error;

use crate::{
    did::{DidDocument, did_from_public_key},
    registry::DidRegistry,
    risk::{RiskAttestation, RiskContext, RiskLevel, assess_risk},
};

#[derive(Debug, Error)]
pub enum VerificationCeremonyError {
    #[error("Ceremony has expired")]
    Expired,
    #[error("Ceremony is already finalized")]
    AlreadyFinalized,
    #[error("Invalid signature proof")]
    InvalidSignature,
    #[error("signature proof message is not the canonical ceremony challenge")]
    SignatureChallengeMismatch,
    #[error("signature proof key resolves to {derived_did}, not target ceremony DID {target_did}")]
    SignatureKeyNotBoundToTargetDid { target_did: Did, derived_did: Did },
    #[error("signature proof DID derivation failed: {reason}")]
    SignatureDidDerivation { reason: String },
    #[error("unverified proof kind cannot be submitted directly: {kind}")]
    UnverifiedProofKind { kind: &'static str },
    #[error("target DID is not active in the supplied registry: {target_did}")]
    TargetDidNotActive { target_did: Did },
    #[error("registry returned DID document {document_did} for target DID {target_did}")]
    TargetDidDocumentMismatch { target_did: Did, document_did: Did },
    #[error("signature proof key is not declared by active target DID document: {target_did}")]
    SignatureKeyNotDeclaredByTarget { target_did: Did },
    #[error("Duplicate proof kind: {kind}")]
    DuplicateProofKind { kind: &'static str },
    #[error("Insufficient risk score to finalize: {score}")]
    InsufficientScore { score: u32 },
    #[error("Invalid attester DID: {0}")]
    InvalidAttesterDid(String),
    #[error("signature ceremony challenge encoding failed: {reason}")]
    SignatureChallengeEncoding { reason: String },
    #[error("verification ceremony evidence encoding failed: {reason}")]
    EvidenceEncoding { reason: String },
    #[error("risk attestation failed: {0}")]
    RiskAttestation(#[from] crate::error::IdentityError),
}

/// Domain tag for canonical verification ceremony evidence.
pub const VERIFICATION_CEREMONY_EVIDENCE_DOMAIN: &str =
    "exo.identity.verification_ceremony.evidence.v1";

const VERIFICATION_CEREMONY_EVIDENCE_SCHEMA_VERSION: u16 = 1;
const VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_DOMAIN: &str =
    "exo.identity.verification_ceremony.proof_material.v1";
const VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_SCHEMA_VERSION: u16 = 1;
pub const VERIFICATION_CEREMONY_SIGNATURE_CHALLENGE_DOMAIN: &str =
    "exo.identity.verification_ceremony.signature_challenge.v1";
const VERIFICATION_CEREMONY_SIGNATURE_CHALLENGE_SCHEMA_VERSION: u16 = 1;
pub const VERIFICATION_CEREMONY_EXPIRY_WINDOW_MS: u64 = 3_600_000;

#[derive(Clone, PartialEq, Eq)]
pub enum IdentityProof {
    Signature(Signature, PublicKey, Vec<u8>), // sig, pubkey, message
    Otp(String),
    WebAuthnAssertion(Vec<u8>),
    KycToken(String),
}

impl fmt::Debug for IdentityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature(signature, public_key, message) => f
                .debug_struct("Signature")
                .field("signature", signature)
                .field("public_key", public_key)
                .field("message", &"<redacted>")
                .field("message_len", &message.len())
                .finish(),
            Self::Otp(_) => f.debug_struct("Otp").field("token", &"<redacted>").finish(),
            Self::WebAuthnAssertion(assertion) => f
                .debug_struct("WebAuthnAssertion")
                .field("assertion", &"<redacted>")
                .field("assertion_len", &assertion.len())
                .finish(),
            Self::KycToken(_) => f
                .debug_struct("KycToken")
                .field("token", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerificationCeremony {
    target_did: Did,
    session_id: String,
    initiated_at: Timestamp,
    proofs: Vec<IdentityProof>,
    finalized: bool,
}

#[derive(Debug, Serialize)]
struct VerificationCeremonySignatureChallengePayload<'a> {
    domain: &'static str,
    schema_version: u16,
    target_did: &'a Did,
    session_id: &'a str,
    initiated_at: Timestamp,
}

#[derive(Debug, Serialize)]
struct VerificationCeremonyEvidencePayload {
    domain: &'static str,
    schema_version: u16,
    target_did: Did,
    session_id: String,
    initiated_at: Timestamp,
    proofs: Vec<VerificationProofEvidencePayload>,
}

#[derive(Debug, Serialize)]
struct VerificationProofEvidencePayload {
    index: u64,
    kind: &'static str,
    material_hash: Hash256,
}

#[derive(Serialize)]
struct SignatureProofMaterialPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    kind: &'static str,
    signature: &'a Signature,
    public_key: &'a PublicKey,
    message: &'a [u8],
}

#[derive(Serialize)]
struct OtpProofMaterialPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    kind: &'static str,
    token: &'a str,
}

#[derive(Serialize)]
struct WebAuthnProofMaterialPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    kind: &'static str,
    assertion: &'a [u8],
}

#[derive(Serialize)]
struct KycProofMaterialPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    kind: &'static str,
    token: &'a str,
}

impl VerificationCeremony {
    pub fn new(target_did: Did, session_id: String, initiated_at: Timestamp) -> Self {
        Self {
            target_did,
            session_id,
            initiated_at,
            proofs: Vec::new(),
            finalized: false,
        }
    }

    #[must_use]
    pub fn target_did(&self) -> &Did {
        &self.target_did
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn initiated_at(&self) -> Timestamp {
        self.initiated_at
    }

    #[must_use]
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    #[must_use]
    pub const fn is_finalized(&self) -> bool {
        self.finalized
    }

    pub fn signature_challenge(&self) -> Result<Vec<u8>, VerificationCeremonyError> {
        let payload = VerificationCeremonySignatureChallengePayload {
            domain: VERIFICATION_CEREMONY_SIGNATURE_CHALLENGE_DOMAIN,
            schema_version: VERIFICATION_CEREMONY_SIGNATURE_CHALLENGE_SCHEMA_VERSION,
            target_did: &self.target_did,
            session_id: &self.session_id,
            initiated_at: self.initiated_at,
        };
        let mut out = Vec::new();
        ciborium::ser::into_writer(&payload, &mut out).map_err(|e| {
            VerificationCeremonyError::SignatureChallengeEncoding {
                reason: e.to_string(),
            }
        })?;
        Ok(out)
    }

    pub fn submit_proof(
        &mut self,
        proof: IdentityProof,
        now: Timestamp,
    ) -> Result<(), VerificationCeremonyError> {
        let proof_kind = proof.kind();
        self.ensure_can_accept_proof(proof_kind, now)?;

        match &proof {
            IdentityProof::Signature(signature, public_key, message) => {
                self.validate_signature_proof(signature, public_key, message)?;
            }
            IdentityProof::Otp(_)
            | IdentityProof::WebAuthnAssertion(_)
            | IdentityProof::KycToken(_) => {
                return Err(VerificationCeremonyError::UnverifiedProofKind { kind: proof_kind });
            }
        }

        self.proofs.push(proof);
        Ok(())
    }

    fn ensure_can_accept_proof(
        &self,
        proof_kind: &'static str,
        now: Timestamp,
    ) -> Result<(), VerificationCeremonyError> {
        if self.finalized {
            return Err(VerificationCeremonyError::AlreadyFinalized);
        }
        if ceremony_is_expired(self.initiated_at, now) {
            return Err(VerificationCeremonyError::Expired);
        }

        if self
            .proofs
            .iter()
            .any(|existing| existing.kind() == proof_kind)
        {
            return Err(VerificationCeremonyError::DuplicateProofKind { kind: proof_kind });
        }

        Ok(())
    }

    fn validate_signature_proof(
        &self,
        signature: &Signature,
        public_key: &PublicKey,
        message: &[u8],
    ) -> Result<(), VerificationCeremonyError> {
        let expected_challenge = self.signature_challenge()?;
        if message != expected_challenge.as_slice() {
            return Err(VerificationCeremonyError::SignatureChallengeMismatch);
        }

        let derived_did = did_from_public_key(public_key).map_err(|e| {
            VerificationCeremonyError::SignatureDidDerivation {
                reason: e.to_string(),
            }
        })?;
        if derived_did != self.target_did {
            return Err(VerificationCeremonyError::SignatureKeyNotBoundToTargetDid {
                target_did: self.target_did.clone(),
                derived_did,
            });
        }

        if !exo_core::crypto::verify(message, signature, public_key) {
            return Err(VerificationCeremonyError::InvalidSignature);
        }

        Ok(())
    }

    pub fn calculate_risk_score(&self) -> u32 {
        let mut score: u32 = 0;
        // BTreeMap used as required
        let mut proof_weights: BTreeMap<&str, u32> = BTreeMap::new();
        proof_weights.insert("Signature", 1000);
        proof_weights.insert("Otp", 2000);
        proof_weights.insert("WebAuthnAssertion", 4000);
        proof_weights.insert("KycToken", 5000);

        let mut seen = std::collections::BTreeSet::new();
        for proof in &self.proofs {
            let proof_kind = proof.kind();
            if !seen.insert(proof_kind) {
                continue;
            }
            let s = proof_weights.get(proof_kind).copied().unwrap_or(0);
            score = score.saturating_add(s);
        }
        score
    }

    /// Finalize the ceremony and produce a **signed** [`RiskAttestation`].
    ///
    /// Closes GAP-004. The previous implementation returned a
    /// `RiskAttestation` with a zero-byte signature and a zero-byte
    /// evidence hash — structurally well-formed but cryptographically
    /// meaningless. Any downstream code that trusted the attestation
    /// would have accepted a forgery.
    ///
    /// The caller now MUST supply:
    /// - `attester_did`: the DID of the identity system issuing the
    ///   attestation (e.g. `did:exo:system` or a specific adjudicator).
    /// - `attester_key`: the secret key corresponding to the attester's
    ///   published public key. The produced attestation's signature is
    ///   verifiable with `risk::verify_attestation` against that pubkey.
    ///
    /// The evidence bytes over which the attestation's `evidence_hash`
    /// is computed are a domain-separated canonical CBOR summary of the
    /// submitted proofs in submission order. This binds the attestation to the
    /// exact proof set that produced the risk score.
    pub fn finalize<R: DidRegistry>(
        &mut self,
        registry: &R,
        now: Timestamp,
        attester_did: &Did,
        attester_key: &SecretKey,
    ) -> Result<RiskAttestation, VerificationCeremonyError> {
        if self.finalized {
            return Err(VerificationCeremonyError::AlreadyFinalized);
        }
        if ceremony_is_expired(self.initiated_at, now) {
            return Err(VerificationCeremonyError::Expired);
        }

        let target_document = registry.resolve(&self.target_did).ok_or_else(|| {
            VerificationCeremonyError::TargetDidNotActive {
                target_did: self.target_did.clone(),
            }
        })?;
        self.validate_active_target_document(target_document)?;

        let score = self.calculate_risk_score();
        if score < 1000 {
            return Err(VerificationCeremonyError::InsufficientScore { score });
        }

        // Reject an empty attester DID up front.
        if attester_did.as_str().is_empty() {
            return Err(VerificationCeremonyError::InvalidAttesterDid(
                "attester DID is empty".to_owned(),
            ));
        }

        let level = if score >= 5000 {
            RiskLevel::Critical
        } else if score >= 4000 {
            RiskLevel::High
        } else if score >= 3000 {
            RiskLevel::Medium
        } else if score >= 2000 {
            RiskLevel::Low
        } else {
            RiskLevel::Minimal
        };

        // Build canonical CBOR evidence bytes summarizing the proof set.
        // The attestation's evidence_hash will be blake3 over these bytes
        // (computed inside risk::assess_risk).
        let evidence = self.canonical_evidence()?;

        // Validity: 1 year from `now`, matching the previous behavior.
        const ONE_YEAR_MS: u64 = 31_536_000_000;

        let ctx = RiskContext {
            attester_did: attester_did.clone(),
            evidence,
            now,
            validity_ms: ONE_YEAR_MS,
            level,
        };

        let attestation = assess_risk(&self.target_did, &ctx, attester_key)?;

        // Only flip the finalized flag once the real attestation has been
        // produced successfully.
        self.finalized = true;

        // Sanity: the returned attestation must verify under the public
        // key corresponding to the supplied secret key. We don't have the
        // pubkey here, so we instead assert that the signature is not the
        // zero-byte sentinel — closing the exact shape of the old bug.
        debug_assert!(
            !matches!(attestation.signature, Signature::Ed25519(bytes) if bytes.iter().all(|b| *b == 0)),
            "assess_risk produced a zero signature"
        );
        debug_assert!(
            attestation.evidence_hash != [0u8; 32],
            "assess_risk produced a zero evidence_hash"
        );

        Ok(attestation)
    }

    fn validate_active_target_document(
        &self,
        target_document: &DidDocument,
    ) -> Result<(), VerificationCeremonyError> {
        if target_document.id != self.target_did {
            return Err(VerificationCeremonyError::TargetDidDocumentMismatch {
                target_did: self.target_did.clone(),
                document_did: target_document.id.clone(),
            });
        }
        if target_document.revoked {
            return Err(VerificationCeremonyError::TargetDidNotActive {
                target_did: self.target_did.clone(),
            });
        }

        for proof in &self.proofs {
            if let IdentityProof::Signature(_, public_key, _) = proof {
                let declared = target_document
                    .public_keys
                    .iter()
                    .any(|declared_key| declared_key == public_key);
                if !declared {
                    return Err(VerificationCeremonyError::SignatureKeyNotDeclaredByTarget {
                        target_did: self.target_did.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Canonical CBOR serialization of this ceremony's proof set, used
    /// as input to the attestation's `evidence_hash`.
    ///
    /// The evidence payload binds the exact target DID, session ID, full
    /// initiation HLC timestamp, proof ordering, proof kind, and per-proof
    /// canonical material hash. Raw OTP, KYC, and WebAuthn material does not
    /// appear directly in the evidence bytes.
    fn canonical_evidence(&self) -> Result<Vec<u8>, VerificationCeremonyError> {
        let payload = self.evidence_payload()?;
        let mut out = Vec::new();
        ciborium::ser::into_writer(&payload, &mut out).map_err(|e| {
            VerificationCeremonyError::EvidenceEncoding {
                reason: e.to_string(),
            }
        })?;
        Ok(out)
    }

    fn evidence_payload(
        &self,
    ) -> Result<VerificationCeremonyEvidencePayload, VerificationCeremonyError> {
        let mut proofs = Vec::with_capacity(self.proofs.len());
        for (idx, proof) in self.proofs.iter().enumerate() {
            let index =
                u64::try_from(idx).map_err(|e| VerificationCeremonyError::EvidenceEncoding {
                    reason: format!("proof index does not fit u64: {e}"),
                })?;
            proofs.push(VerificationProofEvidencePayload {
                index,
                kind: proof.kind(),
                material_hash: proof.material_hash()?,
            });
        }

        Ok(VerificationCeremonyEvidencePayload {
            domain: VERIFICATION_CEREMONY_EVIDENCE_DOMAIN,
            schema_version: VERIFICATION_CEREMONY_EVIDENCE_SCHEMA_VERSION,
            target_did: self.target_did.clone(),
            session_id: self.session_id.clone(),
            initiated_at: self.initiated_at,
            proofs,
        })
    }
}

fn ceremony_is_expired(initiated_at: Timestamp, now: Timestamp) -> bool {
    let Some(expires_at) = initiated_at
        .physical_ms
        .checked_add(VERIFICATION_CEREMONY_EXPIRY_WINDOW_MS)
    else {
        return true;
    };
    now.physical_ms > expires_at
}

impl IdentityProof {
    fn kind(&self) -> &'static str {
        match self {
            Self::Signature(..) => "Signature",
            Self::Otp(_) => "Otp",
            Self::WebAuthnAssertion(_) => "WebAuthnAssertion",
            Self::KycToken(_) => "KycToken",
        }
    }

    fn material_hash(&self) -> Result<Hash256, VerificationCeremonyError> {
        let hash_result = match self {
            Self::Signature(signature, public_key, message) => {
                hash_structured(&SignatureProofMaterialPayload {
                    domain: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_DOMAIN,
                    schema_version: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_SCHEMA_VERSION,
                    kind: self.kind(),
                    signature,
                    public_key,
                    message,
                })
            }
            Self::Otp(token) => hash_structured(&OtpProofMaterialPayload {
                domain: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_DOMAIN,
                schema_version: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_SCHEMA_VERSION,
                kind: self.kind(),
                token,
            }),
            Self::WebAuthnAssertion(assertion) => hash_structured(&WebAuthnProofMaterialPayload {
                domain: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_DOMAIN,
                schema_version: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_SCHEMA_VERSION,
                kind: self.kind(),
                assertion,
            }),
            Self::KycToken(token) => hash_structured(&KycProofMaterialPayload {
                domain: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_DOMAIN,
                schema_version: VERIFICATION_CEREMONY_PROOF_MATERIAL_HASH_SCHEMA_VERSION,
                kind: self.kind(),
                token,
            }),
        };

        hash_result.map_err(|e| VerificationCeremonyError::EvidenceEncoding {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use exo_core::crypto::{generate_keypair, sign};

    use super::*;
    use crate::did::did_from_public_key;

    fn make_signature_ceremony(
        session_id: &str,
        initiated_at: Timestamp,
    ) -> (VerificationCeremony, PublicKey, SecretKey) {
        let (public_key, secret_key) = generate_keypair();
        let did = did_from_public_key(&public_key).unwrap();
        (
            VerificationCeremony::new(did, session_id.to_string(), initiated_at),
            public_key,
            secret_key,
        )
    }

    fn signature_proof_for(
        ceremony: &VerificationCeremony,
        public_key: PublicKey,
        secret_key: &SecretKey,
    ) -> IdentityProof {
        let message = ceremony.signature_challenge().unwrap();
        let signature = sign(&message, secret_key);
        IdentityProof::Signature(signature, public_key, message)
    }

    fn submit_valid_signature(
        ceremony: &mut VerificationCeremony,
        public_key: PublicKey,
        secret_key: &SecretKey,
        now: Timestamp,
    ) {
        let proof = signature_proof_for(ceremony, public_key, secret_key);
        ceremony.submit_proof(proof, now).unwrap();
    }

    fn active_registry_for_key(
        ceremony: &VerificationCeremony,
        public_key: PublicKey,
    ) -> crate::registry::LocalDidRegistry {
        let doc = crate::did::DidDocument {
            id: ceremony.target_did().clone(),
            public_keys: vec![public_key],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::new(1000, 0),
            updated: Timestamp::new(1000, 0),
            revoked: false,
        };
        let mut registry = crate::registry::LocalDidRegistry::new();
        crate::registry::DidRegistry::register(&mut registry, doc).unwrap();
        registry
    }

    #[test]
    fn submit_proof_rejects_signature_over_attacker_chosen_message() {
        let (public_key, secret_key) = generate_keypair();
        let did = did_from_public_key(&public_key).unwrap();
        let mut ceremony = VerificationCeremony::new(
            did,
            "sess-forged-message".to_string(),
            Timestamp::new(1000, 0),
        );
        let message = b"attacker-selected-message".to_vec();
        let signature = sign(&message, &secret_key);

        let result = ceremony.submit_proof(
            IdentityProof::Signature(signature, public_key, message),
            Timestamp::new(1010, 0),
        );

        assert!(
            result.is_err(),
            "signature proofs must be bound to the ceremony challenge, not caller-chosen bytes"
        );
        assert!(ceremony.proofs.is_empty());
    }

    #[test]
    fn submit_proof_rejects_signature_key_unbound_to_target_did() {
        let (target_public_key, _target_secret_key) = generate_keypair();
        let target_did = did_from_public_key(&target_public_key).unwrap();
        let mut ceremony = VerificationCeremony::new(
            target_did,
            "sess-wrong-key".to_string(),
            Timestamp::new(1000, 0),
        );
        let (attacker_public_key, attacker_secret_key) = generate_keypair();
        let message = ceremony.signature_challenge().unwrap();
        let signature = sign(&message, &attacker_secret_key);

        let result = ceremony.submit_proof(
            IdentityProof::Signature(signature, attacker_public_key, message),
            Timestamp::new(1010, 0),
        );

        assert!(
            result.is_err(),
            "signature proofs must prove control of a key bound to target_did"
        );
        assert!(matches!(
            result.unwrap_err(),
            VerificationCeremonyError::SignatureKeyNotBoundToTargetDid { .. }
        ));
        assert!(ceremony.proofs.is_empty());
    }

    #[test]
    fn submit_proof_rejects_unverified_external_proof_kinds() {
        for proof in [
            IdentityProof::Otp("123456".to_string()),
            IdentityProof::WebAuthnAssertion(vec![1, 2, 3]),
            IdentityProof::KycToken("kyc-token".to_string()),
        ] {
            let did = Did::new("did:exo:unverified-proof-kind").unwrap();
            let mut ceremony = VerificationCeremony::new(
                did,
                format!("sess-{}", proof.kind()),
                Timestamp::new(1000, 0),
            );

            let result = ceremony.submit_proof(proof, Timestamp::new(1010, 0));

            assert!(
                result.is_err(),
                "unverified external proof material must fail closed"
            );
            assert!(ceremony.proofs.is_empty());
        }
    }

    #[test]
    fn verification_ceremony_proof_vector_is_not_publicly_mutable() {
        let source = include_str!("verification.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        for forbidden_public_field in [
            "pub target_did:",
            "pub session_id:",
            "pub initiated_at:",
            "pub proofs:",
            "pub finalized:",
        ] {
            assert!(
                !production.contains(forbidden_public_field),
                "ceremony state must not be publicly mutable: {forbidden_public_field}"
            );
        }
    }

    #[test]
    fn signature_challenge_binds_target_session_and_hlc() {
        let (ceremony, _public_key, _secret_key) =
            make_signature_ceremony("sess-bound", Timestamp::new(1000, 7));
        let same = VerificationCeremony::new(
            ceremony.target_did().clone(),
            "sess-bound".to_string(),
            Timestamp::new(1000, 7),
        );
        let different_session = VerificationCeremony::new(
            ceremony.target_did().clone(),
            "sess-other".to_string(),
            Timestamp::new(1000, 7),
        );
        let different_hlc = VerificationCeremony::new(
            ceremony.target_did().clone(),
            "sess-bound".to_string(),
            Timestamp::new(1000, 8),
        );
        let (other_ceremony, _other_public_key, _other_secret_key) =
            make_signature_ceremony("sess-bound", Timestamp::new(1000, 7));

        let challenge = ceremony.signature_challenge().unwrap();

        assert_eq!(challenge, same.signature_challenge().unwrap());
        assert_ne!(challenge, different_session.signature_challenge().unwrap());
        assert_ne!(challenge, different_hlc.signature_challenge().unwrap());
        assert_ne!(challenge, other_ceremony.signature_challenge().unwrap());
    }

    #[test]
    fn finalize_rejects_signature_key_absent_from_active_registry_document() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess-undeclared-key", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1010, 0),
        );
        let (wrong_registry_key, _wrong_secret_key) = generate_keypair();
        let registry = active_registry_for_key(&ceremony, wrong_registry_key);

        let (_attester_public_key, attester_secret_key) = generate_keypair();
        let attester_did = Did::new("did:exo:att-undeclared-key").unwrap();
        let err = ceremony
            .finalize(
                &registry,
                Timestamp::new(1020, 0),
                &attester_did,
                &attester_secret_key,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            VerificationCeremonyError::SignatureKeyNotDeclaredByTarget { .. }
        ));
        assert!(!ceremony.is_finalized());
    }

    #[test]
    fn test_ceremony_lifecycle() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess1", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1010, 0),
        );
        let (att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-lifecycle").unwrap();
        let registry = active_registry_for_key(&ceremony, public_key);
        let attestation = ceremony
            .finalize(&registry, Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap();

        assert_eq!(attestation.level, RiskLevel::Minimal);
        assert!(ceremony.is_finalized());
        // GAP-004: signature must verify, evidence_hash must be non-zero.
        assert!(crate::risk::verify_attestation(&attestation, &att_pk));
        assert_ne!(attestation.evidence_hash, [0u8; 32]);
        assert!(
            !matches!(attestation.signature, Signature::Ed25519(b) if b.iter().all(|x| *x == 0))
        );
    }

    #[test]
    fn test_finalize_without_sufficient_proofs_fails() {
        let (public_key, _secret_key) = generate_keypair();
        let did = did_from_public_key(&public_key).unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess2".to_string(), Timestamp::new(1000, 0));

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-bob").unwrap();
        let registry = active_registry_for_key(&ceremony, public_key);
        let err = ceremony
            .finalize(&registry, Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationCeremonyError::InsufficientScore { .. }
        ));
    }

    #[test]
    fn test_risk_score_calculation() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess3", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1010, 0),
        );
        assert_eq!(ceremony.calculate_risk_score(), 1000);

        ceremony
            .proofs
            .push(IdentityProof::Otp("123456".to_string()));
        assert_eq!(ceremony.calculate_risk_score(), 3000); // 1000 + 2000
    }

    #[test]
    fn identity_proof_debug_redacts_otp_and_kyc_secrets() {
        let otp = IdentityProof::Otp("super-secret-otp".to_string());
        let kyc = IdentityProof::KycToken("super-secret-kyc".to_string());

        let otp_debug = format!("{otp:?}");
        let kyc_debug = format!("{kyc:?}");

        assert!(
            !otp_debug.contains("super-secret-otp"),
            "OTP Debug output must redact the token"
        );
        assert!(
            !kyc_debug.contains("super-secret-kyc"),
            "KYC Debug output must redact the token"
        );
        assert!(otp_debug.contains("<redacted>"));
        assert!(kyc_debug.contains("<redacted>"));
    }

    #[test]
    fn identity_proof_debug_redacts_signature_message_and_webauthn_assertion() {
        let (public_key, secret_key) = generate_keypair();
        let message = b"super-secret-signature-message".to_vec();
        let signature = sign(&message, &secret_key);
        let signature_proof = IdentityProof::Signature(signature, public_key, message);
        let webauthn = IdentityProof::WebAuthnAssertion(b"super-secret-webauthn".to_vec());

        let signature_debug = format!("{signature_proof:?}");
        let webauthn_debug = format!("{webauthn:?}");

        assert!(
            !signature_debug.contains("super-secret-signature-message"),
            "Signature proof Debug output must redact the signed message"
        );
        assert!(
            !webauthn_debug.contains("super-secret-webauthn"),
            "WebAuthn proof Debug output must redact the assertion bytes"
        );
        assert!(signature_debug.contains("<redacted>"));
        assert!(signature_debug.contains("message_len"));
        assert!(webauthn_debug.contains("<redacted>"));
        assert!(webauthn_debug.contains("assertion_len"));
    }

    #[test]
    fn verification_ceremony_debug_uses_redacted_identity_proofs() {
        let did = match Did::new("did:exo:redacted-proof") {
            Ok(did) => did,
            Err(err) => panic!("test DID must be valid: {err}"),
        };
        let mut ceremony =
            VerificationCeremony::new(did, "sess-redacted".to_string(), Timestamp::new(1000, 0));
        ceremony
            .proofs
            .push(IdentityProof::KycToken("ceremony-secret-kyc".to_string()));

        let debug = format!("{ceremony:?}");

        assert!(
            !debug.contains("ceremony-secret-kyc"),
            "VerificationCeremony Debug output must not leak nested proof secrets"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn duplicate_proof_kind_does_not_inflate_risk_score() {
        let did = Did::new("did:exo:duplicate-score").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-dup-score".to_string(), Timestamp::new(1000, 0));

        ceremony
            .proofs
            .push(IdentityProof::Otp("111111".to_string()));
        ceremony
            .proofs
            .push(IdentityProof::Otp("222222".to_string()));

        assert_eq!(
            ceremony.calculate_risk_score(),
            2000,
            "duplicate proof kinds must count once even if inserted directly"
        );
    }

    #[test]
    fn submit_proof_rejects_duplicate_proof_kind() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess-dup-submit", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1001, 0),
        );
        let duplicate = signature_proof_for(&ceremony, public_key, &secret_key);
        let err = ceremony
            .submit_proof(duplicate, Timestamp::new(1002, 0))
            .unwrap_err();

        assert!(matches!(
            err,
            VerificationCeremonyError::DuplicateProofKind { kind: "Signature" }
        ));
        assert_eq!(ceremony.proof_count(), 1);
        assert_eq!(ceremony.calculate_risk_score(), 1000);
    }

    #[test]
    fn test_expired_ceremony_fails() {
        let did = Did::new("did:exo:dave").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess4".to_string(), Timestamp::new(1000, 0));

        let err = ceremony
            .submit_proof(
                IdentityProof::Otp("123".into()),
                Timestamp::new(4_000_000, 0),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::Expired));
    }

    #[test]
    fn ceremony_expiry_overflow_fails_closed_without_panic() {
        let did = Did::new("did:exo:expiry-overflow").unwrap();
        let mut ceremony = VerificationCeremony::new(
            did.clone(),
            "sess-expiry-overflow".to_string(),
            Timestamp::new(u64::MAX, 0),
        );

        let submit_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ceremony.submit_proof(
                IdentityProof::Otp("123456".to_string()),
                Timestamp::new(u64::MAX, 0),
            )
        }));
        assert!(
            matches!(submit_result, Ok(Err(VerificationCeremonyError::Expired))),
            "expiry overflow during submit must fail closed, got {submit_result:?}"
        );
        assert!(ceremony.proofs.is_empty());

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-expiry-overflow").unwrap();
        let registry = LocalDidRegistry::new();
        let finalize_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ceremony.finalize(
                &registry,
                Timestamp::new(u64::MAX, 0),
                &attester_did,
                &att_sk,
            )
        }));
        assert!(
            matches!(finalize_result, Ok(Err(VerificationCeremonyError::Expired))),
            "expiry overflow during finalize must fail closed, got {finalize_result:?}"
        );
        assert!(!ceremony.is_finalized());
    }

    #[test]
    fn test_invalid_signature_proof_rejected() {
        let (mut ceremony, public_key, _secret_key) =
            make_signature_ceremony("sess5", Timestamp::new(1000, 0));
        let (_, sk2) = generate_keypair();
        let msg = ceremony.signature_challenge().unwrap();
        let bad_sig = sign(&msg, &sk2);

        let err = ceremony
            .submit_proof(
                IdentityProof::Signature(bad_sig, public_key, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::InvalidSignature));
    }

    // Integration-style tests combining the registry and verification flow
    use crate::{
        did::DidDocument,
        registry::{DidRegistry, LocalDidRegistry, revocation_proof_payload},
    };

    fn make_did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).expect("valid did")
    }

    fn make_doc(did: Did, pk: exo_core::PublicKey) -> DidDocument {
        DidDocument {
            id: did,
            public_keys: vec![pk],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::new(1000, 0),
            updated: Timestamp::new(1000, 0),
            revoked: false,
        }
    }

    #[test]
    fn test_integration_full_verification_flow() {
        let (pk, sk) = generate_keypair();
        let did = did_from_public_key(&pk).unwrap();
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let mut ceremony = VerificationCeremony::new(
            did.clone(),
            "session_int_1".to_string(),
            Timestamp::new(1000, 0),
        );

        // 1. Submit signature
        let msg = ceremony.signature_challenge().unwrap();
        let sig = sign(&msg, &sk);
        ceremony
            .submit_proof(
                IdentityProof::Signature(sig, pk, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        // 2. Finalize
        let (att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-int1").unwrap();
        let attestation = ceremony
            .finalize(&reg, Timestamp::new(1030, 0), &attester_did, &att_sk)
            .unwrap();
        assert_eq!(attestation.level, RiskLevel::Minimal);
        assert!(crate::risk::verify_attestation(&attestation, &att_pk));

        // Check that the target DID matches what's in the registry
        let resolved = reg.resolve(&attestation.subject_did).unwrap();
        assert_eq!(resolved.id, did);
    }

    #[test]
    fn test_integration_revoked_did_verification_fails() {
        // Finalization must resolve the target DID from an active registry.
        let (pk, sk) = generate_keypair();
        let did = did_from_public_key(&pk).unwrap();
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        // Revoke the DID
        let payload = revocation_proof_payload(&did).unwrap();
        let proof = crate::did::RevocationProof {
            did: did.clone(),
            signature: sign(&payload, &sk),
        };
        reg.revoke(&did, &proof).unwrap();

        let resolved = reg.resolve(&did);
        assert!(resolved.is_none());

        // Since DID is revoked, even a key-bound ceremony proof must not finalize.
        let mut ceremony =
            VerificationCeremony::new(did, "session_int_2".to_string(), Timestamp::new(1000, 0));
        let msg = ceremony.signature_challenge().unwrap();
        let sig = sign(&msg, &sk);
        ceremony
            .submit_proof(
                IdentityProof::Signature(sig, pk, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-int2").unwrap();
        let err = ceremony
            .finalize(&reg, Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationCeremonyError::TargetDidNotActive { .. }
        ));
    }

    #[test]
    fn test_integration_insufficient_proofs() {
        let (pk, _) = generate_keypair();
        let did = make_did("integration3");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let mut ceremony =
            VerificationCeremony::new(did, "session_int_3".to_string(), Timestamp::new(1000, 0));
        // No proofs submitted
        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-int3").unwrap();
        let err = ceremony
            .finalize(&reg, Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationCeremonyError::InsufficientScore { score: 0 }
        ));
    }

    // Covers submit_proof() returning AlreadyFinalized (line 56) when ceremony has been finalized.
    #[test]
    fn test_submit_proof_after_finalize_returns_already_finalized() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess-finalized-submit", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1010, 0),
        );

        let (_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-finalized-submit").unwrap();
        let registry = active_registry_for_key(&ceremony, public_key);
        let _ = ceremony
            .finalize(&registry, Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap();
        assert!(ceremony.is_finalized());

        let err = ceremony
            .submit_proof(
                IdentityProof::Otp("111".to_string()),
                Timestamp::new(1030, 0),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::AlreadyFinalized));
        // Proof must NOT have been appended.
        assert_eq!(ceremony.proof_count(), 1);
    }

    // Covers finalize() returning AlreadyFinalized (line 124) on a second finalize call.
    #[test]
    fn test_double_finalize_returns_already_finalized() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess-double-final", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1010, 0),
        );

        let (_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-double-final").unwrap();
        let registry = active_registry_for_key(&ceremony, public_key);
        let _first = ceremony
            .finalize(&registry, Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap();
        let err = ceremony
            .finalize(&registry, Timestamp::new(1030, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::AlreadyFinalized));
    }

    // Covers finalize() returning Expired (line 127) when `now` is past the one-hour window.
    #[test]
    fn test_finalize_expired_returns_expired() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess-final-expired", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1010, 0),
        );

        let (_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-fin-exp").unwrap();
        let registry = active_registry_for_key(&ceremony, public_key);
        // now > initiated_at + 3_600_000 ms
        let err = ceremony
            .finalize(
                &registry,
                Timestamp::new(5_000_000, 0),
                &attester_did,
                &att_sk,
            )
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::Expired));
        // Still not finalized.
        assert!(!ceremony.is_finalized());
    }

    // Covers the empty-attester-DID rejection path (lines 137-139) in finalize().
    #[test]
    fn test_finalize_empty_attester_did_rejected() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess-empty-att", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1010, 0),
        );

        let (_pk, att_sk) = generate_keypair();
        let registry = active_registry_for_key(&ceremony, public_key);
        // `Did::new("")` legitimately rejects — so the only way to reach the
        // empty-attester branch in `finalize()` is to deserialize a malformed
        // Did from serde. That mirrors the real attack surface (malformed
        // network input / tampered storage) that the branch is meant to catch.
        let empty_did: Did =
            serde_json::from_str("\"\"").expect("serde_json accepts empty string for Did wrapper");

        let err = ceremony
            .finalize(&registry, Timestamp::new(1020, 0), &empty_did, &att_sk)
            .unwrap_err();
        match err {
            VerificationCeremonyError::InvalidAttesterDid(msg) => {
                assert!(msg.contains("empty"));
            }
            other => panic!("expected InvalidAttesterDid, got {other:?}"),
        }
        // Ceremony must not have been flipped to finalized when validation failed.
        assert!(!ceremony.is_finalized());
    }

    // Covers calculate_risk_score() KycToken arm (line 90) in isolation with a known weight.
    #[test]
    fn test_risk_score_kyc_token_weight() {
        let did = Did::new("did:exo:score-kyc").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-kyc".to_string(), Timestamp::new(1000, 0));
        ceremony.proofs.push(IdentityProof::KycToken("kyc".into()));
        // KYC weight alone is 5000.
        assert_eq!(ceremony.calculate_risk_score(), 5000);
    }

    // Covers RiskLevel::Low branch (line 149): 2000 <= score < 3000.
    #[test]
    fn test_finalize_risk_level_low() {
        let did = Did::new("did:exo:level-low").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-low".to_string(), Timestamp::new(1000, 0));
        ceremony.proofs.push(IdentityProof::Otp("otp".into()));
        assert_eq!(ceremony.calculate_risk_score(), 2000);

        let (att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-low").unwrap();
        let (registry_key, _registry_secret) = generate_keypair();
        let registry = active_registry_for_key(&ceremony, registry_key);
        let attestation = ceremony
            .finalize(&registry, Timestamp::new(1010, 0), &attester_did, &att_sk)
            .unwrap();
        assert_eq!(attestation.level, RiskLevel::Low);
        assert!(crate::risk::verify_attestation(&attestation, &att_pk));
    }

    // Covers RiskLevel::Medium branch (line 147): 3000 <= score < 4000.
    #[test]
    fn test_finalize_risk_level_medium() {
        let (mut ceremony, public_key, secret_key) =
            make_signature_ceremony("sess-med", Timestamp::new(1000, 0));
        submit_valid_signature(
            &mut ceremony,
            public_key,
            &secret_key,
            Timestamp::new(1001, 0),
        );
        ceremony.proofs.push(IdentityProof::Otp("otp".into()));
        // 1000 (sig) + 2000 (otp) = 3000 -> Medium
        assert_eq!(ceremony.calculate_risk_score(), 3000);

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-med").unwrap();
        let registry = active_registry_for_key(&ceremony, public_key);
        let attestation = ceremony
            .finalize(&registry, Timestamp::new(1010, 0), &attester_did, &att_sk)
            .unwrap();
        assert_eq!(attestation.level, RiskLevel::Medium);
    }

    // Covers RiskLevel::High branch (line 145): 4000 <= score < 5000.
    #[test]
    fn test_finalize_risk_level_high() {
        let did = Did::new("did:exo:level-high").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-high".to_string(), Timestamp::new(1000, 0));
        ceremony
            .proofs
            .push(IdentityProof::WebAuthnAssertion(vec![9, 9, 9]));
        // WebAuthn alone = 4000 -> High
        assert_eq!(ceremony.calculate_risk_score(), 4000);

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-high").unwrap();
        let (registry_key, _registry_secret) = generate_keypair();
        let registry = active_registry_for_key(&ceremony, registry_key);
        let attestation = ceremony
            .finalize(&registry, Timestamp::new(1010, 0), &attester_did, &att_sk)
            .unwrap();
        assert_eq!(attestation.level, RiskLevel::High);
    }

    // Covers canonical_evidence() OTP arm (lines 230-234) and KycToken arm (lines 242-246)
    // by finalizing ceremonies whose evidence hashes must change when OTP/KYC material changes.
    #[test]
    fn test_canonical_evidence_otp_and_kyc_branches_are_deterministic() {
        fn run(otp: &str, kyc: &str) -> [u8; 32] {
            let did = Did::new("did:exo:canon-otp-kyc").unwrap();
            let mut ceremony =
                VerificationCeremony::new(did, "sess-canon".to_string(), Timestamp::new(1000, 0));
            ceremony.proofs.push(IdentityProof::Otp(otp.to_string()));
            ceremony
                .proofs
                .push(IdentityProof::KycToken(kyc.to_string()));
            let (_pk, sk) = generate_keypair();
            let attester = Did::new("did:exo:att-canon").unwrap();
            let (registry_key, _registry_secret) = generate_keypair();
            let registry = active_registry_for_key(&ceremony, registry_key);
            let att = ceremony
                .finalize(&registry, Timestamp::new(1010, 0), &attester, &sk)
                .unwrap();
            att.evidence_hash
        }

        let a = run("111111", "kyc-A");
        let b = run("111111", "kyc-A");
        let c_diff_otp = run("222222", "kyc-A");
        let d_diff_kyc = run("111111", "kyc-B");

        // Deterministic for identical inputs.
        assert_eq!(a, b);
        // Different OTP must change the evidence hash -> proves OTP arm is hashed.
        assert_ne!(a, c_diff_otp);
        // Different KYC token must change the evidence hash -> proves KycToken arm is hashed.
        assert_ne!(a, d_diff_kyc);
        // Non-zero sanity (also asserted by debug_assert in finalize).
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn canonical_evidence_binds_initiated_at_hlc_logical_counter() {
        fn evidence_hash_for(initiated_at: Timestamp) -> [u8; 32] {
            let did = Did::new("did:exo:canon-hlc-logical").unwrap();
            let mut ceremony =
                VerificationCeremony::new(did, "sess-canon-hlc".to_string(), initiated_at);
            ceremony
                .proofs
                .push(IdentityProof::KycToken("kyc-logical".to_string()));

            let (_pk, sk) = generate_keypair();
            let attester = Did::new("did:exo:att-canon-hlc").unwrap();
            let (registry_key, _registry_secret) = generate_keypair();
            let registry = active_registry_for_key(&ceremony, registry_key);
            ceremony
                .finalize(&registry, Timestamp::new(2010, 0), &attester, &sk)
                .unwrap()
                .evidence_hash
        }

        let logical_zero = evidence_hash_for(Timestamp::new(1000, 0));
        let logical_one = evidence_hash_for(Timestamp::new(1000, 1));

        assert_ne!(
            logical_zero, logical_one,
            "verification ceremony evidence must bind the full HLC, not only physical_ms"
        );
    }

    #[test]
    fn canonical_evidence_payload_is_domain_separated_cbor() {
        let did = Did::new("did:exo:canon-cbor").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-cbor".to_string(), Timestamp::new(1000, 2));
        ceremony
            .proofs
            .push(IdentityProof::Otp("otp-cbor".to_string()));

        let evidence = ceremony.canonical_evidence().unwrap();

        assert!(
            !evidence.starts_with(b"exo.verification.ceremony.v1\n"),
            "verification ceremony evidence must not use the legacy line format"
        );
        assert!(
            evidence
                .windows(b"exo.identity.verification_ceremony.evidence.v1".len())
                .any(|window| window == b"exo.identity.verification_ceremony.evidence.v1"),
            "canonical evidence must include a domain tag in the CBOR payload"
        );

        let decoded: ciborium::value::Value =
            ciborium::de::from_reader(evidence.as_slice()).expect("canonical evidence CBOR");
        assert!(
            matches!(decoded, ciborium::value::Value::Map(_)),
            "canonical evidence should decode as a structured CBOR map"
        );
    }

    #[test]
    fn verification_evidence_source_has_no_raw_proof_hash_streaming() {
        let source = include_str!("verification.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        assert!(
            !production.contains("blake3::Hasher"),
            "verification ceremony evidence must use domain-separated canonical CBOR, not raw BLAKE3 streaming"
        );
    }
}

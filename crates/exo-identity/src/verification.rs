use std::collections::BTreeMap;

use exo_core::{Did, SecretKey, Signature, Timestamp};
use thiserror::Error;

use crate::risk::{RiskAttestation, RiskContext, RiskLevel, assess_risk};

#[derive(Debug, Error)]
pub enum VerificationCeremonyError {
    #[error("Ceremony has expired")]
    Expired,
    #[error("Ceremony is already finalized")]
    AlreadyFinalized,
    #[error("Invalid signature proof")]
    InvalidSignature,
    #[error("Insufficient risk score to finalize: {score}")]
    InsufficientScore { score: u32 },
    #[error("Invalid attester DID: {0}")]
    InvalidAttesterDid(String),
    #[error("risk attestation failed: {0}")]
    RiskAttestation(#[from] crate::error::IdentityError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityProof {
    Signature(Signature, exo_core::PublicKey, Vec<u8>), // sig, pubkey, message
    Otp(String),
    WebAuthnAssertion(Vec<u8>),
    KycToken(String),
}

#[derive(Debug, Clone)]
pub struct VerificationCeremony {
    pub target_did: Did,
    pub session_id: String,
    pub initiated_at: Timestamp,
    pub proofs: Vec<IdentityProof>,
    pub finalized: bool,
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

    pub fn submit_proof(
        &mut self,
        proof: IdentityProof,
        now: Timestamp,
    ) -> Result<(), VerificationCeremonyError> {
        if self.finalized {
            return Err(VerificationCeremonyError::AlreadyFinalized);
        }
        if now.physical_ms > self.initiated_at.physical_ms + 3_600_000 {
            return Err(VerificationCeremonyError::Expired);
        }

        if let IdentityProof::Signature(ref sig, ref pk, ref msg) = proof {
            if !exo_core::crypto::verify(msg, sig, pk) {
                return Err(VerificationCeremonyError::InvalidSignature);
            }
        }

        self.proofs.push(proof);
        Ok(())
    }

    pub fn calculate_risk_score(&self) -> u32 {
        let mut score = 0;
        // BTreeMap used as required
        let mut proof_weights: BTreeMap<&str, u32> = BTreeMap::new();
        proof_weights.insert("Signature", 1000);
        proof_weights.insert("Otp", 2000);
        proof_weights.insert("WebAuthnAssertion", 4000);
        proof_weights.insert("KycToken", 5000);

        for proof in &self.proofs {
            let s = match proof {
                IdentityProof::Signature(..) => {
                    proof_weights.get("Signature").copied().unwrap_or(0)
                }
                IdentityProof::Otp(_) => proof_weights.get("Otp").copied().unwrap_or(0),
                IdentityProof::WebAuthnAssertion(_) => {
                    proof_weights.get("WebAuthnAssertion").copied().unwrap_or(0)
                }
                IdentityProof::KycToken(_) => proof_weights.get("KycToken").copied().unwrap_or(0),
            };
            score += s;
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
    /// is computed are a canonical summary of the submitted proofs
    /// (one domain-separated line per proof, in submission order).
    /// This binds the attestation to the exact proof set that produced
    /// the risk score.
    pub fn finalize(
        &mut self,
        now: Timestamp,
        attester_did: &Did,
        attester_key: &SecretKey,
    ) -> Result<RiskAttestation, VerificationCeremonyError> {
        if self.finalized {
            return Err(VerificationCeremonyError::AlreadyFinalized);
        }
        if now.physical_ms > self.initiated_at.physical_ms + 3_600_000 {
            return Err(VerificationCeremonyError::Expired);
        }

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

        // Build canonical evidence bytes summarizing the proof set.
        // The attestation's evidence_hash will be blake3 over these bytes
        // (computed inside risk::assess_risk).
        let evidence = self.canonical_evidence();

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

    /// Canonical byte serialization of this ceremony's proof set, used
    /// as input to the attestation's `evidence_hash`. Format is:
    ///
    /// ```text
    /// "exo.verification.ceremony.v1\n"
    /// "<target_did>\n"
    /// "<session_id>\n"
    /// "<initiated_at_ms>\n"
    /// "proof\t<index>\t<kind>\t<hash_hex>\n" ... (one per proof)
    /// ```
    ///
    /// Where `<hash_hex>` is the blake3 hash (32 bytes, hex-encoded) of
    /// a kind-tagged canonical encoding of the proof's contents. This
    /// binds the attestation to an exact proof set and ordering while
    /// keeping raw proof material (e.g. OTPs, KYC tokens) out of the
    /// evidence payload.
    fn canonical_evidence(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"exo.verification.ceremony.v1\n");
        out.extend_from_slice(self.target_did.as_str().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.session_id.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.initiated_at.physical_ms.to_string().as_bytes());
        out.push(b'\n');

        for (idx, proof) in self.proofs.iter().enumerate() {
            let (kind, material_hash) = match proof {
                IdentityProof::Signature(sig, pk, msg) => {
                    let mut h = blake3::Hasher::new();
                    h.update(b"proof.signature.v1");
                    h.update(&sig.to_bytes());
                    h.update(pk.as_bytes());
                    h.update(msg);
                    ("Signature", *h.finalize().as_bytes())
                }
                IdentityProof::Otp(token) => {
                    let mut h = blake3::Hasher::new();
                    h.update(b"proof.otp.v1");
                    h.update(token.as_bytes());
                    ("Otp", *h.finalize().as_bytes())
                }
                IdentityProof::WebAuthnAssertion(bytes) => {
                    let mut h = blake3::Hasher::new();
                    h.update(b"proof.webauthn.v1");
                    h.update(bytes);
                    ("WebAuthnAssertion", *h.finalize().as_bytes())
                }
                IdentityProof::KycToken(token) => {
                    let mut h = blake3::Hasher::new();
                    h.update(b"proof.kyc.v1");
                    h.update(token.as_bytes());
                    ("KycToken", *h.finalize().as_bytes())
                }
            };
            out.extend_from_slice(b"proof\t");
            out.extend_from_slice(idx.to_string().as_bytes());
            out.push(b'\t');
            out.extend_from_slice(kind.as_bytes());
            out.push(b'\t');
            for byte in material_hash {
                out.extend_from_slice(format!("{byte:02x}").as_bytes());
            }
            out.push(b'\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use exo_core::crypto::{generate_keypair, sign};

    use super::*;

    #[test]
    fn test_ceremony_lifecycle() {
        let did = Did::new("did:exo:alice").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess1".to_string(), Timestamp::new(1000, 0));
        let (pk, sk) = generate_keypair();
        let msg = b"msg".to_vec();
        let sig = sign(&msg, &sk);

        ceremony
            .submit_proof(
                IdentityProof::Signature(sig, pk, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap();
        let (att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-lifecycle").unwrap();
        let attestation = ceremony
            .finalize(Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap();

        assert_eq!(attestation.level, RiskLevel::Minimal);
        assert!(ceremony.finalized);
        // GAP-004: signature must verify, evidence_hash must be non-zero.
        assert!(crate::risk::verify_attestation(&attestation, &att_pk));
        assert_ne!(attestation.evidence_hash, [0u8; 32]);
        assert!(
            !matches!(attestation.signature, Signature::Ed25519(b) if b.iter().all(|x| *x == 0))
        );
    }

    #[test]
    fn test_finalize_without_sufficient_proofs_fails() {
        let did = Did::new("did:exo:bob").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess2".to_string(), Timestamp::new(1000, 0));

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-bob").unwrap();
        let err = ceremony
            .finalize(Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationCeremonyError::InsufficientScore { .. }
        ));
    }

    #[test]
    fn test_risk_score_calculation() {
        let did = Did::new("did:exo:charlie").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess3".to_string(), Timestamp::new(1000, 0));

        let (pk, sk) = generate_keypair();
        let msg = b"msg".to_vec();
        let sig = sign(&msg, &sk);

        ceremony
            .submit_proof(
                IdentityProof::Signature(sig, pk, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap();
        assert_eq!(ceremony.calculate_risk_score(), 1000);

        ceremony
            .submit_proof(
                IdentityProof::Otp("123456".to_string()),
                Timestamp::new(1020, 0),
            )
            .unwrap();
        assert_eq!(ceremony.calculate_risk_score(), 3000); // 1000 + 2000
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
    fn test_invalid_signature_proof_rejected() {
        let did = Did::new("did:exo:eve").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess5".to_string(), Timestamp::new(1000, 0));

        let (pk, _) = generate_keypair();
        let (_, sk2) = generate_keypair();
        let msg = b"msg".to_vec();
        let bad_sig = sign(&msg, &sk2);

        let err = ceremony
            .submit_proof(
                IdentityProof::Signature(bad_sig, pk, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::InvalidSignature));
    }

    // Integration-style tests combining the registry and verification flow
    use crate::{
        did::DidDocument,
        registry::{DidRegistry, LocalDidRegistry},
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
        let did = make_did("integration1");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let mut ceremony = VerificationCeremony::new(
            did.clone(),
            "session_int_1".to_string(),
            Timestamp::new(1000, 0),
        );

        // 1. Submit signature
        let msg = b"integration_msg".to_vec();
        let sig = sign(&msg, &sk);
        ceremony
            .submit_proof(
                IdentityProof::Signature(sig, pk, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        // 2. Submit WebAuthn
        ceremony
            .submit_proof(
                IdentityProof::WebAuthnAssertion(vec![1, 2, 3]),
                Timestamp::new(1020, 0),
            )
            .unwrap();

        // 3. Finalize
        let (att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-int1").unwrap();
        let attestation = ceremony
            .finalize(Timestamp::new(1030, 0), &attester_did, &att_sk)
            .unwrap();
        assert_eq!(attestation.level, RiskLevel::Critical); // 1000 + 4000 = 5000 -> Critical
        assert!(crate::risk::verify_attestation(&attestation, &att_pk));

        // Check that the target DID matches what's in the registry
        let resolved = reg.resolve(&attestation.subject_did).unwrap();
        assert_eq!(resolved.id, did);
    }

    #[test]
    fn test_integration_revoked_did_verification_fails() {
        // While the ceremony itself doesn't check the registry in this simple model,
        // an integration flow would ensure we don't verify revoked DIDs.
        let (pk, sk) = generate_keypair();
        let did = make_did("integration2");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        // Revoke the DID
        let proof = crate::did::RevocationProof {
            did: did.clone(),
            signature: sign(did.as_str().as_bytes(), &sk),
        };
        reg.revoke(&did, &proof).unwrap();

        let resolved = reg.resolve(&did);
        assert!(resolved.is_none());

        // Since DID is revoked, the outer system wouldn't even start a ceremony,
        // but if it did, it should not be usable.
        let mut ceremony =
            VerificationCeremony::new(did, "session_int_2".to_string(), Timestamp::new(1000, 0));
        let msg = b"msg".to_vec();
        let sig = sign(&msg, &sk);
        ceremony
            .submit_proof(
                IdentityProof::Signature(sig, pk, msg),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        // Finalize succeeds, but the attestation is useless because resolve() fails
        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:attester-int2").unwrap();
        let attestation = ceremony
            .finalize(Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap();
        assert!(reg.resolve(&attestation.subject_did).is_none());
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
            .finalize(Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationCeremonyError::InsufficientScore { score: 0 }
        ));
    }

    // Covers submit_proof() returning AlreadyFinalized (line 56) when ceremony has been finalized.
    #[test]
    fn test_submit_proof_after_finalize_returns_already_finalized() {
        let did = Did::new("did:exo:finalized-then-submit").unwrap();
        let mut ceremony = VerificationCeremony::new(
            did,
            "sess-finalized-submit".to_string(),
            Timestamp::new(1000, 0),
        );
        ceremony
            .submit_proof(
                IdentityProof::KycToken("kyc-tok".to_string()),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        let (_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-finalized-submit").unwrap();
        let _ = ceremony
            .finalize(Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap();
        assert!(ceremony.finalized);

        let err = ceremony
            .submit_proof(
                IdentityProof::Otp("111".to_string()),
                Timestamp::new(1030, 0),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::AlreadyFinalized));
        // Proof must NOT have been appended.
        assert_eq!(ceremony.proofs.len(), 1);
    }

    // Covers finalize() returning AlreadyFinalized (line 124) on a second finalize call.
    #[test]
    fn test_double_finalize_returns_already_finalized() {
        let did = Did::new("did:exo:double-finalize").unwrap();
        let mut ceremony = VerificationCeremony::new(
            did,
            "sess-double-final".to_string(),
            Timestamp::new(1000, 0),
        );
        ceremony
            .submit_proof(
                IdentityProof::KycToken("t".to_string()),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        let (_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-double-final").unwrap();
        let _first = ceremony
            .finalize(Timestamp::new(1020, 0), &attester_did, &att_sk)
            .unwrap();
        let err = ceremony
            .finalize(Timestamp::new(1030, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::AlreadyFinalized));
    }

    // Covers finalize() returning Expired (line 127) when `now` is past the one-hour window.
    #[test]
    fn test_finalize_expired_returns_expired() {
        let did = Did::new("did:exo:finalize-expired").unwrap();
        let mut ceremony = VerificationCeremony::new(
            did,
            "sess-final-expired".to_string(),
            Timestamp::new(1000, 0),
        );
        ceremony
            .submit_proof(
                IdentityProof::KycToken("t".to_string()),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        let (_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-fin-exp").unwrap();
        // now > initiated_at + 3_600_000 ms
        let err = ceremony
            .finalize(Timestamp::new(5_000_000, 0), &attester_did, &att_sk)
            .unwrap_err();
        assert!(matches!(err, VerificationCeremonyError::Expired));
        // Still not finalized.
        assert!(!ceremony.finalized);
    }

    // Covers the empty-attester-DID rejection path (lines 137-139) in finalize().
    #[test]
    fn test_finalize_empty_attester_did_rejected() {
        let did = Did::new("did:exo:empty-attester").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-empty-att".to_string(), Timestamp::new(1000, 0));
        ceremony
            .submit_proof(
                IdentityProof::KycToken("t".to_string()),
                Timestamp::new(1010, 0),
            )
            .unwrap();

        let (_pk, att_sk) = generate_keypair();
        // `Did::new("")` legitimately rejects — so the only way to reach the
        // empty-attester branch in `finalize()` is to deserialize a malformed
        // Did from serde. That mirrors the real attack surface (malformed
        // network input / tampered storage) that the branch is meant to catch.
        let empty_did: Did =
            serde_json::from_str("\"\"").expect("serde_json accepts empty string for Did wrapper");

        let err = ceremony
            .finalize(Timestamp::new(1020, 0), &empty_did, &att_sk)
            .unwrap_err();
        match err {
            VerificationCeremonyError::InvalidAttesterDid(msg) => {
                assert!(msg.contains("empty"));
            }
            other => panic!("expected InvalidAttesterDid, got {other:?}"),
        }
        // Ceremony must not have been flipped to finalized when validation failed.
        assert!(!ceremony.finalized);
    }

    // Covers calculate_risk_score() KycToken arm (line 90) in isolation with a known weight.
    #[test]
    fn test_risk_score_kyc_token_weight() {
        let did = Did::new("did:exo:score-kyc").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-kyc".to_string(), Timestamp::new(1000, 0));
        ceremony
            .submit_proof(
                IdentityProof::KycToken("kyc".into()),
                Timestamp::new(1001, 0),
            )
            .unwrap();
        // KYC weight alone is 5000.
        assert_eq!(ceremony.calculate_risk_score(), 5000);
    }

    // Covers RiskLevel::Low branch (line 149): 2000 <= score < 3000.
    #[test]
    fn test_finalize_risk_level_low() {
        let did = Did::new("did:exo:level-low").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-low".to_string(), Timestamp::new(1000, 0));
        ceremony
            .submit_proof(IdentityProof::Otp("otp".into()), Timestamp::new(1001, 0))
            .unwrap();
        assert_eq!(ceremony.calculate_risk_score(), 2000);

        let (att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-low").unwrap();
        let attestation = ceremony
            .finalize(Timestamp::new(1010, 0), &attester_did, &att_sk)
            .unwrap();
        assert_eq!(attestation.level, RiskLevel::Low);
        assert!(crate::risk::verify_attestation(&attestation, &att_pk));
    }

    // Covers RiskLevel::Medium branch (line 147): 3000 <= score < 4000.
    #[test]
    fn test_finalize_risk_level_medium() {
        let did = Did::new("did:exo:level-medium").unwrap();
        let mut ceremony =
            VerificationCeremony::new(did, "sess-med".to_string(), Timestamp::new(1000, 0));
        let (pk, sk) = generate_keypair();
        let msg = b"m".to_vec();
        let sig = sign(&msg, &sk);
        ceremony
            .submit_proof(
                IdentityProof::Signature(sig, pk, msg),
                Timestamp::new(1001, 0),
            )
            .unwrap();
        ceremony
            .submit_proof(IdentityProof::Otp("otp".into()), Timestamp::new(1002, 0))
            .unwrap();
        // 1000 (sig) + 2000 (otp) = 3000 -> Medium
        assert_eq!(ceremony.calculate_risk_score(), 3000);

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-med").unwrap();
        let attestation = ceremony
            .finalize(Timestamp::new(1010, 0), &attester_did, &att_sk)
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
            .submit_proof(
                IdentityProof::WebAuthnAssertion(vec![9, 9, 9]),
                Timestamp::new(1001, 0),
            )
            .unwrap();
        // WebAuthn alone = 4000 -> High
        assert_eq!(ceremony.calculate_risk_score(), 4000);

        let (_att_pk, att_sk) = generate_keypair();
        let attester_did = Did::new("did:exo:att-high").unwrap();
        let attestation = ceremony
            .finalize(Timestamp::new(1010, 0), &attester_did, &att_sk)
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
            ceremony
                .submit_proof(IdentityProof::Otp(otp.to_string()), Timestamp::new(1001, 0))
                .unwrap();
            ceremony
                .submit_proof(
                    IdentityProof::KycToken(kyc.to_string()),
                    Timestamp::new(1002, 0),
                )
                .unwrap();
            let (_pk, sk) = generate_keypair();
            let attester = Did::new("did:exo:att-canon").unwrap();
            let att = ceremony
                .finalize(Timestamp::new(1010, 0), &attester, &sk)
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
}

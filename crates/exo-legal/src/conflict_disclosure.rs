//! Conflict of interest disclosure requirements.

use exo_core::{Did, PublicKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};

use crate::error::{LegalError, Result};

/// A conflict-of-interest disclosure filed by a declarant before a governed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    pub declarant: Did,
    pub nature: String,
    pub related_parties: Vec<Did>,
    pub timestamp: Timestamp,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<DisclosureVerification>,
}

/// Cryptographic evidence that a third-party verifier reviewed a disclosure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisclosureVerification {
    pub verifier: Did,
    pub verified_at: Timestamp,
    pub verifier_public_key: PublicKey,
    pub signature: Signature,
}

const REQUIRED_ACTIONS: &[&str] = &[
    "vote",
    "approve",
    "fund",
    "transfer",
    "delegate",
    "adjudicate",
];

/// Returns `true` if the given action requires a conflict-of-interest disclosure before proceeding.
#[must_use]
pub fn require_disclosure(_actor: &Did, action: &str) -> bool {
    let lower = action.to_lowercase();
    REQUIRED_ACTIONS.iter().any(|k| lower.contains(k))
}

/// Files a new unverified disclosure describing the conflict and the related parties.
pub fn file_disclosure(
    actor: &Did,
    nature: &str,
    related: &[Did],
    timestamp: Timestamp,
) -> Result<Disclosure> {
    if nature.trim().is_empty() {
        return Err(LegalError::DisclosureRequired {
            action: "conflict disclosure requires a non-empty nature".into(),
        });
    }
    if timestamp == Timestamp::ZERO {
        return Err(LegalError::DisclosureRequired {
            action: "conflict disclosure timestamp must not be Timestamp::ZERO".into(),
        });
    }
    let mut related_parties = related.to_vec();
    related_parties.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    related_parties.dedup_by(|a, b| a.as_str() == b.as_str());

    Ok(Disclosure {
        declarant: actor.clone(),
        nature: nature.into(),
        related_parties,
        timestamp,
        verified: false,
        verification: None,
    })
}

/// Domain-separated canonical CBOR payload signed to verify a disclosure.
///
/// The payload excludes `verified` and `verification` so the signature binds
/// the filed disclosure content and verifier metadata, not the output field
/// being produced.
pub fn disclosure_verification_payload(
    disclosure: &Disclosure,
    verifier: &Did,
    verified_at: &Timestamp,
) -> Result<Vec<u8>> {
    let related_parties: Vec<String> = disclosure
        .related_parties
        .iter()
        .map(|did| did.as_str().to_string())
        .collect();
    let payload = (
        "exo.legal.conflict_disclosure.verification.v1",
        disclosure.declarant.as_str(),
        disclosure.nature.as_str(),
        related_parties,
        disclosure.timestamp.physical_ms,
        disclosure.timestamp.logical,
        verifier.as_str(),
        verified_at.physical_ms,
        verified_at.logical,
    );
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded).map_err(|e| {
        LegalError::DisclosureVerificationInvalid {
            reason: format!("canonical verification payload encoding failed: {e}"),
        }
    })?;
    Ok(encoded)
}

/// Marks a previously filed disclosure as verified only with signed evidence.
pub fn verify_disclosure(
    disclosure: &mut Disclosure,
    verification: DisclosureVerification,
) -> Result<()> {
    if disclosure.verified || disclosure.verification.is_some() {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "disclosure is already verified".into(),
        });
    }
    if verification.verified_at == Timestamp::ZERO {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "verification timestamp must be caller-supplied and non-zero".into(),
        });
    }
    if verification.verifier == disclosure.declarant {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "self-verification is not permitted for conflict disclosures".into(),
        });
    }
    if verification.signature.is_empty() {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "verification signature must be non-empty Ed25519 evidence".into(),
        });
    }

    let payload = disclosure_verification_payload(
        disclosure,
        &verification.verifier,
        &verification.verified_at,
    )?;
    if !crypto::verify(
        &payload,
        &verification.signature,
        &verification.verifier_public_key,
    ) {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "verification signature does not match the disclosure payload".into(),
        });
    }

    disclosure.verified = true;
    disclosure.verification = Some(verification);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::{Signature, crypto};

    use super::*;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn signed_verification(
        disclosure: &Disclosure,
        verifier: &Did,
        verified_at: Timestamp,
        secret_key: &exo_core::SecretKey,
    ) -> Signature {
        let payload = disclosure_verification_payload(disclosure, verifier, &verified_at)
            .expect("canonical verification payload");
        crypto::sign(&payload, secret_key)
    }

    #[test]
    fn file_disclosure_uses_caller_supplied_timestamp() {
        let disclosure =
            file_disclosure(&did("a"), "board conflict", &[did("b")], ts(1000)).unwrap();
        assert_eq!(disclosure.timestamp, ts(1000));
    }

    #[test]
    fn file_disclosure_rejects_placeholder_metadata() {
        assert!(file_disclosure(&did("a"), "board conflict", &[], Timestamp::ZERO).is_err());
        assert!(file_disclosure(&did("a"), " ", &[], ts(1000)).is_err());
    }

    #[test]
    fn require_vote() {
        assert!(require_disclosure(&did("a"), "vote on proposal"));
    }
    #[test]
    fn require_approve() {
        assert!(require_disclosure(&did("a"), "approve budget"));
    }
    #[test]
    fn require_fund() {
        assert!(require_disclosure(&did("a"), "fund project"));
    }
    #[test]
    fn require_transfer() {
        assert!(require_disclosure(&did("a"), "transfer assets"));
    }
    #[test]
    fn require_delegate() {
        assert!(require_disclosure(&did("a"), "delegate authority"));
    }
    #[test]
    fn require_adjudicate() {
        assert!(require_disclosure(&did("a"), "adjudicate dispute"));
    }
    #[test]
    fn no_require_read() {
        assert!(!require_disclosure(&did("a"), "read document"));
    }
    #[test]
    fn case_insensitive() {
        assert!(require_disclosure(&did("a"), "VOTE"));
    }
    #[test]
    fn file_basic() {
        let d = file_disclosure(&did("a"), "financial", &[did("b")], ts(1000)).unwrap();
        assert_eq!(d.related_parties.len(), 1);
        assert!(!d.verified);
    }
    #[test]
    fn file_empty() {
        let d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        assert!(d.related_parties.is_empty());
    }
    #[test]
    fn verify_disclosure_requires_signed_verification_evidence() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("ethics");
        let (pk, sk) = crypto::generate_keypair();
        let verified_at = ts(2000);
        let signature = signed_verification(&d, &verifier, verified_at, &sk);

        verify_disclosure(
            &mut d,
            DisclosureVerification {
                verifier: verifier.clone(),
                verified_at,
                verifier_public_key: pk,
                signature,
            },
        )
        .expect("signed verification evidence");

        assert!(d.verified);
        assert_eq!(
            d.verification
                .as_ref()
                .expect("verification evidence")
                .verifier,
            verifier
        );
    }

    #[test]
    fn verify_disclosure_rejects_empty_signature() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("ethics");
        let (pk, _sk) = crypto::generate_keypair();

        let err = verify_disclosure(
            &mut d,
            DisclosureVerification {
                verifier,
                verified_at: ts(2000),
                verifier_public_key: pk,
                signature: Signature::Empty,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("signature"));
        assert!(!d.verified);
    }

    #[test]
    fn verify_disclosure_rejects_all_zero_signature() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("ethics");
        let (pk, _sk) = crypto::generate_keypair();

        let err = verify_disclosure(
            &mut d,
            DisclosureVerification {
                verifier,
                verified_at: ts(2000),
                verifier_public_key: pk,
                signature: Signature::from_bytes([0u8; 64]),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("signature"));
        assert!(!d.verified);
    }

    #[test]
    fn verify_disclosure_rejects_wrong_key_signature() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("ethics");
        let (_signer_pk, signer_sk) = crypto::generate_keypair();
        let (wrong_pk, _wrong_sk) = crypto::generate_keypair();
        let verified_at = ts(2000);
        let signature = signed_verification(&d, &verifier, verified_at, &signer_sk);

        let err = verify_disclosure(
            &mut d,
            DisclosureVerification {
                verifier,
                verified_at,
                verifier_public_key: wrong_pk,
                signature,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("signature"));
        assert!(!d.verified);
    }

    #[test]
    fn verify_disclosure_rejects_tampered_disclosure_content() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("ethics");
        let (pk, sk) = crypto::generate_keypair();
        let verified_at = ts(2000);
        let signature = signed_verification(&d, &verifier, verified_at, &sk);
        d.nature = "changed after signing".into();

        let err = verify_disclosure(
            &mut d,
            DisclosureVerification {
                verifier,
                verified_at,
                verifier_public_key: pk,
                signature,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("signature"));
        assert!(!d.verified);
    }

    #[test]
    fn verify_disclosure_rejects_self_verification() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("a");
        let (pk, sk) = crypto::generate_keypair();
        let verified_at = ts(2000);
        let signature = signed_verification(&d, &verifier, verified_at, &sk);

        let err = verify_disclosure(
            &mut d,
            DisclosureVerification {
                verifier,
                verified_at,
                verifier_public_key: pk,
                signature,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("self"));
        assert!(!d.verified);
    }

    #[test]
    fn verify_disclosure_rejects_zero_timestamp() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("ethics");
        let (pk, sk) = crypto::generate_keypair();
        let signature = signed_verification(&d, &verifier, Timestamp::ZERO, &sk);

        let err = verify_disclosure(
            &mut d,
            DisclosureVerification {
                verifier,
                verified_at: Timestamp::ZERO,
                verifier_public_key: pk,
                signature,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("timestamp"));
        assert!(!d.verified);
    }

    #[test]
    fn verify_disclosure_rejects_replay_over_already_verified_disclosure() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        let verifier = did("ethics");
        let (pk, sk) = crypto::generate_keypair();
        let verified_at = ts(2000);
        let signature = signed_verification(&d, &verifier, verified_at, &sk);
        let verification = DisclosureVerification {
            verifier,
            verified_at,
            verifier_public_key: pk,
            signature,
        };

        verify_disclosure(&mut d, verification.clone()).expect("first verification");
        let err = verify_disclosure(&mut d, verification).unwrap_err();

        assert!(err.to_string().contains("already verified"));
    }

    #[test]
    fn disclosure_verification_payload_is_deterministic() {
        let d = file_disclosure(&did("a"), "x", &[did("b")], ts(1000)).unwrap();
        let verifier = did("ethics");
        let verified_at = ts(2000);

        assert_eq!(
            disclosure_verification_payload(&d, &verifier, &verified_at).unwrap(),
            disclosure_verification_payload(&d, &verifier, &verified_at).unwrap()
        );
    }
    #[test]
    fn serde() {
        let d = file_disclosure(&did("a"), "x", &[did("b")], ts(1000)).unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let r: Disclosure = serde_json::from_str(&j).unwrap();
        assert_eq!(r.declarant, did("a"));
    }
    #[test]
    fn required_count() {
        assert_eq!(REQUIRED_ACTIONS.len(), 6);
    }
}

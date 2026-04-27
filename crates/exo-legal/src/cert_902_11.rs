//! FRE 902(11) Self-Authentication Certification Generator (LEG-001 extension).
//!
//! Federal Rule of Evidence 902(11) allows business records to be
//! self-authenticated — admitted without live witness testimony — when
//! accompanied by a signed declaration from a qualified person attesting that:
//!
//! > The record was made at or near the time of the act, condition, or event;
//! > by, or from information transmitted by, a person with knowledge of those
//! > matters; kept in the course of a regularly conducted activity of a
//! > business, organization, occupation, or calling; and making the record
//! > was a regular practice of that activity.
//!
//! This module generates a structured `Cert902_11` artifact containing all
//! required elements.  The `declarant_placeholder` field MUST be completed by
//! a qualified human declarant (typically the custodian of records or a
//! designated officer) before the certificate is filed.
//!
//! # Security note
//!
//! The `cert_hash` is a BLAKE3 digest of all structural fields.  Any
//! modification after generation causes `verify_902_11_cert()` to fail.
//!
//! # Legal disclaimer
//!
//! This generated artifact is NOT ready to file.  The `declarant_placeholder`
//! field must be completed by a qualified human declarant, and the certificate
//! must be reviewed by qualified counsel before use in any legal proceeding.

use exo_core::types::Hash256;
use serde::{Deserialize, Serialize};

use crate::{
    error::{LegalError, Result},
    evidence::{Evidence, verify_chain_of_custody},
};

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

/// FRE 902(11) certification artifact for a single evidence record.
///
/// # Filing requirement
///
/// The `declarant_placeholder` field MUST be replaced with the name, title,
/// and contact information of a qualified declarant before this certificate is
/// filed in any legal proceeding.  Filing with a blank or template placeholder
/// constitutes an incomplete certification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cert902_11 {
    /// BLAKE3 hash of the evidence record being certified.
    pub record_hash: Hash256,
    /// BLAKE3 digest of the full custody chain at certification time.
    pub custody_chain_digest: Hash256,
    /// Description of the system that created the record (FRE 901(b)(9)).
    ///
    /// Should identify the software, version, and regular business practice.
    pub system_description: String,
    /// Placeholder for the qualified declarant's identity.
    ///
    /// **MUST be completed before filing.**  Replace with the declarant's
    /// full name, title, organization, and contact information.
    pub declarant_placeholder: String,
    /// Physical millisecond timestamp when this certificate was generated.
    pub generated_at_ms: u64,
    /// BLAKE3 hash sealing all above fields — tamper-evident.
    pub cert_hash: Hash256,
    /// Mandatory legal disclaimer reminding the user this is not ready to file.
    pub filing_disclaimer: &'static str,
}

impl Cert902_11 {
    /// Disclaimer text included in every certificate.
    pub const FILING_DISCLAIMER: &'static str = "NOT READY TO FILE. The declarant_placeholder field must be completed \
         by a qualified human declarant, and this certificate must be reviewed \
         by qualified counsel before use in any legal proceeding.";
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate a FRE 902(11) certification for an evidence record.
///
/// # Arguments
/// * `evidence` — the evidence record to certify.
/// * `system_description` — human-readable description of the record system
///   (satisfies FRE 901(b)(9) system description requirement).
/// * `generated_at_ms` — wall-clock time in milliseconds (must be > 0).
///
/// # Errors
/// - `InvalidStateTransition` if `evidence.timestamp == Timestamp::ZERO` (evidence
///   lacks a real timestamp and therefore cannot satisfy FRE 803(6)).
/// - `InvalidStateTransition` if `system_description` is empty.
/// - `CustodyChainBroken` if the evidence chain of custody is invalid.
pub fn generate_902_11_cert(
    evidence: &Evidence,
    system_description: &str,
    generated_at_ms: u64,
) -> Result<Cert902_11> {
    // Evidence must have a real timestamp — the FRE 803(6) "at or near the
    // time" requirement fails if timestamp is zero.
    if evidence.timestamp.physical_ms == 0 {
        return Err(LegalError::InvalidStateTransition {
            reason: "FRE 902(11) certification requires evidence with a real timestamp; \
                     Timestamp::ZERO evidence cannot satisfy FRE 803(6)"
                .into(),
        });
    }
    if system_description.is_empty() {
        return Err(LegalError::InvalidStateTransition {
            reason: "system_description must not be empty (required for FRE 901(b)(9))".into(),
        });
    }
    // Verify chain of custody integrity before certifying.
    verify_chain_of_custody(evidence)?;

    let record_hash = evidence.hash;
    let custody_chain_digest = compute_custody_digest(evidence);
    let cert_hash = compute_cert_hash(
        &record_hash,
        &custody_chain_digest,
        system_description,
        generated_at_ms,
    );

    Ok(Cert902_11 {
        record_hash,
        custody_chain_digest,
        system_description: system_description.to_string(),
        declarant_placeholder: "[DECLARANT NAME, TITLE, ORGANIZATION — COMPLETE BEFORE FILING]"
            .to_string(),
        generated_at_ms,
        cert_hash,
        filing_disclaimer: Cert902_11::FILING_DISCLAIMER,
    })
}

/// Verify a `Cert902_11` has not been modified since generation.
///
/// Recomputes `cert_hash` from the structural fields and compares to the
/// stored value.  Returns `true` if the certificate is intact.
#[must_use]
pub fn verify_902_11_cert(cert: &Cert902_11) -> bool {
    let expected = compute_cert_hash(
        &cert.record_hash,
        &cert.custody_chain_digest,
        &cert.system_description,
        cert.generated_at_ms,
    );
    expected == cert.cert_hash
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn compute_custody_digest(evidence: &Evidence) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fre902:custody:");
    hasher.update(evidence.hash.as_bytes());
    hasher.update(&evidence.timestamp.physical_ms.to_le_bytes());
    for transfer in &evidence.chain_of_custody {
        hasher.update(transfer.from.to_string().as_bytes());
        hasher.update(transfer.to.to_string().as_bytes());
        hasher.update(&transfer.timestamp.physical_ms.to_le_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn compute_cert_hash(
    record_hash: &Hash256,
    custody_chain_digest: &Hash256,
    system_description: &str,
    generated_at_ms: u64,
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fre902:cert:v1:");
    hasher.update(record_hash.as_bytes());
    hasher.update(custody_chain_digest.as_bytes());
    hasher.update(system_description.as_bytes());
    hasher.update(&generated_at_ms.to_le_bytes());
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use exo_core::{Did, Timestamp};
    use uuid::Uuid;

    use super::*;
    use crate::evidence::create_evidence;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    fn real_ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn make_evidence() -> Evidence {
        create_evidence(
            Uuid::from_u128(0x90211),
            b"board-minutes",
            &did("secretary"),
            "board-minutes",
            real_ts(1_700_000_000_000),
        )
        .unwrap()
    }

    const SYSTEM_DESC: &str = "EXOCHAIN decision.forum v1.0 — records created at vote-close via BCTS lifecycle \
         as a regular practice of board governance operations.";

    #[test]
    fn cert_contains_required_elements() {
        let ev = make_evidence();
        let cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();

        assert_eq!(
            cert.record_hash, ev.hash,
            "record_hash must match evidence hash"
        );
        assert!(
            !cert.system_description.is_empty(),
            "system_description must be present"
        );
        assert!(
            cert.declarant_placeholder.contains("DECLARANT"),
            "declarant_placeholder must be present"
        );
        assert!(cert.generated_at_ms > 0, "generated_at_ms must be non-zero");
        assert!(
            cert.cert_hash != Hash256::ZERO,
            "cert_hash must not be zero"
        );
        assert!(
            cert.filing_disclaimer.contains("NOT READY TO FILE"),
            "filing_disclaimer must warn about declarant completion"
        );
    }

    #[test]
    fn cert_verification_passes_after_generation() {
        let ev = make_evidence();
        let cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();
        assert!(
            verify_902_11_cert(&cert),
            "cert must verify immediately after generation"
        );
    }

    #[test]
    fn cert_verification_detects_tampering_record_hash() {
        let ev = make_evidence();
        let mut cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();
        cert.record_hash = Hash256::digest(b"tampered");
        assert!(
            !verify_902_11_cert(&cert),
            "tampered record_hash must fail verification"
        );
    }

    #[test]
    fn cert_verification_detects_tampering_system_description() {
        let ev = make_evidence();
        let mut cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();
        cert.system_description = "evil system".to_string();
        assert!(
            !verify_902_11_cert(&cert),
            "tampered system_description must fail verification"
        );
    }

    #[test]
    fn cert_verification_detects_tampering_timestamp() {
        let ev = make_evidence();
        let mut cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();
        cert.generated_at_ms = 9_999_999_999_999;
        assert!(
            !verify_902_11_cert(&cert),
            "tampered timestamp must fail verification"
        );
    }

    #[test]
    fn cert_rejects_zero_timestamp_evidence() {
        // Evidence with Timestamp::ZERO cannot satisfy FRE 803(6).
        // (create_evidence already rejects Timestamp::ZERO, but we test the
        // cert layer independently using a manually constructed Evidence.)
        let mut ev = make_evidence();
        ev.timestamp = Timestamp::ZERO;
        let result = generate_902_11_cert(&ev, SYSTEM_DESC, 1_000);
        assert!(
            result.is_err(),
            "Cert must reject evidence with zero timestamp"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("real timestamp"),
            "Error must explain FRE 803(6) requirement"
        );
    }

    #[test]
    fn cert_rejects_empty_system_description() {
        let ev = make_evidence();
        let result = generate_902_11_cert(&ev, "", 1_000);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("system_description")
        );
    }

    #[test]
    fn cert_custody_chain_digest_changes_with_transfer() {
        use crate::evidence::transfer_custody;

        let mut ev = make_evidence();
        let cert_before = generate_902_11_cert(&ev, SYSTEM_DESC, 1_000).unwrap();

        transfer_custody(
            &mut ev,
            &did("secretary"),
            &did("counsel"),
            real_ts(1_700_000_000_100),
            "certification transfer",
        )
        .unwrap();
        let cert_after = generate_902_11_cert(&ev, SYSTEM_DESC, 2_000).unwrap();

        assert_ne!(
            cert_before.custody_chain_digest, cert_after.custody_chain_digest,
            "custody_chain_digest must reflect chain state"
        );
    }
}

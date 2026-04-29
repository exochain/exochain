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
//! The `cert_hash` is a domain-separated canonical CBOR digest of all
//! structural fields.  Any modification after generation causes
//! `verify_902_11_cert()` to fail.
//!
//! # Legal disclaimer
//!
//! This generated artifact is NOT ready to file.  The `declarant_placeholder`
//! field must be completed by a qualified human declarant, and the certificate
//! must be reviewed by qualified counsel before use in any legal proceeding.

use exo_core::{Did, Timestamp, hash::hash_structured, types::Hash256};
use serde::{Deserialize, Serialize};

use crate::{
    error::{LegalError, Result},
    evidence::{Evidence, verify_chain_of_custody},
};

const CERT_902_11_CUSTODY_DIGEST_DOMAIN: &str = "exo.legal.cert_902_11.custody_digest.v1";
const CERT_902_11_HASH_DOMAIN: &str = "exo.legal.cert_902_11.cert_hash.v1";
const CERT_902_11_HASH_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize)]
struct Cert90211CustodyTransferPayload {
    from: Did,
    to: Did,
    timestamp: Timestamp,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct Cert90211CustodyDigestPayload {
    domain: &'static str,
    schema_version: u16,
    evidence_hash: Hash256,
    evidence_timestamp: Timestamp,
    transfers: Vec<Cert90211CustodyTransferPayload>,
}

#[derive(Debug, Clone, Serialize)]
struct Cert90211HashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    record_hash: Hash256,
    custody_chain_digest: Hash256,
    system_description: &'a str,
    generated_at_ms: u64,
}

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
    /// Domain-separated canonical digest of the full custody chain at certification time.
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
    /// Caller-supplied millisecond timestamp when this certificate was generated.
    pub generated_at_ms: u64,
    /// Domain-separated canonical hash sealing all above fields — tamper-evident.
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
/// * `generated_at_ms` — caller-supplied time in milliseconds (must be > 0).
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
    let custody_chain_digest = compute_custody_digest(evidence)?;
    let cert_hash = compute_cert_hash(
        &record_hash,
        &custody_chain_digest,
        system_description,
        generated_at_ms,
    )?;

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
/// Recomputes `cert_hash` from the structural fields and compares to the stored
/// value.
///
/// # Errors
///
/// Returns [`LegalError::CertificationHashEncodingFailed`] if canonical CBOR
/// hashing fails.
pub fn verify_902_11_cert(cert: &Cert902_11) -> Result<bool> {
    let expected = compute_cert_hash(
        &cert.record_hash,
        &cert.custody_chain_digest,
        &cert.system_description,
        cert.generated_at_ms,
    )?;
    Ok(expected == cert.cert_hash)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn cert_902_11_custody_digest_payload(evidence: &Evidence) -> Cert90211CustodyDigestPayload {
    Cert90211CustodyDigestPayload {
        domain: CERT_902_11_CUSTODY_DIGEST_DOMAIN,
        schema_version: CERT_902_11_HASH_SCHEMA_VERSION,
        evidence_hash: evidence.hash,
        evidence_timestamp: evidence.timestamp,
        transfers: evidence
            .chain_of_custody
            .iter()
            .map(|transfer| Cert90211CustodyTransferPayload {
                from: transfer.from.clone(),
                to: transfer.to.clone(),
                timestamp: transfer.timestamp,
                reason: transfer.reason.clone(),
            })
            .collect(),
    }
}

fn cert_902_11_hash_payload<'a>(
    record_hash: &Hash256,
    custody_chain_digest: &Hash256,
    system_description: &'a str,
    generated_at_ms: u64,
) -> Cert90211HashPayload<'a> {
    Cert90211HashPayload {
        domain: CERT_902_11_HASH_DOMAIN,
        schema_version: CERT_902_11_HASH_SCHEMA_VERSION,
        record_hash: *record_hash,
        custody_chain_digest: *custody_chain_digest,
        system_description,
        generated_at_ms,
    }
}

fn compute_custody_digest(evidence: &Evidence) -> Result<Hash256> {
    hash_structured(&cert_902_11_custody_digest_payload(evidence)).map_err(|e| {
        LegalError::CertificationHashEncodingFailed {
            reason: format!("FRE 902(11) custody digest canonical CBOR hash failed: {e}"),
        }
    })
}

fn compute_cert_hash(
    record_hash: &Hash256,
    custody_chain_digest: &Hash256,
    system_description: &str,
    generated_at_ms: u64,
) -> Result<Hash256> {
    hash_structured(&cert_902_11_hash_payload(
        record_hash,
        custody_chain_digest,
        system_description,
        generated_at_ms,
    ))
    .map_err(|e| LegalError::CertificationHashEncodingFailed {
        reason: format!("FRE 902(11) certificate hash canonical CBOR hash failed: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use exo_core::{Did, Timestamp};
    use uuid::Uuid;

    use super::*;
    use crate::evidence::{create_evidence, transfer_custody};

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

    fn production_source() -> &'static str {
        let source = include_str!("cert_902_11.rs");
        let end = source
            .find("// ---------------------------------------------------------------------------\n// Tests")
            .unwrap();
        &source[..end]
    }

    fn evidence_with_transfer(reason: &str) -> Evidence {
        let mut ev = make_evidence();
        transfer_custody(
            &mut ev,
            &did("secretary"),
            &did("counsel"),
            real_ts(1_700_000_000_100),
            reason,
        )
        .unwrap();
        ev
    }

    #[test]
    fn custody_digest_payload_is_domain_separated_cbor() {
        let ev = evidence_with_transfer("certification transfer");
        let payload = cert_902_11_custody_digest_payload(&ev);
        assert_eq!(payload.domain, CERT_902_11_CUSTODY_DIGEST_DOMAIN);
        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.evidence_hash, ev.hash);
        assert_eq!(payload.evidence_timestamp, ev.timestamp);
        assert_eq!(payload.transfers.len(), 1);
        assert_eq!(payload.transfers[0].from, ev.chain_of_custody[0].from);
        assert_eq!(payload.transfers[0].to, ev.chain_of_custody[0].to);
        assert_eq!(
            payload.transfers[0].timestamp,
            ev.chain_of_custody[0].timestamp
        );
        assert_eq!(payload.transfers[0].reason, ev.chain_of_custody[0].reason);
    }

    #[test]
    fn cert_hash_payload_is_domain_separated_cbor() {
        let ev = make_evidence();
        let custody_digest = compute_custody_digest(&ev).expect("canonical 902(11) custody digest");
        let payload =
            cert_902_11_hash_payload(&ev.hash, &custody_digest, SYSTEM_DESC, 1_700_000_001_000);
        assert_eq!(payload.domain, CERT_902_11_HASH_DOMAIN);
        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.record_hash, ev.hash);
        assert_eq!(payload.custody_chain_digest, custody_digest);
        assert_eq!(payload.system_description, SYSTEM_DESC);
        assert_eq!(payload.generated_at_ms, 1_700_000_001_000);
    }

    #[test]
    fn cert_hashes_reject_legacy_raw_concat_hashes() {
        let ev = evidence_with_transfer("certification transfer");

        let mut custody_hasher = blake3::Hasher::new();
        custody_hasher.update(b"fre902:custody:");
        custody_hasher.update(ev.hash.as_bytes());
        custody_hasher.update(&ev.timestamp.physical_ms.to_le_bytes());
        for transfer in &ev.chain_of_custody {
            custody_hasher.update(transfer.from.to_string().as_bytes());
            custody_hasher.update(transfer.to.to_string().as_bytes());
            custody_hasher.update(&transfer.timestamp.physical_ms.to_le_bytes());
        }
        let legacy_custody_digest = Hash256::from_bytes(*custody_hasher.finalize().as_bytes());

        let mut cert_hasher = blake3::Hasher::new();
        cert_hasher.update(b"fre902:cert:v1:");
        cert_hasher.update(ev.hash.as_bytes());
        cert_hasher.update(legacy_custody_digest.as_bytes());
        cert_hasher.update(SYSTEM_DESC.as_bytes());
        cert_hasher.update(&1_700_000_001_000u64.to_le_bytes());
        let legacy_cert_hash = Hash256::from_bytes(*cert_hasher.finalize().as_bytes());

        let cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();

        assert_ne!(cert.custody_chain_digest, legacy_custody_digest);
        assert_ne!(cert.cert_hash, legacy_cert_hash);
    }

    #[test]
    fn custody_digest_binds_transfer_reason_and_logical_time() {
        let ev_a = evidence_with_transfer("certification transfer");
        let mut ev_b = evidence_with_transfer("litigation hold transfer");
        ev_b.chain_of_custody[0].timestamp = Timestamp::new(
            ev_a.chain_of_custody[0].timestamp.physical_ms,
            ev_a.chain_of_custody[0].timestamp.logical + 1,
        );

        assert_ne!(
            compute_custody_digest(&ev_a).expect("first custody digest"),
            compute_custody_digest(&ev_b).expect("second custody digest")
        );
    }

    #[test]
    fn cert_production_source_has_no_raw_hash_loops() {
        let production = production_source();
        assert!(
            !production.contains("blake3::Hasher"),
            "902(11) certificate hashes must use domain-separated canonical CBOR"
        );
        assert!(
            !production.contains("fre902:"),
            "902(11) certificate hashes must not use raw byte domain prefixes"
        );
    }

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
            verify_902_11_cert(&cert).unwrap(),
            "cert must verify immediately after generation"
        );
    }

    #[test]
    fn cert_verification_detects_tampering_record_hash() {
        let ev = make_evidence();
        let mut cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();
        cert.record_hash = Hash256::digest(b"tampered");
        assert!(
            !verify_902_11_cert(&cert).unwrap(),
            "tampered record_hash must fail verification"
        );
    }

    #[test]
    fn cert_verification_detects_tampering_system_description() {
        let ev = make_evidence();
        let mut cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();
        cert.system_description = "evil system".to_string();
        assert!(
            !verify_902_11_cert(&cert).unwrap(),
            "tampered system_description must fail verification"
        );
    }

    #[test]
    fn cert_verification_detects_tampering_timestamp() {
        let ev = make_evidence();
        let mut cert = generate_902_11_cert(&ev, SYSTEM_DESC, 1_700_000_001_000).unwrap();
        cert.generated_at_ms = 9_999_999_999_999;
        assert!(
            !verify_902_11_cert(&cert).unwrap(),
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

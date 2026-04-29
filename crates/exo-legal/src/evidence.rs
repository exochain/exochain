//! Evidence chain management — litigation-grade evidence tracking.

use exo_core::{Did, Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{LegalError, Result};

const EVIDENCE_CUSTODY_CHAIN_DIGEST_DOMAIN: &str = "exo.legal.evidence.custody_chain.v1";
const EVIDENCE_CUSTODY_CHAIN_DIGEST_SCHEMA_VERSION: u16 = 1;

/// Whether a piece of evidence has been admitted, challenged, excluded, or is still pending review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissibilityStatus {
    Admissible,
    Challenged,
    Excluded,
    Pending,
}

/// A single link in the chain of custody recording a transfer between two parties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyTransfer {
    pub from: Did,
    pub to: Did,
    pub timestamp: Timestamp,
    pub reason: String,
}

/// Litigation-grade evidence item with content hash, creator provenance, and custody chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub type_tag: String,
    pub hash: Hash256,
    pub creator: Did,
    pub timestamp: Timestamp,
    pub chain_of_custody: Vec<CustodyTransfer>,
    pub admissibility_status: AdmissibilityStatus,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceCustodyTransferDigestPayload {
    from: Did,
    to: Did,
    timestamp: Timestamp,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceCustodyChainDigestPayload {
    domain: &'static str,
    schema_version: u16,
    evidence_id: Uuid,
    type_tag: String,
    content_hash: Hash256,
    creator: Did,
    created_at: Timestamp,
    admissibility_status: AdmissibilityStatus,
    transfers: Vec<EvidenceCustodyTransferDigestPayload>,
}

fn validate_evidence_metadata(id: Uuid, type_tag: &str, timestamp: Timestamp) -> Result<()> {
    if id.is_nil() {
        return Err(LegalError::InvalidStateTransition {
            reason: "evidence ID must be caller-supplied and non-nil".into(),
        });
    }
    if type_tag.trim().is_empty() {
        return Err(LegalError::InvalidStateTransition {
            reason: "evidence type_tag must not be empty".into(),
        });
    }
    if timestamp == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "evidence timestamp must not be Timestamp::ZERO; provide a real HLC timestamp"
                .into(),
        });
    }
    Ok(())
}

/// Create evidence with a real HLC timestamp.
///
/// # Errors
/// Returns `LegalError` if the timestamp is `Timestamp::ZERO` (placeholder).
/// Evidence must carry a real timestamp for litigation-grade provenance.
pub fn create_evidence(
    id: Uuid,
    data: &[u8],
    creator: &Did,
    type_tag: &str,
    timestamp: Timestamp,
) -> Result<Evidence> {
    validate_evidence_metadata(id, type_tag, timestamp)?;
    Ok(Evidence {
        id,
        type_tag: type_tag.to_string(),
        hash: Hash256::digest(data),
        creator: creator.clone(),
        timestamp,
        chain_of_custody: Vec::new(),
        admissibility_status: AdmissibilityStatus::Pending,
    })
}

/// Create evidence when the caller already has the canonical content hash.
///
/// # Errors
/// Returns `LegalError` if the ID, type tag, timestamp, or hash is a placeholder.
pub fn create_evidence_from_hash(
    id: Uuid,
    content_hash: Hash256,
    creator: &Did,
    type_tag: &str,
    timestamp: Timestamp,
) -> Result<Evidence> {
    validate_evidence_metadata(id, type_tag, timestamp)?;
    if content_hash == Hash256::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "evidence content hash must not be Hash256::ZERO".into(),
        });
    }
    Ok(Evidence {
        id,
        type_tag: type_tag.to_string(),
        hash: content_hash,
        creator: creator.clone(),
        timestamp,
        chain_of_custody: Vec::new(),
        admissibility_status: AdmissibilityStatus::Pending,
    })
}

/// Transfers custody of evidence from the current holder to a new party, appending to the chain.
pub fn transfer_custody(
    evidence: &mut Evidence,
    from: &Did,
    to: &Did,
    timestamp: Timestamp,
    reason: &str,
) -> Result<()> {
    if timestamp == Timestamp::ZERO {
        return Err(LegalError::CustodyTransferFailed {
            reason: "custody transfer timestamp must not be Timestamp::ZERO".into(),
        });
    }
    if reason.trim().is_empty() {
        return Err(LegalError::CustodyTransferFailed {
            reason: "custody transfer reason must not be empty".into(),
        });
    }
    let current = evidence
        .chain_of_custody
        .last()
        .map(|t| &t.to)
        .unwrap_or(&evidence.creator);
    if current != from {
        return Err(LegalError::CustodyTransferFailed {
            reason: format!("current custodian is {current}, not {from}"),
        });
    }
    let previous_timestamp = evidence
        .chain_of_custody
        .last()
        .map(|t| t.timestamp)
        .unwrap_or(evidence.timestamp);
    if timestamp <= previous_timestamp {
        return Err(LegalError::CustodyTransferFailed {
            reason: format!(
                "custody transfer timestamp {timestamp} must be after previous timestamp {previous_timestamp}"
            ),
        });
    }
    evidence.chain_of_custody.push(CustodyTransfer {
        from: from.clone(),
        to: to.clone(),
        timestamp,
        reason: reason.to_string(),
    });
    Ok(())
}

/// Validates that every custody transfer forms an unbroken chain from the original creator.
pub fn verify_chain_of_custody(evidence: &Evidence) -> Result<()> {
    let mut expected = &evidence.creator;
    for (i, transfer) in evidence.chain_of_custody.iter().enumerate() {
        if &transfer.from != expected {
            return Err(LegalError::CustodyChainBroken { index: i });
        }
        expected = &transfer.to;
    }
    Ok(())
}

fn evidence_custody_chain_digest_payload(evidence: &Evidence) -> EvidenceCustodyChainDigestPayload {
    EvidenceCustodyChainDigestPayload {
        domain: EVIDENCE_CUSTODY_CHAIN_DIGEST_DOMAIN,
        schema_version: EVIDENCE_CUSTODY_CHAIN_DIGEST_SCHEMA_VERSION,
        evidence_id: evidence.id,
        type_tag: evidence.type_tag.clone(),
        content_hash: evidence.hash,
        creator: evidence.creator.clone(),
        created_at: evidence.timestamp,
        admissibility_status: evidence.admissibility_status.clone(),
        transfers: evidence
            .chain_of_custody
            .iter()
            .map(|transfer| EvidenceCustodyTransferDigestPayload {
                from: transfer.from.clone(),
                to: transfer.to.clone(),
                timestamp: transfer.timestamp,
                reason: transfer.reason.clone(),
            })
            .collect(),
    }
}

/// Computes a domain-separated canonical CBOR digest for the evidence custody chain.
///
/// # Errors
/// Returns `LegalError` if the custody chain is broken or canonical CBOR hashing fails.
pub fn custody_chain_digest(evidence: &Evidence) -> Result<Hash256> {
    verify_chain_of_custody(evidence)?;
    hash_structured(&evidence_custody_chain_digest_payload(evidence)).map_err(|e| {
        LegalError::EvidenceHashEncodingFailed {
            reason: format!("evidence custody-chain canonical CBOR hash failed: {e}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn create_uses_caller_supplied_id() {
        let evidence_id = id(0x100);
        let ev = create_evidence(evidence_id, b"doc", &did("a"), "contract", ts(1000)).unwrap();
        assert_eq!(ev.id, evidence_id);
    }

    #[test]
    fn create_rejects_nil_id() {
        let result = create_evidence(Uuid::nil(), b"doc", &did("a"), "contract", ts(1000));
        assert!(result.is_err());
    }

    #[test]
    fn transfer_uses_caller_supplied_timestamp_and_reason() {
        let (a, b) = (did("a"), did("b"));
        let mut ev = create_evidence(id(0x101), b"d", &a, "d", ts(1000)).unwrap();
        transfer_custody(&mut ev, &a, &b, ts(2000), "signed release").unwrap();
        assert_eq!(ev.chain_of_custody[0].timestamp, ts(2000));
        assert_eq!(ev.chain_of_custody[0].reason, "signed release");
    }

    #[test]
    fn transfer_rejects_zero_timestamp() {
        let (a, b) = (did("a"), did("b"));
        let mut ev = create_evidence(id(0x102), b"d", &a, "d", ts(1000)).unwrap();
        assert!(transfer_custody(&mut ev, &a, &b, Timestamp::ZERO, "release").is_err());
    }

    #[test]
    fn create_sets_pending() {
        let ev = create_evidence(id(0x103), b"doc", &did("a"), "contract", ts(1000)).unwrap();
        assert_eq!(ev.admissibility_status, AdmissibilityStatus::Pending);
        assert_eq!(ev.type_tag, "contract");
        assert!(ev.chain_of_custody.is_empty());
    }
    #[test]
    fn create_hashes_data() {
        let ev = create_evidence(id(0x104), b"x", &did("a"), "d", ts(1000)).unwrap();
        assert_eq!(ev.hash, Hash256::digest(b"x"));
    }
    #[test]
    fn create_evidence_from_hash_uses_caller_supplied_hash() {
        let evidence_hash = Hash256::digest(b"already-hashed-evidence");
        let ev =
            create_evidence_from_hash(id(0x120), evidence_hash, &did("a"), "d", ts(1000)).unwrap();
        assert_eq!(ev.hash, evidence_hash);
        assert_eq!(ev.id, id(0x120));
        assert_eq!(ev.creator, did("a"));
        assert_eq!(ev.timestamp, ts(1000));
    }
    #[test]
    fn create_evidence_from_hash_rejects_zero_hash() {
        let result = create_evidence_from_hash(id(0x121), Hash256::ZERO, &did("a"), "d", ts(1000));
        assert!(result.is_err());
    }
    #[test]
    fn create_rejects_zero_timestamp() {
        let result = create_evidence(id(0x105), b"d", &did("a"), "d", Timestamp::ZERO);
        assert!(result.is_err());
    }
    #[test]
    fn create_stores_real_timestamp() {
        let ev = create_evidence(id(0x106), b"d", &did("a"), "d", ts(42000)).unwrap();
        assert_eq!(ev.timestamp, ts(42000));
    }
    #[test]
    fn transfer_success() {
        let (a, b) = (did("a"), did("b"));
        let mut ev = create_evidence(id(0x107), b"d", &a, "d", ts(1000)).unwrap();
        transfer_custody(&mut ev, &a, &b, ts(2000), "custody transfer").unwrap();
        assert_eq!(ev.chain_of_custody.len(), 1);
    }
    #[test]
    fn transfer_chain() {
        let (a, b, c) = (did("a"), did("b"), did("c"));
        let mut ev = create_evidence(id(0x108), b"d", &a, "d", ts(1000)).unwrap();
        transfer_custody(&mut ev, &a, &b, ts(2000), "first transfer").unwrap();
        transfer_custody(&mut ev, &b, &c, ts(3000), "second transfer").unwrap();
        assert_eq!(ev.chain_of_custody.len(), 2);
    }
    #[test]
    fn transfer_wrong_holder() {
        let (a, b, c) = (did("a"), did("b"), did("c"));
        let mut ev = create_evidence(id(0x109), b"d", &a, "d", ts(1000)).unwrap();
        assert!(transfer_custody(&mut ev, &c, &b, ts(2000), "bad transfer").is_err());
    }
    #[test]
    fn verify_empty_ok() {
        let ev = create_evidence(id(0x10a), b"d", &did("a"), "d", ts(1000)).unwrap();
        verify_chain_of_custody(&ev).unwrap();
    }
    #[test]
    fn verify_valid() {
        let (a, b) = (did("a"), did("b"));
        let mut ev = create_evidence(id(0x10b), b"d", &a, "d", ts(1000)).unwrap();
        transfer_custody(&mut ev, &a, &b, ts(2000), "custody transfer").unwrap();
        verify_chain_of_custody(&ev).unwrap();
    }
    #[test]
    fn verify_broken() {
        let (a, b, c) = (did("a"), did("b"), did("c"));
        let mut ev = create_evidence(id(0x10c), b"d", &a, "d", ts(1000)).unwrap();
        ev.chain_of_custody.push(CustodyTransfer {
            from: c,
            to: b,
            timestamp: Timestamp::new(1, 0),
            reason: "bad".into(),
        });
        assert!(verify_chain_of_custody(&ev).is_err());
    }
    #[test]
    fn admissibility_serde() {
        for s in &[
            AdmissibilityStatus::Admissible,
            AdmissibilityStatus::Challenged,
            AdmissibilityStatus::Excluded,
            AdmissibilityStatus::Pending,
        ] {
            let j = serde_json::to_string(s).unwrap();
            let r: AdmissibilityStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(&r, s);
        }
    }
    #[test]
    fn custody_transfer_serde() {
        let ct = CustodyTransfer {
            from: did("a"),
            to: did("b"),
            timestamp: Timestamp::new(100, 0),
            reason: "h".into(),
        };
        let j = serde_json::to_string(&ct).unwrap();
        let r: CustodyTransfer = serde_json::from_str(&j).unwrap();
        assert_eq!(r, ct);
    }
    #[test]
    fn timestamps_increase() {
        let (a, b, c) = (did("a"), did("b"), did("c"));
        let mut ev = create_evidence(id(0x10d), b"d", &a, "d", ts(1000)).unwrap();
        transfer_custody(&mut ev, &a, &b, ts(2000), "first transfer").unwrap();
        transfer_custody(&mut ev, &b, &c, ts(3000), "second transfer").unwrap();
        assert!(ev.chain_of_custody[1].timestamp > ev.chain_of_custody[0].timestamp);
    }
    #[test]
    fn custody_chain_digest_binds_transfer_reason_and_logical_time() {
        let evidence_hash = Hash256::digest(b"evidence-hash");
        let (a, b) = (did("a"), did("b"));
        let mut ev_a =
            create_evidence_from_hash(id(0x122), evidence_hash, &a, "d", ts(1000)).unwrap();
        let mut ev_b =
            create_evidence_from_hash(id(0x122), evidence_hash, &a, "d", ts(1000)).unwrap();

        transfer_custody(&mut ev_a, &a, &b, Timestamp::new(2000, 0), "first transfer").unwrap();
        transfer_custody(
            &mut ev_b,
            &a,
            &b,
            Timestamp::new(2000, 1),
            "alternate transfer",
        )
        .unwrap();

        assert_ne!(
            custody_chain_digest(&ev_a).unwrap(),
            custody_chain_digest(&ev_b).unwrap()
        );
    }
}

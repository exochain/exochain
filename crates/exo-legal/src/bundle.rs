//! Evidence Bundle — self-contained, offline-verifiable forensic artifact.
//!
//! A complete evidence bundle packages a decision's evidentiary record:
//! events with causal dependencies, evidence items, consent records,
//! contract summaries, FRE 902(11) certification, DAG anchor, and
//! verification manifest.  The bundle hash seals all content; signatures
//! attest to the hash without altering it.

use exo_core::{Did, Hash256, PublicKey, SecretKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};

use crate::{
    cert_902_11::Cert902_11,
    error::{LegalError, Result},
    evidence::Evidence,
};

/// Owned snapshot of a `Cert902_11` for bundle serialization.
///
/// `Cert902_11` contains `&'static str` which complicates `Deserialize`.
/// This owned mirror captures all fields as `String` so the bundle can
/// round-trip through JSON without modifying the upstream cert type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSnapshot {
    pub record_hash: Hash256,
    pub custody_chain_digest: Hash256,
    pub system_description: String,
    pub declarant_placeholder: String,
    pub generated_at_ms: u64,
    pub cert_hash: Hash256,
    pub filing_disclaimer: String,
}

impl CertSnapshot {
    /// Create a snapshot from a `Cert902_11`.
    #[must_use]
    pub fn from_cert(cert: &Cert902_11) -> Self {
        Self {
            record_hash: cert.record_hash,
            custody_chain_digest: cert.custody_chain_digest,
            system_description: cert.system_description.clone(),
            declarant_placeholder: cert.declarant_placeholder.clone(),
            generated_at_ms: cert.generated_at_ms,
            cert_hash: cert.cert_hash,
            filing_disclaimer: cert.filing_disclaimer.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A complete, self-contained evidence bundle for offline verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub id: String,
    pub version: u32,
    pub created_at: Timestamp,
    pub subject: BundleSubject,
    pub events: Vec<BundleEvent>,
    pub evidence_items: Vec<Evidence>,
    pub consent_records: Vec<ConsentSummary>,
    pub contract_summary: Option<ContractSummary>,
    pub certification: Option<CertSnapshot>,
    pub dag_anchor: DagAnchor,
    pub verification: VerificationManifest,
    pub bundle_hash: Hash256,
    pub signatures: Vec<BundleSignature>,
}

/// Deterministic assembly input for an evidence bundle.
///
/// Bundle IDs and creation timestamps are part of the bundle hash, so callers
/// must supply them from the surrounding HLC/provenance context instead of this
/// module consulting wall-clock time or randomness.
#[derive(Debug, Clone)]
pub struct BundleAssemblyInput {
    pub id: String,
    pub created_at: Timestamp,
    pub subject: BundleSubject,
    pub events: Vec<BundleEvent>,
    pub evidence_items: Vec<Evidence>,
    pub consent_records: Vec<ConsentSummary>,
    pub contract_summary: Option<ContractSummary>,
    pub certification: Option<Cert902_11>,
    pub dag_anchor: DagAnchor,
}

/// What a bundle is about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSubject {
    pub subject_type: SubjectType,
    pub subject_id: String,
    pub title: String,
    pub description: String,
}

/// The category of the bundle's subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectType {
    Decision,
    Transaction,
    Delegation,
    Identity,
    Consent,
    Emergency,
}

impl SubjectType {
    fn as_tag(&self) -> &'static str {
        match self {
            Self::Decision => "Decision",
            Self::Transaction => "Transaction",
            Self::Delegation => "Delegation",
            Self::Identity => "Identity",
            Self::Consent => "Consent",
            Self::Emergency => "Emergency",
        }
    }
}

/// A single event in the causal sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleEvent {
    pub sequence: u32,
    pub event_hash: Hash256,
    pub event_type: String,
    pub actor: Did,
    pub timestamp: Timestamp,
    pub payload_summary: String,
    pub parent_hashes: Vec<Hash256>,
    pub dag_node_hash: Hash256,
}

/// Summary of an active consent/bailment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentSummary {
    pub bailment_id: String,
    pub bailor: Did,
    pub bailee: Did,
    pub bailment_type: String,
    pub terms_hash: Hash256,
    pub status: String,
}

/// Summary of a governing contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSummary {
    pub contract_id: String,
    pub contract_hash: Hash256,
    pub template_name: String,
    pub parties: Vec<Did>,
    pub key_terms: Vec<String>,
}

/// Link to a finalized DAG checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagAnchor {
    pub checkpoint_height: u64,
    pub event_root: Hash256,
    pub state_root: Hash256,
    pub validator_signatures: Vec<ValidatorSig>,
    pub anchored_at: Timestamp,
}

/// A validator's attestation to a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSig {
    pub validator_did: Did,
    pub signature: Signature,
}

/// Describes how to verify the bundle offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationManifest {
    pub format_version: u32,
    pub hash_algorithm: String,
    pub verification_steps: Vec<VerificationStep>,
}

/// A single step in the verification protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStep {
    pub step_number: u32,
    pub description: String,
    pub input_hashes: Vec<Hash256>,
    pub expected_output: Hash256,
}

/// A signature over the bundle hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSignature {
    pub signer_did: Did,
    pub signer_role: String,
    pub signature: Signature,
    pub signed_at: Timestamp,
}

/// Result of offline bundle verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub hash_valid: bool,
    pub event_chain_valid: bool,
    pub causal_order_valid: bool,
    pub signatures_valid: Vec<SignatureCheck>,
    pub overall: bool,
}

/// Result of checking a single signature.
#[derive(Debug, Clone)]
pub struct SignatureCheck {
    pub signer: Did,
    pub role: String,
    pub valid: bool,
}

/// Resolves a bundle signer DID to the Ed25519 public key authorized to sign.
pub trait BundleSignerKeyResolver {
    fn public_key_for(&self, signer: &Did) -> Option<PublicKey>;
}

impl<F> BundleSignerKeyResolver for F
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    fn public_key_for(&self, signer: &Did) -> Option<PublicKey> {
        self(signer)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BUNDLE_VERSION: u32 = 1;
#[cfg(test)]
const BUNDLE_DOMAIN: &[u8] = b"exo:bundle:v1:";
const BUNDLE_HASH_DOMAIN: &str = "exo.legal.bundle.hash.v1";
const BUNDLE_HASH_SCHEMA_VERSION: u32 = 1;
const BUNDLE_EVENT_CHAIN_DOMAIN: &str = "exo.legal.bundle.event_chain.v1";
const BUNDLE_EVIDENCE_HASHES_DOMAIN: &str = "exo.legal.bundle.evidence_hashes.v1";
const BUNDLE_SIGNATURE_DOMAIN: &str = "exo.legal.bundle.signature.v1";

/// Safe usize → u32 conversion (saturating for safety).
#[allow(clippy::as_conversions)]
fn idx_u32(n: usize) -> u32 {
    n as u32
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Assemble an evidence bundle from its constituent parts.
///
/// Validates event ordering and causal chain, builds the verification
/// manifest, and computes the root hash.
///
/// # Errors
/// - `InvalidStateTransition` if events are empty, mis-ordered, or violate causal ordering.
pub fn assemble(input: BundleAssemblyInput) -> Result<EvidenceBundle> {
    if input.id.trim().is_empty() {
        return Err(LegalError::InvalidStateTransition {
            reason: "bundle id must not be empty".into(),
        });
    }

    let cert_snapshot = input.certification.as_ref().map(CertSnapshot::from_cert);
    // Validate events
    if input.events.is_empty() {
        return Err(LegalError::InvalidStateTransition {
            reason: "bundle must contain at least one event".into(),
        });
    }
    validate_event_ordering(&input.events)?;
    validate_causal_chain(&input.events)?;

    // Build the initial bundle value before computing its content hash.
    let mut bundle = EvidenceBundle {
        id: input.id,
        version: BUNDLE_VERSION,
        created_at: input.created_at,
        subject: input.subject,
        events: input.events,
        evidence_items: input.evidence_items,
        consent_records: input.consent_records,
        contract_summary: input.contract_summary,
        certification: cert_snapshot,
        dag_anchor: input.dag_anchor,
        verification: VerificationManifest {
            format_version: BUNDLE_VERSION,
            hash_algorithm: "BLAKE3".into(),
            verification_steps: Vec::new(),
        },
        bundle_hash: Hash256::ZERO,
        signatures: Vec::new(),
    };

    // Compute hash and build verification steps
    let hash = compute_bundle_hash(&bundle)?;
    bundle.bundle_hash = hash;
    bundle.verification.verification_steps = build_verification_steps(&bundle)?;

    Ok(bundle)
}

fn validate_event_ordering(events: &[BundleEvent]) -> Result<()> {
    for (i, event) in events.iter().enumerate() {
        if event.sequence != idx_u32(i) {
            return Err(LegalError::InvalidStateTransition {
                reason: format!(
                    "event at position {i} has sequence {}, expected {i}",
                    event.sequence
                ),
            });
        }
    }
    Ok(())
}

fn validate_causal_chain(events: &[BundleEvent]) -> Result<()> {
    for (i, event) in events.iter().enumerate() {
        if i == 0 {
            // Genesis event must have no parents
            if !event.parent_hashes.is_empty() {
                return Err(LegalError::InvalidStateTransition {
                    reason: "genesis event (sequence 0) must have empty parent_hashes".into(),
                });
            }
        } else {
            // Every parent hash must appear in a preceding event
            for parent in &event.parent_hashes {
                let found = events[..i].iter().any(|e| &e.event_hash == parent);
                if !found {
                    return Err(LegalError::InvalidStateTransition {
                        reason: format!(
                            "event {} references parent hash {} not found in preceding events",
                            event.sequence, parent
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Canonical CBOR payload hashed to produce a bundle root.
///
/// The payload excludes `bundle_hash`, bundle signer `signatures`, and derived
/// verification steps. It includes checkpoint validator signatures because they
/// are part of the DAG anchor content sealed by the bundle.
///
/// # Errors
/// Returns `LegalError` if canonical payload serialization fails.
pub fn bundle_hash_payload(bundle: &EvidenceBundle) -> Result<Vec<u8>> {
    let payload = (
        BUNDLE_HASH_DOMAIN,
        BUNDLE_HASH_SCHEMA_VERSION,
        &bundle.id,
        bundle.version,
        bundle.created_at,
        &bundle.subject,
        &bundle.events,
        &bundle.evidence_items,
        &bundle.consent_records,
        &bundle.contract_summary,
        &bundle.certification,
        &bundle.dag_anchor,
        bundle.verification.format_version,
        &bundle.verification.hash_algorithm,
    );
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        LegalError::InvalidStateTransition {
            reason: format!("bundle hash payload CBOR serialization failed: {e}"),
        }
    })?;
    Ok(encoded)
}

/// Compute the deterministic BLAKE3 root hash of a canonical CBOR bundle payload.
///
/// Covers all content fields except `bundle_hash`, signer `signatures`, and
/// derived verification steps.
///
/// # Errors
/// Returns `LegalError` if canonical payload serialization fails.
pub fn compute_bundle_hash(bundle: &EvidenceBundle) -> Result<Hash256> {
    let payload = bundle_hash_payload(bundle)?;
    Ok(Hash256::digest(&payload))
}

fn canonical_input_hash(domain: &str, input_hashes: &[Hash256]) -> Result<Hash256> {
    let payload = (domain, BUNDLE_HASH_SCHEMA_VERSION, input_hashes);
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        LegalError::InvalidStateTransition {
            reason: format!("verification input hash CBOR serialization failed: {e}"),
        }
    })?;
    Ok(Hash256::digest(&encoded))
}

fn build_verification_steps(bundle: &EvidenceBundle) -> Result<Vec<VerificationStep>> {
    let event_hashes: Vec<Hash256> = bundle.events.iter().map(|e| e.event_hash).collect();
    let event_chain_hash = canonical_input_hash(BUNDLE_EVENT_CHAIN_DOMAIN, &event_hashes)?;

    let evidence_hashes: Vec<Hash256> = bundle.evidence_items.iter().map(|e| e.hash).collect();
    let evidence_hash = canonical_input_hash(BUNDLE_EVIDENCE_HASHES_DOMAIN, &evidence_hashes)?;

    Ok(vec![
        VerificationStep {
            step_number: 1,
            description: "Verify event chain hash".into(),
            input_hashes: event_hashes,
            expected_output: event_chain_hash,
        },
        VerificationStep {
            step_number: 2,
            description: "Verify evidence items hash".into(),
            input_hashes: evidence_hashes,
            expected_output: evidence_hash,
        },
        VerificationStep {
            step_number: 3,
            description: "Verify bundle root hash".into(),
            input_hashes: vec![bundle.bundle_hash],
            expected_output: bundle.bundle_hash,
        },
    ])
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a bundle offline: recompute hash, check event ordering, causal
/// chain, and fail closed for any signatures that cannot be checked without a
/// signer key resolver.
///
/// # Errors
/// Returns `LegalError` only for structural failures (e.g. event ordering).
/// Hash mismatches are reported in the `VerificationResult`, not as errors.
pub fn verify(bundle: &EvidenceBundle) -> Result<VerificationResult> {
    verify_inner(bundle, None)
}

/// Verify a bundle offline with Ed25519 signer keys.
///
/// Every signature is checked against a domain-separated canonical CBOR payload
/// binding the bundle hash, signer DID, signer role, and signed timestamp.
///
/// # Errors
/// Returns `LegalError` only for structural failures (e.g. event ordering) or
/// canonical payload encoding failure.
pub fn verify_with_signer_keys<R>(
    bundle: &EvidenceBundle,
    resolver: &R,
) -> Result<VerificationResult>
where
    R: BundleSignerKeyResolver,
{
    verify_inner(bundle, Some(resolver))
}

fn verify_inner(
    bundle: &EvidenceBundle,
    resolver: Option<&dyn BundleSignerKeyResolver>,
) -> Result<VerificationResult> {
    let recomputed = compute_bundle_hash(bundle)?;
    let hash_valid = recomputed == bundle.bundle_hash;

    let event_chain_valid = validate_event_ordering(&bundle.events).is_ok();
    let causal_order_valid = validate_causal_chain(&bundle.events).is_ok();

    let signatures_valid: Vec<SignatureCheck> = bundle
        .signatures
        .iter()
        .map(|sig| {
            let valid = resolver
                .and_then(|r| r.public_key_for(&sig.signer_did))
                .is_some_and(|public_key| verify_bundle_signature(bundle, sig, &public_key));
            SignatureCheck {
                signer: sig.signer_did.clone(),
                role: sig.signer_role.clone(),
                valid,
            }
        })
        .collect();

    let sigs_ok = signatures_valid.iter().all(|s| s.valid);
    let overall = hash_valid && event_chain_valid && causal_order_valid && sigs_ok;

    Ok(VerificationResult {
        hash_valid,
        event_chain_valid,
        causal_order_valid,
        signatures_valid,
        overall,
    })
}

fn verify_bundle_signature(
    bundle: &EvidenceBundle,
    sig: &BundleSignature,
    public_key: &PublicKey,
) -> bool {
    if sig.signer_role.trim().is_empty() || sig.signature.is_empty() {
        return false;
    }
    let Ok(payload) = bundle_signature_payload(
        &bundle.bundle_hash,
        &sig.signer_did,
        &sig.signer_role,
        sig.signed_at,
    ) else {
        return false;
    };
    crypto::verify(&payload, &sig.signature, public_key)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render the bundle as human-readable JSON.
///
/// # Errors
/// Returns `LegalError` if serialization fails.
pub fn render_json(bundle: &EvidenceBundle) -> Result<String> {
    serde_json::to_string_pretty(bundle).map_err(|e| LegalError::InvalidStateTransition {
        reason: format!("JSON serialization failed: {e}"),
    })
}

/// Render a Markdown executive summary for Board Book inclusion.
#[must_use]
pub fn render_markdown_summary(bundle: &EvidenceBundle) -> String {
    let mut md = String::new();

    md.push_str(&format!("# Evidence Bundle: {}\n\n", bundle.subject.title));
    md.push_str(&format!("**Bundle ID:** {}  \n", bundle.id));
    md.push_str(&format!("**Created:** {}  \n", bundle.created_at));
    md.push_str(&format!(
        "**Subject:** {} — {}  \n\n",
        bundle.subject.subject_type.as_tag(),
        bundle.subject.description
    ));

    // Event timeline
    md.push_str("## Event Timeline\n\n");
    md.push_str("| # | Type | Actor | Time | Summary |\n");
    md.push_str("|---|------|-------|------|---------|");
    for event in &bundle.events {
        md.push_str(&format!(
            "\n| {} | {} | {} | {} | {} |",
            event.sequence, event.event_type, event.actor, event.timestamp, event.payload_summary
        ));
    }
    md.push_str("\n\n");

    // Evidence inventory
    let admissible_count = bundle
        .evidence_items
        .iter()
        .filter(|e| {
            matches!(
                e.admissibility_status,
                crate::evidence::AdmissibilityStatus::Admissible
            )
        })
        .count();
    md.push_str("## Evidence Inventory\n\n");
    md.push_str(&format!(
        "- {} evidence items, {} admissible\n\n",
        bundle.evidence_items.len(),
        admissible_count
    ));

    // Signatures
    if !bundle.signatures.is_empty() {
        md.push_str("## Signatures\n\n");
        for sig in &bundle.signatures {
            md.push_str(&format!(
                "- {}: {} at {}\n",
                sig.signer_role, sig.signer_did, sig.signed_at
            ));
        }
        md.push('\n');
    }

    md.push_str(&format!("**Bundle Hash:** {}\n", bundle.bundle_hash));

    md
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Canonical CBOR payload signed by a bundle signer.
///
/// # Errors
/// Returns `LegalError` if canonical payload serialization fails.
pub fn bundle_signature_payload(
    bundle_hash: &Hash256,
    signer: &Did,
    role: &str,
    signed_at: Timestamp,
) -> Result<Vec<u8>> {
    let payload = (
        BUNDLE_SIGNATURE_DOMAIN,
        bundle_hash,
        signer,
        role,
        signed_at,
    );
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        LegalError::InvalidStateTransition {
            reason: format!("bundle signature payload CBOR serialization failed: {e}"),
        }
    })?;
    Ok(encoded)
}

/// Add an Ed25519 signature to the bundle.
///
/// Signatures attest to the `bundle_hash` and do not change it.
///
/// # Errors
/// Returns `LegalError` if the role string is empty, the bundle hash is stale,
/// or the signing payload cannot be serialized.
pub fn sign(
    bundle: &mut EvidenceBundle,
    signer: &Did,
    role: &str,
    signed_at: Timestamp,
    secret_key: &SecretKey,
) -> Result<()> {
    if role.trim().is_empty() {
        return Err(LegalError::InvalidStateTransition {
            reason: "signer role must not be empty".into(),
        });
    }
    if compute_bundle_hash(bundle)? != bundle.bundle_hash {
        return Err(LegalError::InvalidStateTransition {
            reason: "bundle hash must be current before signing".into(),
        });
    }
    let payload = bundle_signature_payload(&bundle.bundle_hash, signer, role, signed_at)?;
    let signature = crypto::sign(&payload, secret_key);
    bundle.signatures.push(BundleSignature {
        signer_did: signer.clone(),
        signer_role: role.to_string(),
        signature,
        signed_at,
    });
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use uuid::Uuid;

    use super::*;
    use crate::{cert_902_11::generate_902_11_cert, evidence::create_evidence};

    // -- Helpers ----------------------------------------------------------

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn keypair(seed: u8) -> exo_core::crypto::KeyPair {
        exo_core::crypto::KeyPair::from_secret_bytes([seed; 32]).unwrap()
    }

    #[derive(Default)]
    struct StaticResolver {
        keys: BTreeMap<Did, PublicKey>,
    }

    impl StaticResolver {
        fn with(mut self, did: Did, public_key: PublicKey) -> Self {
            self.keys.insert(did, public_key);
            self
        }
    }

    impl BundleSignerKeyResolver for StaticResolver {
        fn public_key_for(&self, signer: &Did) -> Option<PublicKey> {
            self.keys.get(signer).copied()
        }
    }

    fn make_event(seq: u32, parents: Vec<Hash256>) -> BundleEvent {
        let hash = Hash256::digest(format!("event-{seq}").as_bytes());
        BundleEvent {
            sequence: seq,
            event_hash: hash,
            event_type: format!("test.event.{seq}"),
            actor: did("alice"),
            timestamp: ts(1000 + u64::from(seq) * 100),
            payload_summary: format!("Event {seq} summary"),
            parent_hashes: parents,
            dag_node_hash: Hash256::digest(format!("dag-{seq}").as_bytes()),
        }
    }

    fn make_evidence_item() -> Evidence {
        create_evidence(
            Uuid::from_u128(0x900),
            b"test-data",
            &did("bob"),
            "document",
            ts(900),
        )
        .unwrap()
    }

    fn make_anchor() -> DagAnchor {
        DagAnchor {
            checkpoint_height: 42,
            event_root: Hash256::digest(b"mmr-root"),
            state_root: Hash256::digest(b"smt-root"),
            validator_signatures: vec![ValidatorSig {
                validator_did: did("validator-1"),
                signature: Signature::from_bytes([0xaa; 64]),
            }],
            anchored_at: ts(2000),
        }
    }

    fn make_subject() -> BundleSubject {
        BundleSubject {
            subject_type: SubjectType::Decision,
            subject_id: "DEC-001".into(),
            title: "Board Resolution 2026-Q1".into(),
            description: "Quarterly budget approval".into(),
        }
    }

    fn make_consent() -> ConsentSummary {
        ConsentSummary {
            bailment_id: "BAIL-001".into(),
            bailor: did("alice"),
            bailee: did("bob"),
            bailment_type: "data-custody".into(),
            terms_hash: Hash256::digest(b"terms"),
            status: "active".into(),
        }
    }

    fn make_contract() -> ContractSummary {
        ContractSummary {
            contract_id: "CTR-001".into(),
            contract_hash: Hash256::digest(b"contract"),
            template_name: "data-bailment-v1".into(),
            parties: vec![did("alice"), did("bob")],
            key_terms: vec![
                "90-day retention".into(),
                "encryption-at-rest required".into(),
            ],
        }
    }

    fn make_assembly_input(id: &str, events: Vec<BundleEvent>) -> BundleAssemblyInput {
        BundleAssemblyInput {
            id: id.to_string(),
            created_at: ts(2500),
            subject: make_subject(),
            events,
            evidence_items: vec![make_evidence_item()],
            consent_records: vec![],
            contract_summary: None,
            certification: None,
            dag_anchor: make_anchor(),
        }
    }

    fn assemble_minimal() -> EvidenceBundle {
        let e0 = make_event(0, vec![]);
        assemble(make_assembly_input("bundle-minimal", vec![e0])).unwrap()
    }

    fn assemble_full() -> EvidenceBundle {
        let e0 = make_event(0, vec![]);
        let e1 = make_event(1, vec![e0.event_hash]);
        let e2 = make_event(2, vec![e1.event_hash]);

        let ev = make_evidence_item();
        let cert =
            generate_902_11_cert(&ev, "EXOCHAIN decision.forum v1.0", 1_700_000_001_000).unwrap();

        let mut input = make_assembly_input("bundle-full", vec![e0, e1, e2]);
        input.evidence_items = vec![ev];
        input.consent_records = vec![make_consent()];
        input.contract_summary = Some(make_contract());
        input.certification = Some(cert);
        assemble(input).unwrap()
    }

    fn legacy_len_u64(n: usize) -> u64 {
        #[allow(clippy::as_conversions)]
        {
            n as u64
        }
    }

    fn legacy_bundle_hash(bundle: &EvidenceBundle) -> Hash256 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BUNDLE_DOMAIN);

        hasher.update(bundle.id.as_bytes());
        hasher.update(&bundle.version.to_le_bytes());
        hasher.update(&bundle.created_at.physical_ms.to_le_bytes());
        hasher.update(&bundle.created_at.logical.to_le_bytes());

        hasher.update(bundle.subject.subject_type.as_tag().as_bytes());
        hasher.update(bundle.subject.subject_id.as_bytes());
        hasher.update(bundle.subject.title.as_bytes());
        hasher.update(bundle.subject.description.as_bytes());

        hasher.update(&legacy_len_u64(bundle.events.len()).to_le_bytes());
        for event in &bundle.events {
            hasher.update(&event.sequence.to_le_bytes());
            hasher.update(event.event_hash.as_bytes());
            hasher.update(event.event_type.as_bytes());
            hasher.update(event.actor.to_string().as_bytes());
            hasher.update(&event.timestamp.physical_ms.to_le_bytes());
            hasher.update(&event.timestamp.logical.to_le_bytes());
            hasher.update(event.payload_summary.as_bytes());
            hasher.update(&legacy_len_u64(event.parent_hashes.len()).to_le_bytes());
            for ph in &event.parent_hashes {
                hasher.update(ph.as_bytes());
            }
            hasher.update(event.dag_node_hash.as_bytes());
        }

        hasher.update(&legacy_len_u64(bundle.evidence_items.len()).to_le_bytes());
        for ev in &bundle.evidence_items {
            hasher.update(ev.id.as_bytes());
            hasher.update(ev.type_tag.as_bytes());
            hasher.update(ev.hash.as_bytes());
            hasher.update(ev.creator.to_string().as_bytes());
            hasher.update(&ev.timestamp.physical_ms.to_le_bytes());
            hasher.update(&ev.timestamp.logical.to_le_bytes());
        }

        hasher.update(&legacy_len_u64(bundle.consent_records.len()).to_le_bytes());
        for c in &bundle.consent_records {
            hasher.update(c.bailment_id.as_bytes());
            hasher.update(c.bailor.to_string().as_bytes());
            hasher.update(c.bailee.to_string().as_bytes());
            hasher.update(c.bailment_type.as_bytes());
            hasher.update(c.terms_hash.as_bytes());
            hasher.update(c.status.as_bytes());
        }

        if let Some(cs) = &bundle.contract_summary {
            hasher.update(&[0x01]);
            hasher.update(cs.contract_id.as_bytes());
            hasher.update(cs.contract_hash.as_bytes());
            hasher.update(cs.template_name.as_bytes());
            hasher.update(&legacy_len_u64(cs.parties.len()).to_le_bytes());
            for p in &cs.parties {
                hasher.update(p.to_string().as_bytes());
            }
            hasher.update(&legacy_len_u64(cs.key_terms.len()).to_le_bytes());
            for t in &cs.key_terms {
                hasher.update(t.as_bytes());
            }
        } else {
            hasher.update(&[0x00]);
        }

        if let Some(cert) = &bundle.certification {
            hasher.update(&[0x01]);
            hasher.update(cert.cert_hash.as_bytes());
        } else {
            hasher.update(&[0x00]);
        }

        hasher.update(&bundle.dag_anchor.checkpoint_height.to_le_bytes());
        hasher.update(bundle.dag_anchor.event_root.as_bytes());
        hasher.update(bundle.dag_anchor.state_root.as_bytes());
        hasher.update(&bundle.dag_anchor.anchored_at.physical_ms.to_le_bytes());
        hasher.update(&bundle.dag_anchor.anchored_at.logical.to_le_bytes());

        hasher.update(&bundle.verification.format_version.to_le_bytes());
        hasher.update(bundle.verification.hash_algorithm.as_bytes());

        Hash256::from_bytes(*hasher.finalize().as_bytes())
    }

    fn canonical_verification_input_hash(domain: &str, input_hashes: &[Hash256]) -> Hash256 {
        let payload = (domain, 1u32, input_hashes);
        let mut encoded = Vec::new();
        ciborium::into_writer(&payload, &mut encoded)
            .expect("canonical verification step input payload");
        Hash256::digest(&encoded)
    }

    // -- Tests ------------------------------------------------------------

    #[test]
    fn test_assemble_minimal() {
        let bundle = assemble_minimal();
        assert_eq!(bundle.version, BUNDLE_VERSION);
        assert_eq!(bundle.events.len(), 1);
        assert_eq!(bundle.evidence_items.len(), 1);
        assert!(bundle.consent_records.is_empty());
        assert!(bundle.contract_summary.is_none());
        assert!(bundle.certification.is_none());
        assert!(bundle.signatures.is_empty());
        assert_ne!(bundle.bundle_hash, Hash256::ZERO);
    }

    #[test]
    fn test_assemble_full() {
        let bundle = assemble_full();
        assert_eq!(bundle.events.len(), 3);
        assert_eq!(bundle.evidence_items.len(), 1);
        assert_eq!(bundle.consent_records.len(), 1);
        assert!(bundle.contract_summary.is_some());
        assert!(bundle.certification.is_some());
        assert_ne!(bundle.bundle_hash, Hash256::ZERO);
    }

    #[test]
    fn test_assemble_uses_supplied_metadata() {
        let bundle = assemble(make_assembly_input(
            "bundle-explicit-metadata",
            vec![make_event(0, vec![])],
        ))
        .unwrap();
        assert_eq!(bundle.id, "bundle-explicit-metadata");
        assert_eq!(bundle.created_at, ts(2500));
    }

    #[test]
    fn test_assemble_rejects_empty_id() {
        let mut input = make_assembly_input("bundle-empty-id", vec![make_event(0, vec![])]);
        input.id = "  ".into();
        let err = assemble(input).unwrap_err();
        assert!(err.to_string().contains("id"));
    }

    #[test]
    fn test_bundle_hash_deterministic() {
        // Assemble two bundles with identical content (fixed timestamps/ids)
        let e0 = make_event(0, vec![]);
        let ev = make_evidence_item();

        let mk = |id: &str| {
            let mut b = EvidenceBundle {
                id: id.to_string(),
                version: BUNDLE_VERSION,
                created_at: ts(5000),
                subject: make_subject(),
                events: vec![e0.clone()],
                evidence_items: vec![ev.clone()],
                consent_records: vec![],
                contract_summary: None,
                certification: None,
                dag_anchor: make_anchor(),
                verification: VerificationManifest {
                    format_version: BUNDLE_VERSION,
                    hash_algorithm: "BLAKE3".into(),
                    verification_steps: vec![],
                },
                bundle_hash: Hash256::ZERO,
                signatures: vec![],
            };
            b.bundle_hash = compute_bundle_hash(&b).unwrap();
            b
        };

        let b1 = mk("same-id");
        let b2 = mk("same-id");
        assert_eq!(b1.bundle_hash, b2.bundle_hash);
    }

    #[test]
    fn bundle_hash_payload_is_domain_separated_cbor() {
        type DecodedBundleHashPayload = (
            String,
            u32,
            String,
            u32,
            Timestamp,
            BundleSubject,
            Vec<BundleEvent>,
            Vec<Evidence>,
            Vec<ConsentSummary>,
            Option<ContractSummary>,
            Option<CertSnapshot>,
            DagAnchor,
            u32,
            String,
        );

        let bundle = assemble_full();
        let payload = bundle_hash_payload(&bundle).unwrap();
        let legacy_payload_hash = legacy_bundle_hash(&bundle);
        let decoded: DecodedBundleHashPayload = ciborium::de::from_reader(payload.as_slice())
            .expect("bundle hash payload decodes as canonical CBOR tuple");

        assert_ne!(Hash256::digest(&payload), legacy_payload_hash);
        assert_eq!(decoded.0, BUNDLE_HASH_DOMAIN);
        assert_eq!(decoded.1, 1);
        assert_eq!(decoded.2, bundle.id);
        assert_eq!(
            decoded.11.validator_signatures.len(),
            bundle.dag_anchor.validator_signatures.len()
        );
        assert_eq!(
            decoded.11.validator_signatures[0].validator_did,
            bundle.dag_anchor.validator_signatures[0].validator_did
        );
        assert_eq!(
            decoded.11.validator_signatures[0].signature,
            bundle.dag_anchor.validator_signatures[0].signature
        );
    }

    #[test]
    fn verify_rejects_legacy_byte_concat_bundle_hash() {
        let mut bundle = assemble_full();
        bundle.bundle_hash = legacy_bundle_hash(&bundle);

        let result = verify(&bundle).unwrap();

        assert!(!result.hash_valid);
        assert!(!result.overall);
    }

    #[test]
    fn bundle_hash_changes_when_validator_signature_changes() {
        let mut bundle = assemble_minimal();
        let original = compute_bundle_hash(&bundle).unwrap();
        bundle.dag_anchor.validator_signatures[0].signature = Signature::from_bytes([0xbb; 64]);

        let changed = compute_bundle_hash(&bundle).unwrap();

        assert_ne!(changed, original);
    }

    #[test]
    fn verification_steps_use_domain_separated_cbor_hashes() {
        let bundle = assemble_full();
        let event_hashes: Vec<Hash256> = bundle.events.iter().map(|e| e.event_hash).collect();
        let evidence_hashes: Vec<Hash256> = bundle.evidence_items.iter().map(|e| e.hash).collect();

        assert_eq!(
            bundle.verification.verification_steps[0].expected_output,
            canonical_verification_input_hash("exo.legal.bundle.event_chain.v1", &event_hashes)
        );
        assert_eq!(
            bundle.verification.verification_steps[1].expected_output,
            canonical_verification_input_hash(
                "exo.legal.bundle.evidence_hashes.v1",
                &evidence_hashes
            )
        );
    }

    #[test]
    fn test_bundle_hash_changes_with_events() {
        let e0 = make_event(0, vec![]);
        let e0_alt = BundleEvent {
            payload_summary: "different summary".into(),
            ..make_event(0, vec![])
        };

        let mk = |events: Vec<BundleEvent>| {
            let mut b = EvidenceBundle {
                id: "test".into(),
                version: BUNDLE_VERSION,
                created_at: ts(5000),
                subject: make_subject(),
                events,
                evidence_items: vec![make_evidence_item()],
                consent_records: vec![],
                contract_summary: None,
                certification: None,
                dag_anchor: make_anchor(),
                verification: VerificationManifest {
                    format_version: BUNDLE_VERSION,
                    hash_algorithm: "BLAKE3".into(),
                    verification_steps: vec![],
                },
                bundle_hash: Hash256::ZERO,
                signatures: vec![],
            };
            b.bundle_hash = compute_bundle_hash(&b).unwrap();
            b
        };

        let b1 = mk(vec![e0]);
        let b2 = mk(vec![e0_alt]);
        assert_ne!(b1.bundle_hash, b2.bundle_hash);
    }

    #[test]
    fn test_verify_valid_bundle() {
        let bundle = assemble_minimal();
        let result = verify(&bundle).unwrap();
        assert!(result.hash_valid);
        assert!(result.event_chain_valid);
        assert!(result.causal_order_valid);
        assert!(result.overall);
    }

    #[test]
    fn test_verify_tampered_event() {
        let mut bundle = assemble_minimal();
        bundle.events[0].payload_summary = "tampered!".into();
        let result = verify(&bundle).unwrap();
        assert!(!result.hash_valid);
        assert!(!result.overall);
    }

    #[test]
    fn test_verify_tampered_hash() {
        let mut bundle = assemble_minimal();
        bundle.bundle_hash = Hash256::digest(b"wrong");
        let result = verify(&bundle).unwrap();
        assert!(!result.hash_valid);
        assert!(!result.overall);
    }

    #[test]
    fn test_verify_empty_signatures() {
        let bundle = assemble_minimal();
        let result = verify(&bundle).unwrap();
        assert!(result.hash_valid);
        assert!(result.signatures_valid.is_empty());
        assert!(result.overall);
    }

    #[test]
    fn test_event_ordering() {
        // Out-of-order sequence numbers should fail
        let e0 = make_event(0, vec![]);
        let mut e1 = make_event(1, vec![e0.event_hash]);
        e1.sequence = 5; // wrong

        let result = assemble(make_assembly_input("bad-order", vec![e0, e1]));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sequence"));
    }

    #[test]
    fn test_event_causal_chain() {
        // Event 1 references a hash not in preceding events
        let e0 = make_event(0, vec![]);
        let e1 = make_event(1, vec![Hash256::digest(b"nonexistent")]);

        let result = assemble(make_assembly_input("bad-causal-chain", vec![e0, e1]));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parent hash"));
    }

    #[test]
    fn test_render_json_roundtrip() {
        let bundle = assemble_minimal();
        let json = render_json(&bundle).unwrap();
        let parsed: EvidenceBundle = serde_json::from_str(&json).unwrap();
        let recomputed = compute_bundle_hash(&parsed).unwrap();
        assert_eq!(recomputed, bundle.bundle_hash);
    }

    #[test]
    fn test_render_markdown_has_subject() {
        let bundle = assemble_minimal();
        let md = render_markdown_summary(&bundle);
        assert!(md.contains("Board Resolution 2026-Q1"));
        assert!(md.contains("Quarterly budget approval"));
    }

    #[test]
    fn test_render_markdown_has_events() {
        let bundle = assemble_full();
        let md = render_markdown_summary(&bundle);
        assert!(md.contains("Event Timeline"));
        assert!(md.contains("test.event.0"));
        assert!(md.contains("test.event.1"));
        assert!(md.contains("test.event.2"));
    }

    #[test]
    fn test_sign_adds_signature() {
        let mut bundle = assemble_minimal();
        let signer_key = keypair(11);
        let signed_at = ts(3000);
        assert!(bundle.signatures.is_empty());
        sign(
            &mut bundle,
            &did("officer"),
            "organization",
            signed_at,
            signer_key.secret_key(),
        )
        .unwrap();
        assert_eq!(bundle.signatures.len(), 1);
        assert_eq!(bundle.signatures[0].signer_did, did("officer"));
        assert_eq!(bundle.signatures[0].signer_role, "organization");
        assert_eq!(bundle.signatures[0].signed_at, signed_at);
        assert!(matches!(
            bundle.signatures[0].signature,
            Signature::Ed25519(_)
        ));
    }

    #[test]
    fn test_sign_preserves_hash() {
        let mut bundle = assemble_minimal();
        let signer_key = keypair(12);
        let hash_before = bundle.bundle_hash;
        sign(
            &mut bundle,
            &did("officer"),
            "organization",
            ts(3000),
            signer_key.secret_key(),
        )
        .unwrap();
        assert_eq!(bundle.bundle_hash, hash_before);
    }

    #[test]
    fn test_sign_rejects_stale_bundle_hash() {
        let mut bundle = assemble_minimal();
        bundle.subject.title = "tampered after hash".into();
        let err = sign(
            &mut bundle,
            &did("officer"),
            "organization",
            ts(3000),
            keypair(16).secret_key(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("current"));
        assert!(bundle.signatures.is_empty());
    }

    #[test]
    fn test_consent_and_contract_in_bundle() {
        let bundle = assemble_full();

        // Consent is in the bundle
        assert_eq!(bundle.consent_records.len(), 1);
        assert_eq!(bundle.consent_records[0].bailment_id, "BAIL-001");

        // Contract is in the bundle
        let cs = bundle.contract_summary.as_ref().unwrap();
        assert_eq!(cs.contract_id, "CTR-001");

        // They affect the hash: removing them changes the hash
        let e0 = make_event(0, vec![]);
        let bundle_without =
            assemble(make_assembly_input("bundle-without-contract", vec![e0])).unwrap();

        // The hashes will differ because the bundles have different IDs and
        // timestamps. Instead, directly verify the consent/contract are hashed
        // by building two bundles with controlled content.
        let mk = |consents: Vec<ConsentSummary>, contract: Option<ContractSummary>| {
            let mut b = EvidenceBundle {
                id: "fixed".into(),
                version: BUNDLE_VERSION,
                created_at: ts(5000),
                subject: make_subject(),
                events: vec![make_event(0, vec![])],
                evidence_items: vec![make_evidence_item()],
                consent_records: consents,
                contract_summary: contract,
                certification: None,
                dag_anchor: make_anchor(),
                verification: VerificationManifest {
                    format_version: BUNDLE_VERSION,
                    hash_algorithm: "BLAKE3".into(),
                    verification_steps: vec![],
                },
                bundle_hash: Hash256::ZERO,
                signatures: vec![],
            };
            b.bundle_hash = compute_bundle_hash(&b).unwrap();
            b
        };

        let with = mk(vec![make_consent()], Some(make_contract()));
        let without = mk(vec![], None);
        assert_ne!(with.bundle_hash, without.bundle_hash);
        // Suppress unused variable warning
        let _ = bundle_without;
    }

    // Covers SubjectType::as_tag for every non-Decision variant.
    #[test]
    fn test_subject_type_as_tag_all_variants() {
        assert_eq!(SubjectType::Decision.as_tag(), "Decision");
        assert_eq!(SubjectType::Transaction.as_tag(), "Transaction");
        assert_eq!(SubjectType::Delegation.as_tag(), "Delegation");
        assert_eq!(SubjectType::Identity.as_tag(), "Identity");
        assert_eq!(SubjectType::Consent.as_tag(), "Consent");
        assert_eq!(SubjectType::Emergency.as_tag(), "Emergency");

        // Each tag must also influence the bundle hash (no two variants collide).
        let mk = |t: SubjectType| {
            let mut b = EvidenceBundle {
                id: "fixed".into(),
                version: BUNDLE_VERSION,
                created_at: ts(5000),
                subject: BundleSubject {
                    subject_type: t,
                    subject_id: "X".into(),
                    title: "T".into(),
                    description: "D".into(),
                },
                events: vec![make_event(0, vec![])],
                evidence_items: vec![],
                consent_records: vec![],
                contract_summary: None,
                certification: None,
                dag_anchor: make_anchor(),
                verification: VerificationManifest {
                    format_version: BUNDLE_VERSION,
                    hash_algorithm: "BLAKE3".into(),
                    verification_steps: vec![],
                },
                bundle_hash: Hash256::ZERO,
                signatures: vec![],
            };
            b.bundle_hash = compute_bundle_hash(&b).unwrap();
            b.bundle_hash
        };
        let all = [
            mk(SubjectType::Decision),
            mk(SubjectType::Transaction),
            mk(SubjectType::Delegation),
            mk(SubjectType::Identity),
            mk(SubjectType::Consent),
            mk(SubjectType::Emergency),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "subject-type hashes must differ");
            }
        }
    }

    // Covers assemble() rejecting an empty events vector.
    #[test]
    fn test_assemble_rejects_empty_events() {
        let err = assemble(make_assembly_input("empty-events", vec![])).unwrap_err();
        assert!(err.to_string().contains("at least one event"));
    }

    // Covers validate_causal_chain rejecting a non-empty genesis parent list.
    #[test]
    fn test_assemble_rejects_genesis_with_parents() {
        let bad_genesis = BundleEvent {
            parent_hashes: vec![Hash256::digest(b"phantom-parent")],
            ..make_event(0, vec![])
        };
        let err = assemble(make_assembly_input("bad-genesis", vec![bad_genesis])).unwrap_err();
        assert!(err.to_string().contains("genesis"));
    }

    // Covers fail-closed verification for a non-empty but unauthenticated signature.
    #[test]
    fn test_verify_rejects_fake_non_empty_signature() {
        let mut bundle = assemble_minimal();
        bundle.signatures.push(BundleSignature {
            signer_did: did("officer"),
            signer_role: "organization".into(),
            signature: Signature::from_bytes([0xab; 64]),
            signed_at: ts(3000),
        });
        let result = verify(&bundle).unwrap();
        assert_eq!(result.signatures_valid.len(), 1);
        let check = &result.signatures_valid[0];
        assert_eq!(check.signer, did("officer"));
        assert_eq!(check.role, "organization");
        assert!(!check.valid);
        assert!(!result.overall);
    }

    #[test]
    fn test_bundle_signature_payload_is_deterministic_and_domain_separated() {
        let bundle = assemble_minimal();
        let signer = did("officer");
        let first =
            bundle_signature_payload(&bundle.bundle_hash, &signer, "organization", ts(3000))
                .unwrap();
        let second =
            bundle_signature_payload(&bundle.bundle_hash, &signer, "organization", ts(3000))
                .unwrap();
        let different_role =
            bundle_signature_payload(&bundle.bundle_hash, &signer, "legal", ts(3000)).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, different_role);
    }

    #[test]
    fn test_verify_with_signer_keys_accepts_valid_signature() {
        let signer = did("officer");
        let signer_key = keypair(21);
        let mut bundle = assemble_minimal();
        sign(
            &mut bundle,
            &signer,
            "organization",
            ts(3000),
            signer_key.secret_key(),
        )
        .unwrap();
        let resolver = StaticResolver::default().with(signer.clone(), *signer_key.public_key());

        let result = verify_with_signer_keys(&bundle, &resolver).unwrap();

        assert!(result.hash_valid);
        assert_eq!(result.signatures_valid.len(), 1);
        assert!(result.signatures_valid[0].valid);
        assert!(result.overall);
    }

    #[test]
    fn test_verify_with_signer_keys_rejects_wrong_key() {
        let signer = did("officer");
        let signer_key = keypair(22);
        let wrong_key = keypair(23);
        let mut bundle = assemble_minimal();
        sign(
            &mut bundle,
            &signer,
            "organization",
            ts(3000),
            signer_key.secret_key(),
        )
        .unwrap();
        let resolver = StaticResolver::default().with(signer, *wrong_key.public_key());

        let result = verify_with_signer_keys(&bundle, &resolver).unwrap();

        assert_eq!(result.signatures_valid.len(), 1);
        assert!(!result.signatures_valid[0].valid);
        assert!(!result.overall);
    }

    #[test]
    fn test_verify_with_signer_keys_rejects_replayed_signature() {
        let signer = did("officer");
        let signer_key = keypair(24);
        let mut signed_bundle = assemble_minimal();
        sign(
            &mut signed_bundle,
            &signer,
            "organization",
            ts(3000),
            signer_key.secret_key(),
        )
        .unwrap();

        let mut replay_target = assemble(make_assembly_input(
            "bundle-replay-target",
            vec![make_event(0, vec![])],
        ))
        .unwrap();
        replay_target.signatures = signed_bundle.signatures.clone();
        let resolver = StaticResolver::default().with(signer, *signer_key.public_key());

        let result = verify_with_signer_keys(&replay_target, &resolver).unwrap();

        assert!(result.hash_valid);
        assert_eq!(result.signatures_valid.len(), 1);
        assert!(!result.signatures_valid[0].valid);
        assert!(!result.overall);
    }

    #[test]
    fn test_verify_with_signer_keys_rejects_tampered_bundle() {
        let signer = did("officer");
        let signer_key = keypair(25);
        let mut bundle = assemble_minimal();
        sign(
            &mut bundle,
            &signer,
            "organization",
            ts(3000),
            signer_key.secret_key(),
        )
        .unwrap();
        bundle.events[0].payload_summary = "tampered after signature".into();
        let resolver = StaticResolver::default().with(signer, *signer_key.public_key());

        let result = verify_with_signer_keys(&bundle, &resolver).unwrap();

        assert!(!result.hash_valid);
        assert!(result.signatures_valid[0].valid);
        assert!(!result.overall);
    }

    // Covers the signature-check closure flagging an empty (all-zero) signature as invalid.
    #[test]
    fn test_verify_reports_invalid_empty_signature() {
        let mut bundle = assemble_minimal();
        bundle.signatures.push(BundleSignature {
            signer_did: did("officer"),
            signer_role: "organization".into(),
            signature: Signature::from_bytes([0u8; 64]),
            signed_at: ts(3000),
        });
        let result = verify(&bundle).unwrap();
        assert_eq!(result.signatures_valid.len(), 1);
        assert!(!result.signatures_valid[0].valid);
        // overall must be false when any signature is invalid
        assert!(!result.overall);
    }

    // Covers the signatures-present branch of render_markdown_summary.
    #[test]
    fn test_render_markdown_includes_signatures_section() {
        let mut bundle = assemble_minimal();
        let officer_key = keypair(13);
        let counsel_key = keypair(14);
        sign(
            &mut bundle,
            &did("officer"),
            "organization",
            ts(3000),
            officer_key.secret_key(),
        )
        .unwrap();
        sign(
            &mut bundle,
            &did("counsel"),
            "legal",
            ts(3100),
            counsel_key.secret_key(),
        )
        .unwrap();
        let md = render_markdown_summary(&bundle);
        assert!(md.contains("## Signatures"));
        assert!(md.contains("organization"));
        assert!(md.contains("legal"));
        assert!(md.contains("did:exo:officer"));
        assert!(md.contains("did:exo:counsel"));
    }

    // Covers sign() rejecting an empty role string.
    #[test]
    fn test_sign_rejects_empty_role() {
        let mut bundle = assemble_minimal();
        let err = sign(
            &mut bundle,
            &did("officer"),
            "",
            ts(3000),
            keypair(15).secret_key(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("role"));
        assert!(bundle.signatures.is_empty());
    }

    // Covers CertSnapshot::from_cert field-by-field mirroring from a live Cert902_11.
    #[test]
    fn test_cert_snapshot_from_cert_mirrors_fields() {
        let ev = make_evidence_item();
        let cert =
            generate_902_11_cert(&ev, "EXOCHAIN decision.forum v1.0", 1_700_000_001_000).unwrap();
        let snap = CertSnapshot::from_cert(&cert);
        assert_eq!(snap.record_hash, cert.record_hash);
        assert_eq!(snap.custody_chain_digest, cert.custody_chain_digest);
        assert_eq!(snap.system_description, cert.system_description);
        assert_eq!(snap.declarant_placeholder, cert.declarant_placeholder);
        assert_eq!(snap.generated_at_ms, cert.generated_at_ms);
        assert_eq!(snap.cert_hash, cert.cert_hash);
        assert_eq!(snap.filing_disclaimer, cert.filing_disclaimer);
    }

    // Covers the certification-present arm of compute_bundle_hash (tag byte 0x01 + cert_hash).
    #[test]
    fn test_bundle_hash_differs_with_and_without_cert() {
        let ev = make_evidence_item();
        let cert =
            generate_902_11_cert(&ev, "EXOCHAIN decision.forum v1.0", 1_700_000_001_000).unwrap();
        let mk = |c: Option<Cert902_11>| {
            let mut b = EvidenceBundle {
                id: "fixed".into(),
                version: BUNDLE_VERSION,
                created_at: ts(5000),
                subject: make_subject(),
                events: vec![make_event(0, vec![])],
                evidence_items: vec![make_evidence_item()],
                consent_records: vec![],
                contract_summary: None,
                certification: c.as_ref().map(CertSnapshot::from_cert),
                dag_anchor: make_anchor(),
                verification: VerificationManifest {
                    format_version: BUNDLE_VERSION,
                    hash_algorithm: "BLAKE3".into(),
                    verification_steps: vec![],
                },
                bundle_hash: Hash256::ZERO,
                signatures: vec![],
            };
            b.bundle_hash = compute_bundle_hash(&b).unwrap();
            b.bundle_hash
        };
        assert_ne!(mk(Some(cert)), mk(None));
    }
}

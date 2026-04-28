//! Bailment model — the legal foundation of consent in EXOCHAIN.
//!
//! A bailment is a trust relationship where a bailor entrusts property (data/authority)
//! to a bailee under specific terms. No action may proceed without an active bailment.

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::error::ConsentError;

/// Domain-separation tag for hashing bailment proposal terms.
pub const BAILMENT_TERMS_HASH_DOMAIN: &str = "exo.bailment.terms.v1";

/// The type of bailment relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BailmentType {
    /// Bailee holds data/authority in custody without processing rights.
    Custody,
    /// Bailee may process data under defined terms.
    Processing,
    /// Bailee may delegate authority to sub-bailees.
    Delegation,
    /// Emergency access — time-limited, requires justification.
    Emergency,
}

/// The lifecycle state of a bailment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BailmentStatus {
    Proposed,
    Active,
    Suspended,
    Terminated,
    Expired,
}

impl std::fmt::Display for BailmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proposed => write!(f, "Proposed"),
            Self::Active => write!(f, "Active"),
            Self::Suspended => write!(f, "Suspended"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

/// A bailment record — the binding consent agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bailment {
    pub id: String,
    pub bailor_did: Did,
    pub bailee_did: Did,
    pub bailment_type: BailmentType,
    pub terms_hash: Hash256,
    pub created: Timestamp,
    pub expires: Option<Timestamp>,
    pub status: BailmentStatus,
    pub signature: Signature,
    #[serde(default)]
    pub bailee_public_key: Option<PublicKey>,
}

/// Propose a new bailment. Returns a bailment in `Proposed` status.
///
/// Callers must supply the proposal ID and creation timestamp from their
/// deterministic execution context. The constructor rejects empty IDs and
/// zero timestamps so consensus/audit-significant bailments cannot silently
/// carry placeholder metadata. The supplied `terms` bytes are never hashed
/// directly; [`terms_hash`] wraps them in a versioned domain tag and hashes
/// the canonical CBOR representation.
///
/// # Errors
/// - `Denied` if `id` is empty or `created` is [`Timestamp::ZERO`].
/// - `Serialization` if canonical CBOR terms hashing fails.
pub fn propose(
    bailor: &Did,
    bailee: &Did,
    terms: &[u8],
    bailment_type: BailmentType,
    id: impl Into<String>,
    created: Timestamp,
) -> Result<Bailment, ConsentError> {
    let id = id.into();
    validate_constructor_metadata("bailment id", &id, "created", &created)?;
    let terms_hash = terms_hash(terms)?;

    Ok(Bailment {
        id,
        bailor_did: bailor.clone(),
        bailee_did: bailee.clone(),
        bailment_type,
        terms_hash,
        created,
        expires: None,
        status: BailmentStatus::Proposed,
        signature: Signature::empty(),
        bailee_public_key: None,
    })
}

/// Hash bailment proposal terms through a versioned canonical-CBOR boundary.
///
/// The input is a byte representation of the proposed terms, but the digest is
/// computed over `(BAILMENT_TERMS_HASH_DOMAIN, terms)` encoded as CBOR. This
/// prevents a caller from defining the cryptographic preimage shape implicitly
/// by choosing arbitrary raw bytes.
///
/// # Errors
/// Returns `Serialization` if canonical CBOR encoding fails.
pub fn terms_hash(terms: &[u8]) -> Result<Hash256, ConsentError> {
    hash_structured(&(BAILMENT_TERMS_HASH_DOMAIN, terms)).map_err(|e| {
        ConsentError::Serialization(format!("bailment terms hash encoding failed: {e}"))
    })
}

fn validate_constructor_metadata(
    id_label: &str,
    id: &str,
    timestamp_label: &str,
    timestamp: &Timestamp,
) -> Result<(), ConsentError> {
    if id.trim().is_empty() {
        return Err(ConsentError::Denied(format!(
            "{id_label} must be caller-supplied and non-empty"
        )));
    }
    if *timestamp == Timestamp::ZERO {
        return Err(ConsentError::Denied(format!(
            "{timestamp_label} must be caller-supplied and non-zero"
        )));
    }
    Ok(())
}

/// Canonical CBOR signing payload for bailment acceptance.
///
/// Encodes the fixed fields the bailee is cryptographically committing to
/// when they sign acceptance: the bailment's id, both parties' DIDs, the
/// type, the hash of the terms, and the creation timestamp. Any tampering
/// with these fields after signing will invalidate the signature.
///
/// The `status`, `signature`, and `expires` fields are deliberately NOT
/// part of the payload: `status` transitions after signing, `signature`
/// is the output being computed, and `expires` may be set or adjusted by
/// the bailor post-acceptance without invalidating bailee consent to the
/// original terms. (If future policy requires expires-at-sign-time, add a
/// v2 payload and version-tag.)
///
/// # Errors
/// Returns `Serialization` on CBOR encoding failure.
pub fn signing_payload(bailment: &Bailment) -> Result<Vec<u8>, ConsentError> {
    // Domain-separation tag + version + ordered tuple of fields.
    let tuple = (
        "exo.bailment.accept.v1",
        &bailment.id,
        &bailment.bailor_did,
        &bailment.bailee_did,
        &bailment.bailment_type,
        &bailment.terms_hash,
        &bailment.created,
    );
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&tuple, &mut buf).map_err(|e| {
        ConsentError::Serialization(format!("bailment signing payload encoding failed: {e}"))
    })?;
    Ok(buf)
}

/// Accept a proposed bailment. Transitions `Proposed` -> `Active`.
///
/// **Closes GAP-012.** The previous implementation checked only that the
/// signature was non-empty and stored it without verifying it against any
/// public key — an attacker with any non-empty byte sequence could flip a
/// bailment to Active. This was a silent authentication bypass.
///
/// Callers now MUST supply the bailee's public key. The signature is
/// verified against the canonical payload from [`signing_payload`] before
/// the status transition. Empty and zero-byte signatures are explicitly
/// rejected.
///
/// # Errors
/// - `InvalidState` if not in `Proposed` status.
/// - `InvalidSignature` if the signature is empty, a zero sentinel, or
///   fails to verify against `bailee_public_key`.
/// - `Serialization` on canonical encoding failure.
pub fn accept(
    bailment: &mut Bailment,
    bailee_public_key: &PublicKey,
    bailee_signature: &Signature,
) -> Result<(), ConsentError> {
    if bailment.status != BailmentStatus::Proposed {
        return Err(ConsentError::InvalidState {
            expected: "Proposed".into(),
            actual: bailment.status.to_string(),
        });
    }
    if bailee_signature.is_empty() {
        return Err(ConsentError::InvalidSignature);
    }
    // Explicit zero-byte sentinel guard — defense in depth against
    // callers who forget to check is_empty() and pass an Ed25519 with
    // all-zero bytes, which some backends treat as a valid point but
    // is a well-known null-signature attack shape.
    if bailee_signature.ed25519_component_is_zero() {
        return Err(ConsentError::InvalidSignature);
    }

    let payload = signing_payload(bailment)?;
    if !crypto::verify(&payload, bailee_signature, bailee_public_key) {
        return Err(ConsentError::InvalidSignature);
    }

    bailment.signature = bailee_signature.clone();
    bailment.bailee_public_key = Some(*bailee_public_key);
    bailment.status = BailmentStatus::Active;
    Ok(())
}

/// Verify that an active bailment carries a cryptographic acceptance proof.
///
/// A status bit alone is not consent. Active bailments must retain the bailee
/// public key used at acceptance and the stored signature must still verify
/// over the canonical acceptance payload.
#[must_use]
pub fn has_valid_acceptance_proof(bailment: &Bailment) -> bool {
    if bailment.status != BailmentStatus::Active {
        return false;
    }
    acceptance_proof_verifies(bailment)
}

fn acceptance_proof_verifies(bailment: &Bailment) -> bool {
    if bailment.signature.is_empty() {
        return false;
    }
    if bailment.signature.ed25519_component_is_zero() {
        return false;
    }
    let Some(bailee_public_key) = bailment.bailee_public_key else {
        return false;
    };
    let Ok(payload) = signing_payload(bailment) else {
        return false;
    };
    crypto::verify(&payload, &bailment.signature, &bailee_public_key)
}

fn require_bailment_party(bailment: &Bailment, actor: &Did) -> Result<(), ConsentError> {
    if *actor != bailment.bailor_did && *actor != bailment.bailee_did {
        return Err(ConsentError::Unauthorized(format!(
            "DID {actor} is neither bailor nor bailee"
        )));
    }
    Ok(())
}

fn require_bailor(bailment: &Bailment, actor: &Did) -> Result<(), ConsentError> {
    if *actor != bailment.bailor_did {
        return Err(ConsentError::Unauthorized(format!(
            "DID {actor} is not the bailor for bailment {}",
            bailment.id
        )));
    }
    Ok(())
}

/// Suspend an active bailment. Either bailor or bailee may pause consent use.
///
/// Suspension preserves the original acceptance proof but makes the bailment
/// inactive until the bailor resumes it. The function verifies the stored
/// acceptance proof before transitioning so a forged `Active` status bit cannot
/// be laundered into a legitimate suspended lifecycle state.
///
/// # Errors
/// - `InvalidState` if the bailment is not currently `Active`.
/// - `Unauthorized` if actor is neither bailor nor bailee.
/// - `InvalidSignature` if the stored acceptance proof is missing or invalid.
pub fn suspend(bailment: &mut Bailment, actor: &Did) -> Result<(), ConsentError> {
    if bailment.status != BailmentStatus::Active {
        return Err(ConsentError::InvalidState {
            expected: "Active".into(),
            actual: bailment.status.to_string(),
        });
    }
    require_bailment_party(bailment, actor)?;
    if !acceptance_proof_verifies(bailment) {
        return Err(ConsentError::InvalidSignature);
    }

    bailment.status = BailmentStatus::Suspended;
    Ok(())
}

/// Resume a suspended bailment. Only the bailor may restore consent use.
///
/// The bailee's original acceptance signature remains binding; resumption
/// verifies it again before returning to `Active`.
///
/// # Errors
/// - `InvalidState` if the bailment is not currently `Suspended`.
/// - `Unauthorized` if actor is not the bailor.
/// - `InvalidSignature` if the stored acceptance proof is missing or invalid.
pub fn resume(bailment: &mut Bailment, actor: &Did) -> Result<(), ConsentError> {
    if bailment.status != BailmentStatus::Suspended {
        return Err(ConsentError::InvalidState {
            expected: "Suspended".into(),
            actual: bailment.status.to_string(),
        });
    }
    require_bailor(bailment, actor)?;
    if !acceptance_proof_verifies(bailment) {
        return Err(ConsentError::InvalidSignature);
    }

    bailment.status = BailmentStatus::Active;
    Ok(())
}

/// Terminate a bailment. Either bailor or bailee may terminate.
///
/// # Errors
/// - `InvalidState` if already terminated or expired.
/// - `Unauthorized` if actor is neither bailor nor bailee.
pub fn terminate(bailment: &mut Bailment, actor: &Did) -> Result<(), ConsentError> {
    if bailment.status == BailmentStatus::Terminated || bailment.status == BailmentStatus::Expired {
        return Err(ConsentError::InvalidState {
            expected: "Active, Proposed, or Suspended".into(),
            actual: bailment.status.to_string(),
        });
    }
    require_bailment_party(bailment, actor)?;
    bailment.status = BailmentStatus::Terminated;
    Ok(())
}

/// Check whether a bailment is currently active (status Active + not expired).
#[must_use]
pub fn is_active(bailment: &Bailment, now: &Timestamp) -> bool {
    if bailment.status != BailmentStatus::Active {
        return false;
    }
    if !has_valid_acceptance_proof(bailment) {
        return false;
    }
    match &bailment.expires {
        Some(exp) => !exp.is_expired(now),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use exo_core::{SecretKey, hash::hash_structured};

    use super::*;

    fn alice() -> Did {
        Did::new("did:exo:alice").unwrap()
    }
    fn bob() -> Did {
        Did::new("did:exo:bob").unwrap()
    }
    fn charlie() -> Did {
        Did::new("did:exo:charlie").unwrap()
    }

    /// Produce a (pubkey, valid-sig-over-canonical-payload) pair for the
    /// bailee of `b`. Used by tests that want the happy path.
    fn sign_as_bailee(b: &Bailment) -> (PublicKey, SecretKey, Signature) {
        let (pk, sk) = crypto::generate_keypair();
        let payload = signing_payload(b).expect("canonical payload");
        let sig = crypto::sign(&payload, &sk);
        (pk, sk, sig)
    }

    fn accept_test_bailment(b: &mut Bailment) {
        let (pk, _sk, sig) = sign_as_bailee(b);
        accept(b, &pk, &sig).expect("test bailment accepts");
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn propose_test(terms: &[u8], bailment_type: BailmentType) -> Bailment {
        propose(
            &alice(),
            &bob(),
            terms,
            bailment_type,
            "bailment-test",
            ts(1000),
        )
        .expect("test bailment proposal")
    }

    fn propose_test_with_metadata(
        terms: &[u8],
        bailment_type: BailmentType,
        id: &str,
        created: Timestamp,
    ) -> Bailment {
        propose(&alice(), &bob(), terms, bailment_type, id, created)
            .expect("test bailment proposal with metadata")
    }

    #[test]
    fn bailment_proposal_constructor_has_no_internal_entropy_or_wall_clock() {
        let source = include_str!("bailment.rs");
        let uuid_pattern = format!("{}{}", "Uuid::", "new_v4()");
        let now_pattern = format!("{}{}", "Timestamp::", "now_utc()");

        assert!(
            !source.contains(&uuid_pattern),
            "bailment proposals must receive caller-supplied IDs"
        );
        assert!(
            !source.contains(&now_pattern),
            "bailment proposals must receive caller-supplied HLC timestamps"
        );
    }

    #[test]
    fn bailment_proposal_terms_hash_is_domain_separated_canonical_cbor() {
        let b = propose_test_with_metadata(
            b"terms",
            BailmentType::Custody,
            "bailment-canonical-terms",
            ts(1234),
        );
        let expected = hash_structured(&(BAILMENT_TERMS_HASH_DOMAIN, b"terms".as_slice()))
            .expect("canonical terms hash");

        assert_eq!(b.terms_hash, expected);
        assert_ne!(b.terms_hash, Hash256::digest(b"terms"));
    }

    #[test]
    fn bailment_proposal_does_not_digest_terms_as_raw_bytes() {
        let source = include_str!("bailment.rs");
        let direct_terms_digest_pattern = format!("{}{}", "Hash256::digest(", "terms)");

        assert!(
            !source.contains(&direct_terms_digest_pattern),
            "bailment proposals must hash terms through a domain-separated canonical-CBOR boundary"
        );
    }

    #[test]
    fn propose_creates_proposed() {
        let b = propose_test_with_metadata(
            b"terms",
            BailmentType::Custody,
            "bailment-explicit",
            ts(1234),
        );
        assert_eq!(b.status, BailmentStatus::Proposed);
        assert_eq!(b.bailor_did, alice());
        assert_eq!(b.bailee_did, bob());
        assert_eq!(b.bailment_type, BailmentType::Custody);
        assert_eq!(b.id, "bailment-explicit");
        assert_eq!(b.created, ts(1234));
        assert!(b.signature.is_empty());
        assert!(b.bailee_public_key.is_none());
        assert!(b.expires.is_none());
    }

    #[test]
    fn propose_rejects_empty_id() {
        let err = propose(
            &alice(),
            &bob(),
            b"terms",
            BailmentType::Custody,
            " ",
            ts(1000),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConsentError::Denied("bailment id must be caller-supplied and non-empty".into())
        );
    }

    #[test]
    fn propose_rejects_zero_created_timestamp() {
        let err = propose(
            &alice(),
            &bob(),
            b"terms",
            BailmentType::Custody,
            "bailment-explicit",
            Timestamp::ZERO,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConsentError::Denied("created must be caller-supplied and non-zero".into())
        );
    }

    #[test]
    fn propose_hashes_terms_deterministically() {
        let a = propose_test(b"terms-a", BailmentType::Processing);
        let b = propose_test(b"terms-b", BailmentType::Processing);
        assert_ne!(a.terms_hash, b.terms_hash);
        let c = propose_test(b"terms-a", BailmentType::Processing);
        assert_eq!(a.terms_hash, c.terms_hash);
    }

    #[test]
    fn accept_transitions_to_active() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        assert!(accept(&mut b, &pk, &sig).is_ok());
        assert_eq!(b.status, BailmentStatus::Active);
        assert!(!b.signature.is_empty());
        assert_eq!(b.bailee_public_key, Some(pk));
        assert!(has_valid_acceptance_proof(&b));
    }

    #[test]
    fn accept_rejects_non_proposed() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        b.status = BailmentStatus::Active;
        assert_eq!(
            accept(&mut b, &pk, &sig),
            Err(ConsentError::InvalidState {
                expected: "Proposed".into(),
                actual: "Active".into()
            })
        );
    }

    #[test]
    fn accept_rejects_empty_signature() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk) = crypto::generate_keypair();
        assert_eq!(
            accept(&mut b, &pk, &Signature::empty()),
            Err(ConsentError::InvalidSignature)
        );
    }

    // ==== GAP-012 regression tests =================================

    /// The exact old-code attack: a non-empty but cryptographically
    /// invalid signature that the old `accept()` would have silently
    /// accepted.
    #[test]
    fn accept_rejects_non_empty_but_invalid_signature() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk) = crypto::generate_keypair();
        // Non-empty junk bytes — the kind of signature the old code let
        // through unchecked.
        let junk = Signature::from_bytes([1u8; 64]);
        assert_eq!(
            accept(&mut b, &pk, &junk),
            Err(ConsentError::InvalidSignature)
        );
        // Critically: status must remain Proposed.
        assert_eq!(b.status, BailmentStatus::Proposed);
    }

    /// An Ed25519 all-zeros signature is rejected even though it is
    /// technically non-empty. Some backends treat [0u8; 64] as a valid
    /// point; EXOCHAIN must not.
    #[test]
    fn accept_rejects_zero_byte_signature() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk) = crypto::generate_keypair();
        let zeros = Signature::from_bytes([0u8; 64]);
        assert_eq!(
            accept(&mut b, &pk, &zeros),
            Err(ConsentError::InvalidSignature)
        );
        assert_eq!(b.status, BailmentStatus::Proposed);
    }

    /// A signature that is valid under some OTHER key than the one the
    /// caller supplies must be rejected. Ensures the verification is
    /// bound to the bailee's public key.
    #[test]
    fn accept_rejects_signature_by_wrong_key() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (_pk_a, sk_a) = crypto::generate_keypair();
        let (pk_b, _sk_b) = crypto::generate_keypair();
        let payload = signing_payload(&b).unwrap();
        let sig = crypto::sign(&payload, &sk_a);
        // Signed by key A, verifying against key B — must fail.
        assert_eq!(
            accept(&mut b, &pk_b, &sig),
            Err(ConsentError::InvalidSignature)
        );
        assert_eq!(b.status, BailmentStatus::Proposed);
    }

    /// A signature over a DIFFERENT bailment's payload must not
    /// authenticate this bailment (replay protection).
    #[test]
    fn accept_rejects_signature_over_different_bailment() {
        let mut b1 = propose_test(b"t1", BailmentType::Custody);
        let b2 = propose_test(b"t2", BailmentType::Custody);
        let (pk, sk) = crypto::generate_keypair();
        let payload2 = signing_payload(&b2).unwrap();
        let sig_on_b2 = crypto::sign(&payload2, &sk);
        assert_eq!(
            accept(&mut b1, &pk, &sig_on_b2),
            Err(ConsentError::InvalidSignature)
        );
        assert_eq!(b1.status, BailmentStatus::Proposed);
    }

    /// Tampering with a signed bailment after acceptance is signed but
    /// before acceptance is processed must invalidate the signature.
    #[test]
    fn accept_rejects_tampered_bailment() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        // Attacker changes the bailee to themselves after the real
        // bailee signed. Should be rejected.
        b.bailee_did = charlie();
        assert_eq!(
            accept(&mut b, &pk, &sig),
            Err(ConsentError::InvalidSignature)
        );
        assert_eq!(b.status, BailmentStatus::Proposed);
    }

    #[test]
    fn accept_rejects_tampered_terms() {
        let mut b = propose_test(b"t-original", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        b.terms_hash = terms_hash(b"t-swapped").expect("canonical terms hash");
        assert_eq!(
            accept(&mut b, &pk, &sig),
            Err(ConsentError::InvalidSignature)
        );
    }

    // ================================================================

    #[test]
    fn suspend_active_bailment_by_bailor() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);

        assert!(suspend(&mut b, &alice()).is_ok());

        assert_eq!(b.status, BailmentStatus::Suspended);
        assert!(!is_active(&b, &ts(1000)));
    }

    #[test]
    fn suspend_active_bailment_by_bailee() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);

        assert!(suspend(&mut b, &bob()).is_ok());

        assert_eq!(b.status, BailmentStatus::Suspended);
        assert!(!is_active(&b, &ts(1000)));
    }

    #[test]
    fn suspend_rejects_unauthorized_actor() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);

        assert!(matches!(
            suspend(&mut b, &charlie()),
            Err(ConsentError::Unauthorized(_))
        ));
        assert_eq!(b.status, BailmentStatus::Active);
    }

    #[test]
    fn suspend_rejects_non_active_states() {
        let mut proposed = propose_test(b"t", BailmentType::Custody);
        assert_eq!(
            suspend(&mut proposed, &alice()),
            Err(ConsentError::InvalidState {
                expected: "Active".into(),
                actual: "Proposed".into()
            })
        );

        let mut active = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut active);
        suspend(&mut active, &alice()).expect("suspend active bailment");
        assert_eq!(
            suspend(&mut active, &alice()),
            Err(ConsentError::InvalidState {
                expected: "Active".into(),
                actual: "Suspended".into()
            })
        );

        let mut terminated = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut terminated);
        terminate(&mut terminated, &alice()).expect("terminate active bailment");
        assert_eq!(
            suspend(&mut terminated, &alice()),
            Err(ConsentError::InvalidState {
                expected: "Active".into(),
                actual: "Terminated".into()
            })
        );

        let mut expired = propose_test(b"t", BailmentType::Custody);
        expired.status = BailmentStatus::Expired;
        assert_eq!(
            suspend(&mut expired, &alice()),
            Err(ConsentError::InvalidState {
                expected: "Active".into(),
                actual: "Expired".into()
            })
        );
    }

    #[test]
    fn suspend_rejects_status_forged_active_bailment() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        b.status = BailmentStatus::Active;
        b.signature = Signature::from_bytes([0xAB; 64]);

        assert_eq!(
            suspend(&mut b, &alice()),
            Err(ConsentError::InvalidSignature)
        );
        assert_eq!(b.status, BailmentStatus::Active);
    }

    #[test]
    fn resume_suspended_bailment_by_bailor() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);
        suspend(&mut b, &bob()).expect("bailee may suspend consent use");

        assert!(resume(&mut b, &alice()).is_ok());

        assert_eq!(b.status, BailmentStatus::Active);
        assert!(has_valid_acceptance_proof(&b));
        assert!(is_active(&b, &ts(1000)));
    }

    #[test]
    fn resume_rejects_bailee() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);
        suspend(&mut b, &alice()).expect("suspend active bailment");

        assert!(matches!(
            resume(&mut b, &bob()),
            Err(ConsentError::Unauthorized(_))
        ));
        assert_eq!(b.status, BailmentStatus::Suspended);
    }

    #[test]
    fn resume_rejects_non_suspended_state() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);

        assert_eq!(
            resume(&mut b, &alice()),
            Err(ConsentError::InvalidState {
                expected: "Suspended".into(),
                actual: "Active".into()
            })
        );
    }

    #[test]
    fn resume_rejects_suspended_without_acceptance_proof() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        b.status = BailmentStatus::Suspended;

        assert_eq!(
            resume(&mut b, &alice()),
            Err(ConsentError::InvalidSignature)
        );
        assert_eq!(b.status, BailmentStatus::Suspended);
    }

    #[test]
    fn terminate_by_bailor() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        assert!(terminate(&mut b, &alice()).is_ok());
        assert_eq!(b.status, BailmentStatus::Terminated);
    }

    #[test]
    fn terminate_by_bailee() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        assert!(terminate(&mut b, &bob()).is_ok());
        assert_eq!(b.status, BailmentStatus::Terminated);
    }

    #[test]
    fn terminate_rejects_unauthorized() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        assert!(matches!(
            terminate(&mut b, &charlie()),
            Err(ConsentError::Unauthorized(_))
        ));
    }

    #[test]
    fn terminate_rejects_already_terminated() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        terminate(&mut b, &alice()).ok();
        assert!(matches!(
            terminate(&mut b, &alice()),
            Err(ConsentError::InvalidState { .. })
        ));
    }

    #[test]
    fn terminate_rejects_expired() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        b.status = BailmentStatus::Expired;
        assert!(matches!(
            terminate(&mut b, &alice()),
            Err(ConsentError::InvalidState { .. })
        ));
    }

    #[test]
    fn terminate_proposed() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        assert!(terminate(&mut b, &alice()).is_ok());
    }

    #[test]
    fn terminate_suspended() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);
        suspend(&mut b, &alice()).expect("suspend active bailment");
        assert!(terminate(&mut b, &alice()).is_ok());
    }

    #[test]
    fn is_active_with_no_expiry() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        assert!(is_active(&b, &ts(5000)));
    }

    #[test]
    fn is_active_before_expiry() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        b.expires = Some(ts(10000));
        assert!(is_active(&b, &ts(5000)));
    }

    #[test]
    fn not_active_after_expiry() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        b.expires = Some(ts(1000));
        assert!(!is_active(&b, &ts(5000)));
    }

    #[test]
    fn is_active_rejects_status_forged_empty_signature() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        b.status = BailmentStatus::Active;
        b.signature = Signature::Empty;

        assert!(
            !is_active(&b, &ts(1000)),
            "active bailments must not be trusted without a verifiable acceptance signature"
        );
    }

    #[test]
    fn is_active_rejects_status_forged_junk_signature() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        b.status = BailmentStatus::Active;
        b.signature = Signature::from_bytes([0xAB; 64]);

        assert!(
            !is_active(&b, &ts(1000)),
            "active bailments must not trust non-empty signatures without the bailee key proof"
        );
    }

    #[test]
    fn not_active_at_exact_expiry() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        b.expires = Some(ts(5000));
        assert!(!is_active(&b, &ts(5000)));
    }

    #[test]
    fn not_active_when_proposed() {
        let b = propose_test(b"t", BailmentType::Custody);
        assert!(!is_active(&b, &ts(1000)));
    }

    #[test]
    fn not_active_when_terminated() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        let (pk, _sk, sig) = sign_as_bailee(&b);
        accept(&mut b, &pk, &sig).ok();
        terminate(&mut b, &alice()).ok();
        assert!(!is_active(&b, &ts(1000)));
    }

    #[test]
    fn not_active_when_suspended() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        accept_test_bailment(&mut b);
        suspend(&mut b, &alice()).expect("suspend active bailment");
        assert!(!is_active(&b, &ts(1000)));
    }

    #[test]
    fn not_active_when_expired_status() {
        let mut b = propose_test(b"t", BailmentType::Custody);
        b.status = BailmentStatus::Expired;
        assert!(!is_active(&b, &ts(1000)));
    }

    #[test]
    fn bailment_type_variants() {
        assert_ne!(BailmentType::Custody, BailmentType::Processing);
        assert_ne!(BailmentType::Delegation, BailmentType::Emergency);
        assert_eq!(BailmentType::Custody, BailmentType::Custody);
    }

    #[test]
    fn bailment_status_display() {
        assert_eq!(BailmentStatus::Proposed.to_string(), "Proposed");
        assert_eq!(BailmentStatus::Active.to_string(), "Active");
        assert_eq!(BailmentStatus::Suspended.to_string(), "Suspended");
        assert_eq!(BailmentStatus::Terminated.to_string(), "Terminated");
        assert_eq!(BailmentStatus::Expired.to_string(), "Expired");
    }
}

//! Peer-to-peer mesh networking.
use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, Result};

const P2P_MESSAGE_SIGNING_DOMAIN: &str = "exo.p2p.message.v1";

/// Unique identifier for a peer in the P2P mesh, wrapping a DID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Did);

/// Metadata describing a known peer (addresses, key hash, reputation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addresses: Vec<String>,
    pub public_key_hash: Hash256,
    pub last_seen: Timestamp,
    pub reputation_score: u32,
}

/// In-memory registry of known peers in the P2P mesh.
#[derive(Debug, Clone, Default)]
pub struct PeerRegistry {
    pub peers: BTreeMap<PeerId, PeerInfo>,
}

impl PeerRegistry {
    /// Create an empty peer registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }
    /// Register a peer, replacing any existing entry with the same ID.
    pub fn register(&mut self, info: PeerInfo) {
        self.peers.insert(info.id.clone(), info);
    }
    /// Look up a peer by its ID.
    #[must_use]
    pub fn get(&self, id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(id)
    }
    /// Return the number of registered peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    /// Return `true` if no peers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// A signed peer-to-peer message with optional recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub from: PeerId,
    pub to: Option<PeerId>,
    pub payload: Vec<u8>,
    pub signature: Signature,
    pub nonce: u64,
}

/// Rate-limit tracking per peer.
#[derive(Debug, Default)]
pub struct RateLimiter {
    counts: BTreeMap<PeerId, u32>,
}
impl RateLimiter {
    const MAX_PER_WINDOW: u32 = 100;
    /// Create a new rate limiter with zero counts.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counts: BTreeMap::new(),
        }
    }
    /// Increment the request count for a peer, returning an error if the limit is exceeded.
    pub fn check_and_increment(&mut self, peer: &PeerId) -> Result<()> {
        let c = self.counts.entry(peer.clone()).or_insert(0);
        if *c >= Self::MAX_PER_WINDOW {
            return Err(ApiError::RateLimited {
                peer_id: format!("{:?}", peer),
            });
        }
        *c += 1;
        Ok(())
    }
    /// Reset all peer counters for the next rate-limit window.
    pub fn reset(&mut self) {
        self.counts.clear();
    }
}

/// Send a message, verifying the recipient exists in the registry (if addressed).
pub fn send(registry: &PeerRegistry, msg: &Message) -> Result<()> {
    if let Some(ref to) = msg.to {
        if !registry.peers.contains_key(to) {
            return Err(ApiError::PeerNotFound(format!("{to:?}")));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct MessageSigningPayload<'a> {
    domain: &'static str,
    from: &'a str,
    to: Option<&'a str>,
    payload: &'a [u8],
    nonce: u64,
}

/// Canonical CBOR payload signed by a peer-to-peer message sender.
///
/// The domain tag prevents cross-protocol replay, and the payload binds sender,
/// optional recipient, body bytes, and nonce. The signature field is excluded
/// so callers can use this function before and after signing.
pub fn message_signing_payload(msg: &Message) -> Result<Vec<u8>> {
    let payload = MessageSigningPayload {
        domain: P2P_MESSAGE_SIGNING_DOMAIN,
        from: msg.from.0.as_str(),
        to: msg.to.as_ref().map(|peer| peer.0.as_str()),
        payload: &msg.payload,
        nonce: msg.nonce,
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded)
        .map_err(|e| ApiError::SerializationError(e.to_string()))?;
    Ok(encoded)
}

/// Validate structural integrity of a peer-to-peer message.
///
/// Validates:
/// 1. Signature is not empty / all-zero (rejects [`Signature::Empty`] and zero-filled Ed25519).
/// 2. Sender DID (`msg.from`) is well-formed.
///
/// This helper is intentionally not named `verify`: it does not authenticate
/// the signature. Use [`verify_message`] for Ed25519 verification.
pub fn validate_message_structure(msg: &Message) -> Result<()> {
    // Reject empty / all-zero signatures.
    if msg.signature.is_empty() {
        return Err(ApiError::VerificationFailed {
            reason: "empty or zero signature".into(),
        });
    }
    // Reject malformed sender DID (syntactic check — Does it parse?).
    if msg.from.0.to_string().is_empty() {
        return Err(ApiError::VerificationFailed {
            reason: "sender DID is empty".into(),
        });
    }
    Ok(())
}

/// Verify a peer-to-peer message Ed25519 signature against the sender public key.
pub fn verify_message(msg: &Message, sender_public_key: &PublicKey) -> Result<()> {
    validate_message_structure(msg)?;
    let payload = message_signing_payload(msg)?;
    if exo_core::crypto::verify(&payload, &msg.signature, sender_public_key) {
        Ok(())
    } else {
        Err(ApiError::VerificationFailed {
            reason: "invalid Ed25519 signature".into(),
        })
    }
}

/// Discover new peers from bootstrap addresses and register them.
pub fn discover_peers(registry: &mut PeerRegistry, bootstrap: &[String]) -> Result<Vec<PeerId>> {
    let mut discovered = Vec::new();
    for addr in bootstrap {
        let did = Did::new(&format!(
            "did:exo:peer-{}",
            blake3::hash(addr.as_bytes()).to_hex()
        ))
        .map_err(|e| ApiError::InvalidSchema {
            reason: e.to_string(),
        })?;
        let pid = PeerId(did);
        if !registry.peers.contains_key(&pid) {
            registry.register(PeerInfo {
                id: pid.clone(),
                addresses: vec![addr.clone()],
                public_key_hash: Hash256::digest(addr.as_bytes()),
                last_seen: Timestamp::ZERO,
                reputation_score: 50,
            });
            discovered.push(pid);
        }
    }
    Ok(discovered)
}

// ---------------------------------------------------------------------------
// ASN Diversity Enforcement (T-06: Eclipse Attack mitigation)
// ---------------------------------------------------------------------------

/// Autonomous System Number wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Asn(pub u32);

/// Extended peer metadata including ASN information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMetadata {
    pub info: PeerInfo,
    pub asn: Option<Asn>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

/// Policy governing ASN diversity requirements.
#[derive(Debug, Clone)]
pub struct AsnPolicy {
    /// Minimum number of unique ASNs required for a healthy peer set.
    pub min_unique_asns: usize,
    /// Maximum number of peers allowed from a single ASN.
    pub max_peers_per_asn: usize,
    /// Interval in milliseconds after which peers are considered for rotation.
    pub rotation_interval_ms: u64,
}

impl Default for AsnPolicy {
    fn default() -> Self {
        Self {
            min_unique_asns: 3,
            max_peers_per_asn: 5,
            rotation_interval_ms: 3_600_000, // 1 hour
        }
    }
}

/// Result of an ASN diversity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiversityResult {
    Sufficient,
    Insufficient { unique_asns: usize, required: usize },
}

/// Sentinel ASN value used to group peers with no known ASN.
const UNKNOWN_ASN: Asn = Asn(0);

/// Resolve a peer's ASN for grouping purposes.
/// Peers with `asn: None` are all placed in the same group ([`UNKNOWN_ASN`]).
fn effective_asn(peer: &PeerMetadata) -> Asn {
    peer.asn.unwrap_or(UNKNOWN_ASN)
}

/// Check whether the peer set meets the ASN diversity threshold.
#[must_use]
pub fn check_asn_diversity(peers: &[PeerMetadata], policy: &AsnPolicy) -> DiversityResult {
    let unique: BTreeSet<Asn> = peers.iter().map(effective_asn).collect();
    if unique.len() >= policy.min_unique_asns {
        DiversityResult::Sufficient
    } else {
        DiversityResult::Insufficient {
            unique_asns: unique.len(),
            required: policy.min_unique_asns,
        }
    }
}

/// Select peers that maximise ASN diversity.
///
/// Strategy: round-robin across unique ASNs, then fill within each ASN up to
/// `max_peers_per_asn`, stopping when `max_peers` is reached.
#[must_use]
pub fn select_diverse_peers(
    candidates: &[PeerMetadata],
    policy: &AsnPolicy,
    max_peers: usize,
) -> Vec<PeerMetadata> {
    if candidates.is_empty() || max_peers == 0 {
        return Vec::new();
    }

    // Group candidates by effective ASN, preserving order within each group.
    let mut by_asn: BTreeMap<Asn, Vec<&PeerMetadata>> = BTreeMap::new();
    for c in candidates {
        by_asn.entry(effective_asn(c)).or_default().push(c);
    }

    let mut selected: Vec<PeerMetadata> = Vec::with_capacity(max_peers);
    let mut round = 0usize;

    loop {
        if selected.len() >= max_peers {
            break;
        }
        let mut added_this_round = false;
        for bucket in by_asn.values() {
            if selected.len() >= max_peers {
                break;
            }
            if round >= policy.max_peers_per_asn {
                continue;
            }
            if let Some(peer) = bucket.get(round) {
                selected.push((*peer).clone());
                added_this_round = true;
            }
        }
        if !added_this_round {
            break;
        }
        round += 1;
    }

    selected
}

/// Return the IDs of peers that have not been seen within `max_age_ms` of `now`.
#[must_use]
pub fn identify_stale_peers(
    peers: &[PeerMetadata],
    now: &Timestamp,
    max_age_ms: u64,
) -> Vec<PeerId> {
    peers
        .iter()
        .filter(|p| {
            // A peer is stale when its last_seen is older than now - max_age_ms.
            now.physical_ms.saturating_sub(p.last_seen.physical_ms) > max_age_ms
        })
        .map(|p| p.info.id.clone())
        .collect()
}

/// Evict stale peers from `current` and replace them with diverse candidates.
///
/// Returns the [`PeerId`]s of the evicted peers.
pub fn rotate_peers(
    current: &mut Vec<PeerMetadata>,
    candidates: &[PeerMetadata],
    policy: &AsnPolicy,
    now: &Timestamp,
) -> Vec<PeerId> {
    let stale_ids: BTreeSet<PeerId> =
        identify_stale_peers(current, now, policy.rotation_interval_ms)
            .into_iter()
            .collect();

    let evicted: Vec<PeerId> = stale_ids.iter().cloned().collect();

    // Remove stale peers.
    current.retain(|p| !stale_ids.contains(&p.info.id));

    // Filter candidates that are not already in current.
    let current_ids: BTreeSet<PeerId> = current.iter().map(|p| p.info.id.clone()).collect();
    let fresh_candidates: Vec<PeerMetadata> = candidates
        .iter()
        .filter(|c| !current_ids.contains(&c.info.id))
        .cloned()
        .collect();

    // Select diverse replacements up to the number of evicted peers.
    let replacements = select_diverse_peers(&fresh_candidates, policy, evicted.len());
    current.extend(replacements);

    evicted
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    fn pid(n: &str) -> PeerId {
        PeerId(Did::new(&format!("did:exo:{n}")).unwrap())
    }
    fn info(n: &str) -> PeerInfo {
        PeerInfo {
            id: pid(n),
            addresses: vec!["addr".into()],
            public_key_hash: Hash256::ZERO,
            last_seen: Timestamp::ZERO,
            reputation_score: 50,
        }
    }
    fn msg(from: &str, to: Option<&str>) -> Message {
        let mut sig = [0u8; 64];
        sig[0] = 1;
        Message {
            from: pid(from),
            to: to.map(pid),
            payload: b"hello".to_vec(),
            signature: Signature::from_bytes(sig),
            nonce: 1,
        }
    }
    fn keypair(seed: u8) -> (PublicKey, exo_core::SecretKey) {
        let keypair = exo_core::crypto::KeyPair::from_secret_bytes([seed; 32]).expect("keypair");
        (*keypair.public_key(), keypair.secret_key().clone())
    }
    fn signed_msg(from: &str, to: Option<&str>, seed: u8) -> (Message, PublicKey) {
        let (public_key, secret_key) = keypair(seed);
        let mut message = Message {
            from: pid(from),
            to: to.map(pid),
            payload: b"hello".to_vec(),
            signature: Signature::Empty,
            nonce: 1,
        };
        let payload = message_signing_payload(&message).expect("signing payload");
        message.signature = exo_core::crypto::sign(&payload, &secret_key);
        (message, public_key)
    }

    #[test]
    fn registry_empty() {
        let r = PeerRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }
    #[test]
    fn registry_register() {
        let mut r = PeerRegistry::new();
        r.register(info("a"));
        assert_eq!(r.len(), 1);
        assert!(r.get(&pid("a")).is_some());
    }
    #[test]
    fn registry_default() {
        assert!(PeerRegistry::default().is_empty());
    }
    #[test]
    fn send_known_peer() {
        let mut r = PeerRegistry::new();
        r.register(info("b"));
        assert!(send(&r, &msg("a", Some("b"))).is_ok());
    }
    #[test]
    fn send_unknown_peer() {
        let r = PeerRegistry::new();
        assert!(send(&r, &msg("a", Some("b"))).is_err());
    }
    #[test]
    fn send_broadcast() {
        let r = PeerRegistry::new();
        assert!(send(&r, &msg("a", None)).is_ok());
    }
    #[test]
    fn message_signing_payload_is_domain_separated_and_deterministic() {
        let (message, _) = signed_msg("a", Some("b"), 7);
        let first = message_signing_payload(&message).expect("payload");
        let second = message_signing_payload(&message).expect("payload");
        assert_eq!(first, second);

        #[derive(Deserialize)]
        struct DecodedPayload {
            domain: String,
        }
        let decoded: DecodedPayload = ciborium::from_reader(&first[..]).expect("decode");
        assert_eq!(decoded.domain, "exo.p2p.message.v1");
    }
    #[test]
    fn verify_message_accepts_correct_signature() {
        let (message, public_key) = signed_msg("a", None, 7);
        assert!(verify_message(&message, &public_key).is_ok());
    }
    #[test]
    fn verify_message_rejects_empty_and_zero_signatures() {
        let (public_key, _) = keypair(7);
        let m = Message {
            from: pid("a"),
            to: None,
            payload: vec![],
            signature: Signature::Empty,
            nonce: 0,
        };
        assert!(verify_message(&m, &public_key).is_err());

        let m = Message {
            from: pid("a"),
            to: None,
            payload: vec![],
            signature: Signature::from_bytes([0u8; 64]),
            nonce: 0,
        };
        assert!(verify_message(&m, &public_key).is_err());
    }
    #[test]
    fn verify_message_rejects_fake_non_empty_signature() {
        let (public_key, _) = keypair(7);
        assert!(verify_message(&msg("a", None), &public_key).is_err());
    }
    #[test]
    fn verify_message_rejects_wrong_key() {
        let (message, _) = signed_msg("a", Some("b"), 7);
        let (wrong_public_key, _) = keypair(8);
        assert!(verify_message(&message, &wrong_public_key).is_err());
    }
    #[test]
    fn verify_message_rejects_tampering() {
        let (message, public_key) = signed_msg("a", Some("b"), 7);

        let mut tampered_payload = message.clone();
        tampered_payload.payload = b"goodbye".to_vec();
        assert!(verify_message(&tampered_payload, &public_key).is_err());

        let mut tampered_recipient = message.clone();
        tampered_recipient.to = Some(pid("c"));
        assert!(verify_message(&tampered_recipient, &public_key).is_err());

        let mut tampered_nonce = message.clone();
        tampered_nonce.nonce = 2;
        assert!(verify_message(&tampered_nonce, &public_key).is_err());

        let mut tampered_sender = message.clone();
        tampered_sender.from = pid("z");
        assert!(verify_message(&tampered_sender, &public_key).is_err());
    }
    #[test]
    fn validate_message_structure_keeps_non_crypto_checks_separate() {
        assert!(validate_message_structure(&msg("a", None)).is_ok());
    }
    #[test]
    fn discover() {
        let mut r = PeerRegistry::new();
        let d = discover_peers(&mut r, &["addr1".into(), "addr2".into()]).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(r.len(), 2);
    }
    #[test]
    fn discover_no_dupes() {
        let mut r = PeerRegistry::new();
        discover_peers(&mut r, &["a".into()]).unwrap();
        let d = discover_peers(&mut r, &["a".into()]).unwrap();
        assert!(d.is_empty());
    }
    #[test]
    fn rate_limiter() {
        let mut rl = RateLimiter::new();
        for _ in 0..100 {
            rl.check_and_increment(&pid("a")).unwrap();
        }
        assert!(rl.check_and_increment(&pid("a")).is_err());
    }
    #[test]
    fn rate_limiter_reset() {
        let mut rl = RateLimiter::new();
        for _ in 0..100 {
            rl.check_and_increment(&pid("a")).unwrap();
        }
        rl.reset();
        assert!(rl.check_and_increment(&pid("a")).is_ok());
    }
    #[test]
    fn peer_id_ord() {
        assert!(pid("a") < pid("b"));
    }
    #[test]
    fn message_serde() {
        let m = msg("a", Some("b"));
        let j = serde_json::to_string(&m).unwrap();
        assert!(!j.is_empty());
    }

    // -- ASN diversity helpers -----------------------------------------------

    fn peer_meta(name: &str, asn: Option<u32>, last_seen_ms: u64) -> PeerMetadata {
        PeerMetadata {
            info: info(name),
            asn: asn.map(Asn),
            first_seen: Timestamp::ZERO,
            last_seen: Timestamp::new(last_seen_ms, 0),
        }
    }

    // 1. All peers from a single ASN → Insufficient
    #[test]
    fn reject_single_asn_peer_set() {
        let peers: Vec<PeerMetadata> = (0..5)
            .map(|i| peer_meta(&format!("p{i}"), Some(64512), 1000))
            .collect();
        let policy = AsnPolicy::default();
        assert_eq!(
            check_asn_diversity(&peers, &policy),
            DiversityResult::Insufficient {
                unique_asns: 1,
                required: 3
            }
        );
    }

    // 2. Peers from 3+ ASNs → Sufficient
    #[test]
    fn accept_diverse_peer_set() {
        let peers = vec![
            peer_meta("a", Some(100), 1000),
            peer_meta("b", Some(200), 1000),
            peer_meta("c", Some(300), 1000),
        ];
        let policy = AsnPolicy::default();
        assert_eq!(
            check_asn_diversity(&peers, &policy),
            DiversityResult::Sufficient
        );
    }

    // 3. 10 peers from same ASN, max_peers_per_asn=5 → only 5 selected
    #[test]
    fn max_peers_per_asn_enforced() {
        let candidates: Vec<PeerMetadata> = (0..10)
            .map(|i| peer_meta(&format!("p{i}"), Some(64512), 1000))
            .collect();
        let policy = AsnPolicy {
            max_peers_per_asn: 5,
            ..AsnPolicy::default()
        };
        let selected = select_diverse_peers(&candidates, &policy, 20);
        assert_eq!(selected.len(), 5);
    }

    // 4. Candidates from 4 ASNs, max 8 → 2 per ASN (round-robin)
    #[test]
    fn select_diverse_round_robin() {
        let mut candidates = Vec::new();
        for asn in [10, 20, 30, 40] {
            for i in 0..4 {
                candidates.push(peer_meta(&format!("asn{asn}-p{i}"), Some(asn), 1000));
            }
        }
        let policy = AsnPolicy::default();
        let selected = select_diverse_peers(&candidates, &policy, 8);
        assert_eq!(selected.len(), 8);
        // Count per ASN — each should have exactly 2
        let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
        for p in &selected {
            *counts.entry(p.asn.unwrap().0).or_default() += 1;
        }
        for &c in counts.values() {
            assert_eq!(c, 2);
        }
    }

    // 5. Stale peers identified correctly
    #[test]
    fn identify_stale_peers_test() {
        let now = Timestamp::new(10_000_000, 0);
        let max_age_ms = 7_200_000; // 2 hours
        let peers = vec![
            peer_meta("fresh", Some(1), 9_000_000), // seen 1 s ago, not stale
            peer_meta("stale1", Some(2), 1_000_000), // seen 9000 s ago, stale
            peer_meta("stale2", Some(3), 2_000_000), // seen 8000 s ago, stale
        ];
        let stale = identify_stale_peers(&peers, &now, max_age_ms);
        assert_eq!(stale.len(), 2);
        assert!(stale.contains(&pid("stale1")));
        assert!(stale.contains(&pid("stale2")));
    }

    // 6. Stale peers evicted and replaced with diverse candidates
    #[test]
    fn rotate_replaces_stale_with_diverse() {
        let now = Timestamp::new(10_000_000, 0);
        let policy = AsnPolicy {
            rotation_interval_ms: 3_600_000,
            ..AsnPolicy::default()
        };
        let mut current = vec![
            peer_meta("keep", Some(100), 9_000_000), // fresh
            peer_meta("old1", Some(100), 1_000_000), // stale
            peer_meta("old2", Some(100), 2_000_000), // stale
        ];
        let candidates = vec![
            peer_meta("new1", Some(200), 9_500_000),
            peer_meta("new2", Some(300), 9_500_000),
        ];
        let evicted = rotate_peers(&mut current, &candidates, &policy, &now);
        assert_eq!(evicted.len(), 2);
        assert!(evicted.contains(&pid("old1")));
        assert!(evicted.contains(&pid("old2")));
        // current should now have: keep + up to 2 replacements
        assert!(current.len() >= 2 && current.len() <= 3);
        let ids: Vec<PeerId> = current.iter().map(|p| p.info.id.clone()).collect();
        assert!(ids.contains(&pid("keep")));
    }

    // 7. Empty candidates → no crash
    #[test]
    fn empty_candidates_no_crash() {
        let selected = select_diverse_peers(&[], &AsnPolicy::default(), 10);
        assert!(selected.is_empty());
        let stale = identify_stale_peers(&[], &Timestamp::ZERO, 1000);
        assert!(stale.is_empty());
    }

    // 8. Peers with asn: None grouped together
    #[test]
    fn no_asn_peers_treated_as_same_group() {
        let peers = vec![
            peer_meta("a", None, 1000),
            peer_meta("b", None, 1000),
            peer_meta("c", None, 1000),
        ];
        let policy = AsnPolicy::default();
        // All None → single effective ASN group → 1 unique ASN
        assert_eq!(
            check_asn_diversity(&peers, &policy),
            DiversityResult::Insufficient {
                unique_asns: 1,
                required: 3
            }
        );
        // select_diverse_peers respects max_peers_per_asn for the None group
        let policy2 = AsnPolicy {
            max_peers_per_asn: 2,
            ..AsnPolicy::default()
        };
        let selected = select_diverse_peers(&peers, &policy2, 10);
        assert_eq!(selected.len(), 2);
    }

    // 9. Policy default values
    #[test]
    fn policy_default_values() {
        let p = AsnPolicy::default();
        assert_eq!(p.min_unique_asns, 3);
        assert_eq!(p.max_peers_per_asn, 5);
        assert_eq!(p.rotation_interval_ms, 3_600_000);
    }
}

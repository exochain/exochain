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

//! Peer-to-peer mesh networking.
use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, Result};

const P2P_MESSAGE_SIGNING_DOMAIN: &str = "exo.p2p.message.v1";
pub const MAX_P2P_MESSAGE_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_BOOTSTRAP_DISCOVERY_PEERS: usize = 4_096;
const MAX_DIVERSE_SELECTION_PEERS: usize = 4_096;

/// Unique identifier for a peer in the P2P mesh, wrapping a DID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Did);

impl PeerId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MessageReplayKey {
    from: PeerId,
    nonce: u64,
}

impl MessageReplayKey {
    fn from_message(msg: &Message) -> Self {
        Self {
            from: msg.from.clone(),
            nonce: msg.nonce,
        }
    }
}

/// Stateful acceptance guard for signed peer-to-peer messages.
#[derive(Debug, Default)]
pub struct MessageReplayGuard {
    seen: BTreeSet<MessageReplayKey>,
}

impl MessageReplayGuard {
    /// Maximum accepted messages tracked in a replay window.
    pub const MAX_TRACKED_MESSAGES: usize = 4096;

    /// Create an empty replay guard.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }

    /// Return the number of messages currently tracked in the replay window.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Return `true` when no message keys are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Reset the replay window.
    pub fn reset(&mut self) {
        self.seen.clear();
    }

    /// Verify a message signature and record its replay key after success.
    pub fn verify_and_record(
        &mut self,
        msg: &Message,
        sender_public_key: &PublicKey,
    ) -> Result<()> {
        validate_message_structure(msg)?;
        let key = MessageReplayKey::from_message(msg);
        if self.seen.contains(&key) {
            return Err(ApiError::ReplayDetected {
                peer_id: msg.from.to_string(),
                nonce: msg.nonce,
            });
        }
        if self.seen.len() >= Self::MAX_TRACKED_MESSAGES {
            return Err(ApiError::RateLimited {
                peer_id: msg.from.to_string(),
            });
        }
        verify_message_signature(msg, sender_public_key)?;
        self.seen.insert(key);
        Ok(())
    }
}

/// Rate-limit tracking per peer.
#[derive(Debug, Default)]
pub struct RateLimiter {
    counts: BTreeMap<PeerId, u32>,
}
impl RateLimiter {
    /// Maximum number of distinct peers tracked in one rate-limit window.
    ///
    /// Distinct peer IDs are attacker-controlled at the network boundary. Keep
    /// this bounded so a stream of one-shot IDs cannot grow memory without
    /// limit before the next window reset.
    pub const MAX_TRACKED_PEERS: usize = 4096;
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
        if !self.counts.contains_key(peer) && self.counts.len() >= Self::MAX_TRACKED_PEERS {
            return Err(ApiError::RateLimited {
                peer_id: peer.to_string(),
            });
        }

        let c = self.counts.entry(peer.clone()).or_insert(0);
        if *c >= Self::MAX_PER_WINDOW {
            return Err(ApiError::RateLimited {
                peer_id: peer.to_string(),
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
            return Err(ApiError::PeerNotFound(to.to_string()));
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

fn validate_message_payload_size(msg: &Message) -> Result<()> {
    if msg.payload.len() > MAX_P2P_MESSAGE_PAYLOAD_BYTES {
        return Err(ApiError::InvalidSchema {
            reason: format!(
                "P2P message payload length {} exceeds maximum {}",
                msg.payload.len(),
                MAX_P2P_MESSAGE_PAYLOAD_BYTES
            ),
        });
    }
    Ok(())
}

/// Canonical CBOR payload signed by a peer-to-peer message sender.
///
/// The domain tag prevents cross-protocol replay, and the payload binds sender,
/// optional recipient, body bytes, and nonce. The signature field is excluded
/// so callers can use this function before and after signing.
pub fn message_signing_payload(msg: &Message) -> Result<Vec<u8>> {
    validate_message_payload_size(msg)?;
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
    validate_message_payload_size(msg)?;
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

fn verify_message_signature(msg: &Message, sender_public_key: &PublicKey) -> Result<()> {
    let payload = message_signing_payload(msg)?;
    if exo_core::crypto::verify(&payload, &msg.signature, sender_public_key) {
        Ok(())
    } else {
        Err(ApiError::VerificationFailed {
            reason: "invalid Ed25519 signature".into(),
        })
    }
}

/// Verify a peer-to-peer message Ed25519 signature against the sender public key.
pub fn verify_message(msg: &Message, sender_public_key: &PublicKey) -> Result<()> {
    validate_message_structure(msg)?;
    verify_message_signature(msg, sender_public_key)
}

/// Discover new peers from bootstrap addresses and register them.
pub fn discover_peers(registry: &mut PeerRegistry, bootstrap: &[String]) -> Result<Vec<PeerId>> {
    if bootstrap.len() > MAX_BOOTSTRAP_DISCOVERY_PEERS {
        return Err(ApiError::InvalidSchema {
            reason: format!(
                "bootstrap peer list length {} exceeds maximum {}",
                bootstrap.len(),
                MAX_BOOTSTRAP_DISCOVERY_PEERS
            ),
        });
    }

    let mut discovered = Vec::with_capacity(bootstrap.len());
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
    Insufficient {
        unique_asns: usize,
        required: usize,
    },
    OverrepresentedAsn {
        asn: Asn,
        peers: usize,
        maximum: usize,
    },
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
    let mut by_asn: BTreeMap<Asn, usize> = BTreeMap::new();
    for peer in peers {
        *by_asn.entry(effective_asn(peer)).or_default() += 1;
    }

    for (asn, peer_count) in &by_asn {
        if *peer_count > policy.max_peers_per_asn {
            return DiversityResult::OverrepresentedAsn {
                asn: *asn,
                peers: *peer_count,
                maximum: policy.max_peers_per_asn,
            };
        }
    }

    if by_asn.len() >= policy.min_unique_asns {
        DiversityResult::Sufficient
    } else {
        DiversityResult::Insufficient {
            unique_asns: by_asn.len(),
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
    let selection_limit = max_peers
        .min(candidates.len())
        .min(MAX_DIVERSE_SELECTION_PEERS);
    if candidates.is_empty() || selection_limit == 0 {
        return Vec::new();
    }

    // Group candidates by effective ASN, preserving order within each group.
    let mut by_asn: BTreeMap<Asn, Vec<&PeerMetadata>> = BTreeMap::new();
    for c in candidates {
        by_asn.entry(effective_asn(c)).or_default().push(c);
    }

    let mut selected: Vec<PeerMetadata> = Vec::with_capacity(selection_limit);
    let mut round = 0usize;

    loop {
        if selected.len() >= selection_limit {
            break;
        }
        let mut added_this_round = false;
        for bucket in by_asn.values() {
            if selected.len() >= selection_limit {
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
            now.physical_ms
                .checked_sub(p.last_seen.physical_ms)
                .is_none_or(|age| age > max_age_ms)
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
        sign_message(&mut message, &secret_key);
        (message, public_key)
    }
    fn sign_message(message: &mut Message, secret_key: &exo_core::SecretKey) {
        let payload = message_signing_payload(message).expect("signing payload");
        message.signature = exo_core::crypto::sign(&payload, secret_key);
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
        let err = send(&r, &msg("a", Some("b"))).unwrap_err();
        assert!(matches!(
            err,
            ApiError::PeerNotFound(peer_id) if peer_id == "did:exo:b"
        ));
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
    fn verify_message_rejects_oversized_payload_before_signature_work() {
        let (public_key, _) = keypair(7);
        let oversized = Message {
            from: pid("a"),
            to: None,
            payload: vec![0xA5; MAX_P2P_MESSAGE_PAYLOAD_BYTES + 1],
            signature: Signature::from_bytes([1u8; 64]),
            nonce: 42,
        };

        let err = verify_message(&oversized, &public_key).unwrap_err();

        assert!(matches!(
            err,
            ApiError::InvalidSchema { reason } if reason.contains("payload")
                && reason.contains(&MAX_P2P_MESSAGE_PAYLOAD_BYTES.to_string())
        ));
    }
    #[test]
    fn message_signing_payload_rejects_oversized_payload_before_cbor_serialization() {
        let mut message = msg("a", None);
        message.payload = vec![0xA5; MAX_P2P_MESSAGE_PAYLOAD_BYTES + 1];

        let err = message_signing_payload(&message).unwrap_err();

        assert!(matches!(
            err,
            ApiError::InvalidSchema { reason } if reason.contains("payload")
                && reason.contains(&MAX_P2P_MESSAGE_PAYLOAD_BYTES.to_string())
        ));
    }
    #[test]
    fn message_replay_guard_rejects_duplicate_signed_message_without_recording_tamper() {
        let (message, public_key) = signed_msg("a", Some("b"), 7);
        let mut guard = MessageReplayGuard::new();

        assert!(guard.verify_and_record(&message, &public_key).is_ok());
        let replay = guard.verify_and_record(&message, &public_key).unwrap_err();

        assert!(matches!(
            replay,
            ApiError::ReplayDetected { peer_id, nonce }
                if peer_id == "did:exo:a" && nonce == message.nonce
        ));

        let mut tampered = message.clone();
        tampered.nonce += 1;
        tampered.payload = b"tampered".to_vec();
        let tamper_err = guard.verify_and_record(&tampered, &public_key).unwrap_err();
        assert!(matches!(
            tamper_err,
            ApiError::VerificationFailed { reason } if reason == "invalid Ed25519 signature"
        ));
        assert_eq!(
            guard.len(),
            1,
            "failed verifications must not grow replay state"
        );
    }
    #[test]
    fn message_replay_guard_rejects_reused_sender_nonce_with_new_valid_payload() {
        let (public_key, secret_key) = keypair(7);
        let mut first = Message {
            from: pid("a"),
            to: Some(pid("b")),
            payload: b"hello".to_vec(),
            signature: Signature::Empty,
            nonce: 7,
        };
        sign_message(&mut first, &secret_key);
        let mut second = first.clone();
        second.payload = b"new signed payload".to_vec();
        second.signature = Signature::Empty;
        sign_message(&mut second, &secret_key);
        let mut guard = MessageReplayGuard::new();

        assert!(guard.verify_and_record(&first, &public_key).is_ok());
        let replay = guard.verify_and_record(&second, &public_key).unwrap_err();

        assert!(matches!(
            replay,
            ApiError::ReplayDetected { peer_id, nonce } if peer_id == "did:exo:a" && nonce == 7
        ));
        assert_eq!(guard.len(), 1);
    }
    #[test]
    fn message_replay_guard_bounds_tracked_state_and_can_reset() {
        let (message, public_key) = signed_msg("a", Some("b"), 7);
        let mut guard = MessageReplayGuard::new();
        for nonce in 0..MessageReplayGuard::MAX_TRACKED_MESSAGES {
            guard.seen.insert(MessageReplayKey {
                from: pid("filled"),
                nonce: u64::try_from(nonce).unwrap(),
            });
        }

        let err = guard.verify_and_record(&message, &public_key).unwrap_err();

        assert!(matches!(
            err,
            ApiError::RateLimited { peer_id } if peer_id == "did:exo:a"
        ));
        assert_eq!(guard.len(), MessageReplayGuard::MAX_TRACKED_MESSAGES);

        guard.reset();
        assert!(guard.is_empty());
        assert!(guard.verify_and_record(&message, &public_key).is_ok());
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
    fn discover_peers_rejects_oversized_bootstrap_before_mutating_registry() {
        const MAX_BOOTSTRAP_PEERS: usize = 4_096;
        let bootstrap: Vec<String> = (0..(MAX_BOOTSTRAP_PEERS + 1))
            .map(|i| format!("addr-{i}"))
            .collect();
        let mut registry = PeerRegistry::new();

        let err = discover_peers(&mut registry, &bootstrap).unwrap_err();

        assert!(matches!(err, ApiError::InvalidSchema { .. }));
        assert_eq!(registry.len(), 0);
    }
    #[test]
    fn rate_limiter() {
        let mut rl = RateLimiter::new();
        for _ in 0..100 {
            rl.check_and_increment(&pid("a")).unwrap();
        }
        let err = rl.check_and_increment(&pid("a")).unwrap_err();
        assert!(matches!(
            err,
            ApiError::RateLimited { peer_id } if peer_id == "did:exo:a"
        ));
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
    fn rate_limiter_bounds_distinct_peer_tracking() {
        let mut rl = RateLimiter::new();
        for i in 0..RateLimiter::MAX_TRACKED_PEERS {
            rl.check_and_increment(&pid(&format!("peer-{i}"))).unwrap();
        }

        assert_eq!(rl.counts.len(), RateLimiter::MAX_TRACKED_PEERS);
        let err = rl.check_and_increment(&pid("overflow-peer")).unwrap_err();
        assert!(matches!(
            err,
            ApiError::RateLimited { peer_id } if peer_id == "did:exo:overflow-peer"
        ));
        assert_eq!(
            rl.counts.len(),
            RateLimiter::MAX_TRACKED_PEERS,
            "refused peers must not grow the limiter state"
        );
        assert!(rl.check_and_increment(&pid("peer-0")).is_ok());
    }
    #[test]
    fn p2p_error_peer_labels_do_not_depend_on_debug_formatting() {
        let source = include_str!("p2p.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(
            !production.contains("format!(\"{:?}\", peer)"),
            "P2P rate-limit errors must use stable peer labels"
        );
        assert!(
            !production.contains("format!(\"{to:?}\")"),
            "P2P peer lookup errors must use stable peer labels"
        );
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

    #[test]
    fn reject_peer_set_exceeding_max_peers_per_asn_even_when_unique_asns_sufficient() {
        let mut peers: Vec<PeerMetadata> = (0..6)
            .map(|i| peer_meta(&format!("attacker-{i}"), Some(64512), 1000))
            .collect();
        peers.push(peer_meta("honest-a", Some(64513), 1000));
        peers.push(peer_meta("honest-b", Some(64514), 1000));
        let policy = AsnPolicy::default();

        assert_eq!(
            check_asn_diversity(&peers, &policy),
            DiversityResult::OverrepresentedAsn {
                asn: Asn(64512),
                peers: 6,
                maximum: 5
            }
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

    #[test]
    fn select_diverse_peers_clamps_untrusted_max_peers_before_allocating() {
        const EXPECTED_SELECTION_LIMIT: usize = 4_096;
        let candidates: Vec<PeerMetadata> = (0..(EXPECTED_SELECTION_LIMIT + 1))
            .map(|i| {
                peer_meta(
                    &format!("peer-{i}"),
                    Some(u32::try_from(i + 1).unwrap()),
                    1000,
                )
            })
            .collect();
        let policy = AsnPolicy {
            max_peers_per_asn: 1,
            ..AsnPolicy::default()
        };

        let selected = select_diverse_peers(&candidates, &policy, usize::MAX);

        assert_eq!(selected.len(), EXPECTED_SELECTION_LIMIT);
        assert_eq!(selected.first().unwrap().info.id, candidates[0].info.id);
        assert_eq!(
            selected.last().unwrap().info.id,
            candidates[EXPECTED_SELECTION_LIMIT - 1].info.id
        );
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

    #[test]
    fn identify_stale_peers_treats_future_last_seen_as_stale() {
        let now = Timestamp::new(10_000_000, 0);
        let peers = vec![peer_meta("future", Some(1), 10_001_000)];

        let stale = identify_stale_peers(&peers, &now, 7_200_000);

        assert_eq!(stale, vec![pid("future")]);
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

//! 0dentity score and claim store.
//!
//! This module provides the shared state accessor for 0dentity scoring data.
//! The full SQLite-backed persistence layer is implemented in APE-72.  This
//! stub exposes the interface the sentinel, API handlers, and Telegram adjutant
//! depend on so APE-73 can land independently; APE-72 fills in the actual storage.
//!
//! All inner maps use `BTreeMap` (never `HashMap`) for deterministic iteration.
//!
//! Spec reference: §9, §12.1.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use exo_core::types::{Did, Hash256, ReceiptOutcome, Signature, Timestamp, TrustReceipt};
use exo_dag::dag::DagNode;

use super::types::{
    BehavioralSample, ClaimStatus, DeviceFingerprint, IdentityClaim, IdentitySession, OtpChallenge,
    PeerAttestation, ZerodentityScore,
};

// ---------------------------------------------------------------------------
// ZerodentityStore
// ---------------------------------------------------------------------------

/// In-memory 0dentity store.
///
/// Keyed by DID string for O(log n) lookup.  All inner maps use `BTreeMap`
/// (never `HashMap`) for deterministic iteration order.
///
/// APE-72 replaces this with a SQLite-backed implementation; the public
/// interface must remain stable.
#[derive(Debug, Default)]
pub struct ZerodentityStore {
    /// Latest score snapshot per DID.
    scores: BTreeMap<String, ZerodentityScore>,
    /// Previous score snapshot per DID (one level of history).
    prev_scores: BTreeMap<String, ZerodentityScore>,
    /// All score history per DID.
    score_history: BTreeMap<String, Vec<ZerodentityScore>>,
    /// Identity claims per DID: (claim_id, claim).
    claims: BTreeMap<String, Vec<(String, IdentityClaim)>>,
    /// Device fingerprints per DID.
    fingerprints: BTreeMap<String, Vec<DeviceFingerprint>>,
    /// Behavioral samples per DID.
    behavioral: BTreeMap<String, Vec<BehavioralSample>>,
    /// OTP lockout event timestamps (epoch ms) per DID.
    otp_lockouts: BTreeMap<String, Vec<u64>>,
    /// Active OTP challenges by challenge_id.
    otp_challenges: BTreeMap<String, OtpChallenge>,
    /// Peer attestations: (attester_did_str, target_did_str) → attestation.
    attestations: BTreeMap<(String, String), PeerAttestation>,
    /// Identity sessions by session token.
    sessions: BTreeMap<String, IdentitySession>,
    /// DAG nodes recorded for claim operations (APE-72).
    dag_nodes: Vec<DagNode>,
    /// Trust receipts emitted for claim verification events (APE-72).
    trust_receipts: Vec<TrustReceipt>,
}

impl ZerodentityStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the 0dentity store.
    ///
    /// In this in-memory implementation the `data_dir` argument is accepted but
    /// ignored — all data lives in process memory only.  APE-72 will replace this
    /// with a SQLite-backed implementation that reads/writes `data_dir/dag.db`.
    pub fn open(_data_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self::new())
    }

    // -----------------------------------------------------------------------
    // Write — claims
    // -----------------------------------------------------------------------

    /// Store an identity claim under the given claim ID.
    pub fn insert_claim(&mut self, claim_id: &str, claim: &IdentityClaim) -> anyhow::Result<()> {
        self.claims
            .entry(claim.subject_did.as_str().to_owned())
            .or_default()
            .push((claim_id.to_owned(), claim.clone()));
        Ok(())
    }

    /// Append a claim for a DID (mutable convenience method).
    #[allow(dead_code)]
    pub fn put_claim(&mut self, claim: IdentityClaim) {
        let key = claim.subject_did.as_str().to_owned();
        let claim_id = hex::encode(claim.claim_hash.as_bytes());
        self.claims.entry(key).or_default().push((claim_id, claim));
    }

    // -----------------------------------------------------------------------
    // Write — fingerprints / behavioral
    // -----------------------------------------------------------------------

    /// Append a device fingerprint for a DID.
    #[allow(dead_code)]
    pub fn put_fingerprint(&mut self, did: &Did, fp: DeviceFingerprint) {
        self.fingerprints
            .entry(did.as_str().to_owned())
            .or_default()
            .push(fp);
    }

    /// Append a behavioral sample for a DID.
    #[allow(dead_code)]
    pub fn put_behavioral(&mut self, did: &Did, sample: BehavioralSample) {
        self.behavioral
            .entry(did.as_str().to_owned())
            .or_default()
            .push(sample);
    }

    // -----------------------------------------------------------------------
    // Write — scores
    // -----------------------------------------------------------------------

    /// Store a new score snapshot, shifting the current to `prev_scores`.
    #[allow(dead_code)]
    pub fn put_score(&mut self, score: ZerodentityScore) {
        let key = score.subject_did.as_str().to_owned();
        if let Some(existing) = self.scores.remove(&key) {
            self.prev_scores.insert(key.clone(), existing);
        }
        self.score_history
            .entry(key.clone())
            .or_default()
            .push(score.clone());
        self.scores.insert(key, score);
    }

    // -----------------------------------------------------------------------
    // Write — OTP
    // -----------------------------------------------------------------------

    /// Record an OTP lockout event at `timestamp_ms` for a DID.
    #[allow(dead_code)]
    pub fn record_otp_lockout(&mut self, did: &Did, timestamp_ms: u64) {
        self.otp_lockouts
            .entry(did.as_str().to_owned())
            .or_default()
            .push(timestamp_ms);
    }

    /// Persist an OTP challenge.
    pub fn insert_otp_challenge(&mut self, challenge: &OtpChallenge) -> anyhow::Result<()> {
        self.otp_challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(())
    }

    /// Update the state of an existing OTP challenge.
    pub fn update_otp_challenge(&mut self, challenge: &OtpChallenge) -> anyhow::Result<()> {
        if self.otp_challenges.contains_key(&challenge.challenge_id) {
            self.otp_challenges
                .insert(challenge.challenge_id.clone(), challenge.clone());
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write — attestations
    // -----------------------------------------------------------------------

    /// Persist a peer attestation.
    pub fn insert_attestation(&mut self, att: &PeerAttestation) -> anyhow::Result<()> {
        let key = (
            att.attester_did.as_str().to_owned(),
            att.target_did.as_str().to_owned(),
        );
        self.attestations.insert(key, att.clone());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write — sessions
    // -----------------------------------------------------------------------

    /// Persist an identity session.
    pub fn insert_session(&mut self, session: &IdentitySession) -> anyhow::Result<()> {
        self.sessions
            .insert(session.session_token.clone(), session.clone());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read — claims
    // -----------------------------------------------------------------------

    /// Return all claims for a DID with their claim IDs.
    ///
    /// Returns an empty `Vec` (not an error) when the DID has no claims.
    pub fn get_claims(&self, did: &Did) -> anyhow::Result<Vec<(String, IdentityClaim)>> {
        Ok(self.claims.get(did.as_str()).cloned().unwrap_or_default())
    }

    /// Return all claims for a DID as a plain slice (no claim IDs).
    ///
    /// Convenience method for callers that only need the claims themselves
    /// (e.g., sentinels and scoring).
    #[must_use]
    #[allow(dead_code)]
    pub fn get_claims_slice(&self, did: &Did) -> Vec<IdentityClaim> {
        self.claims
            .get(did.as_str())
            .map(|v| v.iter().map(|(_, c)| c.clone()).collect())
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // Read — fingerprints / behavioral
    // -----------------------------------------------------------------------

    /// Return all device fingerprints for a DID.
    pub fn get_fingerprints(&self, did: &Did) -> anyhow::Result<Vec<DeviceFingerprint>> {
        Ok(self
            .fingerprints
            .get(did.as_str())
            .cloned()
            .unwrap_or_default())
    }

    /// Return all behavioral samples for a DID.
    pub fn get_behavioral_samples(&self, did: &Did) -> anyhow::Result<Vec<BehavioralSample>> {
        Ok(self
            .behavioral
            .get(did.as_str())
            .cloned()
            .unwrap_or_default())
    }

    // -----------------------------------------------------------------------
    // Read — scores
    // -----------------------------------------------------------------------

    /// Return the latest score for a DID, or `None` if not yet scored.
    #[must_use]
    pub fn get_score(&self, did: &Did) -> Option<&ZerodentityScore> {
        self.scores.get(did.as_str())
    }

    /// Return the previous score snapshot for a DID, or `None`.
    #[must_use]
    pub fn get_previous_score(&self, did: &Did) -> Option<&ZerodentityScore> {
        self.prev_scores.get(did.as_str())
    }

    /// Return score history for a DID, optionally filtered by time range.
    pub fn get_score_history(
        &self,
        did: &Did,
        from_ms: Option<u64>,
        to_ms: Option<u64>,
    ) -> anyhow::Result<Vec<ZerodentityScore>> {
        let history = self
            .score_history
            .get(did.as_str())
            .map_or(&[][..], Vec::as_slice);
        let filtered: Vec<ZerodentityScore> = history
            .iter()
            .filter(|s| {
                let after = from_ms.is_none_or(|f| s.computed_ms >= f);
                let before = to_ms.is_none_or(|t| s.computed_ms <= t);
                after && before
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    // -----------------------------------------------------------------------
    // Read — OTP
    // -----------------------------------------------------------------------

    /// Return `true` if there is any OTP lockout event for `did` at or after
    /// `since_ms`.
    #[must_use]
    pub fn has_otp_lockout_since(&self, did: &Did, since_ms: u64) -> bool {
        self.otp_lockouts
            .get(did.as_str())
            .is_some_and(|events| events.iter().any(|&t| t >= since_ms))
    }

    /// Retrieve an OTP challenge by ID.
    pub fn get_otp_challenge(&self, challenge_id: &str) -> anyhow::Result<Option<OtpChallenge>> {
        Ok(self.otp_challenges.get(challenge_id).cloned())
    }

    // -----------------------------------------------------------------------
    // Read — attestations
    // -----------------------------------------------------------------------

    /// Return `true` if an attestation from `attester` to `target` already exists.
    pub fn attestation_exists(&self, attester: &Did, target: &Did) -> anyhow::Result<bool> {
        let key = (attester.as_str().to_owned(), target.as_str().to_owned());
        Ok(self.attestations.contains_key(&key))
    }

    // -----------------------------------------------------------------------
    // Read — sessions
    // -----------------------------------------------------------------------

    /// Retrieve an identity session by token.
    ///
    /// Returns `None` if no matching session exists or if the session has been
    /// revoked.
    pub fn get_session(&self, token: &str) -> anyhow::Result<Option<IdentitySession>> {
        Ok(self.sessions.get(token).filter(|s| !s.revoked).cloned())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Sample up to `n` DIDs that have at least one stored score.
    ///
    /// Returns DIDs in sorted order (deterministic) — the sentinel picks
    /// entries from the front for repeatable verification.
    #[must_use]
    pub fn sample_scored_dids(&self, n: usize) -> Vec<Did> {
        self.scores
            .keys()
            .take(n)
            .filter_map(|k| Did::new(k).ok())
            .collect()
    }

    /// Return the count of distinct scored DIDs.
    #[must_use]
    pub fn scored_did_count(&self) -> usize {
        self.scores.len()
    }

    // -----------------------------------------------------------------------
    // APE-72 — CRUD API + DAG/TrustReceipt integration
    // -----------------------------------------------------------------------

    /// Run schema migrations — no-op for the in-memory implementation.
    ///
    /// Idempotent; always returns `Ok(())`.
    #[allow(dead_code)]
    pub fn run_migrations(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Persist a claim, record a DAG node entry, and optionally emit a
    /// `TrustReceipt` when the claim is already `Verified`.
    ///
    /// - A `DagNode` is appended to `self.dag_nodes` on every call.
    /// - A `TrustReceipt` (outcome `Executed`) is pushed to
    ///   `self.trust_receipts` when `claim.status == Verified`.
    #[allow(dead_code)]
    pub fn save_claim(&mut self, claim_id: &str, claim: &IdentityClaim) -> anyhow::Result<()> {
        self.insert_claim(claim_id, claim)?;

        // Record DAG node for this claim.
        let node = DagNode {
            hash: claim.dag_node_hash,
            parents: vec![],
            payload_hash: claim.claim_hash,
            creator_did: claim.subject_did.clone(),
            timestamp: Timestamp::new(claim.created_ms, 0),
            signature: Signature::Empty,
        };
        self.dag_nodes.push(node);

        // Emit TrustReceipt for verified claims.
        if claim.status == ClaimStatus::Verified {
            let verified_ms = claim.verified_ms.unwrap_or(claim.created_ms);
            let receipt = TrustReceipt::new(
                claim.subject_did.clone(),
                Hash256::ZERO,
                None,
                "zerodentity.claim_verified".to_string(),
                claim.claim_hash,
                ReceiptOutcome::Executed,
                Timestamp::new(verified_ms, 0),
                &|_payload| Signature::Empty,
            );
            self.trust_receipts.push(receipt);
        }

        Ok(())
    }

    /// Persist an OTP challenge (APE-72 alias for `insert_otp_challenge`).
    #[allow(dead_code)]
    pub fn save_otp(&mut self, challenge: &OtpChallenge) -> anyhow::Result<()> {
        self.insert_otp_challenge(challenge)
    }

    /// Retrieve an OTP challenge by ID (APE-72 alias for `get_otp_challenge`).
    #[allow(dead_code)]
    pub fn get_otp(&self, challenge_id: &str) -> anyhow::Result<Option<OtpChallenge>> {
        self.get_otp_challenge(challenge_id)
    }

    /// Persist a new score snapshot (APE-72 alias for `put_score`).
    #[allow(dead_code)]
    pub fn save_score(&mut self, score: ZerodentityScore) {
        self.put_score(score);
    }

    /// Return all recorded DAG nodes (APE-72 audit accessor).
    #[must_use]
    #[allow(dead_code)]
    pub fn dag_nodes(&self) -> &[DagNode] {
        &self.dag_nodes
    }

    /// Return all recorded trust receipts (APE-72 audit accessor).
    #[must_use]
    #[allow(dead_code)]
    pub fn trust_receipts(&self) -> &[TrustReceipt] {
        &self.trust_receipts
    }

    // -----------------------------------------------------------------------
    // Write — erasure (§11.4 Right to Erasure)
    // -----------------------------------------------------------------------

    /// Erase all data associated with a DID.
    ///
    /// Implements §11.4 — right to erasure:
    /// 1. Revoke all sessions for this DID.
    /// 2. Mark all claims as `Revoked`.
    /// 3. Remove score snapshots (current, previous, history).
    /// 4. Remove fingerprints and behavioral samples.
    /// 5. Remove OTP challenges belonging to this DID.
    /// 6. Tombstone DAG nodes — zero payload hash, keep structural links.
    /// 7. Emit an erasure receipt.
    ///
    /// Returns the number of claims revoked.
    pub fn erase_did(&mut self, did: &Did) -> anyhow::Result<u32> {
        let key = did.as_str().to_owned();
        let mut revoked_count = 0u32;

        // 1. Revoke sessions
        for session in self.sessions.values_mut() {
            if session.subject_did.as_str() == did.as_str() {
                session.revoked = true;
            }
        }

        // 2. Mark claims Revoked
        if let Some(claims) = self.claims.get_mut(&key) {
            for (_, claim) in claims.iter_mut() {
                if claim.status != ClaimStatus::Revoked {
                    claim.status = ClaimStatus::Revoked;
                    revoked_count += 1;
                }
            }
        }

        // 3. Zero score snapshots
        self.scores.remove(&key);
        self.prev_scores.remove(&key);
        self.score_history.remove(&key);

        // 4. Remove fingerprints and behavioral samples
        self.fingerprints.remove(&key);
        self.behavioral.remove(&key);

        // 5. Remove OTP challenges for this DID
        self.otp_challenges
            .retain(|_, ch| ch.subject_did.as_str() != did.as_str());

        // 6. Tombstone DAG nodes — zero the payload hash
        for node in &mut self.dag_nodes {
            if node.creator_did.as_str() == did.as_str() {
                node.payload_hash = Hash256::ZERO;
            }
        }

        // 7. Emit erasure receipt
        let now_ms = crate::sentinels::now_ms();
        let receipt = TrustReceipt::new(
            did.clone(),
            Hash256::ZERO,
            None,
            "zerodentity.identity_erased".to_string(),
            Hash256::digest(format!("erase:{}", did.as_str()).as_bytes()),
            ReceiptOutcome::Executed,
            Timestamp::new(now_ms, 0),
            &|_payload| Signature::Empty,
        );
        self.trust_receipts.push(receipt);

        Ok(revoked_count)
    }

    // -----------------------------------------------------------------------
    // Read — OTP challenges (sentinel support)
    // -----------------------------------------------------------------------

    /// Return all OTP challenges (for sentinel cleanup checks).
    #[must_use]
    pub fn all_otp_challenges(&self) -> Vec<&OtpChallenge> {
        self.otp_challenges.values().collect()
    }

    /// Remove expired OTP challenges that are still in `Pending` state.
    ///
    /// Returns the number of challenges cleaned up.
    pub fn cleanup_expired_otp(&mut self, now_ms: u64) -> u32 {
        let before = self.otp_challenges.len();
        self.otp_challenges.retain(|_, ch| {
            let expired = now_ms > ch.dispatched_ms.saturating_add(ch.ttl_ms);
            let pending = ch.state == super::types::OtpState::Pending;
            // Remove if both expired and still pending
            !(expired && pending)
        });
        (before - self.otp_challenges.len()) as u32
    }
}

/// Thread-safe shared handle to the 0dentity store.
pub type SharedZerodentityStore = Arc<Mutex<ZerodentityStore>>;

/// Create a new empty shared store.
#[must_use]
#[allow(dead_code)]
pub fn new_shared_store() -> SharedZerodentityStore {
    Arc::new(Mutex::new(ZerodentityStore::new()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use exo_core::types::{Did, Hash256, Signature};

    use super::*;
    use crate::zerodentity::types::{
        ClaimStatus, ClaimType, IdentityClaim, PolarAxes, ZerodentityScore,
    };

    fn did(s: &str) -> Did {
        Did::new(s).unwrap()
    }

    fn h() -> Hash256 {
        Hash256::digest(b"t")
    }

    fn score_for(subject_did: Did, composite: u32) -> ZerodentityScore {
        ZerodentityScore {
            subject_did,
            axes: PolarAxes {
                communication: composite,
                credential_depth: composite,
                device_trust: composite,
                behavioral_signature: composite,
                network_reputation: composite,
                temporal_stability: composite,
                cryptographic_strength: composite,
                constitutional_standing: composite,
            },
            composite,
            computed_ms: 1_000_000,
            dag_state_hash: h(),
            claim_count: 0,
            symmetry: 10_000,
        }
    }

    fn claim(d: &Did, ct: ClaimType) -> IdentityClaim {
        IdentityClaim {
            claim_hash: h(),
            subject_did: d.clone(),
            claim_type: ct,
            status: ClaimStatus::Verified,
            created_ms: 1000,
            verified_ms: Some(2000),
            expires_ms: None,
            signature: Signature::Empty,
            dag_node_hash: h(),
        }
    }

    #[test]
    fn empty_store_returns_none() {
        let store = ZerodentityStore::new();
        assert!(store.get_score(&did("did:exo:a")).is_none());
        assert_eq!(store.get_claims(&did("did:exo:a")).unwrap(), vec![]);
        assert_eq!(store.sample_scored_dids(5), vec![]);
    }

    #[test]
    fn put_and_get_score() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:alice");
        store.put_score(score_for(d.clone(), 5000));
        assert_eq!(store.get_score(&d).unwrap().composite, 5000);
    }

    #[test]
    fn previous_score_after_update() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:bob");
        store.put_score(score_for(d.clone(), 4000));
        store.put_score(score_for(d.clone(), 6000));
        assert_eq!(store.get_score(&d).unwrap().composite, 6000);
        assert_eq!(store.get_previous_score(&d).unwrap().composite, 4000);
    }

    #[test]
    fn score_history_returns_all_snapshots() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:carol");
        store.put_score(score_for(d.clone(), 1000));
        store.put_score(score_for(d.clone(), 2000));
        store.put_score(score_for(d.clone(), 3000));
        let h = store.get_score_history(&d, None, None).unwrap();
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn sample_scored_dids_returns_sorted() {
        let mut store = ZerodentityStore::new();
        store.put_score(score_for(did("did:exo:c"), 1000));
        store.put_score(score_for(did("did:exo:a"), 2000));
        store.put_score(score_for(did("did:exo:b"), 3000));
        let sampled = store.sample_scored_dids(10);
        assert_eq!(sampled.len(), 3);
        assert_eq!(sampled[0].as_str(), "did:exo:a");
    }

    #[test]
    fn otp_lockout_detection() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:dave");
        let now_ms: u64 = 86_400_000;
        let day_ago = now_ms - 86_400_000;
        store.record_otp_lockout(&d, now_ms - 3_600_000);
        assert!(store.has_otp_lockout_since(&d, day_ago));
        assert!(!store.has_otp_lockout_since(&d, now_ms + 1));
    }

    #[test]
    fn put_claim_and_retrieve() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:eve");
        store.put_claim(claim(&d, ClaimType::Email));
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.claim_type, ClaimType::Email);
    }

    #[test]
    fn insert_claim_and_retrieve() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:frank");
        let c = claim(&d, ClaimType::Phone);
        store.insert_claim("test-claim-001", &c).unwrap();
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "test-claim-001");
    }

    #[test]
    fn open_returns_empty_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ZerodentityStore::open(tmp.path()).unwrap();
        assert_eq!(store.scored_did_count(), 0);
    }

    // ---- APE-72 tests ----

    #[test]
    fn run_migrations_is_idempotent() {
        let store = ZerodentityStore::new();
        store.run_migrations().unwrap();
        store.run_migrations().unwrap();
    }

    #[test]
    fn save_claim_stores_claim_and_dag_node() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:grace");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("apg-001", &c).unwrap();

        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "apg-001");

        assert_eq!(store.dag_nodes().len(), 1);
        assert_eq!(store.dag_nodes()[0].payload_hash, c.claim_hash);
        assert_eq!(store.dag_nodes()[0].creator_did, d);
    }

    #[test]
    fn save_verified_claim_emits_trust_receipt() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:heidi");
        let c = claim(&d, ClaimType::Phone); // claim() sets status=Verified
        store.save_claim("apg-002", &c).unwrap();

        assert_eq!(store.trust_receipts().len(), 1);
        let r = &store.trust_receipts()[0];
        assert_eq!(r.actor_did, d);
        assert_eq!(r.action_hash, c.claim_hash);
        assert_eq!(r.action_type, "zerodentity.claim_verified");
    }

    #[test]
    fn save_pending_claim_no_trust_receipt() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:ivan");
        let mut c = claim(&d, ClaimType::GovernmentId);
        c.status = ClaimStatus::Pending;
        store.save_claim("apg-003", &c).unwrap();

        assert_eq!(store.dag_nodes().len(), 1);
        assert_eq!(store.trust_receipts().len(), 0);
    }

    #[test]
    fn save_and_get_otp() {
        use crate::zerodentity::types::{OtpChannel, OtpState};
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:judy");
        let challenge = super::OtpChallenge {
            challenge_id: "ch-001".to_string(),
            subject_did: d,
            channel: OtpChannel::Email,
            hmac_secret: [0u8; 32],
            dispatched_ms: 1_000_000,
            ttl_ms: 600_000,
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.save_otp(&challenge).unwrap();
        let fetched = store.get_otp("ch-001").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().challenge_id, "ch-001");
    }

    #[test]
    fn save_score_and_retrieve() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:karen");
        store.save_score(score_for(d.clone(), 7500));
        assert_eq!(store.get_score(&d).unwrap().composite, 7500);
    }

    // ---- Erasure tests (§11.4) ----

    #[test]
    fn erase_did_revokes_claims_and_zeroes_scores() {
        use crate::zerodentity::types::IdentitySession;

        let mut store = ZerodentityStore::new();
        let d = did("did:exo:eraseme");

        // Set up: claim, score, session
        store.put_claim(claim(&d, ClaimType::Email));
        store.put_claim(claim(&d, ClaimType::Phone));
        store.put_score(score_for(d.clone(), 7000));
        store
            .insert_session(&IdentitySession {
                session_token: "tok-erase".into(),
                subject_did: d.clone(),
                public_key: vec![],
                created_ms: 0,
                last_active_ms: 0,
                revoked: false,
            })
            .unwrap();

        // Erase
        let revoked = store.erase_did(&d).unwrap();
        assert_eq!(revoked, 2);

        // Score gone
        assert!(store.get_score(&d).is_none());
        assert!(store.get_previous_score(&d).is_none());
        assert!(store.get_score_history(&d, None, None).unwrap().is_empty());

        // Claims still exist but all Revoked
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 2);
        for (_, c) in &claims {
            assert_eq!(c.status, ClaimStatus::Revoked);
        }

        // Session revoked
        assert!(store.get_session("tok-erase").unwrap().is_none());

        // Erasure receipt emitted
        let receipts: Vec<_> = store
            .trust_receipts()
            .iter()
            .filter(|r| r.action_type == "zerodentity.identity_erased")
            .collect();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn erase_did_removes_fingerprints_and_behavioral() {
        use std::collections::BTreeMap;

        use crate::zerodentity::types::{
            BehavioralSample, BehavioralSignalType, DeviceFingerprint,
        };

        let mut store = ZerodentityStore::new();
        let d = did("did:exo:fptest");

        store.put_fingerprint(
            &d,
            DeviceFingerprint {
                composite_hash: h(),
                signal_hashes: BTreeMap::new(),
                captured_ms: 1000,
                consistency_score_bp: Some(9500),
            },
        );
        store.put_behavioral(
            &d,
            BehavioralSample {
                sample_hash: h(),
                signal_type: BehavioralSignalType::KeystrokeDynamics,
                captured_ms: 1000,
                baseline_similarity_bp: Some(8000),
            },
        );

        assert!(!store.get_fingerprints(&d).unwrap().is_empty());
        assert!(!store.get_behavioral_samples(&d).unwrap().is_empty());

        store.erase_did(&d).unwrap();

        assert!(store.get_fingerprints(&d).unwrap().is_empty());
        assert!(store.get_behavioral_samples(&d).unwrap().is_empty());
    }

    #[test]
    fn erase_did_tombstones_dag_nodes() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:dagtest");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("dag-001", &c).unwrap();

        assert_ne!(store.dag_nodes()[0].payload_hash, Hash256::ZERO);
        store.erase_did(&d).unwrap();
        assert_eq!(store.dag_nodes()[0].payload_hash, Hash256::ZERO);
    }

    // ---- OTP cleanup tests ----

    #[test]
    fn cleanup_expired_otp_removes_pending() {
        use crate::zerodentity::types::{OtpChannel, OtpState};

        let mut store = ZerodentityStore::new();
        let d = did("did:exo:otptest");

        // Expired pending challenge
        let expired = OtpChallenge {
            challenge_id: "exp-001".into(),
            subject_did: d.clone(),
            channel: OtpChannel::Email,
            hmac_secret: [0u8; 32],
            dispatched_ms: 1_000_000,
            ttl_ms: 300_000, // 5 min
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.insert_otp_challenge(&expired).unwrap();

        // Non-expired pending challenge
        let fresh = OtpChallenge {
            challenge_id: "fresh-001".into(),
            subject_did: d.clone(),
            channel: OtpChannel::Sms,
            hmac_secret: [0u8; 32],
            dispatched_ms: 100_000_000, // far future
            ttl_ms: 300_000,
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.insert_otp_challenge(&fresh).unwrap();

        // Verified challenge (should not be removed even if "expired")
        let verified = OtpChallenge {
            challenge_id: "ver-001".into(),
            subject_did: d,
            channel: OtpChannel::Email,
            hmac_secret: [0u8; 32],
            dispatched_ms: 1_000_000,
            ttl_ms: 300_000,
            attempts: 1,
            max_attempts: 5,
            state: OtpState::Verified,
        };
        store.insert_otp_challenge(&verified).unwrap();

        let cleaned = store.cleanup_expired_otp(2_000_000);
        assert_eq!(cleaned, 1); // Only expired + pending

        assert!(store.get_otp_challenge("exp-001").unwrap().is_none());
        assert!(store.get_otp_challenge("fresh-001").unwrap().is_some());
        assert!(store.get_otp_challenge("ver-001").unwrap().is_some());
    }
}

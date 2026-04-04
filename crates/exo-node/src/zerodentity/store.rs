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

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use exo_core::types::Did;

use super::types::{
    BehavioralSample, DeviceFingerprint, IdentityClaim, IdentitySession, OtpChallenge,
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
    pub fn put_claim(&mut self, claim: IdentityClaim) {
        let key = claim.subject_did.as_str().to_owned();
        let claim_id = hex::encode(claim.claim_hash.as_bytes());
        self.claims
            .entry(key)
            .or_default()
            .push((claim_id, claim));
    }

    // -----------------------------------------------------------------------
    // Write — fingerprints / behavioral
    // -----------------------------------------------------------------------

    /// Append a device fingerprint for a DID.
    pub fn put_fingerprint(&mut self, did: &Did, fp: DeviceFingerprint) {
        self.fingerprints
            .entry(did.as_str().to_owned())
            .or_default()
            .push(fp);
    }

    /// Append a behavioral sample for a DID.
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
        Ok(self
            .claims
            .get(did.as_str())
            .cloned()
            .unwrap_or_default())
    }

    /// Return all claims for a DID as a plain slice (no claim IDs).
    ///
    /// Convenience method for callers that only need the claims themselves
    /// (e.g., sentinels and scoring).
    #[must_use]
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
                let after = from_ms.map_or(true, |f| s.computed_ms >= f);
                let before = to_ms.map_or(true, |t| s.computed_ms <= t);
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
            .map_or(false, |events| events.iter().any(|&t| t >= since_ms))
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
        let key = (
            attester.as_str().to_owned(),
            target.as_str().to_owned(),
        );
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
}

/// Thread-safe shared handle to the 0dentity store.
pub type SharedZerodentityStore = Arc<Mutex<ZerodentityStore>>;

/// Create a new empty shared store.
#[must_use]
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
}

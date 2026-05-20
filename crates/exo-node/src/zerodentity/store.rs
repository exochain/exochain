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

//! 0dentity score and claim store.
//!
//! This module provides the shared state accessor for 0dentity scoring data.
//! It integrates with `exo_identity` to provide cryptographic standing via `LocalDidRegistry`
//! and handles the `VerificationCeremony` state for identity onboarding.
//!
//! While currently a robust in-memory implementation for rapid consensus and state management,
//! the integration path for SQLite persistence remains available.
//!
//! All inner maps use `BTreeMap` (never `HashMap`) for deterministic iteration.
//! Evidence vectors are canonicalized on read before callers perform scoring.
//!
//! Spec reference: §9, §12.1.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};

use exo_core::types::{Did, Hash256, ReceiptOutcome, Signature, Timestamp, TrustReceipt};
use exo_dag::dag::{DagNode, compute_node_hash};
use serde::Serialize;

use super::types::{
    BehavioralSample, ClaimStatus, DeviceFingerprint, IdentityClaim, IdentitySession, OtpChallenge,
    PeerAttestation, ZerodentityScore,
};

pub type ReceiptSigner = Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>;

/// The current 0dentity store is intentionally volatile process memory.
pub const ZERODENTITY_STORE_PERSISTENCE_READY: bool = false;
/// Maximum future skew allowed between a caller-signed erasure timestamp and
/// the trusted validation timestamp supplied by the runtime.
pub const ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS: u64 = 500;

/// Startup warning emitted while 0dentity data is not durable.
pub const ZERODENTITY_STORE_PERSISTENCE_WARNING: &str = "0dentity store is memory only; claims, sessions, OTPs, scores, and receipts are not durable across process restarts";

#[derive(Clone)]
pub struct ReceiptSigningContext {
    actor_did: Did,
    signer: ReceiptSigner,
}

impl ReceiptSigningContext {
    #[must_use]
    pub fn new(actor_did: Did, signer: ReceiptSigner) -> Self {
        Self { actor_did, signer }
    }
}

impl fmt::Debug for ReceiptSigningContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptSigningContext")
            .field("actor_did", &self.actor_did)
            .field("signer", &"<receipt signer>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSaveEvidence {
    pub dag_node_hash: Hash256,
    pub receipt_hash: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureEvidence {
    pub claims_revoked: u32,
    pub dag_node_hash: Hash256,
    pub action_hash: Hash256,
    pub receipt_hash: Hash256,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZerodentityReadFailure {
    Claims,
    Fingerprints,
    Behavioral,
}

fn canonicalize_claim_entries(claims: &mut [(String, IdentityClaim)]) {
    claims.sort_by(|(left_id, left), (right_id, right)| {
        left.created_ms
            .cmp(&right.created_ms)
            .then(left.verified_ms.cmp(&right.verified_ms))
            .then(left.claim_hash.as_bytes().cmp(right.claim_hash.as_bytes()))
            .then(left_id.cmp(right_id))
    });
}

fn canonicalize_fingerprints(fingerprints: &mut [DeviceFingerprint]) {
    fingerprints.sort_by(|left, right| {
        left.captured_ms
            .cmp(&right.captured_ms)
            .then(
                left.composite_hash
                    .as_bytes()
                    .cmp(right.composite_hash.as_bytes()),
            )
            .then(left.consistency_score_bp.cmp(&right.consistency_score_bp))
    });
}

fn canonicalize_behavioral_samples(samples: &mut [BehavioralSample]) {
    samples.sort_by(|left, right| {
        left.captured_ms
            .cmp(&right.captured_ms)
            .then(
                left.sample_hash
                    .as_bytes()
                    .cmp(right.sample_hash.as_bytes()),
            )
            .then(
                left.baseline_similarity_bp
                    .cmp(&right.baseline_similarity_bp),
            )
    });
}

pub(crate) fn otp_challenge_expired(challenge: &OtpChallenge, now_ms: u64) -> bool {
    challenge
        .dispatched_ms
        .checked_add(challenge.ttl_ms)
        .is_none_or(|expires_at| now_ms >= expires_at)
}

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
    /// In-memory DID registry for cryptographic standing.
    #[allow(dead_code)] // Used via trait methods in verification ceremony.
    pub did_registry: exo_identity::registry::LocalDidRegistry,
    /// Active verification ceremonies by session token.
    #[allow(dead_code)] // Used via trait methods in verification ceremony.
    pub ceremonies: BTreeMap<String, exo_identity::verification::VerificationCeremony>,
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
    /// Consumed request nonces keyed by `(session_token, nonce)`.
    session_request_nonces: BTreeSet<(String, String)>,
    /// DAG nodes recorded for claim operations (APE-72).
    dag_nodes: Vec<DagNode>,
    /// Trust receipts emitted for claim verification events (APE-72).
    trust_receipts: Vec<TrustReceipt>,
    /// Node identity signer used to emit verifiable trust receipts.
    receipt_signing: Option<ReceiptSigningContext>,
    #[cfg(test)]
    fail_claim_reads: bool,
    #[cfg(test)]
    fail_fingerprint_reads: bool,
    #[cfg(test)]
    fail_behavioral_reads: bool,
}

impl ZerodentityStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the current store implementation is durable across restarts.
    #[must_use]
    pub const fn persistence_ready() -> bool {
        ZERODENTITY_STORE_PERSISTENCE_READY
    }

    /// Operator-facing warning for the current persistence posture.
    #[must_use]
    pub const fn persistence_warning() -> &'static str {
        ZERODENTITY_STORE_PERSISTENCE_WARNING
    }

    /// Configure the node identity used to sign store-emitted trust receipts.
    pub fn set_receipt_signer(&mut self, actor_did: Did, signer: ReceiptSigner) {
        self.receipt_signing = Some(ReceiptSigningContext::new(actor_did, signer));
    }

    #[cfg(test)]
    pub(crate) fn inject_read_failure(&mut self, failure: ZerodentityReadFailure) {
        match failure {
            ZerodentityReadFailure::Claims => {
                self.fail_claim_reads = true;
            }
            ZerodentityReadFailure::Fingerprints => {
                self.fail_fingerprint_reads = true;
            }
            ZerodentityReadFailure::Behavioral => {
                self.fail_behavioral_reads = true;
            }
        }
    }

    /// Open the 0dentity store.
    ///
    /// In this in-memory implementation the `data_dir` argument is accepted but
    /// ignored — all data lives in process memory only. The integration path
    /// allows for future persistence scaling.
    pub fn open(_data_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self::new())
    }

    fn trust_receipt(
        &self,
        action_type: &str,
        action_hash: Hash256,
        outcome: ReceiptOutcome,
        timestamp: Timestamp,
    ) -> anyhow::Result<TrustReceipt> {
        let Some(context) = &self.receipt_signing else {
            anyhow::bail!("0dentity trust receipt signer is not configured");
        };
        Ok(TrustReceipt::new(
            context.actor_did.clone(),
            Hash256::ZERO,
            None,
            action_type.to_owned(),
            action_hash,
            outcome,
            timestamp,
            &*context.signer,
        )?)
    }

    fn next_dag_parents(&self) -> Vec<Hash256> {
        self.dag_nodes
            .last()
            .map_or_else(Vec::new, |parent| vec![parent.hash])
    }

    fn validate_next_dag_timestamp(
        &self,
        timestamp: Timestamp,
        label: &'static str,
    ) -> anyhow::Result<()> {
        if timestamp.physical_ms == 0 {
            anyhow::bail!("{label} timestamp must be greater than 0");
        }
        if let Some(parent) = self.dag_nodes.last() {
            if timestamp <= parent.timestamp {
                anyhow::bail!("{label} timestamp must strictly exceed latest DAG parent timestamp");
            }
        }
        Ok(())
    }

    /// Compute the next claim DAG node hash without mutating the store.
    pub fn next_claim_dag_node_hash(
        &self,
        payload_hash: Hash256,
        timestamp: Timestamp,
    ) -> anyhow::Result<Hash256> {
        let Some(context) = &self.receipt_signing else {
            anyhow::bail!("0dentity DAG node signer is not configured");
        };
        self.validate_next_dag_timestamp(timestamp, "0dentity claim DAG")?;
        Ok(compute_node_hash(
            &self.next_dag_parents(),
            &payload_hash,
            &context.actor_did,
            &timestamp,
        )?)
    }

    fn signed_dag_node(
        &self,
        payload_hash: Hash256,
        timestamp: Timestamp,
    ) -> anyhow::Result<DagNode> {
        let Some(context) = &self.receipt_signing else {
            anyhow::bail!("0dentity DAG node signer is not configured");
        };
        self.validate_next_dag_timestamp(timestamp, "0dentity DAG node")?;
        let parents = self.next_dag_parents();
        let hash = compute_node_hash(&parents, &payload_hash, &context.actor_did, &timestamp)?;
        let signature = (context.signer)(hash.as_bytes());
        if signature.is_empty() {
            anyhow::bail!("0dentity DAG node signer produced an empty signature");
        }
        Ok(DagNode {
            hash,
            parents,
            payload_hash,
            creator_did: context.actor_did.clone(),
            timestamp,
            signature,
        })
    }

    fn validate_erasure_timestamp(
        &self,
        timestamp: Timestamp,
        validation_time: Timestamp,
    ) -> anyhow::Result<()> {
        if timestamp.physical_ms == 0 {
            anyhow::bail!("0dentity erasure timestamp must be greater than 0");
        }
        if validation_time.physical_ms == 0 {
            anyhow::bail!("0dentity erasure validation timestamp must be greater than 0");
        }
        if timestamp.physical_ms
            > validation_time
                .physical_ms
                .saturating_add(ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS)
        {
            anyhow::bail!("0dentity erasure timestamp exceeds trusted erasure clock tolerance");
        }
        if let Some(parent) = self.dag_nodes.last() {
            if timestamp <= parent.timestamp {
                anyhow::bail!(
                    "0dentity erasure timestamp must strictly exceed latest DAG parent timestamp"
                );
            }
        }
        Ok(())
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

    /// Return a stored peer attestation by attester and target.
    pub fn get_attestation(
        &self,
        attester: &Did,
        target: &Did,
    ) -> anyhow::Result<Option<PeerAttestation>> {
        let key = (attester.as_str().to_owned(), target.as_str().to_owned());
        Ok(self.attestations.get(&key).cloned())
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

    /// Consume a session request nonce.
    ///
    /// Returns `true` when the nonce was new and is now consumed. Returns
    /// `false` when the same session already used the nonce.
    pub fn consume_session_nonce(
        &mut self,
        session_token: &str,
        nonce: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .session_request_nonces
            .insert((session_token.to_owned(), nonce.to_owned())))
    }

    // -----------------------------------------------------------------------
    // Read — claims
    // -----------------------------------------------------------------------

    /// Return all claims for a DID with their claim IDs.
    ///
    /// Returns an empty `Vec` (not an error) when the DID has no claims.
    pub fn get_claims(&self, did: &Did) -> anyhow::Result<Vec<(String, IdentityClaim)>> {
        #[cfg(test)]
        if self.fail_claim_reads {
            anyhow::bail!("injected 0dentity claims read failure");
        }
        let mut claims = self.claims.get(did.as_str()).cloned().unwrap_or_default();
        canonicalize_claim_entries(&mut claims);
        Ok(claims)
    }

    /// Return all claims for a DID as a plain slice (no claim IDs).
    ///
    /// Convenience method for callers that only need the claims themselves
    /// (e.g., sentinels and scoring).
    #[allow(dead_code)]
    pub fn get_claims_slice(&self, did: &Did) -> anyhow::Result<Vec<IdentityClaim>> {
        self.get_claims(did)
            .map(|entries| entries.into_iter().map(|(_, c)| c).collect())
    }

    // -----------------------------------------------------------------------
    // Read — fingerprints / behavioral
    // -----------------------------------------------------------------------

    /// Return all device fingerprints for a DID.
    pub fn get_fingerprints(&self, did: &Did) -> anyhow::Result<Vec<DeviceFingerprint>> {
        #[cfg(test)]
        if self.fail_fingerprint_reads {
            anyhow::bail!("injected 0dentity fingerprint read failure");
        }
        let mut fingerprints = self
            .fingerprints
            .get(did.as_str())
            .cloned()
            .unwrap_or_default();
        canonicalize_fingerprints(&mut fingerprints);
        Ok(fingerprints)
    }

    /// Return all behavioral samples for a DID.
    pub fn get_behavioral_samples(&self, did: &Did) -> anyhow::Result<Vec<BehavioralSample>> {
        #[cfg(test)]
        if self.fail_behavioral_reads {
            anyhow::bail!("injected 0dentity behavioral read failure");
        }
        let mut samples = self
            .behavioral
            .get(did.as_str())
            .cloned()
            .unwrap_or_default();
        canonicalize_behavioral_samples(&mut samples);
        Ok(samples)
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
        Ok(self.get_attestation(attester, target)?.is_some())
    }

    // -----------------------------------------------------------------------
    // Read — sessions
    // -----------------------------------------------------------------------

    /// Retrieve an identity session by token at a trusted timestamp.
    ///
    /// Returns `None` if no matching session exists or if the session has been
    /// revoked or expired.
    pub fn get_session(&self, token: &str, now_ms: u64) -> anyhow::Result<Option<IdentitySession>> {
        Ok(self
            .sessions
            .get(token)
            .filter(|s| !s.revoked && now_ms >= s.created_ms && !s.is_expired_at(now_ms))
            .cloned())
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

    /// Return a bounded page of scored DIDs after the optional cursor.
    ///
    /// Pages are sorted by DID and strictly greater than `after` when a cursor
    /// is provided, so callers can scan the full deterministic keyspace without
    /// holding the store lock for the entire scan.
    #[must_use]
    pub fn scored_dids_page_after(&self, after: Option<&Did>, n: usize) -> Vec<Did> {
        if n == 0 {
            return Vec::new();
        }

        let bounds = match after {
            Some(did) => (
                std::ops::Bound::Excluded(did.as_str().to_owned()),
                std::ops::Bound::Unbounded,
            ),
            None => (std::ops::Bound::Unbounded, std::ops::Bound::Unbounded),
        };

        self.scores
            .range(bounds)
            .take(n)
            .filter_map(|(k, _)| Did::new(k).ok())
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
        self.save_claim_with_evidence(claim_id, claim).map(|_| ())
    }

    /// Persist a claim and return the signed DAG / receipt evidence produced.
    pub fn save_claim_with_evidence(
        &mut self,
        claim_id: &str,
        claim: &IdentityClaim,
    ) -> anyhow::Result<ClaimSaveEvidence> {
        let node = self.signed_dag_node(claim.claim_hash, Timestamp::new(claim.created_ms, 0))?;
        let receipt = if claim.status == ClaimStatus::Verified {
            let verified_ms = claim.verified_ms.unwrap_or(claim.created_ms);
            Some(self.trust_receipt(
                "zerodentity.claim_verified",
                claim.claim_hash,
                ReceiptOutcome::Executed,
                Timestamp::new(verified_ms, 0),
            )?)
        } else {
            None
        };

        let dag_node_hash = node.hash;
        let mut stored_claim = claim.clone();
        stored_claim.dag_node_hash = dag_node_hash;
        self.insert_claim(claim_id, &stored_claim)?;
        self.dag_nodes.push(node);

        // Emit TrustReceipt for verified claims.
        let receipt_hash = receipt.as_ref().map(|receipt| receipt.receipt_hash);
        if let Some(receipt) = receipt {
            self.trust_receipts.push(receipt);
        }

        Ok(ClaimSaveEvidence {
            dag_node_hash,
            receipt_hash,
        })
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

    /// Erase all stored 0dentity data for `did` and return the signed evidence
    /// emitted for the erasure.
    ///
    /// Implements §11.4 — right to erasure:
    /// 1. Revoke all sessions for this DID.
    /// 2. Mark all claims as `Revoked`.
    /// 3. Remove score snapshots (current, previous, history).
    /// 4. Remove fingerprints and behavioral samples.
    /// 5. Remove OTP challenges belonging to this DID.
    /// 6. Tombstone DAG nodes — zero payload hash, keep structural links.
    /// 7. Emit an erasure receipt.
    pub fn erase_did_with_evidence(
        &mut self,
        did: &Did,
        timestamp: Timestamp,
        validation_time: Timestamp,
    ) -> anyhow::Result<ErasureEvidence> {
        if self.receipt_signing.is_none() {
            anyhow::bail!("0dentity trust receipt signer is not configured");
        }
        self.validate_erasure_timestamp(timestamp, validation_time)?;

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

        // 6. Emit erasure receipt and append a signed erasure DAG node. The
        // existing claim nodes remain append-only; erasure is represented as a
        // new tombstone event.
        let erasure_hash = erasure_action_hash(did)?;
        let receipt = self.trust_receipt(
            "zerodentity.identity_erased",
            erasure_hash,
            ReceiptOutcome::Executed,
            timestamp,
        )?;
        let erasure_node = self.signed_dag_node(erasure_hash, timestamp)?;
        let dag_node_hash = erasure_node.hash;
        let receipt_hash = receipt.receipt_hash;
        self.dag_nodes.push(erasure_node);
        self.trust_receipts.push(receipt);

        Ok(ErasureEvidence {
            claims_revoked: revoked_count,
            dag_node_hash,
            action_hash: erasure_hash,
            receipt_hash,
        })
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
    pub fn cleanup_expired_otp(&mut self, now_ms: u64) -> usize {
        let before = self.otp_challenges.len();
        self.otp_challenges.retain(|_, ch| {
            let expired = otp_challenge_expired(ch, now_ms);
            let pending = ch.state == super::types::OtpState::Pending;
            // Remove if both expired and still pending
            !(expired && pending)
        });
        before - self.otp_challenges.len()
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

fn canonical_cbor<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// Domain-separated canonical action hash for a 0dentity erasure event.
pub fn erasure_action_hash(did: &Did) -> anyhow::Result<Hash256> {
    let payload = ("exo.zerodentity.identity_erased.v1", did.as_str());
    Ok(Hash256::digest(&canonical_cbor(&payload)?))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use exo_core::{
        crypto::{KeyPair, verify},
        types::{Did, Hash256, PublicKey, Signature, Timestamp},
    };

    use super::*;
    use crate::zerodentity::types::{
        ClaimStatus, ClaimType, IdentityClaim, OtpHmacSecret, PolarAxes, ZerodentityScore,
    };

    fn did(s: &str) -> Did {
        Did::new(s).unwrap()
    }

    fn h() -> Hash256 {
        Hash256::digest(b"t")
    }

    fn otp_secret(seed: u8) -> OtpHmacSecret {
        OtpHmacSecret::new([seed; 32]).unwrap()
    }

    fn signed_store(seed: u8) -> (ZerodentityStore, Did, PublicKey) {
        let keypair = KeyPair::from_secret_bytes([seed; 32]).unwrap();
        let public_key = *keypair.public_key();
        let actor_did = did(&format!("did:exo:receipt-node-{seed}"));
        let signer = Arc::new(move |payload: &[u8]| keypair.sign(payload));
        let mut store = ZerodentityStore::new();
        store.set_receipt_signer(actor_did.clone(), signer);
        (store, actor_did, public_key)
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
    fn erasure_action_hash_is_deterministic_and_did_bound() {
        let did_a = did("did:exo:erase-a");
        let did_b = did("did:exo:erase-b");

        let first = erasure_action_hash(&did_a).expect("erasure hash");

        assert_eq!(erasure_action_hash(&did_a).expect("erasure hash"), first);
        assert_ne!(erasure_action_hash(&did_b).expect("erasure hash"), first);
    }

    #[test]
    fn erasure_path_does_not_use_ad_hoc_format_hashes() {
        let source = include_str!("store.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let ad_hoc_erasure_hash = format!("{}{}", "format!(\"erase", ":");

        assert!(!production.contains(&ad_hoc_erasure_hash));
    }

    #[test]
    fn empty_store_returns_none() {
        let store = ZerodentityStore::new();
        assert!(store.get_score(&did("did:exo:a")).is_none());
        assert_eq!(store.get_claims(&did("did:exo:a")).unwrap(), vec![]);
        assert_eq!(store.sample_scored_dids(5), vec![]);
    }

    #[test]
    fn production_claim_slice_reads_do_not_squash_store_errors() {
        let source = include_str!("store.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let claim_slice = production
            .split("pub fn get_claims_slice")
            .nth(1)
            .expect("get_claims_slice definition")
            .split("pub fn get_fingerprints")
            .next()
            .expect("get_claims_slice body");

        assert!(
            claim_slice.contains("anyhow::Result<Vec<IdentityClaim>>"),
            "claim slice reads must expose the underlying store read error"
        );
        assert!(
            !claim_slice.contains(".unwrap_or_default()"),
            "claim slice reads must not convert store read failures into empty claim sets"
        );
    }

    #[test]
    fn get_claims_slice_propagates_claim_read_failures() {
        let mut store = ZerodentityStore::new();
        store.inject_read_failure(ZerodentityReadFailure::Claims);

        let err = store
            .get_claims_slice(&did("did:exo:claims-slice-failure"))
            .expect_err("claim slice reads must fail closed on store read errors");

        assert!(err.to_string().contains("claims read failure"));
    }

    #[test]
    fn in_memory_store_declares_persistence_not_ready() {
        assert!(!ZerodentityStore::persistence_ready());
        assert!(
            ZerodentityStore::persistence_warning().contains("memory only"),
            "startup warning must plainly identify the volatile store"
        );
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
    fn scored_dids_page_after_returns_successive_bounded_pages() {
        let mut store = ZerodentityStore::new();
        for did_str in ["did:exo:a", "did:exo:b", "did:exo:c"] {
            store.put_score(score_for(did(did_str), 1000));
        }

        let first_page = store.scored_dids_page_after(None, 2);
        assert_eq!(
            first_page
                .iter()
                .map(|did| did.as_str())
                .collect::<Vec<_>>(),
            vec!["did:exo:a", "did:exo:b"]
        );

        let second_page = store.scored_dids_page_after(first_page.last(), 2);
        assert_eq!(
            second_page
                .iter()
                .map(|did| did.as_str())
                .collect::<Vec<_>>(),
            vec!["did:exo:c"]
        );
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
        let (mut store, node_did, _) = signed_store(3);
        let d = did("did:exo:grace");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("apg-001", &c).unwrap();

        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "apg-001");

        assert_eq!(store.dag_nodes().len(), 1);
        assert_eq!(store.dag_nodes()[0].payload_hash, c.claim_hash);
        assert_eq!(store.dag_nodes()[0].creator_did, node_did);
    }

    #[test]
    fn save_claim_binds_stored_claim_to_signed_dag_node_hash() {
        let (mut store, _, _) = signed_store(34);
        let d = did("did:exo:dag-bound-claim");
        let mut c = claim(&d, ClaimType::Email);
        c.dag_node_hash = Hash256::digest(b"caller-controlled-dag-pointer");

        let evidence = store
            .save_claim_with_evidence("apg-dag-bound-001", &c)
            .unwrap();

        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.dag_node_hash, evidence.dag_node_hash);
        assert_eq!(claims[0].1.dag_node_hash, store.dag_nodes()[0].hash);
        assert_ne!(claims[0].1.dag_node_hash, c.dag_node_hash);
    }

    #[test]
    fn save_claim_dag_node_is_signed_by_node_identity() {
        let (mut store, node_did, node_public_key) = signed_store(31);
        let d = did("did:exo:dag-signed-claim");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("apg-dag-signed-001", &c).unwrap();

        let node = &store.dag_nodes()[0];
        assert_eq!(node.creator_did, node_did);
        assert!(!node.signature.is_empty());
        assert!(verify(
            node.hash.as_bytes(),
            &node.signature,
            &node_public_key
        ));
    }

    #[test]
    fn save_claim_without_node_signer_is_refused() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:dag-unsigned-refusal");
        let c = claim(&d, ClaimType::Email);

        let err = store.save_claim("apg-dag-unsigned-001", &c).unwrap_err();

        assert!(
            err.to_string().contains("DAG node signer"),
            "expected DAG signer refusal, got {err}"
        );
        assert!(store.dag_nodes().is_empty());
        assert!(store.get_claims(&d).unwrap().is_empty());
    }

    #[test]
    fn save_claim_chains_dag_nodes_to_previous_node() {
        let (mut store, _, node_public_key) = signed_store(32);
        let d = did("did:exo:dag-chain");
        let first = claim(&d, ClaimType::Email);
        let mut second = claim(&d, ClaimType::Phone);
        second.created_ms = first.created_ms + 1;
        second.verified_ms = Some(first.created_ms + 2);

        store.save_claim("apg-dag-chain-001", &first).unwrap();
        store.save_claim("apg-dag-chain-002", &second).unwrap();

        let nodes = store.dag_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes[0].parents.is_empty());
        assert_eq!(nodes[1].parents, vec![nodes[0].hash]);
        assert!(verify(
            nodes[0].hash.as_bytes(),
            &nodes[0].signature,
            &node_public_key
        ));
        assert!(verify(
            nodes[1].hash.as_bytes(),
            &nodes[1].signature,
            &node_public_key
        ));
    }

    #[test]
    fn save_claim_rejects_timestamp_not_after_latest_dag_node() {
        let (mut store, _, _) = signed_store(35);
        let d = did("did:exo:dag-causality-claim");
        let first = claim(&d, ClaimType::Email);
        let mut second = claim(&d, ClaimType::Phone);
        second.claim_hash = Hash256::digest(b"same-time-second-claim");
        second.created_ms = first.created_ms;

        store.save_claim("apg-dag-causal-001", &first).unwrap();
        let err = store.save_claim("apg-dag-causal-002", &second).unwrap_err();

        assert!(
            err.to_string()
                .contains("strictly exceed latest DAG parent"),
            "expected claim DAG causality refusal, got {err}"
        );
        assert_eq!(store.dag_nodes().len(), 1);
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "apg-dag-causal-001");
    }

    #[test]
    fn erase_did_appends_signed_erasure_node_without_mutating_claim_node() {
        let (mut store, node_did, node_public_key) = signed_store(33);
        let d = did("did:exo:dag-erasure");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("apg-dag-erasure-001", &c).unwrap();
        let claim_node = store.dag_nodes()[0].clone();

        store
            .erase_did_with_evidence(&d, Timestamp::new(6_000, 0), Timestamp::new(6_000, 0))
            .unwrap();

        let nodes = store.dag_nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0], claim_node);
        assert_eq!(nodes[1].creator_did, node_did);
        assert_eq!(nodes[1].parents, vec![claim_node.hash]);
        assert_ne!(nodes[1].payload_hash, Hash256::ZERO);
        assert!(!nodes[1].signature.is_empty());
        assert!(verify(
            nodes[1].hash.as_bytes(),
            &nodes[1].signature,
            &node_public_key
        ));
    }

    #[test]
    fn save_verified_claim_emits_trust_receipt() {
        let (mut store, node_did, node_public_key) = signed_store(5);
        let d = did("did:exo:heidi");
        let c = claim(&d, ClaimType::Phone); // claim() sets status=Verified
        store.save_claim("apg-002", &c).unwrap();

        assert_eq!(store.trust_receipts().len(), 1);
        let r = &store.trust_receipts()[0];
        assert_eq!(r.actor_did, node_did);
        assert_eq!(r.action_hash, c.claim_hash);
        assert_eq!(r.action_type, "zerodentity.claim_verified");
        assert!(
            r.verify_signature(&node_public_key)
                .expect("verify trust receipt signature")
        );
    }

    #[test]
    fn save_verified_claim_emits_node_signed_trust_receipt() {
        let (mut store, node_did, node_public_key) = signed_store(11);
        let d = did("did:exo:signed-claim");
        let c = claim(&d, ClaimType::Phone);
        store.save_claim("apg-signed-001", &c).unwrap();

        let receipt = &store.trust_receipts()[0];
        assert_eq!(receipt.actor_did, node_did);
        assert_eq!(receipt.action_hash, c.claim_hash);
        assert_eq!(receipt.action_type, "zerodentity.claim_verified");
        assert!(!receipt.signature.is_empty());
        assert!(receipt.verify_hash().expect("verify trust receipt hash"));
        assert!(
            receipt
                .verify_signature(&node_public_key)
                .expect("verify trust receipt signature")
        );
    }

    #[test]
    fn save_pending_claim_no_trust_receipt() {
        let (mut store, _, _) = signed_store(13);
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
            hmac_secret: otp_secret(1),
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

        let (mut store, _, _) = signed_store(7);
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
        let evidence = store
            .erase_did_with_evidence(&d, Timestamp::new(7_000, 0), Timestamp::new(7_000, 0))
            .unwrap();
        assert_eq!(evidence.claims_revoked, 2);

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
        assert!(store.get_session("tok-erase", 7_000).unwrap().is_none());

        // Erasure receipt emitted
        let receipts: Vec<_> = store
            .trust_receipts()
            .iter()
            .filter(|r| r.action_type == "zerodentity.identity_erased")
            .collect();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn erase_did_emits_node_signed_erasure_receipt() {
        let (mut store, node_did, node_public_key) = signed_store(17);
        let d = did("did:exo:signed-erase");
        store.put_claim(claim(&d, ClaimType::Email));

        let evidence = store
            .erase_did_with_evidence(&d, Timestamp::new(8_000, 0), Timestamp::new(8_000, 0))
            .unwrap();
        assert_eq!(evidence.claims_revoked, 1);

        let receipt = store
            .trust_receipts()
            .iter()
            .find(|r| r.action_type == "zerodentity.identity_erased")
            .unwrap();
        assert_eq!(receipt.actor_did, node_did);
        assert!(!receipt.signature.is_empty());
        assert!(receipt.verify_hash().expect("verify trust receipt hash"));
        assert!(
            receipt
                .verify_signature(&node_public_key)
                .expect("verify trust receipt signature")
        );
    }

    #[test]
    fn erase_did_rejects_zero_timestamp() {
        let (mut store, _, _) = signed_store(18);
        let d = did("did:exo:zero-erase");
        store.put_claim(claim(&d, ClaimType::Email));

        let err = store
            .erase_did_with_evidence(&d, Timestamp::new(0, 0), Timestamp::new(8_000, 0))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("erasure timestamp must be greater than 0")
        );
    }

    #[test]
    fn erase_did_rejects_timestamp_not_after_latest_dag_node() {
        let (mut store, _, _) = signed_store(34);
        let d = did("did:exo:old-erase");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("old-erase-claim", &c).unwrap();

        let err = store
            .erase_did_with_evidence(
                &d,
                Timestamp::new(c.created_ms, 0),
                Timestamp::new(c.created_ms, 0),
            )
            .unwrap_err();

        assert!(
            err.to_string().contains("strictly exceed"),
            "expected parent-causality rejection, got {err}"
        );
        assert_eq!(store.dag_nodes().len(), 1);
    }

    #[test]
    fn erase_did_rejects_timestamp_beyond_validation_clock_tolerance() {
        let (mut store, _, _) = signed_store(35);
        let d = did("did:exo:future-erase");
        store.put_claim(claim(&d, ClaimType::Email));

        let err = store
            .erase_did_with_evidence(
                &d,
                Timestamp::new(10_000, 0),
                Timestamp::new(10_000 - ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS - 1, 0),
            )
            .unwrap_err();

        assert!(
            err.to_string().contains("clock tolerance"),
            "expected future-skew rejection, got {err}"
        );
        assert!(store.dag_nodes().is_empty());
    }

    #[test]
    fn erase_did_write_path_does_not_fabricate_runtime_time() {
        let source = include_str!("store.rs");
        let erasure_section = source
            .split("// Write — erasure")
            .nth(1)
            .and_then(|section| section.split("// Read — OTP challenges").next())
            .unwrap();

        assert!(!erasure_section.contains("now_ms()"));
    }

    #[test]
    fn erase_did_removes_fingerprints_and_behavioral() {
        use std::collections::BTreeMap;

        use crate::zerodentity::types::{
            BehavioralSample, BehavioralSignalType, DeviceFingerprint,
        };

        let (mut store, _, _) = signed_store(19);
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

        store
            .erase_did_with_evidence(&d, Timestamp::new(9_000, 0), Timestamp::new(9_000, 0))
            .unwrap();

        assert!(store.get_fingerprints(&d).unwrap().is_empty());
        assert!(store.get_behavioral_samples(&d).unwrap().is_empty());
    }

    #[test]
    fn erase_did_appends_erasure_dag_node() {
        let (mut store, _, _) = signed_store(23);
        let d = did("did:exo:dagtest");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("dag-001", &c).unwrap();

        let claim_node = store.dag_nodes()[0].clone();
        store
            .erase_did_with_evidence(&d, Timestamp::new(10_000, 0), Timestamp::new(10_000, 0))
            .unwrap();
        assert_eq!(store.dag_nodes().len(), 2);
        assert_eq!(store.dag_nodes()[0], claim_node);
        assert_eq!(store.dag_nodes()[1].parents, vec![claim_node.hash]);
        assert_ne!(store.dag_nodes()[1].payload_hash, Hash256::ZERO);
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
            hmac_secret: otp_secret(2),
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
            hmac_secret: otp_secret(3),
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
            hmac_secret: otp_secret(4),
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

    #[test]
    fn cleanup_expired_otp_removes_pending_when_expiry_overflows() {
        use crate::zerodentity::types::{OtpChannel, OtpState};

        let mut store = ZerodentityStore::new();
        let challenge = OtpChallenge {
            challenge_id: "overflow-001".into(),
            subject_did: did("did:exo:otpoverflow"),
            channel: OtpChannel::Email,
            hmac_secret: otp_secret(5),
            dispatched_ms: u64::MAX,
            ttl_ms: 1,
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.insert_otp_challenge(&challenge).unwrap();

        let cleaned = store.cleanup_expired_otp(1_000);

        assert_eq!(cleaned, 1);
        assert!(store.get_otp_challenge("overflow-001").unwrap().is_none());
    }
}

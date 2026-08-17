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

//! In-process policy decision point. Never moves money.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use exo_authority::{DelegationGrant, DelegationRegistry, chain::AuthorityLink};
use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto::KeyPair};
use serde::{Deserialize, Serialize};

use crate::{
    error::{PdpError, Result},
    evidence::{Decision, EvidenceEntry, EvidenceLog},
    policy::{self, DecisionRequest, PolicyVerdict},
    reservation::ReservationBook,
    revocation::{RevocationSet, RevocationTarget},
};

const PDP_STATE_SPEC: &str = "exochain-pdp-state-v1";
const PDP_STATE_SIGNING_DOMAIN: &str = "exo.pdp.state.v1";
const PDP_STATE_SIGNING_SCHEMA_VERSION: u16 = 1;

/// Shared handle used by gateway and node routers.
#[derive(Clone)]
pub struct SharedPdp(Arc<Mutex<PolicyDecisionPoint>>);

/// Service-signed durable runtime authority state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdpSnapshot {
    spec: String,
    service_public_key_hex: String,
    keys: BTreeMap<Did, PublicKey>,
    delegations: DelegationRegistry,
    reservations: Vec<crate::reservation::Reservation>,
    revocations: Vec<crate::revocation::Revocation>,
    evidence_entries: Vec<EvidenceEntry>,
    signature: Signature,
}

impl PdpSnapshot {
    fn signing_payload(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            domain: &'static str,
            schema_version: u16,
            spec: &'a str,
            service_public_key_hex: &'a str,
            keys: &'a BTreeMap<Did, PublicKey>,
            delegations: &'a DelegationRegistry,
            reservations: &'a [crate::reservation::Reservation],
            revocations: &'a [crate::revocation::Revocation],
            evidence_entries: &'a [EvidenceEntry],
        }
        let payload = SigningPayload {
            domain: PDP_STATE_SIGNING_DOMAIN,
            schema_version: PDP_STATE_SIGNING_SCHEMA_VERSION,
            spec: &self.spec,
            service_public_key_hex: &self.service_public_key_hex,
            keys: &self.keys,
            delegations: &self.delegations,
            reservations: &self.reservations,
            revocations: &self.revocations,
            evidence_entries: &self.evidence_entries,
        };
        let mut data = Vec::new();
        ciborium::ser::into_writer(&payload, &mut data)
            .map_err(|e| PdpError::Serialization(e.to_string()))?;
        Ok(data)
    }

    /// Encode the signed snapshot as deterministic CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data)
            .map_err(|e| PdpError::Serialization(e.to_string()))?;
        Ok(data)
    }

    /// Decode a signed snapshot. The PDP verifies it before import.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(|e| PdpError::BadRequest(e.to_string()))
    }
}

impl SharedPdp {
    #[must_use]
    pub fn ephemeral() -> Self {
        Self(Arc::new(Mutex::new(PolicyDecisionPoint::ephemeral())))
    }

    #[must_use]
    pub fn from_pdp(pdp: PolicyDecisionPoint) -> Self {
        Self(Arc::new(Mutex::new(pdp)))
    }

    pub fn lock(&self) -> Result<std::sync::MutexGuard<'_, PolicyDecisionPoint>> {
        self.0.lock().map_err(|_| PdpError::LockPoisoned)
    }
}

/// Runtime authority + receipt service.
pub struct PolicyDecisionPoint {
    service_key: KeyPair,
    pub(crate) keys: BTreeMap<Did, PublicKey>,
    pub delegations: DelegationRegistry,
    reservations: ReservationBook,
    revocations: RevocationSet,
    evidence: EvidenceLog,
}

impl PolicyDecisionPoint {
    #[must_use]
    pub fn new(service_key: KeyPair) -> Self {
        Self {
            service_key,
            keys: BTreeMap::new(),
            delegations: DelegationRegistry::new(),
            reservations: ReservationBook::new(),
            revocations: RevocationSet::new(),
            evidence: EvidenceLog::new(),
        }
    }

    #[must_use]
    pub fn ephemeral() -> Self {
        Self::new(KeyPair::generate())
    }

    #[must_use]
    pub fn service_public_key(&self) -> PublicKey {
        *self.service_key.public_key()
    }

    /// Register a principal/agent verification key.
    pub fn register_key(&mut self, did: Did, key: PublicKey) {
        self.keys.insert(did, key);
    }

    fn resolve(&self, did: &Did) -> Option<PublicKey> {
        self.keys.get(did).copied()
    }

    /// Public key registered for a principal or agent.
    #[must_use]
    pub fn resolve_public(&self, did: &Did) -> Option<PublicKey> {
        self.resolve(did)
    }

    /// Create a signed, attenuated delegation principal → agent.
    pub fn delegate(
        &mut self,
        grant: DelegationGrant<'_>,
        sign: impl FnOnce(&[u8]) -> exo_core::Signature,
    ) -> Result<AuthorityLink> {
        Ok(self.delegations.delegate(grant, sign)?)
    }

    pub fn revoke_mandate(&mut self, hash: Hash256, now: Timestamp, reason: String) {
        self.revocations
            .revoke(RevocationTarget::Mandate(hash), now, reason);
    }

    pub fn revoke_agent(&mut self, agent: Did, now: Timestamp, reason: String) {
        self.revocations
            .revoke(RevocationTarget::Agent(agent), now, reason);
    }

    pub fn revoke_delegation(&mut self, link_id: Hash256, now: Timestamp, reason: String) {
        self.revocations
            .revoke(RevocationTarget::Delegation(link_id), now, reason);
    }

    /// Policy check + signed evidence. Does not settle.
    pub fn decide(&mut self, req: DecisionRequest) -> Result<DecideOutcome> {
        let verdict = policy::evaluate(
            &req,
            &|d| self.resolve(d),
            &self.delegations,
            &self.reservations,
            &self.revocations,
        )?;
        let entry = self.evidence.append(
            &self.service_key,
            crate::evidence::EvidenceDraft {
                decision: verdict.decision,
                reason: verdict.reason.clone(),
                mandate: &req.mandate,
                proposed: &req.proposed,
                payment_presented: req.payment_valid,
                payment_outranked: verdict.payment_outranked,
                now: req.now,
            },
        )?;
        Ok(DecideOutcome {
            verdict,
            evidence: entry,
        })
    }

    /// x402 `/verify` hop: decide, then reserve consume-once mandates on allow.
    pub fn verify_before_settle(&mut self, req: DecisionRequest) -> Result<DecideOutcome> {
        let consume = req.mandate.requires_single_use();
        let hash = req.mandate.mandate_hash()?;
        let now = req.now;
        let out = self.decide(req)?;
        if out.verdict.decision == Decision::Allow && consume {
            self.reservations.reserve(hash, now)?;
        }
        Ok(out)
    }

    pub fn reserve(&mut self, mandate_hash: Hash256, now: Timestamp) -> Result<()> {
        self.reservations.reserve(mandate_hash, now)
    }

    pub fn commit(&mut self, mandate_hash: &Hash256) -> Result<()> {
        self.reservations.commit(mandate_hash)
    }

    pub fn release(&mut self, mandate_hash: &Hash256) -> Result<()> {
        self.reservations.release(mandate_hash)
    }

    #[must_use]
    pub fn evidence(&self, hash: &Hash256) -> Option<&EvidenceEntry> {
        self.evidence.get(hash)
    }

    pub fn verify_evidence(&self, hash: &Hash256) -> Result<&EvidenceEntry> {
        let entry = self.evidence.get(hash).ok_or(PdpError::EvidenceNotFound)?;
        EvidenceLog::verify_entry(entry, self.service_key.public_key())?;
        Ok(entry)
    }

    pub fn verify_log(&self) -> Result<()> {
        self.evidence.verify_all(self.service_key.public_key())
    }

    /// Export a portable Article 26 evidence pack.
    pub fn export_pack(&self) -> Result<crate::pack::EvidencePack> {
        crate::pack::EvidencePack::from_log(&self.evidence, &self.service_key)
    }

    /// Replace the in-memory log from a previously exported pack.
    pub fn import_pack(&mut self, pack: crate::pack::EvidencePack) -> Result<()> {
        pack.verify_with_key(self.service_key.public_key())?;
        self.evidence = crate::evidence::EvidenceLog::from_entries(pack.entries)?;
        Ok(())
    }

    /// Export all replay-, revocation-, authority-, and evidence-critical state.
    pub fn export_snapshot(&self) -> Result<PdpSnapshot> {
        let mut snapshot = PdpSnapshot {
            spec: PDP_STATE_SPEC.into(),
            service_public_key_hex: hex::encode(self.service_key.public_key().as_bytes()),
            keys: self.keys.clone(),
            delegations: self.delegations.clone(),
            reservations: self.reservations.records(),
            revocations: self.revocations.log().to_vec(),
            evidence_entries: self.evidence.entries().to_vec(),
            signature: Signature::empty(),
        };
        snapshot.signature = self.service_key.sign(&snapshot.signing_payload()?);
        Ok(snapshot)
    }

    /// Verify and atomically replace all in-memory PDP state from a snapshot.
    pub fn import_snapshot(&mut self, snapshot: PdpSnapshot) -> Result<()> {
        if snapshot.spec != PDP_STATE_SPEC {
            return Err(PdpError::BadRequest(format!(
                "unknown PDP state spec {}",
                snapshot.spec
            )));
        }
        let expected_key_hex = hex::encode(self.service_key.public_key().as_bytes());
        if snapshot.service_public_key_hex != expected_key_hex
            || snapshot.signature.is_empty()
            || !exo_core::crypto::verify(
                &snapshot.signing_payload()?,
                &snapshot.signature,
                self.service_key.public_key(),
            )
        {
            return Err(PdpError::InvalidSignature);
        }

        snapshot.delegations.validate_persisted_state()?;
        let reservations = ReservationBook::from_records(snapshot.reservations)?;
        let revocations = RevocationSet::from_log(snapshot.revocations)?;
        let evidence = EvidenceLog::from_entries(snapshot.evidence_entries)?;
        evidence.verify_all(self.service_key.public_key())?;

        self.keys = snapshot.keys;
        self.delegations = snapshot.delegations;
        self.reservations = reservations;
        self.revocations = revocations;
        self.evidence = evidence;
        Ok(())
    }

    /// Secret key bytes for durable service identity (never the money).
    #[must_use]
    pub fn service_secret_bytes(&self) -> [u8; 32] {
        *self.service_key.secret_key().as_bytes()
    }

    #[must_use]
    pub fn granted_by(&self, did: &Did) -> usize {
        self.delegations.granted_by(did)
    }

    #[must_use]
    pub fn received_by(&self, did: &Did) -> usize {
        self.delegations.received_by(did)
    }

    #[must_use]
    pub fn permissions_for(&self, did: &Did) -> Vec<String> {
        self.delegations
            .permissions_held_by(did)
            .iter()
            .map(|p| format!("{p:?}"))
            .collect()
    }

    #[must_use]
    pub fn is_mandate_revoked(&self, hash: &Hash256) -> bool {
        self.revocations.is_mandate_revoked(hash)
    }

    #[must_use]
    pub fn is_consumed(&self, hash: &Hash256) -> bool {
        self.reservations.is_consumed(hash)
    }
}

/// Decision plus the signed evidence entry.
#[derive(Debug, Clone)]
pub struct DecideOutcome {
    pub verdict: PolicyVerdict,
    pub evidence: EvidenceEntry,
}

/// JSON-friendly decide response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideResponse {
    pub decision: Decision,
    pub reason: String,
    pub payment_outranked: bool,
    pub evidence_hash: String,
    pub mandate_hash: String,
    pub never_moves_money: bool,
}

impl From<&DecideOutcome> for DecideResponse {
    fn from(o: &DecideOutcome) -> Self {
        Self {
            decision: o.verdict.decision,
            reason: o.verdict.reason.clone(),
            payment_outranked: o.verdict.payment_outranked,
            evidence_hash: o.evidence.entry_hash.to_string(),
            mandate_hash: o.evidence.mandate_hash.to_string(),
            never_moves_money: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use exo_authority::{DelegateeKind, Permission};
    use exo_core::crypto::KeyPair;

    use super::*;
    use crate::mandate::{Caveat, Mandate, MandateKind, ProposedAction};

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    #[test]
    fn verify_hook_reserves_consume_once() {
        let alice = KeyPair::generate();
        let mut pdp = PolicyDecisionPoint::ephemeral();
        pdp.register_key(did("alice"), *alice.public_key());
        let alice_did = did("alice");
        let agent_did = did("agent");
        let alice_pk = *alice.public_key();
        let now = Timestamp::new(1, 0);
        pdp.delegate(
            DelegationGrant {
                from: &alice_did,
                to: &agent_did,
                scope: &[Permission::Spend],
                expires: Timestamp::new(99_000, 0),
                now: &now,
                parent_link_id: None,
                delegatee_kind: DelegateeKind::AiAgent {
                    model_id: "a".into(),
                },
                delegator_public_key: &alice_pk,
            },
            |b| alice.sign(b),
        )
        .unwrap();

        let mut mandate = Mandate {
            kind: MandateKind::Ap2Payment,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(1),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![Caveat::ConsumeOnce],
            expires: None,
            consume_once: true,
            signature: exo_core::Signature::empty(),
            raw_hash: Hash256::ZERO,
        };
        mandate.signature = alice.sign(&mandate.signable_payload().unwrap());
        let hash = mandate.mandate_hash().unwrap();

        let req = DecisionRequest {
            mandate,
            proposed: ProposedAction {
                action: "payment.settle".into(),
                amount_minor: Some(1),
                currency: Some("USD".into()),
                merchant: None,
                rail: None,
            },
            payment_valid: true,
            now: Timestamp::new(2, 0),
        };
        let out = pdp.verify_before_settle(req).unwrap();
        assert_eq!(out.verdict.decision, Decision::Allow);
        assert!(pdp.reservations.is_reserved(&hash));
        pdp.commit(&hash).unwrap();
        assert!(pdp.reservations.is_consumed(&hash));
    }

    #[test]
    fn signed_snapshot_preserves_authority_revocation_and_replay_state() {
        let service = KeyPair::generate();
        let service_secret = *service.secret_key().as_bytes();
        let alice = KeyPair::generate();
        let alice_did = did("alice");
        let agent_did = did("agent");
        let now = Timestamp::new(1, 0);
        let mut pdp = PolicyDecisionPoint::new(service);
        pdp.register_key(alice_did.clone(), *alice.public_key());
        pdp.delegate(
            DelegationGrant {
                from: &alice_did,
                to: &agent_did,
                scope: &[Permission::Spend],
                expires: Timestamp::new(99_000, 0),
                now: &now,
                parent_link_id: None,
                delegatee_kind: DelegateeKind::AiAgent {
                    model_id: "snapshot-agent".into(),
                },
                delegator_public_key: alice.public_key(),
            },
            |payload| alice.sign(payload),
        )
        .unwrap();
        let mandate_hash = Hash256::digest(b"snapshot-mandate");
        pdp.reserve(mandate_hash, Timestamp::new(2, 0)).unwrap();
        pdp.commit(&mandate_hash).unwrap();
        pdp.revoke_mandate(mandate_hash, Timestamp::new(3, 0), "revoked".into());

        let encoded = pdp.export_snapshot().unwrap().to_cbor().unwrap();
        let snapshot = PdpSnapshot::from_cbor(&encoded).unwrap();
        let mut restored =
            PolicyDecisionPoint::new(KeyPair::from_secret_bytes(service_secret).unwrap());
        restored.import_snapshot(snapshot).unwrap();

        assert_eq!(
            restored.resolve_public(&alice_did),
            Some(*alice.public_key())
        );
        assert_eq!(restored.granted_by(&alice_did), 1);
        assert!(restored.is_consumed(&mandate_hash));
        assert!(restored.is_mandate_revoked(&mandate_hash));
    }

    #[test]
    fn signed_snapshot_rejects_tampered_authority_state() {
        let service = KeyPair::generate();
        let service_secret = *service.secret_key().as_bytes();
        let mut pdp = PolicyDecisionPoint::new(service);
        let mut snapshot = pdp.export_snapshot().unwrap();
        snapshot
            .keys
            .insert(did("forged"), *KeyPair::generate().public_key());

        let err = pdp.import_snapshot(snapshot).unwrap_err();
        assert_eq!(err, PdpError::InvalidSignature);
        assert!(pdp.resolve_public(&did("forged")).is_none());

        let clean = pdp.export_snapshot().unwrap();
        let mut restored =
            PolicyDecisionPoint::new(KeyPair::from_secret_bytes(service_secret).unwrap());
        restored.import_snapshot(clean).unwrap();
    }
}

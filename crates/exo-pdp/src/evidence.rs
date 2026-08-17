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

//! Third-party-verifiable, hash-chained evidence packs.
//!
//! The pack is the commercial artifact: independently checkable without
//! trusting this process. EXOCHAIN never moves money; the pack only records
//! the policy decision and the mandate that was evaluated.

use std::collections::BTreeMap;

use exo_core::{
    Did, Hash256, PublicKey, Signature, Timestamp,
    crypto::{KeyPair, verify},
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{PdpError, Result},
    mandate::{Mandate, MandateKind, ProposedAction},
};

const EVIDENCE_ENTRY_SIGNING_DOMAIN: &str = "exo.pdp.evidence_entry.v1";
const EVIDENCE_ENTRY_SIGNING_SCHEMA_VERSION: u16 = 1;

/// Policy outcome recorded in the evidence pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    /// Otherwise-permitted commercial action lacking bound payment evidence.
    /// Never a Deny. Adapts to HTTP 402, not 403.
    Challenge,
}

/// Inputs for a new evidence entry.
pub struct EvidenceDraft<'a> {
    pub decision: Decision,
    pub reason: String,
    pub mandate: &'a Mandate,
    pub proposed: &'a ProposedAction,
    pub payment_evidence_hash: Option<Hash256>,
    pub payment_outranked: bool,
    pub now: Timestamp,
}

/// One hash-linked evidence entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub seq: u64,
    pub prev_hash: Hash256,
    pub entry_hash: Hash256,
    pub decision: Decision,
    pub reason: String,
    pub mandate_hash: Hash256,
    pub mandate_kind: MandateKind,
    pub principal: Did,
    pub agent: Did,
    pub action: String,
    pub amount_minor: Option<u64>,
    pub currency: Option<String>,
    pub payment_evidence_hash: Option<Hash256>,
    pub payment_outranked: bool,
    pub timestamp: Timestamp,
    pub signature: Signature,
}

impl EvidenceEntry {
    fn signable(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            domain: &'static str,
            schema_version: u16,
            seq: u64,
            prev_hash: &'a Hash256,
            decision: Decision,
            reason: &'a str,
            mandate_hash: &'a Hash256,
            mandate_kind: MandateKind,
            principal: &'a Did,
            agent: &'a Did,
            action: &'a str,
            amount_minor: Option<u64>,
            currency: &'a Option<String>,
            payment_evidence_hash: Option<&'a Hash256>,
            payment_outranked: bool,
            timestamp: &'a Timestamp,
        }
        let payload = SigningPayload {
            domain: EVIDENCE_ENTRY_SIGNING_DOMAIN,
            schema_version: EVIDENCE_ENTRY_SIGNING_SCHEMA_VERSION,
            seq: self.seq,
            prev_hash: &self.prev_hash,
            decision: self.decision,
            reason: &self.reason,
            mandate_hash: &self.mandate_hash,
            mandate_kind: self.mandate_kind,
            principal: &self.principal,
            agent: &self.agent,
            action: &self.action,
            amount_minor: self.amount_minor,
            currency: &self.currency,
            payment_evidence_hash: self.payment_evidence_hash.as_ref(),
            payment_outranked: self.payment_outranked,
            timestamp: &self.timestamp,
        };
        let mut data = Vec::new();
        ciborium::ser::into_writer(&payload, &mut data)
            .map_err(|e| PdpError::Serialization(e.to_string()))?;
        Ok(data)
    }
}

/// Hash-chained, service-signed evidence log.
#[derive(Debug)]
pub struct EvidenceLog {
    entries: Vec<EvidenceEntry>,
    by_hash: BTreeMap<Hash256, usize>,
    tip: Hash256,
}

impl Default for EvidenceLog {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            by_hash: BTreeMap::new(),
            tip: Hash256::ZERO,
        }
    }
}

impl EvidenceLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a signed entry. Returns the new entry.
    pub fn append(&mut self, signer: &KeyPair, draft: EvidenceDraft<'_>) -> Result<EvidenceEntry> {
        let seq = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let mut entry = EvidenceEntry {
            seq,
            prev_hash: self.tip,
            entry_hash: Hash256::ZERO,
            decision: draft.decision,
            reason: draft.reason,
            mandate_hash: draft.mandate.mandate_hash()?,
            mandate_kind: draft.mandate.kind,
            principal: draft.mandate.principal.clone(),
            agent: draft.mandate.agent.clone(),
            action: draft.proposed.action.clone(),
            amount_minor: draft.proposed.amount_minor,
            currency: draft.proposed.currency.clone(),
            payment_evidence_hash: draft.payment_evidence_hash,
            payment_outranked: draft.payment_outranked,
            timestamp: draft.now,
            signature: Signature::empty(),
        };
        let payload = entry.signable()?;
        entry.signature = signer.sign(&payload);
        entry.entry_hash = Hash256::digest(&payload);
        self.by_hash.insert(entry.entry_hash, self.entries.len());
        self.tip = entry.entry_hash;
        self.entries.push(entry.clone());
        Ok(entry)
    }

    #[must_use]
    pub fn get(&self, hash: &Hash256) -> Option<&EvidenceEntry> {
        self.by_hash.get(hash).and_then(|i| self.entries.get(*i))
    }

    #[must_use]
    pub fn tip(&self) -> Hash256 {
        self.tip
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Exported entries in chain order.
    #[must_use]
    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    /// Rebuild a log from previously exported entries. Does not verify signatures.
    pub fn from_entries(entries: Vec<EvidenceEntry>) -> Result<Self> {
        let mut log = Self::new();
        for (i, e) in entries.into_iter().enumerate() {
            let expect = u64::try_from(i).unwrap_or(u64::MAX);
            if e.seq != expect {
                return Err(PdpError::EvidenceBroken);
            }
            if e.prev_hash != log.tip {
                return Err(PdpError::EvidenceBroken);
            }
            log.by_hash.insert(e.entry_hash, log.entries.len());
            log.tip = e.entry_hash;
            log.entries.push(e);
        }
        Ok(log)
    }

    /// Independently verify the whole chain against the service public key.
    pub fn verify_all(&self, service_key: &PublicKey) -> Result<()> {
        let mut expected_prev = Hash256::ZERO;
        for (i, e) in self.entries.iter().enumerate() {
            if e.prev_hash != expected_prev {
                return Err(PdpError::EvidenceBroken);
            }
            let payload = e.signable()?;
            if Hash256::digest(&payload) != e.entry_hash {
                return Err(PdpError::EvidenceBroken);
            }
            if !verify(&payload, &e.signature, service_key) {
                return Err(PdpError::InvalidSignature);
            }
            let expect_seq = u64::try_from(i).unwrap_or(u64::MAX);
            if e.seq != expect_seq {
                return Err(PdpError::EvidenceBroken);
            }
            expected_prev = e.entry_hash;
        }
        Ok(())
    }

    /// Verify a single entry (hash + signature). Does not walk the chain.
    pub fn verify_entry(entry: &EvidenceEntry, service_key: &PublicKey) -> Result<()> {
        let payload = entry.signable()?;
        if Hash256::digest(&payload) != entry.entry_hash {
            return Err(PdpError::EvidenceBroken);
        }
        if !verify(&payload, &entry.signature, service_key) {
            return Err(PdpError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mandate::MandateKind;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    fn mandate() -> Mandate {
        Mandate {
            kind: MandateKind::Native,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(100),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![],
            expires: None,
            consume_once: false,
            signature: Signature::empty(),
            raw_hash: Hash256::ZERO,
        }
    }

    #[test]
    fn chain_verifies() {
        let kp = KeyPair::generate();
        let mut log = EvidenceLog::new();
        let proposed = ProposedAction {
            action: "payment.settle".into(),
            amount_minor: Some(100),
            currency: Some("USD".into()),
            merchant: None,
            rail: None,
        };
        log.append(
            &kp,
            EvidenceDraft {
                decision: Decision::Allow,
                reason: "ok".into(),
                mandate: &mandate(),
                proposed: &proposed,
                payment_evidence_hash: None,
                payment_outranked: false,
                now: Timestamp::new(1, 0),
            },
        )
        .unwrap();
        log.append(
            &kp,
            EvidenceDraft {
                decision: Decision::Deny,
                reason: "cap".into(),
                mandate: &mandate(),
                proposed: &proposed,
                payment_evidence_hash: Some(Hash256::from_bytes([0x11; 32])),
                payment_outranked: true,
                now: Timestamp::new(2, 0),
            },
        )
        .unwrap();
        assert_eq!(log.len(), 2);
        assert!(log.verify_all(kp.public_key()).is_ok());
    }

    #[test]
    fn tamper_detected() {
        let kp = KeyPair::generate();
        let mut log = EvidenceLog::new();
        let proposed = ProposedAction {
            action: "x".into(),
            ..ProposedAction::default()
        };
        log.append(
            &kp,
            EvidenceDraft {
                decision: Decision::Allow,
                reason: "ok".into(),
                mandate: &mandate(),
                proposed: &proposed,
                payment_evidence_hash: None,
                payment_outranked: false,
                now: Timestamp::new(1, 0),
            },
        )
        .unwrap();
        log.entries[0].reason = "tampered".into();
        assert!(log.verify_all(kp.public_key()).is_err());
    }

    #[test]
    fn entry_hash_separates_agent_and_action_fields() {
        let kp = KeyPair::generate();
        let mut first_mandate = mandate();
        first_mandate.agent = did("a");
        first_mandate.action = "bc".into();
        let mut second_mandate = first_mandate.clone();
        second_mandate.agent = did("ab");
        second_mandate.action = "c".into();
        let first_action = ProposedAction {
            action: "bc".into(),
            ..ProposedAction::default()
        };
        let second_action = ProposedAction {
            action: "c".into(),
            ..ProposedAction::default()
        };
        let mut first_log = EvidenceLog::new();
        let mut second_log = EvidenceLog::new();
        let first = first_log
            .append(
                &kp,
                EvidenceDraft {
                    decision: Decision::Allow,
                    reason: "permitted".into(),
                    mandate: &first_mandate,
                    proposed: &first_action,
                    payment_evidence_hash: Some(Hash256::from_bytes([0x11; 32])),
                    payment_outranked: false,
                    now: Timestamp::new(1, 0),
                },
            )
            .unwrap();
        let second = second_log
            .append(
                &kp,
                EvidenceDraft {
                    decision: Decision::Allow,
                    reason: "permitted".into(),
                    mandate: &second_mandate,
                    proposed: &second_action,
                    payment_evidence_hash: Some(Hash256::from_bytes([0x11; 32])),
                    payment_outranked: false,
                    now: Timestamp::new(1, 0),
                },
            )
            .unwrap();

        assert_ne!(first.entry_hash, second.entry_hash);
    }
}

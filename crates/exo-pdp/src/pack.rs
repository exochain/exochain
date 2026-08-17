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

//! Portable evidence pack — the commercial artifact.
//!
//! A pack is JSON a third party can check with this crate and a service
//! public key obtained through a separate trusted channel. No running node.
//! No settlement. Aligns to EU AI Act (Regulation 2024/1689) Article 26 deployer logs:
//! automatically generated, retained at least six months, records
//! human-oversight posture and incident-class denies.

use exo_core::{PublicKey, Signature, crypto::KeyPair};
use serde::{Deserialize, Serialize};

use crate::{
    error::{PdpError, Result},
    evidence::{Decision, EvidenceEntry, EvidenceLog},
};

/// Spec id written into every pack.
pub const EVIDENCE_PACK_SPEC: &str = "exochain-evidence-pack-v1";

/// Article 26 minimum retention, in whole days.
pub const ART26_RETENTION_DAYS: u64 = 180;

/// Milliseconds in one day (integer; no floats).
pub const MS_PER_DAY: u64 = 86_400_000;
const EVIDENCE_PACK_SIGNING_DOMAIN: &str = "exo.pdp.evidence_pack.v1";
const EVIDENCE_PACK_SIGNING_SCHEMA_VERSION: u16 = 1;

/// EU AI Act Article 26 metadata bound into the pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Article26Record {
    pub regulation: String,
    pub article: String,
    pub automatically_generated: bool,
    pub retention_days_min: u64,
    pub human_oversight: String,
    pub incident_denies: u64,
    pub never_moves_money: bool,
}

impl Article26Record {
    #[must_use]
    pub fn from_entries(entries: &[EvidenceEntry]) -> Self {
        let incident_denies = entries
            .iter()
            .filter(|e| e.decision == Decision::Deny)
            .count();
        Self {
            regulation: "EU 2024/1689".into(),
            article: "26".into(),
            automatically_generated: true,
            retention_days_min: ART26_RETENTION_DAYS,
            human_oversight: "principal-signed mandate required; deny-outranks-payment".into(),
            incident_denies: u64::try_from(incident_denies).unwrap_or(u64::MAX),
            never_moves_money: true,
        }
    }
}

/// A portable evidence pack independently verifiable against a trusted service key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePack {
    pub spec: String,
    pub never_moves_money: bool,
    pub service_public_key_hex: String,
    pub tip_hex: String,
    pub article_26: Article26Record,
    pub entries: Vec<EvidenceEntry>,
    pub pack_signature: Signature,
}

impl EvidencePack {
    /// Build and sign a pack from a live log.
    pub fn from_log(log: &EvidenceLog, service_key: &KeyPair) -> Result<Self> {
        let mut pack = Self {
            spec: EVIDENCE_PACK_SPEC.into(),
            never_moves_money: true,
            service_public_key_hex: hex::encode(service_key.public_key().as_bytes()),
            tip_hex: log.tip().to_string(),
            article_26: Article26Record::from_entries(log.entries()),
            entries: log.entries().to_vec(),
            pack_signature: Signature::empty(),
        };
        pack.pack_signature = service_key.sign(&pack.signing_payload()?);
        Ok(pack)
    }

    /// Parse JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| PdpError::BadRequest(e.to_string()))
    }

    /// Canonical JSON for export.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| PdpError::BadRequest(e.to_string()))
    }

    /// Verify internal integrity using the embedded key.
    ///
    /// This proves that one key signed the pack, not that the key belongs to a
    /// particular service. External verifiers must call [`Self::verify_with_key`]
    /// with a separately trusted service key before accepting provenance.
    pub fn verify(&self) -> Result<()> {
        let embedded_key = parse_public_key_hex(&self.service_public_key_hex)?;
        self.verify_with_key(&embedded_key)
    }

    /// Verify the pack against a service key obtained through a trusted channel.
    pub fn verify_with_key(&self, expected_service_key: &PublicKey) -> Result<()> {
        if self.spec != EVIDENCE_PACK_SPEC {
            return Err(PdpError::BadRequest(format!(
                "unknown evidence spec {}",
                self.spec
            )));
        }
        if !self.never_moves_money || !self.article_26.never_moves_money {
            return Err(PdpError::BadRequest(
                "pack claims to move money — rejected".into(),
            ));
        }
        if self.article_26.retention_days_min < ART26_RETENTION_DAYS {
            return Err(PdpError::BadRequest(
                "Article 26 retention below six months".into(),
            ));
        }
        if !self.article_26.automatically_generated {
            return Err(PdpError::BadRequest(
                "Article 26 requires automatically generated logs".into(),
            ));
        }
        let embedded_key = parse_public_key_hex(&self.service_public_key_hex)?;
        if embedded_key != *expected_service_key {
            return Err(PdpError::InvalidSignature);
        }
        if self.pack_signature.is_empty()
            || !exo_core::crypto::verify(
                &self.signing_payload()?,
                &self.pack_signature,
                expected_service_key,
            )
        {
            return Err(PdpError::InvalidSignature);
        }
        let log = EvidenceLog::from_entries(self.entries.clone())?;
        log.verify_all(expected_service_key)?;
        if log.tip().to_string() != self.tip_hex {
            return Err(PdpError::EvidenceBroken);
        }
        let expected = Article26Record::from_entries(&self.entries);
        if expected != self.article_26 {
            return Err(PdpError::EvidenceBroken);
        }
        Ok(())
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            domain: &'static str,
            schema_version: u16,
            spec: &'a str,
            never_moves_money: bool,
            service_public_key_hex: &'a str,
            tip_hex: &'a str,
            article_26: &'a Article26Record,
            entries: &'a [EvidenceEntry],
        }
        let payload = SigningPayload {
            domain: EVIDENCE_PACK_SIGNING_DOMAIN,
            schema_version: EVIDENCE_PACK_SIGNING_SCHEMA_VERSION,
            spec: &self.spec,
            never_moves_money: self.never_moves_money,
            service_public_key_hex: &self.service_public_key_hex,
            tip_hex: &self.tip_hex,
            article_26: &self.article_26,
            entries: &self.entries,
        };
        let mut data = Vec::new();
        ciborium::ser::into_writer(&payload, &mut data)
            .map_err(|e| PdpError::Serialization(e.to_string()))?;
        Ok(data)
    }

    /// Earliest timestamp at which an entry may be discarded (now + 180 days
    /// from the entry's own clock). Integer milliseconds.
    #[must_use]
    pub fn retention_until_ms(entry: &EvidenceEntry) -> u64 {
        entry
            .timestamp
            .physical_ms
            .saturating_add(ART26_RETENTION_DAYS.saturating_mul(MS_PER_DAY))
    }
}

pub fn parse_public_key_hex(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| PdpError::BadRequest(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(PdpError::BadRequest("public key must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Hash256, Signature, Timestamp, crypto::KeyPair};

    use super::*;
    use crate::{
        evidence::{EvidenceDraft, EvidenceLog},
        mandate::{Mandate, MandateKind, ProposedAction},
    };

    fn mandate() -> Mandate {
        Mandate {
            kind: MandateKind::Native,
            principal: Did::new("did:exo:alice").unwrap(),
            agent: Did::new("did:exo:agent").unwrap(),
            action: "payment.settle".into(),
            amount_minor: Some(1),
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
    fn pack_roundtrip_verifies() {
        let kp = KeyPair::generate();
        let mut log = EvidenceLog::new();
        let proposed = ProposedAction {
            action: "payment.settle".into(),
            amount_minor: Some(1),
            currency: Some("USD".into()),
            merchant: None,
            rail: None,
        };
        log.append(
            &kp,
            EvidenceDraft {
                decision: Decision::Deny,
                reason: "cap".into(),
                mandate: &mandate(),
                proposed: &proposed,
                payment_evidence_hash: Some(exo_core::Hash256::from_bytes([0x11; 32])),
                payment_outranked: true,
                now: Timestamp::new(1_000, 0),
            },
        )
        .unwrap();
        let pack = EvidencePack::from_log(&log, &kp).unwrap();
        assert_eq!(pack.article_26.incident_denies, 1);
        assert_eq!(pack.article_26.retention_days_min, 180);
        assert!(pack.verify_with_key(kp.public_key()).is_ok());
        let json = pack.to_json().unwrap();
        let parsed = EvidencePack::from_json(&json).unwrap();
        assert!(parsed.verify_with_key(kp.public_key()).is_ok());
        assert_eq!(
            EvidencePack::retention_until_ms(&parsed.entries[0]),
            1_000 + 180 * 86_400_000
        );
    }

    #[test]
    fn pack_tamper_fails() {
        let kp = KeyPair::generate();
        let log = EvidenceLog::new();
        let mut pack = EvidencePack::from_log(&log, &kp).unwrap();
        pack.tip_hex = Hash256::digest(b"nope").to_string();
        assert!(pack.verify().is_err());
    }

    #[test]
    fn pack_rejects_money_claim() {
        let kp = KeyPair::generate();
        let log = EvidenceLog::new();
        let mut pack = EvidencePack::from_log(&log, &kp).unwrap();
        pack.never_moves_money = false;
        assert!(pack.verify().is_err());
    }

    #[test]
    fn pack_rejects_tampered_article_26_metadata() {
        let kp = KeyPair::generate();
        let log = EvidenceLog::new();
        let mut pack = EvidencePack::from_log(&log, &kp).unwrap();
        pack.article_26.human_oversight = "none".into();
        assert!(pack.verify().is_err());
    }

    #[test]
    fn pack_rejects_an_attacker_selected_embedded_key() {
        let trusted = KeyPair::generate();
        let attacker = KeyPair::generate();
        let log = EvidenceLog::new();
        let forged = EvidencePack::from_log(&log, &attacker).unwrap();

        assert_eq!(
            forged.verify_with_key(trusted.public_key()),
            Err(PdpError::InvalidSignature)
        );
    }
}

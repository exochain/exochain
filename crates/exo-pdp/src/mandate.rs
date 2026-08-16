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

//! Protocol-neutral mandates and adapters for AP2 / ACP / x402 / native.

use exo_authority::Permission;
use exo_core::{Did, ExoError, Hash256, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{PdpError, Result};

/// Wire format of a mandate. The enforcement core is format-neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateKind {
    Native,
    Ap2Intent,
    Ap2Cart,
    Ap2Payment,
    AcpDelegatePayment,
    X402Payload,
}

/// A narrowing constraint. New caveats may only be appended (attenuation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Caveat {
    ActionEq(String),
    AmountMax { minor: u64, currency: String },
    MerchantEq(String),
    NotAfter(Timestamp),
    ConsumeOnce,
    RailIn(Vec<String>),
}

/// Canonical mandate the PDP evaluates. Never moves money.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mandate {
    pub kind: MandateKind,
    pub principal: Did,
    pub agent: Did,
    pub action: String,
    pub amount_minor: Option<u64>,
    pub currency: Option<String>,
    pub merchant: Option<String>,
    pub caveats: Vec<Caveat>,
    pub expires: Option<Timestamp>,
    pub consume_once: bool,
    pub signature: Signature,
    /// BLAKE3 of the original wire bytes (or of the canonical payload if native).
    pub raw_hash: Hash256,
}

impl Mandate {
    /// Canonical bytes the principal must sign.
    #[must_use]
    pub fn signable_payload(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(format!("{:?}", self.kind).as_bytes());
        data.extend_from_slice(self.principal.as_str().as_bytes());
        data.extend_from_slice(self.agent.as_str().as_bytes());
        data.extend_from_slice(self.action.as_bytes());
        if let Some(amt) = self.amount_minor {
            data.extend_from_slice(&amt.to_le_bytes());
        }
        if let Some(cur) = &self.currency {
            data.extend_from_slice(cur.as_bytes());
        }
        if let Some(m) = &self.merchant {
            data.extend_from_slice(m.as_bytes());
        }
        for c in &self.caveats {
            data.extend_from_slice(format!("{c:?}").as_bytes());
        }
        if let Some(exp) = &self.expires {
            data.extend_from_slice(&exp.physical_ms.to_le_bytes());
            data.extend_from_slice(&exp.logical.to_le_bytes());
        }
        data.push(u8::from(self.consume_once));
        data
    }

    /// Content-addressed mandate hash (independent of signature).
    #[must_use]
    pub fn mandate_hash(&self) -> Hash256 {
        Hash256::digest(&self.signable_payload())
    }

    /// Append caveats only. Existing caveats cannot be removed or relaxed.
    pub fn attenuate(&mut self, extra: Vec<Caveat>) -> Result<()> {
        for c in extra {
            if self.would_widen(&c) {
                return Err(PdpError::ScopeWidening);
            }
            if matches!(c, Caveat::ConsumeOnce) {
                self.consume_once = true;
            }
            self.caveats.push(c);
        }
        Ok(())
    }

    fn would_widen(&self, next: &Caveat) -> bool {
        match next {
            Caveat::AmountMax { minor, currency } => self.caveats.iter().any(|c| {
                matches!(
                    c,
                    Caveat::AmountMax { minor: prev, currency: prev_c }
                        if prev_c == currency && *minor > *prev
                )
            }),
            Caveat::NotAfter(ts) => self.caveats.iter().any(|c| match c {
                Caveat::NotAfter(prev) => ts.physical_ms > prev.physical_ms,
                _ => false,
            }),
            _ => false,
        }
    }

    /// Verify the principal's Ed25519 signature over the canonical payload.
    pub fn verify_signature(&self, principal_key: &PublicKey) -> Result<()> {
        if self.signature.is_empty() {
            return Err(PdpError::InvalidSignature);
        }
        if !exo_core::crypto::verify(&self.signable_payload(), &self.signature, principal_key) {
            return Err(PdpError::InvalidSignature);
        }
        Ok(())
    }

    /// Evaluate caveats + expiry against a proposed action. Fail-closed.
    pub fn check_caveats(&self, now: &Timestamp, proposed: &ProposedAction) -> Result<()> {
        if let Some(exp) = &self.expires {
            if exp.is_expired(now) {
                return Err(PdpError::Expired);
            }
        }
        for c in &self.caveats {
            match c {
                Caveat::ActionEq(allowed) => {
                    if &proposed.action != allowed {
                        return Err(PdpError::CaveatFailed(format!(
                            "action {} != {allowed}",
                            proposed.action
                        )));
                    }
                }
                Caveat::AmountMax { minor, currency } => {
                    let Some(amt) = proposed.amount_minor else {
                        return Err(PdpError::CaveatFailed("amount required".into()));
                    };
                    if proposed.currency.as_deref() != Some(currency.as_str()) {
                        return Err(PdpError::CaveatFailed("currency mismatch".into()));
                    }
                    if amt > *minor {
                        return Err(PdpError::CaveatFailed(format!(
                            "amount {amt} exceeds cap {minor}"
                        )));
                    }
                }
                Caveat::MerchantEq(m) => {
                    if proposed.merchant.as_deref() != Some(m.as_str()) {
                        return Err(PdpError::CaveatFailed("merchant mismatch".into()));
                    }
                }
                Caveat::NotAfter(ts) => {
                    if ts.is_expired(now) {
                        return Err(PdpError::Expired);
                    }
                }
                Caveat::ConsumeOnce => {}
                Caveat::RailIn(rails) => {
                    if let Some(rail) = &proposed.rail {
                        if !rails.iter().any(|r| r == rail) {
                            return Err(PdpError::CaveatFailed(format!("rail {rail} not allowed")));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Permission implied by this mandate's action.
    #[must_use]
    pub fn implied_permission(&self) -> Permission {
        if self.action.starts_with("payment") || self.action.contains("settle") {
            Permission::Spend
        } else if self.action.contains("write") {
            Permission::Write
        } else if self.action.contains("execute") {
            Permission::Execute
        } else {
            Permission::Read
        }
    }
}

/// Proposed action presented to the PDP (pre-settlement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProposedAction {
    pub action: String,
    pub amount_minor: Option<u64>,
    pub currency: Option<String>,
    pub merchant: Option<String>,
    pub rail: Option<String>,
}

/// Maps a native / AP2 / ACP / x402 wire shape onto one [`Mandate`].
pub trait MandateAdapter {
    fn kind(&self) -> MandateKind;
    fn into_mandate(self) -> Result<Mandate>;
}

/// JSON body accepted by HTTP adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMandate {
    pub kind: MandateKind,
    pub principal: String,
    pub agent: String,
    pub action: String,
    #[serde(default)]
    pub amount_minor: Option<u64>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub merchant: Option<String>,
    #[serde(default)]
    pub caveats: Vec<Caveat>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
    #[serde(default)]
    pub consume_once: bool,
    /// Hex-encoded Ed25519 signature (128 hex chars).
    pub signature_hex: String,
    /// Optional original wire bytes (hex) whose hash is stored as `raw_hash`.
    #[serde(default)]
    pub raw_hex: Option<String>,
}

impl MandateAdapter for WireMandate {
    fn kind(&self) -> MandateKind {
        self.kind
    }

    fn into_mandate(self) -> Result<Mandate> {
        let principal = coerce_did(&self.principal)?;
        let agent = coerce_did(&self.agent)?;
        let signature = parse_sig_hex(&self.signature_hex)?;
        let raw_hash = if let Some(raw) = &self.raw_hex {
            let bytes = hex::decode(raw).map_err(|e| PdpError::BadRequest(e.to_string()))?;
            Hash256::digest(&bytes)
        } else {
            Hash256::ZERO
        };
        let mut mandate = Mandate {
            kind: self.kind,
            principal,
            agent,
            action: self.action,
            amount_minor: self.amount_minor,
            currency: self.currency,
            merchant: self.merchant,
            caveats: self.caveats,
            expires: self.expires_ms.map(|ms| Timestamp::new(ms, 0)),
            consume_once: self.consume_once,
            signature,
            raw_hash,
        };
        if mandate.raw_hash == Hash256::ZERO {
            mandate.raw_hash = mandate.mandate_hash();
        }
        if mandate.consume_once
            && !mandate
                .caveats
                .iter()
                .any(|c| matches!(c, Caveat::ConsumeOnce))
        {
            mandate.caveats.push(Caveat::ConsumeOnce);
        }
        Ok(mandate)
    }
}

/// Coerce any DID-like string into EXOCHAIN `did:exo:…`.
pub fn coerce_did(raw: &str) -> Result<Did> {
    match Did::new(raw) {
        Ok(d) => Ok(d),
        Err(ExoError::InvalidDid { .. }) => {
            let sanitized: String = raw
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            Did::new(&format!("did:exo:ext:{sanitized}")).map_err(PdpError::from)
        }
        Err(e) => Err(PdpError::from(e)),
    }
}

pub(crate) fn parse_sig_hex(hex_str: &str) -> Result<Signature> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| PdpError::BadRequest(e.to_string()))?;
    if bytes.len() != 64 {
        return Err(PdpError::BadRequest(format!(
            "signature must be 64 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use exo_core::crypto::KeyPair;

    use super::*;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    fn signed_mandate(kp: &KeyPair, consume_once: bool) -> Mandate {
        let mut m = Mandate {
            kind: MandateKind::Native,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(500),
            currency: Some("USD".into()),
            merchant: Some("store".into()),
            caveats: vec![Caveat::AmountMax {
                minor: 1000,
                currency: "USD".into(),
            }],
            expires: Some(Timestamp::new(10_000, 0)),
            consume_once,
            signature: Signature::empty(),
            raw_hash: Hash256::ZERO,
        };
        m.signature = kp.sign(&m.signable_payload());
        m.raw_hash = m.mandate_hash();
        m
    }

    #[test]
    fn signature_roundtrip() {
        let kp = KeyPair::generate();
        let m = signed_mandate(&kp, true);
        assert!(m.verify_signature(kp.public_key()).is_ok());
    }

    #[test]
    fn tamper_breaks_signature() {
        let kp = KeyPair::generate();
        let mut m = signed_mandate(&kp, false);
        m.amount_minor = Some(9999);
        assert_eq!(
            m.verify_signature(kp.public_key()),
            Err(PdpError::InvalidSignature)
        );
    }

    #[test]
    fn attenuate_only_narrows() {
        let kp = KeyPair::generate();
        let mut m = signed_mandate(&kp, false);
        assert!(
            m.attenuate(vec![Caveat::AmountMax {
                minor: 200,
                currency: "USD".into(),
            }])
            .is_ok()
        );
        assert!(
            m.attenuate(vec![Caveat::AmountMax {
                minor: 5000,
                currency: "USD".into(),
            }])
            .is_err()
        );
    }

    #[test]
    fn caveats_reject_overspend() {
        let kp = KeyPair::generate();
        let m = signed_mandate(&kp, false);
        let proposed = ProposedAction {
            action: "payment.settle".into(),
            amount_minor: Some(2000),
            currency: Some("USD".into()),
            merchant: Some("store".into()),
            rail: None,
        };
        assert!(
            m.check_caveats(&Timestamp::new(1000, 0), &proposed)
                .is_err()
        );
    }

    #[test]
    fn coerce_foreign_did() {
        let d = coerce_did("did:web:example.com:alice").unwrap();
        assert!(d.as_str().starts_with("did:exo:"));
    }

    #[test]
    fn wire_adapter_native() {
        let kp = KeyPair::generate();
        let mut m = signed_mandate(&kp, true);
        let hex_sig = hex::encode(m.signature.ed25519_bytes().expect("ed25519"));
        m.signature = Signature::empty();
        let wire = WireMandate {
            kind: MandateKind::Ap2Intent,
            principal: "did:exo:alice".into(),
            agent: "did:exo:agent".into(),
            action: "payment.settle".into(),
            amount_minor: Some(500),
            currency: Some("USD".into()),
            merchant: Some("store".into()),
            caveats: vec![],
            expires_ms: Some(10_000),
            consume_once: true,
            signature_hex: hex_sig,
            raw_hex: None,
        };
        let parsed = wire.into_mandate().unwrap();
        assert_eq!(parsed.kind, MandateKind::Ap2Intent);
        assert!(parsed.consume_once);
        assert!(
            parsed
                .caveats
                .iter()
                .any(|c| matches!(c, Caveat::ConsumeOnce))
        );
    }
}

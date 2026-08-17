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

//! x402 `/verify` hop — adapter in front of the PDP.
//!
//! EXOCHAIN never implements settle. The PDP decides; this module maps
//! that decision onto facilitator HTTP and binds payment evidence by
//! hash. `PAYMENT-SIGNATURE` header presence is never paid.

use exo_core::Hash256;
use serde::{Deserialize, Serialize};

use crate::{
    error::{PdpError, Result},
    evidence::Decision,
    mandate::{MandateAdapter, ProposedAction, WireMandate},
    policy::DecisionRequest,
    service::{DecideResponse, PolicyDecisionPoint},
};

/// Domain for canonical payment-evidence CBOR. AVC receipts store the hash.
pub const PAYMENT_EVIDENCE_DOMAIN: &str = "exo.x402.payment.evidence.v1";

pub const HTTP_OK: u16 = 200;
pub const HTTP_PAYMENT_REQUIRED: u16 = 402;
pub const HTTP_FORBIDDEN: u16 = 403;
pub const HTTP_PRECONDITION_REQUIRED: u16 = 428;
pub const HEADER_PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";

/// Body posted to `POST /x402/verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402VerifyRequest {
    pub mandate: WireMandate,
    #[serde(default)]
    pub proposed: Option<ProposedAction>,
    /// Hex-encoded BLAKE3 of canonical payment evidence. Not a boolean.
    #[serde(default)]
    pub payment_evidence_hash_hex: Option<String>,
    /// If sent without a bound hash, still unpaid. Never treated as paid.
    #[serde(default)]
    pub payment_signature_header: Option<String>,
    #[serde(default)]
    pub now_ms: Option<u64>,
}

/// Facilitator-shaped verify response. `is_valid` is true only on Allow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402VerifyResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    pub decision: Decision,
    pub http_status: u16,
    pub payment_outranked: bool,
    pub evidence_hash: String,
    pub mandate_hash: String,
    pub never_moves_money: bool,
}

impl From<DecideResponse> for X402VerifyResponse {
    fn from(d: DecideResponse) -> Self {
        let is_valid = d.decision == Decision::Allow;
        Self {
            invalid_reason: if is_valid {
                None
            } else {
                Some(d.reason.clone())
            },
            is_valid,
            decision: d.decision,
            http_status: map_decision_to_http(d.decision, is_valid).status,
            payment_outranked: d.payment_outranked,
            evidence_hash: d.evidence_hash,
            mandate_hash: d.mandate_hash,
            never_moves_money: true,
        }
    }
}

/// HTTP mapping for a PDP decision. Deny never becomes 402.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationHttpMapping {
    pub status: u16,
    pub payment_required: bool,
}

#[must_use]
pub fn map_decision_to_http(decision: Decision, payment_bound: bool) -> AuthorizationHttpMapping {
    match decision {
        Decision::Deny => AuthorizationHttpMapping {
            status: HTTP_FORBIDDEN,
            payment_required: false,
        },
        Decision::Challenge => AuthorizationHttpMapping {
            status: HTTP_PAYMENT_REQUIRED,
            payment_required: true,
        },
        Decision::Allow if payment_bound => AuthorizationHttpMapping {
            status: HTTP_OK,
            payment_required: false,
        },
        Decision::Allow => AuthorizationHttpMapping {
            status: HTTP_PAYMENT_REQUIRED,
            payment_required: true,
        },
    }
}

/// Paths that must never be commercially gated.
#[must_use]
pub fn is_never_paywalled_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path == "/api/v1/avc/validate"
        || path.contains("/api/v1/0dentity/")
        || (path.starts_with("/api/v1/agents/") && path.ends_with("/consent"))
}

fn parse_bound_hash(hex_in: Option<&str>) -> Result<Option<Hash256>> {
    let Some(raw) = hex_in.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(raw).map_err(|e| PdpError::BadRequest(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(PdpError::BadRequest(
            "payment_evidence_hash_hex must be 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let hash = Hash256::from_bytes(arr);
    if hash == Hash256::ZERO {
        return Err(PdpError::BadRequest(
            "payment evidence hash must be non-zero".into(),
        ));
    }
    Ok(Some(hash))
}

/// Run the verify hop against a live PDP.
pub fn verify(
    pdp: &mut PolicyDecisionPoint,
    body: X402VerifyRequest,
) -> crate::error::Result<X402VerifyResponse> {
    let mandate = body.mandate.into_mandate()?;
    let proposed = body.proposed.unwrap_or_else(|| ProposedAction {
        action: mandate.action.clone(),
        amount_minor: mandate.amount_minor,
        currency: mandate.currency.clone(),
        merchant: mandate.merchant.clone(),
        rail: None,
    });
    let now = match body.now_ms {
        Some(ms) if ms > 0 => exo_core::Timestamp::new(ms, 0),
        _ => {
            return Err(crate::error::PdpError::BadRequest(
                "now_ms is required (HLC physical milliseconds, non-zero)".into(),
            ));
        }
    };
    let req = DecisionRequest {
        mandate,
        proposed,
        payment_evidence_hash: parse_bound_hash(body.payment_evidence_hash_hex.as_deref())?,
        now,
    };
    let out = pdp.verify_before_settle(req)?;
    Ok(DecideResponse::from(&out).into())
}

#[cfg(test)]
mod tests {
    use exo_authority::{DelegateeKind, Permission};
    use exo_core::{Did, Timestamp, crypto::KeyPair};

    use super::*;
    use crate::mandate::{Caveat, Mandate, MandateKind};

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    #[test]
    fn valid_payment_still_denied() {
        let alice = KeyPair::generate();
        let mut pdp = PolicyDecisionPoint::ephemeral();
        pdp.register_key(did("alice"), *alice.public_key());

        let mut m = Mandate {
            kind: MandateKind::X402Payload,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(99),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![Caveat::AmountMax {
                minor: 1,
                currency: "USD".into(),
            }],
            expires: None,
            consume_once: false,
            signature: exo_core::Signature::empty(),
            raw_hash: exo_core::Hash256::ZERO,
        };
        m.signature = alice.sign(&m.signable_payload().unwrap());

        let body = X402VerifyRequest {
            mandate: WireMandate {
                kind: MandateKind::X402Payload,
                principal: "did:exo:alice".into(),
                agent: "did:exo:agent".into(),
                action: m.action.clone(),
                amount_minor: m.amount_minor,
                currency: m.currency.clone(),
                merchant: None,
                caveats: m.caveats.clone(),
                expires_ms: None,
                consume_once: false,
                signature_hex: hex::encode(m.signature.ed25519_bytes().expect("ed25519")),
                raw_hex: None,
            },
            proposed: Some(ProposedAction {
                action: "payment.settle".into(),
                amount_minor: Some(99),
                currency: Some("USD".into()),
                merchant: None,
                rail: None,
            }),
            payment_evidence_hash_hex: Some(hex::encode([0x11u8; 32])),
            payment_signature_header: None,
            now_ms: Some(1),
        };
        let resp = verify(&mut pdp, body).unwrap();
        assert!(!resp.is_valid);
        assert_eq!(resp.decision, Decision::Deny);
        assert_eq!(resp.http_status, HTTP_FORBIDDEN);
        assert!(resp.payment_outranked);
        assert!(resp.never_moves_money);
    }

    #[test]
    fn allow_when_delegated() {
        let alice = KeyPair::generate();
        let mut pdp = PolicyDecisionPoint::ephemeral();
        pdp.register_key(did("alice"), *alice.public_key());
        let alice_did = did("alice");
        let agent_did = did("agent");
        let alice_pk = *alice.public_key();
        let now = Timestamp::new(1, 0);
        pdp.delegate(
            exo_authority::DelegationGrant {
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

        let mut m = Mandate {
            kind: MandateKind::X402Payload,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(1),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![],
            expires: None,
            consume_once: false,
            signature: exo_core::Signature::empty(),
            raw_hash: exo_core::Hash256::ZERO,
        };
        m.signature = alice.sign(&m.signable_payload().unwrap());

        let body = X402VerifyRequest {
            mandate: WireMandate {
                kind: MandateKind::X402Payload,
                principal: "did:exo:alice".into(),
                agent: "did:exo:agent".into(),
                action: m.action,
                amount_minor: m.amount_minor,
                currency: m.currency,
                merchant: None,
                caveats: vec![],
                expires_ms: None,
                consume_once: false,
                signature_hex: hex::encode(m.signature.ed25519_bytes().expect("ed25519")),
                raw_hex: None,
            },
            proposed: None,
            payment_evidence_hash_hex: Some(hex::encode([0x11u8; 32])),
            payment_signature_header: None,
            now_ms: Some(2),
        };
        let resp = verify(&mut pdp, body).unwrap();
        assert!(resp.is_valid);
        assert_eq!(resp.decision, Decision::Allow);
        assert_eq!(resp.http_status, HTTP_OK);
    }

    #[test]
    fn header_presence_is_not_payment() {
        let alice = KeyPair::generate();
        let mut pdp = PolicyDecisionPoint::ephemeral();
        pdp.register_key(did("alice"), *alice.public_key());
        let alice_did = did("alice");
        let agent_did = did("agent");
        let alice_pk = *alice.public_key();
        let now = Timestamp::new(1, 0);
        pdp.delegate(
            exo_authority::DelegationGrant {
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

        let mut m = Mandate {
            kind: MandateKind::X402Payload,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(1),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![],
            expires: None,
            consume_once: false,
            signature: exo_core::Signature::empty(),
            raw_hash: exo_core::Hash256::ZERO,
        };
        m.signature = alice.sign(&m.signable_payload().unwrap());

        let body = X402VerifyRequest {
            mandate: WireMandate {
                kind: MandateKind::X402Payload,
                principal: "did:exo:alice".into(),
                agent: "did:exo:agent".into(),
                action: m.action,
                amount_minor: m.amount_minor,
                currency: m.currency,
                merchant: None,
                caveats: vec![],
                expires_ms: None,
                consume_once: false,
                signature_hex: hex::encode(m.signature.ed25519_bytes().expect("ed25519")),
                raw_hex: None,
            },
            proposed: None,
            payment_evidence_hash_hex: None,
            payment_signature_header: Some("sig".into()),
            now_ms: Some(2),
        };
        let resp = verify(&mut pdp, body).unwrap();
        assert!(!resp.is_valid);
        assert_eq!(resp.decision, Decision::Challenge);
        assert_eq!(resp.http_status, HTTP_PAYMENT_REQUIRED);
        assert_eq!(HEADER_PAYMENT_SIGNATURE, "PAYMENT-SIGNATURE");
    }

    #[test]
    fn deny_never_maps_to_402() {
        let mapped = map_decision_to_http(Decision::Deny, true);
        assert_eq!(mapped.status, HTTP_FORBIDDEN);
        assert!(!mapped.payment_required);
    }

    #[test]
    fn never_paywalled_paths_include_validate_identity_and_consent() {
        assert!(is_never_paywalled_path("/api/v1/avc/validate"));
        assert!(is_never_paywalled_path("/api/v1/avc/validate?now=1"));
        assert!(is_never_paywalled_path(
            "/api/v1/0dentity/did:exo:agent/score"
        ));
        assert!(is_never_paywalled_path(
            "/api/v1/agents/did:exo:agent/consent"
        ));
        assert!(!is_never_paywalled_path("/api/v1/avc/receipts/emit"));
        assert_eq!(HTTP_PRECONDITION_REQUIRED, 428);
        assert_eq!(PAYMENT_EVIDENCE_DOMAIN, "exo.x402.payment.evidence.v1");
    }
}

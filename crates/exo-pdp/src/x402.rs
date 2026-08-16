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

//! x402 `/verify` hop — policy gate before `/settle`.
//!
//! EXOCHAIN never implements settle. A deny here is the facilitator signal
//! that settlement must not be attempted.

use serde::{Deserialize, Serialize};

use crate::{
    evidence::Decision,
    mandate::{MandateAdapter, ProposedAction, WireMandate},
    policy::DecisionRequest,
    service::{DecideResponse, PolicyDecisionPoint},
};

/// Body posted to `POST /x402/verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402VerifyRequest {
    pub mandate: WireMandate,
    #[serde(default)]
    pub proposed: Option<ProposedAction>,
    /// Facilitator already validated the PaymentPayload locally.
    #[serde(default)]
    pub payment_valid: bool,
    #[serde(default)]
    pub now_ms: Option<u64>,
}

/// Facilitator-shaped verify response. `is_valid == false` blocks settle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402VerifyResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    pub decision: Decision,
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
            payment_outranked: d.payment_outranked,
            evidence_hash: d.evidence_hash,
            mandate_hash: d.mandate_hash,
            never_moves_money: true,
        }
    }
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
        payment_valid: body.payment_valid,
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
        m.signature = alice.sign(&m.signable_payload());

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
            payment_valid: true,
            now_ms: Some(1),
        };
        let resp = verify(&mut pdp, body).unwrap();
        assert!(!resp.is_valid);
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
        m.signature = alice.sign(&m.signable_payload());

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
            payment_valid: true,
            now_ms: Some(2),
        };
        let resp = verify(&mut pdp, body).unwrap();
        assert!(resp.is_valid);
        assert_eq!(resp.decision, Decision::Allow);
    }
}

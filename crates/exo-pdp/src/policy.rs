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

//! Deny-outranks-payment policy evaluation.

use exo_authority::{
    DelegationRegistry,
    chain::{self, AuthorityChain},
};
use exo_core::{Did, PublicKey, Timestamp};

use crate::{
    error::Result,
    evidence::Decision,
    mandate::{Mandate, ProposedAction},
    reservation::ReservationBook,
    revocation::RevocationSet,
};

/// Input to a single policy decision. Payment validity never overrides deny.
#[derive(Debug, Clone)]
pub struct DecisionRequest {
    pub mandate: Mandate,
    pub proposed: ProposedAction,
    /// Facilitator/PSP says the payment payload itself is valid.
    pub payment_valid: bool,
    pub now: Timestamp,
}

/// Result of policy evaluation before evidence is appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub decision: Decision,
    pub reason: String,
    /// True when a valid payment was presented and still denied.
    pub payment_outranked: bool,
}

/// Evaluate policy. Never settles. Fail-closed.
pub fn evaluate(
    req: &DecisionRequest,
    keys: &dyn Fn(&Did) -> Option<PublicKey>,
    delegations: &DelegationRegistry,
    reservations: &ReservationBook,
    revocations: &RevocationSet,
) -> Result<PolicyVerdict> {
    let mandate = &req.mandate;
    let hash = mandate.mandate_hash();

    if revocations.is_mandate_revoked(&hash) || revocations.is_agent_revoked(&mandate.agent) {
        return Ok(deny(req, "revoked"));
    }

    if mandate.consume_once && reservations.is_consumed(&hash) {
        return Ok(deny(req, "mandate already consumed"));
    }
    if mandate.consume_once && reservations.is_reserved(&hash) {
        return Ok(deny(req, "mandate already reserved"));
    }

    let Some(pk) = keys(&mandate.principal) else {
        return Ok(deny(req, "unknown principal key"));
    };
    if let Err(e) = mandate.verify_signature(&pk) {
        return Ok(deny(req, &e.to_string()));
    }

    if let Err(e) = mandate.check_caveats(&req.now, &req.proposed) {
        return Ok(deny(req, &e.to_string()));
    }

    // Delegation must exist principal → agent and include the implied permission.
    // Fail-closed: missing chain is a deny, never an allow.
    match delegations.find_chain(&mandate.principal, &mandate.agent) {
        Some(chain) => {
            if let Err(e) = verify_chain_or_deny(&chain, &req.now, keys) {
                return Ok(deny(req, &e.to_string()));
            }
            let needed = mandate.implied_permission();
            if !chain::has_permission(&chain, &needed) {
                return Ok(deny(req, &format!("delegation does not grant {needed:?}")));
            }
            for link in &chain.links {
                if let Ok(id) = link.id() {
                    if revocations.is_delegation_revoked(&id) {
                        return Ok(deny(req, "delegation link revoked"));
                    }
                }
            }
        }
        None => return Ok(deny(req, "no principal→agent delegation")),
    }

    Ok(PolicyVerdict {
        decision: Decision::Allow,
        reason: "permitted".into(),
        payment_outranked: false,
    })
}

fn verify_chain_or_deny<F>(chain: &AuthorityChain, now: &Timestamp, keys: F) -> Result<()>
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    chain::verify_chain(chain, now, keys).map_err(Into::into)
}

fn deny(req: &DecisionRequest, reason: &str) -> PolicyVerdict {
    PolicyVerdict {
        decision: Decision::Deny,
        reason: reason.to_owned(),
        payment_outranked: req.payment_valid,
    }
}

#[cfg(test)]
mod tests {
    use exo_authority::{DelegateeKind, Permission};
    use exo_core::crypto::KeyPair;

    use super::*;
    use crate::mandate::{Caveat, MandateKind};

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    #[test]
    fn deny_outranks_valid_payment() {
        let principal = KeyPair::generate();
        let mut mandate = Mandate {
            kind: MandateKind::X402Payload,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(50),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![Caveat::AmountMax {
                minor: 10,
                currency: "USD".into(),
            }],
            expires: None,
            consume_once: false,
            signature: exo_core::Signature::empty(),
            raw_hash: exo_core::Hash256::ZERO,
        };
        mandate.signature = principal.sign(&mandate.signable_payload());

        let req = DecisionRequest {
            mandate,
            proposed: ProposedAction {
                action: "payment.settle".into(),
                amount_minor: Some(50),
                currency: Some("USD".into()),
                merchant: None,
                rail: None,
            },
            payment_valid: true,
            now: Timestamp::new(1, 0),
        };
        let keys = |d: &Did| {
            if d == &did("alice") {
                Some(*principal.public_key())
            } else {
                None
            }
        };
        let v = evaluate(
            &req,
            &keys,
            &DelegationRegistry::new(),
            &ReservationBook::new(),
            &RevocationSet::new(),
        )
        .unwrap();
        assert_eq!(v.decision, Decision::Deny);
        assert!(v.payment_outranked);
    }

    #[test]
    fn allow_with_signed_delegation() {
        let alice = KeyPair::generate();
        let mut mandate = Mandate {
            kind: MandateKind::Native,
            principal: did("alice"),
            agent: did("agent"),
            action: "payment.settle".into(),
            amount_minor: Some(5),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![],
            expires: None,
            consume_once: false,
            signature: exo_core::Signature::empty(),
            raw_hash: exo_core::Hash256::ZERO,
        };
        mandate.signature = alice.sign(&mandate.signable_payload());

        let mut reg = DelegationRegistry::new();
        let now = Timestamp::new(1, 0);
        let alice_did = did("alice");
        let agent_did = did("agent");
        let alice_pk = *alice.public_key();
        reg.delegate(
            exo_authority::DelegationGrant {
                from: &alice_did,
                to: &agent_did,
                scope: &[Permission::Spend],
                expires: Timestamp::new(99_000, 0),
                now: &now,
                parent_link_id: None,
                delegatee_kind: DelegateeKind::AiAgent {
                    model_id: "shopper".into(),
                },
                delegator_public_key: &alice_pk,
            },
            |bytes| alice.sign(bytes),
        )
        .unwrap();

        let req = DecisionRequest {
            mandate,
            proposed: ProposedAction {
                action: "payment.settle".into(),
                amount_minor: Some(5),
                currency: Some("USD".into()),
                merchant: None,
                rail: None,
            },
            payment_valid: false,
            now,
        };
        let keys = |d: &Did| {
            if d == &did("alice") {
                Some(*alice.public_key())
            } else {
                None
            }
        };
        let v = evaluate(
            &req,
            &keys,
            &reg,
            &ReservationBook::new(),
            &RevocationSet::new(),
        )
        .unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert!(!v.payment_outranked);
    }
}

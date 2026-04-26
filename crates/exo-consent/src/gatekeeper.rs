//! Consent gate — the default-deny enforcement point.
//!
//! All actions must pass through the consent gate. The gate holds the
//! policy engine and active bailments, and returns a deterministic
//! consent decision for every action request.

use std::collections::BTreeMap;

use exo_core::{Did, Timestamp};

use crate::{
    bailment::{self, Bailment},
    policy::{ActionRequest, ActiveConsent, ConsentDecision, ConsentPolicy, PolicyEngine},
};

/// Internal consent registration.
#[derive(Debug, Clone)]
struct ConsentReg {
    action_type: String,
    role: String,
    clearance_level: u32,
    bailment: Bailment,
}

/// The consent gate — default-deny enforcement point.
#[derive(Debug)]
pub struct ConsentGate {
    engine: PolicyEngine,
    policy: ConsentPolicy,
    bailments: BTreeMap<String, Vec<Bailment>>,
    consents: BTreeMap<String, Vec<ConsentReg>>,
}

impl ConsentGate {
    #[must_use]
    pub fn new(policy: ConsentPolicy) -> Self {
        Self {
            engine: PolicyEngine::new(),
            policy,
            bailments: BTreeMap::new(),
            consents: BTreeMap::new(),
        }
    }

    pub fn register_bailment(&mut self, bailment: Bailment) {
        self.bailments
            .entry(bailment.bailee_did.as_str().to_owned())
            .or_default()
            .push(bailment);
    }

    pub fn register_consent(
        &mut self,
        actor: &Did,
        action_type: &str,
        role: &str,
        clearance_level: u32,
        bailment: Bailment,
    ) {
        self.consents
            .entry(actor.as_str().to_owned())
            .or_default()
            .push(ConsentReg {
                action_type: action_type.into(),
                role: role.into(),
                clearance_level,
                bailment,
            });
    }

    pub fn revoke_by_bailment_id(&mut self, bailment_id: &str) {
        for regs in self.consents.values_mut() {
            regs.retain(|r| r.bailment.id != bailment_id);
        }
        for bs in self.bailments.values_mut() {
            bs.retain(|b| b.id != bailment_id);
        }
    }

    /// Check consent. Default: DENY.
    pub fn check(&self, actor: &Did, action: &str, now: &Timestamp) -> ConsentDecision {
        let req = ActionRequest {
            actor: actor.clone(),
            action_type: action.into(),
        };
        let active: Vec<ActiveConsent> = self
            .consents
            .get(actor.as_str())
            .map(|regs| {
                regs.iter()
                    .filter(|r| bailment::is_active(&r.bailment, now))
                    .map(|r| ActiveConsent {
                        grantor: r.bailment.bailor_did.clone(),
                        action_type: r.action_type.clone(),
                        role: r.role.clone(),
                        clearance_level: r.clearance_level,
                        bailment: r.bailment.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        self.engine.evaluate(&self.policy, &active, &req, now)
    }

    #[must_use]
    pub fn policy(&self) -> &ConsentPolicy {
        &self.policy
    }

    pub fn set_policy(&mut self, policy: ConsentPolicy) {
        self.policy = policy;
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        bailment::{self, BailmentType},
        policy::ConsentRequirement,
    };

    fn alice() -> Did {
        Did::new("did:exo:alice").unwrap()
    }
    fn bob() -> Did {
        Did::new("did:exo:bob").unwrap()
    }
    fn charlie() -> Did {
        Did::new("did:exo:charlie").unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn now() -> Timestamp {
        ts(5000)
    }

    fn strict_policy() -> ConsentPolicy {
        ConsentPolicy {
            id: "strict".into(),
            name: "strict".into(),
            deny_by_default: true,
            required_consents: vec![ConsentRequirement {
                action_type: "read".into(),
                required_role: "data-owner".into(),
                min_clearance_level: 1,
            }],
        }
    }

    fn make_bailment(
        bailor: &Did,
        bailee: &Did,
        bt: BailmentType,
        exp: Option<Timestamp>,
    ) -> Bailment {
        let mut b = bailment::propose(bailor, bailee, b"gt", bt, "gatekeeper-test", ts(1000))
            .expect("test bailment proposal");
        // Produce a valid bailee signature for the GAP-012-verified accept().
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let payload = bailment::signing_payload(&b).expect("canonical payload");
        let sig = exo_core::crypto::sign(&payload, &sk);
        bailment::accept(&mut b, &pk, &sig).expect("test bailment accepts");
        b.expires = exp;
        b
    }

    #[test]
    fn default_deny() {
        let g = ConsentGate::new(strict_policy());
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Denied { .. }
        ));
    }

    #[test]
    fn grant_with_valid_consent() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        g.register_bailment(b.clone());
        g.register_consent(&bob(), "read", "data-owner", 1, b);
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Granted { .. }
        ));
    }

    #[test]
    fn deny_after_revocation() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let bid = b.id.clone();
        g.register_bailment(b.clone());
        g.register_consent(&bob(), "read", "data-owner", 1, b);
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Granted { .. }
        ));
        g.revoke_by_bailment_id(&bid);
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Denied { .. }
        ));
    }

    #[test]
    fn deny_after_expiry() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(ts(3000)));
        g.register_bailment(b.clone());
        g.register_consent(&bob(), "read", "data-owner", 1, b);
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Denied { .. }
        ));
    }

    #[test]
    fn grant_with_future_expiry() {
        let mut g = ConsentGate::new(strict_policy());
        let exp = ts(10000);
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(exp));
        g.register_bailment(b.clone());
        g.register_consent(&bob(), "read", "data-owner", 1, b);
        assert_eq!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Granted { expires: Some(exp) }
        );
    }

    #[test]
    fn escalate_with_delegation() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Delegation, None);
        g.register_bailment(b.clone());
        g.register_consent(&bob(), "read", "viewer", 0, b);
        let d = g.check(&bob(), "read", &now());
        assert!(matches!(d, ConsentDecision::Escalated { .. }));
        if let ConsentDecision::Escalated { to } = d {
            assert_eq!(to, alice());
        }
    }

    #[test]
    fn deny_unknown_action() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        g.register_consent(&bob(), "read", "data-owner", 1, b);
        assert!(matches!(
            g.check(&bob(), "write", &now()),
            ConsentDecision::Denied { .. }
        ));
    }

    #[test]
    fn deny_unknown_actor() {
        let g = ConsentGate::new(strict_policy());
        assert!(matches!(
            g.check(&charlie(), "read", &now()),
            ConsentDecision::Denied { .. }
        ));
    }

    #[test]
    fn policy_accessor() {
        let g = ConsentGate::new(strict_policy());
        assert_eq!(g.policy().id, "strict");
    }

    #[test]
    fn set_policy() {
        let mut g = ConsentGate::new(strict_policy());
        let p = ConsentPolicy {
            id: "perm".into(),
            name: "perm".into(),
            required_consents: vec![],
            deny_by_default: false,
        };
        g.set_policy(p);
        assert_eq!(g.policy().id, "perm");
        assert!(matches!(
            g.check(&bob(), "anything", &now()),
            ConsentDecision::Granted { .. }
        ));
    }

    #[test]
    fn multiple_consents() {
        let mut g = ConsentGate::new(ConsentPolicy {
            id: "m".into(),
            name: "m".into(),
            deny_by_default: true,
            required_consents: vec![
                ConsentRequirement {
                    action_type: "read".into(),
                    required_role: "data-owner".into(),
                    min_clearance_level: 1,
                },
                ConsentRequirement {
                    action_type: "write".into(),
                    required_role: "admin".into(),
                    min_clearance_level: 2,
                },
            ],
        });
        let b1 = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let b2 = make_bailment(&alice(), &bob(), BailmentType::Processing, None);
        g.register_consent(&bob(), "read", "data-owner", 1, b1);
        g.register_consent(&bob(), "write", "admin", 3, b2);
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Granted { .. }
        ));
        assert!(matches!(
            g.check(&bob(), "write", &now()),
            ConsentDecision::Granted { .. }
        ));
    }

    #[test]
    fn revoke_nonexistent_is_noop() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        g.register_consent(&bob(), "read", "data-owner", 1, b);
        g.revoke_by_bailment_id("nonexistent");
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            ConsentDecision::Granted { .. }
        ));
    }
}

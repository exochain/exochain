//! Consent policies — rules governing what actions require what consent.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::bailment::{self, Bailment, BailmentType};

/// A requirement that must be satisfied for consent to be granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequirement {
    pub action_type: String,
    pub required_role: String,
    pub min_clearance_level: u32,
}

/// A consent policy — a named collection of requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentPolicy {
    pub id: String,
    pub name: String,
    pub required_consents: Vec<ConsentRequirement>,
    pub deny_by_default: bool,
}

/// An active consent backed by a bailment.
#[derive(Debug, Clone)]
pub struct ActiveConsent {
    pub grantor: Did,
    pub action_type: String,
    pub role: String,
    pub clearance_level: u32,
    pub bailment: Bailment,
}

/// A request to perform an action requiring consent.
#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub actor: Did,
    pub action_type: String,
}

/// The result of evaluating a consent policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentDecision {
    Granted { expires: Option<Timestamp> },
    Denied { reason: String },
    Escalated { to: Did },
}

/// Evaluates consent policies against active consents.
#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a policy against current consents.
    #[must_use]
    pub fn evaluate(
        &self,
        policy: &ConsentPolicy,
        consents: &[ActiveConsent],
        action: &ActionRequest,
        now: &Timestamp,
    ) -> ConsentDecision {
        let applicable: Vec<&ConsentRequirement> = policy
            .required_consents
            .iter()
            .filter(|r| r.action_type == action.action_type)
            .collect();

        if applicable.is_empty() {
            return if policy.deny_by_default {
                ConsentDecision::Denied {
                    reason: format!(
                        "no policy covers action '{}' and deny_by_default is true",
                        action.action_type
                    ),
                }
            } else {
                ConsentDecision::Granted { expires: None }
            };
        }

        let mut earliest_expiry: Option<Timestamp> = None;

        for req in &applicable {
            let satisfied = consents.iter().any(|c| {
                c.action_type == req.action_type
                    && c.role == req.required_role
                    && c.clearance_level >= req.min_clearance_level
                    && bailment::is_active(&c.bailment, now)
            });

            if !satisfied {
                // Check for escalation via delegation bailment
                let esc = consents.iter().find(|c| {
                    c.action_type == req.action_type
                        && c.bailment.bailment_type == BailmentType::Delegation
                        && bailment::is_active(&c.bailment, now)
                });
                if let Some(e) = esc {
                    return ConsentDecision::Escalated {
                        to: e.bailment.bailor_did.clone(),
                    };
                }
                return ConsentDecision::Denied {
                    reason: format!(
                        "requirement not met: action='{}', role='{}', clearance>={}",
                        req.action_type, req.required_role, req.min_clearance_level
                    ),
                };
            }

            // Track earliest expiry
            for c in consents.iter() {
                if c.action_type == req.action_type
                    && c.role == req.required_role
                    && c.clearance_level >= req.min_clearance_level
                    && bailment::is_active(&c.bailment, now)
                {
                    if let Some(exp) = c.bailment.expires {
                        earliest_expiry = Some(match earliest_expiry {
                            Some(cur) if exp < cur => exp,
                            Some(cur) => cur,
                            None => exp,
                        });
                    }
                }
            }
        }

        ConsentDecision::Granted {
            expires: earliest_expiry,
        }
    }
}

#[cfg(test)]
mod tests {
    use exo_core::Signature;

    use super::*;
    use crate::bailment;

    fn alice() -> Did {
        Did::new("did:exo:alice").unwrap()
    }
    fn bob() -> Did {
        Did::new("did:exo:bob").unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn now() -> Timestamp {
        ts(5000)
    }

    fn make_bailment(
        bailor: &Did,
        bailee: &Did,
        btype: BailmentType,
        exp: Option<Timestamp>,
    ) -> Bailment {
        let mut b = bailment::propose(bailor, bailee, b"terms", btype);
        // Produce a valid bailee signature for the GAP-012-verified accept().
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let payload = bailment::signing_payload(&b).expect("canonical payload");
        let sig = exo_core::crypto::sign(&payload, &sk);
        bailment::accept(&mut b, &pk, &sig).expect("test bailment accepts");
        b.expires = exp;
        b
    }

    fn consent(grantor: &Did, action: &str, role: &str, cl: u32, b: Bailment) -> ActiveConsent {
        ActiveConsent {
            grantor: grantor.clone(),
            action_type: action.into(),
            role: role.into(),
            clearance_level: cl,
            bailment: b,
        }
    }

    fn read_policy() -> ConsentPolicy {
        ConsentPolicy {
            id: "pol-1".into(),
            name: "read-policy".into(),
            deny_by_default: true,
            required_consents: vec![ConsentRequirement {
                action_type: "read".into(),
                required_role: "data-owner".into(),
                min_clearance_level: 1,
            }],
        }
    }

    #[test]
    fn grant_when_satisfied() {
        let e = PolicyEngine::new();
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let c = vec![consent(&alice(), "read", "data-owner", 1, b)];
        let d = e.evaluate(
            &read_policy(),
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert_eq!(d, ConsentDecision::Granted { expires: None });
    }

    #[test]
    fn grant_with_expiry() {
        let e = PolicyEngine::new();
        let exp = ts(10000);
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(exp));
        let c = vec![consent(&alice(), "read", "data-owner", 1, b)];
        let d = e.evaluate(
            &read_policy(),
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert_eq!(d, ConsentDecision::Granted { expires: Some(exp) });
    }

    #[test]
    fn deny_no_consent() {
        let e = PolicyEngine::new();
        let d = e.evaluate(
            &read_policy(),
            &[],
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Denied { .. }));
    }

    #[test]
    fn deny_clearance_too_low() {
        let e = PolicyEngine::new();
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let c = vec![consent(&alice(), "read", "data-owner", 0, b)];
        let d = e.evaluate(
            &read_policy(),
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Denied { .. }));
    }

    #[test]
    fn deny_wrong_role() {
        let e = PolicyEngine::new();
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let c = vec![consent(&alice(), "read", "viewer", 5, b)];
        let d = e.evaluate(
            &read_policy(),
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Denied { .. }));
    }

    #[test]
    fn deny_expired_bailment() {
        let e = PolicyEngine::new();
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(ts(1000)));
        let c = vec![consent(&alice(), "read", "data-owner", 1, b)];
        let d = e.evaluate(
            &read_policy(),
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Denied { .. }));
    }

    #[test]
    fn escalate_via_delegation() {
        let e = PolicyEngine::new();
        let b = make_bailment(&alice(), &bob(), BailmentType::Delegation, None);
        let c = vec![consent(&alice(), "read", "viewer", 0, b)];
        let d = e.evaluate(
            &read_policy(),
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Escalated { .. }));
        if let ConsentDecision::Escalated { to } = d {
            assert_eq!(to, alice());
        }
    }

    #[test]
    fn no_escalation_when_delegation_expired() {
        let e = PolicyEngine::new();
        let b = make_bailment(&alice(), &bob(), BailmentType::Delegation, Some(ts(1000)));
        let c = vec![consent(&alice(), "read", "viewer", 0, b)];
        let d = e.evaluate(
            &read_policy(),
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Denied { .. }));
    }

    #[test]
    fn grant_no_requirements_permissive() {
        let e = PolicyEngine::new();
        let p = ConsentPolicy {
            id: "p".into(),
            name: "p".into(),
            required_consents: vec![],
            deny_by_default: false,
        };
        let d = e.evaluate(
            &p,
            &[],
            &ActionRequest {
                actor: bob(),
                action_type: "x".into(),
            },
            &now(),
        );
        assert_eq!(d, ConsentDecision::Granted { expires: None });
    }

    #[test]
    fn deny_no_requirements_strict() {
        let e = PolicyEngine::new();
        let p = ConsentPolicy {
            id: "p".into(),
            name: "p".into(),
            required_consents: vec![],
            deny_by_default: true,
        };
        let d = e.evaluate(
            &p,
            &[],
            &ActionRequest {
                actor: bob(),
                action_type: "x".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Denied { .. }));
    }

    #[test]
    fn deny_unmatched_action() {
        let e = PolicyEngine::new();
        let d = e.evaluate(
            &read_policy(),
            &[],
            &ActionRequest {
                actor: bob(),
                action_type: "write".into(),
            },
            &now(),
        );
        assert!(matches!(d, ConsentDecision::Denied { .. }));
    }

    #[test]
    fn earliest_expiry_wins() {
        let e = PolicyEngine::new();
        let p = ConsentPolicy {
            id: "m".into(),
            name: "m".into(),
            deny_by_default: true,
            required_consents: vec![
                ConsentRequirement {
                    action_type: "read".into(),
                    required_role: "owner".into(),
                    min_clearance_level: 1,
                },
                ConsentRequirement {
                    action_type: "read".into(),
                    required_role: "auditor".into(),
                    min_clearance_level: 1,
                },
            ],
        };
        let b1 = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(ts(8000)));
        let b2 = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(ts(12000)));
        let c = vec![
            consent(&alice(), "read", "owner", 2, b1),
            consent(&alice(), "read", "auditor", 1, b2),
        ];
        let d = e.evaluate(
            &p,
            &c,
            &ActionRequest {
                actor: bob(),
                action_type: "read".into(),
            },
            &now(),
        );
        assert_eq!(
            d,
            ConsentDecision::Granted {
                expires: Some(ts(8000))
            }
        );
    }

    #[test]
    fn active_consent_fields() {
        let b = make_bailment(&alice(), &bob(), BailmentType::Processing, None);
        let c = consent(&alice(), "process", "processor", 2, b);
        assert_eq!(c.grantor, alice());
        assert_eq!(c.action_type, "process");
        assert_eq!(c.clearance_level, 2);
    }
}

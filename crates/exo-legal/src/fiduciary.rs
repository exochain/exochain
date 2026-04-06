//! Fiduciary duty tracking.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{LegalError, Result};

/// Classification of fiduciary obligations owed by a fiduciary to a principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DutyType {
    Care,
    Loyalty,
    GoodFaith,
    Disclosure,
    Confidentiality,
}

/// A fiduciary duty binding a fiduciary to act in a principal's interest within a defined scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiduciaryDuty {
    pub principal_did: Did,
    pub fiduciary_did: Did,
    pub duty_type: DutyType,
    pub scope: String,
    pub created: Timestamp,
}

/// An auditable record of an action taken by an actor, optionally on behalf of a beneficiary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub actor: Did,
    pub action: String,
    pub timestamp: Timestamp,
    pub beneficiary: Option<Did>,
}

/// Outcome of a fiduciary duty compliance check -- either compliant or listing violations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceResult {
    Compliant,
    Violation { reasons: Vec<String> },
}

/// Evaluates a set of audit entries against a fiduciary duty and returns any violations found.
#[must_use]
pub fn check_duty_compliance(duty: &FiduciaryDuty, actions: &[AuditEntry]) -> ComplianceResult {
    let mut reasons = Vec::new();
    match duty.duty_type {
        DutyType::Care => {
            if actions.is_empty() {
                reasons.push("no actions — duty of care requires diligence".into());
            }
        }
        DutyType::Loyalty => {
            for e in actions {
                if let Some(ref b) = e.beneficiary {
                    if b != &duty.principal_did && e.actor == duty.fiduciary_did {
                        reasons.push(format!("'{}' benefits {} not principal", e.action, b));
                    }
                }
            }
        }
        DutyType::GoodFaith => {
            for e in actions {
                if e.actor != duty.fiduciary_did {
                    reasons.push(format!("'{}' by {} not fiduciary", e.action, e.actor));
                }
            }
        }
        DutyType::Disclosure => {
            if !actions.iter().any(|e| e.action.contains("disclose")) {
                reasons.push("no disclosure found".into());
            }
        }
        DutyType::Confidentiality => {
            for e in actions {
                if e.action.contains("share") || e.action.contains("publish") {
                    reasons.push(format!("'{}' violates confidentiality", e.action));
                }
            }
        }
    }
    if reasons.is_empty() {
        ComplianceResult::Compliant
    } else {
        ComplianceResult::Violation { reasons }
    }
}

/// Establishes a fiduciary duty between distinct principal and fiduciary identities.
pub fn create_duty(
    principal: &Did,
    fiduciary: &Did,
    duty_type: DutyType,
    scope: &str,
) -> Result<FiduciaryDuty> {
    if principal == fiduciary {
        return Err(LegalError::FiduciaryViolation {
            reason: "principal and fiduciary cannot be same".into(),
        });
    }
    Ok(FiduciaryDuty {
        principal_did: principal.clone(),
        fiduciary_did: fiduciary.clone(),
        duty_type,
        scope: scope.into(),
        created: Timestamp::ZERO,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn entry(actor: &str, action: &str, ben: Option<&str>) -> AuditEntry {
        AuditEntry {
            actor: did(actor),
            action: action.into(),
            timestamp: Timestamp::ZERO,
            beneficiary: ben.map(did),
        }
    }
    #[test]
    fn care_ok() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Care, "a").unwrap();
        assert_eq!(
            check_duty_compliance(&d, &[entry("f", "review", None)]),
            ComplianceResult::Compliant
        );
    }
    #[test]
    fn care_fail() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Care, "a").unwrap();
        assert!(matches!(
            check_duty_compliance(&d, &[]),
            ComplianceResult::Violation { .. }
        ));
    }
    #[test]
    fn loyalty_ok() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Loyalty, "a").unwrap();
        assert_eq!(
            check_duty_compliance(&d, &[entry("f", "act", Some("p"))]),
            ComplianceResult::Compliant
        );
    }
    #[test]
    fn loyalty_fail() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Loyalty, "a").unwrap();
        assert!(matches!(
            check_duty_compliance(&d, &[entry("f", "act", Some("x"))]),
            ComplianceResult::Violation { .. }
        ));
    }
    #[test]
    fn good_faith_ok() {
        let d = create_duty(&did("p"), &did("f"), DutyType::GoodFaith, "a").unwrap();
        assert_eq!(
            check_duty_compliance(&d, &[entry("f", "act", None)]),
            ComplianceResult::Compliant
        );
    }
    #[test]
    fn good_faith_fail() {
        let d = create_duty(&did("p"), &did("f"), DutyType::GoodFaith, "a").unwrap();
        assert!(matches!(
            check_duty_compliance(&d, &[entry("x", "act", None)]),
            ComplianceResult::Violation { .. }
        ));
    }
    #[test]
    fn disclosure_ok() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Disclosure, "a").unwrap();
        assert_eq!(
            check_duty_compliance(&d, &[entry("f", "disclose conflict", None)]),
            ComplianceResult::Compliant
        );
    }
    #[test]
    fn disclosure_fail() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Disclosure, "a").unwrap();
        assert!(matches!(
            check_duty_compliance(&d, &[entry("f", "acted", None)]),
            ComplianceResult::Violation { .. }
        ));
    }
    #[test]
    fn confidentiality_ok() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Confidentiality, "a").unwrap();
        assert_eq!(
            check_duty_compliance(&d, &[entry("f", "reviewed", None)]),
            ComplianceResult::Compliant
        );
    }
    #[test]
    fn confidentiality_fail_share() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Confidentiality, "a").unwrap();
        assert!(matches!(
            check_duty_compliance(&d, &[entry("f", "share x", None)]),
            ComplianceResult::Violation { .. }
        ));
    }
    #[test]
    fn confidentiality_fail_publish() {
        let d = create_duty(&did("p"), &did("f"), DutyType::Confidentiality, "a").unwrap();
        assert!(matches!(
            check_duty_compliance(&d, &[entry("f", "publish x", None)]),
            ComplianceResult::Violation { .. }
        ));
    }
    #[test]
    fn same_entity_fails() {
        assert!(create_duty(&did("s"), &did("s"), DutyType::Care, "a").is_err());
    }
    #[test]
    fn duty_type_serde() {
        for dt in [
            DutyType::Care,
            DutyType::Loyalty,
            DutyType::GoodFaith,
            DutyType::Disclosure,
            DutyType::Confidentiality,
        ] {
            let j = serde_json::to_string(&dt).unwrap();
            let r: DutyType = serde_json::from_str(&j).unwrap();
            assert_eq!(r, dt);
        }
    }
    #[test]
    fn compliance_serde() {
        let c = ComplianceResult::Compliant;
        let j = serde_json::to_string(&c).unwrap();
        let r: ComplianceResult = serde_json::from_str(&j).unwrap();
        assert_eq!(r, c);
    }
}

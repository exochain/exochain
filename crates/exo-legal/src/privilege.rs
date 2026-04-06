//! Legal privilege assertions.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Category of legal privilege that may shield evidence from disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeType {
    AttorneyClient,
    WorkProduct,
    Deliberative,
    TradeSecret,
}

/// A recorded claim that a piece of evidence is protected by legal privilege.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeAssertion {
    pub evidence_id: Uuid,
    pub privilege_type: PrivilegeType,
    pub asserter: Did,
    pub basis: String,
    pub timestamp: Timestamp,
}

/// Resolution status of a privilege challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    Pending,
    Upheld,
    Overruled,
}

/// A formal challenge disputing a privilege assertion on evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeChallenge {
    pub assertion_evidence_id: Uuid,
    pub challenger: Did,
    pub grounds: String,
    pub status: ChallengeStatus,
    pub timestamp: Timestamp,
}

/// Creates a privilege assertion linking an evidence item to a privilege type and legal basis.
#[must_use]
pub fn assert_privilege(
    evidence_id: &Uuid,
    privilege_type: PrivilegeType,
    asserter: &Did,
    basis: &str,
) -> PrivilegeAssertion {
    PrivilegeAssertion {
        evidence_id: *evidence_id,
        privilege_type,
        asserter: asserter.clone(),
        basis: basis.to_string(),
        timestamp: Timestamp::ZERO,
    }
}

/// Files a challenge against an existing privilege assertion with stated grounds.
#[must_use]
pub fn challenge_privilege(
    assertion: &PrivilegeAssertion,
    challenger: &Did,
    grounds: &str,
) -> PrivilegeChallenge {
    PrivilegeChallenge {
        assertion_evidence_id: assertion.evidence_id,
        challenger: challenger.clone(),
        grounds: grounds.to_string(),
        status: ChallengeStatus::Pending,
        timestamp: Timestamp::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    #[test]
    fn assert_all_types() {
        for pt in [
            PrivilegeType::AttorneyClient,
            PrivilegeType::WorkProduct,
            PrivilegeType::Deliberative,
            PrivilegeType::TradeSecret,
        ] {
            let a = assert_privilege(&Uuid::new_v4(), pt.clone(), &did("c"), "basis");
            assert_eq!(a.privilege_type, pt);
        }
    }
    #[test]
    fn challenge_pending() {
        let a = assert_privilege(
            &Uuid::new_v4(),
            PrivilegeType::AttorneyClient,
            &did("c"),
            "advice",
        );
        let ch = challenge_privilege(&a, &did("o"), "crime-fraud");
        assert_eq!(ch.status, ChallengeStatus::Pending);
        assert!(ch.grounds.contains("crime-fraud"));
    }
    #[test]
    fn privilege_type_serde() {
        for pt in [
            PrivilegeType::AttorneyClient,
            PrivilegeType::WorkProduct,
            PrivilegeType::Deliberative,
            PrivilegeType::TradeSecret,
        ] {
            let j = serde_json::to_string(&pt).unwrap();
            let r: PrivilegeType = serde_json::from_str(&j).unwrap();
            assert_eq!(r, pt);
        }
    }
    #[test]
    fn challenge_status_serde() {
        for s in [
            ChallengeStatus::Pending,
            ChallengeStatus::Upheld,
            ChallengeStatus::Overruled,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let r: ChallengeStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(r, s);
        }
    }
    #[test]
    fn assertion_serde() {
        let a = assert_privilege(&Uuid::nil(), PrivilegeType::WorkProduct, &did("a"), "b");
        let j = serde_json::to_string(&a).unwrap();
        let r: PrivilegeAssertion = serde_json::from_str(&j).unwrap();
        assert_eq!(r.evidence_id, Uuid::nil());
    }
}

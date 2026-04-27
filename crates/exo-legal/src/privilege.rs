//! Legal privilege assertions.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{LegalError, Result};

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
pub fn assert_privilege(
    evidence_id: &Uuid,
    privilege_type: PrivilegeType,
    asserter: &Did,
    basis: &str,
    timestamp: Timestamp,
) -> Result<PrivilegeAssertion> {
    if evidence_id.is_nil() {
        return Err(LegalError::PrivilegeInvalid {
            reason: "privilege evidence ID must be caller-supplied and non-nil".into(),
        });
    }
    if basis.trim().is_empty() {
        return Err(LegalError::PrivilegeInvalid {
            reason: "privilege basis must not be empty".into(),
        });
    }
    if timestamp == Timestamp::ZERO {
        return Err(LegalError::PrivilegeInvalid {
            reason: "privilege assertion timestamp must not be Timestamp::ZERO".into(),
        });
    }
    Ok(PrivilegeAssertion {
        evidence_id: *evidence_id,
        privilege_type,
        asserter: asserter.clone(),
        basis: basis.to_string(),
        timestamp,
    })
}

/// Files a challenge against an existing privilege assertion with stated grounds.
pub fn challenge_privilege(
    assertion: &PrivilegeAssertion,
    challenger: &Did,
    grounds: &str,
    timestamp: Timestamp,
) -> Result<PrivilegeChallenge> {
    if grounds.trim().is_empty() {
        return Err(LegalError::PrivilegeInvalid {
            reason: "privilege challenge grounds must not be empty".into(),
        });
    }
    if timestamp == Timestamp::ZERO {
        return Err(LegalError::PrivilegeInvalid {
            reason: "privilege challenge timestamp must not be Timestamp::ZERO".into(),
        });
    }
    Ok(PrivilegeChallenge {
        assertion_evidence_id: assertion.evidence_id,
        challenger: challenger.clone(),
        grounds: grounds.to_string(),
        status: ChallengeStatus::Pending,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    #[test]
    fn assertion_and_challenge_use_caller_supplied_timestamps() {
        let assertion = assert_privilege(
            &id(0x400),
            PrivilegeType::AttorneyClient,
            &did("c"),
            "basis",
            ts(1000),
        )
        .unwrap();
        assert_eq!(assertion.timestamp, ts(1000));

        let challenge =
            challenge_privilege(&assertion, &did("o"), "crime-fraud", ts(2000)).unwrap();
        assert_eq!(challenge.timestamp, ts(2000));
    }

    #[test]
    fn assertion_and_challenge_reject_placeholder_metadata() {
        assert!(
            assert_privilege(
                &Uuid::nil(),
                PrivilegeType::AttorneyClient,
                &did("c"),
                "basis",
                ts(1000),
            )
            .is_err()
        );
        assert!(
            assert_privilege(
                &id(0x401),
                PrivilegeType::AttorneyClient,
                &did("c"),
                "basis",
                Timestamp::ZERO,
            )
            .is_err()
        );
        let assertion = assert_privilege(
            &id(0x402),
            PrivilegeType::AttorneyClient,
            &did("c"),
            "basis",
            ts(1000),
        )
        .unwrap();
        assert!(challenge_privilege(&assertion, &did("o"), " ", ts(2000)).is_err());
        assert!(
            challenge_privilege(&assertion, &did("o"), "crime-fraud", Timestamp::ZERO).is_err()
        );
    }

    #[test]
    fn assert_all_types() {
        for pt in [
            PrivilegeType::AttorneyClient,
            PrivilegeType::WorkProduct,
            PrivilegeType::Deliberative,
            PrivilegeType::TradeSecret,
        ] {
            let a = assert_privilege(&id(0x403), pt.clone(), &did("c"), "basis", ts(1000)).unwrap();
            assert_eq!(a.privilege_type, pt);
        }
    }
    #[test]
    fn challenge_pending() {
        let a = assert_privilege(
            &id(0x404),
            PrivilegeType::AttorneyClient,
            &did("c"),
            "advice",
            ts(1000),
        )
        .unwrap();
        let ch = challenge_privilege(&a, &did("o"), "crime-fraud", ts(2000)).unwrap();
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
        let a = assert_privilege(
            &id(0x405),
            PrivilegeType::WorkProduct,
            &did("a"),
            "b",
            ts(1000),
        )
        .unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let r: PrivilegeAssertion = serde_json::from_str(&j).unwrap();
        assert_eq!(r.evidence_id, id(0x405));
    }
}

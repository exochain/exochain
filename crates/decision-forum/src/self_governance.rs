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

//! Recursive self-governance (GOV-013).
//!
//! Platform evolution as Decision Objects. Governance simulator for
//! stress-testing proposed changes. Self-modification compliance tracking (M12).

use exo_core::types::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ForumError, Result};

/// A proposed governance change tracked as a self-governance item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub change_type: GovernanceChangeType,
    pub decision_id: Option<Uuid>,
    pub simulation_result: Option<SimulationResult>,
    pub proposed_at: Timestamp,
}

/// Types of governance changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GovernanceChangeType {
    ConstitutionalAmendment,
    QuorumPolicyChange,
    AuthorityMatrixUpdate,
    HumanGatePolicyChange,
    EmergencyPolicyChange,
    MetricsThresholdChange,
}

/// Result of a governance simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub passed: bool,
    pub issues: Vec<String>,
    pub simulated_at: Timestamp,
    pub input_hash: Hash256,
}

/// The governance simulator: stress-test proposed changes before adoption.
pub struct GovernanceSimulator;

impl GovernanceSimulator {
    /// Simulate a governance change and return the result.
    /// This validates that the change does not violate any structural invariants.
    pub fn simulate(
        proposal: &GovernanceProposal,
        _current_constitution_hash: Hash256,
        timestamp: Timestamp,
    ) -> SimulationResult {
        let mut issues = Vec::new();

        // Constitutional amendments must be class Constitutional
        if proposal.change_type == GovernanceChangeType::ConstitutionalAmendment
            && proposal.decision_id.is_none()
        {
            issues.push("constitutional amendment requires backing decision".into());
        }

        // All changes need a title
        if proposal.title.is_empty() {
            issues.push("proposal title is empty".into());
        }

        let input_hash = Hash256::digest(proposal.title.as_bytes());

        SimulationResult {
            passed: issues.is_empty(),
            issues,
            simulated_at: timestamp,
            input_hash,
        }
    }
}

/// Track self-modification compliance (M12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTracker {
    pub total_modifications: u64,
    pub compliant_modifications: u64,
}

impl ComplianceTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_modifications: 0,
            compliant_modifications: 0,
        }
    }

    /// Record a modification.
    pub fn record(&mut self, compliant: bool) {
        self.total_modifications = self.total_modifications.saturating_add(1);
        if compliant {
            self.compliant_modifications = self.compliant_modifications.saturating_add(1);
        }
    }

    /// Compliance rate as a percentage (0-100).
    #[must_use]
    pub fn compliance_rate_pct(&self) -> u64 {
        if self.total_modifications == 0 {
            return 100;
        }
        let pct =
            (u128::from(self.compliant_modifications) * 100) / u128::from(self.total_modifications);
        u64::try_from(pct.min(100)).unwrap_or(100)
    }
}

impl Default for ComplianceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-supplied metadata for creating a governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposalInput {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub change_type: GovernanceChangeType,
    pub proposed_at: Timestamp,
}

/// Create a governance proposal.
pub fn create_proposal(input: GovernanceProposalInput) -> Result<GovernanceProposal> {
    if input.id.is_nil() {
        return Err(ForumError::InvalidProvenance {
            reason: "governance proposal id must not be nil".into(),
        });
    }
    if input.proposed_at == Timestamp::ZERO {
        return Err(ForumError::InvalidProvenance {
            reason: "governance proposal proposed_at must be non-zero HLC".into(),
        });
    }
    if input.title.trim().is_empty() {
        return Err(ForumError::InvalidProvenance {
            reason: "governance proposal title must be non-empty".into(),
        });
    }
    if input.description.trim().is_empty() {
        return Err(ForumError::InvalidProvenance {
            reason: "governance proposal description must be non-empty".into(),
        });
    }

    Ok(GovernanceProposal {
        id: input.id,
        title: input.title,
        description: input.description,
        change_type: input.change_type,
        decision_id: None,
        simulation_result: None,
        proposed_at: input.proposed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> Timestamp {
        Timestamp::new(1_000_000, 0)
    }

    fn proposal_input(
        id: Uuid,
        title: &str,
        change_type: GovernanceChangeType,
    ) -> GovernanceProposalInput {
        GovernanceProposalInput {
            id,
            title: title.into(),
            description: "desc".into(),
            change_type,
            proposed_at: ts(),
        }
    }

    #[test]
    fn create_proposal_requires_caller_supplied_identity_and_hlc() {
        let proposal = create_proposal(proposal_input(
            Uuid::from_u128(70),
            "Update quorum",
            GovernanceChangeType::QuorumPolicyChange,
        ))
        .expect("valid");
        assert_eq!(proposal.id, Uuid::from_u128(70));

        let nil = create_proposal(proposal_input(
            Uuid::nil(),
            "bad",
            GovernanceChangeType::QuorumPolicyChange,
        ))
        .unwrap_err();
        assert!(matches!(nil, ForumError::InvalidProvenance { .. }));

        let zero_time = create_proposal(GovernanceProposalInput {
            proposed_at: Timestamp::ZERO,
            ..proposal_input(
                Uuid::from_u128(71),
                "bad",
                GovernanceChangeType::QuorumPolicyChange,
            )
        })
        .unwrap_err();
        assert!(matches!(zero_time, ForumError::InvalidProvenance { .. }));
    }

    #[test]
    fn create_proposal_basic() {
        let p = create_proposal(GovernanceProposalInput {
            description: "Change thresholds".into(),
            ..proposal_input(
                Uuid::from_u128(72),
                "Update quorum",
                GovernanceChangeType::QuorumPolicyChange,
            )
        })
        .expect("valid");
        assert_eq!(p.title, "Update quorum");
        assert!(p.decision_id.is_none());
        assert!(p.simulation_result.is_none());
    }

    #[test]
    fn simulate_valid_proposal() {
        let p = create_proposal(proposal_input(
            Uuid::from_u128(73),
            "Test",
            GovernanceChangeType::QuorumPolicyChange,
        ))
        .expect("valid");
        let result = GovernanceSimulator::simulate(&p, Hash256::ZERO, ts());
        assert!(result.passed);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn simulate_amendment_without_decision() {
        let p = create_proposal(proposal_input(
            Uuid::from_u128(74),
            "Amend",
            GovernanceChangeType::ConstitutionalAmendment,
        ))
        .expect("valid");
        let result = GovernanceSimulator::simulate(&p, Hash256::ZERO, ts());
        assert!(!result.passed);
        assert!(result.issues.iter().any(|i| i.contains("backing decision")));
    }

    #[test]
    fn simulate_empty_title() {
        let err = create_proposal(proposal_input(
            Uuid::from_u128(75),
            "",
            GovernanceChangeType::QuorumPolicyChange,
        ))
        .unwrap_err();
        assert!(matches!(err, ForumError::InvalidProvenance { .. }));
    }

    #[test]
    fn compliance_tracker() {
        let mut t = ComplianceTracker::new();
        assert_eq!(t.compliance_rate_pct(), 100); // No data = 100%
        t.record(true);
        t.record(true);
        t.record(false);
        assert_eq!(t.compliance_rate_pct(), 66); // 2/3
        assert_eq!(t.total_modifications, 3);
    }

    #[test]
    fn compliance_tracker_clamps_deserialized_overflow_shape() {
        let t = ComplianceTracker {
            total_modifications: 1,
            compliant_modifications: u64::MAX,
        };

        assert_eq!(t.compliance_rate_pct(), 100);
    }

    #[test]
    fn compliance_tracker_record_saturates_deserialized_counter_maxima_without_panicking() {
        let mut t = ComplianceTracker {
            total_modifications: u64::MAX,
            compliant_modifications: u64::MAX,
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            t.record(true);
        }));

        assert!(result.is_ok());
        assert_eq!(t.total_modifications, u64::MAX);
        assert_eq!(t.compliant_modifications, u64::MAX);
    }

    #[test]
    fn compliance_tracker_default() {
        let t = ComplianceTracker::default();
        assert_eq!(t.total_modifications, 0);
    }
}

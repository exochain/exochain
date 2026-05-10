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

//! Foundational economy types — actor classes, event classes, assurance
//! classes, pricing modes, zero-fee reasons, and revenue-share recipient
//! shapes. All values are integer-only; basis points are bounded.

use exo_core::Did;
use serde::{Deserialize, Serialize};

/// Smallest unit of internal account currency. Integer-only.
pub type MicroExo = u128;

/// Basis points — 1 / 10_000. Bounded `0..=10_000`.
pub type BasisPoints = u32;

/// Maximum basis points value (100.00%).
pub const MAX_BASIS_POINTS: BasisPoints = 10_000;

/// Maximum bounded multiplier expressed in basis points. Allows up to 10×.
pub const MAX_MULTIPLIER_BP: BasisPoints = 100_000;

/// Default multiplier (1.0×).
pub const NEUTRAL_MULTIPLIER_BP: BasisPoints = 10_000;

/// Default quote validity window when not overridden by the policy.
pub const DEFAULT_QUOTE_TTL_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActorClass {
    Human,
    HumanSponsoredAgent,
    AutonomousAgent,
    Holon,
    Enterprise,
    Validator,
    PublicGood,
    Unknown,
}

impl ActorClass {
    /// All variants — used by exhaustive coverage tests.
    pub const ALL: [ActorClass; 8] = [
        ActorClass::Human,
        ActorClass::HumanSponsoredAgent,
        ActorClass::AutonomousAgent,
        ActorClass::Holon,
        ActorClass::Enterprise,
        ActorClass::Validator,
        ActorClass::PublicGood,
        ActorClass::Unknown,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventClass {
    IdentityResolution,
    AgentPassportLookup,
    AvcIssue,
    AvcValidate,
    AvcDelegate,
    AvcRevoke,
    ConsentGrant,
    ConsentRevoke,
    TrustReceiptCreate,
    CustodyAnchor,
    ComputeInvocation,
    ValueSettlement,
    GovernanceVote,
    Escalation,
    LegalEvidenceExport,
    HolonCommercialAction,
    AgentToAgentHandshake,
}

impl EventClass {
    pub const ALL: [EventClass; 17] = [
        EventClass::IdentityResolution,
        EventClass::AgentPassportLookup,
        EventClass::AvcIssue,
        EventClass::AvcValidate,
        EventClass::AvcDelegate,
        EventClass::AvcRevoke,
        EventClass::ConsentGrant,
        EventClass::ConsentRevoke,
        EventClass::TrustReceiptCreate,
        EventClass::CustodyAnchor,
        EventClass::ComputeInvocation,
        EventClass::ValueSettlement,
        EventClass::GovernanceVote,
        EventClass::Escalation,
        EventClass::LegalEvidenceExport,
        EventClass::HolonCommercialAction,
        EventClass::AgentToAgentHandshake,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssuranceClass {
    Free,
    Standard,
    Anchored,
    LegalGrade,
    Regulated,
    Critical,
}

impl AssuranceClass {
    pub const ALL: [AssuranceClass; 6] = [
        AssuranceClass::Free,
        AssuranceClass::Standard,
        AssuranceClass::Anchored,
        AssuranceClass::LegalGrade,
        AssuranceClass::Regulated,
        AssuranceClass::Critical,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PricingMode {
    Zero,
    CostRecovery,
    UsageMetered,
    ValueShare,
    ComputeMarket,
    Hybrid,
}

impl PricingMode {
    pub const ALL: [PricingMode; 6] = [
        PricingMode::Zero,
        PricingMode::CostRecovery,
        PricingMode::UsageMetered,
        PricingMode::ValueShare,
        PricingMode::ComputeMarket,
        PricingMode::Hybrid,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroFeeReason {
    /// The default human-trust subsidy.
    HumanBaseline,
    /// Public-good operations (governance access, audit reads).
    PublicGood,
    /// Standard free tier under abuse thresholds.
    FreeTier,
    /// Subsidy applied by policy or treasury.
    Subsidized,
    /// Policy-configured zero — the default in this launch phase.
    PolicyConfiguredZero,
    /// Internal testing path.
    InternalTest,
    /// Governance-mandated waiver for a specific event.
    GovernanceWaiver,
    /// Developer-preview phase: nonzero pricing not yet activated.
    DeveloperPreview,
    /// Bootstrap phase for a new human onboarding the network.
    HumanTrustBootstrap,
    /// Subsidy explicitly paid by the launch program.
    LaunchSubsidy,
    /// Identity lookups are free.
    IdentityLookup,
    /// AVC validation must never be paywalled.
    AgentValidation,
    /// Consent revocation must never be paywalled.
    ConsentRevocation,
}

impl ZeroFeeReason {
    pub const ALL: [ZeroFeeReason; 13] = [
        ZeroFeeReason::HumanBaseline,
        ZeroFeeReason::PublicGood,
        ZeroFeeReason::FreeTier,
        ZeroFeeReason::Subsidized,
        ZeroFeeReason::PolicyConfiguredZero,
        ZeroFeeReason::InternalTest,
        ZeroFeeReason::GovernanceWaiver,
        ZeroFeeReason::DeveloperPreview,
        ZeroFeeReason::HumanTrustBootstrap,
        ZeroFeeReason::LaunchSubsidy,
        ZeroFeeReason::IdentityLookup,
        ZeroFeeReason::AgentValidation,
        ZeroFeeReason::ConsentRevocation,
    ];
}

/// Recipient role for a single revenue-share line.
///
/// Holding a `Did` allows precise routing once the launch policy is
/// activated; in the zero phase, every recipient receives `0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevenueRecipient {
    ProtocolTreasury,
    NodeOperator { did: Did },
    ValidatorSet,
    CustodyVerifier { did: Did },
    AppLayer { app_id: String },
    CredentialIssuer { did: Did },
    ComputeProvider { did: Did },
    DataSubject { did: Did },
    InsuranceReserve,
    PolicyDomain { id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_class_all_includes_every_variant() {
        assert_eq!(ActorClass::ALL.len(), 8);
    }

    #[test]
    fn event_class_all_includes_every_variant() {
        assert_eq!(EventClass::ALL.len(), 17);
    }

    #[test]
    fn assurance_class_all_includes_every_variant() {
        assert_eq!(AssuranceClass::ALL.len(), 6);
    }

    #[test]
    fn pricing_mode_all_includes_every_variant() {
        assert_eq!(PricingMode::ALL.len(), 6);
    }

    #[test]
    fn zero_fee_reason_all_includes_every_variant() {
        assert_eq!(ZeroFeeReason::ALL.len(), 13);
    }

    #[test]
    fn neutral_multiplier_is_ten_thousand() {
        assert_eq!(NEUTRAL_MULTIPLIER_BP, 10_000);
    }

    #[test]
    fn revenue_recipient_round_trips() {
        let did = Did::new("did:exo:treasury").unwrap();
        let cases = vec![
            RevenueRecipient::ProtocolTreasury,
            RevenueRecipient::NodeOperator { did: did.clone() },
            RevenueRecipient::ValidatorSet,
            RevenueRecipient::CustodyVerifier { did: did.clone() },
            RevenueRecipient::AppLayer {
                app_id: "alpha".into(),
            },
            RevenueRecipient::CredentialIssuer { did: did.clone() },
            RevenueRecipient::ComputeProvider { did: did.clone() },
            RevenueRecipient::DataSubject { did },
            RevenueRecipient::InsuranceReserve,
            RevenueRecipient::PolicyDomain {
                id: "us-fin".into(),
            },
        ];
        for r in cases {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&r, &mut buf).unwrap();
            let decoded: RevenueRecipient = ciborium::de::from_reader(buf.as_slice()).unwrap();
            assert_eq!(decoded, r);
        }
    }

    #[test]
    fn actor_class_ord_consistent() {
        let mut v = ActorClass::ALL.to_vec();
        v.sort();
        assert_eq!(v.first().unwrap(), &ActorClass::Human);
    }
}

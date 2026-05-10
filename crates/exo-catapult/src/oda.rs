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

//! FM 3-05 Operational Detachment Alpha — team structure adapted for business.
//!
//! Each newco is staffed by a 12-agent ODA following Army Special Operations
//! doctrine. Two founding agents (HR and Deep Researcher) recruit the
//! remaining ten through a governed assessment-and-selection pipeline.

use serde::{Deserialize, Serialize};

/// Military Occupational Specialty codes adapted for Catapult business operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MosCode {
    /// 18A — Detachment Commander.
    Alpha18A,
    /// 180A — Assistant Detachment Commander.
    Alpha180A,
    /// 18Z — Operations Sergeant.
    Zulu18Z,
    /// 18F — Intelligence Sergeant.
    Fox18F,
    /// 18B — Weapons Sergeant (Growth).
    Bravo18B,
    /// 18E — Communications Sergeant.
    Echo18E,
    /// 18D — Medical Sergeant (HR/People).
    Delta18D,
    /// 18C — Engineering Sergeant.
    Charlie18C,
}

/// Named slot in the ODA roster, mapping FM 3-05 positions to business roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OdaSlot {
    /// 18A — Mission authority, strategic decisions.
    VentureCommander,
    /// 180A — Operational continuity, backup command.
    OperationsDeputy,
    /// 18Z — Workflow orchestration, training.
    ProcessArchitect,
    /// 18F — Market/competitive intelligence. **Founding agent.**
    DeepResearcher,
    /// 18B — Market attack, revenue generation (slot 1).
    GrowthEngineer1,
    /// 18B — Market attack, revenue generation (slot 2).
    GrowthEngineer2,
    /// 18E — Brand, stakeholder, PR (slot 1).
    Communications1,
    /// 18E — Brand, stakeholder, PR (slot 2).
    Communications2,
    /// 18D — Team health, talent, assessment. **Founding agent.**
    HrPeopleOps1,
    /// 18D — Team health, culture (slot 2).
    HrPeopleOps2,
    /// 18C — Product/service building (slot 1).
    PlatformEngineer1,
    /// 18C — Product/service building (slot 2).
    PlatformEngineer2,
}

impl OdaSlot {
    /// All 12 ODA slots in hierarchy order.
    pub const ALL: [OdaSlot; 12] = [
        Self::VentureCommander,
        Self::OperationsDeputy,
        Self::ProcessArchitect,
        Self::DeepResearcher,
        Self::GrowthEngineer1,
        Self::GrowthEngineer2,
        Self::Communications1,
        Self::Communications2,
        Self::HrPeopleOps1,
        Self::HrPeopleOps2,
        Self::PlatformEngineer1,
        Self::PlatformEngineer2,
    ];

    /// The two founding agents that bootstrap every newco.
    pub const FOUNDERS: [OdaSlot; 2] = [Self::HrPeopleOps1, Self::DeepResearcher];

    /// Return the FM 3-05 MOS code for this slot.
    #[must_use]
    pub const fn mos_code(&self) -> MosCode {
        match self {
            Self::VentureCommander => MosCode::Alpha18A,
            Self::OperationsDeputy => MosCode::Alpha180A,
            Self::ProcessArchitect => MosCode::Zulu18Z,
            Self::DeepResearcher => MosCode::Fox18F,
            Self::GrowthEngineer1 | Self::GrowthEngineer2 => MosCode::Bravo18B,
            Self::Communications1 | Self::Communications2 => MosCode::Echo18E,
            Self::HrPeopleOps1 | Self::HrPeopleOps2 => MosCode::Delta18D,
            Self::PlatformEngineer1 | Self::PlatformEngineer2 => MosCode::Charlie18C,
        }
    }

    /// Whether this slot is one of the two founding agents.
    #[must_use]
    pub const fn is_founding(&self) -> bool {
        matches!(self, Self::HrPeopleOps1 | Self::DeepResearcher)
    }

    /// Human-readable display name for the slot.
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::VentureCommander => "Venture Commander",
            Self::OperationsDeputy => "Operations Deputy",
            Self::ProcessArchitect => "Process Architect",
            Self::DeepResearcher => "Deep Researcher",
            Self::GrowthEngineer1 => "Growth Engineer 1",
            Self::GrowthEngineer2 => "Growth Engineer 2",
            Self::Communications1 => "Communications 1",
            Self::Communications2 => "Communications 2",
            Self::HrPeopleOps1 => "HR/People Ops 1",
            Self::HrPeopleOps2 => "HR/People Ops 2",
            Self::PlatformEngineer1 => "Platform Engineer 1",
            Self::PlatformEngineer2 => "Platform Engineer 2",
        }
    }

    /// Stable lowercase label for identifiers, APIs, and error messages.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::VentureCommander => "venturecommander",
            Self::OperationsDeputy => "operationsdeputy",
            Self::ProcessArchitect => "processarchitect",
            Self::DeepResearcher => "deepresearcher",
            Self::GrowthEngineer1 => "growthengineer1",
            Self::GrowthEngineer2 => "growthengineer2",
            Self::Communications1 => "communications1",
            Self::Communications2 => "communications2",
            Self::HrPeopleOps1 => "hrpeopleops1",
            Self::HrPeopleOps2 => "hrpeopleops2",
            Self::PlatformEngineer1 => "platformengineer1",
            Self::PlatformEngineer2 => "platformengineer2",
        }
    }

    /// Authority depth in the ODA hierarchy (0 = highest authority).
    #[must_use]
    pub const fn authority_depth(&self) -> u32 {
        match self {
            Self::VentureCommander => 0,
            Self::OperationsDeputy => 1,
            Self::ProcessArchitect => 2,
            Self::DeepResearcher => 2,
            Self::GrowthEngineer1
            | Self::GrowthEngineer2
            | Self::Communications1
            | Self::Communications2
            | Self::HrPeopleOps1
            | Self::HrPeopleOps2
            | Self::PlatformEngineer1
            | Self::PlatformEngineer2 => 3,
        }
    }
}

impl std::fmt::Display for OdaSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_slots_count() {
        assert_eq!(OdaSlot::ALL.len(), 12);
    }

    #[test]
    fn founders() {
        assert_eq!(OdaSlot::FOUNDERS.len(), 2);
        for f in &OdaSlot::FOUNDERS {
            assert!(f.is_founding());
        }
        // Non-founders should not be founding
        assert!(!OdaSlot::VentureCommander.is_founding());
        assert!(!OdaSlot::PlatformEngineer1.is_founding());
    }

    #[test]
    fn mos_codes() {
        assert_eq!(OdaSlot::VentureCommander.mos_code(), MosCode::Alpha18A);
        assert_eq!(OdaSlot::DeepResearcher.mos_code(), MosCode::Fox18F);
        assert_eq!(OdaSlot::HrPeopleOps1.mos_code(), MosCode::Delta18D);
        assert_eq!(OdaSlot::HrPeopleOps2.mos_code(), MosCode::Delta18D);
        assert_eq!(OdaSlot::GrowthEngineer1.mos_code(), MosCode::Bravo18B);
        assert_eq!(OdaSlot::GrowthEngineer2.mos_code(), MosCode::Bravo18B);
    }

    #[test]
    fn authority_depth_hierarchy() {
        assert_eq!(OdaSlot::VentureCommander.authority_depth(), 0);
        assert_eq!(OdaSlot::OperationsDeputy.authority_depth(), 1);
        assert_eq!(OdaSlot::ProcessArchitect.authority_depth(), 2);
        assert_eq!(OdaSlot::PlatformEngineer1.authority_depth(), 3);
    }

    #[test]
    fn display_names() {
        for slot in &OdaSlot::ALL {
            assert!(!slot.display_name().is_empty());
        }
    }

    #[test]
    fn stable_slot_slugs() {
        assert_eq!(OdaSlot::VentureCommander.slug(), "venturecommander");
        assert_eq!(OdaSlot::HrPeopleOps1.slug(), "hrpeopleops1");
        assert_eq!(OdaSlot::PlatformEngineer2.to_string(), "platformengineer2");
    }

    #[test]
    fn slot_serde_roundtrip() {
        for slot in &OdaSlot::ALL {
            let j = serde_json::to_string(slot).unwrap();
            let rt: OdaSlot = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, slot);
        }
    }

    #[test]
    fn mos_serde_roundtrip() {
        let codes = [
            MosCode::Alpha18A,
            MosCode::Alpha180A,
            MosCode::Zulu18Z,
            MosCode::Fox18F,
            MosCode::Bravo18B,
            MosCode::Echo18E,
            MosCode::Delta18D,
            MosCode::Charlie18C,
        ];
        for code in &codes {
            let j = serde_json::to_string(code).unwrap();
            let rt: MosCode = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, code);
        }
    }
}

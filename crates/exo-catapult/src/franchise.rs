//! Franchise blueprints — immutable templates from which newcos are instantiated.

use std::collections::BTreeMap;

use exo_core::{Hash256, Timestamp, Version};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    budget::BudgetTemplate,
    error::{CatapultError, Result},
    goal::GoalTemplate,
    oda::OdaSlot,
};

/// The business model classification for a franchise.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BusinessModel {
    SaaS,
    Marketplace,
    Agency,
    MediaPublisher,
    ConsultingFirm,
    Custom { description: String },
}

/// An immutable franchise blueprint — the template from which newcos are created.
///
/// Once published, a blueprint is content-addressed and cannot be modified.
/// New versions create new blueprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FranchiseBlueprint {
    pub id: Uuid,
    pub name: String,
    pub version: Version,
    pub description: String,
    pub business_model: BusinessModel,
    /// Hash of the constitutional corpus that governs newcos from this blueprint.
    pub constitution_hash: Hash256,
    /// Which ODA slots are mandatory for this franchise type.
    pub required_slots: Vec<OdaSlot>,
    /// Default budget configuration for newcos.
    pub budget_template: BudgetTemplate,
    /// Default goal structure for newcos.
    pub goal_template: GoalTemplate,
    /// When this blueprint was created.
    pub created: Timestamp,
    /// Content-address of the serialized blueprint.
    pub content_hash: Hash256,
}

/// In-memory registry of published franchise blueprints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FranchiseRegistry {
    pub blueprints: BTreeMap<Uuid, FranchiseBlueprint>,
}

impl FranchiseRegistry {
    /// Create an empty franchise registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blueprints: BTreeMap::new(),
        }
    }

    /// Publish a new franchise blueprint.
    pub fn publish(&mut self, blueprint: FranchiseBlueprint) -> Result<Uuid> {
        let id = blueprint.id;
        if self.blueprints.contains_key(&id) {
            return Err(CatapultError::FranchiseAlreadyExists(id));
        }
        self.blueprints.insert(id, blueprint);
        Ok(id)
    }

    /// Look up a blueprint by ID.
    #[must_use]
    pub fn get(&self, id: &Uuid) -> Option<&FranchiseBlueprint> {
        self.blueprints.get(id)
    }

    /// List all published blueprints.
    #[must_use]
    pub fn list(&self) -> Vec<&FranchiseBlueprint> {
        self.blueprints.values().collect()
    }

    /// Number of published blueprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blueprints.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blueprints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{budget::BudgetTemplate, goal::GoalTemplate};

    fn test_blueprint() -> FranchiseBlueprint {
        FranchiseBlueprint {
            id: Uuid::new_v4(),
            name: "Test SaaS Franchise".into(),
            version: Version::ZERO.next(),
            description: "A test SaaS franchise blueprint".into(),
            business_model: BusinessModel::SaaS,
            constitution_hash: Hash256::ZERO,
            required_slots: OdaSlot::ALL.to_vec(),
            budget_template: BudgetTemplate::default(),
            goal_template: GoalTemplate::default(),
            created: Timestamp::ZERO,
            content_hash: Hash256::ZERO,
        }
    }

    #[test]
    fn publish_and_get() {
        let mut reg = FranchiseRegistry::new();
        let bp = test_blueprint();
        let id = bp.id;
        reg.publish(bp).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.get(&id).is_some());
    }

    #[test]
    fn duplicate_rejected() {
        let mut reg = FranchiseRegistry::new();
        let bp = test_blueprint();
        let bp2 = bp.clone();
        reg.publish(bp).unwrap();
        assert!(reg.publish(bp2).is_err());
    }

    #[test]
    fn list() {
        let mut reg = FranchiseRegistry::new();
        reg.publish(test_blueprint()).unwrap();
        reg.publish(test_blueprint()).unwrap();
        assert_eq!(reg.list().len(), 2);
    }

    #[test]
    fn empty() {
        let reg = FranchiseRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn business_model_serde() {
        let models = [
            BusinessModel::SaaS,
            BusinessModel::Marketplace,
            BusinessModel::Agency,
            BusinessModel::MediaPublisher,
            BusinessModel::ConsultingFirm,
            BusinessModel::Custom {
                description: "test".into(),
            },
        ];
        for m in &models {
            let j = serde_json::to_string(m).unwrap();
            let rt: BusinessModel = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, m);
        }
    }

    #[test]
    fn blueprint_serde_roundtrip() {
        let bp = test_blueprint();
        let j = serde_json::to_string(&bp).unwrap();
        let rt: FranchiseBlueprint = serde_json::from_str(&j).unwrap();
        assert_eq!(rt.name, bp.name);
        assert_eq!(rt.business_model, bp.business_model);
    }
}

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

/// Domain tag for franchise blueprint content hashing.
pub const FRANCHISE_BLUEPRINT_HASH_DOMAIN: &str = "exo.catapult.franchise_blueprint.v1";
const FRANCHISE_BLUEPRINT_SCHEMA_VERSION: &str = "1.0.0";

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

/// Caller-supplied deterministic metadata for a franchise blueprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FranchiseBlueprintInput {
    pub id: Uuid,
    pub name: String,
    pub version: Version,
    pub description: String,
    pub business_model: BusinessModel,
    pub constitution_hash: Hash256,
    pub required_slots: Vec<OdaSlot>,
    pub budget_template: BudgetTemplate,
    pub goal_template: GoalTemplate,
    pub created: Timestamp,
}

impl FranchiseBlueprint {
    /// Build a franchise blueprint from caller-supplied deterministic metadata.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if the blueprint contains placeholder metadata
    /// or if canonical CBOR hashing fails.
    pub fn new(input: FranchiseBlueprintInput) -> Result<Self> {
        validate_blueprint_input(&input)?;
        let content_hash = franchise_blueprint_content_hash(&input)?;
        Ok(Self {
            id: input.id,
            name: input.name,
            version: input.version,
            description: input.description,
            business_model: input.business_model,
            constitution_hash: input.constitution_hash,
            required_slots: input.required_slots,
            budget_template: input.budget_template,
            goal_template: input.goal_template,
            created: input.created,
            content_hash,
        })
    }

    /// Recompute and compare this blueprint's canonical content hash.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if the blueprint metadata is invalid or if
    /// canonical CBOR hashing fails.
    pub fn verify_content_hash(&self) -> Result<bool> {
        let expected = franchise_blueprint_content_hash(&self.input())?;
        Ok(self.content_hash == expected)
    }

    fn validate(&self) -> Result<()> {
        validate_blueprint_input(&self.input())?;
        if self.content_hash == Hash256::ZERO {
            return Err(CatapultError::InvalidFranchiseBlueprint {
                reason: "blueprint content hash must not be zero".into(),
            });
        }
        if !self.verify_content_hash()? {
            return Err(CatapultError::InvalidFranchiseBlueprint {
                reason: format!(
                    "blueprint {} content hash does not match canonical payload",
                    self.id
                ),
            });
        }
        Ok(())
    }

    fn input(&self) -> FranchiseBlueprintInput {
        FranchiseBlueprintInput {
            id: self.id,
            name: self.name.clone(),
            version: self.version,
            description: self.description.clone(),
            business_model: self.business_model.clone(),
            constitution_hash: self.constitution_hash,
            required_slots: self.required_slots.clone(),
            budget_template: self.budget_template.clone(),
            goal_template: self.goal_template.clone(),
            created: self.created,
        }
    }
}

/// Compute the canonical content hash for a franchise blueprint input.
///
/// # Errors
/// Returns [`CatapultError`] if the input is invalid or canonical CBOR hashing
/// fails.
pub fn franchise_blueprint_content_hash(input: &FranchiseBlueprintInput) -> Result<Hash256> {
    validate_blueprint_input(input)?;
    exo_core::hash::hash_structured(&FranchiseBlueprintHashPayload::from_input(input)).map_err(
        |e| CatapultError::InvalidFranchiseBlueprint {
            reason: format!("blueprint hash CBOR serialization failed: {e}"),
        },
    )
}

#[derive(Serialize)]
struct FranchiseBlueprintHashPayload<'a> {
    domain: &'static str,
    schema_version: &'static str,
    id: Uuid,
    name: &'a str,
    version: Version,
    description: &'a str,
    business_model: &'a BusinessModel,
    constitution_hash: Hash256,
    required_slots: &'a [OdaSlot],
    budget_template: &'a BudgetTemplate,
    goal_template: &'a GoalTemplate,
    created: Timestamp,
}

impl<'a> FranchiseBlueprintHashPayload<'a> {
    fn from_input(input: &'a FranchiseBlueprintInput) -> Self {
        Self {
            domain: FRANCHISE_BLUEPRINT_HASH_DOMAIN,
            schema_version: FRANCHISE_BLUEPRINT_SCHEMA_VERSION,
            id: input.id,
            name: &input.name,
            version: input.version,
            description: &input.description,
            business_model: &input.business_model,
            constitution_hash: input.constitution_hash,
            required_slots: &input.required_slots,
            budget_template: &input.budget_template,
            goal_template: &input.goal_template,
            created: input.created,
        }
    }
}

fn validate_blueprint_input(input: &FranchiseBlueprintInput) -> Result<()> {
    if input.id.is_nil() {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint id must be caller-supplied and non-nil".into(),
        });
    }
    if input.name.trim().is_empty() {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint name must not be empty".into(),
        });
    }
    if input.version == Version::ZERO {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint version must be greater than zero".into(),
        });
    }
    if input.description.trim().is_empty() {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint description must not be empty".into(),
        });
    }
    if let BusinessModel::Custom { description } = &input.business_model
        && description.trim().is_empty()
    {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "custom business-model description must not be empty".into(),
        });
    }
    if input.constitution_hash == Hash256::ZERO {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint constitution hash must not be zero".into(),
        });
    }
    if input.required_slots.is_empty() {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint required slots must not be empty".into(),
        });
    }
    let mut canonical_slots = input.required_slots.clone();
    canonical_slots.sort();
    canonical_slots.dedup();
    if canonical_slots != input.required_slots {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint required slots must be sorted and unique".into(),
        });
    }
    if input.created == Timestamp::ZERO {
        return Err(CatapultError::InvalidFranchiseBlueprint {
            reason: "blueprint created timestamp must be caller-supplied HLC".into(),
        });
    }
    Ok(())
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
        blueprint.validate()?;
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

    fn test_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn test_hash(label: &str) -> Hash256 {
        Hash256::digest(label.as_bytes())
    }

    fn test_timestamp() -> Timestamp {
        Timestamp {
            physical_ms: 1_765_000_000_000,
            logical: 7,
        }
    }

    fn test_blueprint_input() -> FranchiseBlueprintInput {
        FranchiseBlueprintInput {
            id: test_uuid(1),
            name: "Test SaaS Franchise".into(),
            version: Version::ZERO.next(),
            description: "A governed SaaS franchise blueprint".into(),
            business_model: BusinessModel::SaaS,
            constitution_hash: test_hash("constitution"),
            required_slots: OdaSlot::ALL.to_vec(),
            budget_template: BudgetTemplate::default(),
            goal_template: GoalTemplate::default(),
            created: test_timestamp(),
        }
    }

    fn test_blueprint() -> FranchiseBlueprint {
        FranchiseBlueprint::new(test_blueprint_input()).unwrap()
    }

    #[test]
    fn blueprint_new_computes_and_verifies_canonical_hash() {
        let blueprint = FranchiseBlueprint::new(test_blueprint_input()).unwrap();

        assert_ne!(blueprint.content_hash, Hash256::ZERO);
        assert!(blueprint.verify_content_hash().unwrap());

        let same = FranchiseBlueprint::new(test_blueprint_input()).unwrap();
        assert_eq!(blueprint.content_hash, same.content_hash);

        let mut changed = test_blueprint_input();
        changed.required_slots = vec![OdaSlot::HrPeopleOps1];
        let changed = FranchiseBlueprint::new(changed).unwrap();
        assert_ne!(blueprint.content_hash, changed.content_hash);
    }

    #[test]
    fn blueprint_rejects_placeholder_metadata() {
        let mut input = test_blueprint_input();
        input.id = Uuid::nil();
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.name = "   ".into();
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.version = Version::ZERO;
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.description = " ".into();
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.business_model = BusinessModel::Custom {
            description: " ".into(),
        };
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.constitution_hash = Hash256::ZERO;
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.required_slots = Vec::new();
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.required_slots = vec![OdaSlot::HrPeopleOps1, OdaSlot::DeepResearcher];
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.required_slots = vec![OdaSlot::HrPeopleOps1, OdaSlot::HrPeopleOps1];
        assert!(FranchiseBlueprint::new(input).is_err());

        let mut input = test_blueprint_input();
        input.created = Timestamp::ZERO;
        assert!(FranchiseBlueprint::new(input).is_err());
    }

    #[test]
    fn publish_rejects_tampered_or_placeholder_blueprint_hash() {
        let mut reg = FranchiseRegistry::new();
        let mut blueprint = test_blueprint();
        blueprint.content_hash = test_hash("tampered");

        assert!(reg.publish(blueprint).is_err());

        let mut blueprint = test_blueprint();
        blueprint.id = Uuid::nil();
        assert!(reg.publish(blueprint).is_err());

        let mut blueprint = test_blueprint();
        blueprint.content_hash = Hash256::ZERO;
        assert!(reg.publish(blueprint).is_err());
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
        let mut second = test_blueprint_input();
        second.id = test_uuid(2);
        reg.publish(FranchiseBlueprint::new(second).unwrap())
            .unwrap();
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

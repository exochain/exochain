//! Goal hierarchy and alignment scoring — Paperclip concept adapted for ExoChain.
//!
//! Goals form a tree: Company → Phase → Team → Individual.
//! Alignment scores are computed as integer basis points (0–10000).

use std::collections::BTreeMap;

use exo_core::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{CatapultError, Result},
    oda::OdaSlot,
};

/// Level of a goal in the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GoalLevel {
    /// Franchise-level objective.
    Company,
    /// FM 3-05 phase milestone.
    Phase,
    /// ODA-level deliverable.
    Team,
    /// Per-agent task.
    Individual,
}

/// Status of a goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GoalStatus {
    Planned,
    Active,
    Completed,
    Blocked,
    Cancelled,
}

/// A goal in the hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Goal {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub level: GoalLevel,
    pub status: GoalStatus,
    /// Parent goal — `None` for root company goals.
    pub parent_id: Option<Uuid>,
    /// ODA slot responsible for this goal.
    pub owner_slot: Option<OdaSlot>,
    pub created: Timestamp,
    pub updated: Timestamp,
}

/// Caller-supplied deterministic metadata for creating a goal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalInput {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub level: GoalLevel,
    pub status: GoalStatus,
    pub parent_id: Option<Uuid>,
    pub owner_slot: Option<OdaSlot>,
    pub created: Timestamp,
    pub updated: Timestamp,
}

impl Goal {
    /// Create a goal from caller-supplied deterministic metadata.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if the input contains placeholder IDs or
    /// timestamps.
    pub fn new(input: GoalInput) -> Result<Self> {
        validate_goal_input(&input)?;
        Ok(Self {
            id: input.id,
            title: input.title,
            description: input.description,
            level: input.level,
            status: input.status,
            parent_id: input.parent_id,
            owner_slot: input.owner_slot,
            created: input.created,
            updated: input.updated,
        })
    }

    /// Validate externally supplied or deserialized goal metadata.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if placeholder IDs or timestamps are present.
    pub fn validate(&self) -> Result<()> {
        validate_goal_input(&GoalInput {
            id: self.id,
            title: self.title.clone(),
            description: self.description.clone(),
            level: self.level,
            status: self.status,
            parent_id: self.parent_id,
            owner_slot: self.owner_slot,
            created: self.created,
            updated: self.updated,
        })
    }
}

/// Default goal template for franchise blueprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalTemplate {
    /// Default company-level goals to create for new newcos.
    pub default_goals: Vec<GoalSeed>,
}

/// A seed for creating a goal from a template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalSeed {
    pub title: String,
    pub level: GoalLevel,
    pub owner_slot: Option<OdaSlot>,
}

impl Default for GoalTemplate {
    fn default() -> Self {
        Self {
            default_goals: vec![
                GoalSeed {
                    title: "Achieve product-market fit".into(),
                    level: GoalLevel::Company,
                    owner_slot: None,
                },
                GoalSeed {
                    title: "Complete ODA staffing".into(),
                    level: GoalLevel::Phase,
                    owner_slot: Some(OdaSlot::HrPeopleOps1),
                },
                GoalSeed {
                    title: "Market intelligence report".into(),
                    level: GoalLevel::Phase,
                    owner_slot: Some(OdaSlot::DeepResearcher),
                },
            ],
        }
    }
}

/// Goal tree — hierarchical goal management with alignment scoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoalTree {
    goals: BTreeMap<Uuid, Goal>,
}

impl GoalTree {
    /// Create an empty goal tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            goals: BTreeMap::new(),
        }
    }

    /// Add a goal to the tree.
    pub fn add(&mut self, goal: Goal) -> Result<()> {
        goal.validate()?;
        let id = goal.id;
        if self.goals.contains_key(&id) {
            return Err(CatapultError::DuplicateGoal(id));
        }
        if let Some(parent_id) = goal.parent_id {
            if !self.goals.contains_key(&parent_id) {
                return Err(CatapultError::InvalidGoal {
                    reason: format!("goal parent id {parent_id} does not exist"),
                });
            }
        }
        self.goals.insert(id, goal);
        Ok(())
    }

    /// Get a goal by ID.
    #[must_use]
    pub fn get(&self, id: &Uuid) -> Option<&Goal> {
        self.goals.get(id)
    }

    /// Update the status of a goal.
    pub fn update_status(
        &mut self,
        id: &Uuid,
        status: GoalStatus,
        updated: Timestamp,
    ) -> Result<()> {
        let goal = self
            .goals
            .get_mut(id)
            .ok_or(CatapultError::GoalNotFound(*id))?;
        validate_goal_update_timestamp(goal, updated)?;
        goal.status = status;
        goal.updated = updated;
        Ok(())
    }

    /// Get all root-level company goals.
    #[must_use]
    pub fn company_goals(&self) -> Vec<&Goal> {
        self.goals
            .values()
            .filter(|g| g.level == GoalLevel::Company && g.parent_id.is_none())
            .collect()
    }

    /// Get children of a parent goal.
    #[must_use]
    pub fn children(&self, parent_id: &Uuid) -> Vec<&Goal> {
        self.goals
            .values()
            .filter(|g| g.parent_id.as_ref() == Some(parent_id))
            .collect()
    }

    /// Compute alignment score as integer basis points (0–10000).
    ///
    /// Score = (completed goals * 10000) / total non-cancelled goals.
    /// Returns 10000 if there are no goals (vacuously aligned).
    #[must_use]
    pub fn alignment_score(&self) -> u32 {
        let active_goals: Vec<&Goal> = self
            .goals
            .values()
            .filter(|g| g.status != GoalStatus::Cancelled)
            .collect();

        if active_goals.is_empty() {
            return 10_000;
        }

        let completed = active_goals
            .iter()
            .filter(|g| g.status == GoalStatus::Completed)
            .count();

        // Integer division: (completed * 10000) / total
        #[allow(clippy::as_conversions)]
        let score = (completed as u64)
            .saturating_mul(10_000)
            .checked_div(active_goals.len() as u64)
            .unwrap_or(0);

        // Safe: score is at most 10_000 which fits in u32
        #[allow(clippy::as_conversions)]
        {
            score as u32
        }
    }

    /// Total number of goals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.goals.len()
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.goals.is_empty()
    }

    /// Iterate over all goals.
    pub fn iter(&self) -> impl Iterator<Item = (&Uuid, &Goal)> {
        self.goals.iter()
    }

    /// Validate every goal and parent relationship in a deserialized tree.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if placeholders, mismatched map keys, or
    /// orphan parent references are present.
    pub fn validate(&self) -> Result<()> {
        for (id, goal) in &self.goals {
            if *id != goal.id {
                return Err(CatapultError::InvalidGoal {
                    reason: format!("goal stored under id {id} but declares id {}", goal.id),
                });
            }
            goal.validate()?;
            if let Some(parent_id) = goal.parent_id {
                if !self.goals.contains_key(&parent_id) {
                    return Err(CatapultError::InvalidGoal {
                        reason: format!("goal parent id {parent_id} does not exist"),
                    });
                }
            }
        }
        Ok(())
    }
}

fn validate_goal_input(input: &GoalInput) -> Result<()> {
    if input.id.is_nil() {
        return Err(CatapultError::InvalidGoal {
            reason: "goal id must be caller-supplied and non-nil".into(),
        });
    }
    if input.title.trim().is_empty() {
        return Err(CatapultError::InvalidGoal {
            reason: "goal title must not be empty".into(),
        });
    }
    if input.parent_id == Some(input.id) {
        return Err(CatapultError::InvalidGoal {
            reason: "goal parent id must not equal goal id".into(),
        });
    }
    if input.created == Timestamp::ZERO {
        return Err(CatapultError::InvalidGoal {
            reason: "goal created timestamp must be caller-supplied HLC".into(),
        });
    }
    if input.updated == Timestamp::ZERO {
        return Err(CatapultError::InvalidGoal {
            reason: "goal updated timestamp must be caller-supplied HLC".into(),
        });
    }
    if input.updated < input.created {
        return Err(CatapultError::InvalidGoal {
            reason: "goal updated timestamp must not precede creation timestamp".into(),
        });
    }
    Ok(())
}

fn validate_goal_update_timestamp(goal: &Goal, updated: Timestamp) -> Result<()> {
    if updated == Timestamp::ZERO {
        return Err(CatapultError::InvalidGoal {
            reason: "goal status update timestamp must be caller-supplied HLC".into(),
        });
    }
    if updated < goal.updated {
        return Err(CatapultError::InvalidGoal {
            reason: "goal status update timestamp must not regress".into(),
        });
    }
    if updated < goal.created {
        return Err(CatapultError::InvalidGoal {
            reason: "goal status update timestamp must not precede creation timestamp".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_goal(title: &str, level: GoalLevel, status: GoalStatus) -> Goal {
        let mut bytes = [0u8; 16];
        for (index, byte) in title.as_bytes().iter().take(16).enumerate() {
            bytes[index] = *byte;
        }
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[0] = 1;
        }
        Goal::new(GoalInput {
            id: Uuid::from_bytes(bytes),
            title: title.into(),
            description: None,
            level,
            status,
            parent_id: None,
            owner_slot: None,
            created: Timestamp::new(1_765_000_000_000, 0),
            updated: Timestamp::new(1_765_000_000_000, 0),
        })
        .unwrap()
    }

    fn test_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn test_timestamp(offset: u64) -> Timestamp {
        Timestamp::new(1_765_000_000_000 + offset, 0)
    }

    fn valid_goal(title: &str, level: GoalLevel, status: GoalStatus) -> Goal {
        Goal::new(GoalInput {
            id: test_uuid(1),
            title: title.into(),
            description: None,
            level,
            status,
            parent_id: None,
            owner_slot: None,
            created: test_timestamp(0),
            updated: test_timestamp(0),
        })
        .unwrap()
    }

    #[test]
    fn add_rejects_placeholder_goal_metadata() {
        let mut tree = GoalTree::new();

        let mut goal = valid_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        goal.id = Uuid::nil();
        assert!(tree.add(goal).is_err());

        let mut goal = valid_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        goal.created = Timestamp::ZERO;
        assert!(tree.add(goal).is_err());

        let mut goal = valid_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        goal.updated = Timestamp::new(1, 0);
        goal.created = Timestamp::new(2, 0);
        assert!(tree.add(goal).is_err());
    }

    #[test]
    fn add_rejects_orphan_goal_parent() {
        let mut tree = GoalTree::new();
        let mut child = valid_goal("Child", GoalLevel::Team, GoalStatus::Planned);
        child.parent_id = Some(test_uuid(9));

        assert!(tree.add(child).is_err());
    }

    #[test]
    fn goal_validation_rejects_empty_title_self_parent_and_regressive_update() {
        let mut goal = valid_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        goal.title = "   ".into();
        assert!(goal.validate().is_err());

        let mut goal = valid_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        goal.parent_id = Some(goal.id);
        assert!(goal.validate().is_err());

        let mut tree = GoalTree::new();
        let goal = valid_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        let id = goal.id;
        tree.add(goal).unwrap();
        assert!(
            tree.update_status(&id, GoalStatus::Blocked, test_timestamp(0))
                .is_ok()
        );
        assert!(
            tree.update_status(&id, GoalStatus::Completed, Timestamp::new(1, 0))
                .is_err()
        );
    }

    #[test]
    fn tree_validate_rejects_deserialized_key_mismatch_and_orphan_parent() {
        let mut key_mismatch = GoalTree::new();
        let goal = valid_goal("Mismatch", GoalLevel::Company, GoalStatus::Planned);
        key_mismatch.goals.insert(test_uuid(9), goal);
        assert!(key_mismatch.validate().is_err());

        let mut orphan = GoalTree::new();
        let mut child = valid_goal("Child", GoalLevel::Team, GoalStatus::Planned);
        child.parent_id = Some(test_uuid(8));
        orphan.goals.insert(child.id, child);
        assert!(orphan.validate().is_err());
    }

    #[test]
    fn update_status_requires_caller_supplied_hlc() {
        let mut tree = GoalTree::new();
        let goal = valid_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        let id = goal.id;
        tree.add(goal).unwrap();

        assert!(
            tree.update_status(&id, GoalStatus::Completed, Timestamp::ZERO)
                .is_err()
        );

        let updated = test_timestamp(100);
        tree.update_status(&id, GoalStatus::Completed, updated)
            .unwrap();
        let goal = tree.get(&id).unwrap();
        assert_eq!(goal.status, GoalStatus::Completed);
        assert_eq!(goal.updated, updated);
    }

    #[test]
    fn add_and_get() {
        let mut tree = GoalTree::new();
        let goal = make_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        let id = goal.id;
        tree.add(goal).unwrap();
        assert!(tree.get(&id).is_some());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn duplicate_rejected() {
        let mut tree = GoalTree::new();
        let goal = make_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        let goal2 = goal.clone();
        tree.add(goal).unwrap();
        assert!(tree.add(goal2).is_err());
    }

    #[test]
    fn update_status() {
        let mut tree = GoalTree::new();
        let goal = make_goal("Test", GoalLevel::Company, GoalStatus::Planned);
        let id = goal.id;
        tree.add(goal).unwrap();
        tree.update_status(&id, GoalStatus::Completed, test_timestamp(100))
            .unwrap();
        assert_eq!(tree.get(&id).unwrap().status, GoalStatus::Completed);
    }

    #[test]
    fn update_not_found() {
        let mut tree = GoalTree::new();
        assert!(
            tree.update_status(&Uuid::nil(), GoalStatus::Active, test_timestamp(100))
                .is_err()
        );
    }

    #[test]
    fn alignment_score_empty() {
        let tree = GoalTree::new();
        assert_eq!(tree.alignment_score(), 10_000);
    }

    #[test]
    fn alignment_score_none_completed() {
        let mut tree = GoalTree::new();
        tree.add(make_goal("A", GoalLevel::Company, GoalStatus::Active))
            .unwrap();
        tree.add(make_goal("B", GoalLevel::Phase, GoalStatus::Planned))
            .unwrap();
        assert_eq!(tree.alignment_score(), 0);
    }

    #[test]
    fn alignment_score_half() {
        let mut tree = GoalTree::new();
        tree.add(make_goal("A", GoalLevel::Company, GoalStatus::Completed))
            .unwrap();
        tree.add(make_goal("B", GoalLevel::Phase, GoalStatus::Active))
            .unwrap();
        assert_eq!(tree.alignment_score(), 5000);
    }

    #[test]
    fn alignment_score_all_completed() {
        let mut tree = GoalTree::new();
        tree.add(make_goal("A", GoalLevel::Company, GoalStatus::Completed))
            .unwrap();
        tree.add(make_goal("B", GoalLevel::Phase, GoalStatus::Completed))
            .unwrap();
        assert_eq!(tree.alignment_score(), 10_000);
    }

    #[test]
    fn cancelled_excluded_from_score() {
        let mut tree = GoalTree::new();
        tree.add(make_goal("A", GoalLevel::Company, GoalStatus::Completed))
            .unwrap();
        tree.add(make_goal("B", GoalLevel::Phase, GoalStatus::Cancelled))
            .unwrap();
        // Only one non-cancelled goal, and it's completed
        assert_eq!(tree.alignment_score(), 10_000);
    }

    #[test]
    fn children() {
        let mut tree = GoalTree::new();
        let parent = make_goal("Parent", GoalLevel::Company, GoalStatus::Active);
        let parent_id = parent.id;
        tree.add(parent).unwrap();

        let mut child = make_goal("Child", GoalLevel::Team, GoalStatus::Planned);
        child.parent_id = Some(parent_id);
        tree.add(child).unwrap();

        assert_eq!(tree.children(&parent_id).len(), 1);
        assert_eq!(tree.company_goals().len(), 1);
    }

    #[test]
    fn goal_level_serde() {
        let levels = [
            GoalLevel::Company,
            GoalLevel::Phase,
            GoalLevel::Team,
            GoalLevel::Individual,
        ];
        for l in &levels {
            let j = serde_json::to_string(l).unwrap();
            let rt: GoalLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, l);
        }
    }

    #[test]
    fn goal_status_serde() {
        let statuses = [
            GoalStatus::Planned,
            GoalStatus::Active,
            GoalStatus::Completed,
            GoalStatus::Blocked,
            GoalStatus::Cancelled,
        ];
        for s in &statuses {
            let j = serde_json::to_string(s).unwrap();
            let rt: GoalStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, s);
        }
    }

    #[test]
    fn template_default() {
        let t = GoalTemplate::default();
        assert_eq!(t.default_goals.len(), 3);
    }
}

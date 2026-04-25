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
        let id = goal.id;
        if self.goals.contains_key(&id) {
            return Err(CatapultError::DuplicateGoal(id));
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
    pub fn update_status(&mut self, id: &Uuid, status: GoalStatus) -> Result<()> {
        let goal = self
            .goals
            .get_mut(id)
            .ok_or(CatapultError::GoalNotFound(*id))?;
        goal.status = status;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_goal(title: &str, level: GoalLevel, status: GoalStatus) -> Goal {
        Goal {
            id: Uuid::new_v4(),
            title: title.into(),
            description: None,
            level,
            status,
            parent_id: None,
            owner_slot: None,
            created: Timestamp::ZERO,
            updated: Timestamp::ZERO,
        }
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
        tree.update_status(&id, GoalStatus::Completed).unwrap();
        assert_eq!(tree.get(&id).unwrap().status, GoalStatus::Completed);
    }

    #[test]
    fn update_not_found() {
        let mut tree = GoalTree::new();
        assert!(
            tree.update_status(&Uuid::nil(), GoalStatus::Active)
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

//! Kanban board for escalation cases.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::EscalationError, escalation::EscalationCase};

/// Column in the escalation kanban board representing a workflow stage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KanbanColumn {
    Backlog,
    InProgress,
    Review,
    Resolved,
    Archived,
}

impl std::fmt::Display for KanbanColumn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Board that organises escalation cases into workflow columns.
#[derive(Debug, Clone, Default)]
pub struct KanbanBoard {
    pub columns: BTreeMap<KanbanColumn, Vec<EscalationCase>>,
}

impl KanbanBoard {
    /// Create a new board pre-populated with all five workflow columns.
    #[must_use]
    pub fn new() -> Self {
        let mut columns = BTreeMap::new();
        columns.insert(KanbanColumn::Backlog, Vec::new());
        columns.insert(KanbanColumn::InProgress, Vec::new());
        columns.insert(KanbanColumn::Review, Vec::new());
        columns.insert(KanbanColumn::Resolved, Vec::new());
        columns.insert(KanbanColumn::Archived, Vec::new());
        Self { columns }
    }

    /// Add a case to the backlog.
    pub fn add_case(&mut self, case: EscalationCase) {
        self.columns
            .entry(KanbanColumn::Backlog)
            .or_default()
            .push(case);
    }

    /// Total cases across all columns.
    #[must_use]
    pub fn total_cases(&self) -> usize {
        self.columns.values().map(|v| v.len()).sum()
    }
}

/// Move a case from its current column to a target column.
pub fn move_case(
    board: &mut KanbanBoard,
    case_id: &Uuid,
    to: KanbanColumn,
) -> Result<(), EscalationError> {
    // Find and remove the case from its current column
    let mut found_case: Option<EscalationCase> = None;
    for (_col, cases) in board.columns.iter_mut() {
        if let Some(pos) = cases.iter().position(|c| c.id == *case_id) {
            found_case = Some(cases.remove(pos));
            break;
        }
    }

    let case = found_case.ok_or_else(|| EscalationError::CaseNotFound(case_id.to_string()))?;
    board.columns.entry(to).or_default().push(case);
    Ok(())
}

/// Get cases sorted by priority (Critical first).
#[must_use]
pub fn cases_by_priority(board: &KanbanBoard) -> Vec<&EscalationCase> {
    let mut all: Vec<&EscalationCase> = board.columns.values().flat_map(|v| v.iter()).collect();
    all.sort_by(|a, b| b.priority.cmp(&a.priority)); // Descending priority
    all
}

#[cfg(test)]
mod tests {
    use exo_core::Timestamp;

    use super::*;
    use crate::{detector::*, escalation::*};

    fn signal(confidence: u8) -> DetectionSignal {
        DetectionSignal {
            source: "test".into(),
            signal_type: SignalType::AnomalousPattern,
            confidence,
            evidence_hash: [0u8; 32],
            timestamp: Timestamp::new(1000, 0),
        }
    }

    #[test]
    fn new_board_is_empty() {
        let b = KanbanBoard::new();
        assert_eq!(b.total_cases(), 0);
        assert_eq!(b.columns.len(), 5);
    }
    #[test]
    fn add_case_to_backlog() {
        let mut b = KanbanBoard::new();
        let c = escalate(&signal(50), &EscalationPath::Standard);
        b.add_case(c);
        assert_eq!(b.total_cases(), 1);
        assert_eq!(b.columns[&KanbanColumn::Backlog].len(), 1);
    }
    #[test]
    fn move_case_between_columns() {
        let mut b = KanbanBoard::new();
        let c = escalate(&signal(50), &EscalationPath::Standard);
        let id = c.id;
        b.add_case(c);
        assert!(move_case(&mut b, &id, KanbanColumn::InProgress).is_ok());
        assert_eq!(b.columns[&KanbanColumn::Backlog].len(), 0);
        assert_eq!(b.columns[&KanbanColumn::InProgress].len(), 1);
    }
    #[test]
    fn move_nonexistent_case_fails() {
        let mut b = KanbanBoard::new();
        assert!(move_case(&mut b, &Uuid::new_v4(), KanbanColumn::InProgress).is_err());
    }
    #[test]
    fn move_through_all_columns() {
        let mut b = KanbanBoard::new();
        let c = escalate(&signal(50), &EscalationPath::Standard);
        let id = c.id;
        b.add_case(c);
        assert!(move_case(&mut b, &id, KanbanColumn::InProgress).is_ok());
        assert!(move_case(&mut b, &id, KanbanColumn::Review).is_ok());
        assert!(move_case(&mut b, &id, KanbanColumn::Resolved).is_ok());
        assert!(move_case(&mut b, &id, KanbanColumn::Archived).is_ok());
        assert_eq!(b.columns[&KanbanColumn::Archived].len(), 1);
    }
    #[test]
    fn cases_by_priority_sorted() {
        let mut b = KanbanBoard::new();
        b.add_case(escalate(&signal(20), &EscalationPath::Standard)); // Low
        b.add_case(escalate(&signal(90), &EscalationPath::Standard)); // Critical
        b.add_case(escalate(&signal(50), &EscalationPath::Standard)); // Medium
        let sorted = cases_by_priority(&b);
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].priority, CasePriority::Critical);
        assert_eq!(sorted[2].priority, CasePriority::Low);
    }
    #[test]
    fn column_display() {
        assert_eq!(KanbanColumn::Backlog.to_string(), "Backlog");
        assert_eq!(KanbanColumn::Archived.to_string(), "Archived");
    }
}

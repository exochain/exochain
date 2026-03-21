//! Conflict of interest detection and enforcement.
//!
//! # Enforcement model
//!
//! Two APIs are provided:
//! - `must_recuse()` — advisory bool, retained for backward compatibility.
//! - `check_and_block()` — enforcing gate; returns `Err` when recusal is
//!   required.  Call sites in the vote-casting path **must** use this function.
//!
//! # Standing conflict register
//!
//! `StandingConflictRegister` persists conflict declarations across decisions.
//! A declaration filed in Decision A is automatically re-evaluated in Decision B
//! when the same related DIDs are involved.
//!
//! # Board acknowledgment (DGCL §144(a)(1))
//!
//! `BoardAcknowledgment` records that each non-conflicted board member received
//! and acknowledged a specific conflict disclosure.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConflictError {
    #[error("recusal required: actor {actor} has {severity:?} conflict — vote blocked")]
    RecusalRequired {
        actor: String,
        severity: ConflictSeverity,
    },
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictDeclaration {
    pub declarant_did: Did,
    pub nature: String,
    pub related_dids: Vec<Did>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub action_id: String,
    pub actor_did: Did,
    pub affected_dids: Vec<Did>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub declaration: ConflictDeclaration,
    pub affected_did: Did,
    pub severity: ConflictSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictSeverity {
    Advisory,
    Material,
    Disqualifying,
}

// ---------------------------------------------------------------------------
// DGCL §144(a)(1) board acknowledgment
// ---------------------------------------------------------------------------

/// Records that a board member received and acknowledged a conflict disclosure.
///
/// Required under DGCL §144(a)(1): "material facts as to the director's
/// relationship or interest … are disclosed or are known to the board."
/// Acknowledgment is the proof that the board *received* the disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardAcknowledgment {
    /// DID of the acknowledging board member (must not be the conflicted party).
    pub acknowledger_did: Did,
    /// The conflict declaration being acknowledged.
    pub declaration_timestamp: Timestamp,
    /// When acknowledgment was recorded.
    pub acknowledged_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Standing conflict register
// ---------------------------------------------------------------------------

/// Persists conflict declarations across decision boundaries.
///
/// Declarations filed in one decision are automatically re-evaluated in
/// subsequent decisions that involve the same related DIDs, satisfying
/// the DGCL §144 requirement for ongoing conflict tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StandingConflictRegister {
    entries: Vec<ConflictDeclaration>,
    acknowledgments: Vec<BoardAcknowledgment>,
}

impl StandingConflictRegister {
    /// Create an empty register.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a conflict declaration.  Idempotent: duplicate declarations
    /// (same declarant + nature + related_dids) are silently skipped.
    pub fn register(&mut self, decl: ConflictDeclaration) {
        let already_exists = self.entries.iter().any(|e| {
            e.declarant_did == decl.declarant_did
                && e.nature == decl.nature
                && e.related_dids == decl.related_dids
        });
        if !already_exists {
            self.entries.push(decl);
        }
    }

    /// Record that a board member acknowledged a disclosure.
    pub fn record_acknowledgment(&mut self, ack: BoardAcknowledgment) {
        self.acknowledgments.push(ack);
    }

    /// Return all declarations relevant to an action (for any actor).
    #[must_use]
    pub fn declarations_for_action(&self, action: &ActionRequest) -> Vec<&ConflictDeclaration> {
        self.entries
            .iter()
            .filter(|d| {
                d.declarant_did == action.actor_did
                    && d.related_dids
                        .iter()
                        .any(|r| action.affected_dids.contains(r))
            })
            .collect()
    }

    /// Number of board acknowledgments recorded for a given declarant.
    #[must_use]
    pub fn acknowledgment_count(&self, declarant: &Did) -> usize {
        self.acknowledgments
            .iter()
            .filter(|a| &a.acknowledger_did != declarant)
            .count()
    }

    /// All declarations in the register.
    #[must_use]
    pub fn all_declarations(&self) -> &[ConflictDeclaration] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

#[must_use]
pub fn check_conflicts(
    actor: &Did,
    action: &ActionRequest,
    declarations: &[ConflictDeclaration],
) -> Vec<Conflict> {
    let mut conflicts = Vec::new();
    for decl in declarations {
        if &decl.declarant_did != actor {
            continue;
        }
        for related in &decl.related_dids {
            if action.affected_dids.contains(related) {
                let severity =
                    if decl.nature.contains("financial") || decl.nature.contains("ownership") {
                        ConflictSeverity::Disqualifying
                    } else if decl.nature.contains("personal") || decl.nature.contains("family") {
                        ConflictSeverity::Material
                    } else {
                        ConflictSeverity::Advisory
                    };
                conflicts.push(Conflict {
                    declaration: decl.clone(),
                    affected_did: related.clone(),
                    severity,
                });
            }
        }
    }
    conflicts
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Advisory check — returns `true` when the actor must recuse.
///
/// Retained for backward compatibility.  New vote-casting paths must use
/// `check_and_block()` instead, which enforces at the Rust type level.
#[must_use]
pub fn must_recuse(conflicts: &[Conflict]) -> bool {
    conflicts.iter().any(|c| {
        c.severity == ConflictSeverity::Disqualifying || c.severity == ConflictSeverity::Material
    })
}

/// Enforcing gate — returns `Err(ConflictError::RecusalRequired)` when the
/// actor has a Material or Disqualifying conflict.
///
/// Call this function in any vote-casting or approval path.  The `#[must_use]`
/// attribute ensures callers cannot silently ignore the result.
///
/// # Errors
/// Returns `ConflictError::RecusalRequired` if recusal is required.
#[must_use = "conflict enforcement result must be handled — do not silently discard"]
pub fn check_and_block(actor: &Did, conflicts: &[Conflict]) -> Result<(), ConflictError> {
    for c in conflicts {
        if c.severity == ConflictSeverity::Disqualifying || c.severity == ConflictSeverity::Material
        {
            return Err(ConflictError::RecusalRequired {
                actor: actor.to_string(),
                severity: c.severity.clone(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Quorum adjustment
// ---------------------------------------------------------------------------

/// Compute the effective quorum denominator after removing recused members.
///
/// When members recuse, they must not be counted in the quorum denominator —
/// counting them would create phantom quorum (a member who cannot vote
/// inflating the total so the threshold is harder to reach for those who can).
///
/// # Arguments
/// * `total_members` — the full board or panel count before recusal.
/// * `recused_count` — number of members who have recused (must_recuse returned true).
///
/// Returns the adjusted denominator, minimum 1.
#[must_use]
pub fn adjusted_quorum_denominator(total_members: usize, recused_count: usize) -> usize {
    total_members.saturating_sub(recused_count).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("ok")
    }

    fn decl(nature: &str, related: &str) -> ConflictDeclaration {
        ConflictDeclaration {
            declarant_did: did("alice"),
            nature: nature.into(),
            related_dids: vec![did(related)],
            timestamp: Timestamp::new(1000, 0),
        }
    }
    fn action(affected: &str) -> ActionRequest {
        ActionRequest {
            action_id: "a1".into(),
            actor_did: did("alice"),
            affected_dids: vec![did(affected)],
            description: "test".into(),
        }
    }

    // ---- original advisory tests (backward compat) ----

    #[test]
    fn no_conflicts_when_none() {
        assert!(check_conflicts(&did("alice"), &action("bob"), &[]).is_empty());
    }
    #[test]
    fn financial_disqualifying() {
        let c = check_conflicts(
            &did("alice"),
            &action("bob"),
            &[decl("financial interest", "bob")],
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity, ConflictSeverity::Disqualifying);
        assert!(must_recuse(&c));
    }
    #[test]
    fn personal_material() {
        let c = check_conflicts(
            &did("alice"),
            &action("carol"),
            &[decl("personal relationship", "carol")],
        );
        assert_eq!(c[0].severity, ConflictSeverity::Material);
        assert!(must_recuse(&c));
    }
    #[test]
    fn advisory_no_recuse() {
        let c = check_conflicts(
            &did("alice"),
            &action("dave"),
            &[decl("acquaintance", "dave")],
        );
        assert_eq!(c[0].severity, ConflictSeverity::Advisory);
        assert!(!must_recuse(&c));
    }
    #[test]
    fn no_overlap() {
        assert!(
            check_conflicts(&did("alice"), &action("carol"), &[decl("financial", "bob")])
                .is_empty()
        );
    }
    #[test]
    fn different_actor_ignored() {
        let d = ConflictDeclaration {
            declarant_did: did("bob"),
            nature: "financial".into(),
            related_dids: vec![did("carol")],
            timestamp: Timestamp::new(1000, 0),
        };
        assert!(check_conflicts(&did("alice"), &action("carol"), &[d]).is_empty());
    }
    #[test]
    fn must_recuse_empty() {
        assert!(!must_recuse(&[]));
    }
    #[test]
    fn ownership_disqualifying() {
        let c = check_conflicts(
            &did("alice"),
            &action("bob"),
            &[decl("ownership stake", "bob")],
        );
        assert_eq!(c[0].severity, ConflictSeverity::Disqualifying);
    }
    #[test]
    fn family_material() {
        let c = check_conflicts(
            &did("alice"),
            &action("bob"),
            &[decl("family member", "bob")],
        );
        assert_eq!(c[0].severity, ConflictSeverity::Material);
    }

    // ---- enforcement: check_and_block ----

    #[test]
    fn check_and_block_disqualifying_blocks_vote() {
        let conflicts = check_conflicts(
            &did("alice"),
            &action("bob"),
            &[decl("financial interest", "bob")],
        );
        let result = check_and_block(&did("alice"), &conflicts);
        assert!(result.is_err(), "Disqualifying conflict must block vote");
        let err = result.unwrap_err();
        assert!(matches!(err, ConflictError::RecusalRequired { .. }));
        assert!(err.to_string().contains("vote blocked"));
    }

    #[test]
    fn check_and_block_material_blocks_vote() {
        let conflicts = check_conflicts(
            &did("alice"),
            &action("carol"),
            &[decl("personal relationship", "carol")],
        );
        let result = check_and_block(&did("alice"), &conflicts);
        assert!(result.is_err(), "Material conflict must block vote");
    }

    #[test]
    fn check_and_block_advisory_permits_vote() {
        let conflicts = check_conflicts(
            &did("alice"),
            &action("dave"),
            &[decl("acquaintance", "dave")],
        );
        assert!(
            check_and_block(&did("alice"), &conflicts).is_ok(),
            "Advisory conflict must not block vote"
        );
    }

    #[test]
    fn check_and_block_no_conflicts_permits_vote() {
        assert!(check_and_block(&did("alice"), &[]).is_ok());
    }

    // ---- board acknowledgment (DGCL §144(a)(1)) ----

    #[test]
    fn board_acknowledgment_records_receipt() {
        let mut register = StandingConflictRegister::new();
        let declarant = did("alice");
        register.register(decl("financial interest", "bob"));

        let ack = BoardAcknowledgment {
            acknowledger_did: did("carol"),
            declaration_timestamp: Timestamp::new(1000, 0),
            acknowledged_at: Timestamp::new(2000, 0),
        };
        register.record_acknowledgment(ack);

        // carol acknowledged, not alice (the conflicted party)
        assert_eq!(register.acknowledgment_count(&declarant), 1);
    }

    #[test]
    fn board_acknowledgment_excludes_declarant() {
        // The conflicted party acknowledging their own disclosure does not count.
        let mut register = StandingConflictRegister::new();
        let declarant = did("alice");
        let ack = BoardAcknowledgment {
            acknowledger_did: declarant.clone(), // same as declarant
            declaration_timestamp: Timestamp::new(1000, 0),
            acknowledged_at: Timestamp::new(2000, 0),
        };
        register.record_acknowledgment(ack);
        assert_eq!(
            register.acknowledgment_count(&declarant),
            0,
            "Declarant self-acknowledgment must not count toward DGCL §144(a)(1)"
        );
    }

    // ---- standing conflict register ----

    #[test]
    fn standing_register_cross_decision_detection() {
        let mut register = StandingConflictRegister::new();
        // Filed in "decision A"
        register.register(ConflictDeclaration {
            declarant_did: did("alice"),
            nature: "financial interest".into(),
            related_dids: vec![did("acme-corp")],
            timestamp: Timestamp::new(1000, 0),
        });

        // "decision B" — different action_id, same related_dids
        let action_b = ActionRequest {
            action_id: "decision-b".into(),
            actor_did: did("alice"),
            affected_dids: vec![did("acme-corp")],
            description: "approve contract with acme".into(),
        };

        let relevant = register.declarations_for_action(&action_b);
        assert_eq!(
            relevant.len(),
            1,
            "Cross-decision conflict must be detected"
        );
    }

    #[test]
    fn standing_register_deduplicates() {
        let mut register = StandingConflictRegister::new();
        let d = decl("financial interest", "bob");
        register.register(d.clone());
        register.register(d);
        assert_eq!(register.all_declarations().len(), 1);
    }

    #[test]
    fn standing_register_unrelated_action_not_flagged() {
        let mut register = StandingConflictRegister::new();
        register.register(decl("financial interest", "bob"));

        let unrelated = ActionRequest {
            action_id: "a2".into(),
            actor_did: did("alice"),
            affected_dids: vec![did("carol")], // carol, not bob
            description: "vote on carol proposal".into(),
        };
        assert!(register.declarations_for_action(&unrelated).is_empty());
    }

    // ---- quorum adjustment ----

    #[test]
    fn quorum_adjustment_reduces_denominator() {
        // 5 members, 2 recuse → effective denominator is 3
        assert_eq!(adjusted_quorum_denominator(5, 2), 3);
    }

    #[test]
    fn quorum_adjustment_all_recuse_returns_one() {
        // Denominator never goes below 1 to avoid division-by-zero.
        assert_eq!(adjusted_quorum_denominator(3, 3), 1);
    }

    #[test]
    fn quorum_adjustment_no_recusals_unchanged() {
        assert_eq!(adjusted_quorum_denominator(7, 0), 7);
    }
}

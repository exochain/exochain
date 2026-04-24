//! Constitutional Corpus — per-tenant signed versioned governance framework.
//!
//! Satisfies: GOV-001, GOV-002, GOV-006, TNC-04

use crate::delegation::DelegationScope;
use crate::errors::GovernanceError;
use crate::types::*;
use exo_core::Did;
use exo_core::types::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};

/// Precedence level in the constitutional hierarchy.
/// Articles > Bylaws > Resolutions > Charters > Policies (GOV-006).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrecedenceLevel {
    Articles = 5,
    Bylaws = 4,
    Resolutions = 3,
    Charters = 2,
    Policies = 1,
}

/// A constitutional document within the corpus.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstitutionalDocument {
    pub id: String,
    pub precedence: PrecedenceLevel,
    pub content: serde_json::Value,
    pub constraints: Vec<Constraint>,
}

/// A machine-evaluable constraint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Constraint {
    pub id: String,
    pub description: String,
    pub expression: ConstraintExpression,
    pub failure_action: FailureAction,
}

/// Constraint expression types — evaluated synchronously before action (TNC-04).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConstraintExpression {
    /// Require that a specific decision class has a human gate.
    RequireHumanGate { decision_class: DecisionClass },
    /// Require minimum quorum size for a decision class.
    RequireMinQuorum {
        decision_class: DecisionClass,
        minimum: u32,
    },
    /// Require specific approval threshold percentage.
    RequireApprovalThreshold {
        decision_class: DecisionClass,
        threshold_pct: u32,
    },
    /// Require monetary cap on delegations for a class.
    RequireMonetaryCap {
        decision_class: DecisionClass,
        max_cents: u64,
    },
    /// Require conflict disclosure for specific decision classes.
    RequireConflictDisclosure { decision_class: DecisionClass },
    /// Maximum delegation chain depth.
    MaxDelegationDepth { max_depth: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Expr {
    Variable(String),
    Literal(String),
    Eq(Box<Expr>, Box<Expr>),
    GreaterThan(Box<Expr>, Box<Expr>),
    Contains(Box<Expr>, Box<Expr>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomConstraint {
    pub id: String,
    pub description: String,
    pub expression: Expr,
}

pub struct CustomConstraintEvaluator;

impl CustomConstraintEvaluator {
    pub fn evaluate_expr(
        expr: &Expr,
        context: &exo_core::DeterministicMap<String, String>,
    ) -> Result<String, GovernanceError> {
        match expr {
            Expr::Variable(name) => {
                context
                    .get(name)
                    .cloned()
                    .ok_or_else(|| GovernanceError::ConstitutionalViolation {
                        constraint_id: "MISSING_VAR".to_string(),
                        reason: format!("Variable '{}' not found in context", name),
                    })
            }
            Expr::Literal(val) => Ok(val.clone()),
            Expr::Eq(left, right) => {
                let l = Self::evaluate_expr(left, context)?;
                let r = Self::evaluate_expr(right, context)?;
                if l == r {
                    Ok("true".to_string())
                } else {
                    Ok("false".to_string())
                }
            }
            Expr::GreaterThan(left, right) => {
                let l = Self::evaluate_expr(left, context)?;
                let r = Self::evaluate_expr(right, context)?;
                let l_num: u64 = l.parse().unwrap_or(0);
                let r_num: u64 = r.parse().unwrap_or(0);
                if l_num > r_num {
                    Ok("true".to_string())
                } else {
                    Ok("false".to_string())
                }
            }
            Expr::Contains(left, right) => {
                let l = Self::evaluate_expr(left, context)?;
                let r = Self::evaluate_expr(right, context)?;
                if l.contains(&r) {
                    Ok("true".to_string())
                } else {
                    Ok("false".to_string())
                }
            }
        }
    }
}

pub fn evaluate_custom_constraints(
    constraints: &[CustomConstraint],
    context: &exo_core::DeterministicMap<String, String>,
) -> Result<(), GovernanceError> {
    for constraint in constraints {
        let result = CustomConstraintEvaluator::evaluate_expr(&constraint.expression, context)?;
        if result != "true" {
            return Err(GovernanceError::ConstitutionalViolation {
                constraint_id: constraint.id.clone(),
                reason: constraint.description.clone(),
            });
        }
    }
    Ok(())
}

/// Definition of a decision class in the constitution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionClassDef {
    pub class: DecisionClass,
    pub description: String,
    pub requires_human_gate: bool,
    pub default_quorum: QuorumDefaults,
}

/// Default quorum settings for a decision class.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumDefaults {
    pub minimum_participants: u32,
    pub approval_threshold_pct: u32,
}

/// Emergency authority specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencySpec {
    pub authorized_roles: Vec<Did>,
    pub scope: DelegationScope,
    pub max_duration_hours: u32,
    pub ratification_deadline_hours: u32,
    pub max_per_quarter: u32,
}

/// The complete Constitutional Corpus for a tenant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Constitution {
    pub tenant_id: TenantId,
    pub version: SemVer,
    pub hash: Hash256,
    pub documents: Vec<ConstitutionalDocument>,
    pub decision_classes: Vec<DecisionClassDef>,
    pub human_gate_classes: Vec<DecisionClass>,
    pub emergency_authorities: Vec<EmergencySpec>,
    pub default_delegation_expiry_hours: u32,
    pub max_delegation_depth: u32,
    pub created_at: Timestamp,
    pub signatures: Vec<GovernanceSignature>,
}

/// Result of evaluating a constraint.
#[derive(Clone, Debug)]
pub struct ConstraintResult {
    pub constraint_id: String,
    pub satisfied: bool,
    pub failure_action: Option<FailureAction>,
    pub message: String,
}

impl Constitution {
    /// Compute the content hash of this constitution.
    pub fn compute_hash(&self) -> Result<Hash256, GovernanceError> {
        let canonical = serde_json::to_vec(&self.documents)
            .map_err(|_| GovernanceError::Serialization("failed to encode constitution".into()))?;
        Ok(Hash256::digest(&canonical))
    }

    /// Evaluate all constraints against a proposed action (TNC-04: synchronous).
    ///
    /// Returns a list of constraint results. If any constraint with `Block` failure
    /// action is violated, the action MUST NOT proceed.
    pub fn evaluate_constraints(
        &self,
        class: &DecisionClass,
        delegation_depth: u32,
        quorum_size: Option<u32>,
        approval_threshold: Option<u32>,
        monetary_amount: Option<u64>,
        has_human_signer: bool,
    ) -> Vec<ConstraintResult> {
        let mut results = Vec::new();

        for doc in &self.documents {
            for constraint in &doc.constraints {
                let result = self.evaluate_single_constraint(
                    constraint,
                    class,
                    delegation_depth,
                    quorum_size,
                    approval_threshold,
                    monetary_amount,
                    has_human_signer,
                );
                results.push(result);
            }
        }

        results
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_single_constraint(
        &self,
        constraint: &Constraint,
        class: &DecisionClass,
        delegation_depth: u32,
        quorum_size: Option<u32>,
        approval_threshold: Option<u32>,
        monetary_amount: Option<u64>,
        has_human_signer: bool,
    ) -> ConstraintResult {
        let (satisfied, message) = match &constraint.expression {
            ConstraintExpression::RequireHumanGate { decision_class } => {
                if decision_class == class {
                    (
                        has_human_signer,
                        if has_human_signer {
                            "Human gate satisfied".to_string()
                        } else {
                            format!(
                                "Human gate required for {:?} decisions but no human signer present",
                                class
                            )
                        },
                    )
                } else {
                    (true, "Not applicable to this decision class".to_string())
                }
            }
            ConstraintExpression::RequireMinQuorum {
                decision_class,
                minimum,
            } => {
                if decision_class == class {
                    let met = quorum_size.is_some_and(|q| q >= *minimum);
                    (
                        met,
                        if met {
                            format!("Quorum of {} met", minimum)
                        } else {
                            format!(
                                "Minimum quorum of {} required, got {:?}",
                                minimum, quorum_size
                            )
                        },
                    )
                } else {
                    (true, "Not applicable to this decision class".to_string())
                }
            }
            ConstraintExpression::RequireApprovalThreshold {
                decision_class,
                threshold_pct,
            } => {
                if decision_class == class {
                    let met = approval_threshold.is_none_or(|t| t >= *threshold_pct);
                    (
                        met,
                        format!("Approval threshold {}% required", threshold_pct),
                    )
                } else {
                    (true, "Not applicable".to_string())
                }
            }
            ConstraintExpression::RequireMonetaryCap {
                decision_class,
                max_cents,
            } => {
                if decision_class == class {
                    let met = monetary_amount.is_none_or(|a| a <= *max_cents);
                    (
                        met,
                        if met {
                            format!(
                                "Within monetary cap of ${}.{:02}",
                                *max_cents / 100,
                                *max_cents % 100
                            )
                        } else {
                            format!(
                                "Exceeds monetary cap of ${}.{:02}",
                                *max_cents / 100,
                                *max_cents % 100
                            )
                        },
                    )
                } else {
                    (true, "Not applicable".to_string())
                }
            }
            ConstraintExpression::RequireConflictDisclosure { decision_class } => {
                if decision_class == class {
                    // Conflict disclosure is checked at the decision level, not here
                    (
                        true,
                        "Conflict disclosure check deferred to decision".to_string(),
                    )
                } else {
                    (true, "Not applicable".to_string())
                }
            }
            ConstraintExpression::MaxDelegationDepth { max_depth } => {
                let met = delegation_depth <= *max_depth;
                (
                    met,
                    if met {
                        format!(
                            "Delegation depth {} within max {}",
                            delegation_depth, max_depth
                        )
                    } else {
                        format!(
                            "Delegation depth {} exceeds maximum {}",
                            delegation_depth, max_depth
                        )
                    },
                )
            }
        };

        ConstraintResult {
            constraint_id: constraint.id.clone(),
            satisfied,
            failure_action: if satisfied {
                None
            } else {
                Some(constraint.failure_action.clone())
            },
            message,
        }
    }

    /// Check if any blocking constraint is violated.
    /// Returns Err if any Block-level constraint fails (TNC-04).
    pub fn check_blocking_constraints(
        &self,
        class: &DecisionClass,
        delegation_depth: u32,
        quorum_size: Option<u32>,
        approval_threshold: Option<u32>,
        monetary_amount: Option<u64>,
        has_human_signer: bool,
    ) -> Result<Vec<ConstraintResult>, GovernanceError> {
        let results = self.evaluate_constraints(
            class,
            delegation_depth,
            quorum_size,
            approval_threshold,
            monetary_amount,
            has_human_signer,
        );

        for r in &results {
            if !r.satisfied {
                if let Some(FailureAction::Block) = &r.failure_action {
                    return Err(GovernanceError::ConstitutionalViolation {
                        constraint_id: r.constraint_id.clone(),
                        reason: r.message.clone(),
                    });
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hlc(ms: u64) -> Timestamp {
        Timestamp {
            physical_ms: ms,
            logical: 0,
        }
    }

    fn test_constitution() -> Constitution {
        Constitution {
            tenant_id: "tenant-1".to_string(),
            version: SemVer::new(1, 0, 0),
            hash: Hash256::ZERO,
            documents: vec![ConstitutionalDocument {
                id: "bylaws-v1".to_string(),
                precedence: PrecedenceLevel::Bylaws,
                content: serde_json::json!({"title": "Test Bylaws"}),
                constraints: vec![
                    Constraint {
                        id: "C-001".to_string(),
                        description: "Strategic decisions require human gate".to_string(),
                        expression: ConstraintExpression::RequireHumanGate {
                            decision_class: DecisionClass::Strategic,
                        },
                        failure_action: FailureAction::Block,
                    },
                    Constraint {
                        id: "C-002".to_string(),
                        description: "Min quorum of 3 for strategic".to_string(),
                        expression: ConstraintExpression::RequireMinQuorum {
                            decision_class: DecisionClass::Strategic,
                            minimum: 3,
                        },
                        failure_action: FailureAction::Block,
                    },
                    Constraint {
                        id: "C-003".to_string(),
                        description: "Max delegation depth 5".to_string(),
                        expression: ConstraintExpression::MaxDelegationDepth { max_depth: 5 },
                        failure_action: FailureAction::Block,
                    },
                ],
            }],
            decision_classes: vec![],
            human_gate_classes: vec![DecisionClass::Strategic, DecisionClass::Constitutional],
            emergency_authorities: vec![],
            default_delegation_expiry_hours: 720,
            max_delegation_depth: 5,
            created_at: test_hlc(1000),
            signatures: vec![],
        }
    }

    #[test]
    fn test_tnc04_blocking_constraint_human_gate() {
        let c = test_constitution();

        // Strategic without human signer — should block
        let result = c.check_blocking_constraints(
            &DecisionClass::Strategic,
            1,
            Some(5),
            None,
            None,
            false, // no human signer
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ConstitutionalViolation { .. }
        ));

        // Strategic with human signer — should pass
        let result =
            c.check_blocking_constraints(&DecisionClass::Strategic, 1, Some(5), None, None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quorum_constraint() {
        let c = test_constitution();

        // Strategic with quorum of 2 (< 3 required) — should block
        let result =
            c.check_blocking_constraints(&DecisionClass::Strategic, 1, Some(2), None, None, true);
        assert!(result.is_err());

        // Strategic with quorum of 3 — should pass
        let result =
            c.check_blocking_constraints(&DecisionClass::Strategic, 1, Some(3), None, None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_delegation_depth_constraint() {
        let c = test_constitution();

        // Depth 6 exceeds max 5 — should block
        let result =
            c.check_blocking_constraints(&DecisionClass::Operational, 6, None, None, None, true);
        assert!(result.is_err());

        // Depth 5 — should pass
        let result =
            c.check_blocking_constraints(&DecisionClass::Operational, 5, None, None, None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_operational_not_affected_by_strategic_constraints() {
        let c = test_constitution();

        // Operational decisions don't need human gate or quorum=3
        let result =
            c.check_blocking_constraints(&DecisionClass::Operational, 1, None, None, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_precedence_ordering() {
        assert!(PrecedenceLevel::Articles > PrecedenceLevel::Bylaws);
        assert!(PrecedenceLevel::Bylaws > PrecedenceLevel::Resolutions);
        assert!(PrecedenceLevel::Resolutions > PrecedenceLevel::Charters);
        assert!(PrecedenceLevel::Charters > PrecedenceLevel::Policies);
    }

    #[test]
    fn test_custom_constraint_eq_pass() {
        let mut ctx = exo_core::DeterministicMap::new();
        ctx.insert("role".to_string(), "auditor".to_string());
        let constraints = vec![CustomConstraint {
            id: "C-EQ".to_string(),
            description: "Role must be auditor".to_string(),
            expression: Expr::Eq(
                Box::new(Expr::Variable("role".to_string())),
                Box::new(Expr::Literal("auditor".to_string())),
            ),
        }];
        assert!(evaluate_custom_constraints(&constraints, &ctx).is_ok());
    }

    #[test]
    fn test_custom_constraint_eq_fail() {
        let mut ctx = exo_core::DeterministicMap::new();
        ctx.insert("role".to_string(), "user".to_string());
        let constraints = vec![CustomConstraint {
            id: "C-EQ".to_string(),
            description: "Role must be auditor".to_string(),
            expression: Expr::Eq(
                Box::new(Expr::Variable("role".to_string())),
                Box::new(Expr::Literal("auditor".to_string())),
            ),
        }];
        assert!(evaluate_custom_constraints(&constraints, &ctx).is_err());
    }

    #[test]
    fn test_custom_constraint_gt_pass() {
        let mut ctx = exo_core::DeterministicMap::new();
        ctx.insert("amount".to_string(), "100".to_string());
        let constraints = vec![CustomConstraint {
            id: "C-GT".to_string(),
            description: "Amount > 50".to_string(),
            expression: Expr::GreaterThan(
                Box::new(Expr::Variable("amount".to_string())),
                Box::new(Expr::Literal("50".to_string())),
            ),
        }];
        assert!(evaluate_custom_constraints(&constraints, &ctx).is_ok());
    }

    #[test]
    fn test_custom_constraint_missing_variable() {
        let ctx = exo_core::DeterministicMap::new();
        let constraints = vec![CustomConstraint {
            id: "C-MISSING".to_string(),
            description: "Requires amount".to_string(),
            expression: Expr::GreaterThan(
                Box::new(Expr::Variable("amount".to_string())),
                Box::new(Expr::Literal("50".to_string())),
            ),
        }];
        let res = evaluate_custom_constraints(&constraints, &ctx);
        assert!(matches!(
            res.unwrap_err(),
            GovernanceError::ConstitutionalViolation { constraint_id, .. } if constraint_id == "MISSING_VAR"
        ));
    }

    #[test]
    fn test_complex_custom_constraint_evaluation() {
        let mut ctx = exo_core::DeterministicMap::new();
        ctx.insert("dept".to_string(), "finance_dept".to_string());
        ctx.insert("level".to_string(), "5".to_string());

        // dept contains "finance" AND level > 3
        // We simulate AND with nesting or multiple constraints.
        // Actually, let's use two constraints.
        let constraints = vec![
            CustomConstraint {
                id: "C-COMPLEX-1".to_string(),
                description: "Dept must contain finance".to_string(),
                expression: Expr::Contains(
                    Box::new(Expr::Variable("dept".to_string())),
                    Box::new(Expr::Literal("finance".to_string())),
                ),
            },
            CustomConstraint {
                id: "C-COMPLEX-2".to_string(),
                description: "Level > 3".to_string(),
                expression: Expr::GreaterThan(
                    Box::new(Expr::Variable("level".to_string())),
                    Box::new(Expr::Literal("3".to_string())),
                ),
            },
        ];
        assert!(evaluate_custom_constraints(&constraints, &ctx).is_ok());

        ctx.insert("level".to_string(), "2".to_string());
        assert!(evaluate_custom_constraints(&constraints, &ctx).is_err());
    }
}

//! Pure PRD04 layer hygiene scoring and planning contracts.
//!
//! This module is intentionally side-effect free. It scores layer edges,
//! proposes auditable hygiene actions, and filters retrieval candidates without
//! writing state or exposing any hard-delete action.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};

/// Plan schema emitted by this pure PRD04 planner.
pub const LAYERED_HYGIENE_PLAN_SCHEMA_VERSION: &str = "dagdb_layered_hygiene_plan_v1";
/// Retrieval hygiene report schema emitted by this pure PRD04 planner.
pub const LAYERED_RETRIEVAL_HYGIENE_SCHEMA_VERSION: &str = "dagdb_layered_retrieval_hygiene_v1";
/// Default active same-layer graph edge budget per layer.
pub const DEFAULT_SAME_LAYER_ACTIVE_EDGE_BUDGET: usize = 64;
/// Default active cross-layer layer edge budget per layer.
pub const DEFAULT_CROSS_LAYER_ACTIVE_EDGE_BUDGET: usize = 24;

const MAX_BASIS_POINTS: u16 = 10_000;
const AUTHORITY_WEIGHT_PERCENT: u16 = 25;
const FRESHNESS_WEIGHT_PERCENT: u16 = 20;
const RETRIEVAL_USE_WEIGHT_PERCENT: u16 = 20;
const ROUTE_UTILITY_WEIGHT_PERCENT: u16 = 20;
const RECEIPT_WEIGHT_BPS: u16 = 1_500;

/// Layer edge budget class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerHygieneEdgeScope {
    /// Ordinary graph edge whose endpoints are in the same layer.
    SameLayerGraphEdge,
    /// Layer edge that crosses from one layer to another.
    CrossLayerLayerEdge,
}

impl LayerHygieneEdgeScope {
    /// Stable storage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameLayerGraphEdge => "same_layer_graph_edge",
            Self::CrossLayerLayerEdge => "cross_layer_layer_edge",
        }
    }
}

/// Current hygiene state of an edge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerHygieneEdgeState {
    /// Edge is active and eligible for retrieval.
    #[default]
    Active,
    /// Edge is retained for provenance but excluded by default.
    Demoted,
    /// Edge is retained as tombstoned history and excluded by default.
    Tombstoned,
}

impl LayerHygieneEdgeState {
    /// Stable storage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Demoted => "demoted",
            Self::Tombstoned => "tombstoned",
        }
    }
}

impl FromStr for LayerHygieneEdgeState {
    type Err = LayerHygieneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "demoted" => Ok(Self::Demoted),
            "tombstoned" => Ok(Self::Tombstoned),
            _ => Err(LayerHygieneError::InvalidHygieneState {
                state: value.to_owned(),
            }),
        }
    }
}

/// Contradiction and supersession evidence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerHygieneEvidenceState {
    /// No contradiction or supersession evidence is known.
    Current,
    /// Edge is contradicted but not superseded.
    Contradicted,
    /// Edge is superseded by newer evidence.
    Superseded,
    /// Edge is both contradicted and superseded.
    ContradictedAndSuperseded,
}

impl LayerHygieneEvidenceState {
    /// Stable storage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Contradicted => "contradicted",
            Self::Superseded => "superseded",
            Self::ContradictedAndSuperseded => "contradicted_and_superseded",
        }
    }

    #[must_use]
    const fn is_superseded(self) -> bool {
        matches!(self, Self::Superseded | Self::ContradictedAndSuperseded)
    }
}

/// Advisory PRD04 action. There is deliberately no delete variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerHygieneActionKind {
    /// Keep an active edge.
    Keep,
    /// Demote an edge while preserving provenance and receipts.
    Demote,
    /// Record a tombstone while preserving provenance and receipts.
    Tombstone,
    /// Relink to a superseding edge while preserving the old edge.
    Relink,
    /// Refresh a rollup summary because topology or health changed.
    RollupRefresh,
    /// No mutation is proposed.
    NoOp,
}

impl LayerHygieneActionKind {
    /// Stable storage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Demote => "demote",
            Self::Tombstone => "tombstone",
            Self::Relink => "relink",
            Self::RollupRefresh => "rollup_refresh",
            Self::NoOp => "no_op",
        }
    }
}

/// Deterministic policy inputs for PRD04 hygiene.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerHygienePolicy {
    /// Max active same-layer graph edges retained per layer.
    pub same_layer_active_edge_budget: usize,
    /// Max active cross-layer layer edges retained per layer.
    pub cross_layer_active_edge_budget: usize,
    /// Retrieval-use count that maps to the full retrieval-use component.
    pub retrieval_use_saturation_count: u32,
    /// Selection count that maps to the full child-layer health component.
    pub child_layer_selection_saturation_count: u32,
    /// Consecutive retrieval windows without selected refs/edges before stale.
    pub stale_child_layer_window_count: u32,
    /// Active edges below this score are demoted when unprotected.
    pub low_score_demote_threshold_bps: u16,
    /// Superseded edges at or below this score may be tombstoned when receipted.
    pub tombstone_score_threshold_bps: u16,
}

impl Default for LayerHygienePolicy {
    fn default() -> Self {
        Self {
            same_layer_active_edge_budget: DEFAULT_SAME_LAYER_ACTIVE_EDGE_BUDGET,
            cross_layer_active_edge_budget: DEFAULT_CROSS_LAYER_ACTIVE_EDGE_BUDGET,
            retrieval_use_saturation_count: 12,
            child_layer_selection_saturation_count: 8,
            stale_child_layer_window_count: 3,
            low_score_demote_threshold_bps: 3_500,
            tombstone_score_threshold_bps: 2_000,
        }
    }
}

impl LayerHygienePolicy {
    /// Return the active edge budget for a scope.
    #[must_use]
    pub const fn budget_for(&self, edge_scope: LayerHygieneEdgeScope) -> usize {
        match edge_scope {
            LayerHygieneEdgeScope::SameLayerGraphEdge => self.same_layer_active_edge_budget,
            LayerHygieneEdgeScope::CrossLayerLayerEdge => self.cross_layer_active_edge_budget,
        }
    }

    fn validate(&self) -> Result<(), LayerHygieneError> {
        if self.same_layer_active_edge_budget == 0 {
            return Err(LayerHygieneError::InvalidPolicy {
                field: "same_layer_active_edge_budget",
                reason: "budget_must_be_positive",
            });
        }
        if self.cross_layer_active_edge_budget == 0 {
            return Err(LayerHygieneError::InvalidPolicy {
                field: "cross_layer_active_edge_budget",
                reason: "budget_must_be_positive",
            });
        }
        if self.retrieval_use_saturation_count == 0 {
            return Err(LayerHygieneError::InvalidPolicy {
                field: "retrieval_use_saturation_count",
                reason: "saturation_must_be_positive",
            });
        }
        if self.child_layer_selection_saturation_count == 0 {
            return Err(LayerHygieneError::InvalidPolicy {
                field: "child_layer_selection_saturation_count",
                reason: "saturation_must_be_positive",
            });
        }
        if self.low_score_demote_threshold_bps > MAX_BASIS_POINTS {
            return Err(LayerHygieneError::InvalidPolicy {
                field: "low_score_demote_threshold_bps",
                reason: "basis_points_out_of_range",
            });
        }
        if self.tombstone_score_threshold_bps > MAX_BASIS_POINTS {
            return Err(LayerHygieneError::InvalidPolicy {
                field: "tombstone_score_threshold_bps",
                reason: "basis_points_out_of_range",
            });
        }
        Ok(())
    }
}

/// Input row for scoring and planning one edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerHygieneEdge {
    /// Tenant scope.
    pub tenant_id: String,
    /// Namespace scope.
    pub namespace: String,
    /// Layer whose budget owns this edge.
    pub layer_id: String,
    /// Edge identifier.
    pub edge_id: String,
    /// Budget class for this edge.
    pub edge_scope: LayerHygieneEdgeScope,
    /// Source layer identifier.
    pub from_layer_id: String,
    /// Target layer identifier.
    pub to_layer_id: String,
    /// Existing hygiene state.
    pub state: LayerHygieneEdgeState,
    /// Source authority score, 0..=10000 basis points.
    pub authority_score_bps: u16,
    /// Freshness score, 0..=10000 basis points.
    pub freshness_score_bps: u16,
    /// Count of retrieval selections in the caller's deterministic window.
    pub retrieval_use_count: u32,
    /// Route utility score, 0..=10000 basis points.
    pub route_utility_score_bps: u16,
    /// Contradiction/supersession state.
    pub evidence_state: LayerHygieneEvidenceState,
    /// Optional receipt/provenance identifier.
    pub receipt_id: Option<String>,
    /// Required route or citation anchor protected from ordinary demotion.
    pub required_route_anchor: bool,
    /// Optional superseding edge target for relink actions.
    pub relink_target_edge_id: Option<String>,
    /// Safe evidence handles supporting the score.
    pub evidence_refs: Vec<String>,
}

impl LayerHygieneEdge {
    /// True when the edge has a receipt/provenance handle.
    #[must_use]
    pub fn receipt_present(&self) -> bool {
        self.receipt_id.is_some()
    }
}

/// Layer snapshot used for child-layer health and rollup refresh planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerHygieneLayerSnapshot {
    /// Tenant scope.
    pub tenant_id: String,
    /// Namespace scope.
    pub namespace: String,
    /// Layer identifier.
    pub layer_id: String,
    /// Relative layer path for reports.
    pub layer_path: String,
    /// Selected refs in the caller's deterministic retrieval window.
    pub selected_ref_count: u32,
    /// Selected edges in the caller's deterministic retrieval window.
    pub selected_edge_count: u32,
    /// Consecutive retrieval windows with no selected refs/edges.
    pub stale_retrieval_window_count: u32,
    /// True when parent/child bindings indicate orphan risk.
    pub orphan_risk: bool,
    /// True when the rollup summary is stale.
    pub rollup_stale: bool,
    /// True when layer membership changed materially.
    pub membership_changed: bool,
}

/// Deterministic score breakdown for one edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerEdgeScore {
    /// Edge identifier.
    pub edge_id: String,
    /// Layer whose budget owns the edge.
    pub layer_id: String,
    /// Budget class.
    pub edge_scope: LayerHygieneEdgeScope,
    /// Authority contribution.
    pub authority_component_bps: u16,
    /// Freshness contribution.
    pub freshness_component_bps: u16,
    /// Retrieval-use contribution.
    pub retrieval_use_component_bps: u16,
    /// Route-utility contribution.
    pub route_utility_component_bps: u16,
    /// Receipt-presence contribution.
    pub receipt_component_bps: u16,
    /// Contradiction/supersession penalty.
    pub contradiction_penalty_bps: u16,
    /// Final score, 0..=10000.
    pub total_score_bps: u16,
    /// Whether a receipt/provenance handle is present.
    pub receipt_present: bool,
    /// Whether this edge is a required route/citation anchor.
    pub required_route_anchor: bool,
    /// Contradiction/supersession state used for scoring.
    pub evidence_state: LayerHygieneEvidenceState,
}

/// Child-layer health score and observable flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerHealthScore {
    /// Layer identifier.
    pub layer_id: String,
    /// Relative layer path.
    pub layer_path: String,
    /// Health score, 0..=10000.
    pub health_score_bps: u16,
    /// True when repeated retrieval windows selected no refs/edges.
    pub stale_child_layer: bool,
    /// True when parent/child bindings indicate orphan risk.
    pub orphan_risk: bool,
    /// True when a rollup refresh should be emitted.
    pub rollup_refresh_required: bool,
}

/// Advisory action emitted by the planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerHygieneAction {
    /// Action kind.
    pub action_kind: LayerHygieneActionKind,
    /// Tenant scope.
    pub tenant_id: String,
    /// Namespace scope.
    pub namespace: String,
    /// Affected layer.
    pub layer_id: String,
    /// Affected edge, when this is an edge action.
    pub edge_id: Option<String>,
    /// Edge scope, when this is an edge action.
    pub edge_scope: Option<LayerHygieneEdgeScope>,
    /// Edge score, when this is an edge action.
    pub score_bps: Option<u16>,
    /// Stable machine-readable reason.
    pub reason: String,
    /// Superseding edge target for relink actions.
    pub relink_target_edge_id: Option<String>,
    /// True for every PRD04 action in this module.
    pub preserves_history: bool,
}

impl LayerHygieneAction {
    /// This type cannot represent hard deletion.
    #[must_use]
    pub const fn hard_delete(&self) -> bool {
        false
    }
}

/// Active edge count before and after advisory planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerEdgeBudgetCount {
    /// Tenant scope.
    pub tenant_id: String,
    /// Namespace scope.
    pub namespace: String,
    /// Layer identifier.
    pub layer_id: String,
    /// Budget class.
    pub edge_scope: LayerHygieneEdgeScope,
    /// Active edge count before the plan.
    pub active_before: usize,
    /// Active edge count after applying advisory actions.
    pub active_after: usize,
    /// Configured budget.
    pub budget: usize,
}

/// Full pure planning report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerHygienePlan {
    /// Plan schema version.
    pub schema_version: String,
    /// Policy used for the plan.
    pub policy: LayerHygienePolicy,
    /// Deterministic edge scores.
    pub scored_edges: Vec<LayerEdgeScore>,
    /// Deterministic child-layer health scores.
    pub layer_health_scores: Vec<LayerHealthScore>,
    /// Advisory actions. None can hard-delete.
    pub actions: Vec<LayerHygieneAction>,
    /// Action counts keyed by stable action label.
    pub action_counts: BTreeMap<String, usize>,
    /// Active edge counts before and after the advisory plan.
    pub budget_counts: Vec<LayerEdgeBudgetCount>,
}

/// Retrieval-visible hygiene report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerRetrievalHygieneReport {
    /// Report schema version.
    pub schema_version: String,
    /// Active edge IDs selected under per-layer budgets.
    pub selected_active_edge_ids: Vec<String>,
    /// Active edge IDs excluded only because a budget was full.
    pub excluded_over_budget_edge_ids: Vec<String>,
    /// Demoted edge IDs excluded from retrieval.
    pub excluded_demoted_edge_ids: Vec<String>,
    /// Tombstoned edge IDs excluded from retrieval.
    pub excluded_tombstoned_edge_ids: Vec<String>,
}

/// Fail-closed validation and planning errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "error_kind")]
pub enum LayerHygieneError {
    /// A policy field is invalid.
    InvalidPolicy {
        /// Field name.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A required field was missing or blank.
    MissingRequiredField {
        /// Field name.
        field: &'static str,
    },
    /// A supplied field contains unsafe material.
    UnsafeField {
        /// Field name.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A basis-point score was outside 0..=10000.
    ScoreOutOfRange {
        /// Field name.
        field: &'static str,
        /// Supplied value.
        value: u16,
    },
    /// Edge IDs must be unique within a plan.
    DuplicateEdgeId {
        /// Duplicate edge ID.
        edge_id: String,
    },
    /// Layer IDs must be unique within layer snapshots.
    DuplicateLayerId {
        /// Duplicate layer ID.
        layer_id: String,
    },
    /// A layer snapshot and edge disagree on tenant or namespace.
    LayerScopeMismatch {
        /// Layer identifier.
        layer_id: String,
        /// Edge identifier.
        edge_id: String,
    },
    /// Required route anchors alone exceed the configured active edge budget.
    ProtectedRouteAnchorBudgetExceeded {
        /// Layer identifier.
        layer_id: String,
        /// Budget class.
        edge_scope: LayerHygieneEdgeScope,
        /// Protected count.
        protected_count: usize,
        /// Configured budget.
        budget: usize,
    },
    /// A retrieval hygiene state was not one of active/demoted/tombstoned.
    InvalidHygieneState {
        /// Supplied state value.
        state: String,
    },
}

impl fmt::Display for LayerHygieneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy { field, reason } => {
                write!(formatter, "invalid_layer_hygiene_policy: {field}: {reason}")
            }
            Self::MissingRequiredField { field } => {
                write!(formatter, "missing_required_layer_hygiene_field: {field}")
            }
            Self::UnsafeField { field, reason } => {
                write!(formatter, "unsafe_layer_hygiene_field: {field}: {reason}")
            }
            Self::ScoreOutOfRange { field, value } => {
                write!(
                    formatter,
                    "layer_hygiene_score_out_of_range: {field}: {value}"
                )
            }
            Self::DuplicateEdgeId { edge_id } => {
                write!(formatter, "duplicate_layer_hygiene_edge_id: {edge_id}")
            }
            Self::DuplicateLayerId { layer_id } => {
                write!(formatter, "duplicate_layer_hygiene_layer_id: {layer_id}")
            }
            Self::LayerScopeMismatch { layer_id, edge_id } => write!(
                formatter,
                "layer_hygiene_scope_mismatch: layer_id={layer_id} edge_id={edge_id}"
            ),
            Self::ProtectedRouteAnchorBudgetExceeded {
                layer_id,
                edge_scope,
                protected_count,
                budget,
            } => write!(
                formatter,
                "protected_route_anchor_budget_exceeded: layer_id={layer_id} edge_scope={} protected_count={protected_count} budget={budget}",
                edge_scope.as_str()
            ),
            Self::InvalidHygieneState { state } => {
                write!(formatter, "invalid_layer_hygiene_state: {state}")
            }
        }
    }
}

impl Error for LayerHygieneError {}

/// Score layer edges without mutating state.
pub fn score_layer_edges(
    edges: &[LayerHygieneEdge],
    policy: &LayerHygienePolicy,
) -> Result<Vec<LayerEdgeScore>, LayerHygieneError> {
    policy.validate()?;
    validate_edges(edges)?;

    let mut scores = Vec::with_capacity(edges.len());
    for edge in edges {
        scores.push(score_edge(edge, policy)?);
    }
    scores.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    Ok(scores)
}

/// Score child layers without mutating state.
pub fn score_child_layer_health(
    layers: &[LayerHygieneLayerSnapshot],
    policy: &LayerHygienePolicy,
) -> Result<Vec<LayerHealthScore>, LayerHygieneError> {
    policy.validate()?;
    validate_layers(layers)?;

    let mut scores = Vec::with_capacity(layers.len());
    for layer in layers {
        let selection_score = saturated_count_bps(
            layer
                .selected_ref_count
                .saturating_add(layer.selected_edge_count),
            policy.child_layer_selection_saturation_count,
        );
        let stale_child_layer = layer.selected_ref_count == 0
            && layer.selected_edge_count == 0
            && layer.stale_retrieval_window_count >= policy.stale_child_layer_window_count;
        let mut health = selection_score;
        if stale_child_layer {
            health = health.saturating_sub(3_000);
        }
        if layer.orphan_risk {
            health = health.saturating_sub(3_000);
        }
        if layer.rollup_stale {
            health = health.saturating_sub(2_000);
        }
        scores.push(LayerHealthScore {
            layer_id: layer.layer_id.clone(),
            layer_path: layer.layer_path.clone(),
            health_score_bps: health,
            stale_child_layer,
            orphan_risk: layer.orphan_risk,
            rollup_refresh_required: layer.rollup_stale || layer.membership_changed,
        });
    }
    scores.sort_by(|left, right| left.layer_id.cmp(&right.layer_id));
    Ok(scores)
}

/// Build a non-mutating PRD04 hygiene plan.
pub fn plan_layer_hygiene(
    layers: &[LayerHygieneLayerSnapshot],
    edges: &[LayerHygieneEdge],
    policy: &LayerHygienePolicy,
) -> Result<LayerHygienePlan, LayerHygieneError> {
    policy.validate()?;
    validate_layers(layers)?;
    validate_edges(edges)?;
    validate_edge_layer_scopes(layers, edges)?;

    let scored_edges = score_layer_edges(edges, policy)?;
    let score_by_edge_id = scored_edges
        .iter()
        .map(|score| (score.edge_id.clone(), score))
        .collect::<BTreeMap<_, _>>();
    let layer_health_scores = score_child_layer_health(layers, policy)?;
    let mut actions_by_key = BTreeMap::new();
    let mut changed_layers = BTreeSet::new();
    let mut protected_counts = BTreeMap::<BudgetGroupKey, usize>::new();
    let mut budget_candidates = BTreeMap::<BudgetGroupKey, Vec<&LayerHygieneEdge>>::new();
    let mut active_before = BTreeMap::<BudgetGroupKey, usize>::new();

    for edge in sorted_edges(edges) {
        let group_key = BudgetGroupKey::from_edge(edge);
        if edge.state == LayerHygieneEdgeState::Active {
            increment_count(&mut active_before, group_key.clone());
        }
        let Some(score) = score_by_edge_id.get(&edge.edge_id) else {
            continue;
        };

        match edge.state {
            LayerHygieneEdgeState::Tombstoned => {
                insert_edge_action(
                    &mut actions_by_key,
                    edge,
                    score,
                    LayerHygieneActionKind::NoOp,
                    "already_tombstoned",
                    None,
                );
            }
            LayerHygieneEdgeState::Demoted => {
                if edge.evidence_state.is_superseded() && edge.relink_target_edge_id.is_some() {
                    insert_edge_action(
                        &mut actions_by_key,
                        edge,
                        score,
                        LayerHygieneActionKind::Relink,
                        "demoted_edge_has_superseding_relink",
                        edge.relink_target_edge_id.clone(),
                    );
                    changed_layers.insert(group_key);
                } else {
                    insert_edge_action(
                        &mut actions_by_key,
                        edge,
                        score,
                        LayerHygieneActionKind::NoOp,
                        "already_demoted",
                        None,
                    );
                }
            }
            LayerHygieneEdgeState::Active => {
                let mut state = PlanActiveEdgeState {
                    actions_by_key: &mut actions_by_key,
                    changed_layers: &mut changed_layers,
                    protected_counts: &mut protected_counts,
                    budget_candidates: &mut budget_candidates,
                };
                plan_active_edge(edge, score, group_key, policy, &mut state);
            }
        }
    }

    enforce_budgets(
        policy,
        &score_by_edge_id,
        protected_counts,
        budget_candidates,
        &mut actions_by_key,
        &mut changed_layers,
    )?;
    insert_rollup_actions(layers, &changed_layers, &mut actions_by_key);

    let actions = actions_by_key.into_values().collect::<Vec<_>>();
    let budget_counts = build_budget_counts(policy, &active_before, &actions);
    Ok(LayerHygienePlan {
        schema_version: LAYERED_HYGIENE_PLAN_SCHEMA_VERSION.to_owned(),
        policy: policy.clone(),
        scored_edges,
        layer_health_scores,
        action_counts: count_actions(&actions),
        actions,
        budget_counts,
    })
}

/// Build a retrieval-visible hygiene report without mutating state.
pub fn build_layered_retrieval_hygiene_report(
    edges: &[LayerHygieneEdge],
    policy: &LayerHygienePolicy,
) -> Result<LayerRetrievalHygieneReport, LayerHygieneError> {
    policy.validate()?;
    validate_edges(edges)?;

    let scored_edges = score_layer_edges(edges, policy)?;
    let score_by_edge_id = scored_edges
        .iter()
        .map(|score| (score.edge_id.clone(), score))
        .collect::<BTreeMap<_, _>>();
    let mut active_by_group = BTreeMap::<BudgetGroupKey, Vec<&LayerHygieneEdge>>::new();
    let mut excluded_demoted_edge_ids = Vec::new();
    let mut excluded_tombstoned_edge_ids = Vec::new();

    for edge in sorted_edges(edges) {
        match edge.state {
            LayerHygieneEdgeState::Active => {
                active_by_group
                    .entry(BudgetGroupKey::from_edge(edge))
                    .or_default()
                    .push(edge);
            }
            LayerHygieneEdgeState::Demoted => excluded_demoted_edge_ids.push(edge.edge_id.clone()),
            LayerHygieneEdgeState::Tombstoned => {
                excluded_tombstoned_edge_ids.push(edge.edge_id.clone());
            }
        }
    }

    let mut selected_active_edge_ids = Vec::new();
    let mut excluded_over_budget_edge_ids = Vec::new();
    for (group_key, mut group_edges) in active_by_group {
        sort_edges_by_score_desc(&mut group_edges, &score_by_edge_id);
        let budget = policy.budget_for(group_key.edge_scope);
        for (index, edge) in group_edges.into_iter().enumerate() {
            if index < budget {
                selected_active_edge_ids.push(edge.edge_id.clone());
            } else {
                excluded_over_budget_edge_ids.push(edge.edge_id.clone());
            }
        }
    }

    selected_active_edge_ids.sort();
    excluded_over_budget_edge_ids.sort();
    excluded_demoted_edge_ids.sort();
    excluded_tombstoned_edge_ids.sort();

    Ok(LayerRetrievalHygieneReport {
        schema_version: LAYERED_RETRIEVAL_HYGIENE_SCHEMA_VERSION.to_owned(),
        selected_active_edge_ids,
        excluded_over_budget_edge_ids,
        excluded_demoted_edge_ids,
        excluded_tombstoned_edge_ids,
    })
}

struct PlanActiveEdgeState<'edges, 'state> {
    actions_by_key: &'state mut BTreeMap<String, LayerHygieneAction>,
    changed_layers: &'state mut BTreeSet<BudgetGroupKey>,
    protected_counts: &'state mut BTreeMap<BudgetGroupKey, usize>,
    budget_candidates: &'state mut BTreeMap<BudgetGroupKey, Vec<&'edges LayerHygieneEdge>>,
}

fn plan_active_edge<'edges>(
    edge: &'edges LayerHygieneEdge,
    score: &LayerEdgeScore,
    group_key: BudgetGroupKey,
    policy: &LayerHygienePolicy,
    state: &mut PlanActiveEdgeState<'edges, '_>,
) {
    if edge.evidence_state.is_superseded() {
        if let Some(relink_target_edge_id) = &edge.relink_target_edge_id {
            insert_edge_action(
                &mut *state.actions_by_key,
                edge,
                score,
                LayerHygieneActionKind::Relink,
                "superseded_edge_relink",
                Some(relink_target_edge_id.clone()),
            );
        } else if edge.receipt_present()
            && score.total_score_bps <= policy.tombstone_score_threshold_bps
        {
            insert_edge_action(
                &mut *state.actions_by_key,
                edge,
                score,
                LayerHygieneActionKind::Tombstone,
                "superseded_receipted_edge_tombstone",
                None,
            );
        } else {
            insert_edge_action(
                &mut *state.actions_by_key,
                edge,
                score,
                LayerHygieneActionKind::Demote,
                "superseded_edge_demote",
                None,
            );
        }
        state.changed_layers.insert(group_key);
        return;
    }

    if edge.required_route_anchor {
        insert_edge_action(
            &mut *state.actions_by_key,
            edge,
            score,
            LayerHygieneActionKind::Keep,
            "required_route_anchor",
            None,
        );
        increment_count(&mut *state.protected_counts, group_key);
        return;
    }

    if edge.evidence_state == LayerHygieneEvidenceState::Contradicted {
        insert_edge_action(
            &mut *state.actions_by_key,
            edge,
            score,
            LayerHygieneActionKind::Demote,
            "contradicted_edge_demote",
            None,
        );
        state.changed_layers.insert(group_key);
        return;
    }

    if score.total_score_bps < policy.low_score_demote_threshold_bps {
        insert_edge_action(
            &mut *state.actions_by_key,
            edge,
            score,
            LayerHygieneActionKind::Demote,
            "low_score_edge_demote",
            None,
        );
        state.changed_layers.insert(group_key);
        return;
    }

    state
        .budget_candidates
        .entry(group_key)
        .or_default()
        .push(edge);
}

fn enforce_budgets(
    policy: &LayerHygienePolicy,
    score_by_edge_id: &BTreeMap<String, &LayerEdgeScore>,
    protected_counts: BTreeMap<BudgetGroupKey, usize>,
    mut budget_candidates: BTreeMap<BudgetGroupKey, Vec<&LayerHygieneEdge>>,
    actions_by_key: &mut BTreeMap<String, LayerHygieneAction>,
    changed_layers: &mut BTreeSet<BudgetGroupKey>,
) -> Result<(), LayerHygieneError> {
    for (group_key, protected_count) in &protected_counts {
        let budget = policy.budget_for(group_key.edge_scope);
        if *protected_count > budget {
            return Err(LayerHygieneError::ProtectedRouteAnchorBudgetExceeded {
                layer_id: group_key.layer_id.clone(),
                edge_scope: group_key.edge_scope,
                protected_count: *protected_count,
                budget,
            });
        }
    }

    for (group_key, group_edges) in &mut budget_candidates {
        sort_edges_by_score_desc(group_edges, score_by_edge_id);
        let protected_count = protected_counts.get(group_key).copied().unwrap_or(0);
        let budget = policy.budget_for(group_key.edge_scope);
        let open_slots = budget.saturating_sub(protected_count);
        for (index, edge) in group_edges.iter().enumerate() {
            let Some(score) = score_by_edge_id.get(&edge.edge_id).copied() else {
                continue;
            };
            if index < open_slots {
                insert_edge_action(
                    actions_by_key,
                    edge,
                    score,
                    LayerHygieneActionKind::Keep,
                    "within_layer_budget",
                    None,
                );
            } else {
                insert_edge_action(
                    actions_by_key,
                    edge,
                    score,
                    LayerHygieneActionKind::Demote,
                    "over_layer_edge_budget",
                    None,
                );
                changed_layers.insert(group_key.clone());
            }
        }
    }
    Ok(())
}

fn insert_rollup_actions(
    layers: &[LayerHygieneLayerSnapshot],
    changed_layers: &BTreeSet<BudgetGroupKey>,
    actions_by_key: &mut BTreeMap<String, LayerHygieneAction>,
) {
    let layers_by_id = layers
        .iter()
        .map(|layer| (layer.layer_id.clone(), layer))
        .collect::<BTreeMap<_, _>>();
    let mut rollup_layers = BTreeSet::<(String, String, String, String)>::new();
    for layer in layers {
        if layer.rollup_stale || layer.membership_changed {
            rollup_layers.insert((
                layer.tenant_id.clone(),
                layer.namespace.clone(),
                layer.layer_id.clone(),
                "rollup_stale_or_membership_changed".to_owned(),
            ));
        }
    }
    for group_key in changed_layers {
        let reason = if layers_by_id.contains_key(&group_key.layer_id) {
            "active_edge_set_changed"
        } else {
            "active_edge_set_changed_without_layer_snapshot"
        };
        rollup_layers.insert((
            group_key.tenant_id.clone(),
            group_key.namespace.clone(),
            group_key.layer_id.clone(),
            reason.to_owned(),
        ));
    }

    for (tenant_id, namespace, layer_id, reason) in rollup_layers {
        actions_by_key.insert(
            format!("rollup:{tenant_id}:{namespace}:{layer_id}"),
            LayerHygieneAction {
                action_kind: LayerHygieneActionKind::RollupRefresh,
                tenant_id,
                namespace,
                layer_id,
                edge_id: None,
                edge_scope: None,
                score_bps: None,
                reason,
                relink_target_edge_id: None,
                preserves_history: true,
            },
        );
    }
}

fn build_budget_counts(
    policy: &LayerHygienePolicy,
    active_before: &BTreeMap<BudgetGroupKey, usize>,
    actions: &[LayerHygieneAction],
) -> Vec<LayerEdgeBudgetCount> {
    let mut active_after = BTreeMap::<BudgetGroupKey, usize>::new();
    for action in actions {
        if action.action_kind != LayerHygieneActionKind::Keep {
            continue;
        }
        let Some(edge_scope) = action.edge_scope else {
            continue;
        };
        increment_count(
            &mut active_after,
            BudgetGroupKey {
                tenant_id: action.tenant_id.clone(),
                namespace: action.namespace.clone(),
                layer_id: action.layer_id.clone(),
                edge_scope,
            },
        );
    }

    let mut keys = active_before.keys().cloned().collect::<BTreeSet<_>>();
    keys.extend(active_after.keys().cloned());

    let mut counts = Vec::with_capacity(keys.len());
    for key in keys {
        counts.push(LayerEdgeBudgetCount {
            tenant_id: key.tenant_id.clone(),
            namespace: key.namespace.clone(),
            layer_id: key.layer_id.clone(),
            edge_scope: key.edge_scope,
            active_before: active_before.get(&key).copied().unwrap_or(0),
            active_after: active_after.get(&key).copied().unwrap_or(0),
            budget: policy.budget_for(key.edge_scope),
        });
    }
    counts
}

fn count_actions(actions: &[LayerHygieneAction]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for action in actions {
        let count = counts
            .entry(action.action_kind.as_str().to_owned())
            .or_insert(0);
        *count += 1;
    }
    counts
}

fn insert_edge_action(
    actions_by_key: &mut BTreeMap<String, LayerHygieneAction>,
    edge: &LayerHygieneEdge,
    score: &LayerEdgeScore,
    action_kind: LayerHygieneActionKind,
    reason: &str,
    relink_target_edge_id: Option<String>,
) {
    actions_by_key.insert(
        format!("edge:{}", edge.edge_id),
        LayerHygieneAction {
            action_kind,
            tenant_id: edge.tenant_id.clone(),
            namespace: edge.namespace.clone(),
            layer_id: edge.layer_id.clone(),
            edge_id: Some(edge.edge_id.clone()),
            edge_scope: Some(edge.edge_scope),
            score_bps: Some(score.total_score_bps),
            reason: reason.to_owned(),
            relink_target_edge_id,
            preserves_history: true,
        },
    );
}

fn score_edge(
    edge: &LayerHygieneEdge,
    policy: &LayerHygienePolicy,
) -> Result<LayerEdgeScore, LayerHygieneError> {
    validate_score("authority_score_bps", edge.authority_score_bps)?;
    validate_score("freshness_score_bps", edge.freshness_score_bps)?;
    validate_score("route_utility_score_bps", edge.route_utility_score_bps)?;

    let authority_component_bps = weighted_bps(edge.authority_score_bps, AUTHORITY_WEIGHT_PERCENT);
    let freshness_component_bps = weighted_bps(edge.freshness_score_bps, FRESHNESS_WEIGHT_PERCENT);
    let retrieval_use_component_bps = weighted_bps(
        saturated_count_bps(
            edge.retrieval_use_count,
            policy.retrieval_use_saturation_count,
        ),
        RETRIEVAL_USE_WEIGHT_PERCENT,
    );
    let route_utility_component_bps =
        weighted_bps(edge.route_utility_score_bps, ROUTE_UTILITY_WEIGHT_PERCENT);
    let receipt_component_bps = if edge.receipt_present() {
        RECEIPT_WEIGHT_BPS
    } else {
        0
    };
    let contradiction_penalty_bps = contradiction_penalty(edge.evidence_state);
    let raw_score = authority_component_bps
        .saturating_add(freshness_component_bps)
        .saturating_add(retrieval_use_component_bps)
        .saturating_add(route_utility_component_bps)
        .saturating_add(receipt_component_bps);
    let total_score_bps = raw_score.saturating_sub(contradiction_penalty_bps);

    Ok(LayerEdgeScore {
        edge_id: edge.edge_id.clone(),
        layer_id: edge.layer_id.clone(),
        edge_scope: edge.edge_scope,
        authority_component_bps,
        freshness_component_bps,
        retrieval_use_component_bps,
        route_utility_component_bps,
        receipt_component_bps,
        contradiction_penalty_bps,
        total_score_bps,
        receipt_present: edge.receipt_present(),
        required_route_anchor: edge.required_route_anchor,
        evidence_state: edge.evidence_state,
    })
}

fn contradiction_penalty(evidence_state: LayerHygieneEvidenceState) -> u16 {
    match evidence_state {
        LayerHygieneEvidenceState::Current => 0,
        LayerHygieneEvidenceState::Contradicted => 3_000,
        LayerHygieneEvidenceState::Superseded => 4_500,
        LayerHygieneEvidenceState::ContradictedAndSuperseded => 6_000,
    }
}

fn weighted_bps(value_bps: u16, weight_percent: u16) -> u16 {
    let value = u32::from(value_bps);
    let weight = u32::from(weight_percent);
    let weighted = (value.saturating_mul(weight)) / 100;
    u16::try_from(weighted).unwrap_or(u16::MAX)
}

fn saturated_count_bps(count: u32, saturation_count: u32) -> u16 {
    let capped = count.min(saturation_count);
    let value = capped
        .saturating_mul(u32::from(MAX_BASIS_POINTS))
        .checked_div(saturation_count)
        .unwrap_or(0);
    u16::try_from(value.min(u32::from(MAX_BASIS_POINTS))).unwrap_or(MAX_BASIS_POINTS)
}

fn validate_score(field: &'static str, value: u16) -> Result<(), LayerHygieneError> {
    if value > MAX_BASIS_POINTS {
        return Err(LayerHygieneError::ScoreOutOfRange { field, value });
    }
    Ok(())
}

fn validate_layers(layers: &[LayerHygieneLayerSnapshot]) -> Result<(), LayerHygieneError> {
    let mut seen_layer_ids = BTreeSet::new();
    for layer in layers {
        validate_required_token("tenant_id", &layer.tenant_id)?;
        validate_required_token("namespace", &layer.namespace)?;
        validate_required_token("layer_id", &layer.layer_id)?;
        validate_relative_path("layer_path", &layer.layer_path)?;
        if !seen_layer_ids.insert(layer.layer_id.clone()) {
            return Err(LayerHygieneError::DuplicateLayerId {
                layer_id: layer.layer_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_edges(edges: &[LayerHygieneEdge]) -> Result<(), LayerHygieneError> {
    let mut seen_edge_ids = BTreeSet::new();
    for edge in edges {
        validate_required_token("tenant_id", &edge.tenant_id)?;
        validate_required_token("namespace", &edge.namespace)?;
        validate_required_token("layer_id", &edge.layer_id)?;
        validate_required_token("edge_id", &edge.edge_id)?;
        validate_required_token("from_layer_id", &edge.from_layer_id)?;
        validate_required_token("to_layer_id", &edge.to_layer_id)?;
        validate_score("authority_score_bps", edge.authority_score_bps)?;
        validate_score("freshness_score_bps", edge.freshness_score_bps)?;
        validate_score("route_utility_score_bps", edge.route_utility_score_bps)?;
        if !seen_edge_ids.insert(edge.edge_id.clone()) {
            return Err(LayerHygieneError::DuplicateEdgeId {
                edge_id: edge.edge_id.clone(),
            });
        }
        if let Some(receipt_id) = &edge.receipt_id {
            validate_required_token("receipt_id", receipt_id)?;
        }
        if let Some(relink_target_edge_id) = &edge.relink_target_edge_id {
            validate_required_token("relink_target_edge_id", relink_target_edge_id)?;
        }
        validate_safe_refs("evidence_refs", &edge.evidence_refs)?;
    }
    Ok(())
}

fn validate_edge_layer_scopes(
    layers: &[LayerHygieneLayerSnapshot],
    edges: &[LayerHygieneEdge],
) -> Result<(), LayerHygieneError> {
    let layer_scope = layers
        .iter()
        .map(|layer| {
            (
                layer.layer_id.clone(),
                (layer.tenant_id.clone(), layer.namespace.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for edge in edges {
        if let Some((tenant_id, namespace)) = layer_scope.get(&edge.layer_id)
            && (tenant_id != &edge.tenant_id || namespace != &edge.namespace)
        {
            return Err(LayerHygieneError::LayerScopeMismatch {
                layer_id: edge.layer_id.clone(),
                edge_id: edge.edge_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_safe_refs(field: &'static str, values: &[String]) -> Result<(), LayerHygieneError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_required_token(field, value)?;
        if !seen.insert(value) {
            return Err(LayerHygieneError::UnsafeField {
                field,
                reason: "duplicate_value",
            });
        }
    }
    Ok(())
}

fn validate_required_token(field: &'static str, value: &str) -> Result<(), LayerHygieneError> {
    if value.is_empty() || value.trim().is_empty() {
        return Err(LayerHygieneError::MissingRequiredField { field });
    }
    if value != value.trim() {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "leading_or_trailing_whitespace",
        });
    }
    validate_safe_text(field, value)?;
    if value.contains('/') || value.contains('\\') || value.contains('~') || value.contains("..") {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "unsafe_token_path_material",
        });
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.' | '@'))
    {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "unsafe_token_character",
        });
    }
    Ok(())
}

fn validate_relative_path(field: &'static str, value: &str) -> Result<(), LayerHygieneError> {
    if value.is_empty() || value.trim().is_empty() {
        return Err(LayerHygieneError::MissingRequiredField { field });
    }
    if value != value.trim() {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "leading_or_trailing_whitespace",
        });
    }
    validate_safe_text(field, value)?;
    if value.starts_with('/') || value.starts_with('~') || value.ends_with('/') {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "unsafe_relative_path_boundary",
        });
    }
    if value.contains('\\') || value.contains("//") {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "unsafe_relative_path_separator",
        });
    }
    for part in value.split('/') {
        validate_required_token(field, part)?;
    }
    Ok(())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), LayerHygieneError> {
    if value.len() > 256 {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "value_too_long",
        });
    }
    if !value.chars().all(|ch| ch.is_ascii_graphic()) {
        return Err(LayerHygieneError::UnsafeField {
            field,
            reason: "control_or_non_ascii_character",
        });
    }
    let normalized = value.to_ascii_lowercase();
    for forbidden in FORBIDDEN_FIELD_FRAGMENTS {
        if normalized.contains(forbidden) {
            return Err(LayerHygieneError::UnsafeField {
                field,
                reason: "forbidden_field_fragment",
            });
        }
    }
    Ok(())
}

const FORBIDDEN_FIELD_FRAGMENTS: &[&str] = &[
    "/users/",
    "\\users\\",
    "/home/",
    "/tmp/",
    "~/",
    "authorization",
    "begin private key",
    "database_url",
    ".env",
    "password",
    "postgres://",
    "postgresql://",
    "private key-----",
    "raw_body",
    "raw_document_body",
    "raw_markdown",
    "raw_model_output",
    "raw_private_payload",
    "raw_prompt",
    "secret",
    "sk-proj-",
    "source_excerpt",
];

fn sorted_edges(edges: &[LayerHygieneEdge]) -> Vec<&LayerHygieneEdge> {
    let mut sorted = edges.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    sorted
}

fn sort_edges_by_score_desc(
    edges: &mut Vec<&LayerHygieneEdge>,
    score_by_edge_id: &BTreeMap<String, &LayerEdgeScore>,
) {
    edges.sort_by(|left, right| {
        let left_score = score_by_edge_id
            .get(&left.edge_id)
            .map_or(0, |score| score.total_score_bps);
        let right_score = score_by_edge_id
            .get(&right.edge_id)
            .map_or(0, |score| score.total_score_bps);
        match right_score.cmp(&left_score) {
            Ordering::Equal => left.edge_id.cmp(&right.edge_id),
            ordering => ordering,
        }
    });
}

fn increment_count(map: &mut BTreeMap<BudgetGroupKey, usize>, key: BudgetGroupKey) {
    let count = map.entry(key).or_insert(0);
    *count += 1;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BudgetGroupKey {
    tenant_id: String,
    namespace: String,
    layer_id: String,
    edge_scope: LayerHygieneEdgeScope,
}

impl BudgetGroupKey {
    fn from_edge(edge: &LayerHygieneEdge) -> Self {
        Self {
            tenant_id: edge.tenant_id.clone(),
            namespace: edge.namespace.clone(),
            layer_id: edge.layer_id.clone(),
            edge_scope: edge.edge_scope,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layered_edge_scoring_uses_default_budgets_and_score_components() {
        let policy = LayerHygienePolicy::default();
        assert_eq!(
            policy.same_layer_active_edge_budget,
            DEFAULT_SAME_LAYER_ACTIVE_EDGE_BUDGET
        );
        assert_eq!(
            policy.cross_layer_active_edge_budget,
            DEFAULT_CROSS_LAYER_ACTIVE_EDGE_BUDGET
        );

        let edge = edge("edge-a");
        let scores = score_layer_edges(&[edge], &policy).expect("score succeeds");
        let score = &scores[0];

        assert_eq!(score.receipt_component_bps, RECEIPT_WEIGHT_BPS);
        assert_eq!(score.contradiction_penalty_bps, 0);
        assert!(score.total_score_bps > 8_000);
    }

    #[test]
    fn layered_hygiene_stable_labels_and_scope_budgets_are_contracts() {
        let policy = LayerHygienePolicy {
            same_layer_active_edge_budget: 7,
            cross_layer_active_edge_budget: 3,
            ..LayerHygienePolicy::default()
        };

        assert_eq!(
            policy.budget_for(LayerHygieneEdgeScope::SameLayerGraphEdge),
            7
        );
        assert_eq!(
            policy.budget_for(LayerHygieneEdgeScope::CrossLayerLayerEdge),
            3
        );

        for (scope, label) in [
            (
                LayerHygieneEdgeScope::SameLayerGraphEdge,
                "same_layer_graph_edge",
            ),
            (
                LayerHygieneEdgeScope::CrossLayerLayerEdge,
                "cross_layer_layer_edge",
            ),
        ] {
            assert_eq!(scope.as_str(), label);
        }

        for (state, label) in [
            (LayerHygieneEdgeState::Active, "active"),
            (LayerHygieneEdgeState::Demoted, "demoted"),
            (LayerHygieneEdgeState::Tombstoned, "tombstoned"),
        ] {
            assert_eq!(state.as_str(), label);
        }

        for (state, label) in [
            (LayerHygieneEvidenceState::Current, "current"),
            (LayerHygieneEvidenceState::Contradicted, "contradicted"),
            (LayerHygieneEvidenceState::Superseded, "superseded"),
            (
                LayerHygieneEvidenceState::ContradictedAndSuperseded,
                "contradicted_and_superseded",
            ),
        ] {
            assert_eq!(state.as_str(), label);
        }
    }

    #[test]
    fn layered_hygiene_policy_validation_rejects_invalid_fields() {
        let mut policy = LayerHygienePolicy {
            same_layer_active_edge_budget: 0,
            ..LayerHygienePolicy::default()
        };
        assert_invalid_policy(
            policy,
            "same_layer_active_edge_budget",
            "budget_must_be_positive",
        );

        policy = LayerHygienePolicy {
            cross_layer_active_edge_budget: 0,
            ..LayerHygienePolicy::default()
        };
        assert_invalid_policy(
            policy,
            "cross_layer_active_edge_budget",
            "budget_must_be_positive",
        );

        policy = LayerHygienePolicy {
            retrieval_use_saturation_count: 0,
            ..LayerHygienePolicy::default()
        };
        assert_invalid_policy(
            policy,
            "retrieval_use_saturation_count",
            "saturation_must_be_positive",
        );

        policy = LayerHygienePolicy {
            child_layer_selection_saturation_count: 0,
            ..LayerHygienePolicy::default()
        };
        assert_invalid_policy(
            policy,
            "child_layer_selection_saturation_count",
            "saturation_must_be_positive",
        );

        policy = LayerHygienePolicy {
            low_score_demote_threshold_bps: MAX_BASIS_POINTS + 1,
            ..LayerHygienePolicy::default()
        };
        assert_invalid_policy(
            policy,
            "low_score_demote_threshold_bps",
            "basis_points_out_of_range",
        );

        policy = LayerHygienePolicy {
            tombstone_score_threshold_bps: MAX_BASIS_POINTS + 1,
            ..LayerHygienePolicy::default()
        };
        assert_invalid_policy(
            policy,
            "tombstone_score_threshold_bps",
            "basis_points_out_of_range",
        );
    }

    #[test]
    fn layered_hygiene_errors_render_stable_messages() {
        let cases = [
            (
                LayerHygieneError::InvalidPolicy {
                    field: "same_layer_active_edge_budget",
                    reason: "budget_must_be_positive",
                },
                "invalid_layer_hygiene_policy: same_layer_active_edge_budget: budget_must_be_positive",
            ),
            (
                LayerHygieneError::MissingRequiredField { field: "layer_id" },
                "missing_required_layer_hygiene_field: layer_id",
            ),
            (
                LayerHygieneError::UnsafeField {
                    field: "evidence_refs",
                    reason: "duplicate_value",
                },
                "unsafe_layer_hygiene_field: evidence_refs: duplicate_value",
            ),
            (
                LayerHygieneError::ScoreOutOfRange {
                    field: "authority_score_bps",
                    value: MAX_BASIS_POINTS + 1,
                },
                "layer_hygiene_score_out_of_range: authority_score_bps: 10001",
            ),
            (
                LayerHygieneError::DuplicateEdgeId {
                    edge_id: "edge-a".to_owned(),
                },
                "duplicate_layer_hygiene_edge_id: edge-a",
            ),
            (
                LayerHygieneError::DuplicateLayerId {
                    layer_id: "layer-a".to_owned(),
                },
                "duplicate_layer_hygiene_layer_id: layer-a",
            ),
            (
                LayerHygieneError::LayerScopeMismatch {
                    layer_id: "layer-a".to_owned(),
                    edge_id: "edge-a".to_owned(),
                },
                "layer_hygiene_scope_mismatch: layer_id=layer-a edge_id=edge-a",
            ),
            (
                LayerHygieneError::ProtectedRouteAnchorBudgetExceeded {
                    layer_id: "layer-a".to_owned(),
                    edge_scope: LayerHygieneEdgeScope::SameLayerGraphEdge,
                    protected_count: 2,
                    budget: 1,
                },
                "protected_route_anchor_budget_exceeded: layer_id=layer-a edge_scope=same_layer_graph_edge protected_count=2 budget=1",
            ),
            (
                LayerHygieneError::InvalidHygieneState {
                    state: "archived".to_owned(),
                },
                "invalid_layer_hygiene_state: archived",
            ),
        ];

        for (error, expected_message) in cases {
            assert_eq!(error.to_string(), expected_message);
        }
    }

    #[test]
    fn layered_edge_scoring_planner_emits_all_non_destructive_actions() {
        let policy = LayerHygienePolicy {
            same_layer_active_edge_budget: 8,
            cross_layer_active_edge_budget: 8,
            ..LayerHygienePolicy::default()
        };
        let mut keep = edge("edge-keep");
        keep.required_route_anchor = true;

        let mut demote = edge("edge-demote");
        demote.authority_score_bps = 0;
        demote.freshness_score_bps = 0;
        demote.retrieval_use_count = 0;
        demote.route_utility_score_bps = 0;
        demote.receipt_id = None;

        let mut relink = edge("edge-relink");
        relink.evidence_state = LayerHygieneEvidenceState::Superseded;
        relink.relink_target_edge_id = Some("edge-relink-target".to_owned());

        let mut tombstone = edge("edge-tombstone");
        tombstone.evidence_state = LayerHygieneEvidenceState::ContradictedAndSuperseded;
        tombstone.authority_score_bps = 0;
        tombstone.freshness_score_bps = 0;
        tombstone.retrieval_use_count = 0;
        tombstone.route_utility_score_bps = 0;

        let mut no_op = edge("edge-no-op");
        no_op.state = LayerHygieneEdgeState::Demoted;

        let plan = plan_layer_hygiene(
            &[LayerHygieneLayerSnapshot {
                tenant_id: "tenant-a".to_owned(),
                namespace: "default".to_owned(),
                layer_id: "layer-a".to_owned(),
                layer_path: "root/repository".to_owned(),
                selected_ref_count: 1,
                selected_edge_count: 1,
                stale_retrieval_window_count: 0,
                orphan_risk: false,
                rollup_stale: false,
                membership_changed: true,
            }],
            &[keep, demote, relink, tombstone, no_op],
            &policy,
        )
        .expect("plan succeeds");

        for action_kind in [
            LayerHygieneActionKind::Keep,
            LayerHygieneActionKind::Demote,
            LayerHygieneActionKind::Tombstone,
            LayerHygieneActionKind::Relink,
            LayerHygieneActionKind::RollupRefresh,
            LayerHygieneActionKind::NoOp,
        ] {
            assert!(
                plan.actions
                    .iter()
                    .any(|action| action.action_kind == action_kind),
                "missing action {action_kind:?}"
            );
        }
        assert!(plan.actions.iter().all(|action| action.preserves_history));
        assert!(plan.actions.iter().all(|action| !action.hard_delete()));
    }

    #[test]
    fn layered_hygiene_plan_handles_existing_tombstones_and_demoted_relinks() {
        let mut tombstoned = edge("edge-already-tombstoned");
        tombstoned.state = LayerHygieneEdgeState::Tombstoned;

        let mut demoted_relink = edge("edge-demoted-relink");
        demoted_relink.state = LayerHygieneEdgeState::Demoted;
        demoted_relink.evidence_state = LayerHygieneEvidenceState::Superseded;
        demoted_relink.relink_target_edge_id = Some("edge-current".to_owned());

        let plan = plan_layer_hygiene(
            &[],
            &[demoted_relink, tombstoned],
            &LayerHygienePolicy::default(),
        )
        .expect("plan succeeds");

        let tombstone_action = action_for_edge(&plan, "edge-already-tombstoned");
        assert_eq!(tombstone_action.action_kind, LayerHygieneActionKind::NoOp);
        assert_eq!(tombstone_action.reason, "already_tombstoned");

        let relink_action = action_for_edge(&plan, "edge-demoted-relink");
        assert_eq!(relink_action.action_kind, LayerHygieneActionKind::Relink);
        assert_eq!(
            relink_action.relink_target_edge_id.as_deref(),
            Some("edge-current")
        );
        assert_eq!(relink_action.reason, "demoted_edge_has_superseding_relink");
    }

    #[test]
    fn layered_hygiene_plan_demotes_superseded_and_contradicted_active_edges() {
        let mut superseded = edge("edge-superseded-demote");
        superseded.evidence_state = LayerHygieneEvidenceState::Superseded;
        superseded.receipt_id = None;

        let mut contradicted = edge("edge-contradicted-demote");
        contradicted.evidence_state = LayerHygieneEvidenceState::Contradicted;

        let plan = plan_layer_hygiene(
            &[],
            &[superseded, contradicted],
            &LayerHygienePolicy::default(),
        )
        .expect("plan succeeds");

        let superseded_action = action_for_edge(&plan, "edge-superseded-demote");
        assert_eq!(
            superseded_action.action_kind,
            LayerHygieneActionKind::Demote
        );
        assert_eq!(superseded_action.reason, "superseded_edge_demote");

        let contradicted_action = action_for_edge(&plan, "edge-contradicted-demote");
        assert_eq!(
            contradicted_action.action_kind,
            LayerHygieneActionKind::Demote
        );
        assert_eq!(contradicted_action.reason, "contradicted_edge_demote");

        let contradicted_score = plan
            .scored_edges
            .iter()
            .find(|score| score.edge_id == "edge-contradicted-demote")
            .expect("contradicted edge score");
        assert_eq!(contradicted_score.contradiction_penalty_bps, 3_000);
    }

    #[test]
    fn layered_edge_scoring_demotes_over_budget_edges_deterministically() {
        let policy = LayerHygienePolicy {
            same_layer_active_edge_budget: 2,
            cross_layer_active_edge_budget: 8,
            ..LayerHygienePolicy::default()
        };
        let mut first = edge("edge-001");
        first.authority_score_bps = 10_000;
        let mut second = edge("edge-002");
        second.authority_score_bps = 9_000;
        let mut third = edge("edge-003");
        third.authority_score_bps = 8_000;

        let plan = plan_layer_hygiene(&[], &[third, first, second], &policy).expect("plan");
        let keep_ids = action_edge_ids(&plan, LayerHygieneActionKind::Keep);
        let demote_ids = action_edge_ids(&plan, LayerHygieneActionKind::Demote);

        assert_eq!(keep_ids, vec!["edge-001", "edge-002"]);
        assert_eq!(demote_ids, vec!["edge-003"]);
        let budget = &plan.budget_counts[0];
        assert_eq!(budget.active_before, 3);
        assert_eq!(budget.active_after, 2);
        assert_eq!(budget.budget, 2);
    }

    #[test]
    fn layered_edge_scoring_fails_closed_when_route_anchors_exceed_budget() {
        let policy = LayerHygienePolicy {
            same_layer_active_edge_budget: 1,
            cross_layer_active_edge_budget: 8,
            ..LayerHygienePolicy::default()
        };
        let mut first = edge("edge-anchor-a");
        first.required_route_anchor = true;
        let mut second = edge("edge-anchor-b");
        second.required_route_anchor = true;

        let error = plan_layer_hygiene(&[], &[first, second], &policy)
            .expect_err("protected route anchors cannot be silently trimmed");

        assert!(matches!(
            error,
            LayerHygieneError::ProtectedRouteAnchorBudgetExceeded { .. }
        ));
    }

    #[test]
    fn layered_retrieval_hygiene_excludes_demoted_tombstoned_and_over_budget_edges() {
        let policy = LayerHygienePolicy {
            same_layer_active_edge_budget: 1,
            cross_layer_active_edge_budget: 8,
            ..LayerHygienePolicy::default()
        };
        let mut active = edge("edge-active");
        active.authority_score_bps = 10_000;
        let mut over_budget = edge("edge-over-budget");
        over_budget.authority_score_bps = 1_000;
        let mut demoted = edge("edge-demoted");
        demoted.state = LayerHygieneEdgeState::Demoted;
        let mut tombstoned = edge("edge-tombstoned");
        tombstoned.state = LayerHygieneEdgeState::Tombstoned;

        let report = build_layered_retrieval_hygiene_report(
            &[over_budget, tombstoned, active, demoted],
            &policy,
        )
        .expect("retrieval hygiene succeeds");

        assert_eq!(report.selected_active_edge_ids, vec!["edge-active"]);
        assert_eq!(
            report.excluded_over_budget_edge_ids,
            vec!["edge-over-budget"]
        );
        assert_eq!(report.excluded_demoted_edge_ids, vec!["edge-demoted"]);
        assert_eq!(report.excluded_tombstoned_edge_ids, vec!["edge-tombstoned"]);
    }

    #[test]
    fn layered_retrieval_hygiene_tie_breaks_equal_scores_by_edge_id() {
        let policy = LayerHygienePolicy {
            same_layer_active_edge_budget: 1,
            cross_layer_active_edge_budget: 8,
            ..LayerHygienePolicy::default()
        };
        let first_by_id = edge("edge-a");
        let second_by_id = edge("edge-b");

        let report = build_layered_retrieval_hygiene_report(&[second_by_id, first_by_id], &policy)
            .expect("retrieval hygiene succeeds");

        assert_eq!(report.selected_active_edge_ids, vec!["edge-a"]);
        assert_eq!(report.excluded_over_budget_edge_ids, vec!["edge-b"]);
    }

    #[test]
    fn layered_retrieval_hygiene_fails_closed_on_missing_ids_and_unsafe_fields() {
        let policy = LayerHygienePolicy::default();
        let mut missing_layer = edge("edge-missing-layer");
        missing_layer.layer_id.clear();

        assert!(matches!(
            build_layered_retrieval_hygiene_report(&[missing_layer], &policy),
            Err(LayerHygieneError::MissingRequiredField { field: "layer_id" })
        ));

        let mut unsafe_edge = edge("edge-unsafe");
        unsafe_edge.evidence_refs = vec!["raw_body".to_owned()];

        assert!(matches!(
            build_layered_retrieval_hygiene_report(&[unsafe_edge], &policy),
            Err(LayerHygieneError::UnsafeField {
                field: "evidence_refs",
                ..
            })
        ));
    }

    #[test]
    fn layered_hygiene_validation_rejects_duplicate_and_mismatched_scope_inputs() {
        let policy = LayerHygienePolicy::default();

        let duplicate_layer_error =
            score_child_layer_health(&[layer("layer-a"), layer("layer-a")], &policy)
                .expect_err("duplicate layer rejected");
        assert_eq!(
            duplicate_layer_error,
            LayerHygieneError::DuplicateLayerId {
                layer_id: "layer-a".to_owned()
            }
        );

        let duplicate_edge_error =
            build_layered_retrieval_hygiene_report(&[edge("edge-a"), edge("edge-a")], &policy)
                .expect_err("duplicate edge rejected");
        assert_eq!(
            duplicate_edge_error,
            LayerHygieneError::DuplicateEdgeId {
                edge_id: "edge-a".to_owned()
            }
        );

        let mut out_of_range_edge = edge("edge-out-of-range");
        out_of_range_edge.authority_score_bps = MAX_BASIS_POINTS + 1;
        let score_error = build_layered_retrieval_hygiene_report(&[out_of_range_edge], &policy)
            .expect_err("out-of-range score rejected");
        assert_eq!(
            score_error,
            LayerHygieneError::ScoreOutOfRange {
                field: "authority_score_bps",
                value: MAX_BASIS_POINTS + 1
            }
        );

        let mut mismatched_layer = layer("layer-a");
        mismatched_layer.tenant_id = "tenant-b".to_owned();
        let scope_error = plan_layer_hygiene(&[mismatched_layer], &[edge("edge-a")], &policy)
            .expect_err("scope mismatch rejected");
        assert_eq!(
            scope_error,
            LayerHygieneError::LayerScopeMismatch {
                layer_id: "layer-a".to_owned(),
                edge_id: "edge-a".to_owned()
            }
        );
    }

    #[test]
    fn layered_hygiene_validation_rejects_unsafe_tokens_refs_and_paths() {
        let mut duplicate_ref = edge("edge-duplicate-ref");
        duplicate_ref.evidence_refs = vec!["evidence-a".to_owned(), "evidence-a".to_owned()];
        assert_unsafe_edge(duplicate_ref, "evidence_refs", "duplicate_value");

        let mut whitespace_receipt = edge("edge-whitespace-receipt");
        whitespace_receipt.receipt_id = Some(" receipt-edge".to_owned());
        assert_unsafe_edge(
            whitespace_receipt,
            "receipt_id",
            "leading_or_trailing_whitespace",
        );

        let mut path_material = edge("edge-path-material");
        path_material.relink_target_edge_id = Some("target/edge".to_owned());
        assert_unsafe_edge(
            path_material,
            "relink_target_edge_id",
            "unsafe_token_path_material",
        );

        let mut unsafe_character = edge("edge-unsafe-character");
        unsafe_character.namespace = "default!".to_owned();
        assert_unsafe_edge(unsafe_character, "namespace", "unsafe_token_character");

        let mut too_long = edge("edge-too-long");
        too_long.edge_id = "a".repeat(257);
        assert_unsafe_edge(too_long, "edge_id", "value_too_long");

        let mut control_character = edge("edge-control-character");
        control_character.edge_id = "edge\ncontrol".to_owned();
        assert_unsafe_edge(
            control_character,
            "edge_id",
            "control_or_non_ascii_character",
        );

        assert_layer_path_error(
            " ",
            LayerHygieneError::MissingRequiredField {
                field: "layer_path",
            },
        );
        assert_layer_path_error(
            " root/repository",
            LayerHygieneError::UnsafeField {
                field: "layer_path",
                reason: "leading_or_trailing_whitespace",
            },
        );
        assert_layer_path_error(
            "/root/repository",
            LayerHygieneError::UnsafeField {
                field: "layer_path",
                reason: "unsafe_relative_path_boundary",
            },
        );
        assert_layer_path_error(
            "root//repository",
            LayerHygieneError::UnsafeField {
                field: "layer_path",
                reason: "unsafe_relative_path_separator",
            },
        );
    }

    #[test]
    fn layered_retrieval_hygiene_scores_stale_child_layers_and_rollup_refresh() {
        let policy = LayerHygienePolicy::default();
        let layers = vec![LayerHygieneLayerSnapshot {
            tenant_id: "tenant-a".to_owned(),
            namespace: "default".to_owned(),
            layer_id: "layer-a".to_owned(),
            layer_path: "root/repository".to_owned(),
            selected_ref_count: 0,
            selected_edge_count: 0,
            stale_retrieval_window_count: policy.stale_child_layer_window_count,
            orphan_risk: true,
            rollup_stale: true,
            membership_changed: false,
        }];

        let health = score_child_layer_health(&layers, &policy).expect("health score");

        assert!(health[0].stale_child_layer);
        assert!(health[0].orphan_risk);
        assert!(health[0].rollup_refresh_required);
        assert!(health[0].health_score_bps < 5_000);
    }

    fn assert_invalid_policy(
        policy: LayerHygienePolicy,
        expected_field: &'static str,
        expected_reason: &'static str,
    ) {
        let error = score_layer_edges(&[], &policy).expect_err("invalid policy must fail closed");
        assert_eq!(
            error,
            LayerHygieneError::InvalidPolicy {
                field: expected_field,
                reason: expected_reason
            }
        );
    }

    fn assert_unsafe_edge(
        edge: LayerHygieneEdge,
        expected_field: &'static str,
        expected_reason: &'static str,
    ) {
        let policy = LayerHygienePolicy::default();
        let error = build_layered_retrieval_hygiene_report(&[edge], &policy)
            .expect_err("unsafe edge must fail closed");
        assert_eq!(
            error,
            LayerHygieneError::UnsafeField {
                field: expected_field,
                reason: expected_reason
            }
        );
    }

    fn assert_layer_path_error(path: &str, expected_error: LayerHygieneError) {
        let policy = LayerHygienePolicy::default();
        let mut layer = layer("layer-path");
        layer.layer_path = path.to_owned();

        let error = score_child_layer_health(&[layer], &policy).expect_err("invalid path rejected");
        assert_eq!(error, expected_error);
    }

    fn action_for_edge<'plan>(
        plan: &'plan LayerHygienePlan,
        edge_id: &str,
    ) -> &'plan LayerHygieneAction {
        plan.actions
            .iter()
            .find(|action| action.edge_id.as_deref() == Some(edge_id))
            .expect("edge action")
    }

    fn action_edge_ids(plan: &LayerHygienePlan, kind: LayerHygieneActionKind) -> Vec<&str> {
        let mut ids = plan
            .actions
            .iter()
            .filter(|action| action.action_kind == kind)
            .filter_map(|action| action.edge_id.as_deref())
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }

    fn edge(edge_id: &str) -> LayerHygieneEdge {
        LayerHygieneEdge {
            tenant_id: "tenant-a".to_owned(),
            namespace: "default".to_owned(),
            layer_id: "layer-a".to_owned(),
            edge_id: edge_id.to_owned(),
            edge_scope: LayerHygieneEdgeScope::SameLayerGraphEdge,
            from_layer_id: "layer-a".to_owned(),
            to_layer_id: "layer-a".to_owned(),
            state: LayerHygieneEdgeState::Active,
            authority_score_bps: 8_000,
            freshness_score_bps: 8_000,
            retrieval_use_count: 12,
            route_utility_score_bps: 8_000,
            evidence_state: LayerHygieneEvidenceState::Current,
            receipt_id: Some(format!("receipt-{edge_id}")),
            required_route_anchor: false,
            relink_target_edge_id: None,
            evidence_refs: vec![format!("evidence-{edge_id}")],
        }
    }

    fn layer(layer_id: &str) -> LayerHygieneLayerSnapshot {
        LayerHygieneLayerSnapshot {
            tenant_id: "tenant-a".to_owned(),
            namespace: "default".to_owned(),
            layer_id: layer_id.to_owned(),
            layer_path: "root/repository".to_owned(),
            selected_ref_count: 1,
            selected_edge_count: 1,
            stale_retrieval_window_count: 0,
            orphan_risk: false,
            rollup_stale: false,
            membership_changed: false,
        }
    }
}

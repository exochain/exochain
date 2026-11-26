//! Pure PRD09 graph-governed layer creation policy.
//!
//! This module is intentionally side-effect free. It evaluates supplied graph
//! pressure metrics and returns a deterministic decision; persistence and
//! runtime mutation are handled by later surfaces.

use std::collections::BTreeSet;

use exo_core::Hash256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Policy schema version recorded by PRD09 decisions.
pub const LAYER_CREATION_POLICY_SCHEMA_VERSION: &str = "layer_creation_policy_v1";
/// Decision schema version recorded by PRD09 decisions.
pub const LAYER_CREATION_DECISION_SCHEMA_VERSION: &str = "layer_creation_decision_v1";
/// Repository/test policy version.
pub const LAYER_CREATION_POLICY_VERSION: &str = "dagdb-layer-creation-policy-v1";
/// Maximum accepted policy depth, with root at depth zero.
pub const LAYER_CREATION_MAX_DEPTH: u32 = 8;
/// Score threshold for automatic create/reuse decisions.
pub const LAYER_CREATION_CREATE_THRESHOLD_BP: u16 = 6_500;
/// Existing-child similarity threshold for reuse.
pub const LAYER_CREATION_REUSE_SIMILARITY_THRESHOLD_BP: u16 = 8_500;
/// Maximum child layers under a parent before operator review.
pub const LAYER_CREATION_MAX_CHILD_LAYERS_PER_PARENT: u32 = 16;
/// Memory count hard split trigger.
pub const LAYER_CREATION_MEMORY_COUNT_TRIGGER: u32 = 128;
/// Token pressure hard split trigger.
pub const LAYER_CREATION_TOKEN_PRESSURE_TRIGGER: u32 = 4_096;
/// Retrieval-use hard split trigger.
pub const LAYER_CREATION_RETRIEVAL_USE_TRIGGER_7D: u32 = 12;
/// Selected-ref hard split trigger paired with retrieval use.
pub const LAYER_CREATION_SELECTED_REF_TRIGGER_7D: u32 = 8;
/// Semantic spread hard split trigger.
pub const LAYER_CREATION_SEMANTIC_SPREAD_TRIGGER_BP: u16 = 6_500;
/// Candidate cluster size paired with semantic spread.
pub const LAYER_CREATION_CLUSTER_MEMORY_COUNT_TRIGGER: u32 = 8;
/// Unsupported-claim quality pressure trigger.
pub const LAYER_CREATION_UNSUPPORTED_CLAIM_TRIGGER_7D: u32 = 3;
/// Contradiction quality pressure trigger.
pub const LAYER_CREATION_CONTRADICTION_TRIGGER_7D: u32 = 2;
/// Same-layer edge pressure trigger.
pub const LAYER_CREATION_SAME_LAYER_EDGE_TRIGGER: u32 = 64;
/// Cross-layer edge pressure trigger.
pub const LAYER_CREATION_CROSS_LAYER_EDGE_TRIGGER: u32 = 24;
/// Low semantic spread threshold for trimming before splitting.
pub const LAYER_CREATION_LOW_SEMANTIC_SPREAD_BP: u16 = 3_500;
/// Size pressure weight.
pub const LAYER_CREATION_SIZE_WEIGHT_PERCENT: u16 = 30;
/// Graph connectivity pressure weight.
pub const LAYER_CREATION_GRAPH_WEIGHT_PERCENT: u16 = 20;
/// Retrieval pressure weight.
pub const LAYER_CREATION_RETRIEVAL_WEIGHT_PERCENT: u16 = 20;
/// Semantic spread pressure weight.
pub const LAYER_CREATION_SEMANTIC_WEIGHT_PERCENT: u16 = 15;
/// Quality pressure weight.
pub const LAYER_CREATION_QUALITY_WEIGHT_PERCENT: u16 = 10;
/// Hygiene pressure weight.
pub const LAYER_CREATION_HYGIENE_WEIGHT_PERCENT: u16 = 5;

const MAX_BASIS_POINTS: u16 = 10_000;
const CHILD_LAYER_ID_DOMAIN: &str = "layer_creation_policy_v1.child_layer_id";

/// Policy values used for threshold snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerCreationPolicyV1 {
    /// Stable policy version.
    pub policy_version: String,
    /// Maximum accepted layer depth.
    pub max_layer_depth: u32,
    /// Maximum child layers per parent before review.
    pub max_child_layers_per_parent: u32,
    /// Create threshold in basis points.
    pub create_threshold_bp: u16,
    /// Existing child reuse threshold in basis points.
    pub reuse_similarity_threshold_bp: u16,
    /// Direct-memory-count split trigger.
    pub memory_count_trigger: u32,
    /// Token pressure split trigger.
    pub token_pressure_trigger: u32,
    /// Retrieval-use split trigger.
    pub retrieval_use_trigger_7d: u32,
    /// Selected-ref split trigger.
    pub selected_ref_trigger_7d: u32,
    /// Semantic spread trigger.
    pub semantic_spread_trigger_bp: u16,
    /// Cluster count trigger paired with semantic spread.
    pub cluster_memory_count_trigger: u32,
    /// Unsupported-claim trigger.
    pub unsupported_claim_trigger_7d: u32,
    /// Contradiction trigger.
    pub contradiction_trigger_7d: u32,
    /// Same-layer edge trigger.
    pub same_layer_edge_trigger: u32,
    /// Cross-layer edge trigger.
    pub cross_layer_edge_trigger: u32,
    /// Low semantic spread trim threshold.
    pub low_semantic_spread_bp: u16,
    /// Size pressure weight.
    pub size_weight_percent: u16,
    /// Graph pressure weight.
    pub graph_weight_percent: u16,
    /// Retrieval pressure weight.
    pub retrieval_weight_percent: u16,
    /// Semantic spread weight.
    pub semantic_weight_percent: u16,
    /// Quality pressure weight.
    pub quality_weight_percent: u16,
    /// Hygiene pressure weight.
    pub hygiene_weight_percent: u16,
}

impl Default for LayerCreationPolicyV1 {
    fn default() -> Self {
        Self {
            policy_version: LAYER_CREATION_POLICY_VERSION.to_owned(),
            max_layer_depth: LAYER_CREATION_MAX_DEPTH,
            max_child_layers_per_parent: LAYER_CREATION_MAX_CHILD_LAYERS_PER_PARENT,
            create_threshold_bp: LAYER_CREATION_CREATE_THRESHOLD_BP,
            reuse_similarity_threshold_bp: LAYER_CREATION_REUSE_SIMILARITY_THRESHOLD_BP,
            memory_count_trigger: LAYER_CREATION_MEMORY_COUNT_TRIGGER,
            token_pressure_trigger: LAYER_CREATION_TOKEN_PRESSURE_TRIGGER, // pragma-allowlist-secret
            retrieval_use_trigger_7d: LAYER_CREATION_RETRIEVAL_USE_TRIGGER_7D,
            selected_ref_trigger_7d: LAYER_CREATION_SELECTED_REF_TRIGGER_7D,
            semantic_spread_trigger_bp: LAYER_CREATION_SEMANTIC_SPREAD_TRIGGER_BP,
            cluster_memory_count_trigger: LAYER_CREATION_CLUSTER_MEMORY_COUNT_TRIGGER,
            unsupported_claim_trigger_7d: LAYER_CREATION_UNSUPPORTED_CLAIM_TRIGGER_7D,
            contradiction_trigger_7d: LAYER_CREATION_CONTRADICTION_TRIGGER_7D,
            same_layer_edge_trigger: LAYER_CREATION_SAME_LAYER_EDGE_TRIGGER,
            cross_layer_edge_trigger: LAYER_CREATION_CROSS_LAYER_EDGE_TRIGGER,
            low_semantic_spread_bp: LAYER_CREATION_LOW_SEMANTIC_SPREAD_BP,
            size_weight_percent: LAYER_CREATION_SIZE_WEIGHT_PERCENT,
            graph_weight_percent: LAYER_CREATION_GRAPH_WEIGHT_PERCENT,
            retrieval_weight_percent: LAYER_CREATION_RETRIEVAL_WEIGHT_PERCENT,
            semantic_weight_percent: LAYER_CREATION_SEMANTIC_WEIGHT_PERCENT,
            quality_weight_percent: LAYER_CREATION_QUALITY_WEIGHT_PERCENT,
            hygiene_weight_percent: LAYER_CREATION_HYGIENE_WEIGHT_PERCENT,
        }
    }
}

/// Metrics and parent evidence for one layer creation candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerCreationCandidateV1 {
    /// Tenant scope for the candidate.
    pub tenant_id: String,
    /// Namespace scope for the candidate.
    pub namespace: String,
    /// Parent tenant scope.
    pub parent_tenant_id: String,
    /// Parent namespace scope.
    pub parent_namespace: String,
    /// Parent layer ID, required for child-layer claims.
    pub parent_layer_id: Option<Hash256>,
    /// Parent graph node ID, required for child-layer claims.
    pub parent_graph_node_id: Option<Hash256>,
    /// Parent layer path.
    pub parent_layer_path: String,
    /// Parent layer depth.
    pub parent_layer_depth: u32,
    /// Candidate cluster ID.
    pub candidate_cluster_id: String,
    /// Candidate label used to derive a child slug.
    pub candidate_label: String,
    /// Candidate child layer path.
    pub candidate_child_layer_path: String,
    /// Existing child layer ID when a reusable child already exists.
    pub existing_child_layer_id: Option<Hash256>,
    /// Whether caller supplied candidate evidence.
    pub candidate_evidence_hash_present: bool,
    /// Direct memory count under the candidate node or subgraph.
    pub direct_memory_count: u32,
    /// Memory count inside the candidate cluster.
    pub candidate_cluster_memory_count: u32,
    /// Active same-layer edge count.
    pub active_same_layer_edge_count: u32,
    /// Active cross-layer edge count.
    pub active_cross_layer_edge_count: u32,
    /// Selected token estimate.
    pub selected_token_estimate: u32,
    /// Retrieval-use count over seven days.
    pub retrieval_use_count_7d: u32,
    /// Selected-ref count over seven days.
    pub selected_ref_count_7d: u32,
    /// Selected-edge count over seven days.
    pub selected_edge_count_7d: u32,
    /// Topic entropy in basis points.
    pub topic_entropy_bp: u16,
    /// Unsupported-claim count over seven days.
    pub unsupported_claim_count_7d: u32,
    /// Contradiction count over seven days.
    pub contradiction_count_7d: u32,
    /// True when the layer rollup is stale.
    pub rollup_stale: bool,
    /// True when membership changed.
    pub membership_changed: bool,
    /// Existing child layer count under parent.
    pub child_layer_count_for_parent: u32,
    /// Similarity to existing child layer in basis points.
    pub child_layer_similarity_bp: u16,
}

/// Score components in basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerCreationScoreComponents {
    /// Size pressure score.
    pub size_pressure_bp: u16,
    /// Graph connectivity pressure score.
    pub graph_connectivity_pressure_bp: u16,
    /// Retrieval pressure score.
    pub retrieval_pressure_bp: u16,
    /// Semantic spread score.
    pub semantic_spread_bp: u16,
    /// Quality pressure score.
    pub quality_pressure_bp: u16,
    /// Hygiene pressure score.
    pub hygiene_pressure_bp: u16,
}

/// Final decision status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerCreationDecisionStatus {
    /// Candidate remains in the current layer.
    StayCurrentLayer,
    /// Existing child layer is reused.
    ReuseExistingChildLayer,
    /// New child layer is created.
    CreateChildLayer,
    /// Candidate must be trimmed before a split can be reconsidered.
    TrimBeforeSplit,
    /// Target depth exceeds policy limit.
    RejectOverDepth,
    /// Required parent evidence is missing.
    RejectMissingParent,
    /// Tenant or namespace scope does not match parent scope.
    RejectNamespaceScope,
    /// Parent has reached the child-layer review cap.
    OperatorReviewRequired,
}

impl LayerCreationDecisionStatus {
    /// Stable snake_case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StayCurrentLayer => "stay_current_layer",
            Self::ReuseExistingChildLayer => "reuse_existing_child_layer",
            Self::CreateChildLayer => "create_child_layer",
            Self::TrimBeforeSplit => "trim_before_split",
            Self::RejectOverDepth => "reject_over_depth",
            Self::RejectMissingParent => "reject_missing_parent",
            Self::RejectNamespaceScope => "reject_namespace_scope",
            Self::OperatorReviewRequired => "operator_review_required",
        }
    }
}

/// Evaluated layer creation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerCreationDecisionV1 {
    /// Decision schema.
    pub schema_version: String,
    /// Policy version.
    pub policy_version: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Namespace scope.
    pub namespace: String,
    /// Parent layer ID.
    pub parent_layer_id: Option<Hash256>,
    /// Parent graph node ID.
    pub parent_graph_node_id: Option<Hash256>,
    /// Parent layer path.
    pub parent_layer_path: String,
    /// Parent layer depth.
    pub parent_layer_depth: u32,
    /// Candidate cluster ID.
    pub candidate_cluster_id: String,
    /// Candidate child layer path.
    pub candidate_child_layer_path: String,
    /// Decision status.
    pub decision_status: LayerCreationDecisionStatus,
    /// Stable reason codes.
    pub decision_reason_codes: Vec<String>,
    /// Component scores.
    pub score_components_bp: LayerCreationScoreComponents,
    /// Total weighted score.
    pub total_creation_score_bp: u16,
    /// Hard trigger IDs.
    pub hard_trigger_ids: Vec<String>,
    /// Hard blocker IDs.
    pub hard_blocker_ids: Vec<String>,
    /// Policy threshold snapshot hash.
    pub threshold_snapshot_hash: String,
    /// Candidate evidence hash.
    pub candidate_evidence_hash: String,
    /// Deterministic child layer ID when create or reuse applies.
    pub deterministic_child_layer_id: Option<Hash256>,
    /// Decision hash over this payload excluding this field.
    pub decision_hash: String,
}

/// Policy validation or evaluation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LayerCreationPolicyError {
    /// Basis-point value exceeded 10,000.
    #[error("invalid_basis_points: {field}")]
    InvalidBasisPoints {
        /// Field name.
        field: &'static str,
    },
    /// Required scope string is empty.
    #[error("invalid_scope: {field}")]
    InvalidScope {
        /// Field name.
        field: &'static str,
    },
    /// Layer path is not a safe relative path.
    #[error("invalid_layer_path: {field}")]
    InvalidLayerPath {
        /// Field name.
        field: &'static str,
    },
    /// Policy hash material could not be serialized.
    #[error("layer_creation_hash_material_failed: {reason}")]
    HashMaterial {
        /// Stable serialization reason.
        reason: String,
    },
}

/// Build the repository/test policy.
#[must_use]
pub fn default_layer_creation_policy() -> LayerCreationPolicyV1 {
    LayerCreationPolicyV1::default()
}

/// Evaluate one layer creation candidate.
pub fn evaluate_layer_creation_candidate(
    policy: &LayerCreationPolicyV1,
    candidate: &LayerCreationCandidateV1,
) -> Result<LayerCreationDecisionV1, LayerCreationPolicyError> {
    validate_policy(policy)?;
    validate_candidate(candidate)?;

    let score_components = score_layer_creation_candidate(policy, candidate);
    let total_creation_score_bp = weighted_total_score(policy, score_components);
    let mut hard_trigger_ids = hard_triggers(policy, candidate);
    hard_trigger_ids.sort();
    let mut hard_blocker_ids = hard_blockers(policy, candidate);
    hard_blocker_ids.sort();
    let threshold_snapshot_hash = hash_json_hex(policy)?;
    let candidate_evidence_hash = hash_json_hex(candidate)?;
    let decision_status = select_decision_status(
        policy,
        candidate,
        total_creation_score_bp,
        &hard_trigger_ids,
        &hard_blocker_ids,
    );
    let deterministic_child_layer_id = match decision_status {
        LayerCreationDecisionStatus::CreateChildLayer
        | LayerCreationDecisionStatus::ReuseExistingChildLayer => Some(
            deterministic_child_layer_id(policy, candidate, &candidate_evidence_hash)?,
        ),
        _ => None,
    };
    let mut decision_reason_codes = decision_reason_codes(
        candidate,
        decision_status,
        total_creation_score_bp,
        &hard_trigger_ids,
        &hard_blocker_ids,
    );
    decision_reason_codes.sort();

    let mut decision = LayerCreationDecisionV1 {
        schema_version: LAYER_CREATION_DECISION_SCHEMA_VERSION.to_owned(),
        policy_version: policy.policy_version.clone(),
        tenant_id: candidate.tenant_id.clone(),
        namespace: candidate.namespace.clone(),
        parent_layer_id: candidate.parent_layer_id,
        parent_graph_node_id: candidate.parent_graph_node_id,
        parent_layer_path: candidate.parent_layer_path.clone(),
        parent_layer_depth: candidate.parent_layer_depth,
        candidate_cluster_id: candidate.candidate_cluster_id.clone(),
        candidate_child_layer_path: candidate.candidate_child_layer_path.clone(),
        decision_status,
        decision_reason_codes,
        score_components_bp: score_components,
        total_creation_score_bp,
        hard_trigger_ids,
        hard_blocker_ids,
        threshold_snapshot_hash,
        candidate_evidence_hash,
        deterministic_child_layer_id,
        decision_hash: String::new(),
    };
    decision.decision_hash = hash_json_hex(&decision)?;
    Ok(decision)
}

/// Compute deterministic score components.
#[must_use]
pub fn score_layer_creation_candidate(
    policy: &LayerCreationPolicyV1,
    candidate: &LayerCreationCandidateV1,
) -> LayerCreationScoreComponents {
    let size_pressure_bp = max_bp(
        ratio_bp(candidate.direct_memory_count, policy.memory_count_trigger),
        ratio_bp(
            candidate.selected_token_estimate,
            policy.token_pressure_trigger,
        ),
    );
    let graph_connectivity_pressure_bp = max_bp(
        ratio_bp(
            candidate.active_same_layer_edge_count,
            policy.same_layer_edge_trigger,
        ),
        ratio_bp(
            candidate.active_cross_layer_edge_count,
            policy.cross_layer_edge_trigger,
        ),
    );
    let retrieval_pressure_bp = max3_bp(
        ratio_bp(
            candidate.retrieval_use_count_7d,
            policy.retrieval_use_trigger_7d,
        ),
        ratio_bp(
            candidate.selected_ref_count_7d,
            policy.selected_ref_trigger_7d,
        ),
        ratio_bp(
            candidate.selected_edge_count_7d,
            policy.selected_ref_trigger_7d,
        ),
    );
    let semantic_spread_bp = max_bp(
        candidate.topic_entropy_bp,
        ratio_bp(
            candidate.candidate_cluster_memory_count,
            policy.cluster_memory_count_trigger,
        ),
    );
    let quality_pressure_bp = max_bp(
        ratio_bp(
            candidate.unsupported_claim_count_7d,
            policy.unsupported_claim_trigger_7d,
        ),
        ratio_bp(
            candidate.contradiction_count_7d,
            policy.contradiction_trigger_7d,
        ),
    );
    let hygiene_pressure_bp = if candidate.rollup_stale || candidate.membership_changed {
        MAX_BASIS_POINTS
    } else {
        0
    };
    LayerCreationScoreComponents {
        size_pressure_bp,
        graph_connectivity_pressure_bp,
        retrieval_pressure_bp,
        semantic_spread_bp,
        quality_pressure_bp,
        hygiene_pressure_bp,
    }
}

/// Generate the canonical child layer slug.
pub fn canonical_child_layer_slug(label: &str) -> Result<String, LayerCreationPolicyError> {
    let mut slug = String::new();
    let mut previous_dash = false;
    for ch in label.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if (ch.is_ascii_whitespace() || ch == '-' || ch == '_' || ch == '/')
            && !slug.is_empty()
            && !previous_dash
        {
            slug.push('-');
            previous_dash = true;
        }
        if slug.len() >= 64 {
            break;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        let fallback = sha256_hex(label.as_bytes());
        return Ok(format!("cluster-{}", &fallback[..16]));
    }
    validate_slug(&slug)?;
    Ok(slug)
}

fn validate_policy(policy: &LayerCreationPolicyV1) -> Result<(), LayerCreationPolicyError> {
    validate_scope_text(&policy.policy_version, "policy_version")?;
    for (field, value) in [
        ("create_threshold_bp", policy.create_threshold_bp),
        (
            "reuse_similarity_threshold_bp",
            policy.reuse_similarity_threshold_bp,
        ),
        (
            "semantic_spread_trigger_bp",
            policy.semantic_spread_trigger_bp,
        ),
        ("low_semantic_spread_bp", policy.low_semantic_spread_bp),
        ("size_weight_percent", policy.size_weight_percent),
        ("graph_weight_percent", policy.graph_weight_percent),
        ("retrieval_weight_percent", policy.retrieval_weight_percent),
        ("semantic_weight_percent", policy.semantic_weight_percent),
        ("quality_weight_percent", policy.quality_weight_percent),
        ("hygiene_weight_percent", policy.hygiene_weight_percent),
    ] {
        if value > MAX_BASIS_POINTS {
            return Err(LayerCreationPolicyError::InvalidBasisPoints { field });
        }
    }
    Ok(())
}

fn validate_candidate(
    candidate: &LayerCreationCandidateV1,
) -> Result<(), LayerCreationPolicyError> {
    validate_scope_text(&candidate.tenant_id, "tenant_id")?;
    validate_scope_text(&candidate.namespace, "namespace")?;
    validate_scope_text(&candidate.parent_tenant_id, "parent_tenant_id")?;
    validate_scope_text(&candidate.parent_namespace, "parent_namespace")?;
    validate_scope_text(&candidate.candidate_cluster_id, "candidate_cluster_id")?;
    validate_relative_path(&candidate.parent_layer_path, "parent_layer_path")?;
    validate_relative_path(
        &candidate.candidate_child_layer_path,
        "candidate_child_layer_path",
    )?;
    if candidate.topic_entropy_bp > MAX_BASIS_POINTS {
        return Err(LayerCreationPolicyError::InvalidBasisPoints {
            field: "topic_entropy_bp",
        });
    }
    if candidate.child_layer_similarity_bp > MAX_BASIS_POINTS {
        return Err(LayerCreationPolicyError::InvalidBasisPoints {
            field: "child_layer_similarity_bp",
        });
    }
    let _ = canonical_child_layer_slug(&candidate.candidate_label)?;
    Ok(())
}

fn validate_scope_text(value: &str, field: &'static str) -> Result<(), LayerCreationPolicyError> {
    if value.trim().is_empty() {
        return Err(LayerCreationPolicyError::InvalidScope { field });
    }
    Ok(())
}

fn validate_relative_path(
    value: &str,
    field: &'static str,
) -> Result<(), LayerCreationPolicyError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value.trim() != value
    {
        return Err(LayerCreationPolicyError::InvalidLayerPath { field });
    }
    Ok(())
}

fn validate_slug(value: &str) -> Result<(), LayerCreationPolicyError> {
    if value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'))
    {
        return Err(LayerCreationPolicyError::InvalidLayerPath {
            field: "candidate_label",
        });
    }
    Ok(())
}

fn weighted_total_score(
    policy: &LayerCreationPolicyV1,
    score: LayerCreationScoreComponents,
) -> u16 {
    let total = u32::from(score.size_pressure_bp) * u32::from(policy.size_weight_percent)
        + u32::from(score.graph_connectivity_pressure_bp) * u32::from(policy.graph_weight_percent)
        + u32::from(score.retrieval_pressure_bp) * u32::from(policy.retrieval_weight_percent)
        + u32::from(score.semantic_spread_bp) * u32::from(policy.semantic_weight_percent)
        + u32::from(score.quality_pressure_bp) * u32::from(policy.quality_weight_percent)
        + u32::from(score.hygiene_pressure_bp) * u32::from(policy.hygiene_weight_percent);
    u16::try_from((total / 100).min(u32::from(MAX_BASIS_POINTS))).unwrap_or(MAX_BASIS_POINTS)
}

fn select_decision_status(
    policy: &LayerCreationPolicyV1,
    candidate: &LayerCreationCandidateV1,
    total_creation_score_bp: u16,
    hard_trigger_ids: &[String],
    hard_blocker_ids: &[String],
) -> LayerCreationDecisionStatus {
    if hard_blocker_ids
        .iter()
        .any(|blocker| blocker == "target_depth_exceeds_policy")
    {
        return LayerCreationDecisionStatus::RejectOverDepth;
    }
    if hard_blocker_ids.iter().any(|blocker| {
        blocker == "missing_parent_layer_id" || blocker == "missing_parent_graph_node_id"
    }) {
        return LayerCreationDecisionStatus::RejectMissingParent;
    }
    if hard_blocker_ids
        .iter()
        .any(|blocker| blocker == "tenant_mismatch" || blocker == "namespace_mismatch")
    {
        return LayerCreationDecisionStatus::RejectNamespaceScope;
    }
    if !hard_blocker_ids.is_empty() {
        return LayerCreationDecisionStatus::OperatorReviewRequired;
    }

    let pressure_accepts =
        total_creation_score_bp >= policy.create_threshold_bp || !hard_trigger_ids.is_empty();
    let edge_pressure = hard_trigger_ids
        .iter()
        .any(|trigger| trigger == "edge_budget_trigger");
    if edge_pressure && candidate.topic_entropy_bp < policy.low_semantic_spread_bp {
        return LayerCreationDecisionStatus::TrimBeforeSplit;
    }
    if candidate.child_layer_count_for_parent >= policy.max_child_layers_per_parent
        && pressure_accepts
    {
        return LayerCreationDecisionStatus::OperatorReviewRequired;
    }
    if pressure_accepts
        && candidate.existing_child_layer_id.is_some()
        && candidate.child_layer_similarity_bp >= policy.reuse_similarity_threshold_bp
    {
        return LayerCreationDecisionStatus::ReuseExistingChildLayer;
    }
    if pressure_accepts {
        return LayerCreationDecisionStatus::CreateChildLayer;
    }
    LayerCreationDecisionStatus::StayCurrentLayer
}

fn hard_triggers(
    policy: &LayerCreationPolicyV1,
    candidate: &LayerCreationCandidateV1,
) -> Vec<String> {
    let mut triggers = Vec::new();
    if candidate.direct_memory_count >= policy.memory_count_trigger {
        triggers.push("memory_count_trigger".to_owned());
    }
    if candidate.selected_token_estimate >= policy.token_pressure_trigger {
        triggers.push("token_pressure_trigger".to_owned());
    }
    if candidate.retrieval_use_count_7d >= policy.retrieval_use_trigger_7d
        && candidate.selected_ref_count_7d >= policy.selected_ref_trigger_7d
    {
        triggers.push("retrieval_pressure_trigger".to_owned());
    }
    if candidate.topic_entropy_bp >= policy.semantic_spread_trigger_bp
        && candidate.candidate_cluster_memory_count >= policy.cluster_memory_count_trigger
    {
        triggers.push("semantic_spread_trigger".to_owned());
    }
    if candidate.unsupported_claim_count_7d >= policy.unsupported_claim_trigger_7d
        || candidate.contradiction_count_7d >= policy.contradiction_trigger_7d
    {
        triggers.push("quality_pressure_trigger".to_owned());
    }
    if candidate.active_same_layer_edge_count >= policy.same_layer_edge_trigger
        || candidate.active_cross_layer_edge_count >= policy.cross_layer_edge_trigger
    {
        triggers.push("edge_budget_trigger".to_owned());
    }
    triggers
}

fn hard_blockers(
    policy: &LayerCreationPolicyV1,
    candidate: &LayerCreationCandidateV1,
) -> Vec<String> {
    let mut blockers = Vec::new();
    let target_depth = candidate.parent_layer_depth.saturating_add(1);
    if target_depth > policy.max_layer_depth {
        blockers.push("target_depth_exceeds_policy".to_owned());
    }
    if candidate.parent_layer_id.is_none() {
        blockers.push("missing_parent_layer_id".to_owned());
    }
    if candidate.parent_graph_node_id.is_none() {
        blockers.push("missing_parent_graph_node_id".to_owned());
    }
    if candidate.tenant_id != candidate.parent_tenant_id {
        blockers.push("tenant_mismatch".to_owned());
    }
    if candidate.namespace != candidate.parent_namespace {
        blockers.push("namespace_mismatch".to_owned());
    }
    if !candidate.candidate_evidence_hash_present {
        blockers.push("missing_candidate_evidence_hash".to_owned());
    }
    blockers
}

fn decision_reason_codes(
    candidate: &LayerCreationCandidateV1,
    decision_status: LayerCreationDecisionStatus,
    total_creation_score_bp: u16,
    hard_trigger_ids: &[String],
    hard_blocker_ids: &[String],
) -> Vec<String> {
    let mut reasons = Vec::new();
    reasons.push(format!("decision:{}", decision_status.as_str()));
    reasons.push(format!("total_score_bp:{total_creation_score_bp}"));
    if candidate.existing_child_layer_id.is_some() {
        reasons.push("existing_child_layer_present".to_owned());
    }
    reasons.extend(
        hard_trigger_ids
            .iter()
            .map(|trigger| format!("trigger:{trigger}")),
    );
    reasons.extend(
        hard_blocker_ids
            .iter()
            .map(|blocker| format!("blocker:{blocker}")),
    );
    reasons
}

fn deterministic_child_layer_id(
    policy: &LayerCreationPolicyV1,
    candidate: &LayerCreationCandidateV1,
    candidate_evidence_hash: &str,
) -> Result<Hash256, LayerCreationPolicyError> {
    let slug = canonical_child_layer_slug(&candidate.candidate_label)?;
    let material = (
        CHILD_LAYER_ID_DOMAIN,
        &policy.policy_version,
        &candidate.tenant_id,
        &candidate.namespace,
        candidate.parent_layer_id,
        candidate.parent_graph_node_id,
        slug,
        &candidate.candidate_child_layer_path,
        candidate.parent_layer_depth.saturating_add(1),
        candidate_evidence_hash,
    );
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&material, &mut buf).map_err(|error| {
        LayerCreationPolicyError::HashMaterial {
            reason: error.to_string(),
        }
    })?;
    Ok(Hash256::from_bytes(sha256_bytes(&buf)))
}

fn ratio_bp(value: u32, threshold: u32) -> u16 {
    if threshold == 0 {
        return 0;
    }
    let bp = u64::from(value).saturating_mul(u64::from(MAX_BASIS_POINTS)) / u64::from(threshold);
    u16::try_from(bp.min(u64::from(MAX_BASIS_POINTS))).unwrap_or(MAX_BASIS_POINTS)
}

fn max_bp(left: u16, right: u16) -> u16 {
    left.max(right)
}

fn max3_bp(first: u16, second: u16, third: u16) -> u16 {
    first.max(second).max(third)
}

fn hash_json_hex<T: Serialize>(value: &T) -> Result<String, LayerCreationPolicyError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| LayerCreationPolicyError::HashMaterial {
            reason: error.to_string(),
        })?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256_bytes(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// PRD-D2 (dimension3-prd-02) S1: deterministic aggregate root-summary distiller.
//
// This is the v2 facet of the layer creation policy: at import the policy
// distills each layer's aggregate root summary from its members' titles and
// summaries — top-N members by `local_node_rank`, PURE extraction and
// concatenation (titles/headings, identifier/definition lines), capped to a
// length bound. No LLM and no randomness participate: the aggregate is a pure
// function of (member set, ranks, the extraction rule, the length cap), so
// byte-identical re-derivation is always possible. Forbidden material is
// screened MANDATORILY (mirroring context_packet_output.rs:662) — a poisoned
// member is rejected rather than concatenated into the aggregate.
// ---------------------------------------------------------------------------

/// Aggregate root-summary schema version recorded by the v2 distiller.
pub const LAYER_AGGREGATE_SUMMARY_SCHEMA_VERSION: &str = "layer_aggregate_summary_v1";
/// CBOR/blake3 id domain for deterministic aggregate ids.
const LAYER_AGGREGATE_SUMMARY_ID_DOMAIN: &str = "layer_creation_policy_v2.aggregate_summary_id";
/// Top-N members (by ascending `local_node_rank`) folded into an aggregate.
pub const LAYER_AGGREGATE_SUMMARY_TOP_N: usize = 16;
/// Never-exceed character ceiling for the distilled aggregate summary.
pub const LAYER_AGGREGATE_SUMMARY_MAX_CHARS: usize = 700;
/// Never-exceed character ceiling for the distilled aggregate title.
pub const LAYER_AGGREGATE_TITLE_MAX_CHARS: usize = 200;

/// Forbidden-material fragments screened on the aggregate path.
///
/// Kept in lock-step with `FORBIDDEN_MATERIAL_FRAGMENTS` in
/// `context_packet_output.rs` (the mandatory packet-output screen) plus the
/// `source_path` JSON-key guard, so an aggregate that would carry forbidden
/// material is rejected at distillation rather than surfacing through the
/// rollup. Matching is case-insensitive substring containment.
const LAYER_AGGREGATE_FORBIDDEN_FRAGMENTS: &[&str] = &[
    "/users/",
    "/home/",
    "/private/",
    "~/",
    "database_url",
    "private key",
    "api_key",
    "bearer ",
    ".env",
    "raw_markdown",
    "raw_body",
    "raw_private_payload",
    "source_excerpt",
    "source_path",
    "postgres://",
    "postgresql://",
    "file://",
];

/// One layer member offered to the aggregate distiller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerAggregateMember {
    /// Stable member identity used as the deterministic tie-break.
    pub member_id: String,
    /// Local rank inside the layer (ascending; lower wins selection).
    pub local_node_rank: u32,
    /// Already-distilled, safe member title text.
    pub title: String,
    /// Already-distilled, safe member summary text.
    pub summary: String,
}

/// Deterministic aggregate root summary distilled from a layer's members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerAggregateSummary {
    /// Schema version of the aggregate.
    pub schema_version: String,
    /// Distilled aggregate title (top member's title, bounded).
    pub title: String,
    /// Distilled aggregate summary text (bounded concatenation).
    pub summary: String,
    /// Count of members actually folded into the aggregate.
    pub member_count: u32,
    /// Total members offered (before top-N truncation).
    pub source_member_count: u32,
    /// True when the top-N bound dropped lower-ranked members.
    pub truncated_members: bool,
    /// True when the length cap dropped trailing pieces.
    pub truncated_length: bool,
    /// CBOR/blake3 id over the distilled material for byte-identical replay.
    pub aggregate_id: String,
}

/// Aggregate distillation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LayerAggregateError {
    /// No member offered any safe, content-bearing piece.
    #[error("layer_aggregate_no_content")]
    NoContent,
    /// A member carried forbidden material on the aggregate path.
    #[error("layer_aggregate_forbidden_material: {fragment}")]
    ForbiddenMaterial {
        /// The offending fragment.
        fragment: String,
    },
    /// Aggregate id material could not be serialized.
    #[error("layer_aggregate_hash_material_failed: {reason}")]
    HashMaterial {
        /// Stable serialization reason.
        reason: String,
    },
}

/// Return the first forbidden fragment present in `text`, or `None`.
fn aggregate_forbidden_fragment(text: &str) -> Option<String> {
    let lowered = text.to_ascii_lowercase();
    LAYER_AGGREGATE_FORBIDDEN_FRAGMENTS
        .iter()
        .find(|fragment| lowered.contains(&fragment.to_ascii_lowercase()))
        .map(|fragment| (*fragment).to_owned())
}

/// Collapse internal whitespace and trim a candidate piece.
fn aggregate_normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A summary line is keepable when it carries a content-bearing identifier or
/// definition shape: a `key: value` row, a backticked identifier, or a
/// sentence ending in terminal punctuation. Pure structural extraction — no
/// model judgment.
fn aggregate_line_is_content(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains('`') {
        return true;
    }
    // `key: value` definition row: an alphanumeric key, a colon, then a value.
    if let Some((key, value)) = trimmed.split_once(':')
        && !key.trim().is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-' || c == '.')
        && !value.trim().is_empty()
    {
        return true;
    }
    // A definition/heading-style sentence ending in terminal punctuation.
    matches!(trimmed.chars().last(), Some('.') | Some('!') | Some('?'))
}

/// Deterministically distill the aggregate root summary for one layer.
///
/// `members` is the layer's member set (each carrying an already-safe,
/// already-distilled title/summary, a local rank, and a stable id). The
/// distiller selects the top-N members by ascending `local_node_rank`
/// (tie-broken by `member_id`), then performs pure extraction/concatenation of
/// titles and identifier/definition lines, deduped in document order, capped to
/// the length bound. Mandatory forbidden-material screening rejects any member
/// that carries forbidden material. The returned `aggregate_id` is a
/// CBOR/blake3 digest of the distilled material so re-derivation is
/// byte-identical.
///
/// # Errors
///
/// Returns [`LayerAggregateError::ForbiddenMaterial`] when a member carries
/// forbidden material, [`LayerAggregateError::NoContent`] when no safe
/// content-bearing piece survives, and [`LayerAggregateError::HashMaterial`] on
/// id serialization failure.
pub fn distill_layer_aggregate_summary(
    members: &[LayerAggregateMember],
) -> Result<LayerAggregateSummary, LayerAggregateError> {
    // Screen EVERY offered member, not just the top-N: a poisoned member must be
    // rejected even if it would have been truncated away, so the aggregate path
    // can never silently absorb forbidden material.
    for member in members {
        if let Some(fragment) = aggregate_forbidden_fragment(&member.title)
            .or_else(|| aggregate_forbidden_fragment(&member.summary))
        {
            return Err(LayerAggregateError::ForbiddenMaterial { fragment });
        }
    }

    let source_member_count = members.len();
    // Deterministic selection order: ascending local_node_rank, then member_id.
    let mut ordered: Vec<&LayerAggregateMember> = members.iter().collect();
    ordered.sort_by(|a, b| {
        a.local_node_rank
            .cmp(&b.local_node_rank)
            .then_with(|| a.member_id.cmp(&b.member_id))
    });
    let truncated_members = ordered.len() > LAYER_AGGREGATE_SUMMARY_TOP_N;
    let selected: Vec<&LayerAggregateMember> = ordered
        .into_iter()
        .take(LAYER_AGGREGATE_SUMMARY_TOP_N)
        .collect();

    // The aggregate title is the top member's title (bounded), falling back to
    // the first member that carries a non-empty title.
    let mut title = String::new();
    for member in &selected {
        let candidate = aggregate_normalize(&member.title);
        if !candidate.is_empty() {
            title = candidate;
            break;
        }
    }
    if title.chars().count() > LAYER_AGGREGATE_TITLE_MAX_CHARS {
        title = title
            .chars()
            .take(LAYER_AGGREGATE_TITLE_MAX_CHARS)
            .collect();
        title = title.trim_end().to_owned();
    }

    // Pure extraction: each selected member contributes its normalized title and
    // its content-bearing summary lines, in selection order, deduped.
    let mut pieces: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut members_with_content = 0u32;
    for member in &selected {
        let mut member_contributed = false;
        let title_piece = aggregate_normalize(&member.title);
        if !title_piece.is_empty() && seen.insert(title_piece.clone()) {
            pieces.push(title_piece);
            member_contributed = true;
        }
        for raw_line in member.summary.split(['\n', '.']) {
            if !aggregate_line_is_content(raw_line) {
                continue;
            }
            let piece = aggregate_normalize(raw_line);
            if piece.is_empty() || !seen.insert(piece.clone()) {
                continue;
            }
            pieces.push(piece);
            member_contributed = true;
        }
        // Fall back to the whole normalized summary when no structured line
        // matched but the member still has prose to contribute.
        if !member_contributed {
            let whole = aggregate_normalize(&member.summary);
            if !whole.is_empty() && seen.insert(whole.clone()) {
                pieces.push(whole);
                member_contributed = true;
            }
        }
        if member_contributed {
            members_with_content += 1;
        }
    }

    // Greedy length-bounded concatenation.
    let mut summary = String::new();
    let mut truncated_length = false;
    for piece in &pieces {
        let addition = if summary.is_empty() {
            piece.chars().count()
        } else {
            piece.chars().count() + 1
        };
        if summary.chars().count() + addition > LAYER_AGGREGATE_SUMMARY_MAX_CHARS {
            truncated_length = true;
            continue;
        }
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str(piece);
    }

    if summary.is_empty() {
        return Err(LayerAggregateError::NoContent);
    }

    // Defense in depth: the distilled output itself is screened before it is
    // ever returned, so a forbidden fragment assembled across pieces cannot
    // escape even if an individual member slipped through.
    if let Some(fragment) =
        aggregate_forbidden_fragment(&summary).or_else(|| aggregate_forbidden_fragment(&title))
    {
        return Err(LayerAggregateError::ForbiddenMaterial { fragment });
    }

    let aggregate_id = aggregate_summary_id(&title, &summary, members_with_content)?;

    Ok(LayerAggregateSummary {
        schema_version: LAYER_AGGREGATE_SUMMARY_SCHEMA_VERSION.to_owned(),
        title,
        summary,
        member_count: members_with_content,
        source_member_count: u32::try_from(source_member_count).unwrap_or(u32::MAX),
        truncated_members,
        truncated_length,
        aggregate_id,
    })
}

/// CBOR/blake3 id over the distilled material (matches the import-path id
/// discipline) so the aggregate id is byte-identical across re-derivations.
fn aggregate_summary_id(
    title: &str,
    summary: &str,
    member_count: u32,
) -> Result<String, LayerAggregateError> {
    let material = (
        LAYER_AGGREGATE_SUMMARY_ID_DOMAIN,
        LAYER_AGGREGATE_SUMMARY_SCHEMA_VERSION,
        title,
        summary,
        member_count,
    );
    let hash = exo_core::hash::hash_structured(&material).map_err(|error| {
        LayerAggregateError::HashMaterial {
            reason: error.to_string(),
        }
    })?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn candidate() -> LayerCreationCandidateV1 {
        LayerCreationCandidateV1 {
            tenant_id: "dag_db-local".to_owned(),
            namespace: "dag_db".to_owned(),
            parent_tenant_id: "dag_db-local".to_owned(),
            parent_namespace: "dag_db".to_owned(),
            parent_layer_id: Some(h(0x11)),
            parent_graph_node_id: Some(h(0x22)),
            parent_layer_path: "root/repository".to_owned(),
            parent_layer_depth: 1,
            candidate_cluster_id: "cluster-policy".to_owned(),
            candidate_label: "Policy Runtime Cluster".to_owned(),
            candidate_child_layer_path: "root/repository/policy-runtime-cluster".to_owned(),
            existing_child_layer_id: None,
            candidate_evidence_hash_present: true,
            direct_memory_count: 16,
            candidate_cluster_memory_count: 4,
            active_same_layer_edge_count: 8,
            active_cross_layer_edge_count: 2,
            selected_token_estimate: 512,
            retrieval_use_count_7d: 2,
            selected_ref_count_7d: 2,
            selected_edge_count_7d: 1,
            topic_entropy_bp: 2_000,
            unsupported_claim_count_7d: 0,
            contradiction_count_7d: 0,
            rollup_stale: false,
            membership_changed: false,
            child_layer_count_for_parent: 2,
            child_layer_similarity_bp: 0,
        }
    }

    #[test]
    fn layer_creation_policy_thresholds_match_prd09() {
        let policy = default_layer_creation_policy();
        assert_eq!(policy.policy_version, LAYER_CREATION_POLICY_VERSION);
        assert_eq!(policy.max_layer_depth, 8);
        assert_eq!(policy.create_threshold_bp, 6_500);
        assert_eq!(policy.reuse_similarity_threshold_bp, 8_500);
        assert_eq!(policy.max_child_layers_per_parent, 16);
        assert_eq!(policy.memory_count_trigger, 128);
        assert_eq!(policy.token_pressure_trigger, 4_096);
        assert_eq!(policy.retrieval_use_trigger_7d, 12);
        assert_eq!(policy.selected_ref_trigger_7d, 8);
        assert_eq!(policy.same_layer_edge_trigger, 64);
        assert_eq!(policy.cross_layer_edge_trigger, 24);
    }

    #[test]
    fn layer_creation_policy_hashes_replay_deterministically() {
        let policy = default_layer_creation_policy();
        let candidate = candidate();
        let first = evaluate_layer_creation_candidate(&policy, &candidate).expect("first");
        let second = evaluate_layer_creation_candidate(&policy, &candidate).expect("second");
        assert_eq!(
            first.threshold_snapshot_hash,
            second.threshold_snapshot_hash
        );
        assert_eq!(
            first.candidate_evidence_hash,
            second.candidate_evidence_hash
        );
        assert_eq!(first.decision_hash, second.decision_hash);
    }

    #[test]
    fn layer_creation_policy_stays_below_threshold_without_trigger() {
        let policy = default_layer_creation_policy();
        let decision = evaluate_layer_creation_candidate(&policy, &candidate()).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::StayCurrentLayer
        );
        assert!(decision.deterministic_child_layer_id.is_none());
    }

    #[test]
    fn layer_creation_policy_creates_on_memory_count_trigger() {
        let policy = default_layer_creation_policy();
        let mut candidate = candidate();
        candidate.direct_memory_count = 128;
        let decision = evaluate_layer_creation_candidate(&policy, &candidate).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::CreateChildLayer
        );
        assert!(
            decision
                .hard_trigger_ids
                .contains(&"memory_count_trigger".to_owned())
        );
        assert!(decision.deterministic_child_layer_id.is_some());
    }

    #[test]
    fn layer_creation_policy_reuses_existing_child_before_create() {
        let policy = default_layer_creation_policy();
        let mut candidate = candidate();
        candidate.direct_memory_count = 128;
        candidate.existing_child_layer_id = Some(h(0x44));
        candidate.child_layer_similarity_bp = 8_500;
        let decision = evaluate_layer_creation_candidate(&policy, &candidate).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::ReuseExistingChildLayer
        );
    }

    #[test]
    fn layer_creation_policy_operator_review_precedes_create() {
        let policy = default_layer_creation_policy();
        let mut candidate = candidate();
        candidate.direct_memory_count = 128;
        candidate.child_layer_count_for_parent = 16;
        let decision = evaluate_layer_creation_candidate(&policy, &candidate).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::OperatorReviewRequired
        );
    }

    #[test]
    fn layer_creation_policy_trims_edge_overload_with_low_entropy() {
        let policy = default_layer_creation_policy();
        let mut candidate = candidate();
        candidate.active_same_layer_edge_count = 64;
        candidate.topic_entropy_bp = 3_499;
        let decision = evaluate_layer_creation_candidate(&policy, &candidate).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::TrimBeforeSplit
        );
    }

    #[test]
    fn layer_creation_policy_rejects_missing_parent() {
        let policy = default_layer_creation_policy();
        let mut candidate = candidate();
        candidate.parent_layer_id = None;
        let decision = evaluate_layer_creation_candidate(&policy, &candidate).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::RejectMissingParent
        );
    }

    #[test]
    fn layer_creation_policy_rejects_over_depth() {
        let policy = default_layer_creation_policy();
        let mut candidate = candidate();
        candidate.parent_layer_depth = 8;
        let decision = evaluate_layer_creation_candidate(&policy, &candidate).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::RejectOverDepth
        );
    }

    #[test]
    fn layer_creation_policy_rejects_namespace_scope() {
        let policy = default_layer_creation_policy();
        let mut candidate = candidate();
        candidate.parent_namespace = "other".to_owned();
        let decision = evaluate_layer_creation_candidate(&policy, &candidate).expect("decision");
        assert_eq!(
            decision.decision_status,
            LayerCreationDecisionStatus::RejectNamespaceScope
        );
    }

    #[test]
    fn layer_creation_policy_boundary_6499_stays_and_6500_creates() {
        let policy = LayerCreationPolicyV1 {
            create_threshold_bp: 6_500,
            size_weight_percent: 100,
            graph_weight_percent: 0,
            retrieval_weight_percent: 0,
            semantic_weight_percent: 0,
            quality_weight_percent: 0,
            hygiene_weight_percent: 0,
            ..LayerCreationPolicyV1::default()
        };
        let mut below = candidate();
        below.direct_memory_count = 83;
        let below_decision = evaluate_layer_creation_candidate(&policy, &below).expect("below");
        assert_eq!(below_decision.total_creation_score_bp, 6_484);
        assert_eq!(
            below_decision.decision_status,
            LayerCreationDecisionStatus::StayCurrentLayer
        );

        let mut at = candidate();
        at.direct_memory_count = 84;
        let at_decision = evaluate_layer_creation_candidate(&policy, &at).expect("at");
        assert_eq!(at_decision.total_creation_score_bp, 6_562);
        assert_eq!(
            at_decision.decision_status,
            LayerCreationDecisionStatus::CreateChildLayer
        );
    }

    #[test]
    fn layer_creation_policy_slug_normalizes_or_falls_back() {
        assert_eq!(
            canonical_child_layer_slug("Policy Runtime Cluster").expect("slug"),
            "policy-runtime-cluster"
        );
        let fallback = canonical_child_layer_slug("!!!").expect("fallback");
        assert!(fallback.starts_with("cluster-"));
        assert_eq!(fallback.len(), "cluster-".len() + 16);
    }

    // --- PRD-D2 S1 aggregate distiller golden tests -------------------------

    fn member(member_id: &str, rank: u32, title: &str, summary: &str) -> LayerAggregateMember {
        LayerAggregateMember {
            member_id: member_id.to_owned(),
            local_node_rank: rank,
            title: title.to_owned(),
            summary: summary.to_owned(),
        }
    }

    #[test]
    fn aggregate_distills_member_set_into_summary() {
        let members = vec![
            member(
                "m2",
                1,
                "Layer Policy",
                "schema_version: layer_creation_policy_v1. Create threshold is `6500` bp.",
            ),
            member(
                "m1",
                0,
                "Retrieval Module",
                "Selection scoring is deterministic. Identifier `PRD09` is preserved.",
            ),
        ];
        let aggregate = distill_layer_aggregate_summary(&members).expect("aggregate");
        // Top member by ascending rank (m1, rank 0) supplies the title.
        assert_eq!(aggregate.title, "Retrieval Module");
        assert_eq!(aggregate.member_count, 2);
        assert_eq!(aggregate.source_member_count, 2);
        assert!(!aggregate.truncated_members);
        // Both members' titles and content lines are folded in, in rank order.
        assert!(aggregate.summary.contains("Retrieval Module"));
        assert!(aggregate.summary.contains("Layer Policy"));
        assert!(aggregate.summary.contains("PRD09"));
        assert!(aggregate.summary.contains("`6500`"));
        // Rank order: the rank-0 member's content precedes the rank-1 member's.
        let retrieval_pos = aggregate.summary.find("Retrieval Module").unwrap();
        let policy_pos = aggregate.summary.find("Layer Policy").unwrap();
        assert!(retrieval_pos < policy_pos);
    }

    #[test]
    fn aggregate_preserves_exact_identifiers() {
        let members = vec![member(
            "m1",
            0,
            "Schema",
            "Versioned name `project_memory_v3`. Threshold `8500` bp. Risk class R1.",
        )];
        let aggregate = distill_layer_aggregate_summary(&members).expect("aggregate");
        assert!(aggregate.summary.contains("`project_memory_v3`"));
        assert!(aggregate.summary.contains("`8500`"));
    }

    #[test]
    fn aggregate_is_deterministic_byte_identical() {
        let members = vec![
            member("m1", 0, "A", "Fact one is `x`."),
            member("m2", 1, "B", "Fact two is `y`."),
        ];
        let first = distill_layer_aggregate_summary(&members).expect("first");
        let second = distill_layer_aggregate_summary(&members).expect("second");
        assert_eq!(first, second);
        // Input order must not change the output (sort is by rank then id).
        let reordered = vec![
            member("m2", 1, "B", "Fact two is `y`."),
            member("m1", 0, "A", "Fact one is `x`."),
        ];
        let reordered_aggregate = distill_layer_aggregate_summary(&reordered).expect("reordered");
        assert_eq!(first, reordered_aggregate);
        assert_eq!(first.aggregate_id, reordered_aggregate.aggregate_id);
    }

    #[test]
    fn aggregate_rejects_forbidden_material() {
        let members = vec![
            member("m1", 0, "Clean", "A safe definition line."),
            member(
                "m2",
                1,
                "Poisoned",
                "leaked credential database_url=postgres://secret",
            ),
        ];
        let error = distill_layer_aggregate_summary(&members).expect_err("must reject");
        match error {
            LayerAggregateError::ForbiddenMaterial { fragment } => {
                assert!(
                    fragment == "database_url" || fragment == "postgres://",
                    "unexpected fragment: {fragment}"
                );
            }
            other => panic!("expected forbidden material, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_rejects_forbidden_material_even_when_truncated_away() {
        // The poisoned member ranks far below the top-N cut, but screening still
        // catches it: the aggregate path can never silently absorb it.
        let mut members = Vec::new();
        for i in 0..LAYER_AGGREGATE_SUMMARY_TOP_N {
            members.push(member(
                &format!("clean{i:02}"),
                u32::try_from(i).expect("test index fits in u32"),
                &format!("Clean {i}"),
                "A safe definition line.",
            ));
        }
        members.push(member(
            "poison",
            999,
            "Poison",
            "absolute path /Users/secret/key",
        ));
        let error = distill_layer_aggregate_summary(&members).expect_err("must reject");
        assert!(matches!(
            error,
            LayerAggregateError::ForbiddenMaterial { .. }
        ));
    }

    #[test]
    fn aggregate_holds_length_bound() {
        let long_line = "Identifier `tok` ".repeat(200);
        let members = vec![member("m1", 0, "Long", &long_line)];
        let aggregate = distill_layer_aggregate_summary(&members).expect("aggregate");
        assert!(aggregate.summary.chars().count() <= LAYER_AGGREGATE_SUMMARY_MAX_CHARS);
        assert!(aggregate.truncated_length);
    }

    #[test]
    fn aggregate_truncates_member_set_to_top_n() {
        let mut members = Vec::new();
        for i in 0..(LAYER_AGGREGATE_SUMMARY_TOP_N + 4) {
            members.push(member(
                &format!("m{i:02}"),
                u32::try_from(i).expect("test index fits in u32"),
                &format!("Title {i}"),
                "Definition line.",
            ));
        }
        let aggregate = distill_layer_aggregate_summary(&members).expect("aggregate");
        assert!(aggregate.truncated_members);
        assert_eq!(
            usize::try_from(aggregate.source_member_count).expect("member count fits in usize"),
            LAYER_AGGREGATE_SUMMARY_TOP_N + 4
        );
        assert!(
            usize::try_from(aggregate.member_count).expect("member count fits in usize")
                <= LAYER_AGGREGATE_SUMMARY_TOP_N
        );
    }

    #[test]
    fn aggregate_rejects_empty_member_set() {
        let error = distill_layer_aggregate_summary(&[]).expect_err("no content");
        assert!(matches!(error, LayerAggregateError::NoContent));
    }
}

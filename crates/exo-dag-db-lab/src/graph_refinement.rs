//! Deterministic advisory graph refinement artifacts for Graph Explorer.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

use exo_dag_db_api::{MemoryEdgeKind, MemoryGraphStyle, MemoryNodeKind};
use serde::{Deserialize, Serialize};

use crate::graph_explorer::{
    GRAPH_DATASET_ID_OVERRIDE_ENV, GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH,
    GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH, GRAPH_EXPLORER_INSPECTOR_PATH,
    GRAPH_EXPLORER_SNAPSHOT_PATH, GRAPH_EXPLORER_TARGET_DIR, GraphExplorerEdge,
    GraphExplorerEdgeStatus, GraphExplorerError, GraphExplorerNode, GraphExplorerNodeStatus,
    GraphExplorerSnapshot, GraphSourceTruthLevel, NodeInspectorDetails,
};

pub const GRAPH_REFINEMENT_REPORT_PATH: &str = "target/dagdb/graph_explorer/refinement_report.json";
pub const GRAPH_REFINEMENT_SUMMARY_PATH: &str = "target/dagdb/graph_explorer/refinement_summary.md";
pub const GRAPH_REFINEMENT_REPORT_SCHEMA_VERSION: &str = "dagdb_graph_refinement_report_v1";
pub const GRAPH_EVIDENCE_CLOSURE_WORKLIST_SCHEMA_VERSION: &str =
    "dagdb_evidence_closure_worklist_v1";
pub const GRAPH_EVIDENCE_CLOSURE_REVIEW_SCHEMA_VERSION: &str = "dagdb_evidence_closure_review_v1";
pub const GRAPH_EVIDENCE_CLOSURE_REVIEW_SUMMARY_SCHEMA_VERSION: &str =
    "dagdb_evidence_closure_review_summary_v1";
pub const GRAPH_EVIDENCE_INTAKE_PACKET_SCHEMA_VERSION: &str = "dagdb_evidence_intake_packet_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRefinementArtifactSet {
    pub report_path: String,
    pub summary_path: String,
    pub report_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphRefinementAction {
    Keep,
    Strengthen,
    Weaken,
    Review,
    Hide,
    Merge,
    Split,
    Supersede,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphRefinementRecommendationTargetType {
    Edge,
    Node,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphRefinementRecommendationGroup {
    ReviewWeakEdges,
    StrengthenUsefulEdges,
    HideNoisyEdges,
    MergeDuplicateEdges,
    InspectContradictions,
    ConnectIsolatedHighValueNodes,
    SplitOverConnectedHubs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphRefinementWritebackStatus {
    AdvisoryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeEvidenceLevel {
    DirectTaskRunnerMatch,
    TaskMatch,
    RunnerMatch,
    ArtifactReferenceOnly,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeTriageCategory {
    NoEvidence,
    NegativeQualityDelta,
    NegativeCitationDelta,
    HigherUnsupportedClaimRate,
    HigherCostThanNeutral,
    WeakFrequentEdge,
    StrongKeepCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeTriageSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeDiagnosisCause {
    QualityRegression,
    CitationRegression,
    UnsupportedClaimRegression,
    CostRegression,
    WeakFrequentConnection,
    MissingEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeClosureAction {
    AddTaskRunnerMetadata,
    AttachReceiptOrValidation,
    InspectRouteContext,
    SplitOverbroadConnection,
    HideNoisyConnection,
    StrengthenSupportedConnection,
    ReviewMissingEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeClosureCause {
    QualityRegression,
    CitationRegression,
    UnsupportedClaimRegression,
    CostRegression,
    WeakFrequentConnection,
    MissingEvidence,
    StrongKeepCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClosureReviewStatus {
    Open,
    EvidenceAttached,
    Verified,
    Deferred,
    RejectedNoise,
    KeepConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClosureVerificationStatus {
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeRefinementAssessment {
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_kind: String,
    pub graph_style: String,
    pub edge_quality_score_bp: u16,
    pub evidence_strength_bp: u16,
    pub contradiction_risk_bp: u16,
    pub staleness_risk_bp: u16,
    pub routing_usefulness_bp: u16,
    pub confidence_reason: String,
    pub recommended_action: GraphRefinementAction,
    pub supporting_artifact_references: Vec<String>,
    pub weakening_artifact_references: Vec<String>,
    #[serde(default = "default_edge_evidence_level")]
    pub evidence_level: EdgeEvidenceLevel,
    #[serde(default)]
    pub task_usage_count: u32,
    #[serde(default)]
    pub matched_task_ids: Vec<String>,
    #[serde(default)]
    pub matched_diagnostic_labels: Vec<String>,
    #[serde(default)]
    pub avg_quality_bp: u16,
    #[serde(default)]
    pub avg_citation_accuracy_bp: u16,
    #[serde(default)]
    pub avg_unsupported_claim_rate_bp: u16,
    #[serde(default)]
    pub quality_delta_vs_neutral_bp: i32,
    #[serde(default)]
    pub citation_delta_vs_neutral_bp: i32,
    #[serde(default)]
    pub unsupported_delta_vs_neutral_bp: i32,
    #[serde(default)]
    pub cost_delta_vs_neutral_micro_exo: i64,
    #[serde(default)]
    pub diagnostic_impact_bp: u16,
    #[serde(default = "default_evidence_summary")]
    pub evidence_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeTriageItem {
    pub triage_id: String,
    pub edge_id: String,
    pub category: EdgeTriageCategory,
    pub severity: EdgeTriageSeverity,
    pub priority_score_bp: u16,
    pub priority_rank: u32,
    pub reason: String,
    pub recommended_action: GraphRefinementAction,
    pub evidence_level: EdgeEvidenceLevel,
    pub task_usage_count: u32,
    pub edge_quality_score_bp: u16,
    pub diagnostic_impact_bp: u16,
    pub quality_delta_vs_neutral_bp: i32,
    pub citation_delta_vs_neutral_bp: i32,
    pub unsupported_delta_vs_neutral_bp: i32,
    pub cost_delta_vs_neutral_micro_exo: i64,
    pub supporting_artifact_references: Vec<String>,
    pub writeback_status: GraphRefinementWritebackStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeTriageSummary {
    pub total_triage_item_count: u32,
    pub no_evidence_count: u32,
    pub negative_quality_delta_count: u32,
    pub negative_citation_delta_count: u32,
    pub higher_unsupported_claim_rate_count: u32,
    pub higher_cost_than_neutral_count: u32,
    pub weak_frequent_edge_count: u32,
    pub strong_keep_candidate_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeDiagnosisItem {
    pub diagnosis_id: String,
    pub edge_id: String,
    pub cause: EdgeDiagnosisCause,
    pub severity: EdgeTriageSeverity,
    pub impact_score_bp: u16,
    pub task_ids: Vec<String>,
    pub diagnostic_labels: Vec<String>,
    pub edge_kind: String,
    pub graph_style: String,
    pub reason: String,
    pub next_evidence_action: String,
    pub supporting_artifact_references: Vec<String>,
    pub writeback_status: GraphRefinementWritebackStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeDiagnosisSummary {
    pub total_diagnosis_item_count: u32,
    pub quality_regression_count: u32,
    pub citation_regression_count: u32,
    pub unsupported_claim_regression_count: u32,
    pub cost_regression_count: u32,
    pub weak_frequent_connection_count: u32,
    pub missing_evidence_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeClosureItem {
    pub closure_id: String,
    pub edge_id: String,
    pub action: EdgeClosureAction,
    pub priority_score_bp: u16,
    pub severity: EdgeTriageSeverity,
    pub cause: EdgeClosureCause,
    pub task_ids: Vec<String>,
    pub diagnostic_labels: Vec<String>,
    pub edge_kind: String,
    pub graph_style: String,
    pub evidence_gap: String,
    pub closure_instruction: String,
    pub verification_hint: String,
    pub supporting_artifact_references: Vec<String>,
    pub writeback_status: GraphRefinementWritebackStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeClosureSummary {
    pub total_closure_item_count: u32,
    pub add_task_runner_metadata_count: u32,
    pub attach_receipt_or_validation_count: u32,
    pub inspect_route_context_count: u32,
    pub split_overbroad_connection_count: u32,
    pub hide_noisy_connection_count: u32,
    pub strengthen_supported_connection_count: u32,
    pub review_missing_evidence_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClosureWorklist {
    pub schema_version: String,
    pub dataset_id: String,
    pub source_snapshot_id: String,
    pub advisory_only: bool,
    pub total_item_count: u32,
    pub action_counts: BTreeMap<String, u32>,
    pub items: Vec<EvidenceClosureWorklistItem>,
    pub artifact_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClosureWorklistItem {
    pub rank: u32,
    pub closure_id: String,
    pub edge_id: String,
    pub action: EdgeClosureAction,
    pub severity: EdgeTriageSeverity,
    pub priority_score_bp: u16,
    pub evidence_gap: String,
    pub closure_instruction: String,
    pub verification_hint: String,
    pub task_ids: Vec<String>,
    pub diagnostic_labels: Vec<String>,
    pub supporting_artifact_references: Vec<String>,
    pub writeback_status: GraphRefinementWritebackStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClosureReviewFile {
    pub schema_version: String,
    pub dataset_id: String,
    pub source_snapshot_id: String,
    pub advisory_only: bool,
    pub items: Vec<EvidenceClosureReviewItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClosureReviewItem {
    pub closure_id: String,
    pub edge_id: String,
    pub review_status: EvidenceClosureReviewStatus,
    pub verification_status: EvidenceClosureVerificationStatus,
    pub operator_note_redacted: String,
    pub evidence_reference_ids: Vec<String>,
    pub reviewed_artifact_references: Vec<String>,
    pub writeback_status: GraphRefinementWritebackStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClosureReviewSummary {
    pub schema_version: String,
    pub dataset_id: String,
    pub source_snapshot_id: String,
    pub advisory_only: bool,
    pub total_closure_item_count: u32,
    pub open_count: u32,
    pub evidence_attached_count: u32,
    pub verified_count: u32,
    pub deferred_count: u32,
    pub rejected_noise_count: u32,
    pub keep_confirmed_count: u32,
    pub completion_rate_bp: u16,
    pub review_items: Vec<EvidenceClosureReviewItem>,
    pub top_open_items: Vec<EvidenceClosureReviewItem>,
    pub top_verified_items: Vec<EvidenceClosureReviewItem>,
    pub artifact_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIntakePacketFile {
    pub schema_version: String,
    pub dataset_id: String,
    pub source_snapshot_id: String,
    pub advisory_only: bool,
    pub limit: u32,
    pub total_packet_item_count: u32,
    pub items: Vec<EvidenceIntakePacketItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIntakePacketItem {
    pub rank: u32,
    pub closure_id: String,
    pub edge_id: String,
    pub action: EdgeClosureAction,
    pub severity: EdgeTriageSeverity,
    pub priority_score_bp: u16,
    pub task_ids: Vec<String>,
    pub diagnostic_labels: Vec<String>,
    pub evidence_gap: String,
    pub closure_instruction: String,
    pub verification_hint: String,
    pub required_evidence_fields: Vec<String>,
    pub supporting_artifact_references: Vec<String>,
    pub writeback_status: GraphRefinementWritebackStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRefinementAssessment {
    pub node_id: String,
    pub visible_degree: u32,
    pub is_high_degree_hub: bool,
    pub is_isolated_important_node: bool,
    pub recommendation_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingEdgeCandidate {
    pub candidate_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub suggested_edge_kind: String,
    pub confidence_bp: u16,
    pub reason: String,
    pub supporting_artifact_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicateEdgeCandidate {
    pub candidate_id: String,
    pub edge_ids: Vec<String>,
    pub confidence_bp: u16,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRefinementRecommendation {
    pub recommendation_id: String,
    pub target_type: GraphRefinementRecommendationTargetType,
    pub target_id: String,
    pub group: GraphRefinementRecommendationGroup,
    pub action: GraphRefinementAction,
    pub confidence_bp: u16,
    pub reason: String,
    pub supporting_artifact_references: Vec<String>,
    pub writeback_status: GraphRefinementWritebackStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRefinementReport {
    pub schema_version: String,
    pub source_snapshot_id: String,
    pub source_truth_level: GraphSourceTruthLevel,
    pub advisory_only: bool,
    pub assessed_edge_count: u32,
    pub assessed_node_count: u32,
    pub average_edge_quality_bp: u16,
    pub weak_edge_count: u32,
    pub missing_edge_candidate_count: u32,
    pub duplicate_edge_candidate_count: u32,
    pub contradicted_edge_candidate_count: u32,
    pub edge_assessments: Vec<EdgeRefinementAssessment>,
    pub node_assessments: Vec<NodeRefinementAssessment>,
    pub missing_edge_candidates: Vec<MissingEdgeCandidate>,
    pub duplicate_edge_candidates: Vec<DuplicateEdgeCandidate>,
    pub recommendations: Vec<GraphRefinementRecommendation>,
    #[serde(default)]
    pub edge_triage_items: Vec<EdgeTriageItem>,
    #[serde(default)]
    pub edge_triage_summary: EdgeTriageSummary,
    #[serde(default)]
    pub edge_diagnosis_items: Vec<EdgeDiagnosisItem>,
    #[serde(default)]
    pub edge_diagnosis_summary: EdgeDiagnosisSummary,
    #[serde(default)]
    pub edge_closure_items: Vec<EdgeClosureItem>,
    #[serde(default)]
    pub edge_closure_summary: EdgeClosureSummary,
    pub artifact_references: Vec<String>,
    pub warnings: Vec<String>,
}

fn default_edge_evidence_level() -> EdgeEvidenceLevel {
    EdgeEvidenceLevel::Unavailable
}

fn default_evidence_summary() -> String {
    "Evidence unavailable".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DiagnosticEvidenceRow {
    #[serde(default)]
    fixture_id: String,
    #[serde(default)]
    task_id: String,
    #[serde(default)]
    diagnostic_label: String,
    #[serde(default)]
    quality_score_bp: Option<u16>,
    #[serde(default)]
    citation_accuracy_bp: Option<u16>,
    #[serde(default)]
    unsupported_claim_rate_bp: Option<u16>,
    #[serde(default)]
    total_cost_micro_exo: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct DiagnosticEvidenceContext {
    rows_by_task_label: BTreeMap<(String, String), Vec<DiagnosticEvidenceRow>>,
    rows_by_task: BTreeMap<String, Vec<DiagnosticEvidenceRow>>,
    rows_by_label: BTreeMap<String, Vec<DiagnosticEvidenceRow>>,
    neutral_by_fixture_task: BTreeMap<(String, String), DiagnosticEvidenceRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EdgeDiagnosticEvidence {
    evidence_level: EdgeEvidenceLevel,
    task_usage_count: u32,
    matched_task_ids: Vec<String>,
    matched_diagnostic_labels: Vec<String>,
    avg_quality_bp: u16,
    avg_citation_accuracy_bp: u16,
    avg_unsupported_claim_rate_bp: u16,
    quality_delta_vs_neutral_bp: i32,
    citation_delta_vs_neutral_bp: i32,
    unsupported_delta_vs_neutral_bp: i32,
    cost_delta_vs_neutral_micro_exo: i64,
    diagnostic_impact_bp: u16,
    evidence_summary: String,
}

impl Default for EdgeDiagnosticEvidence {
    fn default() -> Self {
        Self {
            evidence_level: EdgeEvidenceLevel::Unavailable,
            task_usage_count: 0,
            matched_task_ids: Vec::new(),
            matched_diagnostic_labels: Vec::new(),
            avg_quality_bp: 0,
            avg_citation_accuracy_bp: 0,
            avg_unsupported_claim_rate_bp: 0,
            quality_delta_vs_neutral_bp: 0,
            citation_delta_vs_neutral_bp: 0,
            unsupported_delta_vs_neutral_bp: 0,
            cost_delta_vs_neutral_micro_exo: 0,
            diagnostic_impact_bp: 0,
            evidence_summary: "Evidence unavailable".into(),
        }
    }
}

#[must_use]
pub fn empty_graph_refinement_report(snapshot: &GraphExplorerSnapshot) -> GraphRefinementReport {
    GraphRefinementReport {
        schema_version: GRAPH_REFINEMENT_REPORT_SCHEMA_VERSION.into(),
        source_snapshot_id: snapshot.snapshot_id.clone(),
        source_truth_level: snapshot.source_truth_level,
        advisory_only: true,
        assessed_edge_count: 0,
        assessed_node_count: 0,
        average_edge_quality_bp: 0,
        weak_edge_count: 0,
        missing_edge_candidate_count: 0,
        duplicate_edge_candidate_count: 0,
        contradicted_edge_candidate_count: 0,
        edge_assessments: Vec::new(),
        node_assessments: Vec::new(),
        missing_edge_candidates: Vec::new(),
        duplicate_edge_candidates: Vec::new(),
        recommendations: Vec::new(),
        edge_triage_items: Vec::new(),
        edge_triage_summary: EdgeTriageSummary::default(),
        edge_diagnosis_items: Vec::new(),
        edge_diagnosis_summary: EdgeDiagnosisSummary::default(),
        edge_closure_items: Vec::new(),
        edge_closure_summary: EdgeClosureSummary::default(),
        artifact_references: Vec::new(),
        warnings: vec!["refinement_artifact_unavailable".into()],
    }
}

pub fn generate_graph_refinement_artifacts()
-> Result<GraphRefinementArtifactSet, GraphExplorerError> {
    let root = repo_root_path();
    let target_dir = root.join(GRAPH_EXPLORER_TARGET_DIR);
    let snapshot_path = root.join(GRAPH_EXPLORER_SNAPSHOT_PATH);
    let inspector_path = root.join(GRAPH_EXPLORER_INSPECTOR_PATH);
    let snapshot_body = fs::read(&snapshot_path).map_err(io_error)?;
    let snapshot =
        serde_json::from_slice::<GraphExplorerSnapshot>(&snapshot_body).map_err(|error| {
            GraphExplorerError::Serialization {
                reason: error.to_string(),
            }
        })?;
    let inspector = if inspector_path.exists() {
        let inspector_body = fs::read(&inspector_path).map_err(io_error)?;
        serde_json::from_slice::<BTreeMap<String, NodeInspectorDetails>>(&inspector_body).map_err(
            |error| GraphExplorerError::Serialization {
                reason: error.to_string(),
            },
        )?
    } else {
        BTreeMap::new()
    };
    let mut artifact_references = vec![
        GRAPH_EXPLORER_SNAPSHOT_PATH.into(),
        GRAPH_EXPLORER_INSPECTOR_PATH.into(),
    ];
    if root.join(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH).exists() {
        artifact_references.push(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH.into());
    }
    if root.join(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH).exists() {
        artifact_references.push(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH.into());
    }
    let diagnostic_evidence = diagnostic_evidence_context_from_root(&root)?;
    let report = derive_graph_refinement_report_with_evidence(
        &snapshot,
        &inspector,
        artifact_references,
        &diagnostic_evidence,
    );
    let generated = write_graph_refinement_artifacts(&report, &target_dir)?;
    write_dataset_graph_refinement_artifacts_if_requested(
        &root,
        &target_dir,
        &report,
        graph_refinement_dataset_id_override()?,
    )?;
    Ok(generated)
}

pub fn derive_graph_refinement_report(
    snapshot: &GraphExplorerSnapshot,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
    artifact_references: Vec<String>,
) -> GraphRefinementReport {
    derive_graph_refinement_report_with_evidence(
        snapshot,
        inspector_details,
        artifact_references,
        &DiagnosticEvidenceContext::default(),
    )
}

fn derive_graph_refinement_report_with_evidence(
    snapshot: &GraphExplorerSnapshot,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
    artifact_references: Vec<String>,
    diagnostic_evidence: &DiagnosticEvidenceContext,
) -> GraphRefinementReport {
    let nodes_by_id = snapshot
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut sorted_edges = snapshot.edges.clone();
    sorted_edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    let edge_assessments = sorted_edges
        .iter()
        .filter_map(|edge| {
            let source = nodes_by_id.get(edge.source_node_id.as_str())?;
            let target = nodes_by_id.get(edge.target_node_id.as_str())?;
            Some(assess_edge(
                edge,
                source,
                target,
                inspector_details,
                diagnostic_evidence,
            ))
        })
        .collect::<Vec<_>>();
    let duplicate_edge_candidates = duplicate_edge_candidates(&sorted_edges);
    let missing_edge_candidates = missing_edge_candidates(&snapshot.nodes, &sorted_edges);
    let mut node_assessments = node_assessments(&snapshot.nodes, &sorted_edges);
    let mut recommendations = edge_recommendations(&edge_assessments);
    recommendations.extend(duplicate_recommendations(&duplicate_edge_candidates));
    recommendations.extend(node_recommendations(&mut node_assessments));
    recommendations.sort_by(|left, right| left.recommendation_id.cmp(&right.recommendation_id));
    recommendations.truncate(250);
    let edge_triage_items = edge_triage_items(&edge_assessments);
    let edge_triage_summary = edge_triage_summary(&edge_triage_items);
    let edge_diagnosis_items = edge_diagnosis_items(&edge_assessments, &edge_triage_items);
    let edge_diagnosis_summary = edge_diagnosis_summary(&edge_diagnosis_items);
    let edge_closure_items =
        edge_closure_items(&edge_assessments, &edge_triage_items, &edge_diagnosis_items);
    let edge_closure_summary = edge_closure_summary(&edge_closure_items);

    let assessed_edge_count = usize_to_u32_saturating(edge_assessments.len());
    let average_edge_quality_bp = average_edge_quality(&edge_assessments);
    let weak_edge_count = usize_to_u32_saturating(
        edge_assessments
            .iter()
            .filter(|assessment| assessment.edge_quality_score_bp < 5000)
            .count(),
    );
    let contradicted_edge_candidate_count = usize_to_u32_saturating(
        edge_assessments
            .iter()
            .filter(|assessment| assessment.contradiction_risk_bp >= 7000)
            .count(),
    );
    GraphRefinementReport {
        schema_version: GRAPH_REFINEMENT_REPORT_SCHEMA_VERSION.into(),
        source_snapshot_id: snapshot.snapshot_id.clone(),
        source_truth_level: snapshot.source_truth_level,
        advisory_only: true,
        assessed_edge_count,
        assessed_node_count: usize_to_u32_saturating(snapshot.nodes.len()),
        average_edge_quality_bp,
        weak_edge_count,
        missing_edge_candidate_count: usize_to_u32_saturating(missing_edge_candidates.len()),
        duplicate_edge_candidate_count: usize_to_u32_saturating(duplicate_edge_candidates.len()),
        contradicted_edge_candidate_count,
        edge_assessments,
        node_assessments,
        missing_edge_candidates,
        duplicate_edge_candidates,
        recommendations,
        edge_triage_items,
        edge_triage_summary,
        edge_diagnosis_items,
        edge_diagnosis_summary,
        edge_closure_items,
        edge_closure_summary,
        artifact_references,
        warnings: vec![
            "refinement_layer_advisory_only".into(),
            "missing_edge_candidates_are_not_source_truth".into(),
        ],
    }
}

pub fn write_graph_refinement_artifacts(
    report: &GraphRefinementReport,
    target_dir: &Path,
) -> Result<GraphRefinementArtifactSet, GraphExplorerError> {
    fs::create_dir_all(target_dir).map_err(io_error)?;
    let report_path = target_dir.join("refinement_report.json");
    let summary_path = target_dir.join("refinement_summary.md");
    let closure_worklist_json_path = target_dir.join("evidence_closure_worklist.json");
    let closure_worklist_md_path = target_dir.join("evidence_closure_worklist.md");
    let closure_review_template_json_path =
        target_dir.join("evidence_closure_review_template.json");
    let closure_review_template_md_path = target_dir.join("evidence_closure_review_template.md");
    let report_body = json_body(report)?;
    let summary_body = graph_refinement_summary_markdown(report);
    let dataset_id = evidence_closure_worklist_dataset_id(target_dir);
    let closure_worklist =
        evidence_closure_worklist(&dataset_id, report, repo_relative(&report_path));
    let closure_worklist_json_body = json_body(&closure_worklist)?;
    let closure_worklist_md_body = evidence_closure_worklist_markdown(&closure_worklist);
    let closure_review_template = evidence_closure_review_template(&dataset_id, report);
    let closure_review_template_json_body = json_body(&closure_review_template)?;
    let closure_review_template_md_body =
        evidence_closure_review_template_markdown(&closure_review_template);
    fs::write(&report_path, report_body.as_bytes()).map_err(io_error)?;
    fs::write(&summary_path, summary_body.as_bytes()).map_err(io_error)?;
    fs::write(
        &closure_worklist_json_path,
        closure_worklist_json_body.as_bytes(),
    )
    .map_err(io_error)?;
    fs::write(
        &closure_worklist_md_path,
        closure_worklist_md_body.as_bytes(),
    )
    .map_err(io_error)?;
    fs::write(
        &closure_review_template_json_path,
        closure_review_template_json_body.as_bytes(),
    )
    .map_err(io_error)?;
    fs::write(
        &closure_review_template_md_path,
        closure_review_template_md_body.as_bytes(),
    )
    .map_err(io_error)?;
    Ok(GraphRefinementArtifactSet {
        report_path: repo_relative(&report_path),
        summary_path: repo_relative(&summary_path),
        report_hash: sha256_bytes_hex(report_body.as_bytes()),
    })
}

fn evidence_closure_worklist_dataset_id(target_dir: &Path) -> String {
    let Some(name) = target_dir.file_name().and_then(|value| value.to_str()) else {
        return "current".into();
    };
    if name == "graph_explorer" {
        "current".into()
    } else {
        name.into()
    }
}

pub(crate) fn evidence_closure_worklist(
    dataset_id: &str,
    report: &GraphRefinementReport,
    refinement_report_reference: String,
) -> EvidenceClosureWorklist {
    let items = report
        .edge_closure_items
        .iter()
        .enumerate()
        .map(|(index, item)| EvidenceClosureWorklistItem {
            rank: usize_to_u32_saturating(index.saturating_add(1)),
            closure_id: item.closure_id.clone(),
            edge_id: item.edge_id.clone(),
            action: item.action,
            severity: item.severity,
            priority_score_bp: item.priority_score_bp,
            evidence_gap: item.evidence_gap.clone(),
            closure_instruction: item.closure_instruction.clone(),
            verification_hint: item.verification_hint.clone(),
            task_ids: item.task_ids.clone(),
            diagnostic_labels: item.diagnostic_labels.clone(),
            supporting_artifact_references: item.supporting_artifact_references.clone(),
            writeback_status: item.writeback_status,
        })
        .collect::<Vec<_>>();
    let mut artifact_references = report.artifact_references.clone();
    artifact_references.push(refinement_report_reference);
    artifact_references.sort();
    artifact_references.dedup();
    EvidenceClosureWorklist {
        schema_version: GRAPH_EVIDENCE_CLOSURE_WORKLIST_SCHEMA_VERSION.into(),
        dataset_id: dataset_id.into(),
        source_snapshot_id: report.source_snapshot_id.clone(),
        advisory_only: true,
        total_item_count: usize_to_u32_saturating(items.len()),
        action_counts: edge_closure_action_counts(&report.edge_closure_summary),
        items,
        artifact_references,
    }
}

fn edge_closure_action_counts(summary: &EdgeClosureSummary) -> BTreeMap<String, u32> {
    BTreeMap::from([
        (
            edge_closure_action_key(EdgeClosureAction::AddTaskRunnerMetadata).into(),
            summary.add_task_runner_metadata_count,
        ),
        (
            edge_closure_action_key(EdgeClosureAction::AttachReceiptOrValidation).into(),
            summary.attach_receipt_or_validation_count,
        ),
        (
            edge_closure_action_key(EdgeClosureAction::InspectRouteContext).into(),
            summary.inspect_route_context_count,
        ),
        (
            edge_closure_action_key(EdgeClosureAction::SplitOverbroadConnection).into(),
            summary.split_overbroad_connection_count,
        ),
        (
            edge_closure_action_key(EdgeClosureAction::HideNoisyConnection).into(),
            summary.hide_noisy_connection_count,
        ),
        (
            edge_closure_action_key(EdgeClosureAction::StrengthenSupportedConnection).into(),
            summary.strengthen_supported_connection_count,
        ),
        (
            edge_closure_action_key(EdgeClosureAction::ReviewMissingEvidence).into(),
            summary.review_missing_evidence_count,
        ),
    ])
}

fn evidence_closure_worklist_markdown(worklist: &EvidenceClosureWorklist) -> String {
    let mut output = String::new();
    output.push_str("# EXOCHAIN DAG DB Evidence Closure Worklist\n\n");
    output.push_str(&format!("- schema_version: {}\n", worklist.schema_version));
    output.push_str(&format!("- dataset_id: {}\n", worklist.dataset_id));
    output.push_str(&format!(
        "- source_snapshot_id: {}\n",
        worklist.source_snapshot_id
    ));
    output.push_str(&format!("- advisory_only: {}\n", worklist.advisory_only));
    output.push_str(&format!(
        "- total_item_count: {}\n",
        worklist.total_item_count
    ));
    for (action, count) in &worklist.action_counts {
        output.push_str(&format!("- {action}_count: {count}\n"));
    }
    output.push_str(&format!(
        "- artifact_references: {}\n\n",
        list_label(&worklist.artifact_references)
    ));
    output.push_str("## Top Closure Items\n\n");
    output.push_str("| rank | edge_id | action | severity | priority_score_bp | evidence_gap | verification_hint |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for item in worklist.items.iter().take(25) {
        output.push_str(&format!(
            "| {} | {} | {:?} | {:?} | {} | {} | {} |\n",
            item.rank,
            item.edge_id,
            item.action,
            item.severity,
            item.priority_score_bp,
            item.evidence_gap,
            item.verification_hint
        ));
    }
    output.push_str("\nEvidence closure guidance is advisory. No source DAG records are changed by this browser pass.\n");
    output
}

pub fn evidence_closure_review_template(
    dataset_id: &str,
    report: &GraphRefinementReport,
) -> EvidenceClosureReviewFile {
    EvidenceClosureReviewFile {
        schema_version: GRAPH_EVIDENCE_CLOSURE_REVIEW_SCHEMA_VERSION.into(),
        dataset_id: dataset_id.into(),
        source_snapshot_id: report.source_snapshot_id.clone(),
        advisory_only: true,
        items: report
            .edge_closure_items
            .iter()
            .map(|item| EvidenceClosureReviewItem {
                closure_id: item.closure_id.clone(),
                edge_id: item.edge_id.clone(),
                review_status: EvidenceClosureReviewStatus::Open,
                verification_status: EvidenceClosureVerificationStatus::NotRun,
                operator_note_redacted: String::new(),
                evidence_reference_ids: Vec::new(),
                reviewed_artifact_references: Vec::new(),
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            })
            .collect(),
    }
}

fn evidence_closure_review_template_markdown(review: &EvidenceClosureReviewFile) -> String {
    let mut output = String::new();
    output.push_str("# EXOCHAIN DAG DB Evidence Closure Review Template\n\n");
    output.push_str(&format!("- schema_version: {}\n", review.schema_version));
    output.push_str(&format!("- dataset_id: {}\n", review.dataset_id));
    output.push_str(&format!(
        "- source_snapshot_id: {}\n",
        review.source_snapshot_id
    ));
    output.push_str(&format!("- advisory_only: {}\n", review.advisory_only));
    output.push_str(&format!("- review_item_count: {}\n\n", review.items.len()));
    output.push_str("| closure_id | edge_id | review_status | verification_status |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for item in review.items.iter().take(25) {
        output.push_str(&format!(
            "| {} | {} | {:?} | {:?} |\n",
            item.closure_id, item.edge_id, item.review_status, item.verification_status
        ));
    }
    output.push_str(
        "\nReview artifacts are local and advisory. They do not mutate source DAG records.\n",
    );
    output
}

pub fn evidence_intake_packet_file(
    dataset_id: &str,
    report: &GraphRefinementReport,
    limit: u32,
) -> EvidenceIntakePacketFile {
    let capped_limit = limit.clamp(1, 500);
    let items = report
        .edge_closure_items
        .iter()
        .take(usize::try_from(capped_limit).unwrap_or(500))
        .enumerate()
        .map(|(index, item)| EvidenceIntakePacketItem {
            rank: usize_to_u32_saturating(index.saturating_add(1)),
            closure_id: item.closure_id.clone(),
            edge_id: item.edge_id.clone(),
            action: item.action,
            severity: item.severity,
            priority_score_bp: item.priority_score_bp,
            task_ids: item.task_ids.clone(),
            diagnostic_labels: item.diagnostic_labels.clone(),
            evidence_gap: item.evidence_gap.clone(),
            closure_instruction: item.closure_instruction.clone(),
            verification_hint: item.verification_hint.clone(),
            required_evidence_fields: required_evidence_fields(item.action),
            supporting_artifact_references: item.supporting_artifact_references.clone(),
            writeback_status: item.writeback_status,
        })
        .collect::<Vec<_>>();
    EvidenceIntakePacketFile {
        schema_version: GRAPH_EVIDENCE_INTAKE_PACKET_SCHEMA_VERSION.into(),
        dataset_id: dataset_id.into(),
        source_snapshot_id: report.source_snapshot_id.clone(),
        advisory_only: true,
        limit: capped_limit,
        total_packet_item_count: usize_to_u32_saturating(items.len()),
        items,
    }
}

pub fn evidence_intake_packet_markdown(packet: &EvidenceIntakePacketFile) -> String {
    let mut output = String::new();
    output.push_str("# EXOCHAIN DAG DB Evidence Intake Packets\n\n");
    output.push_str(&format!("- schema_version: {}\n", packet.schema_version));
    output.push_str(&format!("- dataset_id: {}\n", packet.dataset_id));
    output.push_str(&format!(
        "- source_snapshot_id: {}\n",
        packet.source_snapshot_id
    ));
    output.push_str(&format!("- advisory_only: {}\n", packet.advisory_only));
    output.push_str(&format!("- limit: {}\n", packet.limit));
    output.push_str(&format!(
        "- total_packet_item_count: {}\n\n",
        packet.total_packet_item_count
    ));
    output.push_str("| rank | edge_id | action | severity | priority_score_bp | evidence_gap | required_evidence_fields | verification_hint |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for item in &packet.items {
        output.push_str(&format!(
            "| {} | {} | {:?} | {:?} | {} | {} | {} | {} |\n",
            item.rank,
            item.edge_id,
            item.action,
            item.severity,
            item.priority_score_bp,
            item.evidence_gap,
            list_label(&item.required_evidence_fields),
            item.verification_hint
        ));
    }
    output.push_str("\nEvidence intake packets are advisory. No source DAG records are changed.\n");
    output
}

pub fn validate_evidence_closure_review_file(
    review: &EvidenceClosureReviewFile,
    report: &GraphRefinementReport,
) -> Result<(), GraphExplorerError> {
    if review.schema_version != GRAPH_EVIDENCE_CLOSURE_REVIEW_SCHEMA_VERSION {
        return closure_review_error("unsupported closure review schema version");
    }
    if !review.advisory_only {
        return closure_review_error("closure review must be advisory_only");
    }
    if !validate_graph_refinement_dataset_id(&review.dataset_id) {
        return closure_review_error("closure review dataset_id is invalid");
    }
    if review.source_snapshot_id != report.source_snapshot_id {
        return closure_review_error("closure review source_snapshot_id does not match report");
    }
    let known_closure_ids = report
        .edge_closure_items
        .iter()
        .map(|item| (item.closure_id.as_str(), item.edge_id.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for item in &review.items {
        if !seen.insert(item.closure_id.as_str()) {
            return closure_review_error("closure review contains duplicate closure_id");
        }
        let Some(expected_edge_id) = known_closure_ids.get(item.closure_id.as_str()) else {
            return closure_review_error("closure review contains unknown closure_id");
        };
        if item.edge_id != *expected_edge_id {
            return closure_review_error("closure review edge_id does not match closure_id");
        }
        if item.writeback_status != GraphRefinementWritebackStatus::AdvisoryOnly {
            return closure_review_error("closure review writeback_status must be advisory_only");
        }
        validate_safe_review_text("operator_note_redacted", &item.operator_note_redacted, true)?;
        validate_safe_review_values("evidence_reference_ids", &item.evidence_reference_ids)?;
        validate_safe_review_values(
            "reviewed_artifact_references",
            &item.reviewed_artifact_references,
        )?;
    }
    Ok(())
}

pub fn evidence_closure_review_summary(
    review: &EvidenceClosureReviewFile,
    report: &GraphRefinementReport,
    review_reference: String,
) -> Result<EvidenceClosureReviewSummary, GraphExplorerError> {
    validate_evidence_closure_review_file(review, report)?;
    let mut open_count = 0u32;
    let mut evidence_attached_count = 0u32;
    let mut verified_count = 0u32;
    let mut deferred_count = 0u32;
    let mut rejected_noise_count = 0u32;
    let mut keep_confirmed_count = 0u32;
    let mut top_open_items = Vec::new();
    let mut top_verified_items = Vec::new();

    let closure_rank = closure_rank_by_id(report);
    let mut ordered_items = review.items.clone();
    ordered_items.sort_by(|left, right| {
        review_item_sort_key(left, &closure_rank).cmp(&review_item_sort_key(right, &closure_rank))
    });
    let review_items = ordered_items.clone();
    for item in ordered_items {
        match item.review_status {
            EvidenceClosureReviewStatus::Open => {
                open_count = open_count.saturating_add(1);
                top_open_items.push(item);
            }
            EvidenceClosureReviewStatus::EvidenceAttached => {
                evidence_attached_count = evidence_attached_count.saturating_add(1);
            }
            EvidenceClosureReviewStatus::Verified => {
                verified_count = verified_count.saturating_add(1);
                top_verified_items.push(item);
            }
            EvidenceClosureReviewStatus::Deferred => {
                deferred_count = deferred_count.saturating_add(1);
            }
            EvidenceClosureReviewStatus::RejectedNoise => {
                rejected_noise_count = rejected_noise_count.saturating_add(1);
            }
            EvidenceClosureReviewStatus::KeepConfirmed => {
                keep_confirmed_count = keep_confirmed_count.saturating_add(1);
            }
        }
    }
    top_open_items.truncate(25);
    top_verified_items.truncate(25);
    let completed_count = evidence_attached_count
        .saturating_add(verified_count)
        .saturating_add(rejected_noise_count)
        .saturating_add(keep_confirmed_count);
    let total_closure_item_count = report.edge_closure_summary.total_closure_item_count;
    let completion_rate_bp = if total_closure_item_count == 0 {
        0
    } else {
        u16::try_from(
            completed_count
                .saturating_mul(10_000)
                .checked_div(total_closure_item_count)
                .unwrap_or(0),
        )
        .unwrap_or(10_000)
    };
    let mut artifact_references = report.artifact_references.clone();
    artifact_references.push(review_reference);
    artifact_references.sort();
    artifact_references.dedup();
    Ok(EvidenceClosureReviewSummary {
        schema_version: GRAPH_EVIDENCE_CLOSURE_REVIEW_SUMMARY_SCHEMA_VERSION.into(),
        dataset_id: review.dataset_id.clone(),
        source_snapshot_id: review.source_snapshot_id.clone(),
        advisory_only: true,
        total_closure_item_count,
        open_count,
        evidence_attached_count,
        verified_count,
        deferred_count,
        rejected_noise_count,
        keep_confirmed_count,
        completion_rate_bp,
        review_items,
        top_open_items,
        top_verified_items,
        artifact_references,
    })
}

pub fn evidence_closure_review_summary_markdown(summary: &EvidenceClosureReviewSummary) -> String {
    let mut output = String::new();
    output.push_str("# EXOCHAIN DAG DB Evidence Closure Review Summary\n\n");
    output.push_str(&format!("- schema_version: {}\n", summary.schema_version));
    output.push_str(&format!("- dataset_id: {}\n", summary.dataset_id));
    output.push_str(&format!(
        "- source_snapshot_id: {}\n",
        summary.source_snapshot_id
    ));
    output.push_str(&format!("- advisory_only: {}\n", summary.advisory_only));
    output.push_str(&format!(
        "- total_closure_item_count: {}\n",
        summary.total_closure_item_count
    ));
    output.push_str(&format!("- open_count: {}\n", summary.open_count));
    output.push_str(&format!(
        "- evidence_attached_count: {}\n",
        summary.evidence_attached_count
    ));
    output.push_str(&format!("- verified_count: {}\n", summary.verified_count));
    output.push_str(&format!("- deferred_count: {}\n", summary.deferred_count));
    output.push_str(&format!(
        "- rejected_noise_count: {}\n",
        summary.rejected_noise_count
    ));
    output.push_str(&format!(
        "- keep_confirmed_count: {}\n",
        summary.keep_confirmed_count
    ));
    output.push_str(&format!(
        "- completion_rate_bp: {}\n\n",
        summary.completion_rate_bp
    ));
    output.push_str("## Top Open Closure Items\n\n");
    output.push_str("| closure_id | edge_id | review_status | verification_status |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for item in &summary.top_open_items {
        output.push_str(&format!(
            "| {} | {} | {:?} | {:?} |\n",
            item.closure_id, item.edge_id, item.review_status, item.verification_status
        ));
    }
    output.push_str("\n## Top Verified Closure Items\n\n");
    output.push_str("| closure_id | edge_id | review_status | verification_status |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for item in &summary.top_verified_items {
        output.push_str(&format!(
            "| {} | {} | {:?} | {:?} |\n",
            item.closure_id, item.edge_id, item.review_status, item.verification_status
        ));
    }
    output.push_str("\nClosure review is advisory. No source DAG records are changed.\n");
    output
}

fn closure_rank_by_id(report: &GraphRefinementReport) -> BTreeMap<String, (u8, u16, String)> {
    report
        .edge_closure_items
        .iter()
        .map(|item| {
            (
                item.closure_id.clone(),
                (
                    edge_triage_severity_rank(item.severity),
                    u16::MAX.saturating_sub(item.priority_score_bp),
                    item.edge_id.clone(),
                ),
            )
        })
        .collect()
}

fn review_item_sort_key(
    item: &EvidenceClosureReviewItem,
    closure_rank: &BTreeMap<String, (u8, u16, String)>,
) -> (u8, u16, String, String) {
    let rank = closure_rank.get(&item.closure_id).cloned().unwrap_or((
        u8::MAX,
        u16::MAX,
        item.edge_id.clone(),
    ));
    (rank.0, rank.1, rank.2, item.closure_id.clone())
}

fn required_evidence_fields(action: EdgeClosureAction) -> Vec<String> {
    match action {
        EdgeClosureAction::AddTaskRunnerMetadata => {
            vec![
                "task_id".into(),
                "diagnostic_label".into(),
                "edge_id".into(),
            ]
        }
        EdgeClosureAction::AttachReceiptOrValidation => {
            vec![
                "receipt_id".into(),
                "validation_report_id".into(),
                "edge_id".into(),
            ]
        }
        EdgeClosureAction::InspectRouteContext => {
            vec![
                "route_id".into(),
                "context_packet_id".into(),
                "task_id".into(),
            ]
        }
        EdgeClosureAction::SplitOverbroadConnection => {
            vec![
                "replacement_edge_ids".into(),
                "task_ids".into(),
                "edge_id".into(),
            ]
        }
        EdgeClosureAction::HideNoisyConnection => {
            vec!["noise_reason".into(), "task_ids".into(), "edge_id".into()]
        }
        EdgeClosureAction::StrengthenSupportedConnection => {
            vec![
                "receipt_id".into(),
                "supporting_task_ids".into(),
                "edge_id".into(),
            ]
        }
        EdgeClosureAction::ReviewMissingEvidence => {
            vec!["review_reason".into(), "edge_id".into()]
        }
    }
}

fn validate_safe_review_values(label: &str, values: &[String]) -> Result<(), GraphExplorerError> {
    for value in values {
        validate_safe_review_text(label, value, false)?;
    }
    Ok(())
}

fn validate_safe_review_text(
    label: &str,
    value: &str,
    enforce_note_length: bool,
) -> Result<(), GraphExplorerError> {
    if !value.is_ascii() {
        return closure_review_error(&format!("{label} must be ASCII"));
    }
    if enforce_note_length && value.chars().count() > 280 {
        return closure_review_error(&format!("{label} exceeds 280 characters"));
    }
    let lower = value.to_ascii_lowercase();
    let blocked = [
        "postgres://",
        "mysql://",
        "mongodb://",
        "database_url",
        "connection_string",
        "password",
        "secret",
        "token",
        "credential",
        "/users/",
        "file_contents",
        "payload_text",
        "raw_text",
        "phi",
        "pii",
        "nda",
        "```",
    ];
    if blocked.iter().any(|needle| lower.contains(needle)) || contains_url_with_credentials(value) {
        return closure_review_error(&format!("{label} contains unsafe review content"));
    }
    Ok(())
}

fn contains_url_with_credentials(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|part| part.contains("://") && part.contains('@') && part.contains(':'))
}

fn closure_review_error<T>(reason: &str) -> Result<T, GraphExplorerError> {
    Err(GraphExplorerError::Serialization {
        reason: format!("evidence_closure_review_invalid: {reason}"),
    })
}

fn graph_refinement_dataset_id_override() -> Result<Option<String>, GraphExplorerError> {
    match env::var(GRAPH_DATASET_ID_OVERRIDE_ENV) {
        Ok(value) => parse_graph_refinement_dataset_id(value).map(Some),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(value)) => Err(GraphExplorerError::InvalidDatasetId {
            dataset_id: value.to_string_lossy().into_owned(),
        }),
    }
}

fn parse_graph_refinement_dataset_id(value: String) -> Result<String, GraphExplorerError> {
    let dataset_id = value.trim();
    if validate_graph_refinement_dataset_id(dataset_id) {
        Ok(dataset_id.to_owned())
    } else {
        Err(GraphExplorerError::InvalidDatasetId { dataset_id: value })
    }
}

fn validate_graph_refinement_dataset_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    let mut len = 1usize;
    for ch in chars {
        len += 1;
        if len > 80 {
            return false;
        }
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '.' && ch != '_' && ch != '-' {
            return false;
        }
    }
    true
}

fn derive_dataset_graph_refinement_report(
    root: &Path,
    dataset_dir: &Path,
) -> Result<Option<GraphRefinementReport>, GraphExplorerError> {
    let snapshot_path = dataset_dir.join("snapshot.json");
    if !snapshot_path.exists() {
        return Ok(None);
    }
    let inspector_path = dataset_dir.join("node_inspector_details.json");
    let snapshot_body = fs::read(&snapshot_path).map_err(io_error)?;
    let snapshot =
        serde_json::from_slice::<GraphExplorerSnapshot>(&snapshot_body).map_err(|error| {
            GraphExplorerError::Serialization {
                reason: error.to_string(),
            }
        })?;
    let inspector = if inspector_path.exists() {
        let inspector_body = fs::read(&inspector_path).map_err(io_error)?;
        serde_json::from_slice::<BTreeMap<String, NodeInspectorDetails>>(&inspector_body).map_err(
            |error| GraphExplorerError::Serialization {
                reason: error.to_string(),
            },
        )?
    } else {
        BTreeMap::new()
    };
    let mut artifact_references = vec![
        repo_relative(&snapshot_path),
        repo_relative(&inspector_path),
    ];
    if root.join(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH).exists() {
        artifact_references.push(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH.into());
    }
    if root.join(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH).exists() {
        artifact_references.push(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH.into());
    }
    let diagnostic_evidence = diagnostic_evidence_context_from_root(root)?;
    Ok(Some(derive_graph_refinement_report_with_evidence(
        &snapshot,
        &inspector,
        artifact_references,
        &diagnostic_evidence,
    )))
}

fn write_dataset_graph_refinement_artifacts_if_requested(
    root: &Path,
    target_dir: &Path,
    report: &GraphRefinementReport,
    dataset_id: Option<String>,
) -> Result<(), GraphExplorerError> {
    let Some(dataset_id) = dataset_id else {
        return Ok(());
    };
    let dataset_dir = target_dir.join("datasets").join(dataset_id);
    let dataset_report = derive_dataset_graph_refinement_report(root, &dataset_dir)?
        .unwrap_or_else(|| report.clone());
    write_graph_refinement_artifacts(&dataset_report, &dataset_dir)?;
    Ok(())
}

pub(crate) fn graph_refinement_summary_markdown(report: &GraphRefinementReport) -> String {
    let evidence_backed_edge_count = report
        .edge_assessments
        .iter()
        .filter(|assessment| {
            matches!(
                assessment.evidence_level,
                EdgeEvidenceLevel::DirectTaskRunnerMatch
                    | EdgeEvidenceLevel::TaskMatch
                    | EdgeEvidenceLevel::RunnerMatch
            )
        })
        .count();
    let unavailable_edge_evidence_count = report
        .edge_assessments
        .iter()
        .filter(|assessment| {
            matches!(
                assessment.evidence_level,
                EdgeEvidenceLevel::ArtifactReferenceOnly | EdgeEvidenceLevel::Unavailable
            )
        })
        .count();
    let average_diagnostic_impact_bp = average_diagnostic_impact_bp(&report.edge_assessments);
    format!(
        "# EXOCHAIN DAG DB Graph Refinement Summary\n\n\
         - schema_version: {}\n\
         - source_snapshot_id: {}\n\
         - source_truth_level: {:?}\n\
         - advisory_only: {}\n\
         - assessed_edge_count: {}\n\
         - assessed_node_count: {}\n\
         - weak_edge_count: {}\n\
         - missing_edge_candidate_count: {}\n\
         - duplicate_edge_candidate_count: {}\n\
         - contradicted_edge_candidate_count: {}\n\
         - average_edge_quality_bp: {}\n\
         - evidence_backed_edge_count: {}\n\
         - unavailable_edge_evidence_count: {}\n\
         - average_diagnostic_impact_bp: {}\n\
         - edge_triage_item_count: {}\n\
         - edge_triage_no_evidence_count: {}\n\
         - edge_triage_negative_quality_delta_count: {}\n\
         - edge_triage_negative_citation_delta_count: {}\n\
         - edge_triage_higher_unsupported_claim_rate_count: {}\n\
         - edge_triage_higher_cost_than_neutral_count: {}\n\
         - edge_triage_weak_frequent_edge_count: {}\n\
         - edge_triage_strong_keep_candidate_count: {}\n\
         - edge_diagnosis_item_count: {}\n\
         - edge_diagnosis_quality_regression_count: {}\n\
         - edge_diagnosis_citation_regression_count: {}\n\
         - edge_diagnosis_unsupported_claim_regression_count: {}\n\
         - edge_diagnosis_cost_regression_count: {}\n\
         - edge_diagnosis_weak_frequent_connection_count: {}\n\
         - edge_diagnosis_missing_evidence_count: {}\n\
         - edge_closure_item_count: {}\n\
         - edge_closure_add_task_runner_metadata_count: {}\n\
         - edge_closure_attach_receipt_or_validation_count: {}\n\
         - edge_closure_inspect_route_context_count: {}\n\
         - edge_closure_split_overbroad_connection_count: {}\n\
         - edge_closure_hide_noisy_connection_count: {}\n\
         - edge_closure_strengthen_supported_connection_count: {}\n\
         - edge_closure_review_missing_evidence_count: {}\n\
         - artifact_references: {}\n\
         - warnings: {}\n\n\
         Refinement recommendations are advisory. No source DAG records are changed by this browser pass.\n",
        report.schema_version,
        report.source_snapshot_id,
        report.source_truth_level,
        report.advisory_only,
        report.assessed_edge_count,
        report.assessed_node_count,
        report.weak_edge_count,
        report.missing_edge_candidate_count,
        report.duplicate_edge_candidate_count,
        report.contradicted_edge_candidate_count,
        report.average_edge_quality_bp,
        evidence_backed_edge_count,
        unavailable_edge_evidence_count,
        average_diagnostic_impact_bp,
        report.edge_triage_summary.total_triage_item_count,
        report.edge_triage_summary.no_evidence_count,
        report.edge_triage_summary.negative_quality_delta_count,
        report.edge_triage_summary.negative_citation_delta_count,
        report
            .edge_triage_summary
            .higher_unsupported_claim_rate_count,
        report.edge_triage_summary.higher_cost_than_neutral_count,
        report.edge_triage_summary.weak_frequent_edge_count,
        report.edge_triage_summary.strong_keep_candidate_count,
        report.edge_diagnosis_summary.total_diagnosis_item_count,
        report.edge_diagnosis_summary.quality_regression_count,
        report.edge_diagnosis_summary.citation_regression_count,
        report
            .edge_diagnosis_summary
            .unsupported_claim_regression_count,
        report.edge_diagnosis_summary.cost_regression_count,
        report.edge_diagnosis_summary.weak_frequent_connection_count,
        report.edge_diagnosis_summary.missing_evidence_count,
        report.edge_closure_summary.total_closure_item_count,
        report.edge_closure_summary.add_task_runner_metadata_count,
        report
            .edge_closure_summary
            .attach_receipt_or_validation_count,
        report.edge_closure_summary.inspect_route_context_count,
        report.edge_closure_summary.split_overbroad_connection_count,
        report.edge_closure_summary.hide_noisy_connection_count,
        report
            .edge_closure_summary
            .strengthen_supported_connection_count,
        report.edge_closure_summary.review_missing_evidence_count,
        list_label(&report.artifact_references),
        report.warnings.join(", ")
    )
}

fn assess_edge(
    edge: &GraphExplorerEdge,
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
    diagnostic_evidence: &DiagnosticEvidenceContext,
) -> EdgeRefinementAssessment {
    let edge_diagnostic_evidence =
        edge_diagnostic_evidence(edge, source, target, diagnostic_evidence);
    let evidence_strength_bp = evidence_strength(edge, source, target, inspector_details);
    let contradiction_risk_bp = contradiction_risk(edge, source, target);
    let staleness_risk_bp = staleness_risk(edge, source, target);
    let routing_usefulness_bp = routing_usefulness(edge, source, target, inspector_details);
    let edge_quality_score_bp = edge_quality_score(
        evidence_strength_bp,
        contradiction_risk_bp,
        staleness_risk_bp,
        routing_usefulness_bp,
        edge_diagnostic_evidence.diagnostic_impact_bp,
    );
    let recommended_action = recommended_edge_action(
        edge_quality_score_bp,
        contradiction_risk_bp,
        staleness_risk_bp,
    );
    EdgeRefinementAssessment {
        edge_id: edge.edge_id.clone(),
        source_node_id: edge.source_node_id.clone(),
        target_node_id: edge.target_node_id.clone(),
        edge_kind: edge_kind_key(edge.edge_kind).into(),
        graph_style: graph_style_key(edge.graph_style).into(),
        edge_quality_score_bp,
        evidence_strength_bp,
        contradiction_risk_bp,
        staleness_risk_bp,
        routing_usefulness_bp,
        confidence_reason: edge_confidence_reason(
            edge_quality_score_bp,
            evidence_strength_bp,
            contradiction_risk_bp,
            staleness_risk_bp,
            routing_usefulness_bp,
            edge_diagnostic_evidence.diagnostic_impact_bp,
        ),
        recommended_action,
        supporting_artifact_references: edge_supporting_artifacts(edge, &edge_diagnostic_evidence),
        weakening_artifact_references: edge_weakening_artifacts(
            contradiction_risk_bp,
            staleness_risk_bp,
        ),
        evidence_level: edge_diagnostic_evidence.evidence_level,
        task_usage_count: edge_diagnostic_evidence.task_usage_count,
        matched_task_ids: edge_diagnostic_evidence.matched_task_ids,
        matched_diagnostic_labels: edge_diagnostic_evidence.matched_diagnostic_labels,
        avg_quality_bp: edge_diagnostic_evidence.avg_quality_bp,
        avg_citation_accuracy_bp: edge_diagnostic_evidence.avg_citation_accuracy_bp,
        avg_unsupported_claim_rate_bp: edge_diagnostic_evidence.avg_unsupported_claim_rate_bp,
        quality_delta_vs_neutral_bp: edge_diagnostic_evidence.quality_delta_vs_neutral_bp,
        citation_delta_vs_neutral_bp: edge_diagnostic_evidence.citation_delta_vs_neutral_bp,
        unsupported_delta_vs_neutral_bp: edge_diagnostic_evidence.unsupported_delta_vs_neutral_bp,
        cost_delta_vs_neutral_micro_exo: edge_diagnostic_evidence.cost_delta_vs_neutral_micro_exo,
        diagnostic_impact_bp: edge_diagnostic_evidence.diagnostic_impact_bp,
        evidence_summary: edge_diagnostic_evidence.evidence_summary,
    }
}

fn evidence_strength(
    edge: &GraphExplorerEdge,
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
) -> u16 {
    let mut score = 0u16;
    if edge.receipt_id.is_some() {
        score = capped_add_bp(score, 2500);
    }
    if !source.receipt_ids.is_empty() || !target.receipt_ids.is_empty() {
        score = capped_add_bp(score, 2500);
    }
    if shares_catalog_or_hash_prefix(source, target) {
        score = capped_add_bp(score, 2000);
    }
    if matches!(
        edge.graph_style,
        MemoryGraphStyle::ContextPacketGraph | MemoryGraphStyle::RoutingViewGraph
    ) {
        score = capped_add_bp(score, 1500);
    }
    if inspector_references_edge_endpoints(edge, inspector_details) {
        score = capped_add_bp(score, 1500);
    }
    score
}

fn contradiction_risk(
    edge: &GraphExplorerEdge,
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
) -> u16 {
    let mut score = 0u16;
    if edge.edge_kind == MemoryEdgeKind::Contradicts {
        score = capped_add_bp(score, 10000);
    }
    if source.status == GraphExplorerNodeStatus::Contradicted
        || target.status == GraphExplorerNodeStatus::Contradicted
    {
        score = capped_add_bp(score, 8000);
    }
    if edge.graph_style == MemoryGraphStyle::ContradictionSupersessionGraph {
        score = capped_add_bp(score, 6000);
    }
    score
}

fn staleness_risk(
    edge: &GraphExplorerEdge,
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
) -> u16 {
    let mut score = 0u16;
    if matches!(
        edge.status,
        GraphExplorerEdgeStatus::Tombstoned
            | GraphExplorerEdgeStatus::Stale
            | GraphExplorerEdgeStatus::Revoked
    ) {
        score = capped_add_bp(score, 9000);
    }
    if source.status == GraphExplorerNodeStatus::Superseded
        || target.status == GraphExplorerNodeStatus::Superseded
    {
        score = capped_add_bp(score, 7000);
    }
    if source.status == GraphExplorerNodeStatus::Duplicate
        || target.status == GraphExplorerNodeStatus::Duplicate
    {
        score = capped_add_bp(score, 5000);
    }
    score
}

fn routing_usefulness(
    edge: &GraphExplorerEdge,
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
) -> u16 {
    let mut score = 0u16;
    if edge.graph_style == MemoryGraphStyle::RoutingViewGraph {
        score = capped_add_bp(score, 2500);
    }
    if edge.graph_style == MemoryGraphStyle::ContextPacketGraph {
        score = capped_add_bp(score, 2500);
    }
    if source.node_kind == MemoryNodeKind::Route || target.node_kind == MemoryNodeKind::Route {
        score = capped_add_bp(score, 2000);
    }
    if endpoint_details_have_context_packets(source, target, inspector_details) {
        score = capped_add_bp(score, 2000);
    }
    if endpoint_details_have_validation_reports(source, target, inspector_details) {
        score = capped_add_bp(score, 1000);
    }
    score
}

fn diagnostic_evidence_context_from_root(
    root: &Path,
) -> Result<DiagnosticEvidenceContext, GraphExplorerError> {
    let per_task_path = root.join(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH);
    if !per_task_path.exists() {
        return Ok(DiagnosticEvidenceContext::default());
    }
    let body = fs::read(per_task_path).map_err(io_error)?;
    let rows = serde_json::from_slice::<Vec<DiagnosticEvidenceRow>>(&body).map_err(|error| {
        GraphExplorerError::Serialization {
            reason: error.to_string(),
        }
    })?;
    Ok(diagnostic_evidence_context_from_rows(rows))
}

fn diagnostic_evidence_context_from_rows(
    rows: Vec<DiagnosticEvidenceRow>,
) -> DiagnosticEvidenceContext {
    let mut context = DiagnosticEvidenceContext::default();
    for row in rows {
        let fixture_task_key = (row.fixture_id.clone(), row.task_id.clone());
        if row.diagnostic_label == "neutral_long_context" {
            context
                .neutral_by_fixture_task
                .insert(fixture_task_key.clone(), row.clone());
        } else if row.diagnostic_label == "neutral_flat_rag" {
            context
                .neutral_by_fixture_task
                .entry(fixture_task_key.clone())
                .or_insert_with(|| row.clone());
        }

        if !is_graph_enabled_diagnostic_label(&row.diagnostic_label) {
            continue;
        }
        if row.task_id.is_empty() {
            continue;
        }
        context
            .rows_by_task_label
            .entry((row.task_id.clone(), row.diagnostic_label.clone()))
            .or_default()
            .push(row.clone());
        context
            .rows_by_task
            .entry(row.task_id.clone())
            .or_default()
            .push(row.clone());
        context
            .rows_by_label
            .entry(row.diagnostic_label.clone())
            .or_default()
            .push(row);
    }
    context
}

fn is_graph_enabled_diagnostic_label(label: &str) -> bool {
    matches!(
        label,
        "dag_db_routing_raw" | "governed_dagdb" | "governed_dagdb_optimized"
    )
}

fn edge_diagnostic_evidence(
    edge: &GraphExplorerEdge,
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
    context: &DiagnosticEvidenceContext,
) -> EdgeDiagnosticEvidence {
    let task_ids = edge_task_ids(source, target);
    let diagnostic_labels = edge_diagnostic_labels(source, target);
    let mut seen = BTreeSet::<(String, String, String)>::new();
    let mut rows = Vec::<DiagnosticEvidenceRow>::new();

    for task_id in &task_ids {
        for diagnostic_label in &diagnostic_labels {
            if let Some(matches) = context
                .rows_by_task_label
                .get(&(task_id.clone(), diagnostic_label.clone()))
            {
                push_unique_diagnostic_rows(matches, &mut seen, &mut rows);
            }
        }
    }
    if !rows.is_empty() {
        return aggregate_edge_diagnostic_evidence(
            EdgeEvidenceLevel::DirectTaskRunnerMatch,
            rows,
            context,
        );
    }

    for task_id in &task_ids {
        if let Some(matches) = context.rows_by_task.get(task_id) {
            push_unique_diagnostic_rows(matches, &mut seen, &mut rows);
        }
    }
    if !rows.is_empty() {
        return aggregate_edge_diagnostic_evidence(EdgeEvidenceLevel::TaskMatch, rows, context);
    }

    for diagnostic_label in &diagnostic_labels {
        if let Some(matches) = context.rows_by_label.get(diagnostic_label) {
            push_unique_diagnostic_rows(matches, &mut seen, &mut rows);
        }
    }
    if !rows.is_empty() {
        return aggregate_edge_diagnostic_evidence(EdgeEvidenceLevel::RunnerMatch, rows, context);
    }

    if edge.receipt_id.is_some() || source.source_hash.is_some() || target.source_hash.is_some() {
        return EdgeDiagnosticEvidence {
            evidence_level: EdgeEvidenceLevel::ArtifactReferenceOnly,
            evidence_summary:
                "Evidence unavailable; edge has graph artifact references but no matched diagnostic rows"
                    .into(),
            ..EdgeDiagnosticEvidence::default()
        };
    }
    EdgeDiagnosticEvidence::default()
}

fn edge_task_ids(source: &GraphExplorerNode, target: &GraphExplorerNode) -> Vec<String> {
    let mut task_ids = BTreeSet::<String>::new();
    for label in [&source.label, &target.label] {
        if let Some(task_id) = task_id_from_label(label) {
            task_ids.insert(task_id);
        }
    }
    task_ids.into_iter().collect()
}

fn task_id_from_label(label: &str) -> Option<String> {
    let prefix = label.split_whitespace().next().unwrap_or_default();
    if is_task_id(prefix) {
        Some(prefix.into())
    } else {
        None
    }
}

fn is_task_id(value: &str) -> bool {
    if let Some(number) = value.strip_prefix('t') {
        return !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit());
    }
    if let Some(number) = value.strip_prefix("scale-t") {
        return !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit());
    }
    false
}

fn edge_diagnostic_labels(source: &GraphExplorerNode, target: &GraphExplorerNode) -> Vec<String> {
    let mut labels = BTreeSet::<String>::new();
    for value in [source.label.as_str(), target.label.as_str()] {
        collect_diagnostic_labels_from_value(value, &mut labels);
    }
    for metadata in source
        .metadata_summary
        .iter()
        .chain(target.metadata_summary.iter())
    {
        collect_diagnostic_labels_from_value(metadata, &mut labels);
    }
    labels.into_iter().collect()
}

fn collect_diagnostic_labels_from_value(value: &str, labels: &mut BTreeSet<String>) {
    for prefix in ["runner:", "context packets:", "diagnostic_label:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let label = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_matches(|ch: char| ch == ',' || ch == ';');
            if !label.is_empty() {
                labels.insert(label.into());
            }
        }
    }
}

fn push_unique_diagnostic_rows(
    rows: &[DiagnosticEvidenceRow],
    seen: &mut BTreeSet<(String, String, String)>,
    target: &mut Vec<DiagnosticEvidenceRow>,
) {
    for row in rows {
        let key = (
            row.fixture_id.clone(),
            row.task_id.clone(),
            row.diagnostic_label.clone(),
        );
        if seen.insert(key) {
            target.push(row.clone());
        }
    }
}

fn aggregate_edge_diagnostic_evidence(
    evidence_level: EdgeEvidenceLevel,
    rows: Vec<DiagnosticEvidenceRow>,
    context: &DiagnosticEvidenceContext,
) -> EdgeDiagnosticEvidence {
    let mut task_ids = BTreeSet::<String>::new();
    let mut diagnostic_labels = BTreeSet::<String>::new();
    let mut quality_values = Vec::<u16>::new();
    let mut citation_values = Vec::<u16>::new();
    let mut unsupported_values = Vec::<u16>::new();
    let mut quality_deltas = Vec::<i32>::new();
    let mut citation_deltas = Vec::<i32>::new();
    let mut unsupported_deltas = Vec::<i32>::new();
    let mut cost_deltas = Vec::<i64>::new();

    for row in &rows {
        task_ids.insert(row.task_id.clone());
        diagnostic_labels.insert(row.diagnostic_label.clone());
        if let Some(value) = row.quality_score_bp {
            quality_values.push(value);
        }
        if let Some(value) = row.citation_accuracy_bp {
            citation_values.push(value);
        }
        if let Some(value) = row.unsupported_claim_rate_bp {
            unsupported_values.push(value);
        }
        let neutral = context
            .neutral_by_fixture_task
            .get(&(row.fixture_id.clone(), row.task_id.clone()));
        if let Some(neutral_row) = neutral {
            if let (Some(graph), Some(base)) = (row.quality_score_bp, neutral_row.quality_score_bp)
            {
                quality_deltas.push(i32::from(graph) - i32::from(base));
            }
            if let (Some(graph), Some(base)) =
                (row.citation_accuracy_bp, neutral_row.citation_accuracy_bp)
            {
                citation_deltas.push(i32::from(graph) - i32::from(base));
            }
            if let (Some(graph), Some(base)) = (
                row.unsupported_claim_rate_bp,
                neutral_row.unsupported_claim_rate_bp,
            ) {
                unsupported_deltas.push(i32::from(base) - i32::from(graph));
            }
            if let (Some(graph), Some(base)) =
                (row.total_cost_micro_exo, neutral_row.total_cost_micro_exo)
            {
                cost_deltas.push(i64::from(base) - i64::from(graph));
            }
        }
    }

    let matched_task_ids = task_ids.into_iter().collect::<Vec<_>>();
    let matched_diagnostic_labels = diagnostic_labels.into_iter().collect::<Vec<_>>();
    let quality_delta = average_i32(&quality_deltas);
    let citation_delta = average_i32(&citation_deltas);
    let unsupported_delta = average_i32(&unsupported_deltas);
    let cost_delta = average_i64(&cost_deltas);
    let diagnostic_impact_bp =
        diagnostic_impact_bp(quality_delta, citation_delta, unsupported_delta);
    let task_usage_count = usize_to_u32_saturating(rows.len());

    EdgeDiagnosticEvidence {
        evidence_level,
        task_usage_count,
        matched_task_ids,
        matched_diagnostic_labels,
        avg_quality_bp: average_u16(&quality_values),
        avg_citation_accuracy_bp: average_u16(&citation_values),
        avg_unsupported_claim_rate_bp: average_u16(&unsupported_values),
        quality_delta_vs_neutral_bp: quality_delta,
        citation_delta_vs_neutral_bp: citation_delta,
        unsupported_delta_vs_neutral_bp: unsupported_delta,
        cost_delta_vs_neutral_micro_exo: cost_delta,
        diagnostic_impact_bp,
        evidence_summary: evidence_summary(evidence_level, task_usage_count, diagnostic_impact_bp),
    }
}

fn diagnostic_impact_bp(quality_delta: i32, citation_delta: i32, unsupported_delta: i32) -> u16 {
    let impact = quality_delta.max(0) + citation_delta.max(0) + unsupported_delta.max(0);
    u16::try_from(impact).unwrap_or(u16::MAX).min(10_000)
}

fn evidence_summary(
    evidence_level: EdgeEvidenceLevel,
    task_usage_count: u32,
    diagnostic_impact_bp: u16,
) -> String {
    let level = match evidence_level {
        EdgeEvidenceLevel::DirectTaskRunnerMatch => "direct task/runner",
        EdgeEvidenceLevel::TaskMatch => "task",
        EdgeEvidenceLevel::RunnerMatch => "runner",
        EdgeEvidenceLevel::ArtifactReferenceOnly => "artifact reference only",
        EdgeEvidenceLevel::Unavailable => "unavailable",
    };
    format!(
        "{level} evidence from {task_usage_count} diagnostic rows; diagnostic_impact_bp:{diagnostic_impact_bp}"
    )
}

fn average_u16(values: &[u16]) -> u16 {
    if values.is_empty() {
        return 0;
    }
    let total = values.iter().map(|value| u32::from(*value)).sum::<u32>();
    u32_to_u16_saturating(total / usize_to_u32_saturating(values.len()))
}

fn average_i32(values: &[i32]) -> i32 {
    if values.is_empty() {
        return 0;
    }
    let total = values.iter().copied().sum::<i32>();
    total / i32::try_from(values.len()).unwrap_or(i32::MAX).max(1)
}

fn average_i64(values: &[i64]) -> i64 {
    if values.is_empty() {
        return 0;
    }
    let total = values.iter().copied().sum::<i64>();
    total / i64::try_from(values.len()).unwrap_or(i64::MAX).max(1)
}

fn edge_quality_score(
    evidence_strength_bp: u16,
    contradiction_risk_bp: u16,
    staleness_risk_bp: u16,
    routing_usefulness_bp: u16,
    diagnostic_impact_bp: u16,
) -> u16 {
    let score = (u32::from(evidence_strength_bp) * 4)
        + (u32::from(routing_usefulness_bp) * 3)
        + (u32::from(diagnostic_impact_bp) * 2)
        + (u32::from(10_000u16.saturating_sub(contradiction_risk_bp)) * 2)
        + u32::from(10_000u16.saturating_sub(staleness_risk_bp));
    u32_to_u16_saturating(score / 12)
}

fn recommended_edge_action(
    edge_quality_score_bp: u16,
    contradiction_risk_bp: u16,
    staleness_risk_bp: u16,
) -> GraphRefinementAction {
    if contradiction_risk_bp >= 7000 {
        return GraphRefinementAction::Supersede;
    }
    if staleness_risk_bp >= 7000 {
        return GraphRefinementAction::Review;
    }
    if edge_quality_score_bp >= 7500 && contradiction_risk_bp < 3000 {
        return GraphRefinementAction::Keep;
    }
    if edge_quality_score_bp >= 5000 {
        return GraphRefinementAction::Strengthen;
    }
    GraphRefinementAction::Review
}

fn edge_confidence_reason(
    edge_quality_score_bp: u16,
    evidence_strength_bp: u16,
    contradiction_risk_bp: u16,
    staleness_risk_bp: u16,
    routing_usefulness_bp: u16,
    diagnostic_impact_bp: u16,
) -> String {
    format!(
        "quality:{edge_quality_score_bp}; evidence:{evidence_strength_bp}; routing:{routing_usefulness_bp}; diagnostic_impact:{diagnostic_impact_bp}; contradiction_risk:{contradiction_risk_bp}; staleness_risk:{staleness_risk_bp}"
    )
}

fn edge_supporting_artifacts(
    edge: &GraphExplorerEdge,
    diagnostic_evidence: &EdgeDiagnosticEvidence,
) -> Vec<String> {
    let mut references = vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()];
    if edge.receipt_id.is_some() {
        references.push(GRAPH_EXPLORER_INSPECTOR_PATH.into());
    }
    if matches!(
        diagnostic_evidence.evidence_level,
        EdgeEvidenceLevel::DirectTaskRunnerMatch
            | EdgeEvidenceLevel::TaskMatch
            | EdgeEvidenceLevel::RunnerMatch
    ) {
        references.push(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH.into());
    }
    references
}

fn edge_weakening_artifacts(contradiction_risk_bp: u16, staleness_risk_bp: u16) -> Vec<String> {
    if contradiction_risk_bp >= 7000 || staleness_risk_bp >= 7000 {
        vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()]
    } else {
        Vec::new()
    }
}

fn shares_catalog_or_hash_prefix(source: &GraphExplorerNode, target: &GraphExplorerNode) -> bool {
    let shared_catalog = source
        .catalog_path
        .first()
        .zip(target.catalog_path.first())
        .is_some_and(|(left, right)| !left.is_empty() && left == right);
    let shared_hash_prefix = source
        .source_hash
        .as_deref()
        .zip(target.source_hash.as_deref())
        .is_some_and(|(left, right)| {
            let prefix_len = left.len().min(right.len()).min(12);
            prefix_len >= 8 && left[..prefix_len] == right[..prefix_len]
        });
    shared_catalog || shared_hash_prefix
}

fn inspector_references_edge_endpoints(
    edge: &GraphExplorerEdge,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
) -> bool {
    endpoint_details(edge, inspector_details)
        .iter()
        .any(|details| {
            contains_endpoint_reference(&details.evidence, edge)
                || contains_endpoint_reference(&details.routes, edge)
                || contains_endpoint_reference(&details.context_packets, edge)
                || details
                    .edge_details
                    .iter()
                    .any(|detail| detail.edge_id == edge.edge_id)
        })
}

fn contains_endpoint_reference(values: &[String], edge: &GraphExplorerEdge) -> bool {
    values.iter().any(|value| {
        value.contains(&edge.edge_id)
            || value.contains(&edge.source_node_id)
            || value.contains(&edge.target_node_id)
    })
}

fn endpoint_details<'a>(
    edge: &GraphExplorerEdge,
    inspector_details: &'a BTreeMap<String, NodeInspectorDetails>,
) -> Vec<&'a NodeInspectorDetails> {
    [edge.source_node_id.as_str(), edge.target_node_id.as_str()]
        .into_iter()
        .filter_map(|node_id| inspector_details.get(node_id))
        .collect()
}

fn endpoint_details_have_context_packets(
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
) -> bool {
    endpoint_node_details(source, target, inspector_details)
        .iter()
        .any(|details| !details.context_packets.is_empty())
}

fn endpoint_details_have_validation_reports(
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
) -> bool {
    endpoint_node_details(source, target, inspector_details)
        .iter()
        .any(|details| !details.validation_reports.is_empty())
}

fn endpoint_node_details<'a>(
    source: &GraphExplorerNode,
    target: &GraphExplorerNode,
    inspector_details: &'a BTreeMap<String, NodeInspectorDetails>,
) -> Vec<&'a NodeInspectorDetails> {
    [source.node_id.as_str(), target.node_id.as_str()]
        .into_iter()
        .filter_map(|node_id| inspector_details.get(node_id))
        .collect()
}

fn duplicate_edge_candidates(edges: &[GraphExplorerEdge]) -> Vec<DuplicateEdgeCandidate> {
    let mut by_identity = BTreeMap::<String, Vec<String>>::new();
    for edge in edges {
        by_identity
            .entry(format!(
                "{}:{}:{}",
                edge.source_node_id,
                edge.target_node_id,
                edge_kind_key(edge.edge_kind)
            ))
            .or_default()
            .push(edge.edge_id.clone());
    }
    by_identity
        .into_values()
        .filter_map(|mut edge_ids| {
            edge_ids.sort();
            if edge_ids.len() < 2 {
                return None;
            }
            Some(DuplicateEdgeCandidate {
                candidate_id: format!("duplicate-{}", edge_ids.join("-")),
                edge_ids,
                confidence_bp: 8000,
                reason: "multiple source edges share the same endpoints and edge kind".into(),
            })
        })
        .collect()
}

fn missing_edge_candidates(
    nodes: &[GraphExplorerNode],
    edges: &[GraphExplorerEdge],
) -> Vec<MissingEdgeCandidate> {
    let existing = edges
        .iter()
        .map(|edge| format!("{}:{}", edge.source_node_id, edge.target_node_id))
        .collect::<BTreeSet<_>>();
    let mut sorted_nodes = nodes.to_vec();
    sorted_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let mut candidates = Vec::new();
    for source in &sorted_nodes {
        for target in &sorted_nodes {
            if source.node_id.as_str() >= target.node_id.as_str() {
                continue;
            }
            if candidates.len() >= 100 {
                return candidates;
            }
            if existing.contains(&format!("{}:{}", source.node_id, target.node_id))
                || existing.contains(&format!("{}:{}", target.node_id, source.node_id))
            {
                continue;
            }
            if !shares_catalog_or_hash_prefix(source, target) {
                continue;
            }
            candidates.push(MissingEdgeCandidate {
                candidate_id: format!("missing-{}-{}", source.node_id, target.node_id),
                source_node_id: source.node_id.clone(),
                target_node_id: target.node_id.clone(),
                suggested_edge_kind: "related_to".into(),
                confidence_bp: 5000,
                reason: "nodes share catalog path or source hash prefix; candidate only, not source truth".into(),
                supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            });
        }
    }
    candidates
}

fn node_assessments(
    nodes: &[GraphExplorerNode],
    edges: &[GraphExplorerEdge],
) -> Vec<NodeRefinementAssessment> {
    let mut degree_by_node = BTreeMap::<String, u32>::new();
    for node in nodes {
        degree_by_node.insert(node.node_id.clone(), 0);
    }
    for edge in edges {
        if let Some(degree) = degree_by_node.get_mut(&edge.source_node_id) {
            *degree = degree.saturating_add(1);
        }
        if let Some(degree) = degree_by_node.get_mut(&edge.target_node_id) {
            *degree = degree.saturating_add(1);
        }
    }
    let hub_threshold = (usize_to_u32_saturating(edges.len()) / 10).max(8);
    let mut sorted_nodes = nodes.to_vec();
    sorted_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    sorted_nodes
        .into_iter()
        .map(|node| {
            let degree = *degree_by_node.get(&node.node_id).unwrap_or(&0);
            NodeRefinementAssessment {
                node_id: node.node_id.clone(),
                visible_degree: degree,
                is_high_degree_hub: degree > hub_threshold,
                is_isolated_important_node: degree == 0 && is_important_node(&node),
                recommendation_ids: Vec::new(),
            }
        })
        .collect()
}

fn is_important_node(node: &GraphExplorerNode) -> bool {
    !node.receipt_ids.is_empty()
        || matches!(
            node.node_kind,
            MemoryNodeKind::Decision | MemoryNodeKind::Route | MemoryNodeKind::ValidationReport
        )
}

fn edge_recommendations(
    assessments: &[EdgeRefinementAssessment],
) -> Vec<GraphRefinementRecommendation> {
    assessments
        .iter()
        .filter_map(|assessment| {
            let group = match assessment.recommended_action {
                GraphRefinementAction::Keep => return None,
                GraphRefinementAction::Strengthen => {
                    GraphRefinementRecommendationGroup::StrengthenUsefulEdges
                }
                GraphRefinementAction::Hide | GraphRefinementAction::Weaken => {
                    GraphRefinementRecommendationGroup::HideNoisyEdges
                }
                GraphRefinementAction::Supersede => {
                    GraphRefinementRecommendationGroup::InspectContradictions
                }
                GraphRefinementAction::Review => {
                    GraphRefinementRecommendationGroup::ReviewWeakEdges
                }
                GraphRefinementAction::Merge => {
                    GraphRefinementRecommendationGroup::MergeDuplicateEdges
                }
                GraphRefinementAction::Split => {
                    GraphRefinementRecommendationGroup::SplitOverConnectedHubs
                }
            };
            Some(GraphRefinementRecommendation {
                recommendation_id: format!("edge-{}-{:?}", assessment.edge_id, group),
                target_type: GraphRefinementRecommendationTargetType::Edge,
                target_id: assessment.edge_id.clone(),
                group,
                action: assessment.recommended_action,
                confidence_bp: assessment.edge_quality_score_bp,
                reason: assessment.confidence_reason.clone(),
                supporting_artifact_references: assessment.supporting_artifact_references.clone(),
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            })
        })
        .collect()
}

fn duplicate_recommendations(
    candidates: &[DuplicateEdgeCandidate],
) -> Vec<GraphRefinementRecommendation> {
    candidates
        .iter()
        .filter(|candidate| candidate.confidence_bp >= 7500)
        .map(|candidate| GraphRefinementRecommendation {
            recommendation_id: format!("merge-{}", candidate.candidate_id),
            target_type: GraphRefinementRecommendationTargetType::Candidate,
            target_id: candidate.candidate_id.clone(),
            group: GraphRefinementRecommendationGroup::MergeDuplicateEdges,
            action: GraphRefinementAction::Merge,
            confidence_bp: candidate.confidence_bp,
            reason: candidate.reason.clone(),
            supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
        })
        .collect()
}

fn node_recommendations(
    assessments: &mut [NodeRefinementAssessment],
) -> Vec<GraphRefinementRecommendation> {
    let mut recommendations = Vec::new();
    for assessment in assessments {
        if assessment.is_high_degree_hub {
            let recommendation_id = format!("split-hub-{}", assessment.node_id);
            assessment
                .recommendation_ids
                .push(recommendation_id.clone());
            recommendations.push(GraphRefinementRecommendation {
                recommendation_id,
                target_type: GraphRefinementRecommendationTargetType::Node,
                target_id: assessment.node_id.clone(),
                group: GraphRefinementRecommendationGroup::SplitOverConnectedHubs,
                action: GraphRefinementAction::Split,
                confidence_bp: 6500,
                reason: "node has high visible degree and may be an over-connected hub".into(),
                supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            });
        }
        if assessment.is_isolated_important_node {
            let recommendation_id = format!("connect-isolated-{}", assessment.node_id);
            assessment
                .recommendation_ids
                .push(recommendation_id.clone());
            recommendations.push(GraphRefinementRecommendation {
                recommendation_id,
                target_type: GraphRefinementRecommendationTargetType::Node,
                target_id: assessment.node_id.clone(),
                group: GraphRefinementRecommendationGroup::ConnectIsolatedHighValueNodes,
                action: GraphRefinementAction::Review,
                confidence_bp: 6000,
                reason: "important node is isolated in the visible graph".into(),
                supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            });
        }
    }
    recommendations
}

fn edge_triage_items(assessments: &[EdgeRefinementAssessment]) -> Vec<EdgeTriageItem> {
    let mut items = Vec::new();
    for assessment in assessments {
        items.extend(no_evidence_triage_item(assessment));
        items.extend(negative_quality_triage_item(assessment));
        items.extend(negative_citation_triage_item(assessment));
        items.extend(higher_unsupported_triage_item(assessment));
        items.extend(higher_cost_triage_item(assessment));
        items.extend(weak_frequent_triage_item(assessment));
        items.extend(strong_keep_triage_item(assessment));
    }
    items.sort_by(|left, right| {
        edge_triage_severity_rank(left.severity)
            .cmp(&edge_triage_severity_rank(right.severity))
            .then_with(|| right.priority_score_bp.cmp(&left.priority_score_bp))
            .then_with(|| left.edge_id.cmp(&right.edge_id))
            .then_with(|| left.triage_id.cmp(&right.triage_id))
    });
    for (index, item) in items.iter_mut().enumerate() {
        item.priority_rank = usize_to_u32_saturating(index.saturating_add(1));
    }
    items
}

fn no_evidence_triage_item(assessment: &EdgeRefinementAssessment) -> Option<EdgeTriageItem> {
    match assessment.evidence_level {
        EdgeEvidenceLevel::Unavailable | EdgeEvidenceLevel::ArtifactReferenceOnly => {
            Some(edge_triage_item(
                assessment,
                EdgeTriageCategory::NoEvidence,
                7000,
                "edge has no matched task or runner diagnostic evidence",
            ))
        }
        EdgeEvidenceLevel::DirectTaskRunnerMatch
        | EdgeEvidenceLevel::TaskMatch
        | EdgeEvidenceLevel::RunnerMatch => None,
    }
}

fn negative_quality_triage_item(assessment: &EdgeRefinementAssessment) -> Option<EdgeTriageItem> {
    negative_delta_score_if_negative(assessment.quality_delta_vs_neutral_bp).map(|score| {
        edge_triage_item(
            assessment,
            EdgeTriageCategory::NegativeQualityDelta,
            score,
            "graph-enabled task quality is below the neutral baseline",
        )
    })
}

fn negative_citation_triage_item(assessment: &EdgeRefinementAssessment) -> Option<EdgeTriageItem> {
    negative_delta_score_if_negative(assessment.citation_delta_vs_neutral_bp).map(|score| {
        edge_triage_item(
            assessment,
            EdgeTriageCategory::NegativeCitationDelta,
            score,
            "graph-enabled citation accuracy is below the neutral baseline",
        )
    })
}

fn higher_unsupported_triage_item(assessment: &EdgeRefinementAssessment) -> Option<EdgeTriageItem> {
    negative_delta_score_if_negative(assessment.unsupported_delta_vs_neutral_bp).map(|score| {
        edge_triage_item(
            assessment,
            EdgeTriageCategory::HigherUnsupportedClaimRate,
            score,
            "graph-enabled unsupported claim rate is above the neutral baseline",
        )
    })
}

fn higher_cost_triage_item(assessment: &EdgeRefinementAssessment) -> Option<EdgeTriageItem> {
    negative_cost_score_if_negative(assessment.cost_delta_vs_neutral_micro_exo).map(|score| {
        edge_triage_item(
            assessment,
            EdgeTriageCategory::HigherCostThanNeutral,
            score,
            "graph-enabled task cost is above the neutral baseline",
        )
    })
}

fn weak_frequent_triage_item(assessment: &EdgeRefinementAssessment) -> Option<EdgeTriageItem> {
    match (
        assessment.edge_quality_score_bp.cmp(&5000),
        assessment.task_usage_count.cmp(&2),
    ) {
        (Ordering::Less, Ordering::Equal | Ordering::Greater) => Some(edge_triage_item(
            assessment,
            EdgeTriageCategory::WeakFrequentEdge,
            6500,
            "edge is weak but appears in multiple diagnostic task rows",
        )),
        _ => None,
    }
}

fn strong_keep_triage_item(assessment: &EdgeRefinementAssessment) -> Option<EdgeTriageItem> {
    match (
        assessment.recommended_action,
        assessment.edge_quality_score_bp.cmp(&7500),
    ) {
        (GraphRefinementAction::Keep, Ordering::Equal | Ordering::Greater) => {
            Some(edge_triage_item(
                assessment,
                EdgeTriageCategory::StrongKeepCandidate,
                assessment.diagnostic_impact_bp.max(1000),
                "edge is high quality and should remain visible as a strong connection",
            ))
        }
        _ => None,
    }
}

fn edge_triage_item(
    assessment: &EdgeRefinementAssessment,
    category: EdgeTriageCategory,
    priority_score_bp: u16,
    reason: &str,
) -> EdgeTriageItem {
    EdgeTriageItem {
        triage_id: format!(
            "triage-{}-{}",
            edge_triage_category_key(category),
            assessment.edge_id
        ),
        edge_id: assessment.edge_id.clone(),
        category,
        severity: edge_triage_severity(priority_score_bp),
        priority_score_bp,
        priority_rank: 0,
        reason: reason.into(),
        recommended_action: assessment.recommended_action,
        evidence_level: assessment.evidence_level,
        task_usage_count: assessment.task_usage_count,
        edge_quality_score_bp: assessment.edge_quality_score_bp,
        diagnostic_impact_bp: assessment.diagnostic_impact_bp,
        quality_delta_vs_neutral_bp: assessment.quality_delta_vs_neutral_bp,
        citation_delta_vs_neutral_bp: assessment.citation_delta_vs_neutral_bp,
        unsupported_delta_vs_neutral_bp: assessment.unsupported_delta_vs_neutral_bp,
        cost_delta_vs_neutral_micro_exo: assessment.cost_delta_vs_neutral_micro_exo,
        supporting_artifact_references: assessment.supporting_artifact_references.clone(),
        writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
    }
}

fn edge_triage_summary(items: &[EdgeTriageItem]) -> EdgeTriageSummary {
    let mut summary = EdgeTriageSummary {
        total_triage_item_count: usize_to_u32_saturating(items.len()),
        ..EdgeTriageSummary::default()
    };
    for item in items {
        match item.category {
            EdgeTriageCategory::NoEvidence => {
                summary.no_evidence_count = summary.no_evidence_count.saturating_add(1);
            }
            EdgeTriageCategory::NegativeQualityDelta => {
                summary.negative_quality_delta_count =
                    summary.negative_quality_delta_count.saturating_add(1);
            }
            EdgeTriageCategory::NegativeCitationDelta => {
                summary.negative_citation_delta_count =
                    summary.negative_citation_delta_count.saturating_add(1);
            }
            EdgeTriageCategory::HigherUnsupportedClaimRate => {
                summary.higher_unsupported_claim_rate_count = summary
                    .higher_unsupported_claim_rate_count
                    .saturating_add(1);
            }
            EdgeTriageCategory::HigherCostThanNeutral => {
                summary.higher_cost_than_neutral_count =
                    summary.higher_cost_than_neutral_count.saturating_add(1);
            }
            EdgeTriageCategory::WeakFrequentEdge => {
                summary.weak_frequent_edge_count =
                    summary.weak_frequent_edge_count.saturating_add(1);
            }
            EdgeTriageCategory::StrongKeepCandidate => {
                summary.strong_keep_candidate_count =
                    summary.strong_keep_candidate_count.saturating_add(1);
            }
        }
    }
    summary
}

fn edge_diagnosis_items(
    assessments: &[EdgeRefinementAssessment],
    triage_items: &[EdgeTriageItem],
) -> Vec<EdgeDiagnosisItem> {
    let assessment_by_edge_id = assessments
        .iter()
        .map(|assessment| (assessment.edge_id.as_str(), assessment))
        .collect::<BTreeMap<_, _>>();
    let mut items = Vec::new();
    for triage_item in triage_items {
        let Some(cause) = edge_diagnosis_cause_for_triage(triage_item.category) else {
            continue;
        };
        let Some(assessment) = assessment_by_edge_id.get(triage_item.edge_id.as_str()) else {
            continue;
        };
        items.push(edge_diagnosis_item(assessment, triage_item, cause));
    }
    items.sort_by(|left, right| {
        edge_triage_severity_rank(left.severity)
            .cmp(&edge_triage_severity_rank(right.severity))
            .then_with(|| right.impact_score_bp.cmp(&left.impact_score_bp))
            .then_with(|| left.edge_id.cmp(&right.edge_id))
            .then_with(|| left.diagnosis_id.cmp(&right.diagnosis_id))
    });
    items
}

fn edge_diagnosis_cause_for_triage(category: EdgeTriageCategory) -> Option<EdgeDiagnosisCause> {
    match category {
        EdgeTriageCategory::NegativeQualityDelta => Some(EdgeDiagnosisCause::QualityRegression),
        EdgeTriageCategory::NegativeCitationDelta => Some(EdgeDiagnosisCause::CitationRegression),
        EdgeTriageCategory::HigherUnsupportedClaimRate => {
            Some(EdgeDiagnosisCause::UnsupportedClaimRegression)
        }
        EdgeTriageCategory::HigherCostThanNeutral => Some(EdgeDiagnosisCause::CostRegression),
        EdgeTriageCategory::WeakFrequentEdge => Some(EdgeDiagnosisCause::WeakFrequentConnection),
        EdgeTriageCategory::NoEvidence => Some(EdgeDiagnosisCause::MissingEvidence),
        EdgeTriageCategory::StrongKeepCandidate => None,
    }
}

fn edge_diagnosis_item(
    assessment: &EdgeRefinementAssessment,
    triage_item: &EdgeTriageItem,
    cause: EdgeDiagnosisCause,
) -> EdgeDiagnosisItem {
    let (reason, next_evidence_action) = edge_diagnosis_text(cause);
    EdgeDiagnosisItem {
        diagnosis_id: format!(
            "diagnosis-{}-{}",
            edge_diagnosis_cause_key(cause),
            assessment.edge_id
        ),
        edge_id: assessment.edge_id.clone(),
        cause,
        severity: triage_item.severity,
        impact_score_bp: triage_item.priority_score_bp,
        task_ids: assessment.matched_task_ids.clone(),
        diagnostic_labels: assessment.matched_diagnostic_labels.clone(),
        edge_kind: assessment.edge_kind.clone(),
        graph_style: assessment.graph_style.clone(),
        reason: reason.into(),
        next_evidence_action: next_evidence_action.into(),
        supporting_artifact_references: diagnosis_artifact_references(assessment),
        writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
    }
}

fn diagnosis_artifact_references(assessment: &EdgeRefinementAssessment) -> Vec<String> {
    if assessment.supporting_artifact_references.is_empty() {
        vec![GRAPH_REFINEMENT_REPORT_PATH.into()]
    } else {
        assessment.supporting_artifact_references.clone()
    }
}

fn edge_diagnosis_text(cause: EdgeDiagnosisCause) -> (&'static str, &'static str) {
    match cause {
        EdgeDiagnosisCause::QualityRegression => (
            "graph-enabled diagnostic rows reduce quality versus the neutral baseline",
            "Inspect matched task rows and route references before strengthening this edge.",
        ),
        EdgeDiagnosisCause::CitationRegression => (
            "graph-enabled diagnostic rows reduce citation accuracy versus the neutral baseline",
            "Inspect citation-bearing references for matched tasks before preserving this edge.",
        ),
        EdgeDiagnosisCause::UnsupportedClaimRegression => (
            "graph-enabled diagnostic rows increase unsupported claims versus the neutral baseline",
            "Inspect validation reports and remove unsupported route context from this edge.",
        ),
        EdgeDiagnosisCause::CostRegression => (
            "graph-enabled diagnostic rows cost more than the neutral baseline",
            "Inspect route and context packet size for matched tasks before keeping this edge.",
        ),
        EdgeDiagnosisCause::WeakFrequentConnection => (
            "edge is weak but appears in multiple diagnostic task rows",
            "Review whether this edge is an over-broad routing shortcut.",
        ),
        EdgeDiagnosisCause::MissingEvidence => (
            "edge has no matched task or runner diagnostic evidence",
            "Add deterministic task, runner, or receipt metadata before trusting this edge.",
        ),
    }
}

fn edge_diagnosis_summary(items: &[EdgeDiagnosisItem]) -> EdgeDiagnosisSummary {
    let mut summary = EdgeDiagnosisSummary {
        total_diagnosis_item_count: usize_to_u32_saturating(items.len()),
        ..EdgeDiagnosisSummary::default()
    };
    for item in items {
        match item.cause {
            EdgeDiagnosisCause::QualityRegression => {
                summary.quality_regression_count =
                    summary.quality_regression_count.saturating_add(1);
            }
            EdgeDiagnosisCause::CitationRegression => {
                summary.citation_regression_count =
                    summary.citation_regression_count.saturating_add(1);
            }
            EdgeDiagnosisCause::UnsupportedClaimRegression => {
                summary.unsupported_claim_regression_count =
                    summary.unsupported_claim_regression_count.saturating_add(1);
            }
            EdgeDiagnosisCause::CostRegression => {
                summary.cost_regression_count = summary.cost_regression_count.saturating_add(1);
            }
            EdgeDiagnosisCause::WeakFrequentConnection => {
                summary.weak_frequent_connection_count =
                    summary.weak_frequent_connection_count.saturating_add(1);
            }
            EdgeDiagnosisCause::MissingEvidence => {
                summary.missing_evidence_count = summary.missing_evidence_count.saturating_add(1);
            }
        }
    }
    summary
}

fn edge_closure_items(
    assessments: &[EdgeRefinementAssessment],
    triage_items: &[EdgeTriageItem],
    diagnosis_items: &[EdgeDiagnosisItem],
) -> Vec<EdgeClosureItem> {
    let assessment_by_edge_id = assessments
        .iter()
        .map(|assessment| (assessment.edge_id.as_str(), assessment))
        .collect::<BTreeMap<_, _>>();
    let mut items = diagnosis_items
        .iter()
        .map(edge_closure_item_from_diagnosis)
        .collect::<Vec<_>>();
    for triage_item in triage_items {
        if triage_item.category != EdgeTriageCategory::StrongKeepCandidate {
            continue;
        }
        let Some(assessment) = assessment_by_edge_id.get(triage_item.edge_id.as_str()) else {
            continue;
        };
        items.push(edge_closure_item_from_strong_keep(assessment, triage_item));
    }
    items.sort_by(|left, right| {
        edge_triage_severity_rank(left.severity)
            .cmp(&edge_triage_severity_rank(right.severity))
            .then_with(|| right.priority_score_bp.cmp(&left.priority_score_bp))
            .then_with(|| left.edge_id.cmp(&right.edge_id))
            .then_with(|| left.closure_id.cmp(&right.closure_id))
    });
    items
}

fn edge_closure_item_from_diagnosis(diagnosis: &EdgeDiagnosisItem) -> EdgeClosureItem {
    let action = edge_closure_action_for_diagnosis(diagnosis.cause);
    let cause = edge_closure_cause_for_diagnosis(diagnosis.cause);
    let (evidence_gap, closure_instruction, verification_hint) = edge_closure_text(action, cause);
    EdgeClosureItem {
        closure_id: format!(
            "closure-{}-{}-{}",
            edge_closure_action_key(action),
            edge_closure_cause_key(cause),
            diagnosis.edge_id
        ),
        edge_id: diagnosis.edge_id.clone(),
        action,
        priority_score_bp: diagnosis.impact_score_bp.min(10_000),
        severity: edge_triage_severity(diagnosis.impact_score_bp.min(10_000)),
        cause,
        task_ids: diagnosis.task_ids.clone(),
        diagnostic_labels: diagnosis.diagnostic_labels.clone(),
        edge_kind: diagnosis.edge_kind.clone(),
        graph_style: diagnosis.graph_style.clone(),
        evidence_gap: evidence_gap.into(),
        closure_instruction: closure_instruction.into(),
        verification_hint: verification_hint.into(),
        supporting_artifact_references: diagnosis.supporting_artifact_references.clone(),
        writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
    }
}

fn edge_closure_item_from_strong_keep(
    assessment: &EdgeRefinementAssessment,
    triage_item: &EdgeTriageItem,
) -> EdgeClosureItem {
    let action = EdgeClosureAction::StrengthenSupportedConnection;
    let cause = EdgeClosureCause::StrongKeepCandidate;
    let priority_score_bp = triage_item.priority_score_bp.min(10_000);
    let (evidence_gap, closure_instruction, verification_hint) = edge_closure_text(action, cause);
    EdgeClosureItem {
        closure_id: format!(
            "closure-{}-{}-{}",
            edge_closure_action_key(action),
            edge_closure_cause_key(cause),
            assessment.edge_id
        ),
        edge_id: assessment.edge_id.clone(),
        action,
        priority_score_bp,
        severity: edge_triage_severity(priority_score_bp),
        cause,
        task_ids: assessment.matched_task_ids.clone(),
        diagnostic_labels: assessment.matched_diagnostic_labels.clone(),
        edge_kind: assessment.edge_kind.clone(),
        graph_style: assessment.graph_style.clone(),
        evidence_gap: evidence_gap.into(),
        closure_instruction: closure_instruction.into(),
        verification_hint: verification_hint.into(),
        supporting_artifact_references: diagnosis_artifact_references(assessment),
        writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
    }
}

fn edge_closure_action_for_diagnosis(cause: EdgeDiagnosisCause) -> EdgeClosureAction {
    match cause {
        EdgeDiagnosisCause::QualityRegression => EdgeClosureAction::InspectRouteContext,
        EdgeDiagnosisCause::CitationRegression | EdgeDiagnosisCause::UnsupportedClaimRegression => {
            EdgeClosureAction::AttachReceiptOrValidation
        }
        EdgeDiagnosisCause::CostRegression => EdgeClosureAction::HideNoisyConnection,
        EdgeDiagnosisCause::WeakFrequentConnection => EdgeClosureAction::SplitOverbroadConnection,
        EdgeDiagnosisCause::MissingEvidence => EdgeClosureAction::AddTaskRunnerMetadata,
    }
}

fn edge_closure_cause_for_diagnosis(cause: EdgeDiagnosisCause) -> EdgeClosureCause {
    match cause {
        EdgeDiagnosisCause::QualityRegression => EdgeClosureCause::QualityRegression,
        EdgeDiagnosisCause::CitationRegression => EdgeClosureCause::CitationRegression,
        EdgeDiagnosisCause::UnsupportedClaimRegression => {
            EdgeClosureCause::UnsupportedClaimRegression
        }
        EdgeDiagnosisCause::CostRegression => EdgeClosureCause::CostRegression,
        EdgeDiagnosisCause::WeakFrequentConnection => EdgeClosureCause::WeakFrequentConnection,
        EdgeDiagnosisCause::MissingEvidence => EdgeClosureCause::MissingEvidence,
    }
}

fn edge_closure_text(
    action: EdgeClosureAction,
    cause: EdgeClosureCause,
) -> (&'static str, &'static str, &'static str) {
    match (action, cause) {
        (EdgeClosureAction::AddTaskRunnerMetadata, EdgeClosureCause::MissingEvidence) => (
            "edge lacks deterministic task, runner, or receipt evidence",
            "Add task and runner metadata to the source artifacts before trusting this edge.",
            "Regenerate most-recent and verify the edge no longer appears as missing_evidence.",
        ),
        (EdgeClosureAction::InspectRouteContext, EdgeClosureCause::QualityRegression) => (
            "graph-enabled quality is below the neutral baseline",
            "Inspect matched task rows and route context before strengthening or keeping this edge.",
            "Regenerate most-recent and verify quality_delta_vs_neutral_bp is nonnegative.",
        ),
        (EdgeClosureAction::AttachReceiptOrValidation, EdgeClosureCause::CitationRegression) => (
            "citation accuracy is below the neutral baseline",
            "Attach receipt or citation validation references for the matched task and runner evidence.",
            "Regenerate most-recent and verify citation_delta_vs_neutral_bp is nonnegative.",
        ),
        (
            EdgeClosureAction::AttachReceiptOrValidation,
            EdgeClosureCause::UnsupportedClaimRegression,
        ) => (
            "unsupported claim rate is above the neutral baseline",
            "Attach validation reports or remove unsupported route context for this edge.",
            "Regenerate most-recent and verify unsupported_delta_vs_neutral_bp is nonnegative.",
        ),
        (EdgeClosureAction::HideNoisyConnection, EdgeClosureCause::CostRegression) => (
            "graph-enabled cost is above the neutral baseline",
            "Hide or narrow this edge from routing views until its route context cost is justified.",
            "Regenerate most-recent and verify cost_delta_vs_neutral_micro_exo is nonnegative.",
        ),
        (EdgeClosureAction::SplitOverbroadConnection, EdgeClosureCause::WeakFrequentConnection) => {
            (
                "edge is weak but appears in multiple diagnostic task rows",
                "Split this overbroad connection into more specific task or route evidence edges.",
                "Regenerate most-recent and verify the edge no longer appears as weak_frequent_edge.",
            )
        }
        (
            EdgeClosureAction::StrengthenSupportedConnection,
            EdgeClosureCause::StrongKeepCandidate,
        ) => (
            "strong edge should preserve its supporting evidence path",
            "Strengthen this supported connection by keeping task, runner, receipt, and validation references attached.",
            "Regenerate most-recent and verify the edge remains a strong_keep_candidate.",
        ),
        (EdgeClosureAction::ReviewMissingEvidence, _) => (
            "edge needs manual evidence review",
            "Review available artifacts and decide which deterministic evidence should support this edge.",
            "Regenerate most-recent and verify the closure item is replaced by a more specific action.",
        ),
        _ => (
            "edge has an evidence closure gap",
            "Review matched edge evidence and close the specific advisory gap before changing source records.",
            "Regenerate most-recent and verify the closure item count decreases for this edge.",
        ),
    }
}

fn edge_closure_summary(items: &[EdgeClosureItem]) -> EdgeClosureSummary {
    let mut summary = EdgeClosureSummary {
        total_closure_item_count: usize_to_u32_saturating(items.len()),
        ..EdgeClosureSummary::default()
    };
    for item in items {
        match item.action {
            EdgeClosureAction::AddTaskRunnerMetadata => {
                summary.add_task_runner_metadata_count =
                    summary.add_task_runner_metadata_count.saturating_add(1);
            }
            EdgeClosureAction::AttachReceiptOrValidation => {
                summary.attach_receipt_or_validation_count =
                    summary.attach_receipt_or_validation_count.saturating_add(1);
            }
            EdgeClosureAction::InspectRouteContext => {
                summary.inspect_route_context_count =
                    summary.inspect_route_context_count.saturating_add(1);
            }
            EdgeClosureAction::SplitOverbroadConnection => {
                summary.split_overbroad_connection_count =
                    summary.split_overbroad_connection_count.saturating_add(1);
            }
            EdgeClosureAction::HideNoisyConnection => {
                summary.hide_noisy_connection_count =
                    summary.hide_noisy_connection_count.saturating_add(1);
            }
            EdgeClosureAction::StrengthenSupportedConnection => {
                summary.strengthen_supported_connection_count = summary
                    .strengthen_supported_connection_count
                    .saturating_add(1);
            }
            EdgeClosureAction::ReviewMissingEvidence => {
                summary.review_missing_evidence_count =
                    summary.review_missing_evidence_count.saturating_add(1);
            }
        }
    }
    summary
}

fn edge_triage_severity(priority_score_bp: u16) -> EdgeTriageSeverity {
    match priority_score_bp {
        8000..=u16::MAX => EdgeTriageSeverity::Critical,
        6000..=7999 => EdgeTriageSeverity::High,
        3000..=5999 => EdgeTriageSeverity::Medium,
        1000..=2999 => EdgeTriageSeverity::Low,
        0..=999 => EdgeTriageSeverity::Info,
    }
}

fn edge_triage_severity_rank(severity: EdgeTriageSeverity) -> u8 {
    match severity {
        EdgeTriageSeverity::Critical => 0,
        EdgeTriageSeverity::High => 1,
        EdgeTriageSeverity::Medium => 2,
        EdgeTriageSeverity::Low => 3,
        EdgeTriageSeverity::Info => 4,
    }
}

fn edge_triage_category_key(category: EdgeTriageCategory) -> &'static str {
    match category {
        EdgeTriageCategory::NoEvidence => "no_evidence",
        EdgeTriageCategory::NegativeQualityDelta => "negative_quality_delta",
        EdgeTriageCategory::NegativeCitationDelta => "negative_citation_delta",
        EdgeTriageCategory::HigherUnsupportedClaimRate => "higher_unsupported_claim_rate",
        EdgeTriageCategory::HigherCostThanNeutral => "higher_cost_than_neutral",
        EdgeTriageCategory::WeakFrequentEdge => "weak_frequent_edge",
        EdgeTriageCategory::StrongKeepCandidate => "strong_keep_candidate",
    }
}

fn edge_diagnosis_cause_key(cause: EdgeDiagnosisCause) -> &'static str {
    match cause {
        EdgeDiagnosisCause::QualityRegression => "quality_regression",
        EdgeDiagnosisCause::CitationRegression => "citation_regression",
        EdgeDiagnosisCause::UnsupportedClaimRegression => "unsupported_claim_regression",
        EdgeDiagnosisCause::CostRegression => "cost_regression",
        EdgeDiagnosisCause::WeakFrequentConnection => "weak_frequent_connection",
        EdgeDiagnosisCause::MissingEvidence => "missing_evidence",
    }
}

fn edge_closure_action_key(action: EdgeClosureAction) -> &'static str {
    match action {
        EdgeClosureAction::AddTaskRunnerMetadata => "add_task_runner_metadata",
        EdgeClosureAction::AttachReceiptOrValidation => "attach_receipt_or_validation",
        EdgeClosureAction::InspectRouteContext => "inspect_route_context",
        EdgeClosureAction::SplitOverbroadConnection => "split_overbroad_connection",
        EdgeClosureAction::HideNoisyConnection => "hide_noisy_connection",
        EdgeClosureAction::StrengthenSupportedConnection => "strengthen_supported_connection",
        EdgeClosureAction::ReviewMissingEvidence => "review_missing_evidence",
    }
}

fn edge_closure_cause_key(cause: EdgeClosureCause) -> &'static str {
    match cause {
        EdgeClosureCause::QualityRegression => "quality_regression",
        EdgeClosureCause::CitationRegression => "citation_regression",
        EdgeClosureCause::UnsupportedClaimRegression => "unsupported_claim_regression",
        EdgeClosureCause::CostRegression => "cost_regression",
        EdgeClosureCause::WeakFrequentConnection => "weak_frequent_connection",
        EdgeClosureCause::MissingEvidence => "missing_evidence",
        EdgeClosureCause::StrongKeepCandidate => "strong_keep_candidate",
    }
}

fn negative_delta_score(delta_bp: i32) -> u16 {
    let magnitude = i64::from(delta_bp).abs();
    u16::try_from(magnitude.saturating_mul(4))
        .unwrap_or(u16::MAX)
        .min(10_000)
}

fn negative_delta_score_if_negative(delta_bp: i32) -> Option<u16> {
    match delta_bp.cmp(&0) {
        Ordering::Less => Some(negative_delta_score(delta_bp)),
        Ordering::Equal | Ordering::Greater => None,
    }
}

fn negative_cost_score(cost_delta_micro_exo: i64) -> u16 {
    let magnitude = cost_delta_micro_exo.saturating_abs();
    u16::try_from(magnitude / 10)
        .unwrap_or(u16::MAX)
        .min(10_000)
}

fn negative_cost_score_if_negative(cost_delta_micro_exo: i64) -> Option<u16> {
    match cost_delta_micro_exo.cmp(&0) {
        Ordering::Less => Some(negative_cost_score(cost_delta_micro_exo)),
        Ordering::Equal | Ordering::Greater => None,
    }
}

fn average_edge_quality(assessments: &[EdgeRefinementAssessment]) -> u16 {
    if assessments.is_empty() {
        return 0;
    }
    let total = assessments
        .iter()
        .map(|assessment| u32::from(assessment.edge_quality_score_bp))
        .sum::<u32>();
    u32_to_u16_saturating(total / usize_to_u32_saturating(assessments.len()))
}

fn average_diagnostic_impact_bp(assessments: &[EdgeRefinementAssessment]) -> u16 {
    if assessments.is_empty() {
        return 0;
    }
    let total = assessments
        .iter()
        .map(|assessment| u32::from(assessment.diagnostic_impact_bp))
        .sum::<u32>();
    u32_to_u16_saturating(total / usize_to_u32_saturating(assessments.len()))
}

fn capped_add_bp(current: u16, add: u16) -> u16 {
    current.saturating_add(add).min(10_000)
}

fn u32_to_u16_saturating(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn graph_style_key(style: MemoryGraphStyle) -> &'static str {
    match style {
        MemoryGraphStyle::ProvenanceReceiptDag => "provenance_receipt_dag",
        MemoryGraphStyle::CanonicalMemoryGraph => "canonical_memory_graph",
        MemoryGraphStyle::SemanticCatalogGraph => "semantic_catalog_graph",
        MemoryGraphStyle::SimilarityOverlayGraph => "similarity_overlay_graph",
        MemoryGraphStyle::DependencyDag => "dependency_dag",
        MemoryGraphStyle::RoutingViewGraph => "routing_view_graph",
        MemoryGraphStyle::ContradictionSupersessionGraph => "contradiction_supersession_graph",
        MemoryGraphStyle::ContextPacketGraph => "context_packet_graph",
    }
}

fn edge_kind_key(kind: MemoryEdgeKind) -> &'static str {
    match kind {
        MemoryEdgeKind::DerivedFrom => "derived_from",
        MemoryEdgeKind::Summarizes => "summarizes",
        MemoryEdgeKind::Supports => "supports",
        MemoryEdgeKind::Contradicts => "contradicts",
        MemoryEdgeKind::Supersedes => "supersedes",
        MemoryEdgeKind::Replaces => "replaces",
        MemoryEdgeKind::DuplicateOf => "duplicate_of",
        MemoryEdgeKind::NearDuplicateOf => "near_duplicate_of",
        MemoryEdgeKind::RelatedTo => "related_to",
        MemoryEdgeKind::AlternativeSummaryOf => "alternative_summary_of",
        MemoryEdgeKind::DependsOn => "depends_on",
        MemoryEdgeKind::PartOf => "part_of",
        MemoryEdgeKind::OwnedBy => "owned_by",
        MemoryEdgeKind::AccessGrantedBy => "access_granted_by",
        MemoryEdgeKind::VerifiedBy => "verified_by",
        MemoryEdgeKind::UsedByRoute => "used_by_route",
        MemoryEdgeKind::IncludedInContextPacket => "included_in_context_packet",
        MemoryEdgeKind::RevokedBy => "revoked_by",
    }
}

fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn json_body<T: Serialize>(value: &T) -> Result<String, GraphExplorerError> {
    serde_json::to_string_pretty(value)
        .map(|body| format!("{body}\n"))
        .map_err(|error| GraphExplorerError::Serialization {
            reason: error.to_string(),
        })
}

fn list_label(values: &[String]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.join(", ")
    }
}

fn repo_relative(path: &Path) -> String {
    let root = repo_root_path();
    let relative_path = path.strip_prefix(&root).unwrap_or(path);
    relative_path
        .components()
        .collect::<PathBuf>()
        .to_string_lossy()
        .replace('\\', "/")
}

fn repo_root_path() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest_dir)
        .to_path_buf()
}

fn io_error(error: std::io::Error) -> GraphExplorerError {
    GraphExplorerError::Io {
        reason: error.to_string(),
    }
}

fn sha256_bytes_hex(bytes: &[u8]) -> String {
    const SHA256_K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = match u64::try_from(bytes.len()) {
        Ok(len) => len.saturating_mul(8),
        Err(_) => u64::MAX,
    };
    let mut data = Vec::with_capacity(bytes.len().saturating_add(72));
    data.extend_from_slice(bytes);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.as_chunks::<64>().0 {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().enumerate().take(16) {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        let mut index = 16usize;
        while index < 64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
            index += 1;
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        let mut index = 0usize;
        while index < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            index += 1;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = String::with_capacity(64);
    for word in state {
        output.push_str(&format!("{word:08x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_explorer::{
        GRAPH_EXPLORER_TARGET_LOCK, GraphExplorerCluster, GraphExplorerClusterType,
        GraphExplorerDrilldownMode, GraphExplorerDrilldownState, GraphExplorerEdgeDirection,
        GraphExplorerExportResultStatus, GraphExplorerGeneratedFrom, GraphExplorerGenerationMode,
        GraphExplorerLimits, GraphExplorerPermissions, GraphExplorerSourceMode,
        GraphExplorerSummaries, RawContentUnavailableReason,
    };

    fn node(id: &str, kind: MemoryNodeKind, style: MemoryGraphStyle) -> GraphExplorerNode {
        GraphExplorerNode {
            node_id: id.into(),
            label: id.into(),
            node_kind: kind,
            graph_style: style,
            catalog_path: vec!["catalog".into()],
            status: GraphExplorerNodeStatus::Active,
            risk_class: None,
            owner_id: None,
            receipt_ids: Vec::new(),
            source_hash: None,
            content_hash: None,
            raw_content_allowed: false,
            browser_safe_payload: true,
            has_raw_content: false,
            has_children: false,
            child_count: 0,
            parent_count: 0,
            metadata_summary: Vec::new(),
        }
    }

    fn edge(
        id: &str,
        source: &str,
        target: &str,
        kind: MemoryEdgeKind,
        style: MemoryGraphStyle,
    ) -> GraphExplorerEdge {
        GraphExplorerEdge {
            edge_id: id.into(),
            source_node_id: source.into(),
            target_node_id: target.into(),
            edge_kind: kind,
            graph_style: style,
            receipt_id: None,
            status: GraphExplorerEdgeStatus::Active,
            confidence_bp: Some(7000),
            direction: GraphExplorerEdgeDirection::SourceToTarget,
        }
    }

    fn snapshot(
        nodes: Vec<GraphExplorerNode>,
        edges: Vec<GraphExplorerEdge>,
    ) -> GraphExplorerSnapshot {
        GraphExplorerSnapshot {
            schema_version: "dagdb_graph_explorer_snapshot_v1".into(),
            snapshot_id: "snapshot-refinement-test".into(),
            generated_from: GraphExplorerGeneratedFrom::GraphRecords,
            generation_mode: GraphExplorerGenerationMode::ReportFileArtifact,
            export_result_status: GraphExplorerExportResultStatus::GeneratedRealGraphArtifact,
            source_truth_level: GraphSourceTruthLevel::DiagnosticContextPacketArtifact,
            source_mode: GraphExplorerSourceMode::GeneratedGraphArtifact,
            source_description: "test graph artifact".into(),
            source_artifact_paths: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            source_receipt_ids: Vec::new(),
            source_graph_view_ids: Vec::new(),
            source_commit_or_run_id: Some("refinement-test".into()),
            source_is_live_db_export: false,
            source_is_generated_artifact: true,
            artifact_hash: None,
            source_artifact_hashes: BTreeMap::new(),
            source_graph_view_hashes: BTreeMap::new(),
            source_receipt_hashes: BTreeMap::new(),
            schema_inventory_hash: None,
            source_column_set_hash: None,
            source_table_names: Vec::new(),
            query_scope_tenant_id: None,
            query_scope_namespace: None,
            displayed_node_count: usize_to_u32_saturating(nodes.len()),
            total_scoped_node_count: None,
            displayed_edge_count: usize_to_u32_saturating(edges.len()),
            total_scoped_edge_count: None,
            dropped_edge_count: 0,
            limit_applied: false,
            source_unavailable_reason: None,
            graph_export_not_available: false,
            tenant_id: None,
            namespace: None,
            graph_styles_available: vec![MemoryGraphStyle::DependencyDag],
            active_graph_style: MemoryGraphStyle::DependencyDag,
            root_node_ids: nodes
                .first()
                .map(|node| node.node_id.clone())
                .into_iter()
                .collect(),
            nodes,
            edges,
            clusters: vec![GraphExplorerCluster {
                cluster_id: "cluster".into(),
                label: "cluster".into(),
                cluster_type: GraphExplorerClusterType::GraphStyle,
                graph_style: MemoryGraphStyle::DependencyDag,
                node_ids: Vec::new(),
                count: 0,
                color_key: "source".into(),
            }],
            summaries: GraphExplorerSummaries {
                displayed_node_count: 0,
                total_known_node_count: None,
                displayed_edge_count: 0,
                total_known_edge_count: None,
                displayed_cluster_count: 1,
                total_known_cluster_count: None,
                limit_applied: false,
            },
            permissions: GraphExplorerPermissions {
                raw_content_allowed: false,
                private_payloads_allowed: false,
                live_db_export_allowed: false,
                raw_preview_env_approved: false,
                source_mode: "report_file_artifact".into(),
            },
            limits: GraphExplorerLimits::default(),
            drilldown: GraphExplorerDrilldownState {
                breadcrumb: Vec::new(),
                root_node_id: None,
                focused_node_id: None,
                active_graph_style: MemoryGraphStyle::DependencyDag,
                depth: 0,
                mode: GraphExplorerDrilldownMode::Overview,
            },
            warnings: Vec::new(),
        }
    }

    fn empty_details(node: GraphExplorerNode) -> NodeInspectorDetails {
        NodeInspectorDetails {
            node,
            parents: Vec::new(),
            children: Vec::new(),
            dependencies: Vec::new(),
            evidence: Vec::new(),
            receipts: Vec::new(),
            routes: Vec::new(),
            context_packets: Vec::new(),
            contradictions: Vec::new(),
            supersessions: Vec::new(),
            validation_reports: Vec::new(),
            edge_details: Vec::new(),
            raw_content_preview_if_allowed: None,
            raw_content_unavailable_reason: Some(RawContentUnavailableReason::ArtifactUnavailable),
        }
    }

    fn reset_refinement_test_dir(name: &str) -> PathBuf {
        let path = repo_root_path()
            .join("target")
            .join("dagdb")
            .join("graph_refinement_tests")
            .join(name);
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove refinement test dir");
        }
        fs::create_dir_all(&path).expect("create refinement test dir");
        path
    }

    fn diagnostic_row(
        fixture_id: &str,
        task_id: &str,
        diagnostic_label: &str,
        quality_score_bp: u16,
        citation_accuracy_bp: u16,
        unsupported_claim_rate_bp: u16,
        total_cost_micro_exo: u32,
    ) -> DiagnosticEvidenceRow {
        DiagnosticEvidenceRow {
            fixture_id: fixture_id.into(),
            task_id: task_id.into(),
            diagnostic_label: diagnostic_label.into(),
            quality_score_bp: Some(quality_score_bp),
            citation_accuracy_bp: Some(citation_accuracy_bp),
            unsupported_claim_rate_bp: Some(unsupported_claim_rate_bp),
            total_cost_micro_exo: Some(total_cost_micro_exo),
        }
    }

    fn triage_assessment(id: &str) -> EdgeRefinementAssessment {
        EdgeRefinementAssessment {
            edge_id: id.into(),
            source_node_id: "source".into(),
            target_node_id: "target".into(),
            edge_kind: "depends_on".into(),
            graph_style: "dependency_dag".into(),
            edge_quality_score_bp: 6000,
            evidence_strength_bp: 5000,
            contradiction_risk_bp: 0,
            staleness_risk_bp: 0,
            routing_usefulness_bp: 5000,
            confidence_reason: "triage fixture".into(),
            recommended_action: GraphRefinementAction::Strengthen,
            supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            weakening_artifact_references: Vec::new(),
            evidence_level: EdgeEvidenceLevel::DirectTaskRunnerMatch,
            task_usage_count: 1,
            matched_task_ids: vec!["t001".into()],
            matched_diagnostic_labels: vec!["governed_dagdb".into()],
            avg_quality_bp: 8000,
            avg_citation_accuracy_bp: 9000,
            avg_unsupported_claim_rate_bp: 100,
            quality_delta_vs_neutral_bp: 0,
            citation_delta_vs_neutral_bp: 0,
            unsupported_delta_vs_neutral_bp: 0,
            cost_delta_vs_neutral_micro_exo: 0,
            diagnostic_impact_bp: 0,
            evidence_summary:
                "direct task/runner evidence from 1 diagnostic rows; diagnostic_impact_bp:0".into(),
        }
    }

    #[test]
    fn graph_refinement_contract_empty_report_is_advisory_and_deterministic() {
        let snapshot = snapshot(
            vec![node(
                "node-a",
                MemoryNodeKind::Summary,
                MemoryGraphStyle::DependencyDag,
            )],
            Vec::new(),
        );
        let first = empty_graph_refinement_report(&snapshot);
        let second = empty_graph_refinement_report(&snapshot);
        assert_eq!(first, second);
        assert_eq!(first.schema_version, GRAPH_REFINEMENT_REPORT_SCHEMA_VERSION);
        assert_eq!(first.source_snapshot_id, snapshot.snapshot_id);
        assert_eq!(first.source_truth_level, snapshot.source_truth_level);
        assert!(first.advisory_only);
        assert_eq!(first.assessed_edge_count, 0);
        assert_eq!(first.assessed_node_count, 0);
        assert_eq!(first.average_edge_quality_bp, 0);
        assert_eq!(first.warnings, vec!["refinement_artifact_unavailable"]);
    }

    #[test]
    fn graph_refinement_contract_serializes_scores_actions_and_recommendations() {
        let report = GraphRefinementReport {
            schema_version: GRAPH_REFINEMENT_REPORT_SCHEMA_VERSION.into(),
            source_snapshot_id: "snapshot-a".into(),
            source_truth_level: GraphSourceTruthLevel::DiagnosticContextPacketArtifact,
            advisory_only: true,
            assessed_edge_count: 1,
            assessed_node_count: 2,
            average_edge_quality_bp: 7500,
            weak_edge_count: 0,
            missing_edge_candidate_count: 1,
            duplicate_edge_candidate_count: 1,
            contradicted_edge_candidate_count: 0,
            edge_assessments: vec![EdgeRefinementAssessment {
                edge_id: "edge-a".into(),
                source_node_id: "node-a".into(),
                target_node_id: "node-b".into(),
                edge_kind: "depends_on".into(),
                graph_style: "dependency_dag".into(),
                edge_quality_score_bp: 7500,
                evidence_strength_bp: 7000,
                contradiction_risk_bp: 0,
                staleness_risk_bp: 0,
                routing_usefulness_bp: 6000,
                confidence_reason: "deterministic contract test".into(),
                recommended_action: GraphRefinementAction::Keep,
                supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
                weakening_artifact_references: Vec::new(),
                evidence_level: EdgeEvidenceLevel::DirectTaskRunnerMatch,
                task_usage_count: 2,
                matched_task_ids: vec!["t001".into()],
                matched_diagnostic_labels: vec!["governed_dagdb".into()],
                avg_quality_bp: 7600,
                avg_citation_accuracy_bp: 9400,
                avg_unsupported_claim_rate_bp: 100,
                quality_delta_vs_neutral_bp: 500,
                citation_delta_vs_neutral_bp: 250,
                unsupported_delta_vs_neutral_bp: 125,
                cost_delta_vs_neutral_micro_exo: 50,
                diagnostic_impact_bp: 875,
                evidence_summary:
                    "direct task/runner evidence from 2 diagnostic rows; diagnostic_impact_bp:875"
                        .into(),
            }],
            node_assessments: Vec::new(),
            missing_edge_candidates: vec![MissingEdgeCandidate {
                candidate_id: "missing-node-a-node-b".into(),
                source_node_id: "node-a".into(),
                target_node_id: "node-b".into(),
                suggested_edge_kind: "related_to".into(),
                confidence_bp: 5000,
                reason: "shared catalog path".into(),
                supporting_artifact_references: vec![GRAPH_EXPLORER_INSPECTOR_PATH.into()],
            }],
            duplicate_edge_candidates: vec![DuplicateEdgeCandidate {
                candidate_id: "duplicate-edge-a-edge-b".into(),
                edge_ids: vec!["edge-a".into(), "edge-b".into()],
                confidence_bp: 8000,
                reason: "same endpoints and kind".into(),
            }],
            recommendations: vec![GraphRefinementRecommendation {
                recommendation_id: "recommend-edge-a".into(),
                target_type: GraphRefinementRecommendationTargetType::Edge,
                target_id: "edge-a".into(),
                group: GraphRefinementRecommendationGroup::StrengthenUsefulEdges,
                action: GraphRefinementAction::Strengthen,
                confidence_bp: 7000,
                reason: "useful but low evidence".into(),
                supporting_artifact_references: vec![GRAPH_REFINEMENT_REPORT_PATH.into()],
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            }],
            edge_triage_items: vec![EdgeTriageItem {
                triage_id: "triage-strong_keep_candidate-edge-a".into(),
                edge_id: "edge-a".into(),
                category: EdgeTriageCategory::StrongKeepCandidate,
                severity: EdgeTriageSeverity::Low,
                priority_score_bp: 1000,
                priority_rank: 1,
                reason: "edge is high quality and should remain visible as a strong connection"
                    .into(),
                recommended_action: GraphRefinementAction::Keep,
                evidence_level: EdgeEvidenceLevel::DirectTaskRunnerMatch,
                task_usage_count: 2,
                edge_quality_score_bp: 7500,
                diagnostic_impact_bp: 875,
                quality_delta_vs_neutral_bp: 500,
                citation_delta_vs_neutral_bp: 250,
                unsupported_delta_vs_neutral_bp: 125,
                cost_delta_vs_neutral_micro_exo: 50,
                supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            }],
            edge_triage_summary: EdgeTriageSummary {
                total_triage_item_count: 1,
                strong_keep_candidate_count: 1,
                ..EdgeTriageSummary::default()
            },
            edge_diagnosis_items: vec![EdgeDiagnosisItem {
                diagnosis_id: "diagnosis-quality_regression-edge-a".into(),
                edge_id: "edge-a".into(),
                cause: EdgeDiagnosisCause::QualityRegression,
                severity: EdgeTriageSeverity::Medium,
                impact_score_bp: 3000,
                task_ids: vec!["t001".into()],
                diagnostic_labels: vec!["governed_dagdb".into()],
                edge_kind: "depends_on".into(),
                graph_style: "dependency_dag".into(),
                reason: "graph-enabled diagnostic rows reduce quality versus the neutral baseline"
                    .into(),
                next_evidence_action:
                    "Inspect matched task rows and route references before strengthening this edge."
                        .into(),
                supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            }],
            edge_diagnosis_summary: EdgeDiagnosisSummary {
                total_diagnosis_item_count: 1,
                quality_regression_count: 1,
                ..EdgeDiagnosisSummary::default()
            },
            edge_closure_items: vec![EdgeClosureItem {
                closure_id: "closure-inspect_route_context-quality_regression-edge-a".into(),
                edge_id: "edge-a".into(),
                action: EdgeClosureAction::InspectRouteContext,
                priority_score_bp: 3000,
                severity: EdgeTriageSeverity::Medium,
                cause: EdgeClosureCause::QualityRegression,
                task_ids: vec!["t001".into()],
                diagnostic_labels: vec!["governed_dagdb".into()],
                edge_kind: "depends_on".into(),
                graph_style: "dependency_dag".into(),
                evidence_gap: "graph-enabled quality is below the neutral baseline".into(),
                closure_instruction:
                    "Inspect matched task rows and route context before strengthening or keeping this edge."
                        .into(),
                verification_hint:
                    "Regenerate most-recent and verify quality_delta_vs_neutral_bp is nonnegative."
                        .into(),
                supporting_artifact_references: vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
                writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
            }],
            edge_closure_summary: EdgeClosureSummary {
                total_closure_item_count: 1,
                inspect_route_context_count: 1,
                ..EdgeClosureSummary::default()
            },
            artifact_references: vec![
                GRAPH_EXPLORER_SNAPSHOT_PATH.into(),
                GRAPH_EXPLORER_INSPECTOR_PATH.into(),
            ],
            warnings: Vec::new(),
        };
        let body = json_body(&report).expect("json");
        assert!(body.contains("\"schema_version\": \"dagdb_graph_refinement_report_v1\""));
        assert!(body.contains("\"recommended_action\": \"keep\""));
        assert!(body.contains("\"writeback_status\": \"advisory_only\""));
        assert!(body.contains("\"group\": \"strengthen_useful_edges\""));
        assert!(body.contains("\"evidence_level\": \"direct_task_runner_match\""));
        assert!(body.contains("\"diagnostic_impact_bp\": 875"));
        assert!(body.contains("\"category\": \"strong_keep_candidate\""));
        assert!(body.contains("\"edge_triage_summary\""));
        assert!(body.contains("\"cause\": \"quality_regression\""));
        assert!(body.contains("\"edge_diagnosis_summary\""));
        assert!(body.contains("\"action\": \"inspect_route_context\""));
        assert!(body.contains("\"edge_closure_summary\""));
    }

    #[test]
    fn graph_refinement_triage_contract_serializes_ranked_items_and_summary() {
        let report = empty_graph_refinement_report(&snapshot(Vec::new(), Vec::new()));
        let body = json_body(&report).expect("json");
        assert!(body.contains("\"edge_triage_items\": []"));
        assert!(body.contains("\"total_triage_item_count\": 0"));
    }

    #[test]
    fn graph_refinement_edge_diagnosis_contract_serializes_empty_defaults() {
        let report = empty_graph_refinement_report(&snapshot(Vec::new(), Vec::new()));
        let body = json_body(&report).expect("json");
        assert!(body.contains("\"edge_diagnosis_items\": []"));
        assert!(body.contains("\"edge_diagnosis_summary\""));
        assert!(body.contains("\"total_diagnosis_item_count\": 0"));
    }

    #[test]
    fn graph_refinement_edge_closure_contract_serializes_empty_defaults() {
        let report = empty_graph_refinement_report(&snapshot(Vec::new(), Vec::new()));
        let body = json_body(&report).expect("json");
        assert!(body.contains("\"edge_closure_items\": []"));
        assert!(body.contains("\"edge_closure_summary\""));
        assert!(body.contains("\"total_closure_item_count\": 0"));
    }

    #[test]
    fn graph_refinement_edge_evidence_direct_task_runner_match() {
        let mut source = node(
            "source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        source.label = "t001 source summary".into();
        let mut target = node(
            "target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        target
            .metadata_summary
            .push("diagnostic_label:governed_dagdb".into());
        let edge = edge(
            "evidence-edge",
            "source",
            "target",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        let context = diagnostic_evidence_context_from_rows(vec![
            diagnostic_row(
                "fixture-a",
                "t001",
                "neutral_long_context",
                7000,
                8500,
                300,
                2000,
            ),
            diagnostic_row("fixture-a", "t001", "governed_dagdb", 8000, 9000, 100, 1000),
        ]);
        let report = derive_graph_refinement_report_with_evidence(
            &snapshot(vec![source, target], vec![edge]),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            &context,
        );
        let assessment = &report.edge_assessments[0];
        assert_eq!(
            assessment.evidence_level,
            EdgeEvidenceLevel::DirectTaskRunnerMatch
        );
        assert_eq!(assessment.task_usage_count, 1);
        assert_eq!(assessment.matched_task_ids, vec!["t001"]);
        assert_eq!(assessment.matched_diagnostic_labels, vec!["governed_dagdb"]);
        assert_eq!(assessment.avg_quality_bp, 8000);
        assert_eq!(assessment.avg_citation_accuracy_bp, 9000);
        assert_eq!(assessment.avg_unsupported_claim_rate_bp, 100);
        assert_eq!(assessment.quality_delta_vs_neutral_bp, 1000);
        assert_eq!(assessment.citation_delta_vs_neutral_bp, 500);
        assert_eq!(assessment.unsupported_delta_vs_neutral_bp, 200);
        assert_eq!(assessment.cost_delta_vs_neutral_micro_exo, 1000);
        assert_eq!(assessment.diagnostic_impact_bp, 1700);
        assert!(
            assessment
                .confidence_reason
                .contains("diagnostic_impact:1700")
        );
        assert!(
            assessment
                .supporting_artifact_references
                .contains(&GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH.into())
        );
    }

    #[test]
    fn graph_refinement_edge_evidence_task_and_runner_fallbacks_are_deterministic() {
        let mut task_source = node(
            "task-source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        task_source.label = "scale-t002 source summary".into();
        let task_target = node(
            "task-target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let task_edge = edge(
            "task-edge",
            "task-source",
            "task-target",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        let mut runner_source = node(
            "runner-source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        runner_source
            .metadata_summary
            .push("runner:governed_dagdb_optimized".into());
        let runner_target = node(
            "runner-target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let runner_edge = edge(
            "runner-edge",
            "runner-source",
            "runner-target",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        let context = diagnostic_evidence_context_from_rows(vec![
            diagnostic_row(
                "fixture-b",
                "scale-t002",
                "neutral_long_context",
                5000,
                5000,
                500,
                900,
            ),
            diagnostic_row(
                "fixture-b",
                "scale-t002",
                "governed_dagdb",
                6000,
                6000,
                400,
                800,
            ),
            diagnostic_row(
                "fixture-c",
                "t003",
                "neutral_long_context",
                4000,
                4000,
                700,
                1000,
            ),
            diagnostic_row(
                "fixture-c",
                "t003",
                "governed_dagdb_optimized",
                6500,
                7000,
                200,
                700,
            ),
        ]);
        let report = derive_graph_refinement_report_with_evidence(
            &snapshot(
                vec![task_source, task_target, runner_source, runner_target],
                vec![runner_edge, task_edge],
            ),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            &context,
        );
        let by_edge = report
            .edge_assessments
            .iter()
            .map(|assessment| (assessment.edge_id.as_str(), assessment))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_edge["task-edge"].evidence_level,
            EdgeEvidenceLevel::TaskMatch
        );
        assert_eq!(by_edge["task-edge"].matched_task_ids, vec!["scale-t002"]);
        assert_eq!(
            by_edge["runner-edge"].evidence_level,
            EdgeEvidenceLevel::RunnerMatch
        );
        assert_eq!(
            by_edge["runner-edge"].matched_diagnostic_labels,
            vec!["governed_dagdb_optimized"]
        );
    }

    #[test]
    fn graph_refinement_edge_evidence_unavailable_does_not_fabricate_metrics() {
        let source = node(
            "source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let target = node(
            "target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let edge = edge(
            "unmatched-edge",
            "source",
            "target",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        let report = derive_graph_refinement_report_with_evidence(
            &snapshot(vec![source, target], vec![edge]),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            &DiagnosticEvidenceContext::default(),
        );
        let assessment = &report.edge_assessments[0];
        assert_eq!(assessment.evidence_level, EdgeEvidenceLevel::Unavailable);
        assert_eq!(assessment.task_usage_count, 0);
        assert!(assessment.matched_task_ids.is_empty());
        assert!(assessment.matched_diagnostic_labels.is_empty());
        assert_eq!(assessment.avg_quality_bp, 0);
        assert_eq!(assessment.diagnostic_impact_bp, 0);
        assert_eq!(assessment.evidence_summary, "Evidence unavailable");
    }

    #[test]
    fn graph_refinement_edge_evidence_branch_vectors_cover_sparse_inputs() {
        let mut source = node(
            "source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        source.label = "t source without numeric suffix".into();
        let mut target = node(
            "target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        target.label = "scale-t target without numeric suffix".into();

        assert!(!is_task_id("t"));
        assert!(!is_task_id("tbad"));
        assert!(!is_task_id("scale-t"));
        assert!(!is_task_id("scale-tbad"));

        let mut labels = BTreeSet::new();
        collect_diagnostic_labels_from_value("runner:governed_dagdb,", &mut labels);
        collect_diagnostic_labels_from_value("context packets:;", &mut labels);
        assert_eq!(
            labels.into_iter().collect::<Vec<_>>(),
            vec!["governed_dagdb"]
        );

        let duplicate_row = diagnostic_row(
            "fixture-branch",
            "t009",
            "governed_dagdb",
            5000,
            5000,
            500,
            1000,
        );
        let mut seen = BTreeSet::new();
        let mut unique_rows = Vec::new();
        push_unique_diagnostic_rows(
            &[duplicate_row.clone(), duplicate_row],
            &mut seen,
            &mut unique_rows,
        );
        assert_eq!(unique_rows.len(), 1);

        let context = diagnostic_evidence_context_from_rows(vec![
            DiagnosticEvidenceRow {
                fixture_id: "fixture-neutral".into(),
                task_id: "t010".into(),
                diagnostic_label: "neutral_flat_rag".into(),
                quality_score_bp: Some(4000),
                citation_accuracy_bp: Some(4000),
                unsupported_claim_rate_bp: Some(600),
                total_cost_micro_exo: Some(900),
            },
            DiagnosticEvidenceRow {
                fixture_id: "fixture-skip".into(),
                task_id: String::new(),
                diagnostic_label: "governed_dagdb".into(),
                quality_score_bp: Some(5000),
                citation_accuracy_bp: Some(5000),
                unsupported_claim_rate_bp: Some(500),
                total_cost_micro_exo: Some(1000),
            },
        ]);
        assert!(context.rows_by_task.is_empty());
        assert!(
            context
                .neutral_by_fixture_task
                .contains_key(&("fixture-neutral".into(), "t010".into()))
        );

        let no_match_context = diagnostic_evidence_context_from_rows(vec![diagnostic_row(
            "fixture-other",
            "t999",
            "governed_dagdb_optimized",
            6000,
            6000,
            400,
            800,
        )]);
        let mut label_source = source.clone();
        label_source.label = "t011 source".into();
        let mut label_target = target.clone();
        label_target
            .metadata_summary
            .push("runner:governed_dagdb".into());
        let mut source_hash_edge = edge(
            "source-hash-edge",
            "source",
            "target",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        label_source.source_hash = Some("source-hash".into());
        assert_eq!(
            edge_diagnostic_evidence(
                &source_hash_edge,
                &label_source,
                &label_target,
                &no_match_context,
            )
            .evidence_level,
            EdgeEvidenceLevel::ArtifactReferenceOnly
        );
        label_source.source_hash = None;
        label_target.source_hash = Some("target-hash".into());
        source_hash_edge.receipt_id = None;
        assert_eq!(
            edge_diagnostic_evidence(
                &source_hash_edge,
                &label_source,
                &label_target,
                &no_match_context,
            )
            .evidence_level,
            EdgeEvidenceLevel::ArtifactReferenceOnly
        );

        let sparse = aggregate_edge_diagnostic_evidence(
            EdgeEvidenceLevel::ArtifactReferenceOnly,
            vec![DiagnosticEvidenceRow {
                fixture_id: "fixture-sparse".into(),
                task_id: "t012".into(),
                diagnostic_label: "governed_dagdb".into(),
                quality_score_bp: None,
                citation_accuracy_bp: None,
                unsupported_claim_rate_bp: None,
                total_cost_micro_exo: None,
            }],
            &DiagnosticEvidenceContext::default(),
        );
        assert_eq!(sparse.avg_quality_bp, 0);
        assert_eq!(sparse.quality_delta_vs_neutral_bp, 0);
        assert!(
            sparse
                .evidence_summary
                .contains("artifact reference only evidence")
        );
        assert!(evidence_summary(EdgeEvidenceLevel::Unavailable, 0, 0).contains("unavailable"));
    }

    #[test]
    fn graph_refinement_triage_generates_all_categories_and_summary_counts() {
        let mut no_evidence = triage_assessment("edge-no-evidence");
        no_evidence.evidence_level = EdgeEvidenceLevel::Unavailable;

        let mut negative_quality = triage_assessment("edge-negative-quality");
        negative_quality.quality_delta_vs_neutral_bp = -300;

        let mut negative_citation = triage_assessment("edge-negative-citation");
        negative_citation.citation_delta_vs_neutral_bp = -400;

        let mut higher_unsupported = triage_assessment("edge-higher-unsupported");
        higher_unsupported.unsupported_delta_vs_neutral_bp = -500;

        let mut higher_cost = triage_assessment("edge-higher-cost");
        higher_cost.cost_delta_vs_neutral_micro_exo = -70_000;

        let mut weak_frequent = triage_assessment("edge-weak-frequent");
        weak_frequent.edge_quality_score_bp = 4000;
        weak_frequent.task_usage_count = 3;
        weak_frequent.recommended_action = GraphRefinementAction::Review;

        let mut strong_keep = triage_assessment("edge-strong-keep");
        strong_keep.edge_quality_score_bp = 8000;
        strong_keep.diagnostic_impact_bp = 2184;
        strong_keep.recommended_action = GraphRefinementAction::Keep;

        let items = edge_triage_items(&[
            strong_keep,
            weak_frequent,
            higher_cost,
            higher_unsupported,
            negative_citation,
            negative_quality,
            no_evidence,
        ]);
        let summary = edge_triage_summary(&items);
        assert_eq!(summary.total_triage_item_count, 7);
        assert_eq!(summary.no_evidence_count, 1);
        assert_eq!(summary.negative_quality_delta_count, 1);
        assert_eq!(summary.negative_citation_delta_count, 1);
        assert_eq!(summary.higher_unsupported_claim_rate_count, 1);
        assert_eq!(summary.higher_cost_than_neutral_count, 1);
        assert_eq!(summary.weak_frequent_edge_count, 1);
        assert_eq!(summary.strong_keep_candidate_count, 1);
        assert!(
            items
                .iter()
                .any(|item| item.category == EdgeTriageCategory::NoEvidence)
        );
        assert!(
            items
                .iter()
                .any(|item| item.category == EdgeTriageCategory::StrongKeepCandidate)
        );
        assert_eq!(items[0].priority_rank, 1);
        assert_eq!(items[0].severity, EdgeTriageSeverity::High);
        assert_eq!(items[0].priority_score_bp, 7000);
    }

    #[test]
    fn graph_refinement_triage_orders_by_severity_score_and_edge_id() {
        let mut critical_b = triage_assessment("edge-b");
        critical_b.quality_delta_vs_neutral_bp = -3000;
        let mut critical_a = triage_assessment("edge-a");
        critical_a.quality_delta_vs_neutral_bp = -3000;
        let mut medium = triage_assessment("edge-c");
        medium.quality_delta_vs_neutral_bp = -800;
        let items = edge_triage_items(&[medium, critical_b, critical_a]);
        assert_eq!(items[0].edge_id, "edge-a");
        assert_eq!(items[0].priority_rank, 1);
        assert_eq!(items[1].edge_id, "edge-b");
        assert_eq!(items[1].priority_rank, 2);
        assert_eq!(items[2].edge_id, "edge-c");
        assert_eq!(items[2].priority_rank, 3);
        assert_eq!(items[0].severity, EdgeTriageSeverity::Critical);
        assert_eq!(items[2].severity, EdgeTriageSeverity::Medium);
    }

    #[test]
    fn graph_refinement_triage_branch_vectors_cover_false_paths() {
        assert!(edge_triage_items(&[]).is_empty());

        let clean = triage_assessment("edge-clean");
        assert!(edge_triage_items(&[clean]).is_empty());

        let mut artifact_only = triage_assessment("edge-artifact-only");
        artifact_only.evidence_level = EdgeEvidenceLevel::ArtifactReferenceOnly;
        let artifact_items = edge_triage_items(&[artifact_only]);
        assert_eq!(artifact_items.len(), 1);
        assert_eq!(artifact_items[0].category, EdgeTriageCategory::NoEvidence);

        let mut weak_but_rare = triage_assessment("edge-weak-rare");
        weak_but_rare.edge_quality_score_bp = 4000;
        weak_but_rare.task_usage_count = 1;
        assert!(edge_triage_items(&[weak_but_rare]).is_empty());

        let mut frequent_but_not_weak = triage_assessment("edge-frequent-not-weak");
        frequent_but_not_weak.edge_quality_score_bp = 5000;
        frequent_but_not_weak.task_usage_count = 2;
        assert!(edge_triage_items(&[frequent_but_not_weak]).is_empty());

        let mut high_but_not_keep = triage_assessment("edge-high-not-keep");
        high_but_not_keep.edge_quality_score_bp = 8000;
        high_but_not_keep.recommended_action = GraphRefinementAction::Strengthen;
        assert!(edge_triage_items(&[high_but_not_keep]).is_empty());

        let mut keep_but_not_high = triage_assessment("edge-keep-not-high");
        keep_but_not_high.edge_quality_score_bp = 7499;
        keep_but_not_high.recommended_action = GraphRefinementAction::Keep;
        assert!(edge_triage_items(&[keep_but_not_high]).is_empty());

        let mut keep_with_low_impact = triage_assessment("edge-keep-low-impact");
        keep_with_low_impact.edge_quality_score_bp = 7500;
        keep_with_low_impact.recommended_action = GraphRefinementAction::Keep;
        keep_with_low_impact.diagnostic_impact_bp = 0;
        let keep_items = edge_triage_items(&[keep_with_low_impact]);
        assert_eq!(keep_items.len(), 1);
        assert_eq!(
            keep_items[0].category,
            EdgeTriageCategory::StrongKeepCandidate
        );
        assert_eq!(keep_items[0].priority_score_bp, 1000);
    }

    #[test]
    fn graph_refinement_triage_score_helpers_are_capped_and_thresholded() {
        assert_eq!(negative_delta_score(-3000), 10_000);
        assert_eq!(negative_delta_score(-1), 4);
        assert_eq!(negative_cost_score(-150_000), 10_000);
        assert_eq!(negative_cost_score(-99), 9);
        assert_eq!(edge_triage_severity(8000), EdgeTriageSeverity::Critical);
        assert_eq!(edge_triage_severity(6000), EdgeTriageSeverity::High);
        assert_eq!(edge_triage_severity(3000), EdgeTriageSeverity::Medium);
        assert_eq!(edge_triage_severity(1000), EdgeTriageSeverity::Low);
        assert_eq!(edge_triage_severity(999), EdgeTriageSeverity::Info);
    }

    #[test]
    fn graph_refinement_edge_diagnosis_generates_all_causes_and_summary_counts() {
        let mut no_evidence = triage_assessment("edge-no-evidence");
        no_evidence.evidence_level = EdgeEvidenceLevel::Unavailable;

        let mut negative_quality = triage_assessment("edge-negative-quality");
        negative_quality.quality_delta_vs_neutral_bp = -300;

        let mut negative_citation = triage_assessment("edge-negative-citation");
        negative_citation.citation_delta_vs_neutral_bp = -400;

        let mut higher_unsupported = triage_assessment("edge-higher-unsupported");
        higher_unsupported.unsupported_delta_vs_neutral_bp = -500;

        let mut higher_cost = triage_assessment("edge-higher-cost");
        higher_cost.cost_delta_vs_neutral_micro_exo = -70_000;

        let mut weak_frequent = triage_assessment("edge-weak-frequent");
        weak_frequent.edge_quality_score_bp = 4000;
        weak_frequent.task_usage_count = 3;
        weak_frequent.recommended_action = GraphRefinementAction::Review;

        let mut strong_keep = triage_assessment("edge-strong-keep");
        strong_keep.edge_quality_score_bp = 8000;
        strong_keep.diagnostic_impact_bp = 2184;
        strong_keep.recommended_action = GraphRefinementAction::Keep;

        let assessments = vec![
            strong_keep,
            weak_frequent,
            higher_cost,
            higher_unsupported,
            negative_citation,
            negative_quality,
            no_evidence,
        ];
        let triage_items = edge_triage_items(&assessments);
        let diagnosis_items = edge_diagnosis_items(&assessments, &triage_items);
        let summary = edge_diagnosis_summary(&diagnosis_items);

        assert_eq!(summary.total_diagnosis_item_count, 6);
        assert_eq!(summary.quality_regression_count, 1);
        assert_eq!(summary.citation_regression_count, 1);
        assert_eq!(summary.unsupported_claim_regression_count, 1);
        assert_eq!(summary.cost_regression_count, 1);
        assert_eq!(summary.weak_frequent_connection_count, 1);
        assert_eq!(summary.missing_evidence_count, 1);
        assert!(
            diagnosis_items
                .iter()
                .any(|item| item.cause == EdgeDiagnosisCause::QualityRegression)
        );
        assert!(
            diagnosis_items
                .iter()
                .any(|item| item.cause == EdgeDiagnosisCause::WeakFrequentConnection)
        );
        assert!(
            diagnosis_items
                .iter()
                .all(|item| item.edge_id != "edge-strong-keep")
        );
        assert_eq!(diagnosis_items[0].severity, EdgeTriageSeverity::High);
        assert!(diagnosis_items[0].next_evidence_action.contains("Inspect"));
    }

    #[test]
    fn graph_refinement_edge_diagnosis_orders_by_severity_score_edge_and_id() {
        let mut critical_b = triage_assessment("edge-b");
        critical_b.quality_delta_vs_neutral_bp = -3000;
        let mut critical_a = triage_assessment("edge-a");
        critical_a.quality_delta_vs_neutral_bp = -3000;
        let mut medium = triage_assessment("edge-c");
        medium.quality_delta_vs_neutral_bp = -800;

        let assessments = vec![medium, critical_b, critical_a];
        let triage_items = edge_triage_items(&assessments);
        let diagnosis_items = edge_diagnosis_items(&assessments, &triage_items);

        assert_eq!(diagnosis_items[0].edge_id, "edge-a");
        assert_eq!(diagnosis_items[1].edge_id, "edge-b");
        assert_eq!(diagnosis_items[2].edge_id, "edge-c");
        assert_eq!(diagnosis_items[0].severity, EdgeTriageSeverity::Critical);
        assert_eq!(diagnosis_items[2].severity, EdgeTriageSeverity::Medium);
    }

    #[test]
    fn graph_refinement_edge_diagnosis_branch_vectors_cover_non_diagnosis_paths() {
        assert!(edge_diagnosis_items(&[], &[]).is_empty());

        let mut strong_keep = triage_assessment("edge-strong-keep");
        strong_keep.edge_quality_score_bp = 8000;
        strong_keep.recommended_action = GraphRefinementAction::Keep;
        let strong_keep_triage = edge_triage_items(&[strong_keep.clone()]);
        assert_eq!(
            strong_keep_triage[0].category,
            EdgeTriageCategory::StrongKeepCandidate
        );
        assert!(edge_diagnosis_items(&[strong_keep], &strong_keep_triage).is_empty());

        let orphan_triage = EdgeTriageItem {
            triage_id: "triage-negative_quality_delta-edge-orphan".into(),
            edge_id: "edge-orphan".into(),
            category: EdgeTriageCategory::NegativeQualityDelta,
            severity: EdgeTriageSeverity::Medium,
            priority_score_bp: 3000,
            priority_rank: 1,
            reason: "orphan triage".into(),
            recommended_action: GraphRefinementAction::Review,
            evidence_level: EdgeEvidenceLevel::TaskMatch,
            task_usage_count: 1,
            edge_quality_score_bp: 5000,
            diagnostic_impact_bp: 0,
            quality_delta_vs_neutral_bp: -750,
            citation_delta_vs_neutral_bp: 0,
            unsupported_delta_vs_neutral_bp: 0,
            cost_delta_vs_neutral_micro_exo: 0,
            supporting_artifact_references: Vec::new(),
            writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
        };
        assert!(edge_diagnosis_items(&[], &[orphan_triage]).is_empty());

        let mut no_refs = triage_assessment("edge-no-refs");
        no_refs.supporting_artifact_references.clear();
        no_refs.quality_delta_vs_neutral_bp = -750;
        let triage_items = edge_triage_items(&[no_refs.clone()]);
        let diagnosis_items = edge_diagnosis_items(&[no_refs], &triage_items);
        assert_eq!(
            diagnosis_items[0].supporting_artifact_references,
            vec![GRAPH_REFINEMENT_REPORT_PATH.to_string()]
        );

        assert_eq!(
            edge_diagnosis_cause_for_triage(EdgeTriageCategory::StrongKeepCandidate),
            None
        );
        assert_eq!(
            edge_diagnosis_cause_key(EdgeDiagnosisCause::CitationRegression),
            "citation_regression"
        );
        assert_eq!(
            edge_diagnosis_cause_key(EdgeDiagnosisCause::CostRegression),
            "cost_regression"
        );
        assert!(
            edge_diagnosis_text(EdgeDiagnosisCause::MissingEvidence)
                .0
                .contains("no matched task")
        );
    }

    #[test]
    fn graph_refinement_edge_closure_generates_all_actions_and_summary_counts() {
        let mut no_evidence = triage_assessment("edge-no-evidence");
        no_evidence.evidence_level = EdgeEvidenceLevel::Unavailable;

        let mut negative_quality = triage_assessment("edge-negative-quality");
        negative_quality.quality_delta_vs_neutral_bp = -300;

        let mut negative_citation = triage_assessment("edge-negative-citation");
        negative_citation.citation_delta_vs_neutral_bp = -400;

        let mut higher_unsupported = triage_assessment("edge-higher-unsupported");
        higher_unsupported.unsupported_delta_vs_neutral_bp = -500;

        let mut higher_cost = triage_assessment("edge-higher-cost");
        higher_cost.cost_delta_vs_neutral_micro_exo = -70_000;

        let mut weak_frequent = triage_assessment("edge-weak-frequent");
        weak_frequent.edge_quality_score_bp = 4000;
        weak_frequent.task_usage_count = 3;
        weak_frequent.recommended_action = GraphRefinementAction::Review;

        let mut strong_keep = triage_assessment("edge-strong-keep");
        strong_keep.edge_quality_score_bp = 8000;
        strong_keep.diagnostic_impact_bp = 2184;
        strong_keep.recommended_action = GraphRefinementAction::Keep;

        let assessments = vec![
            strong_keep,
            weak_frequent,
            higher_cost,
            higher_unsupported,
            negative_citation,
            negative_quality,
            no_evidence,
        ];
        let triage_items = edge_triage_items(&assessments);
        let diagnosis_items = edge_diagnosis_items(&assessments, &triage_items);
        let closure_items = edge_closure_items(&assessments, &triage_items, &diagnosis_items);
        let summary = edge_closure_summary(&closure_items);

        assert_eq!(summary.total_closure_item_count, 7);
        assert_eq!(summary.add_task_runner_metadata_count, 1);
        assert_eq!(summary.attach_receipt_or_validation_count, 2);
        assert_eq!(summary.inspect_route_context_count, 1);
        assert_eq!(summary.split_overbroad_connection_count, 1);
        assert_eq!(summary.hide_noisy_connection_count, 1);
        assert_eq!(summary.strengthen_supported_connection_count, 1);
        assert_eq!(summary.review_missing_evidence_count, 0);
        assert!(
            closure_items
                .iter()
                .any(|item| item.action == EdgeClosureAction::StrengthenSupportedConnection)
        );
        assert!(
            closure_items
                .iter()
                .any(|item| item.cause == EdgeClosureCause::MissingEvidence)
        );
        assert!(
            closure_items
                .iter()
                .all(|item| item.writeback_status == GraphRefinementWritebackStatus::AdvisoryOnly)
        );
    }

    #[test]
    fn graph_refinement_edge_closure_orders_by_severity_score_edge_and_id() {
        let mut critical_b = triage_assessment("edge-b");
        critical_b.quality_delta_vs_neutral_bp = -3000;
        let mut critical_a = triage_assessment("edge-a");
        critical_a.quality_delta_vs_neutral_bp = -3000;
        let mut medium = triage_assessment("edge-c");
        medium.quality_delta_vs_neutral_bp = -800;

        let assessments = vec![medium, critical_b, critical_a];
        let triage_items = edge_triage_items(&assessments);
        let diagnosis_items = edge_diagnosis_items(&assessments, &triage_items);
        let closure_items = edge_closure_items(&assessments, &triage_items, &diagnosis_items);

        assert_eq!(closure_items[0].edge_id, "edge-a");
        assert_eq!(closure_items[1].edge_id, "edge-b");
        assert_eq!(closure_items[2].edge_id, "edge-c");
        assert_eq!(closure_items[0].severity, EdgeTriageSeverity::Critical);
        assert_eq!(closure_items[2].severity, EdgeTriageSeverity::Medium);
    }

    #[test]
    fn graph_refinement_edge_closure_branch_vectors_cover_empty_orphan_and_review_paths() {
        assert!(edge_closure_items(&[], &[], &[]).is_empty());

        let orphan_triage = EdgeTriageItem {
            triage_id: "triage-strong_keep_candidate-edge-orphan".into(),
            edge_id: "edge-orphan".into(),
            category: EdgeTriageCategory::StrongKeepCandidate,
            severity: EdgeTriageSeverity::Low,
            priority_score_bp: 1000,
            priority_rank: 1,
            reason: "orphan strong keep".into(),
            recommended_action: GraphRefinementAction::Keep,
            evidence_level: EdgeEvidenceLevel::DirectTaskRunnerMatch,
            task_usage_count: 1,
            edge_quality_score_bp: 8000,
            diagnostic_impact_bp: 0,
            quality_delta_vs_neutral_bp: 0,
            citation_delta_vs_neutral_bp: 0,
            unsupported_delta_vs_neutral_bp: 0,
            cost_delta_vs_neutral_micro_exo: 0,
            supporting_artifact_references: Vec::new(),
            writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
        };
        assert!(edge_closure_items(&[], &[orphan_triage], &[]).is_empty());

        assert_eq!(
            edge_closure_action_for_diagnosis(EdgeDiagnosisCause::MissingEvidence),
            EdgeClosureAction::AddTaskRunnerMetadata
        );
        assert_eq!(
            edge_closure_action_key(EdgeClosureAction::ReviewMissingEvidence),
            "review_missing_evidence"
        );
        assert_eq!(
            edge_closure_cause_key(EdgeClosureCause::StrongKeepCandidate),
            "strong_keep_candidate"
        );
        assert!(
            edge_closure_text(
                EdgeClosureAction::ReviewMissingEvidence,
                EdgeClosureCause::MissingEvidence
            )
            .0
            .contains("manual evidence review")
        );

        let review_item = EdgeClosureItem {
            closure_id: "closure-review_missing_evidence-missing_evidence-edge-review".into(),
            edge_id: "edge-review".into(),
            action: EdgeClosureAction::ReviewMissingEvidence,
            priority_score_bp: 1000,
            severity: EdgeTriageSeverity::Low,
            cause: EdgeClosureCause::MissingEvidence,
            task_ids: Vec::new(),
            diagnostic_labels: Vec::new(),
            edge_kind: "related_to".into(),
            graph_style: "dependency_dag".into(),
            evidence_gap: "manual evidence review".into(),
            closure_instruction: "review deterministic evidence".into(),
            verification_hint: "regenerate most-recent".into(),
            supporting_artifact_references: Vec::new(),
            writeback_status: GraphRefinementWritebackStatus::AdvisoryOnly,
        };
        assert_eq!(
            edge_closure_summary(&[review_item]).review_missing_evidence_count,
            1
        );
    }

    #[test]
    fn graph_refinement_edge_closure_worklist_orders_counts_and_references() {
        let mut critical = triage_assessment("edge-critical");
        critical.quality_delta_vs_neutral_bp = -3000;
        let mut high = triage_assessment("edge-high");
        high.edge_quality_score_bp = 4000;
        high.task_usage_count = 3;
        high.recommended_action = GraphRefinementAction::Review;

        let report = derive_graph_refinement_report_with_evidence(
            &snapshot(
                vec![
                    node(
                        "node-a",
                        MemoryNodeKind::Route,
                        MemoryGraphStyle::RoutingViewGraph,
                    ),
                    node(
                        "node-b",
                        MemoryNodeKind::ValidationReport,
                        MemoryGraphStyle::RoutingViewGraph,
                    ),
                ],
                Vec::new(),
            ),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
            &DiagnosticEvidenceContext::default(),
        );
        let triage_items = edge_triage_items(&[high.clone(), critical.clone()]);
        let diagnosis_items = edge_diagnosis_items(&[high, critical], &triage_items);
        let closure_items = edge_closure_items(&[], &[], &diagnosis_items);
        let closure_summary = edge_closure_summary(&closure_items);
        let report = GraphRefinementReport {
            edge_closure_items: closure_items,
            edge_closure_summary: closure_summary,
            ..report
        };
        let worklist = evidence_closure_worklist(
            "most-recent",
            &report,
            "target/dagdb/graph_explorer/datasets/most-recent/refinement_report.json".into(),
        );

        assert_eq!(
            worklist.schema_version,
            GRAPH_EVIDENCE_CLOSURE_WORKLIST_SCHEMA_VERSION
        );
        assert_eq!(worklist.dataset_id, "most-recent");
        assert!(worklist.advisory_only);
        assert_eq!(worklist.total_item_count, 2);
        assert_eq!(worklist.items[0].rank, 1);
        assert_eq!(worklist.items[0].edge_id, "edge-critical");
        assert_eq!(
            worklist.action_counts.get("inspect_route_context").copied(),
            Some(1)
        );
        assert_eq!(
            worklist
                .action_counts
                .get("split_overbroad_connection")
                .copied(),
            Some(1)
        );
        assert!(
            worklist
                .artifact_references
                .iter()
                .any(|reference| reference.ends_with("refinement_report.json"))
        );
        let markdown = evidence_closure_worklist_markdown(&worklist);
        assert!(markdown.contains("EXOCHAIN DAG DB Evidence Closure Worklist"));
        assert!(markdown.contains("No source DAG records are changed"));
    }

    #[test]
    fn graph_refinement_closure_review_contract_serializes_template_and_intake() {
        let mut assessment = triage_assessment("edge-review");
        assessment.quality_delta_vs_neutral_bp = -1000;
        let triage_items = edge_triage_items(&[assessment.clone()]);
        let diagnosis_items = edge_diagnosis_items(&[assessment], &triage_items);
        let closure_items = edge_closure_items(&[], &[], &diagnosis_items);
        let base_report = derive_graph_refinement_report(
            &snapshot(Vec::new(), Vec::new()),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        let report = GraphRefinementReport {
            edge_closure_summary: edge_closure_summary(&closure_items),
            edge_closure_items: closure_items,
            ..base_report
        };

        let template = evidence_closure_review_template("most-recent", &report);
        assert_eq!(
            template.schema_version,
            GRAPH_EVIDENCE_CLOSURE_REVIEW_SCHEMA_VERSION
        );
        assert_eq!(
            template.items[0].review_status,
            EvidenceClosureReviewStatus::Open
        );
        assert!(
            json_body(&template)
                .expect("template json")
                .contains("\"schema_version\": \"dagdb_evidence_closure_review_v1\"")
        );
        assert!(
            evidence_closure_review_template_markdown(&template)
                .contains("Evidence Closure Review Template")
        );

        let packet = evidence_intake_packet_file("most-recent", &report, 1);
        assert_eq!(
            packet.schema_version,
            GRAPH_EVIDENCE_INTAKE_PACKET_SCHEMA_VERSION
        );
        assert_eq!(packet.total_packet_item_count, 1);
        assert_eq!(packet.items[0].rank, 1);
        assert!(
            packet.items[0]
                .required_evidence_fields
                .iter()
                .any(|field| field == "route_id")
        );
        assert!(evidence_intake_packet_markdown(&packet).contains("Evidence Intake Packets"));
    }

    #[test]
    fn graph_refinement_closure_review_validation_rejects_unsafe_unknown_and_duplicate_rows() {
        let mut assessment = triage_assessment("edge-review");
        assessment.quality_delta_vs_neutral_bp = -1000;
        let triage_items = edge_triage_items(&[assessment.clone()]);
        let diagnosis_items = edge_diagnosis_items(&[assessment], &triage_items);
        let closure_items = edge_closure_items(&[], &[], &diagnosis_items);
        let base_report = derive_graph_refinement_report(
            &snapshot(Vec::new(), Vec::new()),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        let report = GraphRefinementReport {
            edge_closure_summary: edge_closure_summary(&closure_items),
            edge_closure_items: closure_items,
            ..base_report
        };
        let mut review = evidence_closure_review_template("most-recent", &report);
        review.source_snapshot_id = report.source_snapshot_id.clone();
        review.items[0].review_status = EvidenceClosureReviewStatus::Verified;
        review.items[0].verification_status = EvidenceClosureVerificationStatus::Passed;
        review.items[0].operator_note_redacted = "redacted route evidence verified".into();
        review.items[0].evidence_reference_ids = vec!["receipt-redacted-1".into()];
        review.items[0].reviewed_artifact_references =
            vec!["target/dagdb/graph_explorer/datasets/most-recent/refinement_report.json".into()];
        validate_evidence_closure_review_file(&review, &report).expect("valid review");

        let summary = evidence_closure_review_summary(
            &review,
            &report,
            "target/dagdb/evidence_closure_reviews/most-recent/evidence_closure_review.json".into(),
        )
        .expect("summary");
        assert_eq!(summary.verified_count, 1);
        assert_eq!(summary.completion_rate_bp, 10_000);
        assert_eq!(summary.review_items.len(), 1);
        assert!(evidence_closure_review_summary_markdown(&summary).contains("verified_count: 1"));

        let mut duplicate = review.clone();
        duplicate.items.push(duplicate.items[0].clone());
        assert!(validate_evidence_closure_review_file(&duplicate, &report).is_err());

        let mut unknown = review.clone();
        unknown.items[0].closure_id = "closure-unknown".into();
        assert!(validate_evidence_closure_review_file(&unknown, &report).is_err());

        let mut unsafe_note = review.clone();
        unsafe_note.items[0].operator_note_redacted = "DATABASE_URL=postgres://safe".into();
        assert!(validate_evidence_closure_review_file(&unsafe_note, &report).is_err());

        let mut long_note = review;
        long_note.items[0].operator_note_redacted = "a".repeat(281);
        assert!(validate_evidence_closure_review_file(&long_note, &report).is_err());
    }

    #[test]
    fn graph_refinement_closure_review_branch_vectors_cover_statuses_safety_and_limits() {
        let mut no_evidence = triage_assessment("edge-no-evidence");
        no_evidence.evidence_level = EdgeEvidenceLevel::Unavailable;

        let mut negative_quality = triage_assessment("edge-negative-quality");
        negative_quality.quality_delta_vs_neutral_bp = -300;

        let mut negative_citation = triage_assessment("edge-negative-citation");
        negative_citation.citation_delta_vs_neutral_bp = -400;

        let mut higher_unsupported = triage_assessment("edge-higher-unsupported");
        higher_unsupported.unsupported_delta_vs_neutral_bp = -500;

        let mut higher_cost = triage_assessment("edge-higher-cost");
        higher_cost.cost_delta_vs_neutral_micro_exo = -70_000;

        let mut weak_frequent = triage_assessment("edge-weak-frequent");
        weak_frequent.edge_quality_score_bp = 4000;
        weak_frequent.task_usage_count = 3;
        weak_frequent.recommended_action = GraphRefinementAction::Review;

        let mut strong_keep = triage_assessment("edge-strong-keep");
        strong_keep.edge_quality_score_bp = 8000;
        strong_keep.diagnostic_impact_bp = 2184;
        strong_keep.recommended_action = GraphRefinementAction::Keep;

        let assessments = vec![
            no_evidence,
            negative_quality,
            negative_citation,
            higher_unsupported,
            higher_cost,
            weak_frequent,
            strong_keep,
        ];
        let triage_items = edge_triage_items(&assessments);
        let diagnosis_items = edge_diagnosis_items(&assessments, &triage_items);
        let closure_items = edge_closure_items(&assessments, &triage_items, &diagnosis_items);
        let base_report = derive_graph_refinement_report(
            &snapshot(Vec::new(), Vec::new()),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        let report = GraphRefinementReport {
            edge_closure_summary: edge_closure_summary(&closure_items),
            edge_closure_items: closure_items,
            ..base_report
        };
        let mut review = evidence_closure_review_template("most-recent", &report);
        review.source_snapshot_id = report.source_snapshot_id.clone();
        let statuses = [
            EvidenceClosureReviewStatus::Open,
            EvidenceClosureReviewStatus::EvidenceAttached,
            EvidenceClosureReviewStatus::Verified,
            EvidenceClosureReviewStatus::Deferred,
            EvidenceClosureReviewStatus::RejectedNoise,
            EvidenceClosureReviewStatus::KeepConfirmed,
        ];
        for (index, status) in statuses.into_iter().enumerate() {
            review.items[index].review_status = status;
            review.items[index].verification_status = match status {
                EvidenceClosureReviewStatus::Verified => EvidenceClosureVerificationStatus::Passed,
                EvidenceClosureReviewStatus::RejectedNoise => {
                    EvidenceClosureVerificationStatus::Failed
                }
                _ => EvidenceClosureVerificationStatus::NotRun,
            };
        }
        review.items[0].operator_note_redacted = "open item kept redacted".into();
        review.items[1].evidence_reference_ids = vec!["receipt-redacted-attached".into()];
        review.items[2].reviewed_artifact_references =
            vec!["target/dagdb/graph_explorer/datasets/most-recent/refinement_report.json".into()];

        let summary = evidence_closure_review_summary(
            &review,
            &report,
            "target/dagdb/evidence_closure_reviews/most-recent/evidence_closure_review.json".into(),
        )
        .expect("summary");
        assert_eq!(summary.open_count, 2);
        assert_eq!(summary.evidence_attached_count, 1);
        assert_eq!(summary.verified_count, 1);
        assert_eq!(summary.deferred_count, 1);
        assert_eq!(summary.rejected_noise_count, 1);
        assert_eq!(summary.keep_confirmed_count, 1);
        assert_eq!(summary.completion_rate_bp, 5714);
        assert_eq!(summary.top_verified_items.len(), 1);
        assert!(
            evidence_closure_review_summary_markdown(&summary)
                .contains("Top Verified Closure Items")
        );

        let empty_report = GraphRefinementReport {
            edge_closure_summary: EdgeClosureSummary::default(),
            edge_closure_items: Vec::new(),
            ..derive_graph_refinement_report(
                &snapshot(Vec::new(), Vec::new()),
                &BTreeMap::new(),
                Vec::new(),
            )
        };
        let empty_review = evidence_closure_review_template("empty-dataset", &empty_report);
        let empty_summary =
            evidence_closure_review_summary(&empty_review, &empty_report, "review-empty".into())
                .expect("empty summary");
        assert_eq!(empty_summary.completion_rate_bp, 0);

        assert_eq!(
            evidence_intake_packet_file("most-recent", &report, 0).limit,
            1
        );
        assert_eq!(
            evidence_intake_packet_file("most-recent", &report, 600).limit,
            500
        );
        assert_eq!(
            required_evidence_fields(EdgeClosureAction::AddTaskRunnerMetadata),
            vec!["task_id", "diagnostic_label", "edge_id"]
        );
        assert_eq!(
            required_evidence_fields(EdgeClosureAction::AttachReceiptOrValidation),
            vec!["receipt_id", "validation_report_id", "edge_id"]
        );
        assert_eq!(
            required_evidence_fields(EdgeClosureAction::SplitOverbroadConnection),
            vec!["replacement_edge_ids", "task_ids", "edge_id"]
        );
        assert_eq!(
            required_evidence_fields(EdgeClosureAction::HideNoisyConnection),
            vec!["noise_reason", "task_ids", "edge_id"]
        );
        assert_eq!(
            required_evidence_fields(EdgeClosureAction::StrengthenSupportedConnection),
            vec!["receipt_id", "supporting_task_ids", "edge_id"]
        );
        assert_eq!(
            required_evidence_fields(EdgeClosureAction::ReviewMissingEvidence),
            vec!["review_reason", "edge_id"]
        );
        assert!(contains_url_with_credentials(
            "https://user:pass@example.invalid/path"
        ));
        assert!(!contains_url_with_credentials(
            "https://example.invalid/path"
        ));

        let mut bad_schema = review.clone();
        bad_schema.schema_version = "bad_schema".into();
        assert!(validate_evidence_closure_review_file(&bad_schema, &report).is_err());

        let mut not_advisory = review.clone();
        not_advisory.advisory_only = false;
        assert!(validate_evidence_closure_review_file(&not_advisory, &report).is_err());

        let mut bad_dataset = review.clone();
        bad_dataset.dataset_id = "../bad".into();
        assert!(validate_evidence_closure_review_file(&bad_dataset, &report).is_err());

        let mut bad_snapshot = review.clone();
        bad_snapshot.source_snapshot_id = "different-snapshot".into();
        assert!(validate_evidence_closure_review_file(&bad_snapshot, &report).is_err());

        let mut bad_edge = review.clone();
        bad_edge.items[0].edge_id = "different-edge".into();
        assert!(validate_evidence_closure_review_file(&bad_edge, &report).is_err());

        let mut non_ascii = review.clone();
        non_ascii.items[0].operator_note_redacted = "not redacted ✓".into();
        assert!(validate_evidence_closure_review_file(&non_ascii, &report).is_err());

        let mut unsafe_evidence_reference = review.clone();
        unsafe_evidence_reference.items[0].evidence_reference_ids =
            vec!["https://user:pass@example.invalid/evidence".into()];
        assert!(
            validate_evidence_closure_review_file(&unsafe_evidence_reference, &report).is_err()
        );

        let mut unsafe_artifact_reference = review;
        unsafe_artifact_reference.items[0].reviewed_artifact_references =
            vec!["raw_payload_text ```".into()];
        assert!(
            validate_evidence_closure_review_file(&unsafe_artifact_reference, &report).is_err()
        );
    }

    #[test]
    fn graph_refinement_scores_all_threshold_actions() {
        assert_eq!(
            recommended_edge_action(8000, 0, 0),
            GraphRefinementAction::Keep
        );
        assert_eq!(
            recommended_edge_action(6500, 0, 0),
            GraphRefinementAction::Strengthen
        );
        assert_eq!(
            recommended_edge_action(3000, 0, 0),
            GraphRefinementAction::Review
        );
        assert_eq!(
            recommended_edge_action(9000, 7000, 0),
            GraphRefinementAction::Supersede
        );
        assert_eq!(
            recommended_edge_action(9000, 0, 7000),
            GraphRefinementAction::Review
        );
    }

    #[test]
    fn graph_refinement_scores_are_capped_and_explainable() {
        let mut source = node(
            "node-a",
            MemoryNodeKind::Route,
            MemoryGraphStyle::RoutingViewGraph,
        );
        let mut target = node(
            "node-b",
            MemoryNodeKind::ValidationReport,
            MemoryGraphStyle::RoutingViewGraph,
        );
        source.receipt_ids.push("receipt-source".into());
        source.source_hash = Some("aaaaaaaa11111111".into());
        target.source_hash = Some("aaaaaaaa22222222".into());
        let mut edge = edge(
            "edge-a",
            "node-a",
            "node-b",
            MemoryEdgeKind::UsedByRoute,
            MemoryGraphStyle::RoutingViewGraph,
        );
        edge.receipt_id = Some("receipt-edge".into());
        let mut details = empty_details(source.clone());
        details.evidence.push("edge-a node-a node-b".into());
        details.context_packets.push("context".into());
        details.validation_reports.push("validation".into());
        details.edge_details.push(edge.clone());
        let inspector = BTreeMap::from([(source.node_id.clone(), details)]);
        let assessment = assess_edge(
            &edge,
            &source,
            &target,
            &inspector,
            &DiagnosticEvidenceContext::default(),
        );
        assert_eq!(assessment.evidence_strength_bp, 10_000);
        assert_eq!(assessment.routing_usefulness_bp, 7500);
        assert_eq!(assessment.recommended_action, GraphRefinementAction::Keep);
        assert!(assessment.confidence_reason.contains("evidence:10000"));
        assert!(
            assessment
                .supporting_artifact_references
                .contains(&GRAPH_EXPLORER_INSPECTOR_PATH.into())
        );
    }

    #[test]
    fn graph_refinement_risk_branches_drive_recommendations() {
        let source = node(
            "node-a",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let mut target = node(
            "node-b",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        target.status = GraphExplorerNodeStatus::Superseded;
        let mut stale = edge(
            "edge-stale",
            "node-a",
            "node-b",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        stale.status = GraphExplorerEdgeStatus::Revoked;
        let stale_assessment = assess_edge(
            &stale,
            &source,
            &target,
            &BTreeMap::new(),
            &DiagnosticEvidenceContext::default(),
        );
        assert_eq!(stale_assessment.staleness_risk_bp, 10_000);
        assert_eq!(
            stale_assessment.recommended_action,
            GraphRefinementAction::Review
        );
        assert!(!stale_assessment.weakening_artifact_references.is_empty());

        let contradicted = edge(
            "edge-contradicted",
            "node-a",
            "node-b",
            MemoryEdgeKind::Contradicts,
            MemoryGraphStyle::ContradictionSupersessionGraph,
        );
        let contradicted_assessment = assess_edge(
            &contradicted,
            &source,
            &target,
            &BTreeMap::new(),
            &DiagnosticEvidenceContext::default(),
        );
        assert_eq!(contradicted_assessment.contradiction_risk_bp, 10_000);
        assert_eq!(
            contradicted_assessment.recommended_action,
            GraphRefinementAction::Supersede
        );
    }

    #[test]
    fn graph_refinement_detects_duplicates_missing_candidates_and_caps() {
        let mut nodes = Vec::new();
        for index in 0..16 {
            nodes.push(node(
                &format!("node-{index:02}"),
                MemoryNodeKind::Summary,
                MemoryGraphStyle::DependencyDag,
            ));
        }
        let no_edge_report = derive_graph_refinement_report(
            &snapshot(nodes, Vec::new()),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        assert_eq!(no_edge_report.missing_edge_candidates.len(), 100);
        assert_eq!(no_edge_report.average_edge_quality_bp, 0);

        let source = node(
            "node-a",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let target = node(
            "node-b",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let duplicate_report = derive_graph_refinement_report(
            &snapshot(
                vec![source, target],
                vec![
                    edge(
                        "edge-a",
                        "node-a",
                        "node-b",
                        MemoryEdgeKind::RelatedTo,
                        MemoryGraphStyle::DependencyDag,
                    ),
                    edge(
                        "edge-b",
                        "node-a",
                        "node-b",
                        MemoryEdgeKind::RelatedTo,
                        MemoryGraphStyle::DependencyDag,
                    ),
                ],
            ),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        assert_eq!(duplicate_report.duplicate_edge_candidate_count, 1);
        assert!(
            duplicate_report
                .recommendations
                .iter()
                .any(|recommendation| recommendation.action == GraphRefinementAction::Merge)
        );
    }

    #[test]
    fn graph_refinement_node_recommendations_cover_hubs_and_isolated_important_nodes() {
        let mut nodes = vec![node(
            "hub",
            MemoryNodeKind::Route,
            MemoryGraphStyle::RoutingViewGraph,
        )];
        let mut edges = Vec::new();
        for index in 0..10 {
            let target_id = format!("target-{index}");
            nodes.push(node(
                &target_id,
                MemoryNodeKind::Summary,
                MemoryGraphStyle::RoutingViewGraph,
            ));
            edges.push(edge(
                &format!("edge-{index}"),
                "hub",
                &target_id,
                MemoryEdgeKind::UsedByRoute,
                MemoryGraphStyle::RoutingViewGraph,
            ));
        }
        nodes.push(node(
            "isolated-decision",
            MemoryNodeKind::Decision,
            MemoryGraphStyle::DependencyDag,
        ));
        let report = derive_graph_refinement_report(
            &snapshot(nodes, edges),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        assert!(
            report
                .node_assessments
                .iter()
                .any(|assessment| assessment.node_id == "hub" && assessment.is_high_degree_hub)
        );
        assert!(report.node_assessments.iter().any(|assessment| {
            assessment.node_id == "isolated-decision" && assessment.is_isolated_important_node
        }));
        assert!(report.recommendations.iter().any(|recommendation| {
            recommendation.group == GraphRefinementRecommendationGroup::SplitOverConnectedHubs
        }));
        assert!(report.recommendations.iter().any(|recommendation| {
            recommendation.group
                == GraphRefinementRecommendationGroup::ConnectIsolatedHighValueNodes
        }));
    }

    #[test]
    fn graph_refinement_recommendation_queue_is_capped_and_advisory() {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        for index in 0..301 {
            let source_id = format!("source-{index:03}");
            let target_id = format!("target-{index:03}");
            nodes.push(node(
                &source_id,
                MemoryNodeKind::Summary,
                MemoryGraphStyle::DependencyDag,
            ));
            nodes.push(node(
                &target_id,
                MemoryNodeKind::Summary,
                MemoryGraphStyle::DependencyDag,
            ));
            edges.push(edge(
                &format!("edge-{index:03}"),
                &source_id,
                &target_id,
                MemoryEdgeKind::RelatedTo,
                MemoryGraphStyle::DependencyDag,
            ));
        }
        let report = derive_graph_refinement_report(
            &snapshot(nodes, edges),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        assert_eq!(report.recommendations.len(), 250);
        assert!(
            report
                .recommendations
                .iter()
                .all(|recommendation| recommendation.writeback_status
                    == GraphRefinementWritebackStatus::AdvisoryOnly)
        );
    }

    #[test]
    fn graph_refinement_helper_branch_vectors() {
        assert_eq!(
            [
                MemoryGraphStyle::ProvenanceReceiptDag,
                MemoryGraphStyle::CanonicalMemoryGraph,
                MemoryGraphStyle::SemanticCatalogGraph,
                MemoryGraphStyle::SimilarityOverlayGraph,
                MemoryGraphStyle::DependencyDag,
                MemoryGraphStyle::RoutingViewGraph,
                MemoryGraphStyle::ContradictionSupersessionGraph,
                MemoryGraphStyle::ContextPacketGraph,
            ]
            .into_iter()
            .map(graph_style_key)
            .collect::<Vec<_>>(),
            vec![
                "provenance_receipt_dag",
                "canonical_memory_graph",
                "semantic_catalog_graph",
                "similarity_overlay_graph",
                "dependency_dag",
                "routing_view_graph",
                "contradiction_supersession_graph",
                "context_packet_graph",
            ]
        );
        assert_eq!(
            [
                MemoryEdgeKind::DerivedFrom,
                MemoryEdgeKind::Summarizes,
                MemoryEdgeKind::Supports,
                MemoryEdgeKind::Contradicts,
                MemoryEdgeKind::Supersedes,
                MemoryEdgeKind::Replaces,
                MemoryEdgeKind::DuplicateOf,
                MemoryEdgeKind::NearDuplicateOf,
                MemoryEdgeKind::RelatedTo,
                MemoryEdgeKind::AlternativeSummaryOf,
                MemoryEdgeKind::DependsOn,
                MemoryEdgeKind::PartOf,
                MemoryEdgeKind::OwnedBy,
                MemoryEdgeKind::AccessGrantedBy,
                MemoryEdgeKind::VerifiedBy,
                MemoryEdgeKind::UsedByRoute,
                MemoryEdgeKind::IncludedInContextPacket,
                MemoryEdgeKind::RevokedBy,
            ]
            .into_iter()
            .map(edge_kind_key)
            .collect::<Vec<_>>(),
            vec![
                "derived_from",
                "summarizes",
                "supports",
                "contradicts",
                "supersedes",
                "replaces",
                "duplicate_of",
                "near_duplicate_of",
                "related_to",
                "alternative_summary_of",
                "depends_on",
                "part_of",
                "owned_by",
                "access_granted_by",
                "verified_by",
                "used_by_route",
                "included_in_context_packet",
                "revoked_by",
            ]
        );
        assert_eq!(list_label(&[]), "none");
        assert_eq!(list_label(&["a".into(), "b".into()]), "a, b");
        assert_eq!(usize_to_u32_saturating(usize::MAX), u32::MAX);
        assert_eq!(u32_to_u16_saturating(u32::MAX), u16::MAX);
        assert_eq!(capped_add_bp(9500, 900), 10_000);
        assert_eq!(
            sha256_bytes_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_bytes_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(
            repo_relative(&repo_root_path().join(GRAPH_REFINEMENT_REPORT_PATH))
                .ends_with(GRAPH_REFINEMENT_REPORT_PATH)
        );
        assert!(validate_graph_refinement_dataset_id("most-recent"));
        assert!(validate_graph_refinement_dataset_id("run_01.snapshot"));
        assert!(validate_graph_refinement_dataset_id(&"a".repeat(80)));
        assert!(!validate_graph_refinement_dataset_id(""));
        assert!(!validate_graph_refinement_dataset_id("-most-recent"));
        assert!(!validate_graph_refinement_dataset_id("Most-Recent"));
        assert!(!validate_graph_refinement_dataset_id("most/recent"));
        assert!(!validate_graph_refinement_dataset_id("most\\recent"));
        assert!(!validate_graph_refinement_dataset_id(&"a".repeat(81)));
        assert_eq!(
            parse_graph_refinement_dataset_id(" most-recent ".into()).expect("dataset id"),
            "most-recent"
        );
        assert!(matches!(
            parse_graph_refinement_dataset_id("Most Recent".into()),
            Err(GraphExplorerError::InvalidDatasetId { .. })
        ));
    }

    #[test]
    fn graph_refinement_dataset_artifact_branch_vectors() {
        let _guard = GRAPH_EXPLORER_TARGET_LOCK
            .lock()
            .expect("target artifact lock should not be poisoned");
        let root = reset_refinement_test_dir("dataset-artifact-branches-root");
        let dataset_dir = root.join("dataset");
        fs::create_dir_all(&dataset_dir).expect("create dataset fixture dir");

        assert!(
            derive_dataset_graph_refinement_report(&root, &dataset_dir)
                .expect("missing dataset report")
                .is_none()
        );

        fs::write(dataset_dir.join("snapshot.json"), b"{").expect("write malformed snapshot");
        assert!(matches!(
            derive_dataset_graph_refinement_report(&root, &dataset_dir),
            Err(GraphExplorerError::Serialization { .. })
        ));

        let mut source = node(
            "source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let mut target = node(
            "target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        source.catalog_path = vec!["source-catalog".into()];
        target.catalog_path = vec!["target-catalog".into()];
        fs::write(
            dataset_dir.join("snapshot.json"),
            json_body(&snapshot(
                vec![source.clone(), target.clone()],
                vec![edge(
                    "edge",
                    "source",
                    "target",
                    MemoryEdgeKind::RelatedTo,
                    MemoryGraphStyle::DependencyDag,
                )],
            ))
            .expect("snapshot json"),
        )
        .expect("write valid snapshot");

        let report_without_inspector = derive_dataset_graph_refinement_report(&root, &dataset_dir)
            .expect("derive without inspector")
            .expect("report without inspector");
        assert_eq!(report_without_inspector.assessed_edge_count, 1);
        assert_eq!(
            report_without_inspector.edge_assessments[0].evidence_strength_bp,
            0
        );

        let inspector = BTreeMap::from([(source.node_id.clone(), empty_details(source))]);
        fs::write(
            dataset_dir.join("node_inspector_details.json"),
            json_body(&inspector).expect("inspector json"),
        )
        .expect("write inspector");
        let report_with_inspector = derive_dataset_graph_refinement_report(&root, &dataset_dir)
            .expect("derive with inspector")
            .expect("report with inspector");
        assert_eq!(report_with_inspector.assessed_node_count, 2);
        assert!(
            report_with_inspector
                .artifact_references
                .iter()
                .any(|reference| reference.ends_with("node_inspector_details.json"))
        );
    }

    #[test]
    fn graph_refinement_dataset_writer_branch_vectors() {
        let root = repo_root_path();
        let target_dir = reset_refinement_test_dir("dataset-writer-branches");
        let report = empty_graph_refinement_report(&snapshot(Vec::new(), Vec::new()));

        write_dataset_graph_refinement_artifacts_if_requested(&root, &target_dir, &report, None)
            .expect("skip dataset write");
        assert!(!target_dir.join("datasets").exists());

        write_dataset_graph_refinement_artifacts_if_requested(
            &root,
            &target_dir,
            &report,
            Some("coverage-dataset".into()),
        )
        .expect("write dataset fallback report");
        assert!(
            target_dir
                .join("datasets")
                .join("coverage-dataset")
                .join("refinement_report.json")
                .exists()
        );
        assert!(
            target_dir
                .join("datasets")
                .join("coverage-dataset")
                .join("refinement_summary.md")
                .exists()
        );
    }

    #[test]
    fn graph_refinement_scoring_branch_vectors_cover_absent_and_partial_evidence() {
        let mut source = node(
            "source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let mut target = node(
            "target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        source.catalog_path = vec!["left".into()];
        target.catalog_path = vec!["right".into()];
        source.source_hash = Some("abc".into());
        target.source_hash = Some("abcdefghi".into());
        let plain = edge(
            "plain",
            "source",
            "target",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        assert_eq!(
            evidence_strength(&plain, &source, &target, &BTreeMap::new()),
            0
        );
        assert_eq!(
            routing_usefulness(&plain, &source, &target, &BTreeMap::new()),
            0
        );
        assert!(!shares_catalog_or_hash_prefix(&source, &target));
        assert_eq!(
            edge_supporting_artifacts(&plain, &EdgeDiagnosticEvidence::default()).len(),
            1
        );
        assert!(edge_weakening_artifacts(0, 0).is_empty());

        target.source_hash = Some("abc999999999".into());
        assert!(!shares_catalog_or_hash_prefix(&source, &target));
        source.source_hash = Some("abc9999999990000".into());
        assert!(shares_catalog_or_hash_prefix(&source, &target));

        let mut routed = edge(
            "routed",
            "source",
            "target",
            MemoryEdgeKind::UsedByRoute,
            MemoryGraphStyle::ContextPacketGraph,
        );
        routed.receipt_id = Some("receipt".into());
        source.node_kind = MemoryNodeKind::Route;
        let mut details = empty_details(source.clone());
        details.routes.push("source target".into());
        let route_only = BTreeMap::from([(source.node_id.clone(), details.clone())]);
        assert!(inspector_references_edge_endpoints(&routed, &route_only));
        details.routes.clear();
        details.context_packets.push("routed".into());
        let context_only = BTreeMap::from([(source.node_id.clone(), details.clone())]);
        assert!(inspector_references_edge_endpoints(&routed, &context_only));
        details.context_packets.clear();
        details.edge_details.push(routed.clone());
        let edge_detail_only = BTreeMap::from([(target.node_id.clone(), details.clone())]);
        assert!(inspector_references_edge_endpoints(
            &routed,
            &edge_detail_only
        ));
        details.edge_details.clear();
        details.validation_reports.push("validated".into());
        let validation_only = BTreeMap::from([(source.node_id.clone(), details)]);
        assert_eq!(
            routing_usefulness(&routed, &source, &target, &validation_only),
            5500
        );
        assert_eq!(
            edge_supporting_artifacts(&routed, &EdgeDiagnosticEvidence::default()),
            vec![
                GRAPH_EXPLORER_SNAPSHOT_PATH.to_string(),
                GRAPH_EXPLORER_INSPECTOR_PATH.to_string()
            ]
        );
    }

    #[test]
    fn graph_refinement_risk_and_queue_branch_vectors_cover_remaining_actions() {
        let mut source = node(
            "source",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let mut target = node(
            "target",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let plain = edge(
            "plain",
            "source",
            "target",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        source.status = GraphExplorerNodeStatus::Contradicted;
        assert_eq!(contradiction_risk(&plain, &source, &target), 8000);
        source.status = GraphExplorerNodeStatus::Active;
        target.status = GraphExplorerNodeStatus::Contradicted;
        assert_eq!(contradiction_risk(&plain, &source, &target), 8000);
        target.status = GraphExplorerNodeStatus::Superseded;
        assert_eq!(staleness_risk(&plain, &source, &target), 7000);
        target.status = GraphExplorerNodeStatus::Duplicate;
        assert_eq!(staleness_risk(&plain, &source, &target), 5000);
        target.status = GraphExplorerNodeStatus::Active;

        let mut stale_edge = plain.clone();
        stale_edge.status = GraphExplorerEdgeStatus::Stale;
        assert_eq!(staleness_risk(&stale_edge, &source, &target), 9000);
        stale_edge.status = GraphExplorerEdgeStatus::Revoked;
        assert_eq!(staleness_risk(&stale_edge, &source, &target), 9000);

        let mut assessments = Vec::new();
        for (index, action) in [
            GraphRefinementAction::Weaken,
            GraphRefinementAction::Hide,
            GraphRefinementAction::Merge,
            GraphRefinementAction::Split,
        ]
        .into_iter()
        .enumerate()
        {
            assessments.push(EdgeRefinementAssessment {
                edge_id: format!("edge-{index}"),
                source_node_id: "source".into(),
                target_node_id: "target".into(),
                edge_kind: "related_to".into(),
                graph_style: "dependency_dag".into(),
                edge_quality_score_bp: 1000,
                evidence_strength_bp: 0,
                contradiction_risk_bp: 0,
                staleness_risk_bp: 0,
                routing_usefulness_bp: 0,
                confidence_reason: "branch vector".into(),
                recommended_action: action,
                supporting_artifact_references: Vec::new(),
                weakening_artifact_references: Vec::new(),
                evidence_level: EdgeEvidenceLevel::Unavailable,
                task_usage_count: 0,
                matched_task_ids: Vec::new(),
                matched_diagnostic_labels: Vec::new(),
                avg_quality_bp: 0,
                avg_citation_accuracy_bp: 0,
                avg_unsupported_claim_rate_bp: 0,
                quality_delta_vs_neutral_bp: 0,
                citation_delta_vs_neutral_bp: 0,
                unsupported_delta_vs_neutral_bp: 0,
                cost_delta_vs_neutral_micro_exo: 0,
                diagnostic_impact_bp: 0,
                evidence_summary: "Evidence unavailable".into(),
            });
        }
        let recommendations = edge_recommendations(&assessments);
        assert!(recommendations.iter().any(|recommendation| {
            recommendation.group == GraphRefinementRecommendationGroup::HideNoisyEdges
        }));
        assert!(recommendations.iter().any(|recommendation| {
            recommendation.group == GraphRefinementRecommendationGroup::MergeDuplicateEdges
        }));
        assert!(recommendations.iter().any(|recommendation| {
            recommendation.group == GraphRefinementRecommendationGroup::SplitOverConnectedHubs
        }));
        assert!(
            duplicate_recommendations(&[DuplicateEdgeCandidate {
                candidate_id: "weak-duplicate".into(),
                edge_ids: vec!["edge-a".into(), "edge-b".into()],
                confidence_bp: 7000,
                reason: "below threshold".into(),
            }])
            .is_empty()
        );
    }

    #[test]
    fn graph_refinement_generation_branches_cover_filesystem_inputs() {
        let _guard = GRAPH_EXPLORER_TARGET_LOCK
            .lock()
            .expect("target artifact lock should not be poisoned");
        let root = repo_root_path();
        let paths = [
            root.join(GRAPH_EXPLORER_SNAPSHOT_PATH),
            root.join(GRAPH_EXPLORER_INSPECTOR_PATH),
            root.join(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH),
            root.join(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH),
            root.join(GRAPH_REFINEMENT_REPORT_PATH),
            root.join(GRAPH_REFINEMENT_SUMMARY_PATH),
        ];
        let backups = paths
            .iter()
            .map(|path| (path.clone(), fs::read(path).ok()))
            .collect::<Vec<_>>();
        for path in &paths {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
        }

        let source = node(
            "node-a",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let target = node(
            "node-b",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let snapshot_body = json_body(&snapshot(
            vec![source.clone(), target.clone()],
            vec![edge(
                "edge-a",
                "node-a",
                "node-b",
                MemoryEdgeKind::RelatedTo,
                MemoryGraphStyle::DependencyDag,
            )],
        ))
        .expect("snapshot json");
        fs::write(root.join(GRAPH_EXPLORER_SNAPSHOT_PATH), snapshot_body).expect("write snapshot");
        let inspector = BTreeMap::from([(source.node_id.clone(), empty_details(source))]);
        fs::write(
            root.join(GRAPH_EXPLORER_INSPECTOR_PATH),
            json_body(&inspector).expect("inspector json"),
        )
        .expect("write inspector");
        fs::write(root.join(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH), b"[]")
            .expect("write diagnostics");
        fs::write(root.join(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH), b"{}").expect("write silo");
        let generated = generate_graph_refinement_artifacts().expect("generate refinement");
        assert_eq!(generated.report_hash.len(), 64);
        assert!(generated.report_path.ends_with("refinement_report.json"));

        fs::write(root.join(GRAPH_EXPLORER_SNAPSHOT_PATH), b"{").expect("write malformed snapshot");
        assert!(matches!(
            generate_graph_refinement_artifacts(),
            Err(GraphExplorerError::Serialization { .. })
        ));
        fs::write(
            root.join(GRAPH_EXPLORER_SNAPSHOT_PATH),
            json_body(&snapshot(vec![target], Vec::new())).expect("snapshot json"),
        )
        .expect("write snapshot without optional artifacts");
        let _ = fs::remove_file(root.join(GRAPH_EXPLORER_INSPECTOR_PATH));
        let _ = fs::remove_file(root.join(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH));
        let _ = fs::remove_file(root.join(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH));
        let generated_without_optional =
            generate_graph_refinement_artifacts().expect("generate without optional files");
        assert!(
            generated_without_optional
                .summary_path
                .ends_with("refinement_summary.md")
        );

        for (path, backup) in backups {
            match backup {
                Some(bytes) => fs::write(path, bytes).expect("restore file"),
                None => {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    #[test]
    fn graph_refinement_artifacts_generate_under_target() {
        let _guard = GRAPH_EXPLORER_TARGET_LOCK
            .lock()
            .expect("target artifact lock should not be poisoned");
        let root = repo_root_path();
        if !root.join(GRAPH_EXPLORER_SNAPSHOT_PATH).exists() {
            return;
        }

        let generated = generate_graph_refinement_artifacts().expect("generate refinement");
        assert!(root.join(&generated.report_path).exists());
        assert!(root.join(&generated.summary_path).exists());
        assert_eq!(generated.report_hash.len(), 64);

        if let Ok(dataset_id) = env::var(GRAPH_DATASET_ID_OVERRIDE_ENV)
            && validate_graph_refinement_dataset_id(&dataset_id)
        {
            let dataset_dir = root
                .join(GRAPH_EXPLORER_TARGET_DIR)
                .join("datasets")
                .join(dataset_id);
            assert!(dataset_dir.join("refinement_report.json").exists());
            assert!(dataset_dir.join("refinement_summary.md").exists());
        }
    }

    #[test]
    fn graph_refinement_remaining_boolean_branch_vectors() {
        let mut a = node(
            "a",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let mut b = node(
            "b",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let mut c = node("c", MemoryNodeKind::Raw, MemoryGraphStyle::DependencyDag);
        a.catalog_path = vec![String::new()];
        b.catalog_path = vec![String::new()];
        assert!(!shares_catalog_or_hash_prefix(&a, &b));
        a.catalog_path = vec!["shared".into()];
        b.catalog_path = vec!["shared".into()];
        assert!(shares_catalog_or_hash_prefix(&a, &b));
        c.catalog_path = vec!["other".into()];

        let ab = edge(
            "ab",
            "a",
            "b",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        assert!(duplicate_edge_candidates(std::slice::from_ref(&ab)).is_empty());
        assert!(
            missing_edge_candidates(&[a.clone(), b.clone()], std::slice::from_ref(&ab)).is_empty()
        );
        let ba = edge(
            "ba",
            "b",
            "a",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        assert!(missing_edge_candidates(&[a.clone(), b.clone()], &[ba]).is_empty());
        assert!(missing_edge_candidates(&[a.clone(), c.clone()], &[]).is_empty());

        let dangling_source = edge(
            "dangling-source",
            "missing",
            "a",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        let dangling_target = edge(
            "dangling-target",
            "a",
            "missing",
            MemoryEdgeKind::RelatedTo,
            MemoryGraphStyle::DependencyDag,
        );
        let assessed = node_assessments(&[a.clone()], &[dangling_source, dangling_target]);
        assert_eq!(assessed[0].visible_degree, 2);
        assert!(!assessed[0].is_high_degree_hub);
        assert!(!assessed[0].is_isolated_important_node);
        assert!(node_recommendations(&mut assessed.clone()).is_empty());
        let dangling_report = derive_graph_refinement_report(
            &snapshot(
                vec![a.clone()],
                vec![edge(
                    "dangling-report-edge",
                    "a",
                    "missing",
                    MemoryEdgeKind::RelatedTo,
                    MemoryGraphStyle::DependencyDag,
                )],
            ),
            &BTreeMap::new(),
            Vec::new(),
        );
        assert_eq!(dangling_report.assessed_edge_count, 0);
        assert_eq!(average_edge_quality(&[]), 0);

        assert!(
            edge_recommendations(&[EdgeRefinementAssessment {
                edge_id: "keep".into(),
                source_node_id: "a".into(),
                target_node_id: "b".into(),
                edge_kind: "related_to".into(),
                graph_style: "dependency_dag".into(),
                edge_quality_score_bp: 9000,
                evidence_strength_bp: 9000,
                contradiction_risk_bp: 0,
                staleness_risk_bp: 0,
                routing_usefulness_bp: 9000,
                confidence_reason: "keep".into(),
                recommended_action: GraphRefinementAction::Keep,
                supporting_artifact_references: Vec::new(),
                weakening_artifact_references: Vec::new(),
                evidence_level: EdgeEvidenceLevel::Unavailable,
                task_usage_count: 0,
                matched_task_ids: Vec::new(),
                matched_diagnostic_labels: Vec::new(),
                avg_quality_bp: 0,
                avg_citation_accuracy_bp: 0,
                avg_unsupported_claim_rate_bp: 0,
                quality_delta_vs_neutral_bp: 0,
                citation_delta_vs_neutral_bp: 0,
                unsupported_delta_vs_neutral_bp: 0,
                cost_delta_vs_neutral_micro_exo: 0,
                diagnostic_impact_bp: 0,
                evidence_summary: "Evidence unavailable".into(),
            }])
            .is_empty()
        );

        let mut route_target = b.clone();
        route_target.node_kind = MemoryNodeKind::Route;
        let route_edge = edge(
            "route-edge",
            "a",
            "b",
            MemoryEdgeKind::UsedByRoute,
            MemoryGraphStyle::RoutingViewGraph,
        );
        let mut details = empty_details(route_target.clone());
        details.context_packets.push("packet".into());
        details.validation_reports.push("report".into());
        let inspector = BTreeMap::from([(route_target.node_id.clone(), details)]);
        assert_eq!(
            routing_usefulness(&route_edge, &a, &route_target, &inspector),
            7500
        );
        assert!(contains_endpoint_reference(&["only a".into()], &route_edge));
        assert!(contains_endpoint_reference(&["only b".into()], &route_edge));
        assert!(!contains_endpoint_reference(&["zzz".into()], &route_edge));

        let mut contradiction_source = a.clone();
        contradiction_source.status = GraphExplorerNodeStatus::Contradicted;
        let contradiction_edge = edge(
            "contradiction",
            "a",
            "b",
            MemoryEdgeKind::Contradicts,
            MemoryGraphStyle::ContradictionSupersessionGraph,
        );
        assert_eq!(
            contradiction_risk(&contradiction_edge, &contradiction_source, &b),
            10_000
        );
        let mut duplicate_source = a.clone();
        duplicate_source.status = GraphExplorerNodeStatus::Duplicate;
        assert_eq!(staleness_risk(&ab, &duplicate_source, &b), 5000);
        let mut superseded_source = a.clone();
        superseded_source.status = GraphExplorerNodeStatus::Superseded;
        assert_eq!(staleness_risk(&ab, &superseded_source, &b), 7000);
        assert_eq!(
            recommended_edge_action(4000, 0, 0),
            GraphRefinementAction::Review
        );
        let mut receipt_node = a.clone();
        receipt_node.receipt_ids.push("receipt".into());
        assert!(is_important_node(&receipt_node));
        assert_eq!(average_diagnostic_impact_bp(&[]), 0);
    }

    #[test]
    fn graph_refinement_writer_reports_io_errors_and_summary_omits_connection_material() {
        let source = node(
            "node-a",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let target = node(
            "node-b",
            MemoryNodeKind::Summary,
            MemoryGraphStyle::DependencyDag,
        );
        let report = derive_graph_refinement_report(
            &snapshot(
                vec![source, target],
                vec![edge(
                    "edge-a",
                    "node-a",
                    "node-b",
                    MemoryEdgeKind::RelatedTo,
                    MemoryGraphStyle::DependencyDag,
                )],
            ),
            &BTreeMap::new(),
            vec![GRAPH_EXPLORER_SNAPSHOT_PATH.into()],
        );
        let summary = graph_refinement_summary_markdown(&report);
        assert!(summary.contains("advisory_only: true"));
        assert!(summary.contains("No source DAG records are changed"));
        assert!(!summary.contains("postgres://"));
        assert!(!summary.contains("DATABASE_URL"));
        assert!(!summary.contains("password"));

        let file_path = repo_root_path()
            .join("target")
            .join("dagdb")
            .join("graph_explorer")
            .join("refinement-error-target");
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(&file_path, b"not-a-directory").expect("write blocking file");
        let result = write_graph_refinement_artifacts(&report, &file_path);
        fs::remove_file(&file_path).expect("remove blocking file");
        assert!(matches!(result, Err(GraphExplorerError::Io { .. })));

        let target_dir = repo_root_path()
            .join("target")
            .join("dagdb")
            .join("graph_explorer")
            .join("worklist-writer-test");
        let generated =
            write_graph_refinement_artifacts(&report, &target_dir).expect("write worklist files");
        assert!(generated.report_path.ends_with("refinement_report.json"));
        assert!(target_dir.join("evidence_closure_worklist.json").exists());
        assert!(target_dir.join("evidence_closure_worklist.md").exists());
    }
}

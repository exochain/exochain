//! Read-only graph explorer contracts and deterministic report-file artifacts.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use exo_dag_db_api::{MemoryEdgeKind, MemoryGraphStyle, MemoryNodeKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    graph::{MemoryGraphEdge, MemoryGraphNode},
    scoring::{DomainError, DomainResult, hash_event_body},
};

pub const GRAPH_EXPLORER_SCHEMA_VERSION: &str = "dagdb_graph_explorer_snapshot_v1";
pub const GRAPH_EXPLORER_TARGET_DIR: &str = "target/dagdb/graph_explorer";
pub const GRAPH_EXPLORER_SNAPSHOT_PATH: &str = "target/dagdb/graph_explorer/snapshot.json";
pub const GRAPH_EXPLORER_INSPECTOR_PATH: &str =
    "target/dagdb/graph_explorer/node_inspector_details.json";
pub const GRAPH_EXPLORER_SUMMARY_PATH: &str =
    "target/dagdb/graph_explorer/graph_explorer_summary.md";
pub const GRAPH_EXPLORER_INDEX_PATH: &str = "target/dagdb/graph_explorer/index.json";
pub const GRAPH_EXPLORER_DATASETS_DIR: &str = "target/dagdb/graph_explorer/datasets";
pub const GRAPH_EXPLORER_DATASET_INDEX_SCHEMA_VERSION: &str =
    "dagdb_graph_explorer_dataset_index_v1";
pub const GRAPH_EXPLORER_DATASET_BUNDLE_HASH_SCHEMA_VERSION: &str =
    "dagdb_graph_explorer_dataset_bundle_hash_v1";
pub const GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH: &str =
    "target/dagdb/end_to_end_diagnostics/per_task_results.json";
pub const GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH: &str =
    "target/dagdb/benchmark_isolation/silo_config_summary.json";
pub const GRAPH_DATASET_ID_OVERRIDE_ENV: &str = "EXO_DAGDB_GRAPH_DATASET_ID_OVERRIDE";
pub const GRAPH_SOURCE_RUN_ID_OVERRIDE_ENV: &str = "EXO_DAGDB_GRAPH_SOURCE_RUN_ID_OVERRIDE";
pub const LIVE_EXPORT_APPROVAL_ENV: &str = "EXO_DAGDB_GRAPH_EXPLORER_LIVE_EXPORT_APPROVED";
pub const RAW_PREVIEW_APPROVAL_ENV: &str = "EXO_DAGDB_GRAPH_EXPLORER_RAW_PREVIEW_APPROVED";
pub const GRAPH_EXPLORER_DATABASE_URL_ENV: &str = "EXO_DAGDB_MAIN_DATABASE_URL";
pub const GRAPH_EXPLORER_LIMIT_WARNING: &str = "graph_explorer_limit_applied";
pub const GRAPH_EXPORT_NOT_AVAILABLE: &str = "graph_export_not_available";
pub const GRAPH_EXPLORER_DATABASE_CONNECTION_FAILED: &str =
    "graph_explorer_database_connection_failed";
pub const GRAPH_EXPLORER_LIVE_EXPORT_BLOCKED_MISSING_ENV: &str =
    "graph_explorer_live_export_blocked_missing_env";
pub const GRAPH_EXPLORER_LIVE_EXPORT_BLOCKED_MISSING_APPROVAL: &str =
    "graph_explorer_live_export_blocked_missing_approval";
pub const GRAPH_EXPLORER_LIVE_EXPORT_FAILED_SCHEMA_MISMATCH: &str =
    "graph_explorer_live_export_failed_schema_mismatch";
pub const GRAPH_EXPLORER_MAX_NODE_ROWS_READ: u16 = 500;
pub const GRAPH_EXPLORER_MAX_EDGE_ROWS_READ: u16 = 1000;
pub const GRAPH_EXPLORER_MAX_GRAPH_VIEW_ROWS_READ: u16 = 100;

static ARTIFACT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) static GRAPH_EXPLORER_TARGET_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GraphExplorerError {
    #[error("graph_explorer_live_export_blocked_missing_approval")]
    LiveExportNotApproved,
    #[error("graph_explorer_live_export_blocked_missing_env")]
    LiveExportDatabaseUrlMissing,
    #[error("graph_explorer_live_export_tenant_id_missing")]
    LiveExportTenantIdMissing,
    #[error("graph_explorer_live_export_namespace_missing")]
    LiveExportNamespaceMissing,
    #[error("graph_explorer_database_connection_failed")]
    DatabaseConnectionFailed,
    #[error("graph_explorer_live_export_failed_schema_mismatch")]
    SchemaMismatch,
    #[error("graph_explorer_invalid_source_row: {reason}")]
    InvalidSourceRow { reason: String },
    #[error("graph_explorer_missing_edge_endpoint: {edge_id}")]
    MissingEdgeEndpoint { edge_id: String },
    #[error("graph_explorer_invalid_dataset_id: {dataset_id}")]
    InvalidDatasetId { dataset_id: String },
    #[error("graph_explorer_io_error")]
    Io { reason: String },
    #[error("graph_explorer_serialization_error")]
    Serialization { reason: String },
}

impl From<GraphExplorerError> for DomainError {
    fn from(error: GraphExplorerError) -> Self {
        Self::HashMaterial {
            reason: error.to_string(),
        }
    }
}

#[must_use]
pub const fn graph_explorer_error_code(error: &GraphExplorerError) -> &'static str {
    match error {
        GraphExplorerError::LiveExportNotApproved => {
            GRAPH_EXPLORER_LIVE_EXPORT_BLOCKED_MISSING_APPROVAL
        }
        GraphExplorerError::LiveExportDatabaseUrlMissing => {
            GRAPH_EXPLORER_LIVE_EXPORT_BLOCKED_MISSING_ENV
        }
        GraphExplorerError::LiveExportTenantIdMissing
        | GraphExplorerError::LiveExportNamespaceMissing => {
            "graph_explorer_live_export_blocked_missing_tenant_namespace"
        }
        GraphExplorerError::DatabaseConnectionFailed => GRAPH_EXPLORER_DATABASE_CONNECTION_FAILED,
        GraphExplorerError::SchemaMismatch => GRAPH_EXPLORER_LIVE_EXPORT_FAILED_SCHEMA_MISMATCH,
        GraphExplorerError::InvalidSourceRow { .. } => "graph_explorer_invalid_source_row",
        GraphExplorerError::MissingEdgeEndpoint { .. } => "graph_explorer_missing_edge_endpoint",
        GraphExplorerError::InvalidDatasetId { .. } => "graph_explorer_invalid_dataset_id",
        GraphExplorerError::Io { .. } => "graph_explorer_io_error",
        GraphExplorerError::Serialization { .. } => "graph_explorer_serialization_error",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphSourceTruthLevel {
    ActualStoredDag,
    ApprovedReadOnlyGraphView,
    GeneratedGraphArtifact,
    DiagnosticContextPacketArtifact,
    ConceptualUnavailableFallback,
    ApprovedLiveExportEmptyScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerExportResultStatus {
    GeneratedRealGraphArtifact,
    GeneratedEmptyScopedGraphArtifact,
    GeneratedUnavailableArtifact,
    BlockedMissingApproval,
    BlockedMissingEnv,
    BlockedMissingTenantNamespace,
    FailedSchemaMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerGeneratedFrom {
    GraphRecords,
    GraphView,
    DiagnosticArtifact,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerGenerationMode {
    ReportFileArtifact,
    ApprovedReadOnlyLiveExport,
    UnavailableConceptualFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerSourceMode {
    GeneratedGraphArtifact,
    ApprovedReadOnlyLiveExport,
    UnavailableConceptualFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerNodeStatus {
    Active,
    Canonical,
    Duplicate,
    Superseded,
    Contradicted,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerEdgeStatus {
    Active,
    Tombstoned,
    Stale,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerEdgeDirection {
    SourceToTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerClusterType {
    CatalogDomain,
    NodeType,
    GraphStyle,
    RiskClass,
    RouteCluster,
    DependencyRegion,
    SourceLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerDrilldownMode {
    Overview,
    Neighborhood,
    Subdag,
    Provenance,
    Dependencies,
    Routes,
    ContextPackets,
    ContradictionsSupersessions,
    RawDetails,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawContentUnavailableReason {
    HashOnlyMemory,
    PrivatePayloadNotExposed,
    ContentStoredOffDag,
    PermissionDenied,
    ArtifactUnavailable,
    BinaryPreviewNotSupported,
    PreviewSizeLimitApplied,
    RawPreviewNotApproved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExplorerContentKind {
    RawContent,
    Summary,
    Metadata,
    Receipt,
    HashOnlyReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerLimits {
    pub max_nodes: u16,
    pub max_edges: u16,
    pub max_clusters: u16,
    pub max_label_chars: u16,
    pub max_metadata_items_per_node: u16,
    pub default_neighborhood_depth: u8,
    pub max_nodes_per_expansion: u16,
    pub max_edges_per_expansion: u16,
    pub max_depth_without_confirmation: u8,
    pub max_preview_bytes: u16,
    pub max_preview_lines: u16,
}

impl Default for GraphExplorerLimits {
    fn default() -> Self {
        Self {
            max_nodes: 500,
            max_edges: 1000,
            max_clusters: 100,
            max_label_chars: 64,
            max_metadata_items_per_node: 12,
            default_neighborhood_depth: 1,
            max_nodes_per_expansion: 250,
            max_edges_per_expansion: 500,
            max_depth_without_confirmation: 2,
            max_preview_bytes: 4096,
            max_preview_lines: 120,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerPermissions {
    pub raw_content_allowed: bool,
    pub private_payloads_allowed: bool,
    pub live_db_export_allowed: bool,
    pub raw_preview_env_approved: bool,
    pub source_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerNode {
    pub node_id: String,
    pub label: String,
    pub node_kind: MemoryNodeKind,
    pub graph_style: MemoryGraphStyle,
    pub catalog_path: Vec<String>,
    pub status: GraphExplorerNodeStatus,
    pub risk_class: Option<String>,
    pub owner_id: Option<String>,
    pub receipt_ids: Vec<String>,
    pub source_hash: Option<String>,
    pub content_hash: Option<String>,
    pub raw_content_allowed: bool,
    pub browser_safe_payload: bool,
    pub has_raw_content: bool,
    pub has_children: bool,
    pub child_count: u32,
    pub parent_count: u32,
    pub metadata_summary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerEdge {
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_kind: MemoryEdgeKind,
    pub graph_style: MemoryGraphStyle,
    pub receipt_id: Option<String>,
    pub status: GraphExplorerEdgeStatus,
    pub confidence_bp: Option<u16>,
    pub direction: GraphExplorerEdgeDirection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerCluster {
    pub cluster_id: String,
    pub label: String,
    pub cluster_type: GraphExplorerClusterType,
    pub graph_style: MemoryGraphStyle,
    pub node_ids: Vec<String>,
    pub count: u32,
    pub color_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerSummaries {
    pub displayed_node_count: u32,
    pub total_known_node_count: Option<u32>,
    pub displayed_edge_count: u32,
    pub total_known_edge_count: Option<u32>,
    pub displayed_cluster_count: u32,
    pub total_known_cluster_count: Option<u32>,
    pub limit_applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerDrilldownState {
    pub breadcrumb: Vec<String>,
    pub root_node_id: Option<String>,
    pub focused_node_id: Option<String>,
    pub active_graph_style: MemoryGraphStyle,
    pub depth: u8,
    pub mode: GraphExplorerDrilldownMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerRawContentPreview {
    pub content_kind: GraphExplorerContentKind,
    pub preview_text: Option<String>,
    pub preview_bytes: u16,
    pub preview_lines: u16,
    pub truncated: bool,
    pub binary_metadata_only: bool,
    pub unavailable_reason: Option<RawContentUnavailableReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInspectorDetails {
    pub node: GraphExplorerNode,
    pub parents: Vec<GraphExplorerNode>,
    pub children: Vec<GraphExplorerNode>,
    pub dependencies: Vec<GraphExplorerNode>,
    pub evidence: Vec<String>,
    pub receipts: Vec<String>,
    pub routes: Vec<String>,
    pub context_packets: Vec<String>,
    pub contradictions: Vec<String>,
    pub supersessions: Vec<String>,
    pub validation_reports: Vec<String>,
    pub edge_details: Vec<GraphExplorerEdge>,
    pub raw_content_preview_if_allowed: Option<GraphExplorerRawContentPreview>,
    pub raw_content_unavailable_reason: Option<RawContentUnavailableReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerSnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    pub generated_from: GraphExplorerGeneratedFrom,
    pub generation_mode: GraphExplorerGenerationMode,
    pub export_result_status: GraphExplorerExportResultStatus,
    pub source_truth_level: GraphSourceTruthLevel,
    pub source_mode: GraphExplorerSourceMode,
    pub source_description: String,
    pub source_artifact_paths: Vec<String>,
    pub source_receipt_ids: Vec<String>,
    pub source_graph_view_ids: Vec<String>,
    pub source_commit_or_run_id: Option<String>,
    pub source_is_live_db_export: bool,
    pub source_is_generated_artifact: bool,
    pub artifact_hash: Option<String>,
    pub source_artifact_hashes: BTreeMap<String, String>,
    pub source_graph_view_hashes: BTreeMap<String, String>,
    pub source_receipt_hashes: BTreeMap<String, String>,
    pub schema_inventory_hash: Option<String>,
    pub source_column_set_hash: Option<String>,
    pub source_table_names: Vec<String>,
    pub query_scope_tenant_id: Option<String>,
    pub query_scope_namespace: Option<String>,
    pub displayed_node_count: u32,
    pub total_scoped_node_count: Option<u32>,
    pub displayed_edge_count: u32,
    pub total_scoped_edge_count: Option<u32>,
    pub dropped_edge_count: u32,
    pub limit_applied: bool,
    pub source_unavailable_reason: Option<String>,
    pub graph_export_not_available: bool,
    pub tenant_id: Option<String>,
    pub namespace: Option<String>,
    pub graph_styles_available: Vec<MemoryGraphStyle>,
    pub active_graph_style: MemoryGraphStyle,
    pub root_node_ids: Vec<String>,
    pub nodes: Vec<GraphExplorerNode>,
    pub edges: Vec<GraphExplorerEdge>,
    pub clusters: Vec<GraphExplorerCluster>,
    pub summaries: GraphExplorerSummaries,
    pub permissions: GraphExplorerPermissions,
    pub limits: GraphExplorerLimits,
    pub drilldown: GraphExplorerDrilldownState,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphExplorerExportInput {
    pub tenant_id: Option<String>,
    pub namespace: Option<String>,
    pub active_graph_style: MemoryGraphStyle,
    pub source_truth_level: GraphSourceTruthLevel,
    pub source_commit_or_run_id: Option<String>,
    pub nodes: Vec<MemoryGraphNode>,
    pub edges: Vec<MemoryGraphEdge>,
    pub source_graph_view_ids: Vec<String>,
    pub source_receipt_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphExplorerSourceNode {
    pub node_id: String,
    pub label: String,
    pub node_kind: MemoryNodeKind,
    pub graph_style: MemoryGraphStyle,
    pub catalog_path: Vec<String>,
    pub status: GraphExplorerNodeStatus,
    pub risk_class: Option<String>,
    pub owner_id: Option<String>,
    pub receipt_ids: Vec<String>,
    pub source_hash: Option<String>,
    pub content_hash: Option<String>,
    pub metadata_summary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphExplorerSourceEdge {
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_kind: MemoryEdgeKind,
    pub graph_style: MemoryGraphStyle,
    pub receipt_id: Option<String>,
    pub status: GraphExplorerEdgeStatus,
    pub confidence_bp: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveGraphExportRequest<'a> {
    pub env: &'a BTreeMap<String, String>,
    pub tenant_id: Option<&'a str>,
    pub namespace: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphExplorerRawContentPreviewRequest<'a> {
    pub env: &'a BTreeMap<String, String>,
    pub raw_content_allowed: bool,
    pub browser_safe_payload: bool,
    pub private_payload: bool,
    pub binary_content: bool,
    pub content_kind: GraphExplorerContentKind,
    pub content: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerArtifactSet {
    pub snapshot_path: String,
    pub inspector_path: String,
    pub summary_path: String,
    pub snapshot_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerDatasetIndex {
    pub schema_version: String,
    pub default_dataset_id: Option<String>,
    pub datasets: Vec<GraphExplorerDatasetRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerDatasetRecord {
    pub dataset_id: String,
    pub label: String,
    pub created_order_key: String,
    pub artifact_paths: GraphExplorerDatasetArtifactPaths,
    pub snapshot_id: String,
    pub source_truth_level: GraphSourceTruthLevel,
    pub export_result_status: GraphExplorerExportResultStatus,
    pub node_count: u32,
    pub edge_count: u32,
    pub cluster_count: u32,
    pub warning_count: u32,
    pub limit_applied: bool,
    pub artifact_hash: String,
    pub artifact_hashes: GraphExplorerDatasetArtifactHashes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerDatasetArtifactPaths {
    pub snapshot: String,
    pub inspector: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplorerDatasetArtifactHashes {
    pub snapshot: String,
    pub inspector: String,
    pub summary: String,
}

#[derive(Debug, Serialize)]
struct GraphExplorerDatasetBundleHashInput {
    schema_version: &'static str,
    artifacts: BTreeMap<&'static str, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DiagnosticGraphTaskRow {
    #[serde(default)]
    fixture_id: String,
    #[serde(default)]
    task_id: String,
    #[serde(default)]
    task_type: String,
    #[serde(default)]
    runner: String,
    #[serde(default)]
    diagnostic_label: String,
    #[serde(default)]
    context_acquisition_profile: String,
    #[serde(default)]
    selected_refs: Option<u32>,
    #[serde(default)]
    route_count: Option<u32>,
    #[serde(default)]
    context_packet_tokens: Option<u32>,
    #[serde(default)]
    quality_score_bp: Option<u16>,
    #[serde(default)]
    citation_accuracy_bp: Option<u16>,
    #[serde(default)]
    unsupported_claim_rate_bp: Option<u16>,
    #[serde(default)]
    latency_ms: Option<u32>,
    #[serde(default)]
    total_cost_micro_exo: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagnosticGraphRunnerAggregate {
    runner: String,
    diagnostic_label: String,
    row_count: u32,
    route_count: u32,
    selected_refs: u32,
    context_packet_tokens: u32,
}

#[must_use]
pub const fn all_graph_styles() -> [MemoryGraphStyle; 8] {
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
}

#[must_use]
pub const fn all_source_truth_levels() -> [GraphSourceTruthLevel; 6] {
    [
        GraphSourceTruthLevel::ActualStoredDag,
        GraphSourceTruthLevel::ApprovedReadOnlyGraphView,
        GraphSourceTruthLevel::GeneratedGraphArtifact,
        GraphSourceTruthLevel::DiagnosticContextPacketArtifact,
        GraphSourceTruthLevel::ConceptualUnavailableFallback,
        GraphSourceTruthLevel::ApprovedLiveExportEmptyScope,
    ]
}

pub fn validate_graph_explorer_source_rows(
    nodes: &[GraphExplorerSourceNode],
    edges: &[GraphExplorerSourceEdge],
) -> Result<(), GraphExplorerError> {
    let mut node_ids = BTreeSet::new();
    for node in nodes {
        if node.node_id.is_empty() {
            return Err(GraphExplorerError::InvalidSourceRow {
                reason: "missing_node_id".into(),
            });
        }
        if node.label.is_empty() {
            return Err(GraphExplorerError::InvalidSourceRow {
                reason: "missing_node_label".into(),
            });
        }
        node_ids.insert(node.node_id.as_str());
    }
    for edge in edges {
        if edge.edge_id.is_empty() {
            return Err(GraphExplorerError::InvalidSourceRow {
                reason: "missing_edge_id".into(),
            });
        }
        if edge.source_node_id.is_empty() || edge.target_node_id.is_empty() {
            return Err(GraphExplorerError::MissingEdgeEndpoint {
                edge_id: edge.edge_id.clone(),
            });
        }
        if !node_ids.contains(edge.source_node_id.as_str())
            || !node_ids.contains(edge.target_node_id.as_str())
        {
            return Err(GraphExplorerError::MissingEdgeEndpoint {
                edge_id: edge.edge_id.clone(),
            });
        }
    }
    Ok(())
}

pub fn validate_live_export_request(
    request: &LiveGraphExportRequest<'_>,
) -> Result<(), GraphExplorerError> {
    if request
        .env
        .get(LIVE_EXPORT_APPROVAL_ENV)
        .map(String::as_str)
        != Some("true")
    {
        return Err(GraphExplorerError::LiveExportNotApproved);
    }
    if request.env.get(GRAPH_EXPLORER_DATABASE_URL_ENV).is_none() {
        return Err(GraphExplorerError::LiveExportDatabaseUrlMissing);
    }
    if request
        .tenant_id
        .filter(|tenant| !tenant.is_empty())
        .is_none()
    {
        return Err(GraphExplorerError::LiveExportTenantIdMissing);
    }
    if request
        .namespace
        .filter(|namespace| !namespace.is_empty())
        .is_none()
    {
        return Err(GraphExplorerError::LiveExportNamespaceMissing);
    }
    Ok(())
}

#[must_use]
pub fn export_result_status_for_error(
    error: &GraphExplorerError,
) -> GraphExplorerExportResultStatus {
    match error {
        GraphExplorerError::LiveExportNotApproved => {
            GraphExplorerExportResultStatus::BlockedMissingApproval
        }
        GraphExplorerError::LiveExportDatabaseUrlMissing => {
            GraphExplorerExportResultStatus::BlockedMissingEnv
        }
        GraphExplorerError::LiveExportTenantIdMissing
        | GraphExplorerError::LiveExportNamespaceMissing => {
            GraphExplorerExportResultStatus::BlockedMissingTenantNamespace
        }
        GraphExplorerError::SchemaMismatch => GraphExplorerExportResultStatus::FailedSchemaMismatch,
        _ => GraphExplorerExportResultStatus::GeneratedUnavailableArtifact,
    }
}

pub fn get_graph_explorer_snapshot(
    input: &GraphExplorerExportInput,
) -> DomainResult<GraphExplorerSnapshot> {
    let mut warnings = Vec::new();
    let limits = GraphExplorerLimits::default();
    let total_known_node_count = usize_to_u32_saturating(input.nodes.len());
    let total_known_edge_count = usize_to_u32_saturating(input.edges.len());
    let limited_nodes = input
        .nodes
        .iter()
        .take(usize::from(limits.max_nodes))
        .copied()
        .collect::<Vec<_>>();
    let visible_ids = limited_nodes
        .iter()
        .map(|node| node.memory_id.to_string())
        .collect::<BTreeSet<_>>();
    let limited_edges = input
        .edges
        .iter()
        .filter(|edge| {
            visible_ids.contains(&edge.from_memory_id.to_string())
                && visible_ids.contains(&edge.to_memory_id.to_string())
        })
        .take(usize::from(limits.max_edges))
        .cloned()
        .collect::<Vec<_>>();
    let limit_applied = input.nodes.len() > usize::from(limits.max_nodes)
        || input.edges.len() > usize::from(limits.max_edges);
    if limit_applied {
        warnings.push(GRAPH_EXPLORER_LIMIT_WARNING.into());
    }

    let nodes = explorer_nodes(&limited_nodes, &limited_edges, &limits);
    let edges = explorer_edges(&limited_edges);
    let clusters = graph_style_clusters(&nodes, &limits);
    let mut root_node_ids = nodes
        .iter()
        .filter(|node| node.parent_count == 0)
        .map(|node| node.node_id.clone())
        .collect::<Vec<_>>();
    root_node_ids.sort();
    let source_truth_level = input.source_truth_level;
    let (generated_from, generation_mode, source_mode, source_description) =
        source_fields(source_truth_level);
    let graph_export_not_available = nodes.is_empty() && edges.is_empty();
    if graph_export_not_available {
        warnings.push(GRAPH_EXPORT_NOT_AVAILABLE.into());
    }
    let summaries = GraphExplorerSummaries {
        displayed_node_count: usize_to_u32_saturating(nodes.len()),
        total_known_node_count: Some(total_known_node_count),
        displayed_edge_count: usize_to_u32_saturating(edges.len()),
        total_known_edge_count: Some(total_known_edge_count),
        displayed_cluster_count: usize_to_u32_saturating(clusters.len()),
        total_known_cluster_count: Some(usize_to_u32_saturating(clusters.len())),
        limit_applied,
    };
    let displayed_node_count = summaries.displayed_node_count;
    let displayed_edge_count = summaries.displayed_edge_count;
    let dropped_edge_count = total_known_edge_count.saturating_sub(displayed_edge_count);
    let permissions = GraphExplorerPermissions {
        raw_content_allowed: false,
        private_payloads_allowed: false,
        live_db_export_allowed: generation_mode
            == GraphExplorerGenerationMode::ApprovedReadOnlyLiveExport,
        raw_preview_env_approved: false,
        source_mode: if generation_mode == GraphExplorerGenerationMode::ApprovedReadOnlyLiveExport {
            "approved_read_only_live_export".into()
        } else {
            "report_file".into()
        },
    };
    let sanitized_source_commit_or_run_id = input
        .source_commit_or_run_id
        .as_deref()
        .map(sanitize_source_commit_or_run_id);
    let mut snapshot = GraphExplorerSnapshot {
        schema_version: GRAPH_EXPLORER_SCHEMA_VERSION.into(),
        snapshot_id: String::new(),
        generated_from,
        generation_mode,
        export_result_status: export_result_status_for(source_truth_level, nodes.len()),
        source_truth_level,
        source_mode,
        source_description,
        source_artifact_paths: vec![
            GRAPH_EXPLORER_SNAPSHOT_PATH.into(),
            GRAPH_EXPLORER_INSPECTOR_PATH.into(),
            GRAPH_EXPLORER_SUMMARY_PATH.into(),
        ],
        source_receipt_ids: sorted(input.source_receipt_ids.clone()),
        source_graph_view_ids: sorted(input.source_graph_view_ids.clone()),
        source_commit_or_run_id: sanitized_source_commit_or_run_id,
        source_is_live_db_export: generation_mode
            == GraphExplorerGenerationMode::ApprovedReadOnlyLiveExport,
        source_is_generated_artifact: generation_mode
            == GraphExplorerGenerationMode::ReportFileArtifact,
        artifact_hash: None,
        source_artifact_hashes: BTreeMap::new(),
        source_graph_view_hashes: BTreeMap::new(),
        source_receipt_hashes: BTreeMap::new(),
        schema_inventory_hash: None,
        source_column_set_hash: None,
        source_table_names: Vec::new(),
        query_scope_tenant_id: input.tenant_id.clone(),
        query_scope_namespace: input.namespace.clone(),
        displayed_node_count,
        total_scoped_node_count: Some(total_known_node_count),
        displayed_edge_count,
        total_scoped_edge_count: Some(total_known_edge_count),
        dropped_edge_count,
        limit_applied,
        source_unavailable_reason: graph_export_not_available
            .then(|| source_unavailable_reason_for(source_truth_level)),
        graph_export_not_available,
        tenant_id: input.tenant_id.clone(),
        namespace: input.namespace.clone(),
        graph_styles_available: all_graph_styles().to_vec(),
        active_graph_style: input.active_graph_style,
        root_node_ids,
        nodes,
        edges,
        clusters,
        summaries,
        permissions,
        limits,
        drilldown: GraphExplorerDrilldownState {
            breadcrumb: vec!["Root Graph".into()],
            root_node_id: None,
            focused_node_id: None,
            active_graph_style: input.active_graph_style,
            depth: 0,
            mode: GraphExplorerDrilldownMode::Overview,
        },
        warnings,
    };
    snapshot.snapshot_id = hash_event_body(&SnapshotIdMaterial {
        generated_from: snapshot.generated_from,
        generation_mode: snapshot.generation_mode,
        source_truth_level: snapshot.source_truth_level,
        source_commit_or_run_id: snapshot.source_commit_or_run_id.as_deref(),
        node_ids: &snapshot
            .nodes
            .iter()
            .map(|node| node.node_id.as_str())
            .collect::<Vec<_>>(),
        edge_ids: &snapshot
            .edges
            .iter()
            .map(|edge| edge.edge_id.as_str())
            .collect::<Vec<_>>(),
    })?
    .to_string();
    snapshot.artifact_hash = Some(hash_event_body(&snapshot)?.to_string());
    Ok(snapshot)
}

pub fn unavailable_graph_explorer_snapshot(
    source_commit_or_run_id: impl Into<String>,
) -> DomainResult<GraphExplorerSnapshot> {
    get_graph_explorer_snapshot(&GraphExplorerExportInput {
        tenant_id: None,
        namespace: None,
        active_graph_style: MemoryGraphStyle::CanonicalMemoryGraph,
        source_truth_level: GraphSourceTruthLevel::ConceptualUnavailableFallback,
        source_commit_or_run_id: Some(source_commit_or_run_id.into()),
        nodes: Vec::new(),
        edges: Vec::new(),
        source_graph_view_ids: Vec::new(),
        source_receipt_ids: Vec::new(),
    })
}

pub fn inspector_details_for_snapshot(
    snapshot: &GraphExplorerSnapshot,
) -> BTreeMap<String, NodeInspectorDetails> {
    snapshot
        .nodes
        .iter()
        .map(|node| {
            (
                node.node_id.clone(),
                NodeInspectorDetails {
                    node: node.clone(),
                    parents: Vec::new(),
                    children: Vec::new(),
                    dependencies: Vec::new(),
                    evidence: Vec::new(),
                    receipts: node.receipt_ids.clone(),
                    routes: Vec::new(),
                    context_packets: Vec::new(),
                    contradictions: Vec::new(),
                    supersessions: Vec::new(),
                    validation_reports: Vec::new(),
                    edge_details: snapshot
                        .edges
                        .iter()
                        .filter(|edge| {
                            edge.source_node_id == node.node_id
                                || edge.target_node_id == node.node_id
                        })
                        .cloned()
                        .collect(),
                    raw_content_preview_if_allowed: None,
                    raw_content_unavailable_reason: Some(
                        RawContentUnavailableReason::RawPreviewNotApproved,
                    ),
                },
            )
        })
        .collect()
}

pub fn get_node_inspector_details(
    details: &BTreeMap<String, NodeInspectorDetails>,
    node_id: &str,
) -> Option<NodeInspectorDetails> {
    details.get(node_id).cloned()
}

pub fn get_subdag(
    snapshot: &GraphExplorerSnapshot,
    focused_node_id: &str,
    requested_depth: u8,
) -> GraphExplorerSnapshot {
    let depth = requested_depth.min(snapshot.limits.max_depth_without_confirmation);
    let mut included = BTreeSet::from([focused_node_id.to_owned()]);
    for _ in 0..depth {
        let mut next = included.clone();
        for edge in &snapshot.edges {
            if included.contains(&edge.source_node_id) {
                next.insert(edge.target_node_id.clone());
            }
            if included.contains(&edge.target_node_id) {
                next.insert(edge.source_node_id.clone());
            }
        }
        included = next;
    }
    let mut subdag = snapshot.clone();
    let max_nodes = usize::from(snapshot.limits.max_nodes_per_expansion);
    let mut kept_ids = BTreeSet::new();
    if snapshot
        .nodes
        .iter()
        .any(|node| node.node_id == focused_node_id)
    {
        kept_ids.insert(focused_node_id.to_owned());
    }
    for node in &snapshot.nodes {
        if kept_ids.len() >= max_nodes {
            break;
        }
        if included.contains(&node.node_id) {
            kept_ids.insert(node.node_id.clone());
        }
    }
    subdag.nodes = snapshot
        .nodes
        .iter()
        .filter(|node| kept_ids.contains(&node.node_id))
        .cloned()
        .collect();
    let visible = subdag
        .nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<BTreeSet<_>>();
    subdag.edges = snapshot
        .edges
        .iter()
        .filter(|edge| {
            visible.contains(&edge.source_node_id) && visible.contains(&edge.target_node_id)
        })
        .take(usize::from(snapshot.limits.max_edges_per_expansion))
        .cloned()
        .collect();
    subdag.drilldown.focused_node_id = Some(focused_node_id.into());
    subdag.drilldown.depth = depth;
    subdag.drilldown.mode = GraphExplorerDrilldownMode::Subdag;
    subdag.drilldown.breadcrumb = vec![
        "Root Graph".into(),
        "Sub-DAG".into(),
        focused_node_id.into(),
    ];
    subdag.summaries.displayed_node_count = usize_to_u32_saturating(subdag.nodes.len());
    subdag.summaries.displayed_edge_count = usize_to_u32_saturating(subdag.edges.len());
    subdag
}

pub fn filter_live_export_edges(
    tenant_id: &str,
    namespace: &str,
    edges: &[MemoryGraphEdge],
) -> Vec<MemoryGraphEdge> {
    edges
        .iter()
        .filter(|edge| edge.tenant_id == tenant_id && edge.namespace == namespace)
        .cloned()
        .collect()
}

pub fn get_node_raw_content_preview(
    request: &GraphExplorerRawContentPreviewRequest<'_>,
    limits: &GraphExplorerLimits,
) -> GraphExplorerRawContentPreview {
    if request
        .env
        .get(RAW_PREVIEW_APPROVAL_ENV)
        .map(String::as_str)
        != Some("true")
    {
        return unavailable_preview(RawContentUnavailableReason::RawPreviewNotApproved);
    }
    if !request.raw_content_allowed || !request.browser_safe_payload {
        return unavailable_preview(RawContentUnavailableReason::PermissionDenied);
    }
    if request.private_payload {
        return unavailable_preview(RawContentUnavailableReason::PrivatePayloadNotExposed);
    }
    let Some(content) = request.content else {
        return unavailable_preview(RawContentUnavailableReason::ArtifactUnavailable);
    };
    if request.binary_content {
        return GraphExplorerRawContentPreview {
            content_kind: request.content_kind,
            preview_text: None,
            preview_bytes: usize_to_u16_saturating(
                content.len().min(usize::from(limits.max_preview_bytes)),
            ),
            preview_lines: 0,
            truncated: content.len() > usize::from(limits.max_preview_bytes),
            binary_metadata_only: true,
            unavailable_reason: Some(RawContentUnavailableReason::BinaryPreviewNotSupported),
        };
    }
    let (preview_text, preview_bytes, preview_lines, truncated) =
        limited_text_preview(content, limits);
    GraphExplorerRawContentPreview {
        content_kind: request.content_kind,
        preview_text: Some(preview_text),
        preview_bytes,
        preview_lines,
        truncated,
        binary_metadata_only: false,
        unavailable_reason: truncated
            .then_some(RawContentUnavailableReason::PreviewSizeLimitApplied),
    }
}

pub fn write_graph_explorer_artifacts(
    snapshot: &GraphExplorerSnapshot,
    inspector_details: &BTreeMap<String, NodeInspectorDetails>,
    target_dir: &Path,
) -> Result<GraphExplorerArtifactSet, GraphExplorerError> {
    fs::create_dir_all(target_dir).map_err(io_error)?;
    let snapshot_path = target_dir.join("snapshot.json");
    let inspector_path = target_dir.join("node_inspector_details.json");
    let summary_path = target_dir.join("graph_explorer_summary.md");
    let snapshot_body = json_body(snapshot)?;
    let inspector_body = json_body(inspector_details)?;
    let summary_body = graph_explorer_summary_markdown(snapshot);
    atomic_write_artifact(&snapshot_path, &snapshot_body)?;
    atomic_write_artifact(&inspector_path, &inspector_body)?;
    fs::write(&summary_path, summary_body.as_bytes()).map_err(io_error)?;
    if repo_relative(target_dir) == GRAPH_EXPLORER_TARGET_DIR {
        write_graph_explorer_dataset_artifacts(
            snapshot,
            &snapshot_body,
            &inspector_body,
            &summary_body,
            target_dir,
        )?;
    }
    Ok(GraphExplorerArtifactSet {
        snapshot_path: repo_relative(&snapshot_path),
        inspector_path: repo_relative(&inspector_path),
        summary_path: repo_relative(&summary_path),
        snapshot_hash: hash_event_body(&snapshot_body)
            .map_err(|error| GraphExplorerError::Serialization {
                reason: error.to_string(),
            })?
            .to_string(),
    })
}

fn atomic_write_artifact(path: &Path, body: &str) -> Result<(), GraphExplorerError> {
    let parent = path.parent().ok_or_else(|| GraphExplorerError::Io {
        reason: "artifact path must have a parent directory".into(),
    })?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphExplorerError::Io {
            reason: "artifact path must end in a UTF-8 file name".into(),
        })?;
    let counter = ARTIFACT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        counter
    ));
    if let Err(error) = fs::write(&temp_path, body.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(io_error(error));
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(io_error(error));
    }
    Ok(())
}

pub fn generate_unavailable_graph_explorer_artifacts(
    source_commit_or_run_id: impl Into<String>,
) -> Result<GraphExplorerArtifactSet, GraphExplorerError> {
    let snapshot =
        unavailable_graph_explorer_snapshot(source_commit_or_run_id).map_err(|error| {
            GraphExplorerError::Serialization {
                reason: error.to_string(),
            }
        })?;
    let inspector = inspector_details_for_snapshot(&snapshot);
    write_graph_explorer_artifacts(
        &snapshot,
        &inspector,
        &repo_root_path().join(GRAPH_EXPLORER_TARGET_DIR),
    )
}

pub fn generate_diagnostic_context_graph_explorer_artifacts(
    source_commit_or_run_id: impl Into<String>,
) -> Result<GraphExplorerArtifactSet, GraphExplorerError> {
    let root = repo_root_path();
    let source_commit_or_run_id =
        graph_source_run_id_override().unwrap_or_else(|| source_commit_or_run_id.into());
    let rows_path = root.join(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH);
    if !rows_path.exists() {
        return generate_unavailable_graph_explorer_artifacts(source_commit_or_run_id);
    }

    let rows_body = fs::read(&rows_path).map_err(io_error)?;
    let rows =
        serde_json::from_slice::<Vec<DiagnosticGraphTaskRow>>(&rows_body).map_err(|error| {
            GraphExplorerError::Serialization {
                reason: error.to_string(),
            }
        })?;
    let mut source_artifact_hashes = BTreeMap::from([(
        GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH.into(),
        sha256_bytes_hex(&rows_body),
    )]);

    let silo_path = root.join(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH);
    if silo_path.exists() {
        let silo_body = fs::read(&silo_path).map_err(io_error)?;
        source_artifact_hashes.insert(
            GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH.into(),
            sha256_bytes_hex(&silo_body),
        );
    }

    let mut snapshot = diagnostic_context_graph_snapshot_from_rows(
        &rows,
        source_artifact_hashes,
        Some(source_commit_or_run_id),
    )?;
    if snapshot.nodes.is_empty() {
        snapshot = unavailable_graph_explorer_snapshot("diagnostic-artifact-no-graph-enabled-rows")
            .map_err(|error| GraphExplorerError::Serialization {
                reason: error.to_string(),
            })?;
    }
    let inspector = inspector_details_for_snapshot(&snapshot);
    write_graph_explorer_artifacts(&snapshot, &inspector, &root.join(GRAPH_EXPLORER_TARGET_DIR))
}

fn diagnostic_context_graph_snapshot_from_rows(
    rows: &[DiagnosticGraphTaskRow],
    source_artifact_hashes: BTreeMap<String, String>,
    source_commit_or_run_id: Option<String>,
) -> Result<GraphExplorerSnapshot, GraphExplorerError> {
    let graph_rows = rows
        .iter()
        .filter(|row| is_graph_enabled_diagnostic_row(row))
        .filter(|row| !row.task_id.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    if graph_rows.is_empty() {
        return unavailable_graph_explorer_snapshot("diagnostic-artifact-no-graph-enabled-rows")
            .map_err(|error| GraphExplorerError::Serialization {
                reason: error.to_string(),
            });
    }

    let limits = GraphExplorerLimits::default();
    let mut nodes = Vec::<GraphExplorerNode>::new();
    let mut edges = Vec::<GraphExplorerEdge>::new();
    let mut edge_keys = BTreeSet::<String>::new();
    let mut runner_aggregates = BTreeMap::<String, DiagnosticGraphRunnerAggregate>::new();
    let mut task_rows = BTreeMap::<String, DiagnosticGraphTaskRow>::new();

    for row in &graph_rows {
        let runner_key = graph_runner_key(row);
        let aggregate = runner_aggregates
            .entry(runner_key.clone())
            .or_insert_with(|| DiagnosticGraphRunnerAggregate {
                runner: row.runner.clone(),
                diagnostic_label: row.diagnostic_label.clone(),
                row_count: 0,
                route_count: 0,
                selected_refs: 0,
                context_packet_tokens: 0,
            });
        aggregate.row_count = aggregate.row_count.saturating_add(1);
        aggregate.route_count = aggregate
            .route_count
            .saturating_add(row.route_count.unwrap_or(0));
        aggregate.selected_refs = aggregate
            .selected_refs
            .saturating_add(row.selected_refs.unwrap_or(0));
        aggregate.context_packet_tokens = aggregate
            .context_packet_tokens
            .saturating_add(row.context_packet_tokens.unwrap_or(0));
        task_rows
            .entry(row.task_id.clone())
            .or_insert_with(|| row.clone());
    }

    let root_node_id = deterministic_graph_node_id("diagnostic-root", "graph-enabled-runs")?;
    let silo_node_id = deterministic_graph_node_id("diagnostic-silo", "governed-dag-benchmark-db")?;
    nodes.push(diagnostic_graph_node(DiagnosticGraphNodeSpec {
        node_id: root_node_id.clone(),
        label: "Diagnostic graph capture".into(),
        node_kind: MemoryNodeKind::Decision,
        graph_style: MemoryGraphStyle::ContextPacketGraph,
        catalog_path: vec!["diagnostics".into(), "graph_capture".into()],
        status: GraphExplorerNodeStatus::Active,
        metadata_summary: vec![
            "source:diagnostic_context_packet_artifact".into(),
            "stored_dag:false".into(),
            format!("graph_enabled_rows:{}", graph_rows.len()),
        ],
    })?);
    nodes.push(diagnostic_graph_node(DiagnosticGraphNodeSpec {
        node_id: silo_node_id.clone(),
        label: "Governed DAG Benchmark DB".into(),
        node_kind: MemoryNodeKind::Concept,
        graph_style: MemoryGraphStyle::SemanticCatalogGraph,
        catalog_path: vec!["benchmark_isolation".into(), "governed".into()],
        status: GraphExplorerNodeStatus::Active,
        metadata_summary: vec![
            "role:governed_dag_benchmark_db".into(),
            "neutral_runners:not_graphed".into(),
        ],
    })?);
    add_diagnostic_edge(
        &mut edges,
        &mut edge_keys,
        &root_node_id,
        &silo_node_id,
        MemoryEdgeKind::PartOf,
        MemoryGraphStyle::SemanticCatalogGraph,
    )?;

    for (runner_key, aggregate) in &runner_aggregates {
        let runner_node_id = deterministic_graph_node_id("diagnostic-runner", runner_key)?;
        let context_node_id = deterministic_graph_node_id("context-packet-group", runner_key)?;
        let refs_node_id = deterministic_graph_node_id("selected-ref-group", runner_key)?;
        let receipt_node_id = deterministic_graph_node_id("graph-receipt-contract", runner_key)?;

        nodes.push(diagnostic_graph_node(DiagnosticGraphNodeSpec {
            node_id: runner_node_id.clone(),
            label: format!("runner:{}", aggregate.diagnostic_label),
            node_kind: MemoryNodeKind::Route,
            graph_style: MemoryGraphStyle::RoutingViewGraph,
            catalog_path: vec!["diagnostics".into(), "runners".into()],
            status: GraphExplorerNodeStatus::Active,
            metadata_summary: vec![
                format!("runner:{}", aggregate.runner),
                format!("diagnostic_label:{}", aggregate.diagnostic_label),
                format!("task_rows:{}", aggregate.row_count),
                format!("route_count:{}", aggregate.route_count),
            ],
        })?);
        nodes.push(diagnostic_graph_node(DiagnosticGraphNodeSpec {
            node_id: context_node_id.clone(),
            label: format!("context packets:{}", aggregate.diagnostic_label),
            node_kind: MemoryNodeKind::Summary,
            graph_style: MemoryGraphStyle::ContextPacketGraph,
            catalog_path: vec!["diagnostics".into(), "context_packets".into()],
            status: GraphExplorerNodeStatus::Active,
            metadata_summary: vec![
                format!("context_packet_tokens:{}", aggregate.context_packet_tokens),
                format!("task_rows:{}", aggregate.row_count),
            ],
        })?);
        nodes.push(diagnostic_graph_node(DiagnosticGraphNodeSpec {
            node_id: refs_node_id.clone(),
            label: format!("selected refs:{}", aggregate.diagnostic_label),
            node_kind: MemoryNodeKind::Related,
            graph_style: MemoryGraphStyle::SemanticCatalogGraph,
            catalog_path: vec!["diagnostics".into(), "selected_refs".into()],
            status: GraphExplorerNodeStatus::Active,
            metadata_summary: vec![
                format!("selected_refs:{}", aggregate.selected_refs),
                "raw_payload:not_exported".into(),
            ],
        })?);
        nodes.push(diagnostic_graph_node(DiagnosticGraphNodeSpec {
            node_id: receipt_node_id.clone(),
            label: format!("graph receipt contract:{}", aggregate.diagnostic_label),
            node_kind: MemoryNodeKind::ValidationReport,
            graph_style: MemoryGraphStyle::ProvenanceReceiptDag,
            catalog_path: vec!["diagnostics".into(), "receipts".into()],
            status: GraphExplorerNodeStatus::Active,
            metadata_summary: vec![
                "future_runs:emit_graph_signature".into(),
                "future_runs:emit_receipt_reference".into(),
            ],
        })?);
        add_diagnostic_edge(
            &mut edges,
            &mut edge_keys,
            &silo_node_id,
            &runner_node_id,
            MemoryEdgeKind::UsedByRoute,
            MemoryGraphStyle::RoutingViewGraph,
        )?;
        add_diagnostic_edge(
            &mut edges,
            &mut edge_keys,
            &runner_node_id,
            &receipt_node_id,
            MemoryEdgeKind::VerifiedBy,
            MemoryGraphStyle::ProvenanceReceiptDag,
        )?;
        add_diagnostic_edge(
            &mut edges,
            &mut edge_keys,
            &context_node_id,
            &refs_node_id,
            MemoryEdgeKind::Supports,
            MemoryGraphStyle::SemanticCatalogGraph,
        )?;
    }

    for (task_id, row) in &task_rows {
        let task_node_id = deterministic_graph_node_id("diagnostic-task", task_id)?;
        nodes.push(diagnostic_graph_node(DiagnosticGraphNodeSpec {
            node_id: task_node_id.clone(),
            label: format!("{} {}", task_id, row.task_type),
            node_kind: MemoryNodeKind::Decision,
            graph_style: MemoryGraphStyle::ContextPacketGraph,
            catalog_path: vec!["diagnostics".into(), "tasks".into()],
            status: GraphExplorerNodeStatus::Active,
            metadata_summary: diagnostic_task_metadata(row),
        })?);
    }

    for row in &graph_rows {
        let runner_key = graph_runner_key(row);
        let runner_node_id = deterministic_graph_node_id("diagnostic-runner", &runner_key)?;
        let task_node_id = deterministic_graph_node_id("diagnostic-task", &row.task_id)?;
        let context_node_id = deterministic_graph_node_id("context-packet-group", &runner_key)?;
        add_diagnostic_edge(
            &mut edges,
            &mut edge_keys,
            &runner_node_id,
            &task_node_id,
            MemoryEdgeKind::UsedByRoute,
            MemoryGraphStyle::RoutingViewGraph,
        )?;
        add_diagnostic_edge(
            &mut edges,
            &mut edge_keys,
            &task_node_id,
            &context_node_id,
            MemoryEdgeKind::IncludedInContextPacket,
            MemoryGraphStyle::ContextPacketGraph,
        )?;
    }

    let total_known_node_count = usize_to_u32_saturating(nodes.len());
    let total_known_edge_count = usize_to_u32_saturating(edges.len());
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    if nodes.len() > usize::from(limits.max_nodes) {
        nodes.truncate(usize::from(limits.max_nodes));
    }
    let visible_node_ids = nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<BTreeSet<_>>();
    edges.retain(|edge| {
        visible_node_ids.contains(&edge.source_node_id)
            && visible_node_ids.contains(&edge.target_node_id)
    });
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    if edges.len() > usize::from(limits.max_edges) {
        edges.truncate(usize::from(limits.max_edges));
    }
    let limit_applied = total_known_node_count > u32::from(limits.max_nodes)
        || total_known_edge_count > u32::from(limits.max_edges);
    apply_graph_explorer_counts(&mut nodes, &edges);
    let clusters = graph_style_clusters(&nodes, &limits);
    let root_node_ids = nodes
        .iter()
        .filter(|node| node.parent_count == 0)
        .map(|node| node.node_id.clone())
        .collect::<Vec<_>>();
    let summaries = GraphExplorerSummaries {
        displayed_node_count: usize_to_u32_saturating(nodes.len()),
        total_known_node_count: Some(total_known_node_count),
        displayed_edge_count: usize_to_u32_saturating(edges.len()),
        total_known_edge_count: Some(total_known_edge_count),
        displayed_cluster_count: usize_to_u32_saturating(clusters.len()),
        total_known_cluster_count: Some(usize_to_u32_saturating(clusters.len())),
        limit_applied,
    };
    let sanitized_source_commit_or_run_id = source_commit_or_run_id
        .as_deref()
        .map(sanitize_source_commit_or_run_id);
    let source_table_names = vec![
        "diagnostic_artifact:end_to_end_per_task_results".into(),
        "diagnostic_artifact:benchmark_isolation_silo_config".into(),
    ];
    let source_column_set_hash = Some(hash_string(
        "task_id,task_type,runner,diagnostic_label,selected_refs,route_count,context_packet_tokens,quality_score_bp,citation_accuracy_bp,unsupported_claim_rate_bp,latency_ms,total_cost_micro_exo",
    )?);
    let mut snapshot = GraphExplorerSnapshot {
        schema_version: GRAPH_EXPLORER_SCHEMA_VERSION.into(),
        snapshot_id: String::new(),
        generated_from: GraphExplorerGeneratedFrom::DiagnosticArtifact,
        generation_mode: GraphExplorerGenerationMode::ReportFileArtifact,
        export_result_status: GraphExplorerExportResultStatus::GeneratedRealGraphArtifact,
        source_truth_level: GraphSourceTruthLevel::DiagnosticContextPacketArtifact,
        source_mode: GraphExplorerSourceMode::GeneratedGraphArtifact,
        source_description:
            "diagnostic context packet artifact showing task-specific context influence, not the full stored DAG"
                .into(),
        source_artifact_paths: vec![
            GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH.into(),
            GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH.into(),
            GRAPH_EXPLORER_SNAPSHOT_PATH.into(),
        ],
        source_receipt_ids: Vec::new(),
        source_graph_view_ids: Vec::new(),
        source_commit_or_run_id: sanitized_source_commit_or_run_id,
        source_is_live_db_export: false,
        source_is_generated_artifact: true,
        artifact_hash: None,
        source_artifact_hashes,
        source_graph_view_hashes: BTreeMap::new(),
        source_receipt_hashes: BTreeMap::new(),
        schema_inventory_hash: Some(hash_string("diagnostic_context_packet_artifact_v1")?),
        source_column_set_hash,
        source_table_names,
        query_scope_tenant_id: None,
        query_scope_namespace: None,
        displayed_node_count: summaries.displayed_node_count,
        total_scoped_node_count: summaries.total_known_node_count,
        displayed_edge_count: summaries.displayed_edge_count,
        total_scoped_edge_count: summaries.total_known_edge_count,
        dropped_edge_count: total_known_edge_count.saturating_sub(summaries.displayed_edge_count),
        limit_applied,
        source_unavailable_reason: None,
        graph_export_not_available: false,
        tenant_id: None,
        namespace: None,
        graph_styles_available: all_graph_styles().to_vec(),
        active_graph_style: MemoryGraphStyle::ContextPacketGraph,
        root_node_ids,
        nodes,
        edges,
        clusters,
        summaries,
        permissions: GraphExplorerPermissions {
            raw_content_allowed: false,
            private_payloads_allowed: false,
            live_db_export_allowed: false,
            raw_preview_env_approved: false,
            source_mode: "report_file".into(),
        },
        limits,
        drilldown: GraphExplorerDrilldownState {
            breadcrumb: vec![
                "Root Graph".into(),
                "Diagnostic Artifact".into(),
                "Context Packet Influence".into(),
            ],
            root_node_id: Some(root_node_id),
            focused_node_id: None,
            active_graph_style: MemoryGraphStyle::ContextPacketGraph,
            depth: 0,
            mode: GraphExplorerDrilldownMode::Overview,
        },
        warnings: if limit_applied {
            vec![
                "diagnostic_context_packet_artifact_not_full_stored_dag".into(),
                GRAPH_EXPLORER_LIMIT_WARNING.into(),
            ]
        } else {
            vec!["diagnostic_context_packet_artifact_not_full_stored_dag".into()]
        },
    };
    snapshot.snapshot_id = hash_event_body(&SnapshotIdMaterial {
        generated_from: snapshot.generated_from,
        generation_mode: snapshot.generation_mode,
        source_truth_level: snapshot.source_truth_level,
        source_commit_or_run_id: snapshot.source_commit_or_run_id.as_deref(),
        node_ids: &snapshot
            .nodes
            .iter()
            .map(|node| node.node_id.as_str())
            .collect::<Vec<_>>(),
        edge_ids: &snapshot
            .edges
            .iter()
            .map(|edge| edge.edge_id.as_str())
            .collect::<Vec<_>>(),
    })
    .map_err(|error| GraphExplorerError::Serialization {
        reason: error.to_string(),
    })?
    .to_string();
    snapshot.artifact_hash = Some(
        hash_event_body(&snapshot)
            .map_err(|error| GraphExplorerError::Serialization {
                reason: error.to_string(),
            })?
            .to_string(),
    );
    Ok(snapshot)
}

fn explorer_nodes(
    nodes: &[MemoryGraphNode],
    edges: &[MemoryGraphEdge],
    limits: &GraphExplorerLimits,
) -> Vec<GraphExplorerNode> {
    let mut parent_counts = BTreeMap::<String, u32>::new();
    let mut child_counts = BTreeMap::<String, u32>::new();
    for edge in edges {
        *child_counts
            .entry(edge.from_memory_id.to_string())
            .or_insert(0) += 1;
        *parent_counts
            .entry(edge.to_memory_id.to_string())
            .or_insert(0) += 1;
    }
    let mut output = nodes
        .iter()
        .map(|node| {
            let node_id = node.memory_id.to_string();
            let label = label_from_hash(&node_id, usize::from(limits.max_label_chars));
            GraphExplorerNode {
                node_id: node_id.clone(),
                label,
                node_kind: node.node_kind,
                graph_style: node.graph_style,
                catalog_path: Vec::new(),
                status: status_for_kind(node.node_kind),
                risk_class: None,
                owner_id: None,
                receipt_ids: Vec::new(),
                source_hash: Some(node_id.clone()),
                content_hash: Some(node_id.clone()),
                raw_content_allowed: false,
                browser_safe_payload: false,
                has_raw_content: false,
                has_children: child_counts.get(&node_id).copied().unwrap_or(0) > 0,
                child_count: child_counts.get(&node_id).copied().unwrap_or(0),
                parent_count: parent_counts.get(&node_id).copied().unwrap_or(0),
                metadata_summary: vec![format!("node_kind:{:?}", node.node_kind)],
            }
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    output
}

struct DiagnosticGraphNodeSpec {
    node_id: String,
    label: String,
    node_kind: MemoryNodeKind,
    graph_style: MemoryGraphStyle,
    catalog_path: Vec<String>,
    status: GraphExplorerNodeStatus,
    metadata_summary: Vec<String>,
}

fn diagnostic_graph_node(
    spec: DiagnosticGraphNodeSpec,
) -> Result<GraphExplorerNode, GraphExplorerError> {
    let node_hash = hash_string(&spec.node_id)?;
    Ok(GraphExplorerNode {
        node_id: spec.node_id,
        label: truncate_label(&spec.label, GraphExplorerLimits::default().max_label_chars),
        node_kind: spec.node_kind,
        graph_style: spec.graph_style,
        catalog_path: spec.catalog_path,
        status: spec.status,
        risk_class: None,
        owner_id: None,
        receipt_ids: Vec::new(),
        source_hash: Some(node_hash.clone()),
        content_hash: Some(node_hash),
        raw_content_allowed: false,
        browser_safe_payload: false,
        has_raw_content: false,
        has_children: false,
        child_count: 0,
        parent_count: 0,
        metadata_summary: spec.metadata_summary.into_iter().take(12).collect(),
    })
}

fn add_diagnostic_edge(
    edges: &mut Vec<GraphExplorerEdge>,
    edge_keys: &mut BTreeSet<String>,
    source_node_id: &str,
    target_node_id: &str,
    edge_kind: MemoryEdgeKind,
    graph_style: MemoryGraphStyle,
) -> Result<(), GraphExplorerError> {
    let edge_key = format!(
        "{}:{}:{}:{}",
        source_node_id,
        target_node_id,
        edge_kind_key(edge_kind),
        graph_style_key(graph_style)
    );
    if !edge_keys.insert(edge_key.clone()) {
        return Ok(());
    }
    edges.push(GraphExplorerEdge {
        edge_id: hash_string(&edge_key)?,
        source_node_id: source_node_id.into(),
        target_node_id: target_node_id.into(),
        edge_kind,
        graph_style,
        receipt_id: None,
        status: GraphExplorerEdgeStatus::Active,
        confidence_bp: None,
        direction: GraphExplorerEdgeDirection::SourceToTarget,
    });
    Ok(())
}

fn apply_graph_explorer_counts(nodes: &mut [GraphExplorerNode], edges: &[GraphExplorerEdge]) {
    let mut parent_counts = BTreeMap::<String, u32>::new();
    let mut child_counts = BTreeMap::<String, u32>::new();
    for edge in edges {
        *child_counts.entry(edge.source_node_id.clone()).or_insert(0) += 1;
        *parent_counts
            .entry(edge.target_node_id.clone())
            .or_insert(0) += 1;
    }
    for node in nodes {
        node.child_count = child_counts.get(&node.node_id).copied().unwrap_or(0);
        node.parent_count = parent_counts.get(&node.node_id).copied().unwrap_or(0);
        node.has_children = node.child_count > 0;
    }
}

fn diagnostic_task_metadata(row: &DiagnosticGraphTaskRow) -> Vec<String> {
    let mut metadata = vec![
        format!("runner:{}", row.runner),
        format!("diagnostic_label:{}", row.diagnostic_label),
        format!("fixture_id:{}", row.fixture_id),
        format!(
            "context_profile:{}",
            empty_label(&row.context_acquisition_profile)
        ),
        format!("route_count:{}", row.route_count.unwrap_or(0)),
        format!("selected_refs:{}", row.selected_refs.unwrap_or(0)),
        format!(
            "context_packet_tokens:{}",
            row.context_packet_tokens.unwrap_or(0)
        ),
    ];
    push_optional_u16(&mut metadata, "quality_score_bp", row.quality_score_bp);
    push_optional_u16(
        &mut metadata,
        "citation_accuracy_bp",
        row.citation_accuracy_bp,
    );
    push_optional_u16(
        &mut metadata,
        "unsupported_claim_rate_bp",
        row.unsupported_claim_rate_bp,
    );
    push_optional_u32(&mut metadata, "latency_ms", row.latency_ms);
    push_optional_u32(
        &mut metadata,
        "total_cost_micro_exo",
        row.total_cost_micro_exo,
    );
    metadata
}

fn is_graph_enabled_diagnostic_row(row: &DiagnosticGraphTaskRow) -> bool {
    matches!(
        row.diagnostic_label.as_str(),
        "dag_db_routing_raw" | "governed_dagdb" | "governed_dagdb_optimized"
    ) || matches!(
        row.runner.as_str(),
        "dag_db_routing" | "governed_dag_db_routing" | "governed_dag_db_optimized"
    )
}

fn graph_runner_key(row: &DiagnosticGraphTaskRow) -> String {
    if row.diagnostic_label.is_empty() {
        row.runner.clone()
    } else {
        row.diagnostic_label.clone()
    }
}

fn deterministic_graph_node_id(kind: &str, key: &str) -> Result<String, GraphExplorerError> {
    hash_string(&format!("{kind}:{key}"))
}

fn hash_string(value: &str) -> Result<String, GraphExplorerError> {
    hash_event_body(&value)
        .map(|hash| hash.to_string())
        .map_err(|error| GraphExplorerError::Serialization {
            reason: error.to_string(),
        })
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

fn truncate_label(value: &str, max_chars: u16) -> String {
    value.chars().take(usize::from(max_chars)).collect()
}

fn empty_label(value: &str) -> &str {
    if value.is_empty() {
        "not_available"
    } else {
        value
    }
}

fn push_optional_u16(metadata: &mut Vec<String>, key: &str, value: Option<u16>) {
    if let Some(value) = value {
        metadata.push(format!("{key}:{value}"));
    }
}

fn push_optional_u32(metadata: &mut Vec<String>, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        metadata.push(format!("{key}:{value}"));
    }
}

fn explorer_edges(edges: &[MemoryGraphEdge]) -> Vec<GraphExplorerEdge> {
    let mut output = edges
        .iter()
        .map(|edge| GraphExplorerEdge {
            edge_id: edge.edge_id.to_string(),
            source_node_id: edge.from_memory_id.to_string(),
            target_node_id: edge.to_memory_id.to_string(),
            edge_kind: edge.edge_kind,
            graph_style: edge.graph_style,
            receipt_id: edge
                .provenance_receipt_id
                .map(|receipt| receipt.to_string()),
            status: GraphExplorerEdgeStatus::Active,
            confidence_bp: None,
            direction: GraphExplorerEdgeDirection::SourceToTarget,
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    output
}

fn graph_style_clusters(
    nodes: &[GraphExplorerNode],
    limits: &GraphExplorerLimits,
) -> Vec<GraphExplorerCluster> {
    let mut by_style = BTreeMap::<MemoryGraphStyle, Vec<String>>::new();
    for node in nodes {
        by_style
            .entry(node.graph_style)
            .or_default()
            .push(node.node_id.clone());
    }
    by_style
        .into_iter()
        .take(usize::from(limits.max_clusters))
        .map(|(style, mut node_ids)| {
            node_ids.sort();
            GraphExplorerCluster {
                cluster_id: format!("graph_style:{}", graph_style_key(style)),
                label: graph_style_label(style).into(),
                cluster_type: GraphExplorerClusterType::GraphStyle,
                graph_style: style,
                count: usize_to_u32_saturating(node_ids.len()),
                color_key: graph_style_key(style).into(),
                node_ids,
            }
        })
        .collect()
}

fn source_fields(
    source_truth_level: GraphSourceTruthLevel,
) -> (
    GraphExplorerGeneratedFrom,
    GraphExplorerGenerationMode,
    GraphExplorerSourceMode,
    String,
) {
    match source_truth_level {
        GraphSourceTruthLevel::ActualStoredDag => (
            GraphExplorerGeneratedFrom::GraphRecords,
            GraphExplorerGenerationMode::ApprovedReadOnlyLiveExport,
            GraphExplorerSourceMode::ApprovedReadOnlyLiveExport,
            "approved read-only export from actual stored DAG graph records".into(),
        ),
        GraphSourceTruthLevel::ApprovedReadOnlyGraphView => (
            GraphExplorerGeneratedFrom::GraphView,
            GraphExplorerGenerationMode::ApprovedReadOnlyLiveExport,
            GraphExplorerSourceMode::ApprovedReadOnlyLiveExport,
            "approved read-only GraphView export generated from source graph records".into(),
        ),
        GraphSourceTruthLevel::GeneratedGraphArtifact => (
            GraphExplorerGeneratedFrom::DiagnosticArtifact,
            GraphExplorerGenerationMode::ReportFileArtifact,
            GraphExplorerSourceMode::GeneratedGraphArtifact,
            "generated graph artifact; inspect provenance fields for the source".into(),
        ),
        GraphSourceTruthLevel::DiagnosticContextPacketArtifact => (
            GraphExplorerGeneratedFrom::DiagnosticArtifact,
            GraphExplorerGenerationMode::ReportFileArtifact,
            GraphExplorerSourceMode::GeneratedGraphArtifact,
            "diagnostic context packet artifact showing task-specific context influence, not the full stored DAG".into(),
        ),
        GraphSourceTruthLevel::ConceptualUnavailableFallback => (
            GraphExplorerGeneratedFrom::Unavailable,
            GraphExplorerGenerationMode::UnavailableConceptualFallback,
            GraphExplorerSourceMode::UnavailableConceptualFallback,
            "unavailable/conceptual fallback; not real graph data".into(),
        ),
        GraphSourceTruthLevel::ApprovedLiveExportEmptyScope => (
            GraphExplorerGeneratedFrom::GraphRecords,
            GraphExplorerGenerationMode::ApprovedReadOnlyLiveExport,
            GraphExplorerSourceMode::ApprovedReadOnlyLiveExport,
            "approved live export returned zero scoped graph rows".into(),
        ),
    }
}

fn export_result_status_for(
    source_truth_level: GraphSourceTruthLevel,
    displayed_node_count: usize,
) -> GraphExplorerExportResultStatus {
    match source_truth_level {
        GraphSourceTruthLevel::ActualStoredDag
        | GraphSourceTruthLevel::ApprovedReadOnlyGraphView
        | GraphSourceTruthLevel::GeneratedGraphArtifact
        | GraphSourceTruthLevel::DiagnosticContextPacketArtifact => {
            if displayed_node_count == 0 {
                GraphExplorerExportResultStatus::GeneratedUnavailableArtifact
            } else {
                GraphExplorerExportResultStatus::GeneratedRealGraphArtifact
            }
        }
        GraphSourceTruthLevel::ApprovedLiveExportEmptyScope => {
            GraphExplorerExportResultStatus::GeneratedEmptyScopedGraphArtifact
        }
        GraphSourceTruthLevel::ConceptualUnavailableFallback => {
            GraphExplorerExportResultStatus::GeneratedUnavailableArtifact
        }
    }
}

fn source_unavailable_reason_for(source_truth_level: GraphSourceTruthLevel) -> String {
    match source_truth_level {
        GraphSourceTruthLevel::ApprovedLiveExportEmptyScope => {
            "approved_live_export_returned_zero_scoped_graph_rows".into()
        }
        _ => GRAPH_EXPORT_NOT_AVAILABLE.into(),
    }
}

fn status_for_kind(kind: MemoryNodeKind) -> GraphExplorerNodeStatus {
    match kind {
        MemoryNodeKind::Canonical => GraphExplorerNodeStatus::Canonical,
        MemoryNodeKind::DuplicateReference => GraphExplorerNodeStatus::Duplicate,
        MemoryNodeKind::Supersession => GraphExplorerNodeStatus::Superseded,
        MemoryNodeKind::Contradiction => GraphExplorerNodeStatus::Contradicted,
        _ => GraphExplorerNodeStatus::Active,
    }
}

fn label_from_hash(hash: &str, max_chars: usize) -> String {
    let prefix_len = hash.len().min(max_chars).min(12);
    format!("memory:{}", &hash[..prefix_len])
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

fn graph_style_label(style: MemoryGraphStyle) -> &'static str {
    match style {
        MemoryGraphStyle::ProvenanceReceiptDag => "Provenance Receipt DAG",
        MemoryGraphStyle::CanonicalMemoryGraph => "Canonical Memory Graph",
        MemoryGraphStyle::SemanticCatalogGraph => "Semantic Catalog Graph",
        MemoryGraphStyle::SimilarityOverlayGraph => "Similarity Overlay Graph",
        MemoryGraphStyle::DependencyDag => "Dependency DAG",
        MemoryGraphStyle::RoutingViewGraph => "Routing View Graph",
        MemoryGraphStyle::ContradictionSupersessionGraph => "Contradiction / Supersession Graph",
        MemoryGraphStyle::ContextPacketGraph => "Context Packet Graph",
    }
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn usize_to_u16_saturating(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn unavailable_preview(reason: RawContentUnavailableReason) -> GraphExplorerRawContentPreview {
    GraphExplorerRawContentPreview {
        content_kind: GraphExplorerContentKind::HashOnlyReference,
        preview_text: None,
        preview_bytes: 0,
        preview_lines: 0,
        truncated: false,
        binary_metadata_only: false,
        unavailable_reason: Some(reason),
    }
}

fn limited_text_preview(content: &str, limits: &GraphExplorerLimits) -> (String, u16, u16, bool) {
    let max_bytes = usize::from(limits.max_preview_bytes);
    let max_lines = usize::from(limits.max_preview_lines);
    let mut preview = String::new();
    let mut bytes_used = 0usize;
    let mut truncated = false;

    for (line_index, segment) in content.split_inclusive('\n').enumerate() {
        if line_index >= max_lines {
            truncated = true;
            break;
        }
        let remaining_bytes = max_bytes.saturating_sub(bytes_used);
        if remaining_bytes == 0 {
            truncated = true;
            break;
        }
        let chunk = prefix_at_char_boundary(segment, remaining_bytes);
        preview.push_str(chunk);
        bytes_used += chunk.len();
        if chunk.len() < segment.len() {
            truncated = true;
            break;
        }
    }

    if bytes_used < content.len() {
        truncated = true;
    }
    let preview_lines = preview.lines().count();
    (
        preview,
        usize_to_u16_saturating(bytes_used.min(max_bytes)),
        usize_to_u16_saturating(preview_lines.min(max_lines)),
        truncated,
    )
}

fn prefix_at_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = 0usize;
    for (index, character) in value.char_indices() {
        let next_end = index + character.len_utf8();
        if next_end > max_bytes {
            break;
        }
        end = next_end;
    }
    &value[..end]
}

fn sanitize_source_commit_or_run_id(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if lower.contains("://")
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("database_url")
        || lower.contains("connection_string")
    {
        "redacted_source_commit_or_run_id".into()
    } else {
        value.into()
    }
}

fn json_body<T: Serialize>(value: &T) -> Result<String, GraphExplorerError> {
    serde_json::to_string_pretty(value)
        .map(|body| format!("{body}\n"))
        .map_err(|error| GraphExplorerError::Serialization {
            reason: error.to_string(),
        })
}

fn graph_explorer_summary_markdown(snapshot: &GraphExplorerSnapshot) -> String {
    format!(
        "# EXOCHAIN DAG DB Graph Explorer Summary\n\n\
         ## Source\n\n\
         - export_result_status: {:?}\n\
         - source_truth_level: {:?}\n\
         - generated_from: {:?}\n\
         - generation_mode: {:?}\n\
         - source_mode: {:?}\n\
         - source_description: {}\n\
         - source_commit_or_run_id: {}\n\n\
         ## Scope And Counts\n\n\
         - query_scope_tenant_id: {}\n\
         - query_scope_namespace: {}\n\
         - displayed_node_count: {}\n\
         - total_scoped_node_count: {}\n\
         - displayed_edge_count: {}\n\
         - total_scoped_edge_count: {}\n\
         - dropped_edge_count: {}\n\
         - limit_applied: {}\n\
         - graph_export_not_available: {}\n\
         - source_unavailable_reason: {}\n\n\
         ## Provenance\n\n\
         - artifact_hash: {}\n\
         - schema_inventory_hash: {}\n\
         - source_column_set_hash: {}\n\
         - source_table_names: {}\n\
         - source_artifact_hash_count: {}\n\
         - source_artifact_hashes: {}\n\
         - source_graph_view_hash_count: {}\n\
         - source_receipt_hash_count: {}\n\
         - source_receipt_ids: {}\n\
         - source_graph_view_ids: {}\n\
         - warnings: {}\n",
        snapshot.export_result_status,
        snapshot.source_truth_level,
        snapshot.generated_from,
        snapshot.generation_mode,
        snapshot.source_mode,
        snapshot.source_description,
        option_label(snapshot.source_commit_or_run_id.as_deref()),
        option_label(snapshot.query_scope_tenant_id.as_deref()),
        option_label(snapshot.query_scope_namespace.as_deref()),
        snapshot.displayed_node_count,
        option_u32_label(snapshot.total_scoped_node_count),
        snapshot.displayed_edge_count,
        option_u32_label(snapshot.total_scoped_edge_count),
        snapshot.dropped_edge_count,
        snapshot.limit_applied,
        snapshot.graph_export_not_available,
        option_label(snapshot.source_unavailable_reason.as_deref()),
        option_label(snapshot.artifact_hash.as_deref()),
        option_label(snapshot.schema_inventory_hash.as_deref()),
        option_label(snapshot.source_column_set_hash.as_deref()),
        list_label(&snapshot.source_table_names),
        snapshot.source_artifact_hashes.len(),
        map_label(&snapshot.source_artifact_hashes),
        snapshot.source_graph_view_hashes.len(),
        snapshot.source_receipt_hashes.len(),
        list_label(&snapshot.source_receipt_ids),
        list_label(&snapshot.source_graph_view_ids),
        snapshot.warnings.join(", ")
    )
}

fn option_label(value: Option<&str>) -> String {
    value.unwrap_or("not_available").into()
}

fn option_u32_label(value: Option<u32>) -> String {
    value
        .map(|count| count.to_string())
        .unwrap_or_else(|| "not_available".into())
}

fn list_label(values: &[String]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.join(", ")
    }
}

fn map_label(values: &BTreeMap<String, String>) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn write_graph_explorer_dataset_artifacts(
    snapshot: &GraphExplorerSnapshot,
    snapshot_body: &str,
    inspector_body: &str,
    summary_body: &str,
    target_dir: &Path,
) -> Result<(), GraphExplorerError> {
    let dataset_id = graph_explorer_dataset_id(snapshot)?;
    let dataset_dir = target_dir.join("datasets").join(&dataset_id);
    ensure_dataset_dir_is_scoped(target_dir, &dataset_dir)?;
    fs::create_dir_all(&dataset_dir).map_err(io_error)?;
    let snapshot_path = dataset_dir.join("snapshot.json");
    let inspector_path = dataset_dir.join("node_inspector_details.json");
    let summary_path = dataset_dir.join("graph_explorer_summary.md");
    atomic_write_artifact(&snapshot_path, snapshot_body)?;
    atomic_write_artifact(&inspector_path, inspector_body)?;
    fs::write(&summary_path, summary_body.as_bytes()).map_err(io_error)?;

    let artifact_hashes = GraphExplorerDatasetArtifactHashes {
        snapshot: sha256_bytes_hex(snapshot_body.as_bytes()),
        inspector: sha256_bytes_hex(inspector_body.as_bytes()),
        summary: sha256_bytes_hex(summary_body.as_bytes()),
    };
    let artifact_hash = graph_explorer_dataset_bundle_hash(&artifact_hashes)?;
    let record = GraphExplorerDatasetRecord {
        dataset_id: dataset_id.clone(),
        label: graph_explorer_dataset_label(snapshot),
        created_order_key: graph_explorer_dataset_order_key(snapshot, &dataset_id),
        artifact_paths: GraphExplorerDatasetArtifactPaths {
            snapshot: repo_relative(&snapshot_path),
            inspector: repo_relative(&inspector_path),
            summary: repo_relative(&summary_path),
        },
        snapshot_id: snapshot.snapshot_id.clone(),
        source_truth_level: snapshot.source_truth_level,
        export_result_status: snapshot.export_result_status,
        node_count: usize_to_u32_saturating(snapshot.nodes.len()),
        edge_count: usize_to_u32_saturating(snapshot.edges.len()),
        cluster_count: usize_to_u32_saturating(snapshot.clusters.len()),
        warning_count: usize_to_u32_saturating(snapshot.warnings.len()),
        limit_applied: snapshot.limit_applied,
        artifact_hash,
        artifact_hashes,
    };
    update_graph_explorer_dataset_index(target_dir, record)
}

fn ensure_dataset_dir_is_scoped(
    target_dir: &Path,
    dataset_dir: &Path,
) -> Result<(), GraphExplorerError> {
    let datasets_dir = target_dir.join("datasets");
    let dataset_dir = path_clean(dataset_dir);
    let datasets_dir = path_clean(&datasets_dir);
    if !dataset_dir.starts_with(&datasets_dir) {
        return Err(GraphExplorerError::InvalidDatasetId {
            dataset_id: repo_relative(&dataset_dir),
        });
    }
    Ok(())
}

fn update_graph_explorer_dataset_index(
    target_dir: &Path,
    record: GraphExplorerDatasetRecord,
) -> Result<(), GraphExplorerError> {
    let index_path = target_dir.join("index.json");
    let mut index = read_graph_explorer_dataset_index(&index_path)?;
    index
        .datasets
        .retain(|dataset| dataset.dataset_id != record.dataset_id);
    index.default_dataset_id = Some(record.dataset_id.clone());
    index.datasets.push(record);
    sort_graph_explorer_dataset_records(&mut index.datasets);
    fs::write(&index_path, json_body(&index)?.as_bytes()).map_err(io_error)
}

fn read_graph_explorer_dataset_index(
    index_path: &Path,
) -> Result<GraphExplorerDatasetIndex, GraphExplorerError> {
    if !index_path.exists() {
        return Ok(GraphExplorerDatasetIndex {
            schema_version: GRAPH_EXPLORER_DATASET_INDEX_SCHEMA_VERSION.into(),
            default_dataset_id: None,
            datasets: Vec::new(),
        });
    }
    let body = fs::read_to_string(index_path).map_err(io_error)?;
    let mut index = serde_json::from_str::<GraphExplorerDatasetIndex>(&body).map_err(|error| {
        GraphExplorerError::Serialization {
            reason: error.to_string(),
        }
    })?;
    sort_graph_explorer_dataset_records(&mut index.datasets);
    Ok(index)
}

fn sort_graph_explorer_dataset_records(records: &mut [GraphExplorerDatasetRecord]) {
    records.sort_by(|left, right| {
        left.created_order_key
            .cmp(&right.created_order_key)
            .then_with(|| left.dataset_id.cmp(&right.dataset_id))
    });
}

fn graph_explorer_dataset_id(
    snapshot: &GraphExplorerSnapshot,
) -> Result<String, GraphExplorerError> {
    let raw_id = graph_dataset_id_override().unwrap_or_else(|| {
        let source = snapshot
            .source_commit_or_run_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("diagnostic-artifact");
        let source = sanitize_graph_explorer_dataset_component(source);
        let snapshot_prefix = snapshot.snapshot_id.chars().take(12).collect::<String>();
        format!("{source}--{snapshot_prefix}")
    });
    let dataset_id = sanitize_graph_explorer_dataset_id(&raw_id);
    if validate_graph_explorer_dataset_id(&dataset_id) {
        Ok(dataset_id)
    } else {
        Err(GraphExplorerError::InvalidDatasetId { dataset_id })
    }
}

fn graph_dataset_id_override() -> Option<String> {
    env::var(GRAPH_DATASET_ID_OVERRIDE_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn graph_source_run_id_override() -> Option<String> {
    env::var(GRAPH_SOURCE_RUN_ID_OVERRIDE_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn sanitize_graph_explorer_dataset_component(value: &str) -> String {
    let component = sanitize_graph_explorer_dataset_id(value);
    if component.is_empty() {
        "diagnostic-artifact".into()
    } else {
        component
    }
}

fn sanitize_graph_explorer_dataset_id(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(80));
    for character in value.to_ascii_lowercase().chars() {
        let next = if character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '.'
            || character == '_'
            || character == '-'
        {
            character
        } else {
            '-'
        };
        if output.len() < 80 {
            output.push(next);
        }
    }
    let trimmed = output
        .trim_matches(|character: char| !character.is_ascii_alphanumeric())
        .to_owned();
    if trimmed.is_empty() {
        "diagnostic-artifact".into()
    } else {
        trimmed
    }
}

fn validate_graph_explorer_dataset_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 80 {
        return false;
    }
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    characters.all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '.'
            || character == '_'
            || character == '-'
    })
}

fn graph_explorer_dataset_label(snapshot: &GraphExplorerSnapshot) -> String {
    let source = snapshot
        .source_commit_or_run_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("diagnostic artifact");
    format!(
        "{source} / {}",
        &snapshot.snapshot_id[..snapshot.snapshot_id.len().min(12)]
    )
}

fn graph_explorer_dataset_order_key(snapshot: &GraphExplorerSnapshot, dataset_id: &str) -> String {
    format!(
        "{}--{}--{}",
        snapshot
            .source_commit_or_run_id
            .as_deref()
            .unwrap_or("diagnostic-artifact"),
        snapshot.snapshot_id,
        dataset_id
    )
}

fn graph_explorer_dataset_bundle_hash(
    artifact_hashes: &GraphExplorerDatasetArtifactHashes,
) -> Result<String, GraphExplorerError> {
    let bundle = GraphExplorerDatasetBundleHashInput {
        schema_version: GRAPH_EXPLORER_DATASET_BUNDLE_HASH_SCHEMA_VERSION,
        artifacts: BTreeMap::from([
            ("graph_explorer_summary.md", artifact_hashes.summary.clone()),
            (
                "node_inspector_details.json",
                artifact_hashes.inspector.clone(),
            ),
            ("snapshot.json", artifact_hashes.snapshot.clone()),
        ]),
    };
    Ok(sha256_bytes_hex(json_body(&bundle)?.as_bytes()))
}

fn path_clean(path: &Path) -> PathBuf {
    path.components().collect()
}

fn repo_relative(path: &Path) -> String {
    let root = repo_root_path();
    let relative_path = path.strip_prefix(&root).unwrap_or(path);
    relative_path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn repo_root_path() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_dir.to_path_buf())
}

fn io_error(error: std::io::Error) -> GraphExplorerError {
    GraphExplorerError::Io {
        reason: error.to_string(),
    }
}

#[derive(Debug, Serialize)]
struct SnapshotIdMaterial<'a> {
    generated_from: GraphExplorerGeneratedFrom,
    generation_mode: GraphExplorerGenerationMode,
    source_truth_level: GraphSourceTruthLevel,
    source_commit_or_run_id: Option<&'a str>,
    node_ids: &'a [&'a str],
    edge_ids: &'a [&'a str],
}

#[cfg(test)]
mod tests {
    use exo_core::Hash256;

    use super::*;

    fn h(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn reset_dataset_test_dir(name: &str) -> PathBuf {
        let path = repo_root_path()
            .join("target")
            .join("dagdb")
            .join("graph_explorer_dataset_tests")
            .join(name);
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove dataset test dir");
        }
        fs::create_dir_all(&path).expect("create dataset test dir");
        path
    }

    fn node(byte: u8, kind: MemoryNodeKind, style: MemoryGraphStyle) -> MemoryGraphNode {
        MemoryGraphNode {
            memory_id: h(byte),
            node_kind: kind,
            graph_style: style,
        }
    }

    fn edge(from: u8, to: u8) -> MemoryGraphEdge {
        MemoryGraphEdge::new(
            "tenant-a".into(),
            "namespace-a".into(),
            h(from),
            h(to),
            MemoryEdgeKind::DependsOn,
            MemoryGraphStyle::DependencyDag,
            Some(h(0xee)),
        )
        .expect("edge")
    }

    fn graph_input() -> GraphExplorerExportInput {
        GraphExplorerExportInput {
            tenant_id: Some("tenant-a".into()),
            namespace: Some("namespace-a".into()),
            active_graph_style: MemoryGraphStyle::DependencyDag,
            source_truth_level: GraphSourceTruthLevel::ActualStoredDag,
            source_commit_or_run_id: Some("test-run".into()),
            nodes: vec![
                node(
                    1,
                    MemoryNodeKind::Canonical,
                    MemoryGraphStyle::DependencyDag,
                ),
                node(2, MemoryNodeKind::Summary, MemoryGraphStyle::DependencyDag),
            ],
            edges: vec![edge(1, 2)],
            source_graph_view_ids: vec!["view-1".into()],
            source_receipt_ids: vec!["receipt-1".into()],
        }
    }

    #[test]
    fn graph_explorer_contract_covers_all_graph_styles() {
        assert_eq!(all_graph_styles().len(), 8);
        assert!(all_graph_styles().contains(&MemoryGraphStyle::SimilarityOverlayGraph));
        assert_eq!(all_source_truth_levels().len(), 6);
        assert!(
            all_source_truth_levels()
                .contains(&GraphSourceTruthLevel::ApprovedLiveExportEmptyScope)
        );
    }

    #[test]
    fn graph_explorer_contract_defaults_are_report_file_safe() {
        let snapshot = unavailable_graph_explorer_snapshot("baseline").expect("snapshot");
        assert_eq!(
            snapshot.source_truth_level,
            GraphSourceTruthLevel::ConceptualUnavailableFallback
        );
        assert_eq!(
            snapshot.generation_mode,
            GraphExplorerGenerationMode::UnavailableConceptualFallback
        );
        assert!(!snapshot.source_is_live_db_export);
        assert!(!snapshot.permissions.raw_content_allowed);
        assert!(snapshot.nodes.is_empty());
        assert!(snapshot.edges.is_empty());
        assert!(snapshot.graph_export_not_available);
    }

    #[test]
    fn graph_snapshot_records_source_mode() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        assert_eq!(
            snapshot.source_truth_level,
            GraphSourceTruthLevel::ActualStoredDag
        );
        assert_eq!(
            snapshot.source_mode,
            GraphExplorerSourceMode::ApprovedReadOnlyLiveExport
        );
        assert!(snapshot.source_description.contains("actual stored DAG"));
        assert_eq!(snapshot.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(snapshot.namespace.as_deref(), Some("namespace-a"));
    }

    #[test]
    fn stored_dag_label_only_for_actual_stored_dag() {
        let generated = GraphSourceTruthLevel::GeneratedGraphArtifact;
        let context_packet = GraphSourceTruthLevel::DiagnosticContextPacketArtifact;
        let conceptual = GraphSourceTruthLevel::ConceptualUnavailableFallback;
        let context_packet_description = source_fields(context_packet).3;
        assert!(!source_fields(generated).3.contains("actual stored DAG"));
        assert!(context_packet_description.contains("not the full stored DAG"));
        assert!(!context_packet_description.contains("actual stored DAG"));
        assert!(!context_packet_description.contains("stored DAG data"));
        assert!(!source_fields(conceptual).3.contains("stored DAG data"));
        assert!(
            source_fields(GraphSourceTruthLevel::ActualStoredDag)
                .3
                .contains("actual stored DAG")
        );
    }

    #[test]
    fn graph_explorer_report_file_mode_opens_no_db_connection() {
        let snapshot = unavailable_graph_explorer_snapshot("no-db").expect("snapshot");
        assert_eq!(snapshot.permissions.source_mode, "report_file");
        assert!(!snapshot.permissions.live_db_export_allowed);
        assert!(snapshot.tenant_id.is_none());
        assert!(snapshot.namespace.is_none());
    }

    #[test]
    fn graph_explorer_live_export_blocked_without_approval() {
        let env = BTreeMap::from([(GRAPH_EXPLORER_DATABASE_URL_ENV.into(), "redacted".into())]);
        let request = LiveGraphExportRequest {
            env: &env,
            tenant_id: Some("tenant-a"),
            namespace: Some("namespace-a"),
        };
        assert_eq!(
            validate_live_export_request(&request),
            Err(GraphExplorerError::LiveExportNotApproved)
        );
    }

    #[test]
    fn graph_explorer_requires_tenant_namespace_for_live_export() {
        let env = BTreeMap::from([
            (GRAPH_EXPLORER_DATABASE_URL_ENV.into(), "redacted".into()),
            (LIVE_EXPORT_APPROVAL_ENV.into(), "true".into()),
        ]);
        let missing_tenant = LiveGraphExportRequest {
            env: &env,
            tenant_id: None,
            namespace: Some("namespace-a"),
        };
        let missing_namespace = LiveGraphExportRequest {
            env: &env,
            tenant_id: Some("tenant-a"),
            namespace: None,
        };
        assert_eq!(
            validate_live_export_request(&missing_tenant),
            Err(GraphExplorerError::LiveExportTenantIdMissing)
        );
        assert_eq!(
            validate_live_export_request(&missing_namespace),
            Err(GraphExplorerError::LiveExportNamespaceMissing)
        );
    }

    #[test]
    fn graph_explorer_applies_node_edge_limits() {
        let mut input = graph_input();
        input.nodes = (0u8..=250u8)
            .map(|index| {
                node(
                    index,
                    MemoryNodeKind::Summary,
                    MemoryGraphStyle::DependencyDag,
                )
            })
            .chain((0u8..=250u8).map(|index| {
                node(
                    index,
                    MemoryNodeKind::Concept,
                    MemoryGraphStyle::CanonicalMemoryGraph,
                )
            }))
            .collect();
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert_eq!(snapshot.nodes.len(), 500);
        assert!(
            snapshot
                .warnings
                .contains(&GRAPH_EXPLORER_LIMIT_WARNING.into())
        );
        assert!(snapshot.summaries.limit_applied);
    }

    #[test]
    fn graph_explorer_artifact_hash_is_deterministic() {
        let first = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let second = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_eq!(first.artifact_hash, second.artifact_hash);
    }

    #[test]
    fn graph_explorer_artifact_writer_replaces_reader_visible_json_atomically() {
        let source = include_str!("graph_explorer.rs");
        let direct_snapshot_write = ["fs::write", "(&snapshot_path"].join("");
        let direct_inspector_write = ["fs::write", "(&inspector_path"].join("");
        assert!(source.contains("atomic_write_artifact(&snapshot_path"));
        assert!(source.contains("atomic_write_artifact(&inspector_path"));
        assert!(!source.contains(&direct_snapshot_write));
        assert!(!source.contains(&direct_inspector_write));
    }

    #[test]
    fn graph_explorer_source_artifact_hash_uses_sha256_file_bytes() {
        assert_eq!(
            sha256_bytes_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_bytes_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn graph_explorer_artifact_missing_sources_not_verified() {
        let snapshot = unavailable_graph_explorer_snapshot("missing").expect("snapshot");
        assert!(snapshot.source_artifact_hashes.is_empty());
        assert!(snapshot.source_graph_view_hashes.is_empty());
        assert!(snapshot.source_receipt_hashes.is_empty());
        assert_eq!(
            snapshot.source_unavailable_reason.as_deref(),
            Some(GRAPH_EXPORT_NOT_AVAILABLE)
        );
    }

    #[test]
    fn graph_explorer_unavailable_does_not_fabricate_nodes() {
        let snapshot = unavailable_graph_explorer_snapshot("missing").expect("snapshot");
        assert!(snapshot.nodes.is_empty());
        assert!(snapshot.edges.is_empty());
        assert_eq!(
            snapshot.source_truth_level,
            GraphSourceTruthLevel::ConceptualUnavailableFallback
        );
    }

    #[test]
    fn graph_explorer_artifacts_generate_under_target() {
        let _guard = GRAPH_EXPLORER_TARGET_LOCK
            .lock()
            .expect("graph explorer target lock should not be poisoned");
        let artifacts = generate_unavailable_graph_explorer_artifacts("graph-explorer-test")
            .expect("artifacts");
        assert_eq!(artifacts.snapshot_path, GRAPH_EXPLORER_SNAPSHOT_PATH);
        assert_eq!(artifacts.inspector_path, GRAPH_EXPLORER_INSPECTOR_PATH);
        assert_eq!(artifacts.summary_path, GRAPH_EXPLORER_SUMMARY_PATH);
        let root = repo_root_path();
        assert!(root.join(GRAPH_EXPLORER_SNAPSHOT_PATH).exists());
        assert!(root.join(GRAPH_EXPLORER_INSPECTOR_PATH).exists());
        assert!(root.join(GRAPH_EXPLORER_SUMMARY_PATH).exists());
    }

    #[test]
    fn graph_explorer_non_root_artifact_write_does_not_create_dataset_index() {
        let target_dir = reset_dataset_test_dir("non-root-artifact-write");
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let inspector = inspector_details_for_snapshot(&snapshot);

        write_graph_explorer_artifacts(&snapshot, &inspector, &target_dir).expect("artifacts");

        assert!(target_dir.join("snapshot.json").exists());
        assert!(!target_dir.join("index.json").exists());
    }

    #[test]
    fn graph_explorer_diagnostic_artifacts_generate_under_target() {
        let _guard = GRAPH_EXPLORER_TARGET_LOCK
            .lock()
            .expect("graph explorer target lock should not be poisoned");
        let artifacts =
            generate_diagnostic_context_graph_explorer_artifacts("diagnostic-graph-capture")
                .expect("artifacts");
        assert_eq!(artifacts.snapshot_path, GRAPH_EXPLORER_SNAPSHOT_PATH);
        assert_eq!(artifacts.inspector_path, GRAPH_EXPLORER_INSPECTOR_PATH);
        assert_eq!(artifacts.summary_path, GRAPH_EXPLORER_SUMMARY_PATH);
        let root = repo_root_path();
        assert!(root.join(GRAPH_EXPLORER_SNAPSHOT_PATH).exists());
        assert!(root.join(GRAPH_EXPLORER_INSPECTOR_PATH).exists());
        assert!(root.join(GRAPH_EXPLORER_SUMMARY_PATH).exists());
    }

    #[test]
    fn graph_explorer_dataset_id_accepts_safe_values() {
        assert!(validate_graph_explorer_dataset_id("proof-a"));
        assert!(validate_graph_explorer_dataset_id("run_01.snapshot"));
        assert!(validate_graph_explorer_dataset_id("a"));
        assert!(validate_graph_explorer_dataset_id(&"a".repeat(80)));
    }

    #[test]
    fn graph_explorer_dataset_id_rejects_unsafe_values() {
        assert!(!validate_graph_explorer_dataset_id(""));
        assert!(!validate_graph_explorer_dataset_id("-proof"));
        assert!(!validate_graph_explorer_dataset_id("Proof-A"));
        assert!(!validate_graph_explorer_dataset_id("proof/a"));
        assert!(!validate_graph_explorer_dataset_id("proof\\a"));
        assert!(!validate_graph_explorer_dataset_id(&"a".repeat(81)));
    }

    #[test]
    fn graph_explorer_dataset_id_sanitizes_values() {
        assert_eq!(
            sanitize_graph_explorer_dataset_id(" Proof A / Capture "),
            "proof-a---capture"
        );
        assert_eq!(sanitize_graph_explorer_dataset_id("../secret"), "secret");
        assert_eq!(
            sanitize_graph_explorer_dataset_id("!!!"),
            "diagnostic-artifact"
        );
    }

    #[test]
    fn graph_explorer_dataset_helper_branch_vectors() {
        let target_dir = reset_dataset_test_dir("dataset-helper-branches");
        let missing_index =
            read_graph_explorer_dataset_index(&target_dir.join("missing-index.json"))
                .expect("missing index");
        assert_eq!(missing_index.default_dataset_id, None);
        assert!(missing_index.datasets.is_empty());

        assert!(matches!(
            ensure_dataset_dir_is_scoped(&target_dir, &target_dir.join("outside").join("proof")),
            Err(GraphExplorerError::InvalidDatasetId { .. })
        ));

        assert_eq!(
            sanitize_graph_explorer_dataset_component("Proof Dataset"),
            "proof-dataset"
        );
        assert_eq!(
            sanitize_graph_explorer_dataset_component("!!!"),
            "diagnostic-artifact"
        );
        assert_eq!(sanitize_graph_explorer_dataset_id("A.B_C-D/z"), "a.b_c-d-z");
        assert_eq!(
            sanitize_graph_explorer_dataset_id(&"a".repeat(90)).len(),
            80
        );
        assert!(validate_graph_explorer_dataset_id("1proof.a_b-c"));
        assert!(!validate_graph_explorer_dataset_id(".proof"));
        assert!(!validate_graph_explorer_dataset_id("proof/a"));

        let mut snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        snapshot.source_commit_or_run_id = None;
        snapshot.snapshot_id = "abcdef0123456789".into();
        let dataset_id = graph_explorer_dataset_id(&snapshot).expect("dataset id");
        assert_eq!(dataset_id, "diagnostic-artifact--abcdef012345");
        assert_eq!(
            graph_explorer_dataset_label(&snapshot),
            "diagnostic artifact / abcdef012345"
        );
        assert!(
            graph_explorer_dataset_order_key(&snapshot, &dataset_id)
                .starts_with("diagnostic-artifact--abcdef0123456789")
        );
    }

    #[test]
    fn graph_explorer_dataset_manifest_records_dataset() {
        let target_dir = reset_dataset_test_dir("manifest-records");
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let inspector = inspector_details_for_snapshot(&snapshot);
        let snapshot_body = json_body(&snapshot).expect("snapshot json");
        let inspector_body = json_body(&inspector).expect("inspector json");
        let summary_body = graph_explorer_summary_markdown(&snapshot);

        write_graph_explorer_dataset_artifacts(
            &snapshot,
            &snapshot_body,
            &inspector_body,
            &summary_body,
            &target_dir,
        )
        .expect("dataset artifacts");

        let index = read_graph_explorer_dataset_index(&target_dir.join("index.json"))
            .expect("dataset index");
        assert_eq!(
            index.schema_version,
            GRAPH_EXPLORER_DATASET_INDEX_SCHEMA_VERSION
        );
        assert_eq!(index.datasets.len(), 1);
        let record = &index.datasets[0];
        assert_eq!(
            index.default_dataset_id.as_deref(),
            Some(record.dataset_id.as_str())
        );
        assert_eq!(record.snapshot_id, snapshot.snapshot_id);
        assert_eq!(
            record.node_count,
            usize_to_u32_saturating(snapshot.nodes.len())
        );
        assert_eq!(
            record.edge_count,
            usize_to_u32_saturating(snapshot.edges.len())
        );
        assert_eq!(
            record.artifact_paths.snapshot,
            repo_relative(
                &target_dir
                    .join("datasets")
                    .join(&record.dataset_id)
                    .join("snapshot.json")
            )
        );
    }

    #[test]
    fn graph_explorer_dataset_manifest_preserves_and_sorts_records() {
        let target_dir = reset_dataset_test_dir("manifest-sorts");
        let mut first = get_graph_explorer_snapshot(&graph_input()).expect("first snapshot");
        first.source_commit_or_run_id = Some("proof-b".into());
        first.snapshot_id = "bbbbbbbbbbbb".into();
        let mut second = first.clone();
        second.source_commit_or_run_id = Some("proof-a".into());
        second.snapshot_id = "aaaaaaaaaaaa".into();

        for snapshot in [first, second] {
            let inspector = inspector_details_for_snapshot(&snapshot);
            write_graph_explorer_dataset_artifacts(
                &snapshot,
                &json_body(&snapshot).expect("snapshot json"),
                &json_body(&inspector).expect("inspector json"),
                &graph_explorer_summary_markdown(&snapshot),
                &target_dir,
            )
            .expect("dataset artifacts");
        }

        let index = read_graph_explorer_dataset_index(&target_dir.join("index.json"))
            .expect("dataset index");
        assert_eq!(index.datasets.len(), 2);
        assert_eq!(
            index
                .datasets
                .iter()
                .map(|record| record.snapshot_id.as_str())
                .collect::<Vec<_>>(),
            vec!["aaaaaaaaaaaa", "bbbbbbbbbbbb"]
        );
        assert_eq!(
            index.default_dataset_id.as_deref(),
            Some(index.datasets[0].dataset_id.as_str())
        );
    }

    #[test]
    fn graph_explorer_dataset_bundle_hash_matches_files() {
        let target_dir = reset_dataset_test_dir("bundle-hash");
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let inspector = inspector_details_for_snapshot(&snapshot);
        let snapshot_body = json_body(&snapshot).expect("snapshot json");
        let inspector_body = json_body(&inspector).expect("inspector json");
        let summary_body = graph_explorer_summary_markdown(&snapshot);
        write_graph_explorer_dataset_artifacts(
            &snapshot,
            &snapshot_body,
            &inspector_body,
            &summary_body,
            &target_dir,
        )
        .expect("dataset artifacts");

        let index = read_graph_explorer_dataset_index(&target_dir.join("index.json"))
            .expect("dataset index");
        let record = &index.datasets[0];
        let dataset_dir = target_dir.join("datasets").join(&record.dataset_id);
        let hashes = GraphExplorerDatasetArtifactHashes {
            snapshot: sha256_bytes_hex(
                &fs::read(dataset_dir.join("snapshot.json")).expect("snapshot"),
            ),
            inspector: sha256_bytes_hex(
                &fs::read(dataset_dir.join("node_inspector_details.json")).expect("inspector"),
            ),
            summary: sha256_bytes_hex(
                &fs::read(dataset_dir.join("graph_explorer_summary.md")).expect("summary"),
            ),
        };
        assert_eq!(record.artifact_hashes, hashes);
        assert_eq!(
            record.artifact_hash,
            graph_explorer_dataset_bundle_hash(&hashes).expect("bundle hash")
        );
    }

    #[test]
    fn graph_explorer_diagnostic_artifact_snapshot_has_graph_enabled_nodes() {
        let rows = vec![
            diagnostic_row(
                "t001",
                "long_context_dump",
                "neutral_long_context",
                0,
                8,
                64,
            ),
            diagnostic_row("t001", "dag_db_routing", "dag_db_routing_raw", 1, 5, 40),
            diagnostic_row(
                "t002",
                "governed_dag_db_routing",
                "governed_dagdb",
                1,
                5,
                36,
            ),
            diagnostic_row(
                "t003",
                "governed_dag_db_optimized",
                "governed_dagdb_optimized",
                1,
                4,
                32,
            ),
        ];
        let snapshot = diagnostic_context_graph_snapshot_from_rows(
            &rows,
            BTreeMap::from([(
                "target/dagdb/end_to_end_diagnostics/per_task_results.json".into(),
                "hash".into(),
            )]),
            Some("diagnostic-run".into()),
        )
        .expect("snapshot");
        assert_eq!(
            snapshot.source_truth_level,
            GraphSourceTruthLevel::DiagnosticContextPacketArtifact
        );
        assert_eq!(
            snapshot.export_result_status,
            GraphExplorerExportResultStatus::GeneratedRealGraphArtifact
        );
        assert!(!snapshot.nodes.is_empty());
        assert!(!snapshot.edges.is_empty());
        assert!(!snapshot.graph_export_not_available);
        assert!(
            snapshot
                .source_description
                .contains("not the full stored DAG")
        );
        assert!(
            snapshot
                .nodes
                .iter()
                .any(|node| node.label == "runner:dag_db_routing_raw")
        );
        assert!(
            snapshot
                .nodes
                .iter()
                .any(|node| node.label == "context packets:governed_dagdb")
        );
        assert!(
            !snapshot
                .nodes
                .iter()
                .any(|node| node.label.contains("neutral_long_context"))
        );
    }

    #[test]
    fn graph_explorer_diagnostic_snapshot_branch_vectors_cover_empty_optional_and_limits() {
        let neutral_rows = vec![diagnostic_row(
            "neutral-task",
            "neutral_long_context",
            "neutral_long_context",
            0,
            0,
            0,
        )];
        let unavailable =
            diagnostic_context_graph_snapshot_from_rows(&neutral_rows, BTreeMap::new(), None)
                .expect("unavailable diagnostic snapshot");
        assert!(unavailable.nodes.is_empty());
        assert!(
            unavailable
                .warnings
                .contains(&GRAPH_EXPORT_NOT_AVAILABLE.into())
        );

        let mut sparse_row = diagnostic_row("task-sparse", "dag_db_routing", "", 1, 0, 0);
        sparse_row.context_acquisition_profile = String::new();
        sparse_row.selected_refs = None;
        sparse_row.route_count = None;
        sparse_row.context_packet_tokens = None;
        sparse_row.quality_score_bp = None;
        sparse_row.citation_accuracy_bp = None;
        sparse_row.unsupported_claim_rate_bp = None;
        sparse_row.latency_ms = None;
        sparse_row.total_cost_micro_exo = None;

        assert!(is_graph_enabled_diagnostic_row(&sparse_row));
        assert_eq!(graph_runner_key(&sparse_row), "dag_db_routing");
        let metadata = diagnostic_task_metadata(&sparse_row);
        assert!(metadata.contains(&"context_profile:not_available".into()));
        assert!(
            !metadata
                .iter()
                .any(|item| item.starts_with("quality_score_bp:"))
        );

        let mut edges = Vec::new();
        let mut edge_keys = BTreeSet::new();
        add_diagnostic_edge(
            &mut edges,
            &mut edge_keys,
            "task-a",
            "runner-a",
            MemoryEdgeKind::UsedByRoute,
            MemoryGraphStyle::RoutingViewGraph,
        )
        .expect("first edge");
        add_diagnostic_edge(
            &mut edges,
            &mut edge_keys,
            "task-a",
            "runner-a",
            MemoryEdgeKind::UsedByRoute,
            MemoryGraphStyle::RoutingViewGraph,
        )
        .expect("duplicate edge");
        assert_eq!(edges.len(), 1);

        let mut rows = Vec::new();
        for index in 0u16..510u16 {
            let mut row = sparse_row.clone();
            row.task_id = format!("task-{index:03}");
            rows.push(row);
        }
        let limited_snapshot = diagnostic_context_graph_snapshot_from_rows(
            &rows,
            BTreeMap::new(),
            Some("limit-proof".into()),
        )
        .expect("limited diagnostic snapshot");
        assert!(limited_snapshot.limit_applied);
        assert!(
            limited_snapshot.nodes.len() <= usize::from(GraphExplorerLimits::default().max_nodes)
        );
        assert!(
            limited_snapshot.edges.len() <= usize::from(GraphExplorerLimits::default().max_edges)
        );
        assert_eq!(
            limited_snapshot.warnings,
            vec![
                "diagnostic_context_packet_artifact_not_full_stored_dag",
                GRAPH_EXPLORER_LIMIT_WARNING
            ]
        );
    }

    #[test]
    fn graph_explorer_generated_unavailable_snapshot_when_no_graph_data() {
        let snapshot = unavailable_graph_explorer_snapshot("no-graph-data").expect("snapshot");
        assert_eq!(snapshot.summaries.displayed_node_count, 0);
        assert_eq!(snapshot.summaries.displayed_edge_count, 0);
        assert!(
            snapshot
                .warnings
                .contains(&GRAPH_EXPORT_NOT_AVAILABLE.into())
        );
        assert_eq!(
            snapshot.source_truth_level,
            GraphSourceTruthLevel::ConceptualUnavailableFallback
        );
    }

    #[test]
    fn graph_explorer_generated_artifacts_are_deterministic() {
        let first = unavailable_graph_explorer_snapshot("deterministic").expect("snapshot");
        let second = unavailable_graph_explorer_snapshot("deterministic").expect("snapshot");
        assert_eq!(
            json_body(&first).expect("json"),
            json_body(&second).expect("json")
        );
    }

    #[test]
    fn graph_explorer_generated_artifacts_omit_secrets() {
        let snapshot = unavailable_graph_explorer_snapshot(
            "postgres://user:password@example.invalid/db?token=secret",
        )
        .expect("snapshot");
        let serialized = json_body(&snapshot).expect("json");
        assert!(!serialized.contains("postgres://"));
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("database_url"));
        assert!(!serialized.contains("connection_string"));
    }

    #[test]
    fn graph_explorer_snapshot_uses_real_graph_records() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        assert_eq!(
            snapshot.export_result_status,
            GraphExplorerExportResultStatus::GeneratedRealGraphArtifact
        );
        assert_eq!(snapshot.nodes.len(), 2);
        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(snapshot.displayed_node_count, 2);
        assert_eq!(snapshot.displayed_edge_count, 1);
        assert_eq!(snapshot.dropped_edge_count, 0);
        assert_eq!(snapshot.nodes[0].source_hash, Some(h(1).to_string()));
        assert_eq!(snapshot.edges[0].receipt_id, Some(h(0xee).to_string()));
    }

    #[test]
    fn graph_explorer_snapshot_uses_real_isolated_nodes_without_edges() {
        let mut input = graph_input();
        input.edges = Vec::new();
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert_eq!(
            snapshot.export_result_status,
            GraphExplorerExportResultStatus::GeneratedRealGraphArtifact
        );
        assert_eq!(snapshot.nodes.len(), 2);
        assert!(snapshot.edges.is_empty());
        assert!(!snapshot.graph_export_not_available);
        assert_eq!(snapshot.displayed_node_count, 2);
        assert_eq!(snapshot.displayed_edge_count, 0);
    }

    #[test]
    fn graph_explorer_inspector_returns_node_details() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let details = inspector_details_for_snapshot(&snapshot);
        let node_id = h(1).to_string();
        let detail = get_node_inspector_details(&details, &node_id).expect("detail");
        assert_eq!(detail.node.node_id, node_id);
        assert_eq!(detail.edge_details.len(), 1);
        assert_eq!(
            detail.raw_content_unavailable_reason,
            Some(RawContentUnavailableReason::RawPreviewNotApproved)
        );
    }

    #[test]
    fn graph_explorer_export_omits_database_urls_and_private_payloads() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let serialized = json_body(&snapshot).expect("json");
        assert!(!serialized.contains("DATABASE_URL"));
        assert!(!serialized.contains("connection_string"));
        assert!(!serialized.contains("private customer payload"));
        assert!(!serialized.contains("password"));
    }

    #[test]
    fn empty_live_export_not_labeled_actual_stored_dag() {
        let input = GraphExplorerExportInput {
            tenant_id: Some("tenant-a".into()),
            namespace: Some("namespace-a".into()),
            active_graph_style: MemoryGraphStyle::CanonicalMemoryGraph,
            source_truth_level: GraphSourceTruthLevel::ApprovedLiveExportEmptyScope,
            source_commit_or_run_id: Some("empty-scope".into()),
            nodes: Vec::new(),
            edges: Vec::new(),
            source_graph_view_ids: Vec::new(),
            source_receipt_ids: Vec::new(),
        };
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert_eq!(
            snapshot.source_truth_level,
            GraphSourceTruthLevel::ApprovedLiveExportEmptyScope
        );
        assert_ne!(
            snapshot.source_truth_level,
            GraphSourceTruthLevel::ActualStoredDag
        );
        assert_eq!(
            snapshot.export_result_status,
            GraphExplorerExportResultStatus::GeneratedEmptyScopedGraphArtifact
        );
        assert!(!snapshot.source_description.contains("actual stored DAG"));
    }

    #[test]
    fn empty_live_export_explains_zero_scoped_rows() {
        let input = GraphExplorerExportInput {
            tenant_id: Some("tenant-a".into()),
            namespace: Some("namespace-a".into()),
            active_graph_style: MemoryGraphStyle::CanonicalMemoryGraph,
            source_truth_level: GraphSourceTruthLevel::ApprovedLiveExportEmptyScope,
            source_commit_or_run_id: Some("empty-scope".into()),
            nodes: Vec::new(),
            edges: Vec::new(),
            source_graph_view_ids: Vec::new(),
            source_receipt_ids: Vec::new(),
        };
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert!(
            snapshot
                .source_description
                .contains("zero scoped graph rows")
        );
        assert_eq!(
            snapshot.source_unavailable_reason.as_deref(),
            Some("approved_live_export_returned_zero_scoped_graph_rows")
        );
        assert_eq!(snapshot.total_scoped_node_count, Some(0));
        assert_eq!(snapshot.total_scoped_edge_count, Some(0));
    }

    #[test]
    fn graph_explorer_export_errors_do_not_include_db_url() {
        let db_url = "postgres://user:password@example.invalid/db?token=secret";
        let errors = [
            GraphExplorerError::DatabaseConnectionFailed,
            GraphExplorerError::SchemaMismatch,
            GraphExplorerError::Io {
                reason: db_url.into(),
            },
            GraphExplorerError::Serialization {
                reason: db_url.into(),
            },
        ];
        for error in errors {
            let rendered = error.to_string();
            assert!(!rendered.contains("postgres://"));
            assert!(!rendered.contains("password"));
            assert!(!rendered.contains("token"));
            assert!(!rendered.contains("secret"));
            assert!(!graph_explorer_error_code(&error).contains("postgres://"));
        }
    }

    #[test]
    fn graph_explorer_connection_failure_uses_generic_error() {
        let error = GraphExplorerError::DatabaseConnectionFailed;
        assert_eq!(
            graph_explorer_error_code(&error),
            GRAPH_EXPLORER_DATABASE_CONNECTION_FAILED
        );
        assert_eq!(error.to_string(), GRAPH_EXPLORER_DATABASE_CONNECTION_FAILED);
    }

    #[test]
    fn graph_explorer_requires_live_export_env() {
        let env = BTreeMap::from([(LIVE_EXPORT_APPROVAL_ENV.into(), "true".into())]);
        let request = LiveGraphExportRequest {
            env: &env,
            tenant_id: Some("tenant-a"),
            namespace: Some("namespace-a"),
        };
        assert_eq!(
            validate_live_export_request(&request),
            Err(GraphExplorerError::LiveExportDatabaseUrlMissing)
        );
        assert_eq!(
            export_result_status_for_error(&GraphExplorerError::LiveExportDatabaseUrlMissing),
            GraphExplorerExportResultStatus::BlockedMissingEnv
        );
    }

    #[test]
    fn missing_approval_returns_blocked_result() {
        assert_eq!(
            export_result_status_for_error(&GraphExplorerError::LiveExportNotApproved),
            GraphExplorerExportResultStatus::BlockedMissingApproval
        );
    }

    #[test]
    fn schema_mismatch_returns_failed_schema_mismatch() {
        assert_eq!(
            graph_explorer_error_code(&GraphExplorerError::SchemaMismatch),
            GRAPH_EXPLORER_LIVE_EXPORT_FAILED_SCHEMA_MISMATCH
        );
        assert_eq!(
            export_result_status_for_error(&GraphExplorerError::SchemaMismatch),
            GraphExplorerExportResultStatus::FailedSchemaMismatch
        );
    }

    #[test]
    fn graph_explorer_live_export_uses_read_only_transaction() {
        let source = postgres_export_source();
        assert!(source.contains("BEGIN READ ONLY"));
        assert!(!source.contains("run_migrations"));
    }

    #[test]
    fn graph_explorer_live_export_does_not_call_init_pool() {
        let source = postgres_export_source();
        assert!(!source.contains("init_pool"));
    }

    #[test]
    fn graph_explorer_live_export_applies_query_limits() {
        let source = postgres_export_source();
        assert!(source.contains("GRAPH_EXPLORER_MAX_NODE_ROWS_READ"));
        assert!(source.contains("GRAPH_EXPLORER_MAX_EDGE_ROWS_READ"));
        assert!(source.contains("GRAPH_EXPLORER_MAX_GRAPH_VIEW_ROWS_READ"));
        assert_eq!(GRAPH_EXPLORER_MAX_NODE_ROWS_READ, 500);
        assert_eq!(GRAPH_EXPLORER_MAX_EDGE_ROWS_READ, 1000);
        assert_eq!(GRAPH_EXPLORER_MAX_GRAPH_VIEW_ROWS_READ, 100);
    }

    #[test]
    fn graph_explorer_live_export_sets_timeouts_when_supported() {
        let source = postgres_export_source();
        assert!(source.contains("statement_timeout"));
        assert!(source.contains("lock_timeout"));
    }

    #[test]
    fn graph_explorer_sql_uses_explicit_columns() {
        let source = postgres_export_source();
        assert!(source.contains("SELECT graph_node_id, tenant_id, namespace, memory_id"));
        assert!(source.contains("SELECT edge.graph_edge_id,"));
        assert!(source.contains("edge.graph_style,"));
        assert!(source.contains("AS is_tombstoned"));
        assert!(source.contains("SELECT view_id"));
    }

    #[test]
    fn graph_explorer_sql_does_not_select_raw_payload_fields() {
        let source = postgres_export_source().to_ascii_lowercase();
        let forbidden_terms = [
            "raw_payload",
            "private_payload",
            "raw_file",
            "file_contents",
            "payload_text",
            "raw_text",
            "file_content",
        ];
        for term in forbidden_terms {
            assert!(!source.contains(term), "forbidden term found: {term}");
        }
    }

    #[test]
    fn graph_explorer_export_does_not_use_select_star() {
        let source = postgres_export_source().to_ascii_lowercase();
        assert!(!source.contains("select *"));
        assert!(!source.contains("select\t*"));
        assert!(!source.contains("select\n*"));
    }

    #[test]
    fn graph_explorer_summary_omits_connection_material() {
        let mut input = graph_input();
        input.source_commit_or_run_id =
            Some("postgres://user:password@example.invalid/db?token=secret".into());
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        let summary = graph_explorer_summary_markdown(&snapshot);
        assert!(!summary.contains("postgres://"));
        assert!(!summary.contains("password"));
        assert!(!summary.contains("token"));
        assert!(!summary.contains("secret"));
    }

    #[test]
    fn graph_explorer_contract_validates_source_rows_and_edge_endpoints() {
        let source_node = GraphExplorerSourceNode {
            node_id: "node-a".into(),
            label: "Node A".into(),
            node_kind: MemoryNodeKind::Canonical,
            graph_style: MemoryGraphStyle::CanonicalMemoryGraph,
            catalog_path: vec!["domain".into()],
            status: GraphExplorerNodeStatus::Canonical,
            risk_class: Some("R1".into()),
            owner_id: Some("did:example:owner".into()),
            receipt_ids: vec!["receipt-a".into()],
            source_hash: Some("source-hash".into()),
            content_hash: Some("content-hash".into()),
            metadata_summary: vec!["safe metadata".into()],
        };
        let valid_edge = GraphExplorerSourceEdge {
            edge_id: "edge-a".into(),
            source_node_id: "node-a".into(),
            target_node_id: "node-a".into(),
            edge_kind: MemoryEdgeKind::DependsOn,
            graph_style: MemoryGraphStyle::DependencyDag,
            receipt_id: None,
            status: GraphExplorerEdgeStatus::Active,
            confidence_bp: Some(10_000),
        };
        assert_eq!(
            validate_graph_explorer_source_rows(
                std::slice::from_ref(&source_node),
                std::slice::from_ref(&valid_edge)
            ),
            Ok(())
        );

        let invalid_node = GraphExplorerSourceNode {
            node_id: String::new(),
            ..source_node.clone()
        };
        assert_eq!(
            validate_graph_explorer_source_rows(&[invalid_node], &[]),
            Err(GraphExplorerError::InvalidSourceRow {
                reason: "missing_node_id".into()
            })
        );

        let missing_label = GraphExplorerSourceNode {
            label: String::new(),
            ..source_node.clone()
        };
        assert_eq!(
            validate_graph_explorer_source_rows(&[missing_label], &[]),
            Err(GraphExplorerError::InvalidSourceRow {
                reason: "missing_node_label".into()
            })
        );

        let missing_edge_id = GraphExplorerSourceEdge {
            edge_id: String::new(),
            ..valid_edge.clone()
        };
        assert_eq!(
            validate_graph_explorer_source_rows(
                std::slice::from_ref(&source_node),
                &[missing_edge_id]
            ),
            Err(GraphExplorerError::InvalidSourceRow {
                reason: "missing_edge_id".into()
            })
        );

        let missing_source_endpoint = GraphExplorerSourceEdge {
            source_node_id: String::new(),
            ..valid_edge.clone()
        };
        assert_eq!(
            validate_graph_explorer_source_rows(
                std::slice::from_ref(&source_node),
                &[missing_source_endpoint]
            ),
            Err(GraphExplorerError::MissingEdgeEndpoint {
                edge_id: "edge-a".into()
            })
        );

        let missing_target_endpoint = GraphExplorerSourceEdge {
            target_node_id: String::new(),
            ..valid_edge.clone()
        };
        assert_eq!(
            validate_graph_explorer_source_rows(
                std::slice::from_ref(&source_node),
                &[missing_target_endpoint]
            ),
            Err(GraphExplorerError::MissingEdgeEndpoint {
                edge_id: "edge-a".into()
            })
        );

        let missing_source = GraphExplorerSourceEdge {
            source_node_id: "missing-node".into(),
            ..valid_edge.clone()
        };
        assert_eq!(
            validate_graph_explorer_source_rows(
                std::slice::from_ref(&source_node),
                &[missing_source]
            ),
            Err(GraphExplorerError::MissingEdgeEndpoint {
                edge_id: "edge-a".into()
            })
        );

        let missing_endpoint = GraphExplorerSourceEdge {
            target_node_id: "missing-node".into(),
            ..valid_edge
        };
        assert_eq!(
            validate_graph_explorer_source_rows(&[source_node], &[missing_endpoint]),
            Err(GraphExplorerError::MissingEdgeEndpoint {
                edge_id: "edge-a".into()
            })
        );
    }

    #[test]
    fn live_export_rejects_missing_tenant_id() {
        let env = BTreeMap::from([
            (GRAPH_EXPLORER_DATABASE_URL_ENV.into(), "redacted".into()),
            (LIVE_EXPORT_APPROVAL_ENV.into(), "true".into()),
        ]);
        let request = LiveGraphExportRequest {
            env: &env,
            tenant_id: None,
            namespace: Some("namespace-a"),
        };
        assert_eq!(
            validate_live_export_request(&request),
            Err(GraphExplorerError::LiveExportTenantIdMissing)
        );
    }

    #[test]
    fn live_export_rejects_missing_namespace() {
        let env = BTreeMap::from([
            (GRAPH_EXPLORER_DATABASE_URL_ENV.into(), "redacted".into()),
            (LIVE_EXPORT_APPROVAL_ENV.into(), "true".into()),
        ]);
        let request = LiveGraphExportRequest {
            env: &env,
            tenant_id: Some("tenant-a"),
            namespace: None,
        };
        assert_eq!(
            validate_live_export_request(&request),
            Err(GraphExplorerError::LiveExportNamespaceMissing)
        );
    }

    #[test]
    fn live_export_excludes_cross_tenant_nodes() {
        let same_scope = edge(1, 2);
        let cross_scope = MemoryGraphEdge::new(
            "tenant-b".into(),
            "namespace-a".into(),
            h(2),
            h(3),
            MemoryEdgeKind::DependsOn,
            MemoryGraphStyle::DependencyDag,
            None,
        )
        .expect("edge");
        let filtered =
            filter_live_export_edges("tenant-a", "namespace-a", &[same_scope, cross_scope]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tenant_id, "tenant-a");
    }

    #[test]
    fn report_file_mode_allows_null_tenant_namespace_with_label() {
        let snapshot = unavailable_graph_explorer_snapshot("report-file").expect("snapshot");
        assert!(snapshot.tenant_id.is_none());
        assert!(snapshot.namespace.is_none());
        assert_eq!(snapshot.permissions.source_mode, "report_file");
    }

    #[test]
    fn graph_explorer_reports_limit_warning() {
        let mut input = graph_input();
        input.edges = (0u16..=1000u16)
            .map(|index| {
                let target = if index % 2 == 0 { 1 } else { 2 };
                edge(1, target)
            })
            .collect();
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert!(snapshot.summaries.limit_applied);
        assert!(
            snapshot
                .warnings
                .contains(&GRAPH_EXPLORER_LIMIT_WARNING.into())
        );
    }

    #[test]
    fn graph_explorer_subdag_respects_depth_limit() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let subdag = get_subdag(&snapshot, &h(1).to_string(), 20);
        assert_eq!(
            subdag.drilldown.depth,
            snapshot.limits.max_depth_without_confirmation
        );
        assert_eq!(subdag.drilldown.mode, GraphExplorerDrilldownMode::Subdag);
        assert!(subdag.nodes.len() <= usize::from(snapshot.limits.max_nodes_per_expansion));
    }

    #[test]
    fn graph_explorer_subdag_keeps_focused_node_under_expansion_cap() {
        let mut input = graph_input();
        let focus = 0xff;
        input.nodes = (0u8..=254u8)
            .map(|byte| {
                node(
                    byte,
                    MemoryNodeKind::Summary,
                    MemoryGraphStyle::DependencyDag,
                )
            })
            .collect();
        input.nodes.push(node(
            focus,
            MemoryNodeKind::Canonical,
            MemoryGraphStyle::DependencyDag,
        ));
        input.edges = (0u8..=254u8).map(|byte| edge(focus, byte)).collect();
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        let focused_node_id = h(focus).to_string();
        let subdag = get_subdag(&snapshot, &focused_node_id, 1);
        assert!(subdag.nodes.len() <= usize::from(snapshot.limits.max_nodes_per_expansion));
        assert!(
            subdag
                .nodes
                .iter()
                .any(|node| node.node_id == focused_node_id),
            "focused node must stay in its own drill-down"
        );
        assert!(!subdag.edges.is_empty());
    }

    #[test]
    fn graph_explorer_artifact_records_provenance() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        assert_eq!(
            snapshot.source_commit_or_run_id.as_deref(),
            Some("test-run")
        );
        assert_eq!(snapshot.source_graph_view_ids, vec!["view-1"]);
        assert_eq!(snapshot.source_receipt_ids, vec!["receipt-1"]);
        assert!(snapshot.artifact_hash.is_some());
    }

    #[test]
    fn graph_export_summary_records_scope_and_counts() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let summary = graph_explorer_summary_markdown(&snapshot);
        assert!(summary.contains("export_result_status: GeneratedRealGraphArtifact"));
        assert!(summary.contains("query_scope_tenant_id: tenant-a"));
        assert!(summary.contains("query_scope_namespace: namespace-a"));
        assert!(summary.contains("displayed_node_count: 2"));
        assert!(summary.contains("total_scoped_node_count: 2"));
        assert!(summary.contains("displayed_edge_count: 1"));
        assert!(summary.contains("total_scoped_edge_count: 1"));
        assert!(summary.contains("limit_applied: false"));
    }

    #[test]
    fn graph_export_summary_omits_db_url() {
        let mut input = graph_input();
        input.source_commit_or_run_id =
            Some("postgres://user:password@example.invalid/db?token=secret".into());
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        let summary = graph_explorer_summary_markdown(&snapshot);
        assert!(!summary.contains("postgres://"));
        assert!(!summary.contains("password"));
        assert!(!summary.contains("token"));
        assert!(!summary.contains("secret"));
        assert!(!summary.contains("example.invalid"));
    }

    #[test]
    fn graph_export_records_dropped_edge_count() {
        let mut input = graph_input();
        input.edges = vec![edge(1, 2), edge(1, 3), edge(3, 2)];
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert_eq!(snapshot.displayed_edge_count, 1);
        assert_eq!(snapshot.total_scoped_edge_count, Some(3));
        assert_eq!(snapshot.dropped_edge_count, 2);
        assert!(graph_explorer_summary_markdown(&snapshot).contains("dropped_edge_count: 2"));
    }

    #[test]
    fn graph_export_records_schema_inventory_hash() {
        let mut snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        snapshot.schema_inventory_hash = Some("schema-hash".into());
        snapshot.source_column_set_hash = Some("column-hash".into());
        snapshot.source_table_names = vec![
            "dagdb_graph_edges".into(),
            "dagdb_graph_nodes".into(),
            "dagdb_graph_views".into(),
        ];
        let summary = graph_explorer_summary_markdown(&snapshot);
        assert!(summary.contains("schema_inventory_hash: schema-hash"));
        assert!(summary.contains("source_column_set_hash: column-hash"));
        assert!(summary.contains("dagdb_graph_nodes"));
        assert!(summary.contains("dagdb_graph_edges"));
    }

    #[test]
    fn graph_export_summary_records_source_artifact_hashes() {
        let mut snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        snapshot.source_artifact_hashes = BTreeMap::from([
            (
                GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH.into(),
                "per-task-sha256".into(),
            ),
            (
                GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH.into(),
                "silo-sha256".into(),
            ),
        ]);
        let summary = graph_explorer_summary_markdown(&snapshot);
        assert!(summary.contains(GRAPH_EXPLORER_DIAGNOSTIC_PER_TASK_PATH));
        assert!(summary.contains("per-task-sha256"));
        assert!(summary.contains(GRAPH_EXPLORER_DIAGNOSTIC_SILO_PATH));
        assert!(summary.contains("silo-sha256"));
    }

    #[test]
    fn graph_explorer_live_export_branch_vectors() {
        let approved_env = BTreeMap::from([
            (GRAPH_EXPLORER_DATABASE_URL_ENV.into(), "redacted".into()),
            (LIVE_EXPORT_APPROVAL_ENV.into(), "true".into()),
        ]);
        let approved = LiveGraphExportRequest {
            env: &approved_env,
            tenant_id: Some("tenant-a"),
            namespace: Some("namespace-a"),
        };
        assert_eq!(validate_live_export_request(&approved), Ok(()));

        let missing_database_env =
            BTreeMap::from([(LIVE_EXPORT_APPROVAL_ENV.into(), "true".into())]);
        let missing_database = LiveGraphExportRequest {
            env: &missing_database_env,
            tenant_id: Some("tenant-a"),
            namespace: Some("namespace-a"),
        };
        assert_eq!(
            validate_live_export_request(&missing_database),
            Err(GraphExplorerError::LiveExportDatabaseUrlMissing)
        );

        let empty_tenant = LiveGraphExportRequest {
            env: &approved_env,
            tenant_id: Some(""),
            namespace: Some("namespace-a"),
        };
        let empty_namespace = LiveGraphExportRequest {
            env: &approved_env,
            tenant_id: Some("tenant-a"),
            namespace: Some(""),
        };
        assert_eq!(
            validate_live_export_request(&empty_tenant),
            Err(GraphExplorerError::LiveExportTenantIdMissing)
        );
        assert_eq!(
            validate_live_export_request(&empty_namespace),
            Err(GraphExplorerError::LiveExportNamespaceMissing)
        );
    }

    #[test]
    fn graph_explorer_source_and_visual_label_branch_vectors() {
        let graph_view_fields = source_fields(GraphSourceTruthLevel::ApprovedReadOnlyGraphView);
        assert_eq!(graph_view_fields.0, GraphExplorerGeneratedFrom::GraphView);
        assert_eq!(
            graph_view_fields.1,
            GraphExplorerGenerationMode::ApprovedReadOnlyLiveExport
        );

        let generated_fields = source_fields(GraphSourceTruthLevel::GeneratedGraphArtifact);
        assert_eq!(
            generated_fields.1,
            GraphExplorerGenerationMode::ReportFileArtifact
        );
        let context_fields = source_fields(GraphSourceTruthLevel::DiagnosticContextPacketArtifact);
        assert!(context_fields.3.contains("task-specific context influence"));
        let unavailable_fields =
            source_fields(GraphSourceTruthLevel::ConceptualUnavailableFallback);
        assert_eq!(
            unavailable_fields.2,
            GraphExplorerSourceMode::UnavailableConceptualFallback
        );

        for style in all_graph_styles() {
            assert!(!graph_style_key(style).is_empty());
            assert!(!graph_style_label(style).is_empty());
        }
        assert_eq!(
            status_for_kind(MemoryNodeKind::Canonical),
            GraphExplorerNodeStatus::Canonical
        );
        assert_eq!(
            status_for_kind(MemoryNodeKind::DuplicateReference),
            GraphExplorerNodeStatus::Duplicate
        );
        assert_eq!(
            status_for_kind(MemoryNodeKind::Supersession),
            GraphExplorerNodeStatus::Superseded
        );
        assert_eq!(
            status_for_kind(MemoryNodeKind::Contradiction),
            GraphExplorerNodeStatus::Contradicted
        );
        assert_eq!(
            status_for_kind(MemoryNodeKind::Raw),
            GraphExplorerNodeStatus::Active
        );
    }

    #[test]
    fn graph_explorer_snapshot_branch_vectors_filter_edges_and_redact_sources() {
        let mut input = graph_input();
        input.source_truth_level = GraphSourceTruthLevel::GeneratedGraphArtifact;
        input.source_commit_or_run_id = Some("postgres://user:password@example.invalid/db".into());
        input.source_graph_view_ids = vec!["view-b".into(), "view-a".into(), "view-a".into()];
        input.source_receipt_ids = vec!["receipt-b".into(), "receipt-a".into(), "receipt-a".into()];
        input.edges = vec![edge(1, 2), edge(1, 3), edge(3, 2)];

        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert_eq!(
            snapshot.generation_mode,
            GraphExplorerGenerationMode::ReportFileArtifact
        );
        assert_eq!(snapshot.permissions.source_mode, "report_file");
        assert!(snapshot.source_is_generated_artifact);
        assert!(!snapshot.source_is_live_db_export);
        assert_eq!(snapshot.edges.len(), 1);
        assert!(!snapshot.graph_export_not_available);
        assert_eq!(
            snapshot.source_commit_or_run_id.as_deref(),
            Some("redacted_source_commit_or_run_id")
        );
        assert_eq!(snapshot.source_graph_view_ids, vec!["view-a", "view-b"]);
        assert_eq!(snapshot.source_receipt_ids, vec!["receipt-a", "receipt-b"]);
    }

    #[test]
    fn graph_explorer_snapshot_and_summary_empty_branch_vectors() {
        let input = GraphExplorerExportInput {
            tenant_id: None,
            namespace: None,
            active_graph_style: MemoryGraphStyle::CanonicalMemoryGraph,
            source_truth_level: GraphSourceTruthLevel::GeneratedGraphArtifact,
            source_commit_or_run_id: None,
            nodes: Vec::new(),
            edges: Vec::new(),
            source_graph_view_ids: Vec::new(),
            source_receipt_ids: Vec::new(),
        };
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        assert!(snapshot.graph_export_not_available);
        assert_eq!(
            snapshot.export_result_status,
            GraphExplorerExportResultStatus::GeneratedUnavailableArtifact
        );
        assert!(
            snapshot
                .warnings
                .contains(&GRAPH_EXPORT_NOT_AVAILABLE.into())
        );
        assert_eq!(
            export_result_status_for(GraphSourceTruthLevel::GeneratedGraphArtifact, 0),
            GraphExplorerExportResultStatus::GeneratedUnavailableArtifact
        );
        assert_eq!(option_label(None), "not_available");
        assert_eq!(option_u32_label(None), "not_available");
        assert_eq!(list_label(&[]), "none");
        assert_eq!(map_label(&BTreeMap::new()), "none");
        let summary = graph_explorer_summary_markdown(&snapshot);
        assert!(summary.contains("source_table_names: none"));
        assert!(summary.contains("source_artifact_hashes: none"));
        assert!(summary.contains("source_graph_view_ids: none"));
    }

    #[test]
    fn graph_explorer_inspector_branch_vectors_cover_source_target_and_empty_edges() {
        let mut input = graph_input();
        input.nodes.push(node(
            3,
            MemoryNodeKind::Related,
            MemoryGraphStyle::SimilarityOverlayGraph,
        ));
        let snapshot = get_graph_explorer_snapshot(&input).expect("snapshot");
        let details = inspector_details_for_snapshot(&snapshot);

        let source_detail =
            get_node_inspector_details(&details, &h(1).to_string()).expect("source detail");
        let target_detail =
            get_node_inspector_details(&details, &h(2).to_string()).expect("target detail");
        let isolated_detail =
            get_node_inspector_details(&details, &h(3).to_string()).expect("isolated detail");

        assert_eq!(source_detail.edge_details.len(), 1);
        assert_eq!(target_detail.edge_details.len(), 1);
        assert!(isolated_detail.edge_details.is_empty());
    }

    #[test]
    fn graph_explorer_subdag_branch_vectors_include_parent_neighborhood() {
        let snapshot = get_graph_explorer_snapshot(&graph_input()).expect("snapshot");
        let focused_node_id = h(2).to_string();
        let subdag = get_subdag(&snapshot, &focused_node_id, 1);
        assert_eq!(subdag.nodes.len(), 2);
        assert_eq!(subdag.edges.len(), 1);
        assert_eq!(
            subdag.drilldown.focused_node_id.as_deref(),
            Some(focused_node_id.as_str())
        );
    }

    #[test]
    fn graph_explorer_filter_and_redaction_branch_vectors() {
        let same_scope = edge(1, 2);
        let wrong_namespace = MemoryGraphEdge::new(
            "tenant-a".into(),
            "namespace-b".into(),
            h(2),
            h(3),
            MemoryEdgeKind::DependsOn,
            MemoryGraphStyle::DependencyDag,
            None,
        )
        .expect("edge");
        let filtered =
            filter_live_export_edges("tenant-a", "namespace-a", &[same_scope, wrong_namespace]);
        assert_eq!(filtered.len(), 1);

        assert_eq!(sanitize_source_commit_or_run_id("safe-run"), "safe-run");
        assert_eq!(
            sanitize_source_commit_or_run_id("contains-password"),
            "redacted_source_commit_or_run_id"
        );
        assert_eq!(
            sanitize_source_commit_or_run_id("contains-secret"),
            "redacted_source_commit_or_run_id"
        );
        assert_eq!(
            sanitize_source_commit_or_run_id("contains-token"),
            "redacted_source_commit_or_run_id"
        );
        assert_eq!(
            sanitize_source_commit_or_run_id("contains-database_url"),
            "redacted_source_commit_or_run_id"
        );
        assert_eq!(
            sanitize_source_commit_or_run_id("contains-connection_string"),
            "redacted_source_commit_or_run_id"
        );
    }

    #[test]
    fn raw_preview_branch_vectors_cover_absent_success_and_char_boundary() {
        let env = raw_env_approved();
        let absent = raw_preview_request(&env, None);
        let absent_preview = get_node_raw_content_preview(&absent, &GraphExplorerLimits::default());
        assert_eq!(
            absent_preview.unavailable_reason,
            Some(RawContentUnavailableReason::ArtifactUnavailable)
        );

        let safe = raw_preview_request(&env, Some("safe line\n"));
        let safe_preview = get_node_raw_content_preview(&safe, &GraphExplorerLimits::default());
        assert_eq!(safe_preview.preview_text.as_deref(), Some("safe line\n"));
        assert!(!safe_preview.truncated);
        assert_eq!(safe_preview.unavailable_reason, None);

        let tight_limits = GraphExplorerLimits {
            max_preview_bytes: 5,
            ..Default::default()
        };
        let unicode = raw_preview_request(&env, Some("ééé"));
        let unicode_preview = get_node_raw_content_preview(&unicode, &tight_limits);
        assert_eq!(unicode_preview.preview_text.as_deref(), Some("éé"));
        assert!(unicode_preview.truncated);
        assert_eq!(
            unicode_preview.unavailable_reason,
            Some(RawContentUnavailableReason::PreviewSizeLimitApplied)
        );

        let byte_boundary_limits = GraphExplorerLimits {
            max_preview_bytes: 4,
            ..Default::default()
        };
        let (byte_boundary_preview, byte_boundary_bytes, _, byte_boundary_truncated) =
            limited_text_preview("abc\nx", &byte_boundary_limits);
        assert_eq!(byte_boundary_preview, "abc\n");
        assert_eq!(byte_boundary_bytes, 4);
        assert!(byte_boundary_truncated);

        let line_boundary_limits = GraphExplorerLimits {
            max_preview_bytes: 4,
            max_preview_lines: 1,
            ..Default::default()
        };
        let (line_boundary_preview, _, line_boundary_lines, line_boundary_truncated) =
            limited_text_preview("one\ntwo\n", &line_boundary_limits);
        assert_eq!(line_boundary_preview, "one\n");
        assert_eq!(line_boundary_lines, 1);
        assert!(line_boundary_truncated);
    }

    fn raw_env_approved() -> BTreeMap<String, String> {
        BTreeMap::from([(RAW_PREVIEW_APPROVAL_ENV.into(), "true".into())])
    }

    fn raw_preview_request<'a>(
        env: &'a BTreeMap<String, String>,
        content: Option<&'a str>,
    ) -> GraphExplorerRawContentPreviewRequest<'a> {
        GraphExplorerRawContentPreviewRequest {
            env,
            raw_content_allowed: true,
            browser_safe_payload: true,
            private_payload: false,
            binary_content: false,
            content_kind: GraphExplorerContentKind::RawContent,
            content,
        }
    }

    fn diagnostic_row(
        task_id: &str,
        runner: &str,
        diagnostic_label: &str,
        route_count: u32,
        selected_refs: u32,
        context_packet_tokens: u32,
    ) -> DiagnosticGraphTaskRow {
        DiagnosticGraphTaskRow {
            fixture_id: "dagdb_mvp_minimum_v1".into(),
            task_id: task_id.into(),
            task_type: "approval_required".into(),
            runner: runner.into(),
            diagnostic_label: diagnostic_label.into(),
            context_acquisition_profile: "graph_routing_context_packet".into(),
            selected_refs: Some(selected_refs),
            route_count: Some(route_count),
            context_packet_tokens: Some(context_packet_tokens),
            quality_score_bp: Some(8500),
            citation_accuracy_bp: Some(9500),
            unsupported_claim_rate_bp: Some(300),
            latency_ms: Some(10),
            total_cost_micro_exo: Some(100),
        }
    }

    fn postgres_export_source() -> String {
        format!(
            "{}\n{}",
            include_str!("graph_explorer_postgres.rs"),
            include_str!("bin/dagdb-graph-explorer-export.rs")
        )
    }

    #[test]
    fn raw_content_denied_by_default() {
        let env = BTreeMap::new();
        let request = raw_preview_request(&env, Some("safe content"));
        let preview = get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert_eq!(
            preview.unavailable_reason,
            Some(RawContentUnavailableReason::RawPreviewNotApproved)
        );
        assert!(preview.preview_text.is_none());
    }

    #[test]
    fn raw_preview_blocked_without_approval_env() {
        let env = BTreeMap::from([(RAW_PREVIEW_APPROVAL_ENV.into(), "false".into())]);
        let request = raw_preview_request(&env, Some("safe content"));
        let preview = get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert_eq!(
            preview.unavailable_reason,
            Some(RawContentUnavailableReason::RawPreviewNotApproved)
        );
    }

    #[test]
    fn raw_preview_requires_node_permission_and_browser_safe_payload() {
        let env = raw_env_approved();
        let mut request = raw_preview_request(&env, Some("safe content"));
        request.raw_content_allowed = false;
        let denied_without_node_permission =
            get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert_eq!(
            denied_without_node_permission.unavailable_reason,
            Some(RawContentUnavailableReason::PermissionDenied)
        );

        request.raw_content_allowed = true;
        request.browser_safe_payload = false;
        let denied_without_safe_payload =
            get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert_eq!(
            denied_without_safe_payload.unavailable_reason,
            Some(RawContentUnavailableReason::PermissionDenied)
        );
    }

    #[test]
    fn raw_preview_env_does_not_allow_private_payload() {
        let env = raw_env_approved();
        let mut request = raw_preview_request(&env, Some("private customer payload"));
        request.private_payload = true;
        let preview = get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert_eq!(
            preview.unavailable_reason,
            Some(RawContentUnavailableReason::PrivatePayloadNotExposed)
        );
        assert!(preview.preview_text.is_none());
    }

    #[test]
    fn raw_content_preview_requires_explicit_permission() {
        let env = raw_env_approved();
        let mut request = raw_preview_request(&env, Some("safe content"));
        request.raw_content_allowed = false;
        let preview = get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert_eq!(
            preview.unavailable_reason,
            Some(RawContentUnavailableReason::PermissionDenied)
        );
    }

    #[test]
    fn raw_content_preview_is_size_limited() {
        let env = raw_env_approved();
        let content = (0..130)
            .map(|index| format!("line-{index:03}-abcdefghijklmnopqrstuvwxyz"))
            .collect::<Vec<_>>()
            .join("\n");
        let request = raw_preview_request(&env, Some(&content));
        let preview = get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert!(preview.truncated);
        assert!(preview.preview_bytes <= GraphExplorerLimits::default().max_preview_bytes);
        assert!(preview.preview_lines <= GraphExplorerLimits::default().max_preview_lines);
        assert_eq!(
            preview.unavailable_reason,
            Some(RawContentUnavailableReason::PreviewSizeLimitApplied)
        );
    }

    #[test]
    fn binary_content_shows_metadata_only() {
        let env = raw_env_approved();
        let mut request = raw_preview_request(&env, Some("binary-metadata"));
        request.binary_content = true;
        let preview = get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        assert!(preview.binary_metadata_only);
        assert!(preview.preview_text.is_none());
        assert_eq!(
            preview.unavailable_reason,
            Some(RawContentUnavailableReason::BinaryPreviewNotSupported)
        );
    }

    #[test]
    fn private_payload_never_renders() {
        let env = raw_env_approved();
        let mut request = raw_preview_request(&env, Some("private customer payload"));
        request.private_payload = true;
        let preview = get_node_raw_content_preview(&request, &GraphExplorerLimits::default());
        let serialized = json_body(&preview).expect("json");
        assert!(!serialized.contains("private customer payload"));
        assert_eq!(
            preview.unavailable_reason,
            Some(RawContentUnavailableReason::PrivatePayloadNotExposed)
        );
    }
}

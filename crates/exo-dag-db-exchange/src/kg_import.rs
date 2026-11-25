//! Dry-run KG import report contracts shared by persisted adapter tests.
//!
//! This module does not open database connections. The feature-gated Postgres
//! adapter consumes these validated shapes in `postgres::kg_import`.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::Hash256;
use exo_dag_db_api::{MemoryGraphStyle, SafeMetadata};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;

use crate::{
    hash::{parse_hash256_hex, stable_hash_parts},
    layer_creation_policy::LAYER_CREATION_MAX_DEPTH,
    layered_hygiene::LayerHygieneEdgeState,
    layered_placement::{
        deterministic_layer_edge_id, deterministic_layer_id, deterministic_layer_membership_id,
    },
};

/// Dry-run importer report schema accepted by the persisted adapter.
pub const KG_IMPORT_DRY_RUN_REPORT_SCHEMA: &str = "dagdb_kg_dry_run_import_report_v1";
/// Source candidate schema expected by the dry-run report.
pub const KG_IMPORT_CANDIDATES_SCHEMA: &str = "dagdb_markdown_kg_import_candidates_v1";
/// Persisted import route name used for idempotency.
pub const KG_IMPORT_PERSISTED_ROUTE_NAME: &str = "dagdb.kg_import.persisted.v1";
/// Environment variable used by Postgres-gated tests and helper entrypoints.
pub const KG_IMPORT_DATABASE_URL_ENV: &str = "EXO_DAGDB_TEST_DATABASE_URL";
/// Persisted import summary schema emitted by the repository adapter.
pub const KG_IMPORT_PERSISTED_SUMMARY_SCHEMA: &str = "dagdb_kg_persisted_import_summary_v1";

const ALLOWED_SOURCE_EDGE_KINDS: &[&str] = &[
    "wikilink",
    "source_containment",
    "schema_reference",
    "command_test",
    "prd_relationship",
    "code_to_test",
];

const RAW_BODY_KEYS: &[&str] = &[
    "body",
    "content",
    "file_text",
    "markdown",
    "raw_body",
    "raw_markdown",
    "text_body",
];

const FORBIDDEN_KEYS: &[&str] = &[
    "database_url",
    "db_url",
    "document_body",
    "gateway_secret",
    "model_output",
    "payload",
    "private_key",
    "private_payload",
    "prompt_body",
    "raw_body",
    "raw_document_body",
    "raw_markdown",
    "raw_markdown_body",
    "raw_model_output",
    "raw_payload",
    "raw_private_payload",
    "raw_prompt_body",
    "source_body",
    "source_excerpt",
];

const FORBIDDEN_VALUE_FRAGMENTS: &[&str] = &[
    "/users/",
    "\\users\\",
    "/home/",
    "~/",
    "begin private key",
    "private key-----",
    "authorization",
    "database_url",
    "db_url",
    ".env",
    "bearer ",
    "mongodb://",
    "mysql://",
    "password",
    "postgres://",
    "postgresql://",
    "redis://",
    "secret",
    "sk-proj-",
    "sqlite://",
    "raw_body",
    "raw_document_body",
    "raw_markdown",
    "raw_markdown_body",
    "raw_model_output",
    "raw_payload",
    "raw_private_payload",
    "raw_prompt_body",
    "source_excerpt",
];

/// Errors raised while validating or mapping dry-run KG import reports.
#[derive(Debug, Error)]
pub enum KgImportError {
    /// Report JSON failed to parse.
    #[error("kg_import_report_json_invalid: {reason}")]
    InvalidJson {
        /// Stable parse reason.
        reason: String,
    },
    /// Report shape is unsupported or unsafe.
    #[error("kg_import_report_invalid: {reason}")]
    InvalidReport {
        /// Stable validation reason.
        reason: String,
    },
    /// Hex hash material is malformed.
    #[error("kg_import_hash_invalid: {field}")]
    InvalidHash {
        /// Field name.
        field: String,
    },
    /// Canonical hash material failed.
    #[error("kg_import_hash_failed: {reason}")]
    Hash {
        /// Stable hash error reason.
        reason: String,
    },
}

/// Result alias for report validation.
pub type Result<T> = std::result::Result<T, KgImportError>;

/// Accepted dry-run report shape used by the persisted import adapter.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportDryRunReport {
    pub schema_version: String,
    pub source_candidates_schema_version: String,
    pub graph_root: String,
    pub tenant_id: String,
    pub namespace: String,
    pub actor_did: String,
    pub batch_id: String,
    pub dry_run_only: bool,
    pub postgres_writes: bool,
    pub raw_markdown_included: bool,
    pub proposed_memory_records: Vec<KgImportMemoryRecord>,
    pub proposed_catalog_entries: Vec<KgImportCatalogEntry>,
    pub proposed_graph_nodes: Vec<KgImportGraphNode>,
    pub proposed_graph_edges: Vec<KgImportGraphEdge>,
    #[serde(default)]
    pub proposed_required_edges: Vec<KgImportRequiredEdge>,
    #[serde(default)]
    pub proposed_layers: Vec<KgImportLayer>,
    #[serde(default)]
    pub proposed_layer_memberships: Vec<KgImportLayerMembership>,
    #[serde(default)]
    pub proposed_layer_edges: Vec<KgImportLayerEdge>,
    pub proposed_placement_decisions: Vec<KgImportPlacementDecision>,
    pub proposed_receipt_intents: Vec<KgImportReceiptIntent>,
    pub proposed_validation_reports: Vec<KgImportValidationReport>,
    #[serde(default)]
    pub proposed_governance_reviews: Vec<JsonValue>,
    #[serde(default)]
    pub proposed_graph_view_refreshes: Vec<JsonValue>,
    #[serde(default)]
    pub proposed_route_invalidations: Vec<JsonValue>,
    #[serde(default)]
    pub proposed_subdag_boundaries: Vec<JsonValue>,
    #[serde(default)]
    pub rollback_plan: JsonValue,
    #[serde(default)]
    pub placement_governance_summary: JsonValue,
    #[serde(default)]
    pub review_items: Vec<JsonValue>,
    #[serde(default)]
    pub warnings: Vec<JsonValue>,
}

impl KgImportDryRunReport {
    /// Parse and validate a dry-run report JSON string.
    pub fn parse_json(report_json: &str) -> Result<Self> {
        let raw: JsonValue =
            serde_json::from_str(report_json).map_err(|error| KgImportError::InvalidJson {
                reason: error.to_string(),
            })?;
        reject_forbidden_report_json(&raw, "report")?;
        let report: Self =
            serde_json::from_value(raw).map_err(|error| KgImportError::InvalidJson {
                reason: error.to_string(),
            })?;
        report.validate()?;
        Ok(report)
    }

    /// Deterministic idempotency key for this import batch.
    pub fn idempotency_key(&self) -> Result<String> {
        Ok(stable_hash(
            "exo.dagdb.kg_import.persisted.idempotency_key",
            &[
                &self.tenant_id,
                &self.namespace,
                &self.actor_did,
                &self.graph_root,
                &self.batch_id,
                &self.schema_version,
            ],
        )?
        .to_string())
    }

    /// Validate invariants that are independent of Postgres.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != KG_IMPORT_DRY_RUN_REPORT_SCHEMA {
            return invalid_report(format!(
                "unsupported schema_version: {}",
                self.schema_version
            ));
        }
        if self.source_candidates_schema_version != KG_IMPORT_CANDIDATES_SCHEMA {
            return invalid_report(format!(
                "unsupported source_candidates_schema_version: {}",
                self.source_candidates_schema_version
            ));
        }
        if !self.dry_run_only || self.postgres_writes || self.raw_markdown_included {
            return invalid_report(
                "report must be dry-run only, DB-free, and raw-Markdown-free".to_owned(),
            );
        }
        validate_non_empty("tenant_id", &self.tenant_id)?;
        validate_non_empty("namespace", &self.namespace)?;
        validate_tenant_identity("tenant_id", &self.tenant_id)?;
        validate_tenant_identity("namespace", &self.namespace)?;
        validate_did("actor_did", &self.actor_did)?;
        validate_hex("batch_id", &self.batch_id)?;
        validate_relative_path("graph_root", &self.graph_root)?;
        ensure_unique(
            "memory_id",
            self.proposed_memory_records
                .iter()
                .map(|record| record.memory_id.as_str()),
        )?;
        for record in &self.proposed_memory_records {
            validate_relative_path("source_path", &record.source_path)?;
        }
        ensure_unique(
            "source_path",
            self.proposed_memory_records
                .iter()
                .map(|record| record.source_path.as_str()),
        )?;
        ensure_unique(
            "catalog_id",
            self.proposed_catalog_entries
                .iter()
                .map(|record| record.catalog_id.as_str()),
        )?;
        ensure_unique(
            "graph_node_id",
            self.proposed_graph_nodes
                .iter()
                .map(|record| record.graph_node_id.as_str()),
        )?;
        ensure_unique(
            "graph_edge_id",
            self.proposed_graph_edges
                .iter()
                .map(|record| record.graph_edge_id.as_str()),
        )?;
        ensure_unique(
            "validation_report_id",
            self.proposed_validation_reports
                .iter()
                .map(|record| record.validation_report_id.as_str()),
        )?;
        ensure_unique(
            "placement_decision_id",
            self.proposed_placement_decisions
                .iter()
                .map(|record| record.placement_decision_id.as_str()),
        )?;
        ensure_unique(
            "layer_id",
            self.proposed_layers
                .iter()
                .map(|record| record.layer_id.as_str()),
        )?;
        ensure_unique(
            "layer_path",
            self.proposed_layers
                .iter()
                .map(|record| record.layer_path.as_str()),
        )?;
        ensure_unique(
            "layer_membership_id",
            self.proposed_layer_memberships
                .iter()
                .map(|record| record.layer_membership_id.as_str()),
        )?;
        ensure_unique(
            "layer_edge_id",
            self.proposed_layer_edges
                .iter()
                .map(|record| record.layer_edge_id.as_str()),
        )?;

        for record in &self.proposed_memory_records {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_catalog_entries {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_graph_nodes {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_graph_edges {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_required_edges {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_layers {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_layer_memberships {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_layer_edges {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_placement_decisions {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        for record in &self.proposed_receipt_intents {
            record.validate(&self.tenant_id, &self.namespace)?;
            // Persisted receipt actors must be the report's declared actor;
            // intents cannot mint receipts under other identities.
            if record.actor_did != self.actor_did {
                return invalid_report(format!(
                    "receipt intent actor_did {} does not match report actor_did {}",
                    record.actor_did, self.actor_did
                ));
            }
        }
        for record in &self.proposed_validation_reports {
            record.validate(&self.tenant_id, &self.namespace)?;
        }
        validate_layer_relationships(self)?;
        Ok(())
    }
}

/// Proposed memory record from the dry-run report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportMemoryRecord {
    pub memory_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub source_path: String,
    pub candidate_id: String,
    pub node_type: String,
    pub source_type: String,
    pub source_hash: String,
    pub payload_hash: String,
    pub owner_did: String,
    pub controller_did: String,
    pub submitted_by_did: String,
    pub consent_purpose: String,
    pub title: SafeMetadata,
    pub summary: SafeMetadata,
    /// PRD-D3 (D3-S4) deep detail tier. Nullable so reports authored before the
    /// two-tier distiller (and rows already persisted) stay valid; when present
    /// it carries the distilled deep summary and is screened fail-closed at
    /// ingestion exactly like the short `summary` (the whole report JSON is run
    /// through `reject_forbidden_report_json` before this struct is built).
    #[serde(default)]
    pub deep_detail_summary: Option<SafeMetadata>,
    pub keywords: Vec<SafeMetadata>,
    pub catalog_path: Vec<String>,
    pub risk_class: String,
    pub risk_bp: u16,
    pub validation_status: String,
    pub council_status: String,
    pub dag_finality_status: String,
    pub status: String,
    pub receipt_intent_id: String,
}

impl KgImportMemoryRecord {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "memory",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("memory_id", &self.memory_id)?;
        validate_relative_path("source_path", &self.source_path)?;
        validate_non_empty("candidate_id", &self.candidate_id)?;
        validate_hex("source_hash", &self.source_hash)?;
        validate_hex("payload_hash", &self.payload_hash)?;
        validate_hex("receipt_intent_id", &self.receipt_intent_id)?;
        validate_did("owner_did", &self.owner_did)?;
        validate_did("controller_did", &self.controller_did)?;
        validate_did("submitted_by_did", &self.submitted_by_did)?;
        validate_catalog_path(&self.catalog_path)?;
        validate_choice("node_type", &self.node_type, &["source"])?;
        validate_choice("source_type", &self.source_type, &["generated"])?;
        validate_choice("consent_purpose", &self.consent_purpose, &["retrieval"])?;
        validate_choice(
            "risk_class",
            &self.risk_class,
            &["R0", "R1", "R2", "R3", "R4", "R5"],
        )?;
        // Imported records are untrusted proposals: governed statuses
        // (routable/approved/passed/committed) may only be reached through
        // the validator/council/finality paths, never self-asserted by the
        // report author.
        validate_choice(
            "validation_status",
            &self.validation_status,
            &["not_required", "pending"],
        )?;
        validate_choice(
            "council_status",
            &self.council_status,
            &["not_required", "pending"],
        )?;
        validate_choice(
            "dag_finality_status",
            &self.dag_finality_status,
            &["pending"],
        )?;
        validate_choice("status", &self.status, &["pending"])
    }
}

/// Proposed catalog entry from the dry-run report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportCatalogEntry {
    pub catalog_id: String,
    pub memory_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub catalog_path: Vec<String>,
    pub catalog_level: u32,
    pub title: SafeMetadata,
    pub summary: SafeMetadata,
    pub payload_hash: String,
    pub source_hash: String,
    pub status: String,
    pub validation_status: String,
    pub council_status: String,
    pub dag_finality_status: String,
    pub receipt_intent_id: String,
}

impl KgImportCatalogEntry {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "catalog",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("catalog_id", &self.catalog_id)?;
        validate_hex("memory_id", &self.memory_id)?;
        validate_hex("payload_hash", &self.payload_hash)?;
        validate_hex("source_hash", &self.source_hash)?;
        validate_hex("receipt_intent_id", &self.receipt_intent_id)?;
        validate_catalog_path(&self.catalog_path)?;
        // Same trust boundary as memory records: imported catalog entries are
        // proposals and cannot self-assert governed statuses.
        validate_choice("status", &self.status, &["pending"])?;
        validate_choice(
            "validation_status",
            &self.validation_status,
            &["not_required", "pending"],
        )?;
        validate_choice(
            "council_status",
            &self.council_status,
            &["not_required", "pending"],
        )?;
        validate_choice(
            "dag_finality_status",
            &self.dag_finality_status,
            &["pending"],
        )
    }
}

/// Proposed graph node from the dry-run report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportGraphNode {
    pub graph_node_id: String,
    pub memory_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub graph_style: String,
    pub node_kind: String,
    pub catalog_path: Vec<String>,
}

impl KgImportGraphNode {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "graph_node",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("graph_node_id", &self.graph_node_id)?;
        validate_hex("memory_id", &self.memory_id)?;
        validate_graph_style(&self.graph_style)?;
        validate_node_kind(&self.node_kind)?;
        validate_catalog_path(&self.catalog_path)
    }
}

/// Proposed graph edge from the dry-run report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportGraphEdge {
    pub graph_edge_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub graph_style: String,
    pub from_memory_id: String,
    pub to_memory_id: String,
    pub edge_kind: String,
    pub source_edge_kind: String,
}

impl KgImportGraphEdge {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "graph_edge",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("graph_edge_id", &self.graph_edge_id)?;
        validate_hex("from_memory_id", &self.from_memory_id)?;
        validate_hex("to_memory_id", &self.to_memory_id)?;
        validate_graph_style(&self.graph_style)?;
        validate_edge_kind(&self.edge_kind)?;
        validate_choice(
            "source_edge_kind",
            &self.source_edge_kind,
            ALLOWED_SOURCE_EDGE_KINDS,
        )
    }
}

/// Proposed required edge from placement/governance dry-run output.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportRequiredEdge {
    pub required_edge_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub graph_style: String,
    pub from_memory_id: String,
    pub to_memory_id: String,
    pub edge_kind: String,
    pub status: String,
}

impl KgImportRequiredEdge {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "required_edge",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("required_edge_id", &self.required_edge_id)?;
        validate_hex("from_memory_id", &self.from_memory_id)?;
        validate_hex("to_memory_id", &self.to_memory_id)?;
        validate_graph_style(&self.graph_style)?;
        validate_edge_kind(&self.edge_kind)?;
        validate_choice("status", &self.status, &["proposed"])
    }
}

/// Proposed layer row from a layer-aware dry-run import report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportLayer {
    pub layer_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub root_memory_id: String,
    pub parent_layer_id: Option<String>,
    pub parent_graph_node_id: Option<String>,
    pub layer_depth: u32,
    pub layer_kind: String,
    pub graph_style: String,
    pub layer_path: String,
    #[serde(default = "empty_json_object")]
    pub metadata: JsonValue,
}

impl KgImportLayer {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "layer",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("layer_id", &self.layer_id)?;
        validate_hex("root_memory_id", &self.root_memory_id)?;
        if let Some(parent_layer_id) = &self.parent_layer_id {
            validate_hex("parent_layer_id", parent_layer_id)?;
        }
        if let Some(parent_graph_node_id) = &self.parent_graph_node_id {
            validate_hex("parent_graph_node_id", parent_graph_node_id)?;
        }
        validate_choice(
            "layer_kind",
            &self.layer_kind,
            &[
                "root",
                "repository",
                "knowledge_graph",
                "source_subgraph",
                "task_subgraph",
                "rollup",
                "route",
            ],
        )?;
        validate_graph_style(&self.graph_style)?;
        validate_relative_path("layer_path", &self.layer_path)?;
        validate_json_object("layer.metadata", &self.metadata)?;
        if self.layer_depth > LAYER_CREATION_MAX_DEPTH {
            return invalid_report(format!(
                "layer_depth {} exceeds maximum {LAYER_CREATION_MAX_DEPTH}",
                self.layer_depth
            ));
        }
        if self.layer_depth == 0 {
            if self.parent_layer_id.is_some() || self.parent_graph_node_id.is_some() {
                return invalid_report("root layer must not include parent references".to_owned());
            }
        } else if self.parent_layer_id.is_none() || self.parent_graph_node_id.is_none() {
            return invalid_report(
                "child layer must include parent layer and parent node".to_owned(),
            );
        }
        let expected_layer_id = expected_layer_id_hex(
            &self.tenant_id,
            &self.namespace,
            &self.graph_style,
            &self.layer_path,
            self.layer_depth,
        )?;
        if self.layer_id != expected_layer_id {
            return invalid_report(
                "layer_id does not match the deterministic tenant-scoped layer derivation"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Proposed layer membership row from a layer-aware dry-run import report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportLayerMembership {
    pub layer_membership_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub layer_id: String,
    pub graph_node_id: String,
    pub graph_style: String,
    pub membership_role: String,
    pub local_node_rank: u32,
    #[serde(default = "empty_json_object")]
    pub metadata: JsonValue,
}

impl KgImportLayerMembership {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "layer_membership",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("layer_membership_id", &self.layer_membership_id)?;
        validate_hex("layer_id", &self.layer_id)?;
        validate_hex("graph_node_id", &self.graph_node_id)?;
        validate_graph_style(&self.graph_style)?;
        validate_choice(
            "membership_role",
            &self.membership_role,
            &["root", "container", "member", "summary", "route_anchor"],
        )?;
        validate_json_object("layer_membership.metadata", &self.metadata)?;
        let expected_membership_id = expected_layer_membership_id_hex(
            &self.tenant_id,
            &self.namespace,
            &self.layer_id,
            &self.graph_node_id,
        )?;
        if self.layer_membership_id != expected_membership_id {
            return invalid_report(
                "layer_membership_id does not match the deterministic tenant-scoped \
                 membership derivation"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Proposed layer edge row from a layer-aware dry-run import report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportLayerEdge {
    pub layer_edge_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub graph_style: String,
    pub from_layer_id: String,
    pub to_layer_id: String,
    pub edge_kind: String,
    pub receipt_hash: Option<String>,
    #[serde(default = "empty_json_object")]
    pub metadata: JsonValue,
}

impl KgImportLayerEdge {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "layer_edge",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("layer_edge_id", &self.layer_edge_id)?;
        validate_hex("from_layer_id", &self.from_layer_id)?;
        validate_hex("to_layer_id", &self.to_layer_id)?;
        if let Some(receipt_hash) = &self.receipt_hash {
            validate_hex("receipt_hash", receipt_hash)?;
        }
        if self.from_layer_id == self.to_layer_id {
            return invalid_report("layer edge cannot point to itself".to_owned());
        }
        validate_graph_style(&self.graph_style)?;
        validate_choice(
            "layer_edge_kind",
            &self.edge_kind,
            &[
                "contains_subgraph",
                "drills_down_to",
                "rolls_up_to",
                "cross_layer_ref",
                "summarizes_layer",
            ],
        )?;
        validate_json_object("layer_edge.metadata", &self.metadata)?;
        validate_layer_edge_hygiene_metadata(&self.metadata)?;
        let expected_layer_edge_id = expected_layer_edge_id_hex(
            &self.tenant_id,
            &self.namespace,
            &self.graph_style,
            &self.from_layer_id,
            &self.to_layer_id,
            &self.edge_kind,
        )?;
        if self.layer_edge_id != expected_layer_edge_id {
            return invalid_report(
                "layer_edge_id does not match the deterministic tenant-scoped \
                 layer-edge derivation"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Proposed placement decision from the dry-run report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportPlacementDecision {
    pub placement_decision_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub input_memory_id: String,
    pub placement_trace: Vec<String>,
    pub canonicalization_decision: KgImportCanonicalizationDecision,
    #[serde(default)]
    pub similarity_results: Vec<JsonValue>,
    pub validator_report: String,
    pub receipt_intent_id: String,
    #[serde(default)]
    pub target_layer_path: Option<String>,
    #[serde(default)]
    pub target_layer_depth: Option<u32>,
    #[serde(default)]
    pub target_layer_reason: Option<String>,
    #[serde(default)]
    pub created_child_layer_id: Option<String>,
    #[serde(default)]
    pub layer_fallback_used: bool,
}

impl KgImportPlacementDecision {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "placement",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("placement_decision_id", &self.placement_decision_id)?;
        validate_hex("input_memory_id", &self.input_memory_id)?;
        validate_hex("receipt_intent_id", &self.receipt_intent_id)?;
        if self.placement_trace != required_trace() {
            return invalid_report("placement trace does not match required order".to_owned());
        }
        self.validate_layer_target()?;
        self.canonicalization_decision.validate()
    }

    fn validate_layer_target(&self) -> Result<()> {
        let has_layer_target = self.target_layer_path.is_some()
            || self.target_layer_depth.is_some()
            || self.target_layer_reason.is_some()
            || self.created_child_layer_id.is_some()
            || self.layer_fallback_used;
        if !has_layer_target {
            return Ok(());
        }
        let Some(target_layer_path) = &self.target_layer_path else {
            return invalid_report("layer-aware placement missing target_layer_path".to_owned());
        };
        let Some(target_layer_depth) = self.target_layer_depth else {
            return invalid_report("layer-aware placement missing target_layer_depth".to_owned());
        };
        let Some(target_layer_reason) = &self.target_layer_reason else {
            return invalid_report("layer-aware placement missing target_layer_reason".to_owned());
        };
        validate_relative_path("target_layer_path", target_layer_path)?;
        validate_non_empty("target_layer_reason", target_layer_reason)?;
        if target_layer_path == "root" {
            if target_layer_depth != 0 {
                return invalid_report("root layer target must use depth zero".to_owned());
            }
        } else if target_layer_depth == 0 {
            return invalid_report("non-root layer target must use positive depth".to_owned());
        }
        if let Some(created_child_layer_id) = &self.created_child_layer_id {
            validate_hex("created_child_layer_id", created_child_layer_id)?;
        }
        Ok(())
    }
}

/// Canonicalization proposal nested under a placement decision.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportCanonicalizationDecision {
    pub canonical_memory_id: Option<String>,
    pub confidence_bp: u16,
    pub decision_kind: String,
    pub decision_reason: String,
    pub matched_memory_ids: Vec<String>,
    pub required_edges_to_create: Vec<JsonValue>,
    pub risk_class: String,
    pub validator_status: String,
}

impl KgImportCanonicalizationDecision {
    fn validate(&self) -> Result<()> {
        if let Some(canonical_memory_id) = &self.canonical_memory_id {
            validate_hex("canonical_memory_id", canonical_memory_id)?;
        }
        for memory_id in &self.matched_memory_ids {
            validate_hex("matched_memory_id", memory_id)?;
        }
        validate_non_empty("decision_reason", &self.decision_reason)?;
        validate_choice(
            "decision_kind",
            &self.decision_kind,
            &[
                "new_canonical",
                "exact_duplicate",
                "near_duplicate",
                "related",
                "replacement",
                "contradiction",
                "supersession",
                "alternate_summary",
                "rejected_needs_review",
            ],
        )?;
        validate_choice(
            "risk_class",
            &self.risk_class,
            &["R0", "R1", "R2", "R3", "R4", "R5"],
        )?;
        validate_choice(
            "validator_status",
            &self.validator_status,
            &[
                "not_required",
                "pending",
                "passed",
                "failed",
                "contradictory",
                "expired",
                "needs_council",
            ],
        )
    }
}

/// Proposed receipt intent from the dry-run report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportReceiptIntent {
    pub receipt_intent_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub event_type: String,
    pub actor_did: String,
    pub reason: String,
}

impl KgImportReceiptIntent {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "receipt",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("receipt_intent_id", &self.receipt_intent_id)?;
        validate_hex("subject_id", &self.subject_id)?;
        validate_did("actor_did", &self.actor_did)?;
        validate_non_empty("reason", &self.reason)?;
        validate_choice(
            "subject_kind",
            &self.subject_kind,
            &[
                "memory",
                "catalog",
                "route",
                "context_packet",
                "validation_report",
                "agent_safety_score",
                "inbound_agent_credential",
                "council_decision",
            ],
        )?;
        validate_choice(
            "event_type",
            &self.event_type,
            &[
                "intake_created",
                "duplicate_rejected",
                "validation_created",
                "validation_passed",
                "validation_failed",
                "memory_approved",
                "memory_routable",
                "memory_revoked",
                "memory_superseded",
                "route_created",
                "route_activated",
                "route_stale",
                "route_invalidated",
                "context_packet_created",
                "writeback_created",
                "trust_check_created",
                "council_decision_recorded",
                "dag_finality_committed",
                "dag_finality_failed",
                "dag_finality_compensated",
            ],
        )
    }
}

/// Proposed validation report from the dry-run report.
#[derive(Debug, Clone, Deserialize)]
pub struct KgImportValidationReport {
    pub validation_report_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub validator_did: String,
    pub input_hash: String,
    pub policy_hash: String,
    pub validation_status: String,
    pub risk_class: String,
    pub risk_bp: u16,
    pub decision: String,
    pub notes: SafeMetadata,
}

impl KgImportValidationReport {
    fn validate(&self, tenant_id: &str, namespace: &str) -> Result<()> {
        validate_scope(
            "validation",
            &self.tenant_id,
            tenant_id,
            &self.namespace,
            namespace,
        )?;
        validate_hex("validation_report_id", &self.validation_report_id)?;
        validate_hex("subject_id", &self.subject_id)?;
        validate_hex("input_hash", &self.input_hash)?;
        validate_hex("policy_hash", &self.policy_hash)?;
        validate_did("validator_did", &self.validator_did)?;
        validate_choice("subject_kind", &self.subject_kind, &["memory"])?;
        validate_choice(
            "validation_status",
            &self.validation_status,
            &[
                "not_required",
                "pending",
                "passed",
                "failed",
                "contradictory",
                "expired",
                "needs_council",
            ],
        )?;
        validate_choice(
            "risk_class",
            &self.risk_class,
            &["R0", "R1", "R2", "R3", "R4", "R5"],
        )?;
        validate_choice(
            "decision",
            &self.decision,
            &[
                "allow",
                "block",
                "needs_council",
                "invalidate",
                "revoke",
                "supersede",
            ],
        )
    }
}

/// Summary returned by the persisted import repository adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KgImportPersistedSummary {
    pub schema_version: String,
    pub tenant_id: String,
    pub namespace: String,
    pub batch_id: String,
    pub idempotency_key: String,
    pub replayed: bool,
    pub inserted_memory_count: u32,
    pub inserted_catalog_count: u32,
    pub inserted_graph_node_count: u32,
    pub inserted_graph_edge_count: u32,
    #[serde(default)]
    pub inserted_layer_count: u32,
    #[serde(default)]
    pub inserted_layer_membership_count: u32,
    #[serde(default)]
    pub inserted_layer_edge_count: u32,
    pub inserted_validation_report_count: u32,
    pub inserted_placement_decision_count: u32,
    pub inserted_placement_trace_count: u32,
    pub inserted_receipt_count: u32,
    pub skipped_advisory_section_count: u32,
}

/// Convert a 64-character lowercase hex string into `Hash256`.
pub fn hash_from_hex(field: &str, value: &str) -> Result<Hash256> {
    validate_hex(field, value)?;
    parse_hash256_hex(field, value).map_err(|error| KgImportError::Hash {
        reason: error.to_string(),
    })
}

/// Compute deterministic import hash material using canonical EXOCHAIN CBOR.
pub fn stable_hash(domain: &str, parts: &[&str]) -> Result<Hash256> {
    stable_hash_parts(domain, parts).map_err(|error| KgImportError::Hash {
        reason: error.to_string(),
    })
}

/// Expected tenant-scoped deterministic layer identity as lowercase hex.
pub fn expected_layer_id_hex(
    tenant_id: &str,
    namespace: &str,
    graph_style: &str,
    layer_path: &str,
    layer_depth: u32,
) -> Result<String> {
    let style = parse_memory_graph_style("graph_style", graph_style)?;
    deterministic_layer_id(tenant_id, namespace, style, layer_path, layer_depth)
        .map(|hash| hash.to_string())
        .map_err(layer_identity_error)
}

/// Expected tenant-scoped deterministic layer-membership identity as lowercase hex.
pub fn expected_layer_membership_id_hex(
    tenant_id: &str,
    namespace: &str,
    layer_id: &str,
    graph_node_id: &str,
) -> Result<String> {
    let layer = hash_from_hex("layer_id", layer_id)?;
    let node = hash_from_hex("graph_node_id", graph_node_id)?;
    deterministic_layer_membership_id(tenant_id, namespace, layer, node)
        .map(|hash| hash.to_string())
        .map_err(layer_identity_error)
}

/// Expected tenant-scoped deterministic layer-edge identity as lowercase hex.
pub fn expected_layer_edge_id_hex(
    tenant_id: &str,
    namespace: &str,
    graph_style: &str,
    from_layer_id: &str,
    to_layer_id: &str,
    edge_kind: &str,
) -> Result<String> {
    let style = parse_memory_graph_style("graph_style", graph_style)?;
    let from_layer = hash_from_hex("from_layer_id", from_layer_id)?;
    let to_layer = hash_from_hex("to_layer_id", to_layer_id)?;
    deterministic_layer_edge_id(tenant_id, namespace, style, from_layer, to_layer, edge_kind)
        .map(|hash| hash.to_string())
        .map_err(layer_identity_error)
}

fn parse_memory_graph_style(field: &str, value: &str) -> Result<MemoryGraphStyle> {
    serde_json::from_value(JsonValue::String(value.to_owned())).map_err(|_| {
        KgImportError::InvalidReport {
            reason: format!("unsupported {field}: {value}"),
        }
    })
}

fn layer_identity_error(error: crate::layered_placement::LayerPlacementError) -> KgImportError {
    KgImportError::InvalidReport {
        reason: format!("layer identity derivation failed: {error}"),
    }
}

fn validate_layer_edge_hygiene_metadata(metadata: &JsonValue) -> Result<()> {
    let Some(state) = metadata.get("hygiene_state") else {
        return Ok(());
    };
    let Some(state) = state.as_str() else {
        return invalid_report("layer_edge.metadata.hygiene_state must be a string".to_owned());
    };
    if state.parse::<LayerHygieneEdgeState>().is_err() {
        return invalid_report(format!(
            "unsupported layer_edge.metadata.hygiene_state: {state}"
        ));
    }
    Ok(())
}

/// Required dry-run placement trace labels.
#[must_use]
pub fn required_trace() -> Vec<String> {
    [
        "source_verification",
        "risk_classification",
        "identity_assignment",
        "exact_duplicate_check",
        "similarity_overlay_check",
        "canonicalization_decision",
        "metadata_attachment",
        "semantic_catalog_graph_placement",
        "provenance_receipt_dag_placement",
        "canonical_memory_graph_update",
        "dependency_dag_update",
        "contradiction_supersession_graph_update",
        "validation",
        "receipt_writeback",
        "routing_view_graph_refresh",
        "route_invalidation",
        "query_exposure",
    ]
    .iter()
    .map(|step| (*step).to_owned())
    .collect()
}

fn reject_forbidden_report_json(value: &JsonValue, location: &str) -> Result<()> {
    match value {
        JsonValue::Object(map) => {
            for (key, nested) in map {
                let lowered_key = key.to_ascii_lowercase();
                if RAW_BODY_KEYS.contains(&lowered_key.as_str())
                    || FORBIDDEN_KEYS.contains(&lowered_key.as_str())
                {
                    return invalid_report(format!("unsafe raw body field at {location}.{key}"));
                }
                reject_forbidden_report_json(nested, &format!("{location}.{key}"))?;
            }
        }
        JsonValue::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                reject_forbidden_report_json(nested, &format!("{location}[{index}]"))?;
            }
        }
        JsonValue::String(value) => reject_forbidden_string(location, value)?,
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
    Ok(())
}

fn reject_forbidden_string(field: &str, value: &str) -> Result<()> {
    let lowered = value.to_ascii_lowercase();
    if let Some(fragment) = FORBIDDEN_VALUE_FRAGMENTS
        .iter()
        .find(|fragment| lowered.contains(**fragment))
    {
        return invalid_report(format!("{field} contains forbidden fragment {fragment}"));
    }
    Ok(())
}

fn ensure_unique<'a>(field: &str, values: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut duplicates = Vec::new();
    for value in values {
        if !seen.insert(value.to_owned()) {
            duplicates.push(value.to_owned());
        }
    }
    if duplicates.is_empty() {
        Ok(())
    } else {
        duplicates.sort();
        invalid_report(format!("duplicate {field}: {}", duplicates.join(",")))
    }
}

fn validate_scope(
    label: &str,
    record_tenant: &str,
    tenant_id: &str,
    record_namespace: &str,
    namespace: &str,
) -> Result<()> {
    if record_tenant != tenant_id || record_namespace != namespace {
        return invalid_report(format!("{label} tenant/namespace mismatch"));
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return invalid_report(format!("missing {field}"));
    }
    reject_forbidden_string(field, value)?;
    Ok(())
}

/// Reject a tenant id / namespace that is not already in canonical, charset-safe
/// form (GAP-012 P1-E). Persisted rows carry this value verbatim and the by-hash
/// read predicates now compare on it, so a non-canonical value (untrimmed, wrong
/// charset, over-length) must fail closed rather than be silently normalized.
fn validate_tenant_identity(field: &str, value: &str) -> Result<()> {
    let normalized = crate::tenant::normalize_tenant_id(value).map_err(|error| {
        KgImportError::InvalidReport {
            reason: format!("{field}: {error}"),
        }
    })?;
    if normalized != value {
        return invalid_report(format!("{field} is not in canonical form"));
    }
    Ok(())
}

fn validate_did(field: &str, value: &str) -> Result<()> {
    validate_non_empty(field, value)?;
    if value.starts_with("did:") {
        Ok(())
    } else {
        invalid_report(format!("{field} must start with did:"))
    }
}

fn validate_hex(field: &str, value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(KgImportError::InvalidHash {
            field: field.to_owned(),
        })
    }
}

fn validate_relative_path(field: &str, value: &str) -> Result<()> {
    validate_non_empty(field, value)?;
    if value.starts_with('/') || value.starts_with('~') || value.contains('\\') {
        return invalid_report(format!("dangerous {field}"));
    }
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return invalid_report(format!("dangerous {field}"));
    }
    Ok(())
}

fn validate_catalog_path(path: &[String]) -> Result<()> {
    if path.is_empty() {
        return invalid_report("missing catalog_path".to_owned());
    }
    for part in path {
        if part.trim().is_empty() || part == "." || part == ".." || part.contains('/') {
            return invalid_report("dangerous catalog_path part".to_owned());
        }
        reject_forbidden_string("catalog_path", part)?;
    }
    Ok(())
}

fn validate_graph_style(value: &str) -> Result<()> {
    validate_choice(
        "graph_style",
        value,
        &[
            "provenance_receipt_dag",
            "canonical_memory_graph",
            "semantic_catalog_graph",
            "similarity_overlay_graph",
            "dependency_dag",
            "routing_view_graph",
            "contradiction_supersession_graph",
            "context_packet_graph",
        ],
    )
}

fn validate_node_kind(value: &str) -> Result<()> {
    validate_choice(
        "node_kind",
        value,
        &[
            "raw",
            "chunk",
            "summary",
            "concept",
            "canonical",
            "duplicate_reference",
            "related",
            "replacement",
            "contradiction",
            "supersession",
            "alternate_summary",
            "decision",
            "route",
            "validation_report",
            "savings_report",
        ],
    )
}

fn validate_edge_kind(value: &str) -> Result<()> {
    validate_choice(
        "edge_kind",
        value,
        &[
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
        ],
    )
}

fn validate_layer_relationships(report: &KgImportDryRunReport) -> Result<()> {
    let layer_mode_enabled = !report.proposed_layers.is_empty()
        || !report.proposed_layer_memberships.is_empty()
        || !report.proposed_layer_edges.is_empty();
    if !layer_mode_enabled {
        return Ok(());
    }

    let memory_ids: BTreeSet<&str> = report
        .proposed_memory_records
        .iter()
        .map(|record| record.memory_id.as_str())
        .collect();
    let graph_nodes: BTreeMap<&str, &KgImportGraphNode> = report
        .proposed_graph_nodes
        .iter()
        .map(|record| (record.graph_node_id.as_str(), record))
        .collect();
    let layers: BTreeMap<&str, &KgImportLayer> = report
        .proposed_layers
        .iter()
        .map(|record| (record.layer_id.as_str(), record))
        .collect();
    let layer_paths: BTreeSet<&str> = report
        .proposed_layers
        .iter()
        .map(|record| record.layer_path.as_str())
        .collect();
    let layer_memberships: BTreeSet<(&str, &str)> = report
        .proposed_layer_memberships
        .iter()
        .map(|record| (record.layer_id.as_str(), record.graph_node_id.as_str()))
        .collect();

    for layer in &report.proposed_layers {
        if !memory_ids.contains(layer.root_memory_id.as_str()) {
            return invalid_report(format!(
                "layer references unknown root memory {}",
                layer.root_memory_id
            ));
        }
        if let Some(parent_layer_id) = layer.parent_layer_id.as_deref() {
            let Some(parent_layer) = layers.get(parent_layer_id) else {
                return invalid_report(format!(
                    "child layer references unknown parent layer {parent_layer_id}"
                ));
            };
            let Some(expected_child_depth) = parent_layer.layer_depth.checked_add(1) else {
                return invalid_report("parent layer depth overflows".to_owned());
            };
            if layer.layer_depth != expected_child_depth {
                return invalid_report("child layer depth does not follow parent depth".to_owned());
            }
        }
        if let Some(parent_graph_node_id) = layer.parent_graph_node_id.as_deref() {
            if !graph_nodes.contains_key(parent_graph_node_id) {
                return invalid_report(format!(
                    "child layer references unknown parent graph node {parent_graph_node_id}"
                ));
            }
            let Some(parent_layer_id) = layer.parent_layer_id.as_deref() else {
                return invalid_report("child layer parent node requires parent layer".to_owned());
            };
            if !layer_memberships.contains(&(parent_layer_id, parent_graph_node_id)) {
                return invalid_report(
                    "child layer parent node must be a member of the parent layer".to_owned(),
                );
            }
        }
    }

    for layer in &report.proposed_layers {
        let mut visited: BTreeSet<&str> = BTreeSet::new();
        let mut current: &KgImportLayer = layer;
        while let Some(parent_layer_id) = current.parent_layer_id.as_deref() {
            if !visited.insert(current.layer_id.as_str()) {
                return invalid_report(format!(
                    "layer parent chain contains a cycle at {}",
                    layer.layer_id
                ));
            }
            let Some(parent_layer) = layers.get(parent_layer_id).copied() else {
                return invalid_report(format!(
                    "child layer references unknown parent layer {parent_layer_id}"
                ));
            };
            current = parent_layer;
        }
        if current.layer_depth != 0 {
            return invalid_report(format!(
                "layer parent chain does not terminate at a depth-0 root for {}",
                layer.layer_id
            ));
        }
    }

    for membership in &report.proposed_layer_memberships {
        let Some(layer) = layers.get(membership.layer_id.as_str()) else {
            return invalid_report(format!(
                "layer membership references unknown layer {}",
                membership.layer_id
            ));
        };
        let Some(graph_node) = graph_nodes.get(membership.graph_node_id.as_str()) else {
            return invalid_report(format!(
                "layer membership references unknown graph node {}",
                membership.graph_node_id
            ));
        };
        if membership.graph_style != layer.graph_style
            || membership.graph_style != graph_node.graph_style
        {
            return invalid_report("layer membership graph_style mismatch".to_owned());
        }
    }

    for graph_node in &report.proposed_graph_nodes {
        if !report
            .proposed_layer_memberships
            .iter()
            .any(|membership| membership.graph_node_id == graph_node.graph_node_id)
        {
            return invalid_report(format!(
                "layer-aware import missing membership for graph node {}",
                graph_node.graph_node_id
            ));
        }
    }

    for edge in &report.proposed_layer_edges {
        let Some(from_layer) = layers.get(edge.from_layer_id.as_str()) else {
            return invalid_report(format!(
                "layer edge references unknown source layer {}",
                edge.from_layer_id
            ));
        };
        let Some(to_layer) = layers.get(edge.to_layer_id.as_str()) else {
            return invalid_report(format!(
                "layer edge references unknown target layer {}",
                edge.to_layer_id
            ));
        };
        if edge.graph_style != from_layer.graph_style || edge.graph_style != to_layer.graph_style {
            return invalid_report("layer edge graph_style mismatch".to_owned());
        }
    }

    for placement in &report.proposed_placement_decisions {
        let Some(target_layer_path) = placement.target_layer_path.as_deref() else {
            return invalid_report(
                "layer-aware import placement missing target_layer_path".to_owned(),
            );
        };
        if !layer_paths.contains(target_layer_path) {
            return invalid_report(format!(
                "placement targets unknown layer path {target_layer_path}"
            ));
        }
        if let Some(created_child_layer_id) = placement.created_child_layer_id.as_deref()
            && !layers.contains_key(created_child_layer_id)
        {
            return invalid_report(format!(
                "placement created_child_layer_id references unknown layer {created_child_layer_id}"
            ));
        }
    }

    Ok(())
}

fn validate_json_object(field: &str, value: &JsonValue) -> Result<()> {
    if value.is_object() {
        Ok(())
    } else {
        invalid_report(format!("{field} must be a JSON object"))
    }
}

fn validate_choice(field: &str, value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        invalid_report(format!("unsupported {field}: {value}"))
    }
}

fn invalid_report<T>(reason: String) -> Result<T> {
    Err(KgImportError::InvalidReport { reason })
}

fn empty_json_object() -> JsonValue {
    JsonValue::Object(serde_json::Map::new())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn safe_text(text: &str) -> JsonValue {
        json!({
            "decision": "allow",
            "text": text,
            "redaction_codes": [],
            "original_hash": "c".repeat(64),
            "truncated": false,
            "byte_len": text.len(),
        })
    }

    fn valid_report_json() -> JsonValue {
        let memory_id = "1".repeat(64);
        let catalog_id = "2".repeat(64);
        let graph_node_id = "3".repeat(64);
        let graph_edge_id = "4".repeat(64);
        let required_edge_id = "5".repeat(64);
        let placement_decision_id = "6".repeat(64);
        let receipt_intent_id = "7".repeat(64);
        let validation_report_id = "8".repeat(64);
        let source_hash = "9".repeat(64);
        let payload_hash = "a".repeat(64);
        let policy_hash = "b".repeat(64);
        let root_layer_id = expected_layer_id_hex(
            "dag-db-local",
            "dag-db",
            "semantic_catalog_graph",
            "root",
            0,
        )
        .expect("root layer id");
        let source_layer_id = expected_layer_id_hex(
            "dag-db-local",
            "dag-db",
            "semantic_catalog_graph",
            "root/knowledge-graph",
            1,
        )
        .expect("source layer id");
        let root_membership_id = expected_layer_membership_id_hex(
            "dag-db-local",
            "dag-db",
            &root_layer_id,
            &graph_node_id,
        )
        .expect("root membership id");
        let source_membership_id = expected_layer_membership_id_hex(
            "dag-db-local",
            "dag-db",
            &source_layer_id,
            &graph_node_id,
        )
        .expect("source membership id");
        let layer_edge_id = expected_layer_edge_id_hex(
            "dag-db-local",
            "dag-db",
            "semantic_catalog_graph",
            &root_layer_id,
            &source_layer_id,
            "contains_subgraph",
        )
        .expect("layer edge id");

        json!({
            "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
            "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
            "graph_root": "KnowledgeGraphs/dag-db",
            "tenant_id": "dag-db-local",
            "namespace": "dag-db",
            "actor_did": "did:exo:kg-importer",
            "batch_id": "d".repeat(64),
            "dry_run_only": true,
            "postgres_writes": false,
            "raw_markdown_included": false,
            "proposed_memory_records": [{
                "memory_id": memory_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "source_path": "KnowledgeGraphs/dag-db/00_Index.md",
                "candidate_id": "candidate-001",
                "node_type": "source",
                "source_type": "generated",
                "source_hash": source_hash,
                "payload_hash": payload_hash,
                "owner_did": "did:exo:owner",
                "controller_did": "did:exo:controller",
                "submitted_by_did": "did:exo:submitter",
                "consent_purpose": "retrieval",
                "title": safe_text("DAG DB index"),
                "summary": safe_text("Safe summary only"),
                "keywords": [safe_text("catalog")],
                "catalog_path": ["KnowledgeGraphs", "dag-db"],
                "risk_class": "R1",
                "risk_bp": 100,
                "validation_status": "pending",
                "council_status": "not_required",
                "dag_finality_status": "pending",
                "status": "pending",
                "receipt_intent_id": receipt_intent_id
            }],
            "proposed_catalog_entries": [{
                "catalog_id": catalog_id,
                "memory_id": memory_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "catalog_path": ["KnowledgeGraphs", "dag-db"],
                "catalog_level": 2,
                "title": safe_text("DAG DB catalog"),
                "summary": safe_text("Catalog metadata"),
                "payload_hash": payload_hash,
                "source_hash": source_hash,
                "status": "pending",
                "validation_status": "pending",
                "council_status": "not_required",
                "dag_finality_status": "pending",
                "receipt_intent_id": receipt_intent_id
            }],
            "proposed_graph_nodes": [{
                "graph_node_id": graph_node_id,
                "memory_id": memory_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "graph_style": "semantic_catalog_graph",
                "node_kind": "raw",
                "catalog_path": ["KnowledgeGraphs", "dag-db"]
            }],
            "proposed_graph_edges": [{
                "graph_edge_id": graph_edge_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "graph_style": "semantic_catalog_graph",
                "from_memory_id": memory_id,
                "to_memory_id": memory_id,
                "edge_kind": "related_to",
                "source_edge_kind": "wikilink"
            }],
            "proposed_required_edges": [{
                "required_edge_id": required_edge_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "graph_style": "routing_view_graph",
                "from_memory_id": memory_id,
                "to_memory_id": memory_id,
                "edge_kind": "used_by_route",
                "status": "proposed"
            }],
            "proposed_layers": [
                {
                    "layer_id": root_layer_id,
                    "tenant_id": "dag-db-local",
                    "namespace": "dag-db",
                    "root_memory_id": memory_id,
                    "parent_layer_id": null,
                    "parent_graph_node_id": null,
                    "layer_depth": 0,
                    "layer_kind": "root",
                    "graph_style": "semantic_catalog_graph",
                    "layer_path": "root",
                    "metadata": {"source": "unit-test"}
                },
                {
                    "layer_id": source_layer_id,
                    "tenant_id": "dag-db-local",
                    "namespace": "dag-db",
                    "root_memory_id": memory_id,
                    "parent_layer_id": root_layer_id,
                    "parent_graph_node_id": graph_node_id,
                    "layer_depth": 1,
                    "layer_kind": "knowledge_graph",
                    "graph_style": "semantic_catalog_graph",
                    "layer_path": "root/knowledge-graph",
                    "metadata": {"source": "unit-test"}
                }
            ],
            "proposed_layer_memberships": [
                {
                    "layer_membership_id": root_membership_id,
                    "tenant_id": "dag-db-local",
                    "namespace": "dag-db",
                    "layer_id": root_layer_id,
                    "graph_node_id": graph_node_id,
                    "graph_style": "semantic_catalog_graph",
                    "membership_role": "root",
                    "local_node_rank": 0,
                    "metadata": {}
                },
                {
                    "layer_membership_id": source_membership_id,
                    "tenant_id": "dag-db-local",
                    "namespace": "dag-db",
                    "layer_id": source_layer_id,
                    "graph_node_id": graph_node_id,
                    "graph_style": "semantic_catalog_graph",
                    "membership_role": "member",
                    "local_node_rank": 0,
                    "metadata": {}
                }
            ],
            "proposed_layer_edges": [{
                "layer_edge_id": layer_edge_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "graph_style": "semantic_catalog_graph",
                "from_layer_id": root_layer_id,
                "to_layer_id": source_layer_id,
                "edge_kind": "contains_subgraph",
                "receipt_hash": null,
                "metadata": {}
            }],
            "proposed_placement_decisions": [{
                "placement_decision_id": placement_decision_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "input_memory_id": memory_id,
                "placement_trace": required_trace(),
                "target_layer_path": "root/knowledge-graph",
                "target_layer_depth": 1,
                "target_layer_reason": "unit_test_knowledge_graph_layer",
                "created_child_layer_id": source_layer_id,
                "layer_fallback_used": false,
                "canonicalization_decision": {
                    "canonical_memory_id": memory_id,
                    "confidence_bp": 9000,
                    "decision_kind": "new_canonical",
                    "decision_reason": "safe metadata fixture",
                    "matched_memory_ids": [memory_id],
                    "required_edges_to_create": [],
                    "risk_class": "R1",
                    "validator_status": "passed"
                },
                "similarity_results": [],
                "validator_report": "passed",
                "receipt_intent_id": receipt_intent_id
            }],
            "proposed_receipt_intents": [{
                "receipt_intent_id": receipt_intent_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "subject_kind": "memory",
                "subject_id": memory_id,
                "event_type": "intake_created",
                "actor_did": "did:exo:kg-importer",
                "reason": "safe repository test fixture"
            }],
            "proposed_validation_reports": [{
                "validation_report_id": validation_report_id,
                "tenant_id": "dag-db-local",
                "namespace": "dag-db",
                "subject_kind": "memory",
                "subject_id": memory_id,
                "validator_did": "did:exo:validator",
                "input_hash": payload_hash,
                "policy_hash": policy_hash,
                "validation_status": "passed",
                "risk_class": "R1",
                "risk_bp": 100,
                "decision": "allow",
                "notes": safe_text("validation metadata")
            }],
            "proposed_governance_reviews": [],
            "proposed_graph_view_refreshes": [],
            "proposed_route_invalidations": [],
            "proposed_subdag_boundaries": [],
            "rollback_plan": {},
            "placement_governance_summary": {},
            "review_items": [],
            "warnings": []
        })
    }

    fn parse_report(value: JsonValue) -> Result<KgImportDryRunReport> {
        KgImportDryRunReport::parse_json(&value.to_string())
    }

    #[test]
    fn kg_import_full_dry_run_report_validates_and_hashes() {
        let report = parse_report(valid_report_json()).expect("valid dry-run import report");

        assert_eq!(report.proposed_memory_records.len(), 1);
        assert_eq!(report.proposed_catalog_entries.len(), 1);
        assert_eq!(report.proposed_graph_nodes.len(), 1);
        assert_eq!(report.proposed_graph_edges.len(), 1);
        assert_eq!(report.proposed_required_edges.len(), 1);
        assert_eq!(report.proposed_layers.len(), 2);
        assert_eq!(report.proposed_layer_memberships.len(), 2);
        assert_eq!(report.proposed_layer_edges.len(), 1);
        assert_eq!(report.proposed_placement_decisions.len(), 1);
        assert_eq!(report.proposed_receipt_intents.len(), 1);
        assert_eq!(report.proposed_validation_reports.len(), 1);
        assert_eq!(
            report.proposed_placement_decisions[0].placement_trace,
            required_trace()
        );
        let first_key = report.idempotency_key();
        let second_key = report.idempotency_key();
        assert!(first_key.is_ok());
        assert_eq!(first_key.ok(), second_key.ok());
        assert!(stable_hash("exo.dagdb.test", &["tenant", "namespace"]).is_ok());
    }

    #[test]
    fn kg_import_report_rejects_malformed_tenant_identity() {
        // GAP-012 P1-E: tenant_id / namespace are validated at the write
        // entrypoint so malformed or ambiguous identities cannot be persisted.
        let valid = parse_report(valid_report_json());
        assert!(valid.is_ok(), "canonical tenant identity must parse");

        for bad in ["bad tenant", "tenant/evil", "tenant%wild", "te\tnant"] {
            let mut report = valid_report_json();
            report["tenant_id"] = json!(bad);
            assert!(
                matches!(
                    parse_report(report),
                    Err(KgImportError::InvalidReport { .. })
                ),
                "malformed tenant_id {bad:?} must fail closed"
            );
        }

        let mut bad_namespace = valid_report_json();
        bad_namespace["namespace"] = json!("name space");
        assert!(matches!(
            parse_report(bad_namespace),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_invalid_layer_relationships() {
        let mut missing_membership = valid_report_json();
        missing_membership["proposed_layer_memberships"] = json!([]);
        assert!(matches!(
            parse_report(missing_membership),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut bad_parent = valid_report_json();
        bad_parent["proposed_layers"][1]["parent_layer_id"] = json!("e1".repeat(32));
        assert!(matches!(
            parse_report(bad_parent),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut bad_layer_edge = valid_report_json();
        bad_layer_edge["proposed_layer_edges"][0]["to_layer_id"] = json!("e2".repeat(32));
        assert!(matches!(
            parse_report(bad_layer_edge),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut bad_target = valid_report_json();
        bad_target["proposed_placement_decisions"][0]["target_layer_path"] = json!("root/missing");
        assert!(matches!(
            parse_report(bad_target),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_non_derived_layer_identities() {
        // A layer_id derived for another tenant must not be importable here.
        let foreign_layer_id = expected_layer_id_hex(
            "victim-tenant",
            "dag-db",
            "semantic_catalog_graph",
            "root/knowledge-graph",
            1,
        )
        .expect("foreign layer id");
        let mut squatted_layer = valid_report_json();
        squatted_layer["proposed_layers"][1]["layer_id"] = json!(foreign_layer_id);
        squatted_layer["proposed_layer_memberships"][1]["layer_id"] = json!(foreign_layer_id);
        squatted_layer["proposed_layer_edges"][0]["to_layer_id"] = json!(foreign_layer_id);
        squatted_layer["proposed_placement_decisions"][0]["created_child_layer_id"] =
            json!(foreign_layer_id);
        match parse_report(squatted_layer) {
            Err(KgImportError::InvalidReport { reason }) => {
                assert!(reason.contains("deterministic"), "unexpected: {reason}");
            }
            other => panic!("expected squatted layer_id rejection, got {other:?}"),
        }

        let mut squatted_membership = valid_report_json();
        squatted_membership["proposed_layer_memberships"][1]["layer_membership_id"] =
            json!("c".repeat(64));
        match parse_report(squatted_membership) {
            Err(KgImportError::InvalidReport { reason }) => {
                assert!(
                    reason.contains("layer_membership_id"),
                    "unexpected: {reason}"
                );
            }
            other => panic!("expected squatted layer_membership_id rejection, got {other:?}"),
        }

        let mut squatted_edge = valid_report_json();
        squatted_edge["proposed_layer_edges"][0]["layer_edge_id"] = json!("c".repeat(64));
        match parse_report(squatted_edge) {
            Err(KgImportError::InvalidReport { reason }) => {
                assert!(reason.contains("layer_edge_id"), "unexpected: {reason}");
            }
            other => panic!("expected squatted layer_edge_id rejection, got {other:?}"),
        }
    }

    #[test]
    fn kg_import_report_rejects_invalid_layer_edge_hygiene_state() {
        let mut invalid_state = valid_report_json();
        invalid_state["proposed_layer_edges"][0]["metadata"] = json!({"hygiene_state": "unknown"});
        match parse_report(invalid_state) {
            Err(KgImportError::InvalidReport { reason }) => {
                assert!(reason.contains("hygiene_state"), "unexpected: {reason}");
            }
            other => panic!("expected invalid hygiene_state rejection, got {other:?}"),
        }

        let mut non_string_state = valid_report_json();
        non_string_state["proposed_layer_edges"][0]["metadata"] = json!({"hygiene_state": 1});
        assert!(matches!(
            parse_report(non_string_state),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut valid_state = valid_report_json();
        valid_state["proposed_layer_edges"][0]["metadata"] = json!({"hygiene_state": "demoted"});
        assert!(parse_report(valid_state).is_ok());
    }

    #[test]
    fn kg_import_report_rejects_layer_parent_cycle_at_max_depth() {
        let mut cyclic = valid_report_json();
        cyclic["proposed_layers"][0]["parent_layer_id"] = json!("f".repeat(64));
        cyclic["proposed_layers"][0]["parent_graph_node_id"] = json!("3".repeat(64));
        cyclic["proposed_layers"][0]["layer_depth"] = json!(u32::MAX);
        cyclic["proposed_layers"][1]["layer_depth"] = json!(u32::MAX);
        assert!(matches!(
            parse_report(cyclic),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_layer_depth_beyond_budget() {
        let mut too_deep = valid_report_json();
        too_deep["proposed_layers"][1]["layer_depth"] = json!(LAYER_CREATION_MAX_DEPTH + 1);
        let error = parse_report(too_deep).expect_err("layer depth beyond budget must fail");
        match error {
            KgImportError::InvalidReport { reason } => assert!(reason.contains("layer_depth")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn kg_import_report_validation_rejects_raw_body_and_dangerous_paths() {
        let raw = json!({
            "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
            "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
            "graph_root": "KnowledgeGraphs/dag-db",
            "tenant_id": "dag-db-local",
            "namespace": "dag-db",
            "actor_did": "did:exo:kg-importer",
            "batch_id": "a".repeat(64),
            "dry_run_only": true,
            "postgres_writes": false,
            "raw_markdown_included": false,
            "proposed_memory_records": [],
            "proposed_catalog_entries": [],
            "proposed_graph_nodes": [],
            "proposed_graph_edges": [],
            "proposed_required_edges": [],
            "proposed_placement_decisions": [],
            "proposed_receipt_intents": [],
            "proposed_validation_reports": [],
            "raw_markdown": "forbidden"
        });
        assert!(matches!(
            KgImportDryRunReport::parse_json(&raw.to_string()),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_case_variant_raw_keys_and_forbidden_values() {
        let mut mixed_case_key = valid_report_json();
        mixed_case_key["review_items"] = json!([{ "Raw_Markdown_Body": "forbidden" }]);
        assert!(matches!(
            parse_report(mixed_case_key),
            Err(KgImportError::InvalidReport { .. })
        ));

        for forbidden_value in [
            "/Users/example/dagdb.md",
            "PostgreSQL://exo:secret@localhost/dagdb",
            "BEGIN PRIVATE KEY",
            "Authorization: Bearer token",
            "sk-proj-example",
        ] {
            let mut report = valid_report_json();
            report["proposed_memory_records"][0]["summary"] = safe_text(forbidden_value);
            assert!(matches!(
                parse_report(report),
                Err(KgImportError::InvalidReport { .. })
            ));
        }
    }

    #[test]
    fn kg_import_report_rejects_review_named_raw_material_keys() {
        for key in [
            "payload",
            "private_payload",
            "Body",
            "body",
            "content",
            "source_body",
            "document_body",
            "prompt_body",
            "model_output",
            "raw_payload",
        ] {
            let mut unsafe_record = serde_json::Map::new();
            unsafe_record.insert(key.to_owned(), json!("unsafe raw material"));

            let mut report = valid_report_json();
            report["review_items"] = json!([JsonValue::Object(unsafe_record)]);

            assert!(
                matches!(
                    parse_report(report),
                    Err(KgImportError::InvalidReport { .. })
                ),
                "expected import report to reject raw material key: {key}"
            );
        }
    }

    #[test]
    fn kg_import_report_rejects_duplicate_invalid_source_path_without_echoing_path() {
        let mut report = valid_report_json();
        let mut duplicate = report["proposed_memory_records"][0].clone();
        duplicate["memory_id"] = json!("e".repeat(64));
        duplicate["source_path"] = json!("/private/dag-db.md");
        report["proposed_memory_records"][0]["source_path"] = json!("/private/dag-db.md");
        report["proposed_memory_records"]
            .as_array_mut()
            .expect("memory records")
            .push(duplicate);

        match parse_report(report) {
            Err(KgImportError::InvalidReport { reason }) => {
                assert!(reason.contains("source_path"));
                assert!(!reason.contains("/private/dag-db.md"));
                assert!(!reason.contains("private/dag-db.md"));
            }
            other => panic!("expected sanitized source_path rejection, got {other:?}"),
        }
    }

    #[test]
    fn kg_import_report_rejects_plain_bearer_marker_and_sanitizes_path_errors() {
        let mut bearer = valid_report_json();
        bearer["proposed_memory_records"][0]["summary"] = safe_text("Bearer abc123");
        assert!(matches!(
            parse_report(bearer),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut absolute_path = valid_report_json();
        absolute_path["graph_root"] = json!("/private/dag-db");
        match parse_report(absolute_path) {
            Err(KgImportError::InvalidReport { reason }) => {
                assert!(reason.contains("graph_root"));
                assert!(!reason.contains("/private/dag-db"));
                assert!(!reason.contains("private/dag-db"));
            }
            other => panic!("expected sanitized graph_root rejection, got {other:?}"),
        }

        let mut catalog_segment = valid_report_json();
        catalog_segment["proposed_catalog_entries"][0]["catalog_path"] =
            json!(["docs", "private/dag-db"]);
        match parse_report(catalog_segment) {
            Err(KgImportError::InvalidReport { reason }) => {
                assert!(reason.contains("catalog_path"));
                assert!(!reason.contains("private/dag-db"));
            }
            other => panic!("expected sanitized catalog_path rejection, got {other:?}"),
        }
    }

    #[test]
    fn kg_import_report_rejects_whitespace_only_required_fields() {
        let mut report = valid_report_json();
        report["tenant_id"] = json!(" \t\n ");
        assert!(matches!(
            parse_report(report),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut nested = valid_report_json();
        nested["proposed_memory_records"][0]["candidate_id"] = json!("   ");
        assert!(matches!(
            parse_report(nested),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut catalog_path = valid_report_json();
        catalog_path["proposed_memory_records"][0]["catalog_path"] = json!(["docs", "   "]);
        assert!(matches!(
            parse_report(catalog_path),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_preserves_generated_source_only_policy() {
        let mut report = valid_report_json();
        report["proposed_memory_records"][0]["source_type"] = json!("runtime");
        assert!(matches!(
            parse_report(report),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_top_level_schema_and_mode_violations() {
        assert!(matches!(
            KgImportDryRunReport::parse_json("{not json"),
            Err(KgImportError::InvalidJson { .. })
        ));

        let mut unsupported_report_schema = valid_report_json();
        unsupported_report_schema["schema_version"] = json!("other_schema");
        assert!(matches!(
            parse_report(unsupported_report_schema),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut unsupported_source_schema = valid_report_json();
        unsupported_source_schema["source_candidates_schema_version"] = json!("other_candidates");
        assert!(matches!(
            parse_report(unsupported_source_schema),
            Err(KgImportError::InvalidReport { .. })
        ));

        for (field, value) in [
            ("dry_run_only", json!(false)),
            ("postgres_writes", json!(true)),
            ("raw_markdown_included", json!(true)),
        ] {
            let mut report = valid_report_json();
            report[field] = value;
            assert!(matches!(
                parse_report(report),
                Err(KgImportError::InvalidReport { .. })
            ));
        }
    }

    #[test]
    fn kg_import_report_rejects_path_did_and_catalog_boundary_variants() {
        for graph_root in [
            "/private/dag-db",
            "~/.dag-db",
            "KnowledgeGraphs\\dag-db",
            "KnowledgeGraphs//dag-db",
            "KnowledgeGraphs/./dag-db",
            "KnowledgeGraphs/../dag-db",
        ] {
            let mut report = valid_report_json();
            report["graph_root"] = json!(graph_root);
            assert!(matches!(
                parse_report(report),
                Err(KgImportError::InvalidReport { .. })
            ));
        }

        let mut bad_did = valid_report_json();
        bad_did["actor_did"] = json!("exo:not-a-did");
        assert!(matches!(
            parse_report(bad_did),
            Err(KgImportError::InvalidReport { .. })
        ));

        for part in [".", "..", "docs/dagdb", "secret-material"] {
            let mut report = valid_report_json();
            report["proposed_catalog_entries"][0]["catalog_path"] = json!(["docs", part]);
            assert!(matches!(
                parse_report(report),
                Err(KgImportError::InvalidReport { .. })
            ));
        }

        let mut empty_catalog_path = valid_report_json();
        empty_catalog_path["proposed_catalog_entries"][0]["catalog_path"] = json!([]);
        assert!(matches!(
            parse_report(empty_catalog_path),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_covers_optional_and_nested_validation_branches() {
        let mut optional = valid_report_json();
        optional["proposed_placement_decisions"][0]["canonicalization_decision"]["canonical_memory_id"] =
            json!(null);
        optional["proposed_placement_decisions"][0]["canonicalization_decision"]["matched_memory_ids"] =
            json!([]);
        assert!(parse_report(optional).is_ok());

        for source_edge_kind in [
            "wikilink",
            "source_containment",
            "schema_reference",
            "command_test",
            "prd_relationship",
            "code_to_test",
        ] {
            let mut report = valid_report_json();
            report["proposed_graph_edges"][0]["source_edge_kind"] = json!(source_edge_kind);
            assert!(
                parse_report(report).is_ok(),
                "{source_edge_kind} must be accepted"
            );
        }

        for (section, field, value) in [
            ("proposed_graph_nodes", "memory_id", json!("not-a-hash")),
            (
                "proposed_graph_edges",
                "source_edge_kind",
                json!("semantic"),
            ),
            ("proposed_required_edges", "status", json!("approved")),
            (
                "proposed_receipt_intents",
                "event_type",
                json!("runtime_approved"),
            ),
            (
                "proposed_validation_reports",
                "decision",
                json!("approve_runtime"),
            ),
        ] {
            let mut report = valid_report_json();
            report[section][0][field] = value;
            assert!(matches!(
                parse_report(report),
                Err(KgImportError::InvalidReport { .. } | KgImportError::InvalidHash { .. })
            ));
        }
    }

    #[test]
    fn kg_import_rejects_self_asserted_governed_statuses() {
        let governed_mutations = [
            ("proposed_memory_records", "status", json!("routable")),
            ("proposed_memory_records", "status", json!("approved")),
            (
                "proposed_memory_records",
                "validation_status",
                json!("passed"),
            ),
            (
                "proposed_memory_records",
                "council_status",
                json!("approved"),
            ),
            (
                "proposed_memory_records",
                "dag_finality_status",
                json!("committed"),
            ),
            ("proposed_catalog_entries", "status", json!("routable")),
            ("proposed_catalog_entries", "status", json!("approved")),
            (
                "proposed_catalog_entries",
                "validation_status",
                json!("passed"),
            ),
            (
                "proposed_catalog_entries",
                "council_status",
                json!("approved"),
            ),
            (
                "proposed_catalog_entries",
                "dag_finality_status",
                json!("committed"),
            ),
        ];
        for (section, field, value) in governed_mutations {
            let mut report = valid_report_json();
            report[section][0][field] = value.clone();
            assert!(
                matches!(
                    parse_report(report),
                    Err(KgImportError::InvalidReport { .. })
                ),
                "import must reject self-asserted {section}.{field} = {value}"
            );
        }
    }

    #[test]
    fn kg_import_rejects_receipt_intent_actor_other_than_report_actor() {
        let mut report = valid_report_json();
        report["proposed_receipt_intents"][0]["actor_did"] = json!("did:exo:rogue-actor");
        assert!(matches!(
            parse_report(report),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_nested_raw_body_key() {
        let mut report = valid_report_json();
        report["review_items"] = json!([{ "content": "forbidden source excerpt" }]);

        assert!(matches!(
            parse_report(report),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_duplicate_and_cross_scope_records() {
        let mut duplicate = valid_report_json();
        let first = duplicate["proposed_memory_records"][0].clone();
        if let Some(records) = duplicate["proposed_memory_records"].as_array_mut() {
            records.push(first);
        }
        assert!(matches!(
            parse_report(duplicate),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut cross_scope = valid_report_json();
        cross_scope["proposed_catalog_entries"][0]["namespace"] = json!("other-namespace");
        assert!(matches!(
            parse_report(cross_scope),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_report_rejects_invalid_nested_choices() {
        let mut bad_graph_style = valid_report_json();
        bad_graph_style["proposed_graph_nodes"][0]["graph_style"] = json!("production_route_graph");
        assert!(matches!(
            parse_report(bad_graph_style),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut bad_decision = valid_report_json();
        bad_decision["proposed_placement_decisions"][0]["canonicalization_decision"]["decision_kind"] =
            json!("silently_accept");
        assert!(matches!(
            parse_report(bad_decision),
            Err(KgImportError::InvalidReport { .. })
        ));

        let mut bad_trace = valid_report_json();
        bad_trace["proposed_placement_decisions"][0]["placement_trace"] =
            json!(["source_verification"]);
        assert!(matches!(
            parse_report(bad_trace),
            Err(KgImportError::InvalidReport { .. })
        ));
    }

    #[test]
    fn kg_import_hash_parser_rejects_bad_hex() {
        assert!(hash_from_hex("fixture", &"a".repeat(64)).is_ok());
        assert!(hash_from_hex("fixture", &"0a".repeat(32)).is_ok());
        assert!(matches!(
            hash_from_hex("fixture", "not-hex"),
            Err(KgImportError::InvalidHash { .. })
        ));
    }
}

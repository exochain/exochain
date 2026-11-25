//! Feature-gated persisted KG import repository adapter.
//!
//! This adapter consumes validated dry-run reports as review artifacts and writes
//! only schema-supported DAG DB rows. It does not expose gateway behavior,
//! retrieval, writeback, export persistence, graph explorer changes, migrations,
//! or `exo-dag` table writes.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Hash256, Timestamp};
use exo_dag_db_api::{ReceiptEventType, SubjectKind};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

use crate::{
    hash::{ReceiptHashMaterial, RequestHashMaterial},
    kg_import::{
        KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_PERSISTED_ROUTE_NAME,
        KG_IMPORT_PERSISTED_SUMMARY_SCHEMA, KgImportCatalogEntry, KgImportDryRunReport,
        KgImportError, KgImportGraphEdge, KgImportGraphNode, KgImportLayer, KgImportLayerEdge,
        KgImportLayerMembership, KgImportMemoryRecord, KgImportPersistedSummary,
        KgImportPlacementDecision, KgImportReceiptIntent, KgImportRequiredEdge,
        KgImportValidationReport, hash_from_hex, stable_hash,
    },
    layer_creation_policy::{
        LayerAggregateError, LayerAggregateMember, distill_layer_aggregate_summary,
    },
    metadata::MetadataField,
    receipt::{
        OperationalReceiptInsert, insert_operational_receipt_in_transaction,
        operational_receipt_subject_id,
    },
    scoring::hash_event_body,
};

const CREATED_AT: Timestamp = Timestamp::new(1, 0);
const EXPIRES_AT: Timestamp = Timestamp::new(86_400_001, 0);
const KG_IMPORT_PERSISTED_IDEMPOTENCY_KEY_DOMAIN: &str =
    "exo.dagdb.kg_import.persisted.idempotency_key.v2";
const KG_IMPORT_PERSISTED_REQUEST_MATERIAL_SCHEMA: &str =
    "dagdb_kg_persisted_import_request_material_v1";

/// Errors raised by the feature-gated persisted KG import adapter.
#[derive(Debug, Error)]
pub enum KgImportPersistenceError {
    /// No database URL was supplied for persisted mode.
    #[error("kg_import_database_url_missing: {env_var}")]
    MissingDatabaseUrl {
        /// Required env var.
        env_var: &'static str,
    },
    /// Dry-run report validation failed.
    #[error(transparent)]
    Report(#[from] KgImportError),
    /// Postgres foundation failed.
    #[error("kg_import_postgres_init_failed")]
    Init {
        /// Source Postgres foundation error.
        #[source]
        source: super::DagDbPostgresError,
    },
    /// SQL operation failed.
    #[error("kg_import_postgres_failed")]
    Postgres {
        /// Source SQLx error.
        #[source]
        source: sqlx::Error,
    },
    /// JSON conversion failed.
    #[error("kg_import_json_failed: {reason}")]
    Json {
        /// Stable conversion reason.
        reason: String,
    },
    /// Existing row or idempotency key conflicts with the incoming report.
    #[error("kg_import_conflict: {reason}")]
    Conflict {
        /// Stable conflict reason.
        reason: String,
    },
    /// The current schema cannot support the requested persisted write.
    #[error("kg_import_unsupported_persisted_section: {section}")]
    UnsupportedSection {
        /// Dry-run section or receipt intent.
        section: String,
    },
    /// Timestamp value cannot be stored.
    #[error("kg_import_timestamp_out_of_range")]
    TimestampOutOfRange,
    /// Count cannot fit response field.
    #[error("kg_import_count_out_of_range")]
    CountOutOfRange,
    /// Hashing failed.
    #[error("kg_import_hash_failed: {reason}")]
    Hash {
        /// Stable hash reason.
        reason: String,
    },
    /// PRD-D2 (D2-S3): the import-time aggregate root summary could not be
    /// distilled (e.g. a layer member carried forbidden material). Fail-closed so
    /// a poisoned member's material never reaches a persisted aggregate.
    #[error("kg_import_layer_aggregate_failed: {reason}")]
    LayerAggregate {
        /// Stable aggregate failure reason.
        reason: String,
    },
}

impl From<LayerAggregateError> for KgImportPersistenceError {
    fn from(error: LayerAggregateError) -> Self {
        KgImportPersistenceError::LayerAggregate {
            reason: error.to_string(),
        }
    }
}

/// Result alias for persisted KG import.
pub type Result<T> = std::result::Result<T, KgImportPersistenceError>;

/// Persist a dry-run KG import report using `EXO_DAGDB_TEST_DATABASE_URL`.
pub async fn persist_kg_import_report_from_env(
    report_json: &str,
) -> Result<KgImportPersistedSummary> {
    let database_url = std::env::var(KG_IMPORT_DATABASE_URL_ENV).map_err(|_| {
        KgImportPersistenceError::MissingDatabaseUrl {
            env_var: KG_IMPORT_DATABASE_URL_ENV,
        }
    })?;
    persist_kg_import_report_from_database_url(Some(database_url.as_str()), report_json).await
}

/// Persist a dry-run KG import report using an explicit database URL.
pub async fn persist_kg_import_report_from_database_url(
    database_url: Option<&str>,
    report_json: &str,
) -> Result<KgImportPersistedSummary> {
    let Some(database_url) = database_url else {
        return Err(KgImportPersistenceError::MissingDatabaseUrl {
            env_var: KG_IMPORT_DATABASE_URL_ENV,
        });
    };
    let pool = super::init_pool(database_url)
        .await
        .map_err(|source| KgImportPersistenceError::Init { source })?;
    let result = persist_kg_import_report(&pool, report_json).await;
    pool.close().await;
    result
}

/// Persist supported sections from a validated dry-run KG import report.
pub async fn persist_kg_import_report(
    pool: &PgPool,
    report_json: &str,
) -> Result<KgImportPersistedSummary> {
    let report = KgImportDryRunReport::parse_json(report_json)?;
    let idempotency_key = persisted_idempotency_key(&report)?;
    let request_hash = RequestHashMaterial {
        route_name: KG_IMPORT_PERSISTED_ROUTE_NAME.to_owned(),
        tenant_id: report.tenant_id.clone(),
        namespace: report.namespace.clone(),
        canonical_redacted_request_body: canonical_persisted_request_body(report_json)?,
    }
    .hash()
    .map_err(|error| KgImportPersistenceError::Hash {
        reason: error.to_string(),
    })?;

    let mut tx = pool.begin().await.map_err(pg)?;
    let result =
        persist_kg_import_report_in_transaction(&mut tx, &report, &idempotency_key, request_hash)
            .await;
    match result {
        Ok(summary) => {
            tx.commit().await.map_err(pg)?;
            Ok(summary)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(
                    operation = "persist_kg_import_report",
                    tenant_id = %report.tenant_id,
                    namespace = %report.namespace,
                    error = %rollback_error,
                    "failed to rollback transaction after KG import persistence error"
                );
            }
            Err(error)
        }
    }
}

async fn persist_kg_import_report_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    report: &KgImportDryRunReport,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<KgImportPersistedSummary> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut **tx)
        .await
        .map_err(pg)?;
    super::bind_tenant_context(tx, &report.tenant_id)
        .await
        .map_err(pg)?;

    if let Some(summary) =
        fetch_idempotency_replay(tx, report, idempotency_key, request_hash).await?
    {
        return Ok(summary);
    }

    let receipt_index = ReceiptIndex::new(&report.proposed_receipt_intents);
    let mut counts = PersistedCounts::default();
    let mut memory_ids = BTreeSet::new();
    let mut graph_node_ids = BTreeSet::new();
    let mut layer_ids = BTreeSet::new();
    let mut graph_edge_keys = BTreeSet::new();

    for memory in &report.proposed_memory_records {
        let receipt = receipt_index.required("memory", &memory.memory_id, "intake_created")?;
        let (receipt_hash, inserted_receipts) = insert_receipt(tx, receipt).await?;
        counts.inserted_receipt_count = counts
            .inserted_receipt_count
            .saturating_add(inserted_receipts);
        counts.inserted_memory_count = counts
            .inserted_memory_count
            .saturating_add(insert_memory(tx, memory, receipt_hash).await?);
        memory_ids.insert(memory.memory_id.clone());
    }

    for catalog in &report.proposed_catalog_entries {
        let receipt = receipt_index.required("catalog", &catalog.catalog_id, "memory_approved")?;
        let (receipt_hash, inserted_receipts) = insert_receipt(tx, receipt).await?;
        counts.inserted_receipt_count = counts
            .inserted_receipt_count
            .saturating_add(inserted_receipts);
        counts.inserted_catalog_count = counts
            .inserted_catalog_count
            .saturating_add(insert_catalog(tx, catalog, receipt_hash).await?);
    }

    for validation in &report.proposed_validation_reports {
        let receipt = receipt_index.required(
            "validation_report",
            &validation.validation_report_id,
            "validation_created",
        )?;
        let (receipt_hash, inserted_receipts) = insert_receipt(tx, receipt).await?;
        counts.inserted_receipt_count = counts
            .inserted_receipt_count
            .saturating_add(inserted_receipts);
        counts.inserted_validation_report_count = counts
            .inserted_validation_report_count
            .saturating_add(insert_validation_report(tx, validation, receipt_hash).await?);
    }

    for node in &report.proposed_graph_nodes {
        if !memory_ids.contains(&node.memory_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!("graph node references unknown memory {}", node.memory_id),
            });
        }
        counts.inserted_graph_node_count = counts
            .inserted_graph_node_count
            .saturating_add(insert_graph_node(tx, node).await?);
        graph_node_ids.insert(node.graph_node_id.clone());
    }

    let mut ordered_layers = report.proposed_layers.iter().collect::<Vec<_>>();
    ordered_layers.sort_by_key(|layer| layer.layer_depth);
    for layer in ordered_layers {
        if !memory_ids.contains(&layer.root_memory_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "layer references unknown root memory {}",
                    layer.root_memory_id
                ),
            });
        }
        if let Some(parent_graph_node_id) = &layer.parent_graph_node_id
            && !graph_node_ids.contains(parent_graph_node_id)
        {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "layer references unknown parent graph node {parent_graph_node_id}"
                ),
            });
        }
        counts.inserted_layer_count = counts
            .inserted_layer_count
            .saturating_add(insert_layer(tx, layer).await?);
        layer_ids.insert(layer.layer_id.clone());
    }

    for membership in &report.proposed_layer_memberships {
        if !layer_ids.contains(&membership.layer_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "layer membership references unknown layer {}",
                    membership.layer_id
                ),
            });
        }
        if !graph_node_ids.contains(&membership.graph_node_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "layer membership references unknown graph node {}",
                    membership.graph_node_id
                ),
            });
        }
        counts.inserted_layer_membership_count = counts
            .inserted_layer_membership_count
            .saturating_add(insert_layer_membership(tx, membership).await?);
    }

    // PRD-D2 (D2-S3): author each layer's aggregate root summary at import time.
    // The aggregate is distilled deterministically (server-side, no LLM) from the
    // layer's members and persisted to dagdb_graph_layers.aggregate_summary, so
    // build_rollup_summaries surfaces a real digest instead of a stub member file.
    author_layer_aggregate_summaries(tx, report).await?;

    for edge in &report.proposed_layer_edges {
        if !layer_ids.contains(&edge.from_layer_id) || !layer_ids.contains(&edge.to_layer_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "layer edge references unknown endpoint {} -> {}",
                    edge.from_layer_id, edge.to_layer_id
                ),
            });
        }
        counts.inserted_layer_edge_count = counts
            .inserted_layer_edge_count
            .saturating_add(insert_layer_edge(tx, edge).await?);
    }

    for edge in &report.proposed_graph_edges {
        if !memory_ids.contains(&edge.from_memory_id) || !memory_ids.contains(&edge.to_memory_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "graph edge references unknown endpoint {} -> {}",
                    edge.from_memory_id, edge.to_memory_id
                ),
            });
        }
        let key = graph_edge_key(
            &edge.graph_style,
            &edge.from_memory_id,
            &edge.to_memory_id,
            &edge.edge_kind,
        );
        graph_edge_keys.insert(key);
        counts.inserted_graph_edge_count = counts
            .inserted_graph_edge_count
            .saturating_add(insert_graph_edge(tx, edge).await?);
    }

    for edge in &report.proposed_required_edges {
        if !memory_ids.contains(&edge.from_memory_id) || !memory_ids.contains(&edge.to_memory_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "required edge references unknown endpoint {} -> {}",
                    edge.from_memory_id, edge.to_memory_id
                ),
            });
        }
        let key = graph_edge_key(
            &edge.graph_style,
            &edge.from_memory_id,
            &edge.to_memory_id,
            &edge.edge_kind,
        );
        if graph_edge_keys.insert(key) {
            counts.inserted_graph_edge_count = counts
                .inserted_graph_edge_count
                .saturating_add(insert_required_edge(tx, edge).await?);
        }
    }

    for decision in &report.proposed_placement_decisions {
        if !memory_ids.contains(&decision.input_memory_id) {
            return Err(KgImportPersistenceError::Conflict {
                reason: format!(
                    "placement decision references unknown memory {}",
                    decision.input_memory_id
                ),
            });
        }
        counts.inserted_placement_decision_count = counts
            .inserted_placement_decision_count
            .saturating_add(insert_canonicalization_decision(tx, decision).await?);
        counts.inserted_placement_trace_count = counts
            .inserted_placement_trace_count
            .saturating_add(insert_placement_trace(tx, decision).await?);
    }

    let skipped_advisory_section_count = advisory_count(report)?;
    insert_import_approval_receipts(tx, report, idempotency_key, request_hash).await?;
    counts.inserted_receipt_count = counts.inserted_receipt_count.saturating_add(
        insert_import_completed_receipt(
            tx,
            report,
            idempotency_key,
            request_hash,
            &counts,
            skipped_advisory_section_count,
        )
        .await?,
    );
    let summary = KgImportPersistedSummary {
        schema_version: KG_IMPORT_PERSISTED_SUMMARY_SCHEMA.to_owned(),
        tenant_id: report.tenant_id.clone(),
        namespace: report.namespace.clone(),
        batch_id: report.batch_id.clone(),
        idempotency_key: idempotency_key.to_owned(),
        replayed: false,
        inserted_memory_count: counts.inserted_memory_count,
        inserted_catalog_count: counts.inserted_catalog_count,
        inserted_graph_node_count: counts.inserted_graph_node_count,
        inserted_graph_edge_count: counts.inserted_graph_edge_count,
        inserted_layer_count: counts.inserted_layer_count,
        inserted_layer_membership_count: counts.inserted_layer_membership_count,
        inserted_layer_edge_count: counts.inserted_layer_edge_count,
        inserted_validation_report_count: counts.inserted_validation_report_count,
        inserted_placement_decision_count: counts.inserted_placement_decision_count,
        inserted_placement_trace_count: counts.inserted_placement_trace_count,
        inserted_receipt_count: counts.inserted_receipt_count,
        skipped_advisory_section_count,
    };
    insert_idempotency_response(tx, &summary, request_hash).await?;
    Ok(summary)
}

async fn insert_import_approval_receipts(
    tx: &mut Transaction<'_, Postgres>,
    report: &KgImportDryRunReport,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<u32> {
    insert_operational_approval_receipts(
        tx,
        OperationalApprovalReceiptInput {
            tenant_id: &report.tenant_id,
            namespace: &report.namespace,
            actor_did: &report.actor_did,
            route_name: KG_IMPORT_PERSISTED_ROUTE_NAME,
            subject_ref: &request_hash.to_string(),
            subject_kind: SubjectKind::ValidationReport,
            idempotency_key,
            request_hash,
            source: "kg_import_persisted_adapter",
        },
    )
    .await
}

async fn insert_import_completed_receipt(
    tx: &mut Transaction<'_, Postgres>,
    report: &KgImportDryRunReport,
    idempotency_key: &str,
    request_hash: Hash256,
    counts: &PersistedCounts,
    skipped_advisory_section_count: u32,
) -> Result<u32> {
    let receipt_body = json!({
        "schema_version": KG_IMPORT_PERSISTED_SUMMARY_SCHEMA,
        "batch_id": report.batch_id,
        "idempotency_key": idempotency_key,
        "request_hash": request_hash.to_string(),
        "inserted_memory_count": counts.inserted_memory_count,
        "inserted_catalog_count": counts.inserted_catalog_count,
        "inserted_graph_node_count": counts.inserted_graph_node_count,
        "inserted_graph_edge_count": counts.inserted_graph_edge_count,
        "inserted_layer_count": counts.inserted_layer_count,
        "inserted_layer_membership_count": counts.inserted_layer_membership_count,
        "inserted_layer_edge_count": counts.inserted_layer_edge_count,
        "inserted_validation_report_count": counts.inserted_validation_report_count,
        "inserted_placement_decision_count": counts.inserted_placement_decision_count,
        "inserted_placement_trace_count": counts.inserted_placement_trace_count,
        "skipped_advisory_section_count": skipped_advisory_section_count,
        "source": "kg_import_persisted_adapter",
    });
    let event_type = ReceiptEventType::DagdbImportCompleted;
    let event_body_hash =
        hash_event_body(&receipt_body).map_err(|error| KgImportPersistenceError::Hash {
            reason: error.to_string(),
        })?;
    let receipt_hash = ReceiptHashMaterial {
        tenant_id: report.tenant_id.clone(),
        namespace: report.namespace.clone(),
        subject_kind: SubjectKind::ValidationReport,
        subject_id: request_hash,
        prev_receipt_hash: Hash256::ZERO,
        seq: 1,
        event_type,
        actor_did: report.actor_did.clone(),
        event_hlc: CREATED_AT,
        event_body_hash,
    }
    .hash()
    .map_err(|error| KgImportPersistenceError::Hash {
        reason: error.to_string(),
    })?;
    let event_hlc = timestamp_parts(CREATED_AT)?;
    let receipt_result = sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $11, $12, $9, $10) \
         ON CONFLICT (receipt_hash) DO NOTHING",
    )
    .bind(hash_bytes(receipt_hash))
    .bind(&report.tenant_id)
    .bind(&report.namespace)
    .bind(subject_kind_sql(SubjectKind::ValidationReport))
    .bind(hash_bytes(request_hash))
    .bind(hash_bytes(Hash256::ZERO))
    .bind(event_type_sql(event_type))
    .bind(&report.actor_did)
    .bind(event_hlc.physical_ms)
    .bind(event_hlc.logical)
    .bind(hash_bytes(event_body_hash))
    .bind(receipt_body)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;

    sqlx::query(
        "INSERT INTO dagdb_subject_receipt_heads \
         (tenant_id, namespace, subject_kind, subject_id, latest_receipt_hash, latest_seq, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, 1, $6, $7) \
         ON CONFLICT (tenant_id, namespace, subject_kind, subject_id) DO NOTHING",
    )
    .bind(&report.tenant_id)
    .bind(&report.namespace)
    .bind(subject_kind_sql(SubjectKind::ValidationReport))
    .bind(hash_bytes(request_hash))
    .bind(hash_bytes(receipt_hash))
    .bind(event_hlc.physical_ms)
    .bind(event_hlc.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;

    Ok(receipt_result
        .rows_affected()
        .try_into()
        .unwrap_or(u32::MAX))
}

struct OperationalApprovalReceiptInput<'a> {
    tenant_id: &'a str,
    namespace: &'a str,
    actor_did: &'a str,
    route_name: &'a str,
    subject_ref: &'a str,
    subject_kind: SubjectKind,
    idempotency_key: &'a str,
    request_hash: Hash256,
    source: &'a str,
}

async fn insert_operational_approval_receipts(
    tx: &mut Transaction<'_, Postgres>,
    input: OperationalApprovalReceiptInput<'_>,
) -> Result<u32> {
    let mut inserted = 0_u32;
    for event_type in [
        ReceiptEventType::DagdbApprovalRequestSubmitted,
        ReceiptEventType::DagdbApprovalGranted,
    ] {
        let receipt_body = json!({
            "route_name": input.route_name,
            "idempotency_key": input.idempotency_key,
            "request_hash": input.request_hash.to_string(),
            "source": input.source,
        });
        let event_body_hash =
            hash_event_body(&receipt_body).map_err(|error| KgImportPersistenceError::Hash {
                reason: error.to_string(),
            })?;
        let rows = insert_operational_receipt_in_transaction(
            tx,
            OperationalReceiptInsert {
                tenant_id: input.tenant_id,
                namespace: input.namespace,
                subject_kind: input.subject_kind,
                subject_id: operational_receipt_subject_id(
                    input.route_name,
                    input.subject_ref,
                    event_type,
                ),
                event_type,
                actor_did: input.actor_did,
                event_hlc: CREATED_AT,
                event_body_hash,
                receipt_body,
            },
        )
        .await
        .map_err(|error| KgImportPersistenceError::Postgres {
            source: sqlx::Error::Protocol(error.to_string()),
        })?;
        inserted = inserted.saturating_add(rows_to_u32(rows)?);
    }
    Ok(inserted)
}

#[derive(Default)]
struct PersistedCounts {
    inserted_memory_count: u32,
    inserted_catalog_count: u32,
    inserted_graph_node_count: u32,
    inserted_graph_edge_count: u32,
    inserted_layer_count: u32,
    inserted_layer_membership_count: u32,
    inserted_layer_edge_count: u32,
    inserted_validation_report_count: u32,
    inserted_placement_decision_count: u32,
    inserted_placement_trace_count: u32,
    inserted_receipt_count: u32,
}

struct ReceiptIndex<'a> {
    by_subject: BTreeMap<(String, String, String), &'a KgImportReceiptIntent>,
}

impl<'a> ReceiptIndex<'a> {
    fn new(receipts: &'a [KgImportReceiptIntent]) -> Self {
        let mut by_subject = BTreeMap::new();
        for receipt in receipts {
            by_subject.insert(
                (
                    receipt.subject_kind.clone(),
                    receipt.subject_id.clone(),
                    receipt.event_type.clone(),
                ),
                receipt,
            );
        }
        Self { by_subject }
    }

    fn required(
        &self,
        subject_kind: &str,
        subject_id: &str,
        event_type: &str,
    ) -> Result<&'a KgImportReceiptIntent> {
        self.by_subject
            .get(&(
                subject_kind.to_owned(),
                subject_id.to_owned(),
                event_type.to_owned(),
            ))
            .copied()
            .ok_or_else(|| KgImportPersistenceError::UnsupportedSection {
                section: format!(
                    "missing supported receipt intent {subject_kind}:{subject_id}:{event_type}"
                ),
            })
    }
}

async fn fetch_idempotency_replay(
    tx: &mut Transaction<'_, Postgres>,
    report: &KgImportDryRunReport,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<Option<KgImportPersistedSummary>> {
    let row = sqlx::query(
        "SELECT request_hash, response_body FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4 \
         FOR UPDATE",
    )
    .bind(&report.tenant_id)
    .bind(&report.namespace)
    .bind(KG_IMPORT_PERSISTED_ROUTE_NAME)
    .bind(idempotency_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;

    let Some(row) = row else {
        return Ok(None);
    };
    let existing_hash = hash_from_vec(row.try_get("request_hash").map_err(pg)?)?;
    if existing_hash != request_hash {
        return Err(KgImportPersistenceError::Conflict {
            reason: "idempotency_key_conflict".to_owned(),
        });
    }
    let body: JsonValue = row.try_get("response_body").map_err(pg)?;
    let mut summary: KgImportPersistedSummary =
        serde_json::from_value(body).map_err(|error| KgImportPersistenceError::Json {
            reason: error.to_string(),
        })?;
    summary.replayed = true;
    Ok(Some(summary))
}

fn persisted_idempotency_key(report: &KgImportDryRunReport) -> Result<String> {
    Ok(stable_hash(
        KG_IMPORT_PERSISTED_IDEMPOTENCY_KEY_DOMAIN,
        &[
            KG_IMPORT_PERSISTED_ROUTE_NAME,
            &report.tenant_id,
            &report.namespace,
            &report.actor_did,
            &report.graph_root,
            &report.batch_id,
            &report.schema_version,
        ],
    )?
    .to_string())
}

fn canonical_persisted_request_body(report_json: &str) -> Result<Vec<u8>> {
    let raw: JsonValue =
        serde_json::from_str(report_json).map_err(|error| KgImportPersistenceError::Json {
            reason: error.to_string(),
        })?;
    let memory_ids = record_id_set(&raw, "proposed_memory_records", "memory_id")?;
    let catalog_ids = record_id_set(&raw, "proposed_catalog_entries", "catalog_id")?;
    let validation_report_ids =
        record_id_set(&raw, "proposed_validation_reports", "validation_report_id")?;

    let dry_run_report = select_fields(
        &raw,
        &[
            "schema_version",
            "source_candidates_schema_version",
            "graph_root",
            "tenant_id",
            "namespace",
            "actor_did",
            "batch_id",
            "dry_run_only",
            "postgres_writes",
            "raw_markdown_included",
        ],
    )?;
    let mut material = json!({
        "schema_version": KG_IMPORT_PERSISTED_REQUEST_MATERIAL_SCHEMA,
        "dry_run_report": dry_run_report,
        "persisted_sections": {
            "proposed_memory_records": material_records_with_optional_fields(
                &raw,
                "proposed_memory_records",
                &[
                    "memory_id",
                    "tenant_id",
                    "namespace",
                    "source_path",
                    "candidate_id",
                    "node_type",
                    "source_type",
                    "source_hash",
                    "payload_hash",
                    "owner_did",
                    "controller_did",
                    "submitted_by_did",
                    "consent_purpose",
                    "title",
                    "summary",
                    "keywords",
                    "catalog_path",
                    "risk_class",
                    "risk_bp",
                    "validation_status",
                    "council_status",
                    "dag_finality_status",
                    "status",
                    "receipt_intent_id",
                ],
                // PRD-D3 (D3-S4): bind the deep tier into the request material
                // hash ONLY when present, so a report without a deep tier hashes
                // byte-identically to before (back-compat); a report carrying one
                // binds it so a changed deep tier conflicts on the same key.
                &["deep_detail_summary"],
            )?,
            "proposed_catalog_entries": material_records(
                &raw,
                "proposed_catalog_entries",
                &[
                    "catalog_id",
                    "memory_id",
                    "tenant_id",
                    "namespace",
                    "catalog_path",
                    "catalog_level",
                    "title",
                    "summary",
                    "payload_hash",
                    "source_hash",
                    "status",
                    "validation_status",
                    "council_status",
                    "dag_finality_status",
                    "receipt_intent_id",
                ],
            )?,
            "proposed_graph_nodes": material_records(
                &raw,
                "proposed_graph_nodes",
                &[
                    "graph_node_id",
                    "memory_id",
                    "tenant_id",
                    "namespace",
                    "graph_style",
                    "node_kind",
                    "catalog_path",
                ],
            )?,
            "proposed_graph_edges": material_records(
                &raw,
                "proposed_graph_edges",
                &[
                    "graph_edge_id",
                    "tenant_id",
                    "namespace",
                    "graph_style",
                    "from_memory_id",
                    "to_memory_id",
                    "edge_kind",
                    "source_edge_kind",
                ],
            )?,
            "proposed_required_edges": material_records(
                &raw,
                "proposed_required_edges",
                &[
                    "required_edge_id",
                    "tenant_id",
                    "namespace",
                    "graph_style",
                    "from_memory_id",
                    "to_memory_id",
                    "edge_kind",
                    "status",
                ],
            )?,
            "proposed_placement_decisions": material_records_with_optional_fields(
                &raw,
                "proposed_placement_decisions",
                &[
                    "placement_decision_id",
                    "tenant_id",
                    "namespace",
                    "input_memory_id",
                    "placement_trace",
                    "canonicalization_decision",
                    "receipt_intent_id",
                ],
                &[
                    "target_layer_path",
                    "target_layer_depth",
                    "target_layer_reason",
                    "created_child_layer_id",
                    "layer_fallback_used",
                ],
            )?,
            "proposed_receipt_intents": persisted_receipt_intent_records(
                &raw,
                &memory_ids,
                &catalog_ids,
                &validation_report_ids,
            )?,
            "proposed_validation_reports": material_records(
                &raw,
                "proposed_validation_reports",
                &[
                    "validation_report_id",
                    "tenant_id",
                    "namespace",
                    "subject_kind",
                    "subject_id",
                    "validator_did",
                    "input_hash",
                    "policy_hash",
                    "validation_status",
                    "risk_class",
                    "risk_bp",
                    "decision",
                    "notes",
                ],
            )?,
        },
    });
    let persisted_sections = material["persisted_sections"]
        .as_object_mut()
        .ok_or_else(|| json_reason("persisted_sections must be an object"))?;
    let proposed_layers = material_records(
        &raw,
        "proposed_layers",
        &[
            "layer_id",
            "tenant_id",
            "namespace",
            "root_memory_id",
            "parent_layer_id",
            "parent_graph_node_id",
            "layer_depth",
            "layer_kind",
            "graph_style",
            "layer_path",
            "metadata",
        ],
    )?;
    if proposed_layers
        .as_array()
        .is_some_and(|records| !records.is_empty())
    {
        persisted_sections.insert("proposed_layers".to_owned(), proposed_layers);
    }
    let proposed_layer_memberships = material_records(
        &raw,
        "proposed_layer_memberships",
        &[
            "layer_membership_id",
            "tenant_id",
            "namespace",
            "layer_id",
            "graph_node_id",
            "graph_style",
            "membership_role",
            "local_node_rank",
            "metadata",
        ],
    )?;
    if proposed_layer_memberships
        .as_array()
        .is_some_and(|records| !records.is_empty())
    {
        persisted_sections.insert(
            "proposed_layer_memberships".to_owned(),
            proposed_layer_memberships,
        );
    }
    let proposed_layer_edges = material_records(
        &raw,
        "proposed_layer_edges",
        &[
            "layer_edge_id",
            "tenant_id",
            "namespace",
            "graph_style",
            "from_layer_id",
            "to_layer_id",
            "edge_kind",
            "receipt_hash",
            "metadata",
        ],
    )?;
    if proposed_layer_edges
        .as_array()
        .is_some_and(|records| !records.is_empty())
    {
        persisted_sections.insert("proposed_layer_edges".to_owned(), proposed_layer_edges);
    }
    serde_json::to_vec(&material).map_err(|error| KgImportPersistenceError::Json {
        reason: error.to_string(),
    })
}

fn material_records(raw: &JsonValue, section: &str, fields: &[&str]) -> Result<JsonValue> {
    material_records_with_optional_fields(raw, section, fields, &[])
}

fn material_records_with_optional_fields(
    raw: &JsonValue,
    section: &str,
    fields: &[&str],
    optional_fields: &[&str],
) -> Result<JsonValue> {
    let records = optional_array(raw, section)?;
    let mut selected = Vec::with_capacity(records.len());
    for record in records {
        selected.push(select_fields_with_optional_fields(
            record,
            fields,
            optional_fields,
        )?);
    }
    sorted_json_array(selected)
}

fn persisted_receipt_intent_records(
    raw: &JsonValue,
    memory_ids: &BTreeSet<String>,
    catalog_ids: &BTreeSet<String>,
    validation_report_ids: &BTreeSet<String>,
) -> Result<JsonValue> {
    let mut selected = Vec::new();
    for receipt in optional_array(raw, "proposed_receipt_intents")? {
        let subject_kind = required_string(receipt, "subject_kind")?;
        let subject_id = required_string(receipt, "subject_id")?;
        let event_type = required_string(receipt, "event_type")?;
        let is_persisted_receipt = (subject_kind == "memory"
            && event_type == "intake_created"
            && memory_ids.contains(subject_id))
            || (subject_kind == "catalog"
                && event_type == "memory_approved"
                && catalog_ids.contains(subject_id))
            || (subject_kind == "validation_report"
                && event_type == "validation_created"
                && validation_report_ids.contains(subject_id));
        if is_persisted_receipt {
            selected.push(select_fields(
                receipt,
                &[
                    "receipt_intent_id",
                    "tenant_id",
                    "namespace",
                    "subject_kind",
                    "subject_id",
                    "event_type",
                    "actor_did",
                    "reason",
                ],
            )?);
        }
    }
    sorted_json_array(selected)
}

fn record_id_set(raw: &JsonValue, section: &str, id_field: &str) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for record in optional_array(raw, section)? {
        ids.insert(required_string(record, id_field)?.to_owned());
    }
    Ok(ids)
}

fn optional_array<'a>(raw: &'a JsonValue, section: &str) -> Result<&'a [JsonValue]> {
    match raw.get(section) {
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| json_reason(format!("{section} must be an array"))),
        None => Ok(&[]),
    }
}

fn select_fields(value: &JsonValue, fields: &[&str]) -> Result<JsonValue> {
    select_fields_with_optional_fields(value, fields, &[])
}

fn select_fields_with_optional_fields(
    value: &JsonValue,
    fields: &[&str],
    optional_fields: &[&str],
) -> Result<JsonValue> {
    let object = value
        .as_object()
        .ok_or_else(|| json_reason("request material record must be an object"))?;
    let mut selected = serde_json::Map::new();
    for field in fields {
        let field_value = object
            .get(*field)
            .ok_or_else(|| json_reason(format!("request material missing {field}")))?;
        selected.insert((*field).to_owned(), field_value.clone());
    }
    for field in optional_fields {
        if let Some(field_value) = object.get(*field) {
            selected.insert((*field).to_owned(), field_value.clone());
        }
    }
    Ok(JsonValue::Object(selected))
}

fn required_string<'a>(value: &'a JsonValue, field: &str) -> Result<&'a str> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| json_reason(format!("request material missing {field}")))
}

fn sorted_json_array(mut values: Vec<JsonValue>) -> Result<JsonValue> {
    values.sort_by_key(canonical_json_string);
    Ok(JsonValue::Array(values))
}

fn canonical_json_string(value: &JsonValue) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

fn json_reason(reason: impl Into<String>) -> KgImportPersistenceError {
    KgImportPersistenceError::Json {
        reason: reason.into(),
    }
}

async fn insert_idempotency_response(
    tx: &mut Transaction<'_, Postgres>,
    summary: &KgImportPersistedSummary,
    request_hash: Hash256,
) -> Result<()> {
    let response_body = json_value(summary)?;
    let response_hash =
        hash_event_body(summary).map_err(|error| KgImportPersistenceError::Hash {
            reason: error.to_string(),
        })?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let expires_at = timestamp_parts(EXPIRES_AT)?;
    sqlx::query(
        "INSERT INTO dagdb_idempotency_keys \
         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, response_body, \
          status_code, cached_failure, created_at_physical_ms, created_at_logical, \
          expires_at_physical_ms, expires_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 201, false, $8, $9, $10, $11)",
    )
    .bind(&summary.tenant_id)
    .bind(&summary.namespace)
    .bind(KG_IMPORT_PERSISTED_ROUTE_NAME)
    .bind(&summary.idempotency_key)
    .bind(hash_bytes(request_hash))
    .bind(hash_bytes(response_hash))
    .bind(response_body)
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .bind(expires_at.physical_ms)
    .bind(expires_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    Ok(())
}

async fn insert_receipt(
    tx: &mut Transaction<'_, Postgres>,
    intent: &KgImportReceiptIntent,
) -> Result<(Hash256, u32)> {
    let subject_kind = subject_kind(intent.subject_kind.as_str())?;
    let subject_id = hash_from_hex("receipt.subject_id", &intent.subject_id)?;
    let event_type = event_type(intent.event_type.as_str())?;
    let receipt_body = json!({
        "receipt_intent_id": intent.receipt_intent_id,
        "reason": intent.reason,
        "source": "kg_import_persisted_adapter"
    });
    let event_body_hash = stable_hash(
        "exo.dagdb.kg_import.persisted.receipt_body_hash",
        &[
            &intent.receipt_intent_id,
            &intent.subject_id,
            &intent.event_type,
            &intent.reason,
        ],
    )?;
    let receipt_hash = ReceiptHashMaterial {
        tenant_id: intent.tenant_id.clone(),
        namespace: intent.namespace.clone(),
        subject_kind,
        subject_id,
        prev_receipt_hash: Hash256::ZERO,
        seq: 1,
        event_type,
        actor_did: intent.actor_did.clone(),
        event_hlc: CREATED_AT,
        event_body_hash,
    }
    .hash()
    .map_err(|error| KgImportPersistenceError::Hash {
        reason: error.to_string(),
    })?;
    let event_hlc = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $11, $12, $9, $10) \
         ON CONFLICT (receipt_hash) DO NOTHING",
    )
    .bind(hash_bytes(receipt_hash))
    .bind(&intent.tenant_id)
    .bind(&intent.namespace)
    .bind(subject_kind_sql(subject_kind))
    .bind(hash_bytes(subject_id))
    .bind(hash_bytes(Hash256::ZERO))
    .bind(event_type_sql(event_type))
    .bind(&intent.actor_did)
    .bind(event_hlc.physical_ms)
    .bind(event_hlc.logical)
    .bind(hash_bytes(event_body_hash))
    .bind(receipt_body)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    let inserted_count = result.rows_affected().try_into().unwrap_or(u32::MAX);

    sqlx::query(
        "INSERT INTO dagdb_subject_receipt_heads \
         (tenant_id, namespace, subject_kind, subject_id, latest_receipt_hash, latest_seq, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, 1, $6, $7) \
         ON CONFLICT (tenant_id, namespace, subject_kind, subject_id) DO NOTHING",
    )
    .bind(&intent.tenant_id)
    .bind(&intent.namespace)
    .bind(subject_kind_sql(subject_kind))
    .bind(hash_bytes(subject_id))
    .bind(hash_bytes(receipt_hash))
    .bind(event_hlc.physical_ms)
    .bind(event_hlc.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    Ok((receipt_hash, inserted_count))
}

async fn insert_memory(
    tx: &mut Transaction<'_, Postgres>,
    memory: &KgImportMemoryRecord,
    latest_receipt_hash: Hash256,
) -> Result<u32> {
    ensure_memory_match(tx, memory).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_memory_objects \
         (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, payload_hash, source_hash, \
          owner_did, controller_did, submitted_by_did, title, summary, deep_detail_summary, keywords, risk_class, risk_bp, \
          status, validation_status, council_status, dag_finality_status, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
          $18, $19, $20, $21, $22, $23, $24, $23, $24) \
         ON CONFLICT (memory_id) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("memory_id", &memory.memory_id)?))
    .bind(&memory.tenant_id)
    .bind(&memory.namespace)
    .bind(&memory.node_type)
    .bind(&memory.source_type)
    .bind(&memory.consent_purpose)
    .bind(hash_bytes(hash_from_hex("payload_hash", &memory.payload_hash)?))
    .bind(hash_bytes(hash_from_hex("source_hash", &memory.source_hash)?))
    .bind(&memory.owner_did)
    .bind(&memory.controller_did)
    .bind(&memory.submitted_by_did)
    .bind(json_value(&memory.title)?)
    .bind(json_value(&memory.summary)?)
    // PRD-D3 (D3-S4): persist the nullable deep tier. NULL when the report
    // carries no deep tier (back-compat); a present deep tier is already screened
    // fail-closed by reject_forbidden_report_json before this insert runs.
    .bind(memory.deep_detail_summary.as_ref().map(json_value).transpose()?)
    .bind(json_value(&memory.keywords)?)
    .bind(&memory.risk_class)
    .bind(i32::from(memory.risk_bp))
    .bind(&memory.status)
    .bind(&memory.validation_status)
    .bind(&memory.council_status)
    .bind(&memory.dag_finality_status)
    .bind(hash_bytes(latest_receipt_hash))
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn insert_catalog(
    tx: &mut Transaction<'_, Postgres>,
    catalog: &KgImportCatalogEntry,
    latest_receipt_hash: Hash256,
) -> Result<u32> {
    ensure_catalog_match(tx, catalog).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_catalog_entries \
         (catalog_id, tenant_id, namespace, memory_id, catalog_level, title, summary, keywords, payload_hash, source_hash, \
          status, validation_status, council_status, dag_finality_status, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, '[]'::jsonb, $8, $9, $10, $11, $12, $13, $14, $15, $16, $15, $16) \
         ON CONFLICT (catalog_id) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("catalog_id", &catalog.catalog_id)?))
    .bind(&catalog.tenant_id)
    .bind(&catalog.namespace)
    .bind(hash_bytes(hash_from_hex("catalog.memory_id", &catalog.memory_id)?))
    .bind(i32::try_from(catalog.catalog_level).map_err(|_| KgImportPersistenceError::CountOutOfRange)?)
    .bind(json_value(&catalog.title)?)
    .bind(json_value(&catalog.summary)?)
    .bind(hash_bytes(hash_from_hex("catalog.payload_hash", &catalog.payload_hash)?))
    .bind(hash_bytes(hash_from_hex("catalog.source_hash", &catalog.source_hash)?))
    .bind(&catalog.status)
    .bind(&catalog.validation_status)
    .bind(&catalog.council_status)
    .bind(&catalog.dag_finality_status)
    .bind(hash_bytes(latest_receipt_hash))
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn insert_validation_report(
    tx: &mut Transaction<'_, Postgres>,
    report: &KgImportValidationReport,
    latest_receipt_hash: Hash256,
) -> Result<u32> {
    ensure_validation_report_match(tx, report).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_validation_reports \
         (validation_report_id, tenant_id, namespace, subject_kind, subject_id, validator_did, input_hash, policy_hash, \
          validation_status, risk_class, risk_bp, decision, notes, contradictory_report_ids, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, '[]'::jsonb, $14, $15, $16) \
         ON CONFLICT (validation_report_id) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("validation_report_id", &report.validation_report_id)?))
    .bind(&report.tenant_id)
    .bind(&report.namespace)
    .bind(&report.subject_kind)
    .bind(hash_bytes(hash_from_hex("validation.subject_id", &report.subject_id)?))
    .bind(&report.validator_did)
    .bind(hash_bytes(hash_from_hex("validation.input_hash", &report.input_hash)?))
    .bind(hash_bytes(hash_from_hex("validation.policy_hash", &report.policy_hash)?))
    .bind(&report.validation_status)
    .bind(&report.risk_class)
    .bind(i32::from(report.risk_bp))
    .bind(&report.decision)
    .bind(json_value(&report.notes)?)
    .bind(hash_bytes(latest_receipt_hash))
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn insert_graph_node(
    tx: &mut Transaction<'_, Postgres>,
    node: &KgImportGraphNode,
) -> Result<u32> {
    ensure_graph_node_match(tx, node).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_graph_nodes \
         (graph_node_id, tenant_id, namespace, memory_id, graph_style, node_kind, catalog_path, metadata, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (graph_node_id) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("graph_node_id", &node.graph_node_id)?))
    .bind(&node.tenant_id)
    .bind(&node.namespace)
    .bind(hash_bytes(hash_from_hex("graph_node.memory_id", &node.memory_id)?))
    .bind(&node.graph_style)
    .bind(&node.node_kind)
    .bind(node.catalog_path.join("/"))
    .bind(json!({"source": "kg_import_dry_run"}))
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn insert_graph_edge(
    tx: &mut Transaction<'_, Postgres>,
    edge: &KgImportGraphEdge,
) -> Result<u32> {
    insert_graph_edge_parts(
        tx,
        &edge.graph_edge_id,
        &edge.tenant_id,
        &edge.namespace,
        &edge.graph_style,
        &edge.from_memory_id,
        &edge.to_memory_id,
        &edge.edge_kind,
    )
    .await
}

async fn insert_required_edge(
    tx: &mut Transaction<'_, Postgres>,
    edge: &KgImportRequiredEdge,
) -> Result<u32> {
    insert_graph_edge_parts(
        tx,
        &edge.required_edge_id,
        &edge.tenant_id,
        &edge.namespace,
        &edge.graph_style,
        &edge.from_memory_id,
        &edge.to_memory_id,
        &edge.edge_kind,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn insert_graph_edge_parts(
    tx: &mut Transaction<'_, Postgres>,
    edge_id: &str,
    tenant_id: &str,
    namespace: &str,
    graph_style: &str,
    from_memory_id: &str,
    to_memory_id: &str,
    edge_kind: &str,
) -> Result<u32> {
    ensure_graph_edge_match(
        tx,
        edge_id,
        tenant_id,
        namespace,
        graph_style,
        from_memory_id,
        to_memory_id,
        edge_kind,
    )
    .await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_graph_edges \
         (graph_edge_id, tenant_id, namespace, graph_style, from_memory_id, to_memory_id, edge_kind, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (tenant_id, namespace, graph_style, from_memory_id, to_memory_id, edge_kind) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("graph_edge_id", edge_id)?))
    .bind(tenant_id)
    .bind(namespace)
    .bind(graph_style)
    .bind(hash_bytes(hash_from_hex("from_memory_id", from_memory_id)?))
    .bind(hash_bytes(hash_from_hex("to_memory_id", to_memory_id)?))
    .bind(edge_kind)
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

/// PRD-D2 (D2-S3): author and persist each layer's aggregate root summary.
///
/// For every proposed layer, the aggregate is distilled deterministically from
/// the layer's NON-root member memories (resolved from the report:
/// membership.graph_node_id -> graph_node.memory_id -> memory.title/summary),
/// top-N by `local_node_rank` exactly as `distill_layer_aggregate_summary` does.
/// The distiller screens forbidden material fail-closed, so a poisoned member's
/// material never reaches a persisted aggregate. The distilled title/summary are
/// re-sanitized into the stored SafeMetadata shape (a second fail-closed screen)
/// and written to `dagdb_graph_layers.aggregate_summary` as `{title, summary}`,
/// the exact object shape `parse_layer_aggregate_summary` reads in the rollup
/// path. A layer with no content-bearing member is left NULL (rollup falls back).
async fn author_layer_aggregate_summaries(
    tx: &mut Transaction<'_, Postgres>,
    report: &KgImportDryRunReport,
) -> Result<()> {
    if report.proposed_layers.is_empty() {
        return Ok(());
    }
    // graph_node_id -> memory_id
    let node_to_memory: BTreeMap<&str, &str> = report
        .proposed_graph_nodes
        .iter()
        .map(|node| (node.graph_node_id.as_str(), node.memory_id.as_str()))
        .collect();
    // memory_id -> (title text, summary text)
    let memory_text: BTreeMap<&str, (&str, &str)> = report
        .proposed_memory_records
        .iter()
        .map(|memory| {
            (
                memory.memory_id.as_str(),
                (memory.title.text.as_str(), memory.summary.text.as_str()),
            )
        })
        .collect();

    for layer in &report.proposed_layers {
        // Collect the layer's members: non-root memberships, resolved to their
        // memory title/summary. Deterministic input — the distiller applies the
        // top-N-by-rank selection and length cap itself.
        let mut members = Vec::new();
        for membership in &report.proposed_layer_memberships {
            if membership.layer_id != layer.layer_id || membership.membership_role == "root" {
                continue;
            }
            let Some(memory_id) = node_to_memory.get(membership.graph_node_id.as_str()) else {
                continue;
            };
            let Some((title, summary)) = memory_text.get(*memory_id) else {
                continue;
            };
            members.push(LayerAggregateMember {
                member_id: (*memory_id).to_owned(),
                local_node_rank: membership.local_node_rank,
                title: (*title).to_owned(),
                summary: (*summary).to_owned(),
            });
        }
        if members.is_empty() {
            continue;
        }

        // Distill (fail-closed forbidden-material screen). NoContent means no safe
        // content-bearing piece survived; leave the aggregate NULL for that layer.
        let aggregate = match distill_layer_aggregate_summary(&members) {
            Ok(aggregate) => aggregate,
            Err(LayerAggregateError::NoContent) => continue,
            Err(error) => return Err(error.into()),
        };

        // Re-sanitize into the stored SafeMetadata shape (second fail-closed
        // screen). Summary field bound (1000) comfortably holds the aggregate
        // title (<=200) and summary (<=700) without re-truncation.
        let title_metadata =
            crate::metadata::sanitize_runtime_metadata(MetadataField::Summary, &aggregate.title)
                .map_err(|error| KgImportPersistenceError::LayerAggregate {
                    reason: format!("aggregate title rejected: {error}"),
                })?;
        let summary_metadata =
            crate::metadata::sanitize_runtime_metadata(MetadataField::Summary, &aggregate.summary)
                .map_err(|error| KgImportPersistenceError::LayerAggregate {
                    reason: format!("aggregate summary rejected: {error}"),
                })?;
        let aggregate_json = json!({
            "title": json_value(&title_metadata)?,
            "summary": json_value(&summary_metadata)?,
        });

        sqlx::query(
            "UPDATE dagdb_graph_layers SET aggregate_summary = $1 \
             WHERE tenant_id = $2 AND namespace = $3 AND layer_id = $4",
        )
        .bind(&aggregate_json)
        .bind(&layer.tenant_id)
        .bind(&layer.namespace)
        .bind(hash_bytes(hash_from_hex(
            "layer.layer_id",
            &layer.layer_id,
        )?))
        .execute(&mut **tx)
        .await
        .map_err(pg)?;
    }
    Ok(())
}

async fn insert_layer(tx: &mut Transaction<'_, Postgres>, layer: &KgImportLayer) -> Result<u32> {
    ensure_layer_match(tx, layer).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let parent_layer_id = layer
        .parent_layer_id
        .as_ref()
        .map(|value| hash_from_hex("parent_layer_id", value).map(hash_bytes))
        .transpose()?;
    let parent_graph_node_id = layer
        .parent_graph_node_id
        .as_ref()
        .map(|value| hash_from_hex("parent_graph_node_id", value).map(hash_bytes))
        .transpose()?;
    let result = sqlx::query(
        "INSERT INTO dagdb_graph_layers \
         (layer_id, tenant_id, namespace, root_memory_id, parent_layer_id, parent_graph_node_id, \
          layer_depth, layer_kind, graph_style, layer_path, metadata, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $12, $13) \
         ON CONFLICT (tenant_id, namespace, layer_path) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("layer_id", &layer.layer_id)?))
    .bind(&layer.tenant_id)
    .bind(&layer.namespace)
    .bind(hash_bytes(hash_from_hex(
        "layer.root_memory_id",
        &layer.root_memory_id,
    )?))
    .bind(parent_layer_id)
    .bind(parent_graph_node_id)
    .bind(i32::try_from(layer.layer_depth).map_err(|_| KgImportPersistenceError::CountOutOfRange)?)
    .bind(&layer.layer_kind)
    .bind(&layer.graph_style)
    .bind(&layer.layer_path)
    .bind(&layer.metadata)
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn insert_layer_membership(
    tx: &mut Transaction<'_, Postgres>,
    membership: &KgImportLayerMembership,
) -> Result<u32> {
    ensure_layer_membership_match(tx, membership).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_graph_layer_memberships \
         (layer_membership_id, tenant_id, namespace, layer_id, graph_node_id, graph_style, \
          membership_role, local_node_rank, metadata, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $10, $11) \
         ON CONFLICT (tenant_id, namespace, layer_id, graph_node_id) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex(
        "layer_membership_id",
        &membership.layer_membership_id,
    )?))
    .bind(&membership.tenant_id)
    .bind(&membership.namespace)
    .bind(hash_bytes(hash_from_hex(
        "layer_membership.layer_id",
        &membership.layer_id,
    )?))
    .bind(hash_bytes(hash_from_hex(
        "layer_membership.graph_node_id",
        &membership.graph_node_id,
    )?))
    .bind(&membership.graph_style)
    .bind(&membership.membership_role)
    .bind(
        i32::try_from(membership.local_node_rank)
            .map_err(|_| KgImportPersistenceError::CountOutOfRange)?,
    )
    .bind(&membership.metadata)
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn insert_layer_edge(
    tx: &mut Transaction<'_, Postgres>,
    edge: &KgImportLayerEdge,
) -> Result<u32> {
    ensure_layer_edge_match(tx, edge).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let metadata = layer_edge_metadata_with_hygiene_default(&edge.metadata);
    let receipt_hash = edge
        .receipt_hash
        .as_ref()
        .map(|value| hash_from_hex("layer_edge.receipt_hash", value).map(hash_bytes))
        .transpose()?;
    let result = sqlx::query(
        "INSERT INTO dagdb_graph_layer_edges \
         (layer_edge_id, tenant_id, namespace, graph_style, from_layer_id, to_layer_id, edge_kind, \
          receipt_hash, metadata, created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $10, $11) \
         ON CONFLICT (tenant_id, namespace, graph_style, from_layer_id, to_layer_id, edge_kind) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("layer_edge_id", &edge.layer_edge_id)?))
    .bind(&edge.tenant_id)
    .bind(&edge.namespace)
    .bind(&edge.graph_style)
    .bind(hash_bytes(hash_from_hex(
        "layer_edge.from_layer_id",
        &edge.from_layer_id,
    )?))
    .bind(hash_bytes(hash_from_hex(
        "layer_edge.to_layer_id",
        &edge.to_layer_id,
    )?))
    .bind(&edge.edge_kind)
    .bind(receipt_hash)
    .bind(metadata)
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

/// Persisted layer edges must always carry a hygiene state so layered
/// retrieval cannot be poisoned by rows that fail its fail-closed parser.
fn layer_edge_metadata_with_hygiene_default(metadata: &JsonValue) -> JsonValue {
    let mut value = metadata.clone();
    if let Some(map) = value.as_object_mut() {
        map.entry("hygiene_state".to_owned())
            .or_insert_with(|| JsonValue::String("active".to_owned()));
    }
    value
}

async fn insert_canonicalization_decision(
    tx: &mut Transaction<'_, Postgres>,
    decision: &KgImportPlacementDecision,
) -> Result<u32> {
    ensure_canonicalization_match(tx, decision).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let canonical_memory_id = decision
        .canonicalization_decision
        .canonical_memory_id
        .as_ref()
        .map(|value| hash_from_hex("canonical_memory_id", value).map(hash_bytes))
        .transpose()?;
    let matched_memory_ids: Vec<String> = decision
        .canonicalization_decision
        .matched_memory_ids
        .clone();
    let result = sqlx::query(
        "INSERT INTO dagdb_graph_canonicalization_decisions \
         (decision_id, tenant_id, namespace, input_memory_id, canonical_memory_id, matched_memory_ids, decision_kind, \
          decision_reason, confidence_bp, risk_class, validator_status, required_edges_to_create, receipt_intent, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         ON CONFLICT (decision_id) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex(
        "placement_decision_id",
        &decision.placement_decision_id,
    )?))
    .bind(&decision.tenant_id)
    .bind(&decision.namespace)
    .bind(hash_bytes(hash_from_hex("input_memory_id", &decision.input_memory_id)?))
    .bind(canonical_memory_id)
    .bind(json_value(&matched_memory_ids)?)
    .bind(&decision.canonicalization_decision.decision_kind)
    .bind(&decision.canonicalization_decision.decision_reason)
    .bind(i32::from(decision.canonicalization_decision.confidence_bp))
    .bind(&decision.canonicalization_decision.risk_class)
    .bind(&decision.canonicalization_decision.validator_status)
    .bind(json_value(
        &decision
            .canonicalization_decision
            .required_edges_to_create,
    )?)
    .bind(&decision.receipt_intent_id)
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn insert_placement_trace(
    tx: &mut Transaction<'_, Postgres>,
    decision: &KgImportPlacementDecision,
) -> Result<u32> {
    let trace_id = stable_hash(
        "exo.dagdb.kg_import.persisted.placement_trace_id",
        &[&decision.placement_decision_id, &decision.input_memory_id],
    )?;
    ensure_placement_trace_match(tx, decision, trace_id).await?;
    let created_at = timestamp_parts(CREATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_graph_placement_traces \
         (placement_trace_id, tenant_id, namespace, input_memory_id, trace_steps, completed, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, true, $6, $7) \
         ON CONFLICT (placement_trace_id) DO NOTHING",
    )
    .bind(hash_bytes(trace_id))
    .bind(&decision.tenant_id)
    .bind(&decision.namespace)
    .bind(hash_bytes(hash_from_hex("input_memory_id", &decision.input_memory_id)?))
    .bind(json_value(&decision.placement_trace)?)
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    rows_to_u32(result.rows_affected())
}

async fn ensure_memory_match(
    tx: &mut Transaction<'_, Postgres>,
    memory: &KgImportMemoryRecord,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, payload_hash, source_hash FROM dagdb_memory_objects WHERE memory_id = $1",
    )
    .bind(hash_bytes(hash_from_hex("memory_id", &memory.memory_id)?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let payload_hash = hash_from_vec(row.try_get("payload_hash").map_err(pg)?)?;
    let source_hash = hash_from_vec(row.try_get("source_hash").map_err(pg)?)?;
    if tenant_id == memory.tenant_id
        && namespace == memory.namespace
        && payload_hash == hash_from_hex("payload_hash", &memory.payload_hash)?
        && source_hash == hash_from_hex("source_hash", &memory.source_hash)?
    {
        Ok(())
    } else {
        Err(KgImportPersistenceError::Conflict {
            reason: format!("existing memory row mismatch for {}", memory.memory_id),
        })
    }
}

async fn ensure_catalog_match(
    tx: &mut Transaction<'_, Postgres>,
    catalog: &KgImportCatalogEntry,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, memory_id, payload_hash, source_hash \
         FROM dagdb_catalog_entries WHERE catalog_id = $1",
    )
    .bind(hash_bytes(hash_from_hex(
        "catalog_id",
        &catalog.catalog_id,
    )?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let memory_id = hash_from_vec(row.try_get("memory_id").map_err(pg)?)?;
    let payload_hash = hash_from_vec(row.try_get("payload_hash").map_err(pg)?)?;
    let source_hash = hash_from_vec(row.try_get("source_hash").map_err(pg)?)?;
    if tenant_id == catalog.tenant_id
        && namespace == catalog.namespace
        && memory_id == hash_from_hex("catalog.memory_id", &catalog.memory_id)?
        && payload_hash == hash_from_hex("catalog.payload_hash", &catalog.payload_hash)?
        && source_hash == hash_from_hex("catalog.source_hash", &catalog.source_hash)?
    {
        Ok(())
    } else {
        row_mismatch("dagdb_catalog_entries", &catalog.catalog_id)
    }
}

async fn ensure_validation_report_match(
    tx: &mut Transaction<'_, Postgres>,
    report: &KgImportValidationReport,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, subject_kind, subject_id, input_hash, policy_hash \
         FROM dagdb_validation_reports WHERE validation_report_id = $1",
    )
    .bind(hash_bytes(hash_from_hex(
        "validation_report_id",
        &report.validation_report_id,
    )?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let subject_kind: String = row.try_get("subject_kind").map_err(pg)?;
    let subject_id = hash_from_vec(row.try_get("subject_id").map_err(pg)?)?;
    let input_hash = hash_from_vec(row.try_get("input_hash").map_err(pg)?)?;
    let policy_hash = hash_from_vec(row.try_get("policy_hash").map_err(pg)?)?;
    if tenant_id == report.tenant_id
        && namespace == report.namespace
        && subject_kind == report.subject_kind
        && subject_id == hash_from_hex("validation.subject_id", &report.subject_id)?
        && input_hash == hash_from_hex("validation.input_hash", &report.input_hash)?
        && policy_hash == hash_from_hex("validation.policy_hash", &report.policy_hash)?
    {
        Ok(())
    } else {
        row_mismatch("dagdb_validation_reports", &report.validation_report_id)
    }
}

async fn ensure_graph_node_match(
    tx: &mut Transaction<'_, Postgres>,
    node: &KgImportGraphNode,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, memory_id, graph_style, node_kind \
         FROM dagdb_graph_nodes WHERE graph_node_id = $1",
    )
    .bind(hash_bytes(hash_from_hex(
        "graph_node_id",
        &node.graph_node_id,
    )?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let memory_id = hash_from_vec(row.try_get("memory_id").map_err(pg)?)?;
    let graph_style: String = row.try_get("graph_style").map_err(pg)?;
    let node_kind: String = row.try_get("node_kind").map_err(pg)?;
    if tenant_id == node.tenant_id
        && namespace == node.namespace
        && memory_id == hash_from_hex("graph_node.memory_id", &node.memory_id)?
        && graph_style == node.graph_style
        && node_kind == node.node_kind
    {
        Ok(())
    } else {
        row_mismatch("dagdb_graph_nodes", &node.graph_node_id)
    }
}

#[allow(clippy::too_many_arguments)]
async fn ensure_graph_edge_match(
    tx: &mut Transaction<'_, Postgres>,
    edge_id: &str,
    tenant_id: &str,
    namespace: &str,
    graph_style: &str,
    from_memory_id: &str,
    to_memory_id: &str,
    edge_kind: &str,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT graph_edge_id, tenant_id, namespace, graph_style, from_memory_id, to_memory_id, edge_kind \
         FROM dagdb_graph_edges \
         WHERE graph_edge_id = $1 \
            OR (tenant_id = $2 AND namespace = $3 AND graph_style = $4 \
                AND from_memory_id = $5 AND to_memory_id = $6 AND edge_kind = $7) \
         ORDER BY graph_edge_id \
         LIMIT 1",
    )
    .bind(hash_bytes(hash_from_hex("graph_edge_id", edge_id)?))
    .bind(tenant_id)
    .bind(namespace)
    .bind(graph_style)
    .bind(hash_bytes(hash_from_hex("from_memory_id", from_memory_id)?))
    .bind(hash_bytes(hash_from_hex("to_memory_id", to_memory_id)?))
    .bind(edge_kind)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let existing_edge_id = hash_from_vec(row.try_get("graph_edge_id").map_err(pg)?)?;
    let existing_tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let existing_namespace: String = row.try_get("namespace").map_err(pg)?;
    let existing_graph_style: String = row.try_get("graph_style").map_err(pg)?;
    let existing_from = hash_from_vec(row.try_get("from_memory_id").map_err(pg)?)?;
    let existing_to = hash_from_vec(row.try_get("to_memory_id").map_err(pg)?)?;
    let existing_kind: String = row.try_get("edge_kind").map_err(pg)?;
    if existing_edge_id == hash_from_hex("graph_edge_id", edge_id)?
        && existing_tenant_id == tenant_id
        && existing_namespace == namespace
        && existing_graph_style == graph_style
        && existing_from == hash_from_hex("from_memory_id", from_memory_id)?
        && existing_to == hash_from_hex("to_memory_id", to_memory_id)?
        && existing_kind == edge_kind
    {
        Ok(())
    } else {
        row_mismatch("dagdb_graph_edges", edge_id)
    }
}

async fn ensure_layer_match(
    tx: &mut Transaction<'_, Postgres>,
    layer: &KgImportLayer,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT layer_id, tenant_id, namespace, root_memory_id, parent_layer_id, parent_graph_node_id, \
                layer_depth, layer_kind, graph_style, layer_path \
         FROM dagdb_graph_layers \
         WHERE layer_id = $1 OR (tenant_id = $2 AND namespace = $3 AND layer_path = $4) \
         ORDER BY layer_id \
         LIMIT 1",
    )
    .bind(hash_bytes(hash_from_hex("layer_id", &layer.layer_id)?))
    .bind(&layer.tenant_id)
    .bind(&layer.namespace)
    .bind(&layer.layer_path)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let existing_layer_id = hash_from_vec(row.try_get("layer_id").map_err(pg)?)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let root_memory_id = hash_from_vec(row.try_get("root_memory_id").map_err(pg)?)?;
    let parent_layer_id = optional_hash_from_vec(row.try_get("parent_layer_id").map_err(pg)?)?;
    let parent_graph_node_id =
        optional_hash_from_vec(row.try_get("parent_graph_node_id").map_err(pg)?)?;
    let layer_depth: i32 = row.try_get("layer_depth").map_err(pg)?;
    let layer_kind: String = row.try_get("layer_kind").map_err(pg)?;
    let graph_style: String = row.try_get("graph_style").map_err(pg)?;
    let layer_path: String = row.try_get("layer_path").map_err(pg)?;
    let expected_parent_layer_id = layer
        .parent_layer_id
        .as_ref()
        .map(|value| hash_from_hex("parent_layer_id", value))
        .transpose()?;
    let expected_parent_graph_node_id = layer
        .parent_graph_node_id
        .as_ref()
        .map(|value| hash_from_hex("parent_graph_node_id", value))
        .transpose()?;
    if existing_layer_id == hash_from_hex("layer_id", &layer.layer_id)?
        && tenant_id == layer.tenant_id
        && namespace == layer.namespace
        && root_memory_id == hash_from_hex("layer.root_memory_id", &layer.root_memory_id)?
        && parent_layer_id == expected_parent_layer_id
        && parent_graph_node_id == expected_parent_graph_node_id
        && layer_depth
            == i32::try_from(layer.layer_depth)
                .map_err(|_| KgImportPersistenceError::CountOutOfRange)?
        && layer_kind == layer.layer_kind
        && graph_style == layer.graph_style
        && layer_path == layer.layer_path
    {
        Ok(())
    } else {
        row_mismatch("dagdb_graph_layers", &layer.layer_id)
    }
}

async fn ensure_layer_membership_match(
    tx: &mut Transaction<'_, Postgres>,
    membership: &KgImportLayerMembership,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT layer_membership_id, tenant_id, namespace, layer_id, graph_node_id, graph_style, \
                membership_role, local_node_rank \
         FROM dagdb_graph_layer_memberships \
         WHERE layer_membership_id = $1 \
            OR (tenant_id = $2 AND namespace = $3 AND layer_id = $4 AND graph_node_id = $5) \
         ORDER BY layer_membership_id \
         LIMIT 1",
    )
    .bind(hash_bytes(hash_from_hex(
        "layer_membership_id",
        &membership.layer_membership_id,
    )?))
    .bind(&membership.tenant_id)
    .bind(&membership.namespace)
    .bind(hash_bytes(hash_from_hex(
        "layer_membership.layer_id",
        &membership.layer_id,
    )?))
    .bind(hash_bytes(hash_from_hex(
        "layer_membership.graph_node_id",
        &membership.graph_node_id,
    )?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let existing_id = hash_from_vec(row.try_get("layer_membership_id").map_err(pg)?)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let layer_id = hash_from_vec(row.try_get("layer_id").map_err(pg)?)?;
    let graph_node_id = hash_from_vec(row.try_get("graph_node_id").map_err(pg)?)?;
    let graph_style: String = row.try_get("graph_style").map_err(pg)?;
    let membership_role: String = row.try_get("membership_role").map_err(pg)?;
    let local_node_rank: i32 = row.try_get("local_node_rank").map_err(pg)?;
    if existing_id == hash_from_hex("layer_membership_id", &membership.layer_membership_id)?
        && tenant_id == membership.tenant_id
        && namespace == membership.namespace
        && layer_id == hash_from_hex("layer_membership.layer_id", &membership.layer_id)?
        && graph_node_id
            == hash_from_hex("layer_membership.graph_node_id", &membership.graph_node_id)?
        && graph_style == membership.graph_style
        && membership_role == membership.membership_role
        && local_node_rank
            == i32::try_from(membership.local_node_rank)
                .map_err(|_| KgImportPersistenceError::CountOutOfRange)?
    {
        Ok(())
    } else {
        row_mismatch(
            "dagdb_graph_layer_memberships",
            &membership.layer_membership_id,
        )
    }
}

async fn ensure_layer_edge_match(
    tx: &mut Transaction<'_, Postgres>,
    edge: &KgImportLayerEdge,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT layer_edge_id, tenant_id, namespace, graph_style, from_layer_id, to_layer_id, edge_kind, receipt_hash \
         FROM dagdb_graph_layer_edges \
         WHERE layer_edge_id = $1 \
            OR (tenant_id = $2 AND namespace = $3 AND graph_style = $4 \
                AND from_layer_id = $5 AND to_layer_id = $6 AND edge_kind = $7) \
         ORDER BY layer_edge_id \
         LIMIT 1",
    )
    .bind(hash_bytes(hash_from_hex("layer_edge_id", &edge.layer_edge_id)?))
    .bind(&edge.tenant_id)
    .bind(&edge.namespace)
    .bind(&edge.graph_style)
    .bind(hash_bytes(hash_from_hex(
        "layer_edge.from_layer_id",
        &edge.from_layer_id,
    )?))
    .bind(hash_bytes(hash_from_hex(
        "layer_edge.to_layer_id",
        &edge.to_layer_id,
    )?))
    .bind(&edge.edge_kind)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let existing_id = hash_from_vec(row.try_get("layer_edge_id").map_err(pg)?)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let graph_style: String = row.try_get("graph_style").map_err(pg)?;
    let from_layer_id = hash_from_vec(row.try_get("from_layer_id").map_err(pg)?)?;
    let to_layer_id = hash_from_vec(row.try_get("to_layer_id").map_err(pg)?)?;
    let edge_kind: String = row.try_get("edge_kind").map_err(pg)?;
    let receipt_hash = optional_hash_from_vec(row.try_get("receipt_hash").map_err(pg)?)?;
    let expected_receipt_hash = edge
        .receipt_hash
        .as_ref()
        .map(|value| hash_from_hex("layer_edge.receipt_hash", value))
        .transpose()?;
    if existing_id == hash_from_hex("layer_edge_id", &edge.layer_edge_id)?
        && tenant_id == edge.tenant_id
        && namespace == edge.namespace
        && graph_style == edge.graph_style
        && from_layer_id == hash_from_hex("layer_edge.from_layer_id", &edge.from_layer_id)?
        && to_layer_id == hash_from_hex("layer_edge.to_layer_id", &edge.to_layer_id)?
        && edge_kind == edge.edge_kind
        && receipt_hash == expected_receipt_hash
    {
        Ok(())
    } else {
        row_mismatch("dagdb_graph_layer_edges", &edge.layer_edge_id)
    }
}

async fn ensure_canonicalization_match(
    tx: &mut Transaction<'_, Postgres>,
    decision: &KgImportPlacementDecision,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, input_memory_id, decision_kind \
         FROM dagdb_graph_canonicalization_decisions WHERE decision_id = $1",
    )
    .bind(hash_bytes(hash_from_hex(
        "placement_decision_id",
        &decision.placement_decision_id,
    )?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let input_memory_id = hash_from_vec(row.try_get("input_memory_id").map_err(pg)?)?;
    let decision_kind: String = row.try_get("decision_kind").map_err(pg)?;
    if tenant_id == decision.tenant_id
        && namespace == decision.namespace
        && input_memory_id == hash_from_hex("input_memory_id", &decision.input_memory_id)?
        && decision_kind == decision.canonicalization_decision.decision_kind
    {
        Ok(())
    } else {
        row_mismatch(
            "dagdb_graph_canonicalization_decisions",
            &decision.placement_decision_id,
        )
    }
}

async fn ensure_placement_trace_match(
    tx: &mut Transaction<'_, Postgres>,
    decision: &KgImportPlacementDecision,
    trace_id: Hash256,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, input_memory_id, completed \
         FROM dagdb_graph_placement_traces WHERE placement_trace_id = $1",
    )
    .bind(hash_bytes(trace_id))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let input_memory_id = hash_from_vec(row.try_get("input_memory_id").map_err(pg)?)?;
    let completed: bool = row.try_get("completed").map_err(pg)?;
    if tenant_id == decision.tenant_id
        && namespace == decision.namespace
        && input_memory_id == hash_from_hex("input_memory_id", &decision.input_memory_id)?
        && completed
    {
        Ok(())
    } else {
        row_mismatch("dagdb_graph_placement_traces", &trace_id.to_string())
    }
}

fn row_mismatch<T>(table: &str, id: &str) -> Result<T> {
    Err(KgImportPersistenceError::Conflict {
        reason: format!("existing {table} row mismatch for {id}"),
    })
}

fn graph_edge_key(
    graph_style: &str,
    from_memory_id: &str,
    to_memory_id: &str,
    edge_kind: &str,
) -> String {
    [graph_style, from_memory_id, to_memory_id, edge_kind].join("\0")
}

fn advisory_count(report: &KgImportDryRunReport) -> Result<u32> {
    let count = report.proposed_governance_reviews.len()
        + report.proposed_graph_view_refreshes.len()
        + report.proposed_route_invalidations.len()
        + report.proposed_subdag_boundaries.len()
        + report.review_items.len()
        + report.warnings.len();
    u32::try_from(count).map_err(|_| KgImportPersistenceError::CountOutOfRange)
}

fn subject_kind(value: &str) -> Result<SubjectKind> {
    match value {
        "memory" => Ok(SubjectKind::Memory),
        "catalog" => Ok(SubjectKind::Catalog),
        "route" => Ok(SubjectKind::Route),
        "context_packet" => Ok(SubjectKind::ContextPacket),
        "validation_report" => Ok(SubjectKind::ValidationReport),
        "agent_safety_score" => Ok(SubjectKind::AgentSafetyScore),
        "inbound_agent_credential" => Ok(SubjectKind::InboundAgentCredential),
        "council_decision" => Ok(SubjectKind::CouncilDecision),
        _ => Err(KgImportPersistenceError::UnsupportedSection {
            section: format!("subject_kind:{value}"),
        }),
    }
}

fn event_type(value: &str) -> Result<ReceiptEventType> {
    match value {
        "intake_created" => Ok(ReceiptEventType::IntakeCreated),
        "duplicate_rejected" => Ok(ReceiptEventType::DuplicateRejected),
        "validation_created" => Ok(ReceiptEventType::ValidationCreated),
        "validation_passed" => Ok(ReceiptEventType::ValidationPassed),
        "validation_failed" => Ok(ReceiptEventType::ValidationFailed),
        "memory_approved" => Ok(ReceiptEventType::MemoryApproved),
        "memory_routable" => Ok(ReceiptEventType::MemoryRoutable),
        "memory_revoked" => Ok(ReceiptEventType::MemoryRevoked),
        "memory_superseded" => Ok(ReceiptEventType::MemorySuperseded),
        "route_created" => Ok(ReceiptEventType::RouteCreated),
        "route_activated" => Ok(ReceiptEventType::RouteActivated),
        "route_stale" => Ok(ReceiptEventType::RouteStale),
        "route_invalidated" => Ok(ReceiptEventType::RouteInvalidated),
        "context_packet_created" => Ok(ReceiptEventType::ContextPacketCreated),
        "writeback_created" => Ok(ReceiptEventType::WritebackCreated),
        "trust_check_created" => Ok(ReceiptEventType::TrustCheckCreated),
        "council_decision_recorded" => Ok(ReceiptEventType::CouncilDecisionRecorded),
        "dag_finality_committed" => Ok(ReceiptEventType::DagFinalityCommitted),
        "dag_finality_failed" => Ok(ReceiptEventType::DagFinalityFailed),
        "dag_finality_compensated" => Ok(ReceiptEventType::DagFinalityCompensated),
        "dagdb_approval_request_submitted" => Ok(ReceiptEventType::DagdbApprovalRequestSubmitted),
        "dagdb_approval_granted" => Ok(ReceiptEventType::DagdbApprovalGranted),
        "dagdb_approval_denied" => Ok(ReceiptEventType::DagdbApprovalDenied),
        "dagdb_record_accepted" => Ok(ReceiptEventType::DagdbRecordAccepted),
        "dagdb_import_completed" => Ok(ReceiptEventType::DagdbImportCompleted),
        "dagdb_export_completed" => Ok(ReceiptEventType::DagdbExportCompleted),
        "dagdb_replay_detected" => Ok(ReceiptEventType::DagdbReplayDetected),
        "dagdb_idempotency_conflict" => Ok(ReceiptEventType::DagdbIdempotencyConflict),
        "dagdb_rls_tenant_violation" => Ok(ReceiptEventType::DagdbRlsTenantViolation),
        "dagdb_signature_failure" => Ok(ReceiptEventType::DagdbSignatureFailure),
        "dagdb_council_operator_decision" => Ok(ReceiptEventType::DagdbCouncilOperatorDecision),
        _ => Err(KgImportPersistenceError::UnsupportedSection {
            section: format!("event_type:{value}"),
        }),
    }
}

fn subject_kind_sql(kind: SubjectKind) -> &'static str {
    match kind {
        SubjectKind::Memory => "memory",
        SubjectKind::Catalog => "catalog",
        SubjectKind::Route => "route",
        SubjectKind::ContextPacket => "context_packet",
        SubjectKind::ValidationReport => "validation_report",
        SubjectKind::AgentSafetyScore => "agent_safety_score",
        SubjectKind::InboundAgentCredential => "inbound_agent_credential",
        SubjectKind::CouncilDecision => "council_decision",
    }
}

fn event_type_sql(event_type: ReceiptEventType) -> &'static str {
    match event_type {
        ReceiptEventType::IntakeCreated => "intake_created",
        ReceiptEventType::DuplicateRejected => "duplicate_rejected",
        ReceiptEventType::ValidationCreated => "validation_created",
        ReceiptEventType::ValidationPassed => "validation_passed",
        ReceiptEventType::ValidationFailed => "validation_failed",
        ReceiptEventType::MemoryApproved => "memory_approved",
        ReceiptEventType::MemoryRoutable => "memory_routable",
        ReceiptEventType::MemoryRevoked => "memory_revoked",
        ReceiptEventType::MemorySuperseded => "memory_superseded",
        ReceiptEventType::RouteCreated => "route_created",
        ReceiptEventType::RouteActivated => "route_activated",
        ReceiptEventType::RouteStale => "route_stale",
        ReceiptEventType::RouteInvalidated => "route_invalidated",
        ReceiptEventType::ContextPacketCreated => "context_packet_created",
        ReceiptEventType::WritebackCreated => "writeback_created",
        ReceiptEventType::TrustCheckCreated => "trust_check_created",
        ReceiptEventType::CouncilDecisionRecorded => "council_decision_recorded",
        ReceiptEventType::DagFinalityCommitted => "dag_finality_committed",
        ReceiptEventType::DagFinalityFailed => "dag_finality_failed",
        ReceiptEventType::DagFinalityCompensated => "dag_finality_compensated",
        ReceiptEventType::DagdbApprovalRequestSubmitted => "dagdb_approval_request_submitted",
        ReceiptEventType::DagdbApprovalGranted => "dagdb_approval_granted",
        ReceiptEventType::DagdbApprovalDenied => "dagdb_approval_denied",
        ReceiptEventType::DagdbRecordAccepted => "dagdb_record_accepted",
        ReceiptEventType::DagdbImportCompleted => "dagdb_import_completed",
        ReceiptEventType::DagdbExportCompleted => "dagdb_export_completed",
        ReceiptEventType::DagdbReplayDetected => "dagdb_replay_detected",
        ReceiptEventType::DagdbIdempotencyConflict => "dagdb_idempotency_conflict",
        ReceiptEventType::DagdbRlsTenantViolation => "dagdb_rls_tenant_violation",
        ReceiptEventType::DagdbSignatureFailure => "dagdb_signature_failure",
        ReceiptEventType::DagdbCouncilOperatorDecision => "dagdb_council_operator_decision",
    }
}

fn json_value<T: Serialize>(value: &T) -> Result<JsonValue> {
    serde_json::to_value(value).map_err(|error| KgImportPersistenceError::Json {
        reason: error.to_string(),
    })
}

#[derive(Debug, Clone, Copy)]
struct SqlTimestamp {
    physical_ms: i64,
    logical: i32,
}

fn timestamp_parts(timestamp: Timestamp) -> Result<SqlTimestamp> {
    Ok(SqlTimestamp {
        physical_ms: i64::try_from(timestamp.physical_ms)
            .map_err(|_| KgImportPersistenceError::TimestampOutOfRange)?,
        logical: i32::try_from(timestamp.logical)
            .map_err(|_| KgImportPersistenceError::TimestampOutOfRange)?,
    })
}

fn rows_to_u32(rows: u64) -> Result<u32> {
    u32::try_from(rows).map_err(|_| KgImportPersistenceError::CountOutOfRange)
}

fn hash_bytes(hash: Hash256) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

fn hash_from_vec(bytes: Vec<u8>) -> Result<Hash256> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KgImportPersistenceError::Conflict {
            reason: "hash column had invalid length".to_owned(),
        })?;
    Ok(Hash256::from_bytes(bytes))
}

fn optional_hash_from_vec(bytes: Option<Vec<u8>>) -> Result<Option<Hash256>> {
    bytes.map(hash_from_vec).transpose()
}

fn pg(source: sqlx::Error) -> KgImportPersistenceError {
    KgImportPersistenceError::Postgres { source }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::kg_import::{KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DRY_RUN_REPORT_SCHEMA};

    const TENANT_ID: &str = "tenant-test";
    const NAMESPACE: &str = "dag-db";

    fn h(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn safe(text: &str) -> JsonValue {
        json!({
            "decision": "allow",
            "text": text,
            "redaction_codes": [],
            "original_hash": h('c'),
            "truncated": false,
            "byte_len": text.len(),
        })
    }

    fn empty_report() -> JsonValue {
        json!({
            "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
            "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
            "graph_root": "KnowledgeGraphs/dag-db",
            "tenant_id": TENANT_ID,
            "namespace": NAMESPACE,
            "actor_did": "did:exo:kg-importer",
            "batch_id": h('0'),
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
            "proposed_governance_reviews": [],
            "proposed_graph_view_refreshes": [],
            "proposed_route_invalidations": [],
            "proposed_subdag_boundaries": [],
            "rollback_plan": {},
            "placement_governance_summary": {},
            "review_items": [],
            "warnings": [],
        })
    }

    fn memory_record(memory_id: &str, receipt_intent_id: &str, title: &str) -> JsonValue {
        json!({
            "memory_id": memory_id,
            "tenant_id": TENANT_ID,
            "namespace": NAMESPACE,
            "source_path": format!("KnowledgeGraphs/dag-db/{memory_id}.md"),
            "candidate_id": format!("candidate-{memory_id}"),
            "node_type": "source",
            "source_type": "generated",
            "source_hash": h('e'),
            "payload_hash": h('f'),
            "owner_did": "did:exo:owner",
            "controller_did": "did:exo:controller",
            "submitted_by_did": "did:exo:submitter",
            "consent_purpose": "retrieval",
            "title": safe(title),
            "summary": safe("safe summary"),
            "keywords": [safe("catalog")],
            "catalog_path": ["KnowledgeGraphs", "dag-db"],
            "risk_class": "R1",
            "risk_bp": 100,
            "validation_status": "passed",
            "council_status": "not_required",
            "dag_finality_status": "pending",
            "status": "routable",
            "receipt_intent_id": receipt_intent_id,
            "ignored_extra": "not persisted",
        })
    }

    fn receipt_intent(
        receipt_intent_id: &str,
        subject_kind: &str,
        subject_id: &str,
        event_type: &str,
    ) -> JsonValue {
        json!({
            "receipt_intent_id": receipt_intent_id,
            "tenant_id": TENANT_ID,
            "namespace": NAMESPACE,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "event_type": event_type,
            "actor_did": "did:exo:kg-importer",
            "reason": "unit test fixture",
        })
    }

    fn canonical_material(report: &JsonValue) -> JsonValue {
        serde_json::from_slice(
            &canonical_persisted_request_body(&report.to_string()).expect("canonical material"),
        )
        .expect("canonical material must be JSON")
    }

    fn empty_dry_run_report() -> KgImportDryRunReport {
        KgImportDryRunReport {
            schema_version: KG_IMPORT_DRY_RUN_REPORT_SCHEMA.to_owned(),
            source_candidates_schema_version: KG_IMPORT_CANDIDATES_SCHEMA.to_owned(),
            graph_root: "KnowledgeGraphs/dag-db".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            namespace: NAMESPACE.to_owned(),
            actor_did: "did:exo:kg-importer".to_owned(),
            batch_id: h('0'),
            dry_run_only: true,
            postgres_writes: false,
            raw_markdown_included: false,
            proposed_memory_records: Vec::new(),
            proposed_catalog_entries: Vec::new(),
            proposed_graph_nodes: Vec::new(),
            proposed_graph_edges: Vec::new(),
            proposed_required_edges: Vec::new(),
            proposed_layers: Vec::new(),
            proposed_layer_memberships: Vec::new(),
            proposed_layer_edges: Vec::new(),
            proposed_placement_decisions: Vec::new(),
            proposed_receipt_intents: Vec::new(),
            proposed_validation_reports: Vec::new(),
            proposed_governance_reviews: Vec::new(),
            proposed_graph_view_refreshes: Vec::new(),
            proposed_route_invalidations: Vec::new(),
            proposed_subdag_boundaries: Vec::new(),
            rollback_plan: JsonValue::Null,
            placement_governance_summary: JsonValue::Null,
            review_items: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn persisted_idempotency_key_is_deterministic_and_separate_from_legacy_key() {
        let report = empty_dry_run_report();
        let first = persisted_idempotency_key(&report).expect("persisted key");
        let second = persisted_idempotency_key(&report).expect("persisted key");
        assert_eq!(first, second);
        assert_ne!(first, report.idempotency_key().expect("legacy key"));

        let mut changed_batch = report;
        changed_batch.batch_id = h('1');
        assert_ne!(
            first,
            persisted_idempotency_key(&changed_batch).expect("changed key")
        );
    }

    #[test]
    fn canonical_persisted_request_body_sorts_and_filters_to_persisted_material() {
        let memory_a = h('a');
        let memory_b = h('b');
        let receipt_a = h('1');
        let receipt_b = h('2');
        let route_receipt = h('3');
        let route_id = h('4');
        let mut report = empty_report();
        report["proposed_memory_records"] = json!([
            memory_record(&memory_b, &receipt_b, "second"),
            memory_record(&memory_a, &receipt_a, "first"),
        ]);
        report["proposed_receipt_intents"] = json!([
            receipt_intent(&route_receipt, "route", &route_id, "route_created"),
            receipt_intent(&receipt_b, "memory", &memory_b, "intake_created"),
            receipt_intent(&receipt_a, "memory", &memory_a, "intake_created"),
        ]);
        report["review_items"] = json!([{ "advisory_only": true }]);

        let material = canonical_material(&report);
        assert_eq!(
            material["schema_version"].as_str(),
            Some(KG_IMPORT_PERSISTED_REQUEST_MATERIAL_SCHEMA)
        );

        let memory_records = material["persisted_sections"]["proposed_memory_records"]
            .as_array()
            .expect("memory records");
        assert_eq!(memory_records.len(), 2);
        assert_eq!(
            memory_records[0]["memory_id"].as_str(),
            Some(memory_a.as_str())
        );
        assert_eq!(
            memory_records[1]["memory_id"].as_str(),
            Some(memory_b.as_str())
        );
        assert!(
            memory_records[0]
                .as_object()
                .expect("memory material")
                .get("ignored_extra")
                .is_none()
        );

        let receipts = material["persisted_sections"]["proposed_receipt_intents"]
            .as_array()
            .expect("receipt intents");
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            receipts[0]["receipt_intent_id"].as_str(),
            Some(receipt_a.as_str())
        );
        assert_eq!(
            receipts[1]["receipt_intent_id"].as_str(),
            Some(receipt_b.as_str())
        );
        assert!(receipts.iter().all(|receipt| {
            receipt["subject_kind"].as_str() == Some("memory")
                && receipt["event_type"].as_str() == Some("intake_created")
        }));

        let first = canonical_persisted_request_body(&report.to_string()).expect("first material");
        let mut advisory_changed = report.clone();
        advisory_changed["review_items"] = json!([{ "advisory_only": "changed" }]);
        advisory_changed["warnings"] = json!(["non-persisted warning changed"]);
        advisory_changed["proposed_memory_records"][0]["ignored_extra"] = json!("changed");
        assert_eq!(
            first,
            canonical_persisted_request_body(&advisory_changed.to_string())
                .expect("advisory-only change")
        );

        let mut persisted_changed = report;
        persisted_changed["proposed_memory_records"][0]["summary"] = safe("changed summary");
        assert_ne!(
            first,
            canonical_persisted_request_body(&persisted_changed.to_string())
                .expect("persisted change")
        );
    }

    #[test]
    fn canonical_persisted_request_body_rejects_missing_persisted_field() {
        let memory_id = h('a');
        let receipt_id = h('1');
        let mut report = empty_report();
        report["proposed_memory_records"] = json!([memory_record(
            &memory_id,
            &receipt_id,
            "missing field fixture"
        )]);
        report["proposed_memory_records"][0]
            .as_object_mut()
            .expect("memory record")
            .remove("payload_hash");

        assert!(matches!(
            canonical_persisted_request_body(&report.to_string()),
            Err(KgImportPersistenceError::Json { reason })
                if reason == "request material missing payload_hash"
        ));
    }

    #[test]
    fn canonical_persisted_request_body_rejects_invalid_json_and_bad_shapes() {
        assert!(matches!(
            canonical_persisted_request_body("{not-json"),
            Err(KgImportPersistenceError::Json { .. })
        ));

        let mut bad_section = empty_report();
        bad_section["proposed_graph_edges"] = json!("not an array");
        assert!(matches!(
            canonical_persisted_request_body(&bad_section.to_string()),
            Err(KgImportPersistenceError::Json { reason })
                if reason == "proposed_graph_edges must be an array"
        ));

        let mut bad_record = empty_report();
        bad_record["proposed_graph_nodes"] = json!([null]);
        assert!(matches!(
            canonical_persisted_request_body(&bad_record.to_string()),
            Err(KgImportPersistenceError::Json { reason })
                if reason == "request material record must be an object"
        ));

        let mut bad_receipt = empty_report();
        bad_receipt["proposed_receipt_intents"] = json!([{
            "receipt_intent_id": h('1'),
            "tenant_id": TENANT_ID,
            "namespace": NAMESPACE,
            "subject_kind": "memory",
            "subject_id": h('a'),
            "actor_did": "did:exo:kg-importer",
            "reason": "missing event type"
        }]);
        assert!(matches!(
            canonical_persisted_request_body(&bad_receipt.to_string()),
            Err(KgImportPersistenceError::Json { reason })
                if reason == "request material missing event_type"
        ));
    }

    #[test]
    fn receipt_label_helpers_map_all_supported_values_and_reject_unknowns() {
        let subject_labels = [
            "memory",
            "catalog",
            "route",
            "context_packet",
            "validation_report",
            "agent_safety_score",
            "inbound_agent_credential",
            "council_decision",
        ];
        for label in subject_labels {
            let kind = subject_kind(label).expect("supported subject kind");
            assert_eq!(subject_kind_sql(kind), label);
        }

        let event_labels = [
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
            "dagdb_approval_request_submitted",
            "dagdb_approval_granted",
            "dagdb_approval_denied",
            "dagdb_record_accepted",
            "dagdb_import_completed",
            "dagdb_export_completed",
            "dagdb_replay_detected",
            "dagdb_idempotency_conflict",
            "dagdb_rls_tenant_violation",
            "dagdb_signature_failure",
            "dagdb_council_operator_decision",
        ];
        for label in event_labels {
            let receipt_event = event_type(label).expect("supported event type");
            assert_eq!(event_type_sql(receipt_event), label);
        }

        assert!(matches!(
            subject_kind("memory_record"),
            Err(KgImportPersistenceError::UnsupportedSection { section })
                if section == "subject_kind:memory_record"
        ));
        assert!(matches!(
            event_type("memory_created"),
            Err(KgImportPersistenceError::UnsupportedSection { section })
                if section == "event_type:memory_created"
        ));
    }

    #[test]
    fn primitive_conversion_helpers_fail_closed_on_out_of_range_values() {
        assert!(matches!(
            rows_to_u32(u64::from(u32::MAX) + 1),
            Err(KgImportPersistenceError::CountOutOfRange)
        ));
        assert!(matches!(
            timestamp_parts(Timestamp::new(i64::MAX.unsigned_abs() + 1, 0)),
            Err(KgImportPersistenceError::TimestampOutOfRange)
        ));
        assert!(matches!(
            timestamp_parts(Timestamp::new(0, i32::MAX.unsigned_abs() + 1)),
            Err(KgImportPersistenceError::TimestampOutOfRange)
        ));
        assert!(matches!(
            hash_from_vec(vec![0; 31]),
            Err(KgImportPersistenceError::Conflict { reason })
                if reason == "hash column had invalid length"
        ));
    }
}

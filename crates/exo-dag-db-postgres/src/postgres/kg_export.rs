//! Feature-gated Postgres adapters for KG portable export reports and compact
//! repository-level export persistence metadata.
//!
//! These adapters do not expose gateway behavior, change graph explorer state,
//! activate routes, write route invalidations, persist raw artifacts, create
//! migrations, or write `exo-dag` tables.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Hash256, Timestamp};
use exo_dag_db_api::{ReceiptEventType, SafeMetadata, SubjectKind};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::{
    hash::RequestHashMaterial,
    kg_export::{
        KG_EXPORT_DATABASE_URL_ENV, KG_EXPORT_FINALITY_OUTBOX_ROUTE_NAME,
        KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA, KG_EXPORT_PERSISTED_ROUTE_NAME,
        KG_EXPORT_PERSISTED_SUMMARY_SCHEMA, KG_EXPORT_PERSISTENCE_VERIFICATION_SCHEMA,
        KG_PORTABLE_EXPORT_SCHEMA, KgExportBuildInput, KgExportError,
        KgExportFinalityOutboxAdvisoryDiagnostics, KgExportFinalityOutboxChallengeDiagnostics,
        KgExportFinalityOutboxDiagnostics, KgExportFinalityOutboxEvidenceDiagnostics,
        KgExportFinalityOutboxMaterialExclusionDiagnostics,
        KgExportFinalityOutboxReceiptDiagnostics, KgExportFinalityOutboxRequest,
        KgExportFinalityOutboxRowDiagnostics, KgExportFinalityOutboxSummary,
        KgExportPersistedAdvisoryDiagnostics, KgExportPersistedChallengeDiagnostics,
        KgExportPersistedDiagnostics, KgExportPersistedEvidenceDiagnostics,
        KgExportPersistedIdempotencyDiagnostics, KgExportPersistedReceiptDiagnostics,
        KgExportPersistedRowCounts, KgExportPersistedSectionDiagnostics, KgExportPersistedSummary,
        KgExportPersistenceVerificationSummary, KgExportRecord, KgExportScope, KgPortableExport,
        Result, build_portable_export, parse_portable_export_json, reject_forbidden_export_json,
        validate_portable_export_for_persistence,
    },
    kg_import::{hash_from_hex, stable_hash},
    kg_retrieval::{KgCitationHandle, KgContextPacketPreview, KgGraphEdgeRef, KgMemoryRef},
    kg_writeback::KG_WRITEBACK_PERSISTED_ROUTE_NAME,
    receipt::{
        OperationalReceiptInsert, insert_operational_receipt_in_transaction,
        operational_receipt_subject_id,
    },
    scoring::hash_event_body,
};

const CREATED_AT: Timestamp = Timestamp::new(1, 0);
const UPDATED_AT: Timestamp = Timestamp::new(1, 1);
const EXPIRES_AT: Timestamp = Timestamp::new(86_400_001, 0);
const DAGDB_EXPORT_COMPLETED_EVENT_TYPE: &str = "dagdb_export_completed";

/// Build a portable KG export report using `EXO_DAGDB_TEST_DATABASE_URL`.
pub async fn build_kg_portable_export_from_env(
    scope: &KgExportScope,
    context_packet_previews: &[KgContextPacketPreview],
) -> Result<KgPortableExport> {
    let database_url = std::env::var(KG_EXPORT_DATABASE_URL_ENV).map_err(|_| {
        KgExportError::MissingDatabaseUrl {
            env_var: KG_EXPORT_DATABASE_URL_ENV,
        }
    })?;
    build_kg_portable_export_from_database_url(
        Some(database_url.as_str()),
        scope,
        context_packet_previews,
    )
    .await
}

/// Build a portable KG export report using an explicit database URL.
pub async fn build_kg_portable_export_from_database_url(
    database_url: Option<&str>,
    scope: &KgExportScope,
    context_packet_previews: &[KgContextPacketPreview],
) -> Result<KgPortableExport> {
    let Some(database_url) = database_url else {
        return Err(KgExportError::MissingDatabaseUrl {
            env_var: KG_EXPORT_DATABASE_URL_ENV,
        });
    };
    let pool = super::init_pool(database_url)
        .await
        .map_err(|source| KgExportError::Init {
            source: Box::new(source),
        })?;
    let result = build_kg_portable_export(&pool, scope, context_packet_previews).await;
    pool.close().await;
    result
}

/// Build a portable KG export report from current-schema DAG DB rows.
pub async fn build_kg_portable_export(
    pool: &PgPool,
    scope: &KgExportScope,
    context_packet_previews: &[KgContextPacketPreview],
) -> Result<KgPortableExport> {
    scope.validate()?;
    let mut tx = super::begin_tenant_transaction(pool, &scope.tenant_id)
        .await
        .map_err(pg)?;
    let memory_records = load_memory_records(&mut tx, scope).await?;
    let catalog_entries = load_catalog_entries(&mut tx, scope).await?;
    let graph_nodes = load_graph_nodes(&mut tx, scope).await?;
    let graph_edges = load_graph_edges(&mut tx, scope).await?;
    let similarity_results = load_similarity_results(&mut tx, scope).await?;
    let canonicalization_decisions = load_canonicalization_decisions(&mut tx, scope).await?;
    let placement_traces = load_placement_traces(&mut tx, scope).await?;
    let validation_reports = load_validation_reports(&mut tx, scope).await?;
    let receipts = load_receipts(&mut tx, scope).await?;
    let subject_receipt_heads = load_subject_receipt_heads(&mut tx, scope).await?;
    let context_packet_records = load_context_packet_records(&mut tx, scope).await?;
    let route_receipts = load_route_receipts(&mut tx, scope).await?;
    let idempotency_references = load_idempotency_references(&mut tx, scope).await?;
    let writeback_summaries = load_writeback_summaries(&mut tx, scope).await?;
    tx.commit().await.map_err(pg)?;
    let context_packet_previews = sanitize_context_packet_previews(scope, context_packet_previews)?;
    let citation_index = build_citation_index(scope, context_packet_previews.as_slice())?;
    let provenance_index = build_provenance_index(&memory_records, &validation_reports, &receipts);

    build_portable_export(KgExportBuildInput {
        scope: scope.clone(),
        memory_records,
        catalog_entries,
        graph_nodes,
        graph_edges,
        similarity_results,
        canonicalization_decisions,
        placement_traces,
        validation_reports,
        receipts,
        subject_receipt_heads,
        context_packet_previews,
        context_packet_records,
        route_receipts,
        writeback_summaries,
        idempotency_references,
        citation_index,
        provenance_index,
    })
}

/// Persist a portable KG export report using `EXO_DAGDB_TEST_DATABASE_URL`.
pub async fn persist_kg_portable_export_from_env(
    export_json: &str,
    requester_did: &str,
) -> Result<KgExportPersistedSummary> {
    let database_url = std::env::var(KG_EXPORT_DATABASE_URL_ENV).map_err(|_| {
        KgExportError::MissingDatabaseUrl {
            env_var: KG_EXPORT_DATABASE_URL_ENV,
        }
    })?;
    persist_kg_portable_export_from_database_url(
        Some(database_url.as_str()),
        export_json,
        requester_did,
    )
    .await
}

/// Persist a portable KG export report using an explicit database URL.
pub async fn persist_kg_portable_export_from_database_url(
    database_url: Option<&str>,
    export_json: &str,
    requester_did: &str,
) -> Result<KgExportPersistedSummary> {
    let Some(database_url) = database_url else {
        return Err(KgExportError::MissingDatabaseUrl {
            env_var: KG_EXPORT_DATABASE_URL_ENV,
        });
    };
    let pool = super::init_pool(database_url)
        .await
        .map_err(|source| KgExportError::Init {
            source: Box::new(source),
        })?;
    let result = persist_kg_portable_export_json(&pool, export_json, requester_did).await;
    pool.close().await;
    result
}

/// Persist a portable KG export report from JSON.
pub async fn persist_kg_portable_export_json(
    pool: &PgPool,
    export_json: &str,
    requester_did: &str,
) -> Result<KgExportPersistedSummary> {
    let export = parse_portable_export_json(export_json)?;
    persist_kg_portable_export(pool, &export, requester_did).await
}

/// Persist a portable KG export report with a deterministic idempotency key.
pub async fn persist_kg_portable_export(
    pool: &PgPool,
    export: &KgPortableExport,
    requester_did: &str,
) -> Result<KgExportPersistedSummary> {
    let idempotency_key = export_persistence_idempotency_key(export, requester_did)?;
    persist_kg_portable_export_with_idempotency_key(pool, export, requester_did, &idempotency_key)
        .await
}

/// Persist a portable KG export report with an explicit idempotency key.
pub async fn persist_kg_portable_export_with_idempotency_key(
    pool: &PgPool,
    export: &KgPortableExport,
    requester_did: &str,
    idempotency_key: &str,
) -> Result<KgExportPersistedSummary> {
    validate_portable_export_for_persistence(export)?;
    validate_export_requester(requester_did)?;
    let export_json = serde_json::to_vec(export).map_err(json_error)?;
    let request_hash = RequestHashMaterial {
        route_name: KG_EXPORT_PERSISTED_ROUTE_NAME.to_owned(),
        tenant_id: export.tenant_id.clone(),
        namespace: export.namespace.clone(),
        canonical_redacted_request_body: export_json,
    }
    .hash()
    .map_err(|error| KgExportError::Hash {
        reason: error.to_string(),
    })?;

    let mut tx = pool.begin().await.map_err(pg)?;
    let result = persist_kg_portable_export_in_transaction(
        &mut tx,
        export,
        requester_did,
        idempotency_key,
        request_hash,
    )
    .await;
    match result {
        Ok(summary) => {
            tx.commit().await.map_err(pg)?;
            Ok(summary)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(
                    operation = "persist_kg_portable_export",
                    tenant_id = %export.tenant_id,
                    namespace = %export.namespace,
                    export_id = %export.export_id,
                    error = %rollback_error,
                    "failed to rollback transaction after KG export persistence error"
                );
            }
            Err(error)
        }
    }
}

/// Verify persisted export rows against the original compact export hash material.
pub async fn verify_persisted_kg_export(
    pool: &PgPool,
    export: &KgPortableExport,
    persisted_summary: &KgExportPersistedSummary,
    requester_did: &str,
) -> Result<KgExportPersistenceVerificationSummary> {
    validate_portable_export_for_persistence(export)?;
    validate_export_requester(requester_did)?;
    let idempotency_key = export_persistence_idempotency_key(export, requester_did)?;
    let export_json = serde_json::to_vec(export).map_err(json_error)?;
    let request_hash = RequestHashMaterial {
        route_name: KG_EXPORT_PERSISTED_ROUTE_NAME.to_owned(),
        tenant_id: export.tenant_id.clone(),
        namespace: export.namespace.clone(),
        canonical_redacted_request_body: export_json,
    }
    .hash()
    .map_err(|error| KgExportError::Hash {
        reason: error.to_string(),
    })?;
    let latest_receipt_hash = export_receipt_hash(export, requester_did)?;
    ensure_summary_matches_export(
        export,
        persisted_summary,
        &idempotency_key,
        request_hash,
        latest_receipt_hash,
    )?;

    let mut tx = super::begin_tenant_transaction(pool, &export.tenant_id)
        .await
        .map_err(pg)?;
    verify_export_record_row(&mut tx, export, requester_did, latest_receipt_hash).await?;
    let challenge_hashes = verify_export_challenge_rows(&mut tx, export).await?;
    verify_export_receipt_row(&mut tx, export, requester_did, latest_receipt_hash).await?;
    verify_export_subject_head_row(&mut tx, export, latest_receipt_hash).await?;
    verify_export_idempotency_response_row(&mut tx, persisted_summary, request_hash).await?;

    let export_rows = count_export_rows(&mut tx, export).await?;
    let challenge_rows = count_export_challenge_rows(&mut tx, export).await?;
    let receipt_rows = count_export_receipt_rows(&mut tx, export, latest_receipt_hash).await?;
    let subject_receipt_head_rows = count_export_subject_head_rows(&mut tx, export).await?;
    let idempotency_response_rows =
        count_export_idempotency_rows(&mut tx, export, &idempotency_key).await?;
    let route_invalidation_rows = count_route_invalidation_rows(&mut tx, export).await?;
    let dagdb_dag_outbox_rows = count_dagdb_dag_outbox_rows(&mut tx, export).await?;
    let exo_dag_rows = count_exo_dag_rows(&mut tx).await?;
    tx.commit().await.map_err(pg)?;
    let raw_artifact_rows = 0;
    let row_counts = KgExportPersistedRowCounts {
        export_rows,
        challenge_rows,
        receipt_rows,
        subject_receipt_head_rows,
        idempotency_response_rows,
        route_invalidation_rows,
        dagdb_dag_outbox_rows,
        raw_artifact_rows,
        exo_dag_rows,
    };
    let challenge_coverage_complete =
        challenge_coverage_complete(&challenge_hashes.keys().cloned().collect::<Vec<_>>());
    let verified = export_rows == 1
        && challenge_rows == 5
        && receipt_rows == 1
        && subject_receipt_head_rows == 1
        && idempotency_response_rows == 1
        && route_invalidation_rows == 0
        && dagdb_dag_outbox_rows == 0
        && raw_artifact_rows == 0
        && exo_dag_rows == 0
        && challenge_coverage_complete;

    Ok(KgExportPersistenceVerificationSummary {
        schema_version: KG_EXPORT_PERSISTENCE_VERIFICATION_SCHEMA.to_owned(),
        tenant_id: export.tenant_id.clone(),
        namespace: export.namespace.clone(),
        export_id: export.export_id.clone(),
        idempotency_key,
        request_hash: request_hash.to_string(),
        whole_export_hash: export.hashes.whole_export_hash.clone(),
        latest_receipt_hash: Some(latest_receipt_hash.to_string()),
        verified,
        deterministic_readback: true,
        export_row_verified: true,
        challenge_rows_verified: true,
        receipt_row_verified: true,
        subject_head_verified: true,
        idempotency_response_verified: true,
        row_counts,
        challenge_hashes,
        challenge_coverage_complete,
        persisted_summary_matches_idempotency_response: true,
        route_invalidation_rows,
        dagdb_dag_outbox_rows,
        raw_artifact_rows,
        exo_dag_rows,
        preview_context_status: persisted_summary
            .diagnostics
            .evidence
            .preview_context_status
            .clone(),
        route_invalidation_status: persisted_summary
            .diagnostics
            .advisory_deferred
            .route_invalidation_status
            .clone(),
        warning_summaries: verification_warnings(persisted_summary),
    })
}

/// Queue a persisted KG export for future DAG finality using an explicit database URL.
pub async fn queue_kg_export_finality_outbox_from_database_url(
    database_url: Option<&str>,
    request: &KgExportFinalityOutboxRequest,
) -> Result<KgExportFinalityOutboxSummary> {
    let Some(database_url) = database_url else {
        return Err(KgExportError::MissingDatabaseUrl {
            env_var: KG_EXPORT_DATABASE_URL_ENV,
        });
    };
    let pool = super::init_pool(database_url)
        .await
        .map_err(|source| KgExportError::Init {
            source: Box::new(source),
        })?;
    let result = queue_kg_export_finality_outbox(&pool, request).await;
    pool.close().await;
    result
}

/// Queue a persisted KG export for future DAG finality using compact outbox metadata only.
pub async fn queue_kg_export_finality_outbox(
    pool: &PgPool,
    request: &KgExportFinalityOutboxRequest,
) -> Result<KgExportFinalityOutboxSummary> {
    request.validate()?;
    let mut tx = pool.begin().await.map_err(pg)?;
    let result = queue_kg_export_finality_outbox_in_transaction(&mut tx, request).await;
    match result {
        Ok(summary) => {
            tx.commit().await.map_err(pg)?;
            Ok(summary)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(
                    operation = "queue_kg_export_finality_outbox",
                    tenant_id = %request.tenant_id,
                    namespace = %request.namespace,
                    export_id = %request.export_id,
                    error = %rollback_error,
                    "failed to rollback transaction after KG export finality outbox error"
                );
            }
            Err(error)
        }
    }
}

/// Derive the deterministic idempotency key for one export finality/outbox request.
pub fn export_finality_outbox_idempotency_key(
    request: &KgExportFinalityOutboxRequest,
    whole_export_hash: &str,
    latest_receipt_hash: &str,
) -> Result<String> {
    request.validate()?;
    Ok(stable_hash(
        "exo.dagdb.kg_export.finality_outbox.idempotency_key",
        &[
            &request.tenant_id,
            &request.namespace,
            &request.export_id,
            &request.requester_did,
            whole_export_hash,
            latest_receipt_hash,
        ],
    )?
    .to_string())
}

async fn queue_kg_export_finality_outbox_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
) -> Result<KgExportFinalityOutboxSummary> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut **tx)
        .await
        .map_err(pg)?;
    super::bind_tenant_context(tx, &request.tenant_id)
        .await
        .map_err(pg)?;

    let evidence = fetch_finality_export_evidence(tx, request).await?;
    let idempotency_key = request.idempotency_key.clone().map(Ok).unwrap_or_else(|| {
        export_finality_outbox_idempotency_key(
            request,
            &evidence.whole_export_hash.to_string(),
            &evidence.latest_receipt_hash.to_string(),
        )
    })?;
    let request_hash = export_finality_outbox_request_hash(request, &evidence)?;
    if let Some(summary) =
        fetch_export_finality_idempotency_replay(tx, request, &idempotency_key, request_hash)
            .await?
    {
        return Ok(summary);
    }

    let challenge = verify_export_finality_challenge_rows(tx, request, &evidence).await?;
    let receipt = verify_export_finality_receipt_rows(tx, request, &evidence).await?;
    let outbox = export_finality_outbox_material(request, &evidence)?;
    let inserted_dag_outbox_count =
        rows_to_u32(insert_export_finality_outbox_row(tx, request, &outbox, &evidence).await?)?;
    let outbox_row = verify_export_finality_outbox_row(tx, request, &outbox, &evidence).await?;
    let persisted_dag_outbox_count =
        count_export_finality_outbox_rows_tx(tx, request, &evidence).await?;
    let route_invalidation_count = count_route_invalidation_rows_tx(tx, request).await?;
    let exo_dag_write_count = count_exo_dag_rows_tx(tx).await?;
    let inserted_idempotency_response_count = 1;
    let summary = export_finality_outbox_summary(FinalityOutboxSummaryInput {
        request,
        evidence: &evidence,
        challenge: &challenge,
        receipt: &receipt,
        outbox: &outbox,
        outbox_row: &outbox_row,
        idempotency_key: &idempotency_key,
        request_hash,
        inserted_dag_outbox_count,
        inserted_idempotency_response_count,
        persisted_dag_outbox_count,
        persisted_route_invalidation_count: route_invalidation_count,
        persisted_exo_dag_write_count: exo_dag_write_count,
        replayed: false,
    })?;
    insert_export_finality_idempotency_response(tx, &summary, request_hash).await?;
    Ok(summary)
}

#[derive(Debug, Clone)]
struct FinalityExportEvidence {
    export_status: String,
    persisted_export_requester_did: String,
    whole_export_hash: Hash256,
    latest_receipt_hash: Hash256,
}

#[derive(Debug, Clone)]
struct FinalityChallengeEvidence {
    challenge_kinds: Vec<String>,
    challenge_hashes: BTreeMap<String, String>,
    challenge_statuses: BTreeMap<String, String>,
    verification_status: String,
}

#[derive(Debug, Clone)]
struct FinalityReceiptEvidence {
    event_type: String,
}

#[derive(Debug, Clone)]
struct FinalityOutboxMaterial {
    outbox_id: Hash256,
    dag_write_id: String,
    dag_payload_hash: Hash256,
}

#[derive(Debug, Clone)]
struct FinalityOutboxRowEvidence {
    dag_finality_status: String,
    dag_receipt_hash_present: bool,
    compensation_receipt_hash_present: bool,
    retry_attempt_count: u32,
    max_attempts: u32,
    next_attempt_status: String,
}

async fn fetch_finality_export_evidence(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
) -> Result<FinalityExportEvidence> {
    let row = sqlx::query(
        "SELECT export_status, requester_did, whole_export_hash, latest_receipt_hash \
         FROM dagdb_exports \
         WHERE tenant_id = $1 AND namespace = $2 AND export_id = $3 \
         FOR UPDATE",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &request.export_id)?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?
    .ok_or_else(|| KgExportError::Conflict {
        reason: format!("persisted export row not found: {}", request.export_id),
    })?;

    let export_status: String = row.try_get("export_status").map_err(pg)?;
    if export_status != "verified" {
        return Err(KgExportError::Conflict {
            reason: "persisted export is not verified".to_owned(),
        });
    }
    let latest_receipt_hash: Option<Vec<u8>> = row.try_get("latest_receipt_hash").map_err(pg)?;
    let Some(latest_receipt_hash) = latest_receipt_hash else {
        return Err(KgExportError::Conflict {
            reason: "persisted export latest receipt is missing".to_owned(),
        });
    };
    Ok(FinalityExportEvidence {
        export_status,
        persisted_export_requester_did: row.try_get("requester_did").map_err(pg)?,
        whole_export_hash: hash_from_vec(row.try_get("whole_export_hash").map_err(pg)?)?,
        latest_receipt_hash: hash_from_vec(latest_receipt_hash)?,
    })
}

async fn verify_export_finality_challenge_rows(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
    evidence: &FinalityExportEvidence,
) -> Result<FinalityChallengeEvidence> {
    let rows = sqlx::query(
        "SELECT challenge_kind, challenge_hash, proof_hash, proof_algorithm, verification_status \
         FROM dagdb_export_challenges \
         WHERE tenant_id = $1 AND namespace = $2 AND export_id = $3 \
         ORDER BY challenge_kind",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &request.export_id)?))
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;
    let expected = [
        "citation_index_hash",
        "omission_summary_hash",
        "provenance_index_hash",
        "redaction_summary_hash",
        "whole_export_hash",
    ];
    if rows.len() != expected.len() {
        return Err(KgExportError::Conflict {
            reason: "export finality challenge row count mismatch".to_owned(),
        });
    }
    let mut challenge_hashes = BTreeMap::new();
    let mut challenge_statuses = BTreeMap::new();
    let mut statuses = BTreeSet::new();
    for row in rows {
        let kind: String = row.try_get("challenge_kind").map_err(pg)?;
        if !expected.iter().any(|expected| *expected == kind) {
            return Err(KgExportError::Conflict {
                reason: format!("unexpected export finality challenge kind: {kind}"),
            });
        }
        let challenge_hash = hash_from_vec(row.try_get("challenge_hash").map_err(pg)?)?;
        if kind == "whole_export_hash" && challenge_hash != evidence.whole_export_hash {
            return Err(KgExportError::Conflict {
                reason: "export finality whole-export challenge mismatch".to_owned(),
            });
        }
        let proof_hash = hash_from_vec(row.try_get("proof_hash").map_err(pg)?)?;
        if proof_hash
            != export_challenge_proof_hash_from_parts(&request.export_id, &kind, challenge_hash)?
        {
            return Err(KgExportError::Conflict {
                reason: format!("export finality challenge proof mismatch: {kind}"),
            });
        }
        let proof_algorithm: String = row.try_get("proof_algorithm").map_err(pg)?;
        if proof_algorithm != "hash_commitment_v1" {
            return Err(KgExportError::Conflict {
                reason: format!("unsupported export finality proof algorithm: {kind}"),
            });
        }
        let verification_status: String = row.try_get("verification_status").map_err(pg)?;
        if verification_status != "pending" && verification_status != "verified" {
            return Err(KgExportError::Conflict {
                reason: format!("unsupported export finality challenge status: {kind}"),
            });
        }
        statuses.insert(verification_status.clone());
        challenge_statuses.insert(kind.clone(), verification_status);
        challenge_hashes.insert(kind, challenge_hash.to_string());
    }
    let verification_status = if statuses.iter().all(|status| status == "verified") {
        "verified"
    } else {
        "readback_verified_pending_challenge_status"
    }
    .to_owned();
    Ok(FinalityChallengeEvidence {
        challenge_kinds: challenge_hashes.keys().cloned().collect(),
        challenge_hashes,
        challenge_statuses,
        verification_status,
    })
}

fn export_challenge_proof_hash_from_parts(
    export_id: &str,
    kind: &str,
    challenge_hash: Hash256,
) -> Result<Hash256> {
    stable_hash(
        "exo.dagdb.kg_export.persisted.challenge_proof",
        &[
            export_id,
            kind,
            &challenge_hash.to_string(),
            "hash_commitment_v1",
        ],
    )
    .map_err(Into::into)
}

async fn verify_export_finality_receipt_rows(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
    evidence: &FinalityExportEvidence,
) -> Result<FinalityReceiptEvidence> {
    let row = sqlx::query(
        "SELECT event_type, receipt_body \
         FROM dagdb_receipts \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'export' \
           AND subject_id = $3 AND receipt_hash = $4",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &request.export_id)?))
    .bind(hash_bytes(evidence.latest_receipt_hash))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?
    .ok_or_else(|| KgExportError::Conflict {
        reason: "export finality receipt evidence not found".to_owned(),
    })?;
    let event_type: String = row.try_get("event_type").map_err(pg)?;
    if event_type != DAGDB_EXPORT_COMPLETED_EVENT_TYPE
        && event_type != "export_created"
        && event_type != "export_verified"
    {
        return Err(KgExportError::Conflict {
            reason: "unsupported export finality receipt event type".to_owned(),
        });
    }
    let receipt_body: JsonValue = row.try_get("receipt_body").map_err(pg)?;
    reject_forbidden_export_json(&receipt_body, "$.export_finality_receipt_body")?;
    if receipt_body
        .get("raw_artifact_persisted")
        .and_then(JsonValue::as_bool)
        != Some(false)
        || receipt_body
            .get("route_invalidation_written")
            .and_then(JsonValue::as_bool)
            != Some(false)
        || receipt_body
            .get("exo_dag_written")
            .and_then(JsonValue::as_bool)
            != Some(false)
    {
        return Err(KgExportError::Conflict {
            reason: "export finality receipt body crossed deferred boundary".to_owned(),
        });
    }
    let subject_head_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM dagdb_subject_receipt_heads \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'export' \
           AND subject_id = $3 AND latest_receipt_hash = $4)",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &request.export_id)?))
    .bind(hash_bytes(evidence.latest_receipt_hash))
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    if !subject_head_exists {
        return Err(KgExportError::Conflict {
            reason: "export finality subject head evidence not found".to_owned(),
        });
    }
    Ok(FinalityReceiptEvidence { event_type })
}

fn export_finality_outbox_request_hash(
    request: &KgExportFinalityOutboxRequest,
    evidence: &FinalityExportEvidence,
) -> Result<Hash256> {
    let body = json!({
        "schema_version": KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA,
        "tenant_id": request.tenant_id,
        "namespace": request.namespace,
        "export_id": request.export_id,
        "requester_did": request.requester_did,
        "whole_export_hash": evidence.whole_export_hash.to_string(),
        "latest_receipt_hash": evidence.latest_receipt_hash.to_string(),
    });
    reject_forbidden_export_json(&body, "$.export_finality_outbox_request")?;
    let canonical_redacted_request_body = serde_json::to_vec(&body).map_err(json_error)?;
    RequestHashMaterial {
        route_name: KG_EXPORT_FINALITY_OUTBOX_ROUTE_NAME.to_owned(),
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        canonical_redacted_request_body,
    }
    .hash()
    .map_err(|error| KgExportError::Hash {
        reason: error.to_string(),
    })
}

fn export_finality_outbox_material(
    request: &KgExportFinalityOutboxRequest,
    evidence: &FinalityExportEvidence,
) -> Result<FinalityOutboxMaterial> {
    let dag_payload_hash = stable_hash(
        "exo.dagdb.kg_export.finality_outbox.payload",
        &[
            &request.tenant_id,
            &request.namespace,
            &request.export_id,
            &request.requester_did,
            &evidence.whole_export_hash.to_string(),
            &evidence.latest_receipt_hash.to_string(),
        ],
    )?;
    let outbox_id = stable_hash(
        "exo.dagdb.kg_export.finality_outbox.outbox_id",
        &[
            &request.tenant_id,
            &request.namespace,
            &request.export_id,
            &dag_payload_hash.to_string(),
        ],
    )?;
    Ok(FinalityOutboxMaterial {
        outbox_id,
        dag_write_id: format!("dagdb-export-finality-{outbox_id}"),
        dag_payload_hash,
    })
}

async fn insert_export_finality_outbox_row(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
    outbox: &FinalityOutboxMaterial,
    evidence: &FinalityExportEvidence,
) -> Result<u64> {
    let created_at = timestamp_parts(CREATED_AT)?;
    let updated_at = timestamp_parts(UPDATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_dag_outbox \
         (outbox_id, tenant_id, namespace, subject_kind, subject_id, dag_write_id, dag_payload_hash, \
          dag_finality_status, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, 'export', $4, $5, $6, 'pending', $7, $8, $9, $10) \
         ON CONFLICT (tenant_id, namespace, subject_kind, subject_id, dag_write_id) DO NOTHING",
    )
    .bind(hash_bytes(outbox.outbox_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &request.export_id)?))
    .bind(&outbox.dag_write_id)
    .bind(hash_bytes(outbox.dag_payload_hash))
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .bind(updated_at.physical_ms)
    .bind(updated_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    if evidence.export_status != "verified" {
        return Err(KgExportError::Conflict {
            reason: "export finality outbox insert requires verified export".to_owned(),
        });
    }
    Ok(result.rows_affected())
}

async fn verify_export_finality_outbox_row(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
    outbox: &FinalityOutboxMaterial,
    evidence: &FinalityExportEvidence,
) -> Result<FinalityOutboxRowEvidence> {
    let row = sqlx::query(
        "SELECT encode(outbox_id, 'hex') AS outbox_id, encode(dag_payload_hash, 'hex') AS dag_payload_hash, \
         dag_finality_status, attempt_count, max_attempts, next_attempt_at_physical_ms, next_attempt_at_logical, \
         dag_receipt_hash, compensation_receipt_hash \
         FROM dagdb_dag_outbox \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'export' \
           AND subject_id = $3 AND dag_write_id = $4",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &request.export_id)?))
    .bind(&outbox.dag_write_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?
    .ok_or_else(|| KgExportError::Conflict {
        reason: "export finality outbox row not found after insert".to_owned(),
    })?;
    require_row_string(&row, "outbox_id", &outbox.outbox_id.to_string())?;
    require_row_string(
        &row,
        "dag_payload_hash",
        &outbox.dag_payload_hash.to_string(),
    )?;
    let dag_finality_status: String = row.try_get("dag_finality_status").map_err(pg)?;
    if dag_finality_status != "pending" {
        return Err(KgExportError::Conflict {
            reason: "export finality outbox row is not pending".to_owned(),
        });
    }
    let dag_receipt_hash: Option<Vec<u8>> = row.try_get("dag_receipt_hash").map_err(pg)?;
    let compensation_receipt_hash: Option<Vec<u8>> =
        row.try_get("compensation_receipt_hash").map_err(pg)?;
    if dag_receipt_hash.is_some() || compensation_receipt_hash.is_some() {
        return Err(KgExportError::Conflict {
            reason: "export finality outbox row already contains DAG write receipt".to_owned(),
        });
    }
    if evidence.latest_receipt_hash == Hash256::ZERO {
        return Err(KgExportError::Conflict {
            reason: "export finality evidence latest receipt is zero".to_owned(),
        });
    }
    let next_attempt_at_physical_ms: Option<i64> =
        row.try_get("next_attempt_at_physical_ms").map_err(pg)?;
    let next_attempt_at_logical: Option<i32> =
        row.try_get("next_attempt_at_logical").map_err(pg)?;
    let next_attempt_status = match (next_attempt_at_physical_ms, next_attempt_at_logical) {
        (None, None) => "not_scheduled",
        (Some(_), Some(_)) => "scheduled",
        _ => {
            return Err(KgExportError::Conflict {
                reason: "export finality outbox retry timestamp is partial".to_owned(),
            });
        }
    }
    .to_owned();
    Ok(FinalityOutboxRowEvidence {
        dag_finality_status,
        dag_receipt_hash_present: dag_receipt_hash.is_some(),
        compensation_receipt_hash_present: compensation_receipt_hash.is_some(),
        retry_attempt_count: i32_to_u32(row.try_get("attempt_count").map_err(pg)?)?,
        max_attempts: i32_to_u32(row.try_get("max_attempts").map_err(pg)?)?,
        next_attempt_status,
    })
}

async fn fetch_export_finality_idempotency_replay(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<Option<KgExportFinalityOutboxSummary>> {
    let row = sqlx::query(
        "SELECT request_hash, response_body FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4 \
         FOR UPDATE",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(KG_EXPORT_FINALITY_OUTBOX_ROUTE_NAME)
    .bind(idempotency_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let existing_hash = hash_from_vec(row.try_get("request_hash").map_err(pg)?)?;
    if existing_hash != request_hash {
        return Err(KgExportError::Conflict {
            reason: "export_finality_outbox_idempotency_key_conflict".to_owned(),
        });
    }
    let body: JsonValue = row.try_get("response_body").map_err(pg)?;
    let mut summary: KgExportFinalityOutboxSummary = decode_cached_replay_summary(
        body,
        KG_EXPORT_FINALITY_OUTBOX_ROUTE_NAME,
        KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA,
    )?;
    normalize_finality_outbox_summary_warnings(&mut summary);
    summary.replayed = true;
    summary.diagnostics.idempotency_replay.replayed = true;
    summary.diagnostics.idempotency_replay.request_hash = request_hash.to_string();
    summary.diagnostics.idempotency_replay.replay_reason = "idempotency_key_match".to_owned();
    Ok(Some(summary))
}

async fn insert_export_finality_idempotency_response(
    tx: &mut Transaction<'_, Postgres>,
    summary: &KgExportFinalityOutboxSummary,
    request_hash: Hash256,
) -> Result<()> {
    let response_body = json_value(summary)?;
    reject_forbidden_export_json(&response_body, "$.export_finality_outbox_summary")?;
    let response_hash = hash_event_body(summary).map_err(|error| KgExportError::Hash {
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
    .bind(KG_EXPORT_FINALITY_OUTBOX_ROUTE_NAME)
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

struct FinalityOutboxSummaryInput<'a> {
    request: &'a KgExportFinalityOutboxRequest,
    evidence: &'a FinalityExportEvidence,
    challenge: &'a FinalityChallengeEvidence,
    receipt: &'a FinalityReceiptEvidence,
    outbox: &'a FinalityOutboxMaterial,
    outbox_row: &'a FinalityOutboxRowEvidence,
    idempotency_key: &'a str,
    request_hash: Hash256,
    inserted_dag_outbox_count: u32,
    inserted_idempotency_response_count: u32,
    persisted_dag_outbox_count: u32,
    persisted_route_invalidation_count: u32,
    persisted_exo_dag_write_count: u32,
    replayed: bool,
}

fn export_finality_outbox_summary(
    input: FinalityOutboxSummaryInput<'_>,
) -> Result<KgExportFinalityOutboxSummary> {
    let warning_summaries = export_finality_outbox_warnings();
    Ok(KgExportFinalityOutboxSummary {
        schema_version: KG_EXPORT_FINALITY_OUTBOX_SUMMARY_SCHEMA.to_owned(),
        tenant_id: input.request.tenant_id.clone(),
        namespace: input.request.namespace.clone(),
        export_id: input.request.export_id.clone(),
        idempotency_key: input.idempotency_key.to_owned(),
        request_hash: input.request_hash.to_string(),
        replayed: input.replayed,
        outbox_id: input.outbox.outbox_id.to_string(),
        dag_write_id: input.outbox.dag_write_id.clone(),
        dag_payload_hash: input.outbox.dag_payload_hash.to_string(),
        export_status: input.evidence.export_status.clone(),
        whole_export_hash: input.evidence.whole_export_hash.to_string(),
        latest_receipt_hash: input.evidence.latest_receipt_hash.to_string(),
        inserted_dag_outbox_count: input.inserted_dag_outbox_count,
        inserted_idempotency_response_count: input.inserted_idempotency_response_count,
        persisted_dag_outbox_count: input.persisted_dag_outbox_count,
        persisted_route_invalidation_count: input.persisted_route_invalidation_count,
        persisted_raw_artifact_count: 0,
        persisted_exo_dag_write_count: input.persisted_exo_dag_write_count,
        diagnostics: KgExportFinalityOutboxDiagnostics {
            evidence: KgExportFinalityOutboxEvidenceDiagnostics {
                tenant_namespace_match: true,
                export_id: input.request.export_id.clone(),
                requester_did: input.request.requester_did.clone(),
                committed_export_evidence_checked: true,
                committed_receipt_evidence_checked: true,
                export_row_verified: true,
                export_status: input.evidence.export_status.clone(),
                persisted_export_requester_did: input
                    .evidence
                    .persisted_export_requester_did
                    .clone(),
                whole_export_hash: input.evidence.whole_export_hash.to_string(),
                latest_receipt_hash: input.evidence.latest_receipt_hash.to_string(),
                outbox_eligible: true,
                evidence_status: "valid".to_owned(),
                context_packet_evidence_status: "preview_only_not_outbox_material".to_owned(),
                preview_context_status: "not_materialized_in_outbox".to_owned(),
                route_invalidation_status: "not_written".to_owned(),
                evidence_warnings: vec![
                    "context_packet_preview_not_persisted_to_outbox".to_owned(),
                    "route_invalidation_evidence_advisory_only".to_owned(),
                ],
            },
            challenge_proof: KgExportFinalityOutboxChallengeDiagnostics {
                expected_challenge_count: 5,
                challenge_count: usize_to_u32(input.challenge.challenge_kinds.len())?,
                challenge_kinds: input.challenge.challenge_kinds.clone(),
                challenge_hashes: input.challenge.challenge_hashes.clone(),
                challenge_statuses: input.challenge.challenge_statuses.clone(),
                challenge_coverage_complete: input.challenge.challenge_kinds.len() == 5,
                whole_export_challenge_hash: required_finality_challenge_hash(
                    input.challenge,
                    "whole_export_hash",
                )?,
                citation_index_challenge_hash: required_finality_challenge_hash(
                    input.challenge,
                    "citation_index_hash",
                )?,
                provenance_index_challenge_hash: required_finality_challenge_hash(
                    input.challenge,
                    "provenance_index_hash",
                )?,
                redaction_summary_challenge_hash: required_finality_challenge_hash(
                    input.challenge,
                    "redaction_summary_hash",
                )?,
                omission_summary_challenge_hash: required_finality_challenge_hash(
                    input.challenge,
                    "omission_summary_hash",
                )?,
                proof_algorithm: "hash_commitment_v1".to_owned(),
                verification_status: input.challenge.verification_status.clone(),
                readback_verified: true,
            },
            receipt: KgExportFinalityOutboxReceiptDiagnostics {
                receipt_subject_kind: "export".to_owned(),
                receipt_event_type: input.receipt.event_type.clone(),
                receipt_event_supported: true,
                latest_receipt_hash: input.evidence.latest_receipt_hash.to_string(),
                receipt_row_verified: true,
                subject_head_verified: true,
                latest_receipt_head_matches: true,
                dag_receipt_hash_present: input.outbox_row.dag_receipt_hash_present,
                compensation_receipt_hash_present: input
                    .outbox_row
                    .compensation_receipt_hash_present,
                receipt_body_raw_artifact_persisted: false,
            },
            outbox: KgExportFinalityOutboxRowDiagnostics {
                outbox_id: input.outbox.outbox_id.to_string(),
                subject_kind: "export".to_owned(),
                subject_id: input.request.export_id.clone(),
                dag_write_id: input.outbox.dag_write_id.clone(),
                dag_payload_hash: input.outbox.dag_payload_hash.to_string(),
                payload_material_class: "hash_only_commitment".to_owned(),
                dag_finality_status: input.outbox_row.dag_finality_status.clone(),
                dag_receipt_hash_present: input.outbox_row.dag_receipt_hash_present,
                compensation_receipt_hash_present: input
                    .outbox_row
                    .compensation_receipt_hash_present,
                retry_attempt_count: input.outbox_row.retry_attempt_count,
                max_attempts: input.outbox_row.max_attempts,
                next_attempt_status: input.outbox_row.next_attempt_status.clone(),
                inserted_dag_outbox_count: input.inserted_dag_outbox_count,
                persisted_dag_outbox_count: input.persisted_dag_outbox_count,
                direct_exo_dag_write: false,
                exo_dag_table_mutated: false,
                route_invalidation_written: false,
                raw_artifact_persisted: false,
            },
            idempotency_replay: KgExportPersistedIdempotencyDiagnostics {
                idempotency_key: input.idempotency_key.to_owned(),
                request_hash: input.request_hash.to_string(),
                replayed: input.replayed,
                response_cached: true,
                status_code: 201,
                replay_reason: if input.replayed {
                    "idempotency_key_match"
                } else {
                    "new_outbox_response"
                }
                .to_owned(),
            },
            material_exclusion: KgExportFinalityOutboxMaterialExclusionDiagnostics {
                json_markdown_artifact_absent: true,
                markdown_body_absent: true,
                private_payload_absent: true,
                model_output_absent: true,
                source_material_absent: true,
                gateway_secret_absent: true,
                database_connection_absent: true,
                private_key_absent: true,
                local_absolute_path_absent: true,
                outbox_payload_is_hash_only: true,
            },
            advisory_deferred: KgExportFinalityOutboxAdvisoryDiagnostics {
                gateway_api_deferred: true,
                graph_explorer_deferred: true,
                production_route_activation_deferred: true,
                route_invalidation_writes_deferred: true,
                raw_artifact_storage_deferred: true,
                broad_product_export_surface_deferred: true,
                direct_exo_dag_writes_deferred: true,
                exo_dag_table_mutation_deferred: true,
            },
            warning_summaries,
        },
    })
}

fn required_finality_challenge_hash(
    challenge: &FinalityChallengeEvidence,
    kind: &str,
) -> Result<String> {
    challenge
        .challenge_hashes
        .get(kind)
        .cloned()
        .ok_or_else(|| KgExportError::Conflict {
            reason: format!("missing export finality challenge hash: {kind}"),
        })
}

fn export_finality_outbox_warnings() -> Vec<String> {
    let mut warnings = BTreeSet::new();
    warnings.insert("repository_level_outbox_metadata_only".to_owned());
    warnings.insert("not_production_finality".to_owned());
    warnings.insert("gateway_api_deferred".to_owned());
    warnings.insert("graph_explorer_deferred".to_owned());
    warnings.insert("production_route_activation_deferred".to_owned());
    warnings.insert("route_invalidation_not_written".to_owned());
    warnings.insert("raw_export_artifact_not_persisted".to_owned());
    warnings.insert("payload_content_not_exported".to_owned());
    warnings.insert("direct_exo_dag_write_deferred".to_owned());
    warnings.insert("exo_dag_table_mutation_deferred".to_owned());
    warnings.into_iter().collect()
}

async fn count_export_finality_outbox_rows_tx(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
    evidence: &FinalityExportEvidence,
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_dag_outbox \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'export' \
           AND subject_id = $3 AND dag_payload_hash = $4",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &request.export_id)?))
    .bind(hash_bytes(
        export_finality_outbox_material(request, evidence)?.dag_payload_hash,
    ))
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_route_invalidation_rows_tx(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgExportFinalityOutboxRequest,
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_graph_route_invalidations WHERE tenant_id = $1 AND namespace = $2",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_exo_dag_rows_tx(tx: &mut Transaction<'_, Postgres>) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name IN ('dag_nodes','dag_committed')",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

/// Derive the deterministic idempotency key for one export persistence request.
pub fn export_persistence_idempotency_key(
    export: &KgPortableExport,
    requester_did: &str,
) -> Result<String> {
    validate_export_requester(requester_did)?;
    Ok(stable_hash(
        "exo.dagdb.kg_export.persisted.idempotency_key",
        &[
            &export.tenant_id,
            &export.namespace,
            requester_did,
            &export.export_id,
            &export.hashes.whole_export_hash,
        ],
    )?
    .to_string())
}

fn ensure_summary_matches_export(
    export: &KgPortableExport,
    summary: &KgExportPersistedSummary,
    idempotency_key: &str,
    request_hash: Hash256,
    latest_receipt_hash: Hash256,
) -> Result<()> {
    let expected_latest_receipt = Some(latest_receipt_hash.to_string());
    if summary.schema_version != KG_EXPORT_PERSISTED_SUMMARY_SCHEMA
        || summary.tenant_id != export.tenant_id
        || summary.namespace != export.namespace
        || summary.export_id != export.export_id
        || summary.idempotency_key != idempotency_key
        || summary.request_hash != request_hash.to_string()
        || summary.whole_export_hash != export.hashes.whole_export_hash
        || summary.latest_receipt_hash != expected_latest_receipt
    {
        return Err(KgExportError::Conflict {
            reason: "persisted export summary does not match export material".to_owned(),
        });
    }
    Ok(())
}

async fn verify_export_record_row(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    requester_did: &str,
    latest_receipt_hash: Hash256,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, schema_version, encode(export_scope_hash, 'hex') AS export_scope_hash, \
         source_commit_or_repo_ref, encode(included_memory_ids_hash, 'hex') AS included_memory_ids_hash, \
         encode(included_receipt_heads_hash, 'hex') AS included_receipt_heads_hash, section_hashes, section_counts, \
         encode(citation_index_hash, 'hex') AS citation_index_hash, \
         encode(provenance_index_hash, 'hex') AS provenance_index_hash, \
         encode(redaction_summary_hash, 'hex') AS redaction_summary_hash, \
         encode(omission_summary_hash, 'hex') AS omission_summary_hash, \
         encode(verification_hash, 'hex') AS verification_hash, \
         encode(whole_export_hash, 'hex') AS whole_export_hash, export_status, requester_did, \
         encode(latest_receipt_hash, 'hex') AS latest_receipt_hash \
         FROM dagdb_exports WHERE export_id = $1 AND tenant_id = $2 AND namespace = $3",
    )
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?
    .ok_or_else(|| KgExportError::Conflict {
        reason: format!("persisted export row not found: {}", export.export_id),
    })?;

    require_row_string(&row, "tenant_id", &export.tenant_id)?;
    require_row_string(&row, "namespace", &export.namespace)?;
    require_row_string(&row, "schema_version", KG_PORTABLE_EXPORT_SCHEMA)?;
    require_row_string(
        &row,
        "export_scope_hash",
        &hash_export_part("export_scope", &export.export_scope)?.to_string(),
    )?;
    let source_ref: Option<String> = row.try_get("source_commit_or_repo_ref").map_err(pg)?;
    if source_ref != export.source_commit_or_repo_ref {
        return Err(KgExportError::Conflict {
            reason: "persisted export source ref mismatch".to_owned(),
        });
    }
    require_row_string(
        &row,
        "included_memory_ids_hash",
        &hash_export_part("included_memory_ids", &export_memory_ids(export))?.to_string(),
    )?;
    require_row_string(
        &row,
        "included_receipt_heads_hash",
        &hash_export_part("subject_receipt_heads", &export.subject_receipt_heads)?.to_string(),
    )?;
    require_row_json(
        &row,
        "section_hashes",
        &json_value(&export.hashes.section_hashes)?,
    )?;
    require_row_json(
        &row,
        "section_counts",
        &json_value(&export.diagnostics.section_counts)?,
    )?;
    require_row_string(
        &row,
        "citation_index_hash",
        &required_section_hash(export, "citation_index")?.to_string(),
    )?;
    require_row_string(
        &row,
        "provenance_index_hash",
        &required_section_hash(export, "provenance_index")?.to_string(),
    )?;
    require_row_string(
        &row,
        "redaction_summary_hash",
        &required_section_hash(export, "redaction_summary")?.to_string(),
    )?;
    require_row_string(
        &row,
        "omission_summary_hash",
        &required_section_hash(export, "omission_summary")?.to_string(),
    )?;
    require_row_string(
        &row,
        "verification_hash",
        &hash_export_part("verification", &export.verification)?.to_string(),
    )?;
    require_row_string(&row, "whole_export_hash", &export.hashes.whole_export_hash)?;
    require_row_string(&row, "export_status", "verified")?;
    require_row_string(&row, "requester_did", requester_did)?;
    require_row_string(
        &row,
        "latest_receipt_hash",
        &latest_receipt_hash.to_string(),
    )?;
    Ok(())
}

async fn verify_export_challenge_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<BTreeMap<String, String>> {
    let rows = sqlx::query(
        "SELECT challenge_kind, encode(challenge_hash, 'hex') AS challenge_hash, \
         encode(proof_hash, 'hex') AS proof_hash, proof_algorithm, verification_status \
         FROM dagdb_export_challenges \
         WHERE tenant_id = $1 AND namespace = $2 AND export_id = $3 \
         ORDER BY challenge_kind",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;
    let expected = challenge_specs(export)?
        .into_iter()
        .map(|spec| (spec.kind, spec.challenge_hash))
        .collect::<BTreeMap<_, _>>();
    if rows.len() != expected.len() {
        return Err(KgExportError::Conflict {
            reason: "persisted export challenge row count mismatch".to_owned(),
        });
    }
    let mut actual = BTreeMap::new();
    for row in rows {
        let kind: String = row.try_get("challenge_kind").map_err(pg)?;
        let challenge_hash: String = row.try_get("challenge_hash").map_err(pg)?;
        let expected_hash = expected.get(&kind).ok_or_else(|| KgExportError::Conflict {
            reason: format!("unexpected export challenge kind: {kind}"),
        })?;
        if challenge_hash != expected_hash.to_string() {
            return Err(KgExportError::Conflict {
                reason: format!("export challenge hash mismatch: {kind}"),
            });
        }
        let proof_hash: String = row.try_get("proof_hash").map_err(pg)?;
        if proof_hash != export_challenge_proof_hash(export, &kind, *expected_hash)?.to_string() {
            return Err(KgExportError::Conflict {
                reason: format!("export challenge proof mismatch: {kind}"),
            });
        }
        require_row_string(&row, "proof_algorithm", "hash_commitment_v1")?;
        require_row_string(&row, "verification_status", "pending")?;
        actual.insert(kind, challenge_hash);
    }
    Ok(actual)
}

async fn verify_export_receipt_row(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    requester_did: &str,
    receipt_hash: Hash256,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, subject_kind, encode(subject_id, 'hex') AS subject_id, seq, \
         event_type, actor_did, encode(event_hash, 'hex') AS event_hash, receipt_body \
         FROM dagdb_receipts WHERE receipt_hash = $1 AND tenant_id = $2 AND namespace = $3",
    )
    .bind(hash_bytes(receipt_hash))
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?
    .ok_or_else(|| KgExportError::Conflict {
        reason: "persisted export receipt not found".to_owned(),
    })?;
    require_row_string(&row, "tenant_id", &export.tenant_id)?;
    require_row_string(&row, "namespace", &export.namespace)?;
    require_row_string(&row, "subject_kind", "export")?;
    require_row_string(&row, "subject_id", &export.export_id)?;
    require_row_i64(&row, "seq", 1)?;
    require_row_string(&row, "event_type", DAGDB_EXPORT_COMPLETED_EVENT_TYPE)?;
    require_row_string(&row, "actor_did", requester_did)?;
    require_row_string(
        &row,
        "event_hash",
        &export_receipt_body_hash(export, requester_did)?.to_string(),
    )?;
    let receipt_body: JsonValue = row.try_get("receipt_body").map_err(pg)?;
    reject_forbidden_export_json(&receipt_body, "$.receipt_body")?;
    if receipt_body
        .get("raw_artifact_persisted")
        .and_then(JsonValue::as_bool)
        != Some(false)
        || receipt_body
            .get("route_invalidation_written")
            .and_then(JsonValue::as_bool)
            != Some(false)
        || receipt_body
            .get("exo_dag_written")
            .and_then(JsonValue::as_bool)
            != Some(false)
    {
        return Err(KgExportError::Conflict {
            reason: "persisted export receipt body crossed deferred boundary".to_owned(),
        });
    }
    Ok(())
}

async fn verify_export_subject_head_row(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    receipt_hash: Hash256,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT latest_seq, encode(latest_receipt_hash, 'hex') AS latest_receipt_hash \
         FROM dagdb_subject_receipt_heads \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'export' AND subject_id = $3",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?
    .ok_or_else(|| KgExportError::Conflict {
        reason: "persisted export subject head not found".to_owned(),
    })?;
    require_row_i64(&row, "latest_seq", 1)?;
    require_row_string(&row, "latest_receipt_hash", &receipt_hash.to_string())?;
    Ok(())
}

async fn verify_export_idempotency_response_row(
    tx: &mut Transaction<'_, Postgres>,
    persisted_summary: &KgExportPersistedSummary,
    request_hash: Hash256,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT encode(request_hash, 'hex') AS request_hash, encode(response_hash, 'hex') AS response_hash, \
         response_body, status_code, cached_failure \
         FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4",
    )
    .bind(&persisted_summary.tenant_id)
    .bind(&persisted_summary.namespace)
    .bind(KG_EXPORT_PERSISTED_ROUTE_NAME)
    .bind(&persisted_summary.idempotency_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?
    .ok_or_else(|| KgExportError::Conflict {
        reason: "persisted export idempotency response not found".to_owned(),
    })?;
    require_row_string(&row, "request_hash", &request_hash.to_string())?;
    require_row_i32(&row, "status_code", 201)?;
    let cached_failure: bool = row.try_get("cached_failure").map_err(pg)?;
    if cached_failure {
        return Err(KgExportError::Conflict {
            reason: "persisted export idempotency response cached failure".to_owned(),
        });
    }
    let expected_summary = idempotency_stored_summary(persisted_summary);
    let expected_body = json_value(&expected_summary)?;
    require_row_json(&row, "response_body", &expected_body)?;
    let expected_response_hash =
        hash_event_body(&expected_summary).map_err(|error| KgExportError::Hash {
            reason: error.to_string(),
        })?;
    require_row_string(&row, "response_hash", &expected_response_hash.to_string())?;
    Ok(())
}

fn idempotency_stored_summary(summary: &KgExportPersistedSummary) -> KgExportPersistedSummary {
    let mut stored = summary.clone();
    stored.replayed = false;
    stored.diagnostics.idempotency_replay.replayed = false;
    stored.diagnostics.idempotency_replay.replay_reason = "new_persisted_response".to_owned();
    stored
}

fn export_challenge_proof_hash(
    export: &KgPortableExport,
    kind: &str,
    challenge_hash: Hash256,
) -> Result<Hash256> {
    stable_hash(
        "exo.dagdb.kg_export.persisted.challenge_proof",
        &[
            &export.export_id,
            kind,
            &challenge_hash.to_string(),
            "hash_commitment_v1",
        ],
    )
    .map_err(Into::into)
}

async fn count_export_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<u32> {
    count_query(
        tx,
        "SELECT count(*) FROM dagdb_exports WHERE tenant_id = $1 AND namespace = $2 AND export_id = $3",
        &[&export.tenant_id, &export.namespace, &export.export_id],
    )
    .await
}

async fn count_export_challenge_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<u32> {
    count_query(
        tx,
        "SELECT count(*) FROM dagdb_export_challenges WHERE tenant_id = $1 AND namespace = $2 AND export_id = $3",
        &[&export.tenant_id, &export.namespace, &export.export_id],
    )
    .await
}

async fn count_export_receipt_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    receipt_hash: Hash256,
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_receipts \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'export' AND subject_id = $3 AND receipt_hash = $4",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .bind(hash_bytes(receipt_hash))
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_export_subject_head_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_subject_receipt_heads \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'export' AND subject_id = $3",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_export_idempotency_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    idempotency_key: &str,
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(KG_EXPORT_PERSISTED_ROUTE_NAME)
    .bind(idempotency_key)
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_route_invalidation_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_graph_route_invalidations WHERE tenant_id = $1 AND namespace = $2",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_dagdb_dag_outbox_rows(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_dag_outbox WHERE tenant_id = $1 AND namespace = $2",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_exo_dag_rows(tx: &mut Transaction<'_, Postgres>) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name IN ('dag_nodes','dag_committed')",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(pg)?;
    i64_to_u32(count)
}

async fn count_query(
    tx: &mut Transaction<'_, Postgres>,
    sql: &'static str,
    scope_and_id: &[&String; 3],
) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(sql)
        .bind(scope_and_id[0])
        .bind(scope_and_id[1])
        .bind(hash_bytes(hash_from_hex("export_id", scope_and_id[2])?))
        .fetch_one(&mut **tx)
        .await
        .map_err(pg)?;
    i64_to_u32(count)
}

fn require_row_string(row: &sqlx::postgres::PgRow, column: &str, expected: &str) -> Result<()> {
    let actual: String = row.try_get(column).map_err(pg)?;
    if actual == expected {
        Ok(())
    } else {
        Err(KgExportError::Conflict {
            reason: format!("persisted export row mismatch: {column}"),
        })
    }
}

fn require_row_i64(row: &sqlx::postgres::PgRow, column: &str, expected: i64) -> Result<()> {
    let actual: i64 = row.try_get(column).map_err(pg)?;
    if actual == expected {
        Ok(())
    } else {
        Err(KgExportError::Conflict {
            reason: format!("persisted export row mismatch: {column}"),
        })
    }
}

fn require_row_i32(row: &sqlx::postgres::PgRow, column: &str, expected: i32) -> Result<()> {
    let actual: i32 = row.try_get(column).map_err(pg)?;
    if actual == expected {
        Ok(())
    } else {
        Err(KgExportError::Conflict {
            reason: format!("persisted export row mismatch: {column}"),
        })
    }
}

fn require_row_json(row: &sqlx::postgres::PgRow, column: &str, expected: &JsonValue) -> Result<()> {
    let actual: JsonValue = row.try_get(column).map_err(pg)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(KgExportError::Conflict {
            reason: format!("persisted export row mismatch: {column}"),
        })
    }
}

fn verification_warnings(summary: &KgExportPersistedSummary) -> Vec<String> {
    let mut warnings = BTreeSet::new();
    warnings.extend(normalize_export_warning_summaries(
        summary.diagnostics.warning_summaries.iter().cloned(),
    ));
    warnings.insert("readback_verification_repository_level_only".to_owned());
    warnings.insert("raw_artifact_rows_verified_absent".to_owned());
    warnings.insert("route_invalidation_rows_verified_absent".to_owned());
    warnings.insert("dagdb_dag_outbox_rows_verified_absent".to_owned());
    warnings.insert("exo_dag_rows_verified_absent".to_owned());
    warnings.into_iter().collect()
}

async fn persist_kg_portable_export_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    requester_did: &str,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<KgExportPersistedSummary> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut **tx)
        .await
        .map_err(pg)?;
    super::bind_tenant_context(tx, &export.tenant_id)
        .await
        .map_err(pg)?;

    if let Some(summary) =
        fetch_export_idempotency_replay(tx, export, idempotency_key, request_hash).await?
    {
        return Ok(summary);
    }

    verify_export_evidence(tx, export).await?;

    let mut counts = ExportPersistedCounts::default();
    let receipt_hash = export_receipt_hash(export, requester_did)?;
    insert_export_approval_receipts(tx, export, requester_did, idempotency_key, request_hash)
        .await?;
    counts.inserted_receipt_count = counts.inserted_receipt_count.saturating_add(rows_to_u32(
        insert_export_receipt(tx, export, requester_did, receipt_hash).await?,
    )?);
    counts.inserted_subject_receipt_head_count =
        rows_to_u32(insert_export_subject_head(tx, export, receipt_hash).await?)?;
    counts.inserted_export_count =
        rows_to_u32(insert_export_record(tx, export, requester_did, receipt_hash).await?)?;
    counts.inserted_challenge_count = insert_export_challenges(tx, export).await?;
    counts.inserted_idempotency_response_count = 1;

    let summary = export_persisted_summary(
        export,
        idempotency_key,
        request_hash,
        receipt_hash,
        counts,
        false,
    )?;
    insert_export_idempotency_response(tx, &summary, request_hash).await?;
    Ok(summary)
}

#[derive(Debug, Clone, Copy, Default)]
struct ExportPersistedCounts {
    inserted_export_count: u32,
    inserted_challenge_count: u32,
    inserted_receipt_count: u32,
    inserted_subject_receipt_head_count: u32,
    inserted_idempotency_response_count: u32,
}

fn export_persisted_summary(
    export: &KgPortableExport,
    idempotency_key: &str,
    request_hash: Hash256,
    receipt_hash: Hash256,
    counts: ExportPersistedCounts,
    replayed: bool,
) -> Result<KgExportPersistedSummary> {
    let challenge_kinds = challenge_specs(export)?
        .into_iter()
        .map(|spec| spec.kind)
        .collect::<Vec<_>>();
    let warning_summaries = export_persisted_warnings();
    Ok(KgExportPersistedSummary {
        schema_version: KG_EXPORT_PERSISTED_SUMMARY_SCHEMA.to_owned(),
        tenant_id: export.tenant_id.clone(),
        namespace: export.namespace.clone(),
        export_id: export.export_id.clone(),
        idempotency_key: idempotency_key.to_owned(),
        request_hash: request_hash.to_string(),
        replayed,
        export_status: "verified".to_owned(),
        whole_export_hash: export.hashes.whole_export_hash.clone(),
        latest_receipt_hash: Some(receipt_hash.to_string()),
        inserted_export_count: counts.inserted_export_count,
        inserted_challenge_count: counts.inserted_challenge_count,
        inserted_receipt_count: counts.inserted_receipt_count,
        inserted_subject_receipt_head_count: counts.inserted_subject_receipt_head_count,
        inserted_idempotency_response_count: counts.inserted_idempotency_response_count,
        persisted_route_invalidation_count: 0,
        persisted_dag_outbox_count: 0,
        persisted_raw_artifact_count: 0,
        persisted_exo_dag_write_count: 0,
        diagnostics: KgExportPersistedDiagnostics {
            row_counts: KgExportPersistedRowCounts {
                export_rows: counts.inserted_export_count,
                challenge_rows: counts.inserted_challenge_count,
                receipt_rows: counts.inserted_receipt_count,
                subject_receipt_head_rows: counts.inserted_subject_receipt_head_count,
                idempotency_response_rows: counts.inserted_idempotency_response_count,
                route_invalidation_rows: 0,
                dagdb_dag_outbox_rows: 0,
                raw_artifact_rows: 0,
                exo_dag_rows: 0,
            },
            evidence: KgExportPersistedEvidenceDiagnostics {
                tenant_namespace_match: true,
                memory_record_count: usize_to_u32(export.memory_records.len())?,
                receipt_record_count: usize_to_u32(export.receipts.len())?,
                subject_receipt_head_count: usize_to_u32(export.subject_receipt_heads.len())?,
                context_packet_record_count: usize_to_u32(export.context_packet_records.len())?,
                context_packet_preview_count: usize_to_u32(export.context_packet_previews.len())?,
                route_receipt_count: usize_to_u32(export.route_receipts.len())?,
                writeback_summary_count: usize_to_u32(export.writeback_summaries.len())?,
                citation_handle_count: usize_to_u32(export.citation_index.len())?,
                provenance_record_count: usize_to_u32(export.provenance_index.len())?,
                committed_memory_evidence_checked: true,
                committed_receipt_evidence_checked: true,
                evidence_status: "valid".to_owned(),
                preview_context_status: if export.context_packet_previews.is_empty() {
                    "not_present"
                } else {
                    "preview_only"
                }
                .to_owned(),
                route_invalidation_status: "not_written".to_owned(),
                evidence_warnings: export_evidence_warnings(export),
            },
            section_persistence: KgExportPersistedSectionDiagnostics {
                persisted_row_sections: persisted_row_sections(),
                hash_only_sections: hash_only_sections(),
                not_persisted_sections: not_persisted_sections(),
                section_hash_count: usize_to_u32(export.hashes.section_hashes.len())?,
                raw_artifact_persisted: false,
            },
            challenge_proof: KgExportPersistedChallengeDiagnostics {
                challenge_count: usize_to_u32(challenge_kinds.len())?,
                challenge_hashes: challenge_hashes(export)?,
                covered_hash_sections: challenge_kinds.clone(),
                coverage_complete: challenge_coverage_complete(&challenge_kinds),
                challenge_kinds,
                proof_algorithm: "hash_commitment_v1".to_owned(),
                verification_status: "pending".to_owned(),
            },
            receipt: KgExportPersistedReceiptDiagnostics {
                receipt_subject_kind: "export".to_owned(),
                receipt_event_type: DAGDB_EXPORT_COMPLETED_EVENT_TYPE.to_owned(),
                latest_receipt_hash: Some(receipt_hash.to_string()),
                subject_head_written: counts.inserted_subject_receipt_head_count > 0 || replayed,
                dag_finality_status: "pending_no_dag_outbox".to_owned(),
                receipt_body_raw_artifact_persisted: false,
                route_invalidation_receipt_written: false,
            },
            idempotency_replay: KgExportPersistedIdempotencyDiagnostics {
                idempotency_key: idempotency_key.to_owned(),
                request_hash: request_hash.to_string(),
                replayed,
                response_cached: true,
                status_code: 201,
                replay_reason: if replayed {
                    "idempotency_key_match"
                } else {
                    "new_persisted_response"
                }
                .to_owned(),
            },
            advisory_deferred: KgExportPersistedAdvisoryDiagnostics {
                route_invalidation_advisory: true,
                route_invalidation_status: "advisory_not_written".to_owned(),
                gateway_api_deferred: true,
                graph_explorer_deferred: true,
                production_route_activation_deferred: true,
                dagdb_dag_outbox_deferred: true,
                exo_dag_writes_deferred: true,
                raw_artifact_storage_deferred: true,
                broad_product_export_surface_deferred: true,
            },
            warning_summaries,
        },
    })
}

fn export_persisted_warnings() -> Vec<String> {
    let mut warnings = BTreeSet::new();
    warnings.insert("route_invalidation_not_written".to_owned());
    warnings.insert("gateway_api_deferred".to_owned());
    warnings.insert("graph_explorer_deferred".to_owned());
    warnings.insert("production_route_activation_deferred".to_owned());
    warnings.insert("dagdb_dag_outbox_write_deferred".to_owned());
    warnings.insert("exo_dag_write_deferred".to_owned());
    warnings.insert("broad_product_export_surface_deferred".to_owned());
    warnings.insert("raw_export_artifact_not_persisted".to_owned());
    warnings.insert("payload_content_not_exported".to_owned());
    warnings.insert("origin_path_not_persisted".to_owned());
    warnings.into_iter().collect()
}

fn export_evidence_warnings(export: &KgPortableExport) -> Vec<String> {
    let mut warnings = BTreeSet::new();
    if !export.context_packet_previews.is_empty() {
        warnings.insert("preview_context_evidence_not_committed".to_owned());
    }
    if export.route_receipts.is_empty() {
        warnings.insert("committed_route_receipts_not_present".to_owned());
    }
    warnings.insert("route_invalidation_evidence_advisory_only".to_owned());
    warnings.into_iter().collect()
}

fn persisted_row_sections() -> Vec<String> {
    [
        "dagdb_exports",
        "dagdb_export_challenges",
        "dagdb_receipts",
        "dagdb_subject_receipt_heads",
        "dagdb_idempotency_keys",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn hash_only_sections() -> Vec<String> {
    [
        "memory_records",
        "catalog_entries",
        "graph_nodes",
        "graph_edges",
        "similarity_results",
        "canonicalization_decisions",
        "placement_traces",
        "validation_reports",
        "receipts",
        "subject_receipt_heads",
        "context_packet_previews",
        "context_packet_records",
        "route_receipts",
        "writeback_summaries",
        "idempotency_references",
        "citation_index",
        "provenance_index",
        "advisory_sections",
        "redaction_summary",
        "omission_summary",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn not_persisted_sections() -> Vec<String> {
    [
        "json_export_artifact",
        "markdown_export_artifact",
        "route_invalidation_writes",
        "gateway_api_exposure",
        "graph_explorer_changes",
        "production_route_activation",
        "dagdb_dag_outbox",
        "exo_dag_finality_writes",
        "broad_product_export_surface",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn challenge_hashes(export: &KgPortableExport) -> Result<BTreeMap<String, String>> {
    challenge_specs(export).map(|specs| {
        specs
            .into_iter()
            .map(|spec| (spec.kind, spec.challenge_hash.to_string()))
            .collect()
    })
}

fn challenge_coverage_complete(challenge_kinds: &[String]) -> bool {
    let expected = [
        "whole_export_hash",
        "citation_index_hash",
        "provenance_index_hash",
        "redaction_summary_hash",
        "omission_summary_hash",
    ];
    expected
        .iter()
        .all(|expected| challenge_kinds.iter().any(|kind| kind == expected))
}

async fn fetch_export_idempotency_replay(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<Option<KgExportPersistedSummary>> {
    let row = sqlx::query(
        "SELECT request_hash, response_body FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4 \
         FOR UPDATE",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(KG_EXPORT_PERSISTED_ROUTE_NAME)
    .bind(idempotency_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;

    let Some(row) = row else {
        return Ok(None);
    };
    let existing_hash = hash_from_vec(row.try_get("request_hash").map_err(pg)?)?;
    if existing_hash != request_hash {
        return Err(KgExportError::Conflict {
            reason: "idempotency_key_conflict".to_owned(),
        });
    }
    let body: JsonValue = row.try_get("response_body").map_err(pg)?;
    let mut summary: KgExportPersistedSummary = decode_cached_replay_summary(
        body,
        KG_EXPORT_PERSISTED_ROUTE_NAME,
        KG_EXPORT_PERSISTED_SUMMARY_SCHEMA,
    )?;
    normalize_persisted_summary_warnings(&mut summary);
    summary.replayed = true;
    summary.diagnostics.idempotency_replay.replayed = true;
    summary.diagnostics.idempotency_replay.request_hash = request_hash.to_string();
    summary.diagnostics.idempotency_replay.replay_reason = "idempotency_key_match".to_owned();
    Ok(Some(summary))
}

async fn insert_export_idempotency_response(
    tx: &mut Transaction<'_, Postgres>,
    summary: &KgExportPersistedSummary,
    request_hash: Hash256,
) -> Result<()> {
    let response_body = json_value(summary)?;
    let response_hash = hash_event_body(summary).map_err(|error| KgExportError::Hash {
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
    .bind(KG_EXPORT_PERSISTED_ROUTE_NAME)
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

async fn verify_export_evidence(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<()> {
    for record in &export.memory_records {
        let memory_id = required_string(record, "memory_id")?;
        ensure_record_scope(export, record)?;
        let row = sqlx::query(
            "SELECT tenant_id, namespace, encode(latest_receipt_hash, 'hex') AS latest_receipt_hash \
             FROM dagdb_memory_objects WHERE memory_id = $1 AND tenant_id = $2 AND namespace = $3",
        )
        .bind(hash_bytes(hash_from_hex("memory_id", memory_id)?))
        .bind(&export.tenant_id)
        .bind(&export.namespace)
        .fetch_optional(&mut **tx)
        .await
        .map_err(pg)?;
        let Some(row) = row else {
            return Err(KgExportError::Conflict {
                reason: format!("export memory evidence not found: {memory_id}"),
            });
        };
        let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
        let namespace: String = row.try_get("namespace").map_err(pg)?;
        if tenant_id != export.tenant_id || namespace != export.namespace {
            return Err(KgExportError::Conflict {
                reason: format!("export memory evidence crosses tenant/namespace: {memory_id}"),
            });
        }
        if let Some(latest_receipt_hash) = record
            .get("latest_receipt_hash")
            .and_then(JsonValue::as_str)
            .filter(|value| !value.is_empty())
        {
            let stored: String = row.try_get("latest_receipt_hash").map_err(pg)?;
            if latest_receipt_hash != stored {
                return Err(KgExportError::Conflict {
                    reason: format!("stale latest receipt for memory: {memory_id}"),
                });
            }
        }
    }
    for record in &export.receipts {
        ensure_record_scope(export, record)?;
        let receipt_hash = required_string(record, "receipt_hash")?;
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM dagdb_receipts WHERE receipt_hash = $1 AND tenant_id = $2 AND namespace = $3)")
                .bind(hash_bytes(hash_from_hex("receipt_hash", receipt_hash)?))
                .bind(&export.tenant_id)
                .bind(&export.namespace)
                .fetch_one(&mut **tx)
                .await
                .map_err(pg)?;
        if !exists {
            return Err(KgExportError::Conflict {
                reason: format!("export receipt evidence not found: {receipt_hash}"),
            });
        }
    }
    Ok(())
}

fn ensure_record_scope(export: &KgPortableExport, record: &KgExportRecord) -> Result<()> {
    let tenant_id = required_string(record, "tenant_id")?;
    let namespace = required_string(record, "namespace")?;
    if tenant_id == export.tenant_id && namespace == export.namespace {
        Ok(())
    } else {
        Err(KgExportError::InvalidScope {
            reason: "export record crosses tenant/namespace".to_owned(),
        })
    }
}

async fn insert_export_receipt(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    requester_did: &str,
    receipt_hash: Hash256,
) -> Result<u64> {
    let export_id = hash_from_hex("export_id", &export.export_id)?;
    let event_hash = export_receipt_body_hash(export, requester_did)?;
    let event_hlc = export_hlc_parts(export)?;
    let receipt_body = json!({
        "schema_version": KG_EXPORT_PERSISTED_SUMMARY_SCHEMA,
        "export_id": export.export_id,
        "whole_export_hash": export.hashes.whole_export_hash,
        "source": "kg_export_persisted_adapter",
        "raw_artifact_persisted": false,
        "route_invalidation_written": false,
        "exo_dag_written": false
    });
    let result = sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, 'export', $4, $5, 1, $6, $7, $8, $9, $10, $11, $8, $9) \
         ON CONFLICT (receipt_hash) DO NOTHING",
    )
    .bind(hash_bytes(receipt_hash))
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(hash_bytes(export_id))
    .bind(hash_bytes(Hash256::ZERO))
    .bind(DAGDB_EXPORT_COMPLETED_EVENT_TYPE)
    .bind(requester_did)
    .bind(event_hlc.physical_ms)
    .bind(event_hlc.logical)
    .bind(hash_bytes(event_hash))
    .bind(receipt_body)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    Ok(result.rows_affected())
}

async fn insert_export_approval_receipts(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    requester_did: &str,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<u32> {
    let mut inserted = 0_u32;
    for event_type in [
        ReceiptEventType::DagdbApprovalRequestSubmitted,
        ReceiptEventType::DagdbApprovalGranted,
    ] {
        let receipt_body = json!({
            "route_name": KG_EXPORT_PERSISTED_ROUTE_NAME,
            "export_id": export.export_id,
            "idempotency_key": idempotency_key,
            "request_hash": request_hash.to_string(),
            "source": "kg_export_persisted_adapter",
        });
        let event_body_hash =
            hash_event_body(&receipt_body).map_err(|error| KgExportError::Hash {
                reason: error.to_string(),
            })?;
        let rows = insert_operational_receipt_in_transaction(
            tx,
            OperationalReceiptInsert {
                tenant_id: &export.tenant_id,
                namespace: &export.namespace,
                subject_kind: SubjectKind::ValidationReport,
                subject_id: operational_receipt_subject_id(
                    KG_EXPORT_PERSISTED_ROUTE_NAME,
                    &export.export_id,
                    event_type,
                ),
                event_type,
                actor_did: requester_did,
                event_hlc: CREATED_AT,
                event_body_hash,
                receipt_body,
            },
        )
        .await
        .map_err(|error| KgExportError::Postgres {
            source: Box::new(error),
        })?;
        inserted = inserted.saturating_add(rows_to_u32(rows)?);
    }
    Ok(inserted)
}

async fn insert_export_subject_head(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    receipt_hash: Hash256,
) -> Result<u64> {
    let export_id = hash_from_hex("export_id", &export.export_id)?;
    let updated_at = export_hlc_parts(export)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_subject_receipt_heads \
         (tenant_id, namespace, subject_kind, subject_id, latest_receipt_hash, latest_seq, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, 'export', $3, $4, 1, $5, $6) \
         ON CONFLICT (tenant_id, namespace, subject_kind, subject_id) DO NOTHING",
    )
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(hash_bytes(export_id))
    .bind(hash_bytes(receipt_hash))
    .bind(updated_at.physical_ms)
    .bind(updated_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    Ok(result.rows_affected())
}

async fn insert_export_record(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    requester_did: &str,
    latest_receipt_hash: Hash256,
) -> Result<u64> {
    ensure_export_record_match(tx, export).await?;
    let created_at = export_hlc_parts(export)?;
    let updated_at = timestamp_parts(UPDATED_AT)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_exports \
         (export_id, tenant_id, namespace, schema_version, export_scope_hash, source_commit_or_repo_ref, \
          included_memory_ids_hash, included_receipt_heads_hash, section_hashes, section_counts, \
          citation_index_hash, provenance_index_hash, redaction_summary_hash, omission_summary_hash, \
          verification_hash, whole_export_hash, export_status, requester_did, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'verified', $17, $18, $19, $20, $21, $22) \
         ON CONFLICT (export_id) DO NOTHING",
    )
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(KG_PORTABLE_EXPORT_SCHEMA)
    .bind(hash_bytes(hash_export_part("export_scope", &export.export_scope)?))
    .bind(&export.source_commit_or_repo_ref)
    .bind(hash_bytes(hash_export_part(
        "included_memory_ids",
        &export_memory_ids(export),
    )?))
    .bind(hash_bytes(hash_export_part(
        "subject_receipt_heads",
        &export.subject_receipt_heads,
    )?))
    .bind(json_value(&export.hashes.section_hashes)?)
    .bind(json_value(&export.diagnostics.section_counts)?)
    .bind(hash_bytes(required_section_hash(export, "citation_index")?))
    .bind(hash_bytes(required_section_hash(export, "provenance_index")?))
    .bind(hash_bytes(required_section_hash(export, "redaction_summary")?))
    .bind(hash_bytes(required_section_hash(export, "omission_summary")?))
    .bind(hash_bytes(hash_export_part("verification", &export.verification)?))
    .bind(hash_bytes(hash_from_hex(
        "whole_export_hash",
        &export.hashes.whole_export_hash,
    )?))
    .bind(requester_did)
    .bind(hash_bytes(latest_receipt_hash))
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .bind(updated_at.physical_ms)
    .bind(updated_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    Ok(result.rows_affected())
}

async fn ensure_export_record_match(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT tenant_id, namespace, encode(whole_export_hash, 'hex') AS whole_export_hash \
         FROM dagdb_exports WHERE export_id = $1",
    )
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .fetch_optional(&mut **tx)
    .await
    .map_err(pg)?;
    let Some(row) = row else {
        return Ok(());
    };
    let tenant_id: String = row.try_get("tenant_id").map_err(pg)?;
    let namespace: String = row.try_get("namespace").map_err(pg)?;
    let whole_export_hash: String = row.try_get("whole_export_hash").map_err(pg)?;
    if tenant_id == export.tenant_id
        && namespace == export.namespace
        && whole_export_hash == export.hashes.whole_export_hash
    {
        Ok(())
    } else {
        Err(KgExportError::Conflict {
            reason: format!("existing export row conflicts: {}", export.export_id),
        })
    }
}

async fn insert_export_challenges(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
) -> Result<u32> {
    let mut inserted = 0u32;
    for spec in challenge_specs(export)? {
        inserted = inserted.saturating_add(rows_to_u32(
            insert_export_challenge(tx, export, &spec).await?,
        )?);
    }
    Ok(inserted)
}

async fn insert_export_challenge(
    tx: &mut Transaction<'_, Postgres>,
    export: &KgPortableExport,
    spec: &ExportChallengeSpec,
) -> Result<u64> {
    let challenge_id = stable_hash(
        "exo.dagdb.kg_export.persisted.challenge_id",
        &[
            &export.tenant_id,
            &export.namespace,
            &export.export_id,
            &spec.kind,
            &spec.challenge_hash.to_string(),
        ],
    )?;
    let proof_hash = stable_hash(
        "exo.dagdb.kg_export.persisted.challenge_proof",
        &[
            &export.export_id,
            &spec.kind,
            &spec.challenge_hash.to_string(),
            "hash_commitment_v1",
        ],
    )?;
    let created_at = export_hlc_parts(export)?;
    let result = sqlx::query(
        "INSERT INTO dagdb_export_challenges \
         (challenge_id, tenant_id, namespace, export_id, challenge_kind, challenge_hash, proof_hash, \
          proof_algorithm, verification_status, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'hash_commitment_v1', 'pending', $8, $9) \
         ON CONFLICT (tenant_id, namespace, export_id, challenge_kind, challenge_hash) DO NOTHING",
    )
    .bind(hash_bytes(challenge_id))
    .bind(&export.tenant_id)
    .bind(&export.namespace)
    .bind(hash_bytes(hash_from_hex("export_id", &export.export_id)?))
    .bind(&spec.kind)
    .bind(hash_bytes(spec.challenge_hash))
    .bind(hash_bytes(proof_hash))
    .bind(created_at.physical_ms)
    .bind(created_at.logical)
    .execute(&mut **tx)
    .await
    .map_err(pg)?;
    Ok(result.rows_affected())
}

#[derive(Debug, Clone)]
struct ExportChallengeSpec {
    kind: String,
    challenge_hash: Hash256,
}

fn challenge_specs(export: &KgPortableExport) -> Result<Vec<ExportChallengeSpec>> {
    Ok(vec![
        ExportChallengeSpec {
            kind: "whole_export_hash".to_owned(),
            challenge_hash: hash_from_hex("whole_export_hash", &export.hashes.whole_export_hash)?,
        },
        ExportChallengeSpec {
            kind: "citation_index_hash".to_owned(),
            challenge_hash: required_section_hash(export, "citation_index")?,
        },
        ExportChallengeSpec {
            kind: "provenance_index_hash".to_owned(),
            challenge_hash: required_section_hash(export, "provenance_index")?,
        },
        ExportChallengeSpec {
            kind: "redaction_summary_hash".to_owned(),
            challenge_hash: required_section_hash(export, "redaction_summary")?,
        },
        ExportChallengeSpec {
            kind: "omission_summary_hash".to_owned(),
            challenge_hash: required_section_hash(export, "omission_summary")?,
        },
    ])
}

fn export_receipt_hash(export: &KgPortableExport, requester_did: &str) -> Result<Hash256> {
    let event_hash = export_receipt_body_hash(export, requester_did)?;
    stable_hash(
        "exo.dagdb.kg_export.persisted.receipt_hash",
        &[
            &export.tenant_id,
            &export.namespace,
            &export.export_id,
            requester_did,
            &export.hashes.whole_export_hash,
            &event_hash.to_string(),
        ],
    )
    .map_err(Into::into)
}

fn export_receipt_body_hash(export: &KgPortableExport, requester_did: &str) -> Result<Hash256> {
    stable_hash(
        "exo.dagdb.kg_export.persisted.receipt_body_hash",
        &[
            &export.export_id,
            &export.hashes.whole_export_hash,
            requester_did,
            DAGDB_EXPORT_COMPLETED_EVENT_TYPE,
        ],
    )
    .map_err(Into::into)
}

fn required_section_hash(export: &KgPortableExport, section: &str) -> Result<Hash256> {
    let Some(value) = export.hashes.section_hashes.get(section) else {
        return Err(KgExportError::Conflict {
            reason: format!("missing section hash: {section}"),
        });
    };
    hash_from_hex(section, value).map_err(Into::into)
}

fn export_memory_ids(export: &KgPortableExport) -> Vec<String> {
    export
        .memory_records
        .iter()
        .filter_map(|record| record.get("memory_id").and_then(JsonValue::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

fn hash_export_part<T: Serialize>(label: &str, value: &T) -> Result<Hash256> {
    hash_event_body(&(label, value)).map_err(|error| KgExportError::Hash {
        reason: error.to_string(),
    })
}

fn required_string<'a>(record: &'a KgExportRecord, key: &str) -> Result<&'a str> {
    record
        .get(key)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| KgExportError::Conflict {
            reason: format!("missing required export record field: {key}"),
        })
}

fn validate_export_requester(requester_did: &str) -> Result<()> {
    if requester_did.is_empty() || !requester_did.starts_with("did:") {
        return Err(KgExportError::InvalidScope {
            reason: "requester_did must be a DID".to_owned(),
        });
    }
    crate::kg_export::reject_forbidden_string("requester_did", requester_did)
}

#[derive(Debug, Clone, Copy)]
struct SqlTimestamp {
    physical_ms: i64,
    logical: i32,
}

fn export_hlc_parts(export: &KgPortableExport) -> Result<SqlTimestamp> {
    Ok(SqlTimestamp {
        physical_ms: i64::try_from(export.created_at_or_hlc.physical_ms)
            .map_err(|_| KgExportError::TimestampOutOfRange)?,
        logical: i32::try_from(export.created_at_or_hlc.logical)
            .map_err(|_| KgExportError::TimestampOutOfRange)?,
    })
}

fn timestamp_parts(timestamp: Timestamp) -> Result<SqlTimestamp> {
    Ok(SqlTimestamp {
        physical_ms: i64::try_from(timestamp.physical_ms)
            .map_err(|_| KgExportError::TimestampOutOfRange)?,
        logical: i32::try_from(timestamp.logical)
            .map_err(|_| KgExportError::TimestampOutOfRange)?,
    })
}

fn rows_to_u32(rows: u64) -> Result<u32> {
    u32::try_from(rows).map_err(|_| KgExportError::CountOutOfRange)
}

fn usize_to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| KgExportError::CountOutOfRange)
}

fn i64_to_u32(value: i64) -> Result<u32> {
    u32::try_from(value).map_err(|_| KgExportError::CountOutOfRange)
}

fn i32_to_u32(value: i32) -> Result<u32> {
    u32::try_from(value).map_err(|_| KgExportError::CountOutOfRange)
}

fn hash_bytes(hash: Hash256) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

fn hash_from_vec(bytes: Vec<u8>) -> Result<Hash256> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| KgExportError::Conflict {
        reason: "hash column had invalid length".to_owned(),
    })?;
    Ok(Hash256::from_bytes(bytes))
}

fn json_value<T: Serialize>(value: &T) -> Result<JsonValue> {
    serde_json::to_value(value).map_err(json_error)
}

async fn load_memory_records(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(memory_id, 'hex') AS memory_id, tenant_id, namespace, node_type, source_type, \
         consent_purpose, encode(payload_hash, 'hex') AS payload_hash, encode(source_hash, 'hex') AS source_hash, \
         encode(payload_uri_hash, 'hex') AS payload_uri_hash, owner_did, controller_did, submitted_by_did, \
         encode(access_policy_hash, 'hex') AS access_policy_hash, encode(declared_rights_hash, 'hex') AS declared_rights_hash, \
         title, summary, keywords, risk_class, risk_bp, status, validation_status, council_status, \
         dag_finality_status, encode(latest_receipt_hash, 'hex') AS latest_receipt_hash, \
         created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical \
         FROM dagdb_memory_objects WHERE tenant_id = $1 AND namespace = $2 ORDER BY memory_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_memory(row, scope).transpose())
        .collect()
}

fn record_memory(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let memory_id: String = row.try_get("memory_id").map_err(pg)?;
    if !memory_allowed(scope, &memory_id) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(&mut record, "memory_id", memory_id);
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "node_type",
        row.try_get("node_type").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "source_type",
        row.try_get("source_type").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "consent_purpose",
        row.try_get("consent_purpose").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "payload_hash",
        row.try_get("payload_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "source_hash",
        row.try_get("source_hash").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "payload_uri_hash",
        row.try_get("payload_uri_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "owner_did",
        row.try_get("owner_did").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "controller_did",
        row.try_get("controller_did").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "submitted_by_did",
        row.try_get("submitted_by_did").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "access_policy_hash",
        row.try_get("access_policy_hash").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "declared_rights_hash",
        row.try_get("declared_rights_hash").map_err(pg)?,
    );
    insert_json(&mut record, "title", row.try_get("title").map_err(pg)?);
    insert_json(&mut record, "summary", row.try_get("summary").map_err(pg)?);
    insert_json(
        &mut record,
        "keywords",
        row.try_get("keywords").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "risk_class",
        row.try_get("risk_class").map_err(pg)?,
    );
    insert_i32(&mut record, "risk_bp", row.try_get("risk_bp").map_err(pg)?);
    insert_string(&mut record, "status", row.try_get("status").map_err(pg)?);
    insert_string(
        &mut record,
        "validation_status",
        row.try_get("validation_status").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "council_status",
        row.try_get("council_status").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "dag_finality_status",
        row.try_get("dag_finality_status").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "latest_receipt_hash",
        row.try_get("latest_receipt_hash").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "created_at_physical_ms",
        row.try_get("created_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "created_at_logical",
        row.try_get("created_at_logical").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "updated_at_physical_ms",
        row.try_get("updated_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "updated_at_logical",
        row.try_get("updated_at_logical").map_err(pg)?,
    );
    checked_record(record).map(Some)
}

async fn load_catalog_entries(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(catalog_id, 'hex') AS catalog_id, tenant_id, namespace, \
         encode(memory_id, 'hex') AS memory_id, encode(parent_catalog_id, 'hex') AS parent_catalog_id, \
         catalog_level, title, summary, keywords, encode(payload_hash, 'hex') AS payload_hash, \
         encode(source_hash, 'hex') AS source_hash, status, validation_status, council_status, \
         dag_finality_status, encode(latest_receipt_hash, 'hex') AS latest_receipt_hash, \
         created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical \
         FROM dagdb_catalog_entries WHERE tenant_id = $1 AND namespace = $2 ORDER BY catalog_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_catalog(row, scope).transpose())
        .collect()
}

fn record_catalog(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let memory_id: Option<String> = row.try_get("memory_id").map_err(pg)?;
    if memory_id
        .as_deref()
        .is_some_and(|memory_id| !memory_allowed(scope, memory_id))
    {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "catalog_id",
        row.try_get("catalog_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_opt_string(&mut record, "memory_id", memory_id);
    insert_opt_string(
        &mut record,
        "parent_catalog_id",
        row.try_get("parent_catalog_id").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "catalog_level",
        row.try_get("catalog_level").map_err(pg)?,
    );
    insert_json(&mut record, "title", row.try_get("title").map_err(pg)?);
    insert_json(&mut record, "summary", row.try_get("summary").map_err(pg)?);
    insert_json(
        &mut record,
        "keywords",
        row.try_get("keywords").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "payload_hash",
        row.try_get("payload_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "source_hash",
        row.try_get("source_hash").map_err(pg)?,
    );
    insert_status_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_graph_nodes(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(graph_node_id, 'hex') AS graph_node_id, tenant_id, namespace, \
         encode(memory_id, 'hex') AS memory_id, graph_style, node_kind, \
         encode(canonical_memory_id, 'hex') AS canonical_memory_id, catalog_path, metadata, \
         created_at_physical_ms, created_at_logical \
         FROM dagdb_graph_nodes WHERE tenant_id = $1 AND namespace = $2 ORDER BY graph_node_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_graph_node(row, scope).transpose())
        .collect()
}

fn record_graph_node(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let memory_id: String = row.try_get("memory_id").map_err(pg)?;
    let graph_style: String = row.try_get("graph_style").map_err(pg)?;
    if !memory_allowed(scope, &memory_id) || !graph_style_allowed(scope, &graph_style) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "graph_node_id",
        row.try_get("graph_node_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "memory_id", memory_id);
    insert_string(&mut record, "graph_style", graph_style);
    insert_string(
        &mut record,
        "node_kind",
        row.try_get("node_kind").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "canonical_memory_id",
        row.try_get("canonical_memory_id").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "catalog_path",
        row.try_get("catalog_path").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "metadata",
        row.try_get("metadata").map_err(pg)?,
    );
    insert_created_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_graph_edges(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(graph_edge_id, 'hex') AS graph_edge_id, tenant_id, namespace, graph_style, \
         encode(from_memory_id, 'hex') AS from_memory_id, encode(to_memory_id, 'hex') AS to_memory_id, \
         edge_kind, encode(receipt_hash, 'hex') AS receipt_hash, created_at_physical_ms, created_at_logical \
         FROM dagdb_graph_edges WHERE tenant_id = $1 AND namespace = $2 ORDER BY graph_edge_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_graph_edge(row, scope).transpose())
        .collect()
}

fn record_graph_edge(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let graph_style: String = row.try_get("graph_style").map_err(pg)?;
    let from_memory_id: String = row.try_get("from_memory_id").map_err(pg)?;
    let to_memory_id: String = row.try_get("to_memory_id").map_err(pg)?;
    if !graph_style_allowed(scope, &graph_style)
        || !memory_allowed(scope, &from_memory_id)
        || !memory_allowed(scope, &to_memory_id)
    {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "graph_edge_id",
        row.try_get("graph_edge_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "graph_style", graph_style);
    insert_string(&mut record, "from_memory_id", from_memory_id);
    insert_string(&mut record, "to_memory_id", to_memory_id);
    insert_string(
        &mut record,
        "edge_kind",
        row.try_get("edge_kind").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "receipt_hash",
        row.try_get("receipt_hash").map_err(pg)?,
    );
    insert_created_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_similarity_results(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(similarity_result_id, 'hex') AS similarity_result_id, tenant_id, namespace, \
         encode(candidate_memory_id, 'hex') AS candidate_memory_id, encode(matched_memory_id, 'hex') AS matched_memory_id, \
         similarity_type, similarity_bp, matched_fields, reason, created_at_physical_ms, created_at_logical \
         FROM dagdb_graph_similarity_results WHERE tenant_id = $1 AND namespace = $2 ORDER BY similarity_result_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_similarity(row, scope).transpose())
        .collect()
}

fn record_similarity(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let candidate_memory_id: String = row.try_get("candidate_memory_id").map_err(pg)?;
    let matched_memory_id: String = row.try_get("matched_memory_id").map_err(pg)?;
    if !memory_allowed(scope, &candidate_memory_id) || !memory_allowed(scope, &matched_memory_id) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "similarity_result_id",
        row.try_get("similarity_result_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "candidate_memory_id", candidate_memory_id);
    insert_string(&mut record, "matched_memory_id", matched_memory_id);
    insert_string(
        &mut record,
        "similarity_type",
        row.try_get("similarity_type").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "similarity_bp",
        row.try_get("similarity_bp").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "matched_fields",
        row.try_get("matched_fields").map_err(pg)?,
    );
    insert_string(&mut record, "reason", row.try_get("reason").map_err(pg)?);
    insert_created_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_canonicalization_decisions(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(decision_id, 'hex') AS decision_id, tenant_id, namespace, \
         encode(input_memory_id, 'hex') AS input_memory_id, encode(canonical_memory_id, 'hex') AS canonical_memory_id, \
         matched_memory_ids, decision_kind, decision_reason, confidence_bp, risk_class, validator_status, \
         required_edges_to_create, encode(receipt_hash, 'hex') AS receipt_hash, receipt_intent, \
         created_at_physical_ms, created_at_logical \
         FROM dagdb_graph_canonicalization_decisions WHERE tenant_id = $1 AND namespace = $2 ORDER BY decision_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_canonicalization(row, scope).transpose())
        .collect()
}

fn record_canonicalization(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let input_memory_id: String = row.try_get("input_memory_id").map_err(pg)?;
    if !memory_allowed(scope, &input_memory_id) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "decision_id",
        row.try_get("decision_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "input_memory_id", input_memory_id);
    insert_opt_string(
        &mut record,
        "canonical_memory_id",
        row.try_get("canonical_memory_id").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "matched_memory_ids",
        row.try_get("matched_memory_ids").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "decision_kind",
        row.try_get("decision_kind").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "decision_reason",
        row.try_get("decision_reason").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "confidence_bp",
        row.try_get("confidence_bp").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "risk_class",
        row.try_get("risk_class").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "validator_status",
        row.try_get("validator_status").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "required_edges_to_create",
        row.try_get("required_edges_to_create").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "receipt_hash",
        row.try_get("receipt_hash").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "receipt_intent",
        row.try_get("receipt_intent").map_err(pg)?,
    );
    insert_created_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_placement_traces(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(placement_trace_id, 'hex') AS placement_trace_id, tenant_id, namespace, \
         encode(input_memory_id, 'hex') AS input_memory_id, trace_steps, completed, \
         created_at_physical_ms, created_at_logical \
         FROM dagdb_graph_placement_traces WHERE tenant_id = $1 AND namespace = $2 ORDER BY placement_trace_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_placement_trace(row, scope).transpose())
        .collect()
}

fn record_placement_trace(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let input_memory_id: String = row.try_get("input_memory_id").map_err(pg)?;
    if !memory_allowed(scope, &input_memory_id) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "placement_trace_id",
        row.try_get("placement_trace_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "input_memory_id", input_memory_id);
    insert_json(
        &mut record,
        "trace_steps",
        row.try_get("trace_steps").map_err(pg)?,
    );
    insert_bool(
        &mut record,
        "completed",
        row.try_get("completed").map_err(pg)?,
    );
    insert_created_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_validation_reports(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(validation_report_id, 'hex') AS validation_report_id, tenant_id, namespace, subject_kind, \
         encode(subject_id, 'hex') AS subject_id, validator_did, encode(input_hash, 'hex') AS input_hash, \
         encode(policy_hash, 'hex') AS policy_hash, validation_status, risk_class, risk_bp, decision, notes, \
         contradictory_report_ids, encode(council_decision_id, 'hex') AS council_decision_id, \
         encode(latest_receipt_hash, 'hex') AS latest_receipt_hash, created_at_physical_ms, created_at_logical \
         FROM dagdb_validation_reports WHERE tenant_id = $1 AND namespace = $2 ORDER BY validation_report_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_validation(row, scope).transpose())
        .collect()
}

fn record_validation(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let subject_kind: String = row.try_get("subject_kind").map_err(pg)?;
    let subject_id: String = row.try_get("subject_id").map_err(pg)?;
    if subject_kind == "memory" && !memory_allowed(scope, &subject_id) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "validation_report_id",
        row.try_get("validation_report_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "subject_kind", subject_kind);
    insert_string(&mut record, "subject_id", subject_id);
    insert_string(
        &mut record,
        "validator_did",
        row.try_get("validator_did").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "input_hash",
        row.try_get("input_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "policy_hash",
        row.try_get("policy_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "validation_status",
        row.try_get("validation_status").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "risk_class",
        row.try_get("risk_class").map_err(pg)?,
    );
    insert_i32(&mut record, "risk_bp", row.try_get("risk_bp").map_err(pg)?);
    insert_string(
        &mut record,
        "decision",
        row.try_get("decision").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "notes",
        sanitize_validation_notes(row.try_get("notes").map_err(pg)?)?,
    );
    insert_json(
        &mut record,
        "contradictory_report_ids",
        row.try_get("contradictory_report_ids").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "council_decision_id",
        row.try_get("council_decision_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "latest_receipt_hash",
        row.try_get("latest_receipt_hash").map_err(pg)?,
    );
    insert_created_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_receipts(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(receipt_hash, 'hex') AS receipt_hash, tenant_id, namespace, subject_kind, \
         encode(subject_id, 'hex') AS subject_id, encode(prev_receipt_hash, 'hex') AS prev_receipt_hash, \
         seq, event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, encode(event_hash, 'hex') AS event_hash, \
         created_at_physical_ms, created_at_logical \
         FROM dagdb_receipts WHERE tenant_id = $1 AND namespace = $2 ORDER BY subject_kind, subject_id, seq, receipt_hash",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_receipt(row, scope).transpose())
        .collect()
}

fn record_receipt(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let subject_kind: String = row.try_get("subject_kind").map_err(pg)?;
    let subject_id: String = row.try_get("subject_id").map_err(pg)?;
    if subject_kind == "memory" && !memory_allowed(scope, &subject_id) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "receipt_hash",
        row.try_get("receipt_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "subject_kind", subject_kind);
    insert_string(&mut record, "subject_id", subject_id);
    insert_string(
        &mut record,
        "prev_receipt_hash",
        row.try_get("prev_receipt_hash").map_err(pg)?,
    );
    insert_i64(&mut record, "seq", row.try_get("seq").map_err(pg)?);
    insert_string(
        &mut record,
        "event_type",
        row.try_get("event_type").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "actor_did",
        row.try_get("actor_did").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "event_hlc_physical_ms",
        row.try_get("event_hlc_physical_ms").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "event_hlc_logical",
        row.try_get("event_hlc_logical").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "event_hash",
        row.try_get("event_hash").map_err(pg)?,
    );
    insert_created_fields(&mut record, &row)?;
    checked_record(record).map(Some)
}

async fn load_subject_receipt_heads(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT tenant_id, namespace, subject_kind, encode(subject_id, 'hex') AS subject_id, \
         encode(latest_receipt_hash, 'hex') AS latest_receipt_hash, latest_seq, updated_at_physical_ms, updated_at_logical \
         FROM dagdb_subject_receipt_heads WHERE tenant_id = $1 AND namespace = $2 ORDER BY subject_kind, subject_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_subject_head(row, scope).transpose())
        .collect()
}

fn record_subject_head(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let subject_kind: String = row.try_get("subject_kind").map_err(pg)?;
    let subject_id: String = row.try_get("subject_id").map_err(pg)?;
    if subject_kind == "memory" && !memory_allowed(scope, &subject_id) {
        return Ok(None);
    }
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(&mut record, "subject_kind", subject_kind);
    insert_string(&mut record, "subject_id", subject_id);
    insert_string(
        &mut record,
        "latest_receipt_hash",
        row.try_get("latest_receipt_hash").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "latest_seq",
        row.try_get("latest_seq").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "updated_at_physical_ms",
        row.try_get("updated_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "updated_at_logical",
        row.try_get("updated_at_logical").map_err(pg)?,
    );
    checked_record(record).map(Some)
}

async fn load_context_packet_records(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(context_packet_id, 'hex') AS context_packet_id, tenant_id, namespace, request_id, \
         encode(route_id, 'hex') AS route_id, encode(task_hash, 'hex') AS task_hash, requesting_agent_did, \
         memory_refs, encode(packet_hash, 'hex') AS packet_hash, token_budget, token_estimate, \
         encode(validation_report_id, 'hex') AS validation_report_id, encode(council_decision_id, 'hex') AS council_decision_id, \
         validation_status, council_status, dag_finality_status, encode(latest_receipt_hash, 'hex') AS latest_receipt_hash, \
         created_at_physical_ms, created_at_logical \
         FROM dagdb_context_packets WHERE tenant_id = $1 AND namespace = $2 ORDER BY context_packet_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter().map(record_context_packet).collect()
}

fn record_context_packet(row: sqlx::postgres::PgRow) -> Result<KgExportRecord> {
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "context_packet_id",
        row.try_get("context_packet_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "request_id",
        row.try_get("request_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "route_id",
        row.try_get("route_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "task_hash",
        row.try_get("task_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "requesting_agent_did",
        row.try_get("requesting_agent_did").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "memory_refs",
        sanitize_context_memory_refs(row.try_get("memory_refs").map_err(pg)?)?,
    );
    insert_string(
        &mut record,
        "packet_hash",
        row.try_get("packet_hash").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "token_budget",
        row.try_get("token_budget").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "token_estimate",
        row.try_get("token_estimate").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "validation_report_id",
        row.try_get("validation_report_id").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "council_decision_id",
        row.try_get("council_decision_id").map_err(pg)?,
    );
    insert_context_status_fields(&mut record, &row)?;
    checked_record(record)
}

async fn load_route_receipts(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT encode(route_id, 'hex') AS route_id, tenant_id, namespace, requesting_agent_did, \
         encode(task_signature_hash, 'hex') AS task_signature_hash, encode(approved_scope_hash, 'hex') AS approved_scope_hash, \
         encode(credential_id, 'hex') AS credential_id, candidate_memory_ids, selected_memory_ids, rejected_memory_ids, \
         route_score_bp, token_budget, token_estimate, overuse_penalty_bp, risk_bp, status, validation_status, council_status, \
         dag_finality_status, encode(validation_report_id, 'hex') AS validation_report_id, encode(council_decision_id, 'hex') AS council_decision_id, \
         stale_at_physical_ms, stale_at_logical, encode(latest_receipt_hash, 'hex') AS latest_receipt_hash, created_at_physical_ms, created_at_logical \
         FROM dagdb_route_receipts WHERE tenant_id = $1 AND namespace = $2 ORDER BY route_id",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter().map(record_route).collect()
}

fn record_route(row: sqlx::postgres::PgRow) -> Result<KgExportRecord> {
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "route_id",
        row.try_get("route_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "requesting_agent_did",
        row.try_get("requesting_agent_did").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "task_signature_hash",
        row.try_get("task_signature_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "approved_scope_hash",
        row.try_get("approved_scope_hash").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "credential_id",
        row.try_get("credential_id").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "candidate_memory_ids",
        row.try_get("candidate_memory_ids").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "selected_memory_ids",
        row.try_get("selected_memory_ids").map_err(pg)?,
    );
    insert_json(
        &mut record,
        "rejected_memory_ids",
        row.try_get("rejected_memory_ids").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "route_score_bp",
        row.try_get("route_score_bp").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "token_budget",
        row.try_get("token_budget").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "token_estimate",
        row.try_get("token_estimate").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "overuse_penalty_bp",
        row.try_get("overuse_penalty_bp").map_err(pg)?,
    );
    insert_i32(&mut record, "risk_bp", row.try_get("risk_bp").map_err(pg)?);
    insert_opt_string(
        &mut record,
        "validation_report_id",
        row.try_get("validation_report_id").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "council_decision_id",
        row.try_get("council_decision_id").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "stale_at_physical_ms",
        row.try_get("stale_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "stale_at_logical",
        row.try_get("stale_at_logical").map_err(pg)?,
    );
    insert_status_fields(&mut record, &row)?;
    checked_record(record)
}

async fn load_idempotency_references(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT tenant_id, namespace, route_name, idempotency_key, encode(request_hash, 'hex') AS request_hash, \
         encode(response_hash, 'hex') AS response_hash, response_body, status_code, cached_failure, \
         created_at_physical_ms, created_at_logical, expires_at_physical_ms, expires_at_logical \
         FROM dagdb_idempotency_keys WHERE tenant_id = $1 AND namespace = $2 ORDER BY route_name, idempotency_key",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| record_idempotency(row, scope).transpose())
        .collect()
}

fn record_idempotency(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let idempotency_key: String = row.try_get("idempotency_key").map_err(pg)?;
    if !idempotency_allowed(scope, &idempotency_key) {
        return Ok(None);
    }
    let response_body: JsonValue = row.try_get("response_body").map_err(pg)?;
    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "tenant_id",
        row.try_get("tenant_id").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "namespace",
        row.try_get("namespace").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "route_name",
        row.try_get("route_name").map_err(pg)?,
    );
    insert_string(&mut record, "idempotency_key", idempotency_key);
    insert_string(
        &mut record,
        "request_hash",
        row.try_get("request_hash").map_err(pg)?,
    );
    insert_string(
        &mut record,
        "response_hash",
        row.try_get("response_hash").map_err(pg)?,
    );
    insert_opt_string(
        &mut record,
        "response_schema_version",
        response_body
            .get("schema_version")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
    );
    insert_i32(
        &mut record,
        "status_code",
        row.try_get("status_code").map_err(pg)?,
    );
    insert_bool(
        &mut record,
        "cached_failure",
        row.try_get("cached_failure").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "created_at_physical_ms",
        row.try_get("created_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "created_at_logical",
        row.try_get("created_at_logical").map_err(pg)?,
    );
    insert_i64(
        &mut record,
        "expires_at_physical_ms",
        row.try_get("expires_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        &mut record,
        "expires_at_logical",
        row.try_get("expires_at_logical").map_err(pg)?,
    );
    checked_record(record).map(Some)
}

async fn load_writeback_summaries(
    tx: &mut Transaction<'_, Postgres>,
    scope: &KgExportScope,
) -> Result<Vec<KgExportRecord>> {
    let rows = sqlx::query(
        "SELECT idempotency_key, response_body FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 ORDER BY idempotency_key",
    )
    .bind(&scope.tenant_id)
    .bind(&scope.namespace)
    .bind(KG_WRITEBACK_PERSISTED_ROUTE_NAME)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;

    rows.into_iter()
        .filter_map(|row| sanitize_writeback_summary(row, scope).transpose())
        .collect()
}

fn sanitize_writeback_summary(
    row: sqlx::postgres::PgRow,
    scope: &KgExportScope,
) -> Result<Option<KgExportRecord>> {
    let idempotency_key: String = row.try_get("idempotency_key").map_err(pg)?;
    if !idempotency_allowed(scope, &idempotency_key) {
        return Ok(None);
    }
    let body: JsonValue = row.try_get("response_body").map_err(pg)?;
    let mut record = KgExportRecord::new();
    insert_value_from_body(&mut record, &body, "schema_version");
    insert_value_from_body(&mut record, &body, "tenant_id");
    insert_value_from_body(&mut record, &body, "namespace");
    insert_value_from_body(&mut record, &body, "proposal_id");
    insert_value_from_body(&mut record, &body, "candidate_id");
    insert_string(&mut record, "idempotency_key", idempotency_key);
    insert_value_from_body(&mut record, &body, "replayed");
    insert_value_from_body(&mut record, &body, "inserted_memory_count");
    insert_value_from_body(&mut record, &body, "inserted_catalog_count");
    insert_value_from_body(&mut record, &body, "inserted_graph_node_count");
    insert_value_from_body(&mut record, &body, "inserted_graph_edge_count");
    insert_value_from_body(&mut record, &body, "inserted_similarity_result_count");
    insert_value_from_body(&mut record, &body, "inserted_validation_report_count");
    insert_value_from_body(&mut record, &body, "inserted_placement_decision_count");
    insert_value_from_body(&mut record, &body, "inserted_placement_trace_count");
    insert_value_from_body(&mut record, &body, "inserted_receipt_count");
    insert_value_from_body(&mut record, &body, "inserted_subject_receipt_head_count");
    insert_value_from_body(&mut record, &body, "inserted_idempotency_response_count");
    insert_value_from_body(&mut record, &body, "skipped_advisory_section_count");
    insert_value_from_body(&mut record, &body, "persisted_route_invalidation_count");
    insert_value_from_body(&mut record, &body, "persisted_export_record_count");
    insert_value_from_body(&mut record, &body, "preview_evidence_only");
    if let Some(diagnostics) = body.get("diagnostics") {
        insert_json(
            &mut record,
            "diagnostics",
            sanitize_writeback_diagnostics(diagnostics),
        );
    }
    checked_record(record).map(Some)
}

fn sanitize_writeback_diagnostics(diagnostics: &JsonValue) -> JsonValue {
    json!({
        "persisted_row_counts": diagnostics.get("persisted_row_counts").cloned().unwrap_or(JsonValue::Null),
        "advisory_deferred": diagnostics.get("advisory_deferred").cloned().unwrap_or(JsonValue::Null),
        "evidence_status": diagnostics.pointer("/evidence/evidence_status").cloned().unwrap_or(JsonValue::Null),
        "placement_decision_kind": diagnostics.pointer("/placement_governance/placement_decision_kind").cloned().unwrap_or(JsonValue::Null),
        "placement_status": diagnostics.pointer("/placement_governance/placement_status").cloned().unwrap_or(JsonValue::Null),
        "validation_status": diagnostics.pointer("/validation_risk_council/validation_status").cloned().unwrap_or(JsonValue::Null),
        "risk_class": diagnostics.pointer("/validation_risk_council/risk_class").cloned().unwrap_or(JsonValue::Null),
        "council_required": diagnostics.pointer("/validation_risk_council/council_required").cloned().unwrap_or(JsonValue::Null),
        "idempotency_replay": diagnostics.get("idempotency_replay").cloned().unwrap_or(JsonValue::Null),
        "warning_summaries": sanitize_warning_values(diagnostics.get("warning_summaries")),
    })
}

fn sanitize_warning_values(value: Option<&JsonValue>) -> JsonValue {
    let warnings = value
        .and_then(JsonValue::as_array)
        .map(|warnings| {
            normalize_export_warning_summaries(
                warnings
                    .iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_owned),
            )
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    JsonValue::Array(warnings)
}

/// Map pre-Wave-A export warning labels to current safe summaries on read paths only.
fn legacy_export_warning_alias(warning: &str) -> &str {
    match warning {
        "raw_payload_not_persisted" => "payload_content_not_exported",
        "source_path_not_persisted" => "origin_path_not_persisted",
        other => other,
    }
}

fn normalize_export_warning_summaries(warnings: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut normalized = BTreeSet::new();
    for warning in warnings {
        normalized.insert(legacy_export_warning_alias(&warning).to_owned());
    }
    normalized.into_iter().collect()
}

fn normalize_persisted_summary_warnings(summary: &mut KgExportPersistedSummary) {
    summary.diagnostics.warning_summaries =
        normalize_export_warning_summaries(summary.diagnostics.warning_summaries.iter().cloned());
}

fn normalize_finality_outbox_summary_warnings(summary: &mut KgExportFinalityOutboxSummary) {
    summary.diagnostics.warning_summaries =
        normalize_export_warning_summaries(summary.diagnostics.warning_summaries.iter().cloned());
}

fn sanitize_context_packet_previews(
    scope: &KgExportScope,
    previews: &[KgContextPacketPreview],
) -> Result<Vec<KgExportRecord>> {
    if !scope.include_preview_context {
        return Ok(Vec::new());
    }
    previews
        .iter()
        .map(|preview| sanitize_context_packet_preview(scope, preview))
        .collect()
}

fn sanitize_context_packet_preview(
    scope: &KgExportScope,
    preview: &KgContextPacketPreview,
) -> Result<KgExportRecord> {
    if preview.tenant_id != scope.tenant_id || preview.namespace != scope.namespace {
        return Err(KgExportError::InvalidScope {
            reason: "context packet preview crosses tenant/namespace scope".to_owned(),
        });
    }
    let memory_refs = preview
        .memory_refs
        .iter()
        .filter(|memory| memory_allowed(scope, &memory.memory_id))
        .map(sanitize_memory_ref)
        .collect::<Result<Vec<_>>>()?;
    let graph_edges = preview
        .graph_edges
        .iter()
        .filter(|edge| {
            memory_allowed(scope, &edge.from_memory_id) && memory_allowed(scope, &edge.to_memory_id)
        })
        .map(sanitize_graph_edge_ref)
        .collect::<Result<Vec<_>>>()?;
    let citation_handles = preview
        .citation_handles
        .iter()
        .filter(|citation| memory_allowed(scope, &citation.memory_id))
        .map(sanitize_citation_handle)
        .collect::<Result<Vec<_>>>()?;

    let mut record = KgExportRecord::new();
    insert_string(
        &mut record,
        "context_packet_id",
        preview.context_packet_id.clone(),
    );
    insert_string(&mut record, "route_hint_id", preview.route_hint_id.clone());
    insert_string(&mut record, "tenant_id", preview.tenant_id.clone());
    insert_string(&mut record, "namespace", preview.namespace.clone());
    insert_bool(&mut record, "preview_only", preview.dry_run_or_preview_only);
    insert_bool(&mut record, "body_content_returned", false);
    insert_u32(&mut record, "token_budget", preview.token_budget);
    insert_u32(&mut record, "token_estimate", preview.token_estimate);
    insert_u32(
        &mut record,
        "memory_ref_count",
        u32::try_from(memory_refs.len()).map_err(|_| KgExportError::InvalidScope {
            reason: "memory_ref_count out of range".to_owned(),
        })?,
    );
    insert_u32(
        &mut record,
        "graph_edge_count",
        u32::try_from(graph_edges.len()).map_err(|_| KgExportError::InvalidScope {
            reason: "graph_edge_count out of range".to_owned(),
        })?,
    );
    insert_json(&mut record, "memory_refs", JsonValue::Array(memory_refs));
    insert_json(&mut record, "graph_edges", JsonValue::Array(graph_edges));
    insert_json(
        &mut record,
        "citation_handles",
        JsonValue::Array(citation_handles),
    );
    insert_json(
        &mut record,
        "warnings",
        JsonValue::Array(
            preview
                .warnings
                .iter()
                .map(|warning| JsonValue::String(warning.clone()))
                .collect(),
        ),
    );
    checked_record(record)
}

fn sanitize_memory_ref(memory: &KgMemoryRef) -> Result<JsonValue> {
    let mut record = KgExportRecord::new();
    insert_string(&mut record, "memory_id", memory.memory_id.clone());
    insert_opt_string(&mut record, "catalog_id", memory.catalog_id.clone());
    insert_json(
        &mut record,
        "catalog_path",
        JsonValue::Array(
            memory
                .catalog_path
                .iter()
                .map(|path| JsonValue::String(path.clone()))
                .collect(),
        ),
    );
    insert_json(
        &mut record,
        "title",
        serde_json::to_value(&memory.title).map_err(json_error)?,
    );
    insert_json(
        &mut record,
        "summary",
        serde_json::to_value(&memory.summary).map_err(json_error)?,
    );
    insert_string(
        &mut record,
        "latest_receipt_hash",
        memory.latest_receipt_hash.clone(),
    );
    insert_string(
        &mut record,
        "validation_status",
        memory.validation_status.clone(),
    );
    insert_string(&mut record, "risk_class", memory.risk_class.clone());
    insert_json(
        &mut record,
        "graph_node_ids",
        JsonValue::Array(
            memory
                .graph_node_ids
                .iter()
                .map(|id| JsonValue::String(id.clone()))
                .collect(),
        ),
    );
    insert_json(
        &mut record,
        "validation_report_ids",
        JsonValue::Array(
            memory
                .validation_report_ids
                .iter()
                .map(|id| JsonValue::String(id.clone()))
                .collect(),
        ),
    );
    insert_string(
        &mut record,
        "citation_handle",
        memory.citation_handle.clone(),
    );
    checked_record(record).map(|record| json!(record))
}

fn sanitize_graph_edge_ref(edge: &KgGraphEdgeRef) -> Result<JsonValue> {
    let mut record = KgExportRecord::new();
    insert_string(&mut record, "graph_edge_id", edge.graph_edge_id.clone());
    insert_string(&mut record, "from_memory_id", edge.from_memory_id.clone());
    insert_string(&mut record, "to_memory_id", edge.to_memory_id.clone());
    insert_string(&mut record, "edge_kind", edge.edge_kind.clone());
    insert_string(&mut record, "graph_style", edge.graph_style.clone());
    insert_opt_string(&mut record, "receipt_hash", edge.receipt_hash.clone());
    checked_record(record).map(|record| json!(record))
}

fn sanitize_citation_handle(citation: &KgCitationHandle) -> Result<JsonValue> {
    let mut record = KgExportRecord::new();
    insert_string(&mut record, "citation_handle", citation.handle.clone());
    insert_string(&mut record, "memory_id", citation.memory_id.clone());
    insert_opt_string(&mut record, "catalog_id", citation.catalog_id.clone());
    insert_string(
        &mut record,
        "latest_receipt_hash",
        citation.latest_receipt_hash.clone(),
    );
    insert_json(
        &mut record,
        "graph_node_ids",
        JsonValue::Array(
            citation
                .graph_node_ids
                .iter()
                .map(|id| JsonValue::String(id.clone()))
                .collect(),
        ),
    );
    insert_json(
        &mut record,
        "graph_edge_ids",
        JsonValue::Array(
            citation
                .graph_edge_ids
                .iter()
                .map(|id| JsonValue::String(id.clone()))
                .collect(),
        ),
    );
    insert_json(
        &mut record,
        "validation_report_ids",
        JsonValue::Array(
            citation
                .validation_report_ids
                .iter()
                .map(|id| JsonValue::String(id.clone()))
                .collect(),
        ),
    );
    checked_record(record).map(|record| json!(record))
}

fn build_citation_index(
    scope: &KgExportScope,
    previews: &[KgExportRecord],
) -> Result<Vec<KgExportRecord>> {
    let mut index = Vec::new();
    for preview in previews {
        let context_packet_id = preview
            .get("context_packet_id")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_owned();
        if let Some(citations) = preview
            .get("citation_handles")
            .and_then(JsonValue::as_array)
        {
            for citation in citations {
                let Some(citation_record) = citation.as_object() else {
                    continue;
                };
                let memory_id = citation_record
                    .get("memory_id")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default();
                if !memory_allowed(scope, memory_id) {
                    continue;
                }
                let mut record = KgExportRecord::new();
                insert_string(
                    &mut record,
                    "citation_handle",
                    citation_record
                        .get("citation_handle")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                );
                insert_string(&mut record, "memory_id", memory_id.to_owned());
                insert_json(
                    &mut record,
                    "catalog_id",
                    citation_record
                        .get("catalog_id")
                        .cloned()
                        .unwrap_or(JsonValue::Null),
                );
                insert_string(
                    &mut record,
                    "latest_receipt_hash",
                    citation_record
                        .get("latest_receipt_hash")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                );
                insert_json(
                    &mut record,
                    "graph_node_ids",
                    citation_record
                        .get("graph_node_ids")
                        .cloned()
                        .unwrap_or(JsonValue::Array(Vec::new())),
                );
                insert_json(
                    &mut record,
                    "graph_edge_ids",
                    citation_record
                        .get("graph_edge_ids")
                        .cloned()
                        .unwrap_or(JsonValue::Array(Vec::new())),
                );
                insert_json(
                    &mut record,
                    "validation_report_ids",
                    citation_record
                        .get("validation_report_ids")
                        .cloned()
                        .unwrap_or(JsonValue::Array(Vec::new())),
                );
                insert_string(&mut record, "context_packet_id", context_packet_id.clone());
                insert_string(&mut record, "citation_status", "preview_only".to_owned());
                index.push(checked_record(record)?);
            }
        }
    }
    Ok(index)
}

fn build_provenance_index(
    memories: &[KgExportRecord],
    validations: &[KgExportRecord],
    receipts: &[KgExportRecord],
) -> Vec<KgExportRecord> {
    let mut index = Vec::new();
    for memory in memories {
        let mut record = KgExportRecord::new();
        copy_field(memory, &mut record, "memory_id", "subject_id");
        insert_string(&mut record, "subject_kind", "memory".to_owned());
        copy_field(memory, &mut record, "payload_hash", "payload_hash");
        copy_field(memory, &mut record, "source_hash", "source_hash");
        copy_field(
            memory,
            &mut record,
            "latest_receipt_hash",
            "latest_receipt_hash",
        );
        insert_string(&mut record, "provenance_status", "row_exported".to_owned());
        index.push(record);
    }
    for validation in validations {
        let mut record = KgExportRecord::new();
        copy_field(
            validation,
            &mut record,
            "validation_report_id",
            "subject_id",
        );
        insert_string(&mut record, "subject_kind", "validation_report".to_owned());
        copy_field(
            validation,
            &mut record,
            "latest_receipt_hash",
            "latest_receipt_hash",
        );
        insert_string(
            &mut record,
            "provenance_status",
            "validation_exported".to_owned(),
        );
        index.push(record);
    }
    for receipt in receipts {
        let mut record = KgExportRecord::new();
        copy_field(receipt, &mut record, "receipt_hash", "subject_id");
        insert_string(&mut record, "subject_kind", "receipt".to_owned());
        copy_field(receipt, &mut record, "event_hash", "event_hash");
        insert_string(
            &mut record,
            "provenance_status",
            "receipt_exported".to_owned(),
        );
        index.push(record);
    }
    index
}

fn copy_field(source: &KgExportRecord, target: &mut KgExportRecord, from: &str, to: &str) {
    if let Some(value) = source.get(from) {
        target.insert(to.to_owned(), value.clone());
    }
}

fn insert_status_fields(record: &mut KgExportRecord, row: &sqlx::postgres::PgRow) -> Result<()> {
    insert_string(record, "status", row.try_get("status").map_err(pg)?);
    insert_string(
        record,
        "validation_status",
        row.try_get("validation_status").map_err(pg)?,
    );
    insert_string(
        record,
        "council_status",
        row.try_get("council_status").map_err(pg)?,
    );
    insert_string(
        record,
        "dag_finality_status",
        row.try_get("dag_finality_status").map_err(pg)?,
    );
    insert_string(
        record,
        "latest_receipt_hash",
        row.try_get("latest_receipt_hash").map_err(pg)?,
    );
    insert_i64(
        record,
        "created_at_physical_ms",
        row.try_get("created_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        record,
        "created_at_logical",
        row.try_get("created_at_logical").map_err(pg)?,
    );
    Ok(())
}

fn insert_context_status_fields(
    record: &mut KgExportRecord,
    row: &sqlx::postgres::PgRow,
) -> Result<()> {
    insert_string(
        record,
        "validation_status",
        row.try_get("validation_status").map_err(pg)?,
    );
    insert_string(
        record,
        "council_status",
        row.try_get("council_status").map_err(pg)?,
    );
    insert_string(
        record,
        "dag_finality_status",
        row.try_get("dag_finality_status").map_err(pg)?,
    );
    insert_string(
        record,
        "latest_receipt_hash",
        row.try_get("latest_receipt_hash").map_err(pg)?,
    );
    insert_i64(
        record,
        "created_at_physical_ms",
        row.try_get("created_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        record,
        "created_at_logical",
        row.try_get("created_at_logical").map_err(pg)?,
    );
    Ok(())
}

fn insert_created_fields(record: &mut KgExportRecord, row: &sqlx::postgres::PgRow) -> Result<()> {
    insert_i64(
        record,
        "created_at_physical_ms",
        row.try_get("created_at_physical_ms").map_err(pg)?,
    );
    insert_i32(
        record,
        "created_at_logical",
        row.try_get("created_at_logical").map_err(pg)?,
    );
    Ok(())
}

fn insert_string(record: &mut KgExportRecord, key: &str, value: String) {
    record.insert(key.to_owned(), JsonValue::String(value));
}

fn insert_opt_string(record: &mut KgExportRecord, key: &str, value: Option<String>) {
    record.insert(
        key.to_owned(),
        value.map_or(JsonValue::Null, JsonValue::String),
    );
}

fn insert_json(record: &mut KgExportRecord, key: &str, value: JsonValue) {
    record.insert(key.to_owned(), value);
}

fn insert_bool(record: &mut KgExportRecord, key: &str, value: bool) {
    record.insert(key.to_owned(), JsonValue::Bool(value));
}

fn insert_i32(record: &mut KgExportRecord, key: &str, value: i32) {
    record.insert(key.to_owned(), json!(value));
}

fn insert_i64(record: &mut KgExportRecord, key: &str, value: i64) {
    record.insert(key.to_owned(), json!(value));
}

fn insert_u32(record: &mut KgExportRecord, key: &str, value: u32) {
    record.insert(key.to_owned(), json!(value));
}

fn insert_value_from_body(record: &mut KgExportRecord, body: &JsonValue, key: &str) {
    if let Some(value) = body.get(key) {
        record.insert(key.to_owned(), value.clone());
    }
}

fn checked_record(record: KgExportRecord) -> Result<KgExportRecord> {
    reject_forbidden_export_json(&json!(record), "$")?;
    Ok(record)
}

/// Persisted validation `notes` JSONB is attacker-influenced: only the typed
/// `SafeMetadata` envelope may cross the export trust boundary. Any extra or
/// missing field fails closed instead of being copied wholesale.
fn sanitize_validation_notes(value: JsonValue) -> Result<JsonValue> {
    let notes: SafeMetadata =
        serde_json::from_value(value).map_err(|error| KgExportError::ForbiddenMaterial {
            path: "$.validation_reports[].notes".to_owned(),
            reason: format!("notes must match the SafeMetadata shape: {error}"),
        })?;
    serde_json::to_value(&notes).map_err(json_error)
}

/// Persisted context-packet `memory_refs` JSONB is attacker-influenced:
/// rebuild each entry from an id/hash allowlist instead of copying arbitrary
/// JSONB into the export.
fn sanitize_context_memory_refs(value: JsonValue) -> Result<JsonValue> {
    let JsonValue::Array(entries) = value else {
        return Err(KgExportError::ForbiddenMaterial {
            path: "$.context_packet_records[].memory_refs".to_owned(),
            reason: "memory_refs must be an array".to_owned(),
        });
    };
    let mut sanitized = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let JsonValue::Object(fields) = entry else {
            return Err(KgExportError::ForbiddenMaterial {
                path: format!("$.context_packet_records[].memory_refs[{index}]"),
                reason: "memory_refs entries must be objects".to_owned(),
            });
        };
        let mut rebuilt = serde_json::Map::new();
        for key in ["memory_id", "latest_receipt_hash"] {
            if let Some(JsonValue::String(field)) = fields.get(key) {
                rebuilt.insert(key.to_owned(), JsonValue::String(field.clone()));
            }
        }
        sanitized.push(JsonValue::Object(rebuilt));
    }
    Ok(JsonValue::Array(sanitized))
}

fn memory_allowed(scope: &KgExportScope, memory_id: &str) -> bool {
    scope.included_memory_ids.is_empty()
        || scope
            .included_memory_ids
            .iter()
            .any(|included| included == memory_id)
}

fn graph_style_allowed(scope: &KgExportScope, graph_style: &str) -> bool {
    scope.included_graph_styles.is_empty()
        || scope
            .included_graph_styles
            .iter()
            .any(|included| included == graph_style)
}

fn idempotency_allowed(scope: &KgExportScope, idempotency_key: &str) -> bool {
    scope.included_writeback_idempotency_keys.is_empty()
        || scope
            .included_writeback_idempotency_keys
            .iter()
            .any(|included| included == idempotency_key)
}

fn pg(source: sqlx::Error) -> KgExportError {
    KgExportError::Postgres {
        source: Box::new(source),
    }
}

fn json_error(error: serde_json::Error) -> KgExportError {
    KgExportError::Json {
        reason: error.to_string(),
    }
}

/// Decode a cached idempotency response, failing closed with a stable typed
/// error when the stored row predates (or otherwise mismatches) the current
/// summary schema instead of surfacing a raw serde error.
fn decode_cached_replay_summary<T: DeserializeOwned>(
    body: JsonValue,
    route_name: &str,
    expected_schema: &str,
) -> Result<T> {
    let cached_schema = body
        .get("schema_version")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    if cached_schema != expected_schema {
        return Err(KgExportError::IncompatibleCachedResponse {
            route_name: route_name.to_owned(),
            reason: format!(
                "cached schema_version {cached_schema:?} does not match expected {expected_schema}"
            ),
        });
    }
    serde_json::from_value(body).map_err(|error| KgExportError::IncompatibleCachedResponse {
        route_name: route_name.to_owned(),
        reason: format!("cached response body does not match the current summary shape: {error}"),
    })
}

#[cfg(test)]
mod legacy_export_warning_alias_tests {
    use serde_json::json;

    use super::*;
    use crate::kg_export::reject_forbidden_export_json;

    const FORBIDDEN_WARNING_FRAGMENTS: &[&str] = &["raw_payload", "raw_markdown", "source_path"];

    fn assert_warning_labels_exclude_forbidden_fragments(warnings: &[String]) {
        for warning in warnings {
            for fragment in FORBIDDEN_WARNING_FRAGMENTS {
                assert!(
                    !warning.contains(fragment),
                    "warning {warning:?} still contains forbidden fragment {fragment}"
                );
            }
        }
    }

    #[test]
    fn legacy_export_warning_aliases_normalize_to_safe_labels() {
        let normalized = normalize_export_warning_summaries([
            "raw_payload_not_persisted".to_owned(),
            "source_path_not_persisted".to_owned(),
            "payload_content_not_exported".to_owned(),
        ]);
        assert_eq!(
            normalized,
            vec![
                "origin_path_not_persisted".to_owned(),
                "payload_content_not_exported".to_owned(),
            ]
        );
        assert_warning_labels_exclude_forbidden_fragments(&normalized);
        reject_forbidden_export_json(&json!(normalized), "$.legacy_export_warning_alias_test")
            .expect("normalized warning labels must pass export forbidden scan");
    }

    #[test]
    fn sanitize_warning_values_normalizes_legacy_labels_on_read_path() {
        let sanitized = sanitize_warning_values(Some(&json!([
            "raw_payload_not_persisted",
            "source_path_not_persisted",
            "repository_level_outbox_metadata_only"
        ])));
        let warnings: Vec<String> = sanitized
            .as_array()
            .expect("warning array")
            .iter()
            .filter_map(JsonValue::as_str)
            .map(str::to_owned)
            .collect();
        assert!(warnings.iter().any(|w| w == "payload_content_not_exported"));
        assert!(warnings.iter().any(|w| w == "origin_path_not_persisted"));
        assert!(!warnings.iter().any(|w| w == "raw_payload_not_persisted"));
        assert!(!warnings.iter().any(|w| w == "source_path_not_persisted"));
        assert_warning_labels_exclude_forbidden_fragments(&warnings);
        reject_forbidden_export_json(&sanitized, "$.warning_summaries")
            .expect("sanitized legacy warnings must pass export forbidden scan");
    }
}

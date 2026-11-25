#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{process, str::FromStr};

use exo_core::{Hash256, Timestamp};
use exo_dag::store::{DagStore, MemoryStore};
use exo_dag_db_api::{ReceiptEventType, SubjectKind};
use exo_dag_db_postgres::{
    outbox::{
        DagWriteMode, OutboxEnqueueRequest, OutboxError, OutboxProcessResult, enqueue_outbox,
        operator_retry_compensated_row, process_next_due_outbox, process_outbox_by_id,
        reconstruct_subject_receipts_after_recovery, subject_has_committed_finality,
        subject_is_context_eligible, subject_is_route_eligible,
    },
    postgres::{
        DAGDB_EXPORT_SCHEMA_SQL, DAGDB_GRAPH_SCHEMA_SQL, DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL,
        DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL, DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL, DAGDB_SCHEMA_SQL,
        DAGDB_TENANT_RLS_SCHEMA_SQL, begin_tenant_transaction,
    },
    receipt::{ReceiptAppendRequest, append_receipt},
};
use serde_json::json;
use sqlx::{
    Connection, PgConnection, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};

#[tokio::test]
async fn pending_outbox_subject_is_invisible_to_route_and_context() {
    let Some(db) = TestDb::maybe_new("outbox_pending_invisible").await else {
        return;
    };
    let subject_id = h(0x21);
    seed_memory_subject(&db.pool, subject_id, h(0x61))
        .await
        .expect("seed pending memory subject");
    let created = enqueue_outbox(&db.pool, &outbox_request(subject_id, h(0xa1), h(0xb1)))
        .await
        .expect("enqueue pending outbox");
    assert!(created);

    assert!(
        !subject_is_route_eligible(
            &db.pool,
            "tenant-a",
            "default",
            SubjectKind::Memory,
            subject_id
        )
        .await
        .expect("route eligibility check")
    );
    assert!(
        !subject_is_context_eligible(
            &db.pool,
            "tenant-a",
            "default",
            SubjectKind::Memory,
            subject_id,
        )
        .await
        .expect("context eligibility check")
    );
}

#[tokio::test]
async fn postgres_success_plus_dag_failure_retries_and_recovers() {
    let Some(db) = TestDb::maybe_new("outbox_retry_recover").await else {
        return;
    };
    let subject_id = h(0x22);
    let outbox_id = h(0xa2);
    seed_memory_subject(&db.pool, subject_id, h(0x62))
        .await
        .expect("seed memory subject");
    enqueue_outbox(&db.pool, &outbox_request(subject_id, outbox_id, h(0xb2)))
        .await
        .expect("enqueue outbox");

    let mut store = MemoryStore::new();
    let now = Timestamp::new(10_000, 0);
    let failed = process_outbox_by_id(
        &db.pool,
        "tenant-a",
        &mut store,
        outbox_id,
        now,
        "did:exo:outbox-worker",
        DagWriteMode::FailBeforeDagWrite {
            error_code: "dag_unavailable".to_owned(),
        },
    )
    .await
    .expect("record retryable DAG failure");
    assert_eq!(
        failed,
        OutboxProcessResult::ScheduledRetry {
            outbox_id,
            attempt_count: 1,
            next_attempt_at: Timestamp::new(11_000, 0),
        }
    );
    let snapshot = outbox_snapshot(&db.pool, outbox_id).await;
    assert_eq!(snapshot.status, "failed");
    assert_eq!(snapshot.attempt_count, 1);
    assert_eq!(snapshot.next_attempt_at, Some(Timestamp::new(11_000, 0)));
    assert_eq!(
        subject_finality_status(&db.pool, subject_id).await,
        "failed"
    );
    assert!(
        process_next_due_outbox(
            &db.pool,
            "tenant-a",
            &mut store,
            now,
            "did:exo:outbox-worker"
        )
        .await
        .expect("no due row before backoff")
        .is_none()
    );

    let committed = process_next_due_outbox(
        &db.pool,
        "tenant-a",
        &mut store,
        Timestamp::new(11_000, 0),
        "did:exo:outbox-worker",
    )
    .await
    .expect("retry due row")
    .expect("due outbox row");
    assert!(matches!(
        committed,
        OutboxProcessResult::Committed {
            outbox_id: committed_id,
            ..
        } if committed_id == outbox_id
    ));
    assert_eq!(
        outbox_snapshot(&db.pool, outbox_id).await.status,
        "committed"
    );
    assert_eq!(
        subject_finality_status(&db.pool, subject_id).await,
        "committed"
    );
    assert!(
        subject_is_route_eligible(
            &db.pool,
            "tenant-a",
            "default",
            SubjectKind::Memory,
            subject_id
        )
        .await
        .expect("committed subject is route eligible")
    );

    let chain = reconstruct_subject_receipts_after_recovery(
        &db.pool,
        "tenant-a",
        "default",
        SubjectKind::Memory,
        subject_id,
    )
    .await
    .expect("reconstruct recovered receipt chain");
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].prev_receipt_hash, Hash256::ZERO);
    assert_eq!(chain[2].seq, 3);
}

#[tokio::test]
async fn dag_success_plus_postgres_update_failure_recovers_to_committed() {
    let Some(db) = TestDb::maybe_new("outbox_pg_update_recover").await else {
        return;
    };
    let subject_id = h(0x23);
    let outbox_id = h(0xa3);
    seed_memory_subject(&db.pool, subject_id, h(0x63))
        .await
        .expect("seed memory subject");
    enqueue_outbox(&db.pool, &outbox_request(subject_id, outbox_id, h(0xb3)))
        .await
        .expect("enqueue outbox");

    let mut store = MemoryStore::new();
    let err = process_outbox_by_id(
        &db.pool,
        "tenant-a",
        &mut store,
        outbox_id,
        Timestamp::new(20_000, 0),
        "did:exo:outbox-worker",
        DagWriteMode::FailAfterDagCommit,
    )
    .await
    .expect_err("postgres update failure is surfaced after DAG commit");
    assert!(matches!(
        err,
        OutboxError::PostgresUpdateFailedAfterDagCommit
    ));
    assert_eq!(outbox_snapshot(&db.pool, outbox_id).await.status, "pending");
    assert_eq!(
        subject_finality_status(&db.pool, subject_id).await,
        "pending"
    );
    assert_eq!(store.committed_height().await.expect("committed height"), 1);

    let recovered = process_outbox_by_id(
        &db.pool,
        "tenant-a",
        &mut store,
        outbox_id,
        Timestamp::new(20_001, 0),
        "did:exo:outbox-worker",
        DagWriteMode::Normal,
    )
    .await
    .expect("retry idempotent DAG result into Postgres");
    assert!(matches!(recovered, OutboxProcessResult::Committed { .. }));
    assert_eq!(store.committed_height().await.expect("height unchanged"), 1);
    assert_eq!(
        outbox_snapshot(&db.pool, outbox_id).await.status,
        "committed"
    );
    assert_eq!(
        subject_finality_status(&db.pool, subject_id).await,
        "committed"
    );

    let chain = reconstruct_subject_receipts_after_recovery(
        &db.pool,
        "tenant-a",
        "default",
        SubjectKind::Memory,
        subject_id,
    )
    .await
    .expect("reconstruct chain after pg recovery");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].seq, 2);
}

#[tokio::test]
async fn max_retry_terminal_failure_compensates_and_blocks_operator_mutation() {
    let Some(db) = TestDb::maybe_new("outbox_compensated").await else {
        return;
    };
    let subject_id = h(0x24);
    let outbox_id = h(0xa4);
    seed_memory_subject(&db.pool, subject_id, h(0x64))
        .await
        .expect("seed memory subject");
    enqueue_outbox(&db.pool, &outbox_request(subject_id, outbox_id, h(0xb4)))
        .await
        .expect("enqueue outbox");
    sqlx::query(
        "UPDATE dagdb_dag_outbox \
         SET dag_finality_status = 'failed', attempt_count = 5, \
             next_attempt_at_physical_ms = 30_000, next_attempt_at_logical = 0 \
         WHERE outbox_id = $1",
    )
    .bind(hb(outbox_id))
    .execute(&db.pool)
    .await
    .expect("prime final retry state");

    let mut store = MemoryStore::new();
    let compensated = process_outbox_by_id(
        &db.pool,
        "tenant-a",
        &mut store,
        outbox_id,
        Timestamp::new(30_000, 0),
        "did:exo:outbox-worker",
        DagWriteMode::FailBeforeDagWrite {
            error_code: "dag_terminal".to_owned(),
        },
    )
    .await
    .expect("terminal failure compensates");
    let compensation_receipt_hash = match compensated {
        OutboxProcessResult::Compensated {
            compensation_receipt_hash,
            ..
        } => compensation_receipt_hash,
        other => panic!("unexpected compensation result: {other:?}"),
    };

    let snapshot = outbox_snapshot(&db.pool, outbox_id).await;
    assert_eq!(snapshot.status, "compensated");
    assert_eq!(snapshot.attempt_count, 6);
    assert_eq!(
        snapshot.compensation_receipt_hash,
        Some(compensation_receipt_hash)
    );
    assert_eq!(
        subject_finality_status(&db.pool, subject_id).await,
        "compensated"
    );
    assert!(matches!(
        operator_retry_compensated_row(&db.pool, "tenant-a", outbox_id).await,
        Err(OutboxError::CompensatedRowsAreTerminal)
    ));
    assert!(
        !subject_is_context_eligible(
            &db.pool,
            "tenant-a",
            "default",
            SubjectKind::Memory,
            subject_id,
        )
        .await
        .expect("compensated subject is context ineligible")
    );

    let chain = reconstruct_subject_receipts_after_recovery(
        &db.pool,
        "tenant-a",
        "default",
        SubjectKind::Memory,
        subject_id,
    )
    .await
    .expect("reconstruct compensated chain");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].receipt_hash, compensation_receipt_hash);
}

#[tokio::test]
async fn duplicate_enqueue_missing_subject_and_terminal_replay_fail_closed() {
    let Some(db) = TestDb::maybe_new("outbox_terminal_replay").await else {
        return;
    };
    let subject_id = h(0x25);
    let outbox_id = h(0xa5);
    let request = outbox_request(subject_id, outbox_id, h(0xb5));
    seed_memory_subject(&db.pool, subject_id, h(0x65))
        .await
        .expect("seed memory subject");
    assert!(
        enqueue_outbox(&db.pool, &request)
            .await
            .expect("first enqueue")
    );
    assert!(
        !enqueue_outbox(&db.pool, &request)
            .await
            .expect("duplicate enqueue is replay-safe")
    );
    assert!(
        !subject_is_route_eligible(
            &db.pool,
            "tenant-a",
            "default",
            SubjectKind::Memory,
            h(0xfe)
        )
        .await
        .expect("missing subjects are not eligible")
    );

    let mut store = MemoryStore::new();
    let committed = process_outbox_by_id(
        &db.pool,
        "tenant-a",
        &mut store,
        outbox_id,
        Timestamp::new(40_000, 0),
        "did:exo:outbox-worker",
        DagWriteMode::Normal,
    )
    .await
    .expect("commit outbox row");
    assert!(matches!(committed, OutboxProcessResult::Committed { .. }));
    assert!(
        operator_retry_compensated_row(&db.pool, "tenant-a", outbox_id)
            .await
            .is_ok()
    );
    assert_eq!(
        process_outbox_by_id(
            &db.pool,
            "tenant-a",
            &mut store,
            outbox_id,
            Timestamp::new(40_001, 0),
            "did:exo:outbox-worker",
            DagWriteMode::Normal,
        )
        .await
        .expect("terminal committed replay"),
        OutboxProcessResult::AlreadyTerminal {
            outbox_id,
            status: exo_dag_db_api::DagFinalityStatus::Committed,
        }
    );
    assert!(matches!(
        process_outbox_by_id(
            &db.pool,
            "tenant-a",
            &mut store,
            h(0xff),
            Timestamp::new(40_001, 0),
            "did:exo:outbox-worker",
            DagWriteMode::Normal,
        )
        .await,
        Err(OutboxError::OutboxNotFound)
    ));
}

#[tokio::test]
async fn concurrent_workers_claim_one_due_row_exactly_once() {
    let Some(db) = TestDb::maybe_new("outbox_double_claim").await else {
        return;
    };
    let subject_id = h(0x26);
    let outbox_id = h(0xa6);
    seed_memory_subject(&db.pool, subject_id, h(0x66))
        .await
        .expect("seed memory subject");
    enqueue_outbox(&db.pool, &outbox_request(subject_id, outbox_id, h(0xb6)))
        .await
        .expect("enqueue outbox");

    let now = Timestamp::new(60_000, 0);
    let pool_a = db.pool.clone();
    let mut store_a = MemoryStore::new();
    let mut store_b = MemoryStore::new();
    let (worker_a, worker_b) = tokio::join!(
        process_next_due_outbox(
            &pool_a,
            "tenant-a",
            &mut store_a,
            now,
            "did:exo:outbox-worker-a"
        ),
        process_next_due_outbox(
            &db.pool,
            "tenant-a",
            &mut store_b,
            now,
            "did:exo:outbox-worker-b"
        ),
    );
    let worker_a = worker_a.expect("worker a result");
    let worker_b = worker_b.expect("worker b result");
    let committed_count = [&worker_a, &worker_b]
        .iter()
        .filter(|result| matches!(result, Some(OutboxProcessResult::Committed { .. })))
        .count();
    assert_eq!(
        committed_count, 1,
        "exactly one worker must claim and commit the due row: {worker_a:?} / {worker_b:?}"
    );
    assert!(
        matches!((&worker_a, &worker_b), (Some(_), None) | (None, Some(_))),
        "the losing worker must observe no due row: {worker_a:?} / {worker_b:?}"
    );

    let snapshot = outbox_snapshot(&db.pool, outbox_id).await;
    assert_eq!(snapshot.status, "committed");
    assert_eq!(snapshot.attempt_count, 0);

    let chain = reconstruct_subject_receipts_after_recovery(
        &db.pool,
        "tenant-a",
        "default",
        SubjectKind::Memory,
        subject_id,
    )
    .await
    .expect("reconstruct double-claim receipt chain");
    assert_eq!(
        chain.len(),
        2,
        "exactly one committed finality receipt must exist after genesis"
    );
}

#[tokio::test]
async fn forced_rls_scopes_due_outbox_claims_to_bound_tenant() {
    let Some(db) = TestDb::maybe_new("outbox_rls_scope").await else {
        return;
    };
    let subject_id = h(0x29);
    let outbox_id = h(0xa9);
    seed_memory_subject(&db.pool, subject_id, h(0x69))
        .await
        .expect("seed memory subject before RLS");
    apply_tenant_rls_schema(&db.pool).await;
    let rls_pool = RlsCheckedPool::new(&db).await;
    enqueue_outbox(
        &rls_pool.pool,
        &outbox_request(subject_id, outbox_id, h(0xb9)),
    )
    .await
    .expect("tenant-bound enqueue under RLS");

    assert!(
        unbound_outbox_claim(&rls_pool.pool, Timestamp::new(61_000, 0))
            .await
            .is_err(),
        "claiming without exo.tenant_id must error instead of idling"
    );

    let mut wrong_tenant_store = MemoryStore::new();
    assert!(matches!(
        process_outbox_by_id(
            &rls_pool.pool,
            "tenant-b",
            &mut wrong_tenant_store,
            outbox_id,
            Timestamp::new(61_001, 0),
            "did:exo:outbox-worker",
            DagWriteMode::Normal,
        )
        .await,
        Err(OutboxError::OutboxNotFound)
    ));
    assert!(
        process_next_due_outbox(
            &rls_pool.pool,
            "tenant-b",
            &mut wrong_tenant_store,
            Timestamp::new(61_002, 0),
            "did:exo:outbox-worker"
        )
        .await
        .expect("wrong tenant claim is isolated")
        .is_none()
    );
    assert_eq!(
        outbox_snapshot(&rls_pool.pool, outbox_id).await.status,
        "pending"
    );

    let mut store = MemoryStore::new();
    let committed = process_next_due_outbox(
        &rls_pool.pool,
        "tenant-a",
        &mut store,
        Timestamp::new(61_003, 0),
        "did:exo:outbox-worker",
    )
    .await
    .expect("tenant-bound claim succeeds")
    .expect("due tenant-a row");
    assert!(matches!(
        committed,
        OutboxProcessResult::Committed {
            outbox_id: committed_id,
            ..
        } if committed_id == outbox_id
    ));
    assert_eq!(
        outbox_snapshot(&rls_pool.pool, outbox_id).await.status,
        "committed"
    );
    rls_pool.cleanup(&db.pool).await;
}

#[tokio::test]
async fn export_outbox_rows_are_skipped_by_generic_finality_worker() {
    let Some(db) = TestDb::maybe_new("outbox_export_skip").await else {
        return;
    };
    sqlx::raw_sql(exo_dag_db_postgres::postgres::DAGDB_EXPORT_FINALITY_OUTBOX_SCHEMA_SQL)
        .execute(&db.pool)
        .await
        .expect("apply export finality outbox schema");
    insert_export_outbox_row(&db.pool, h(0xa7), h(0x27))
        .await
        .expect("insert export outbox row");

    let mut store = MemoryStore::new();
    let now = Timestamp::new(70_000, 0);
    assert!(
        process_next_due_outbox(
            &db.pool,
            "tenant-a",
            &mut store,
            now,
            "did:exo:outbox-worker"
        )
        .await
        .expect("export rows belong to the export finality path, not the generic worker")
        .is_none()
    );
    assert_eq!(outbox_snapshot(&db.pool, h(0xa7)).await.status, "pending");

    let subject_id = h(0x28);
    let memory_outbox_id = h(0xa8);
    seed_memory_subject(&db.pool, subject_id, h(0x68))
        .await
        .expect("seed memory subject");
    enqueue_outbox(
        &db.pool,
        &outbox_request(subject_id, memory_outbox_id, h(0xb8)),
    )
    .await
    .expect("enqueue memory outbox");
    let committed = process_next_due_outbox(
        &db.pool,
        "tenant-a",
        &mut store,
        Timestamp::new(70_001, 0),
        "did:exo:outbox-worker",
    )
    .await
    .expect("export row must not poison the worker queue")
    .expect("due memory row");
    assert!(matches!(
        committed,
        OutboxProcessResult::Committed {
            outbox_id: committed_id,
            ..
        } if committed_id == memory_outbox_id
    ));
}

#[tokio::test]
async fn catalog_route_and_context_finality_updates_are_committed() {
    let Some(db) = TestDb::maybe_new("outbox_other_subjects").await else {
        return;
    };
    let catalog_id = h(0x31);
    let route_id = h(0x32);
    let context_packet_id = h(0x33);
    seed_catalog_subject(&db.pool, catalog_id, h(0x71))
        .await
        .expect("seed catalog subject");
    seed_route_subject(&db.pool, route_id, h(0x72))
        .await
        .expect("seed route subject");
    seed_context_subject(&db.pool, context_packet_id, route_id, h(0x73))
        .await
        .expect("seed context subject");

    let subjects = [
        (SubjectKind::Catalog, catalog_id, h(0xc1), h(0xd1)),
        (SubjectKind::Route, route_id, h(0xc2), h(0xd2)),
        (
            SubjectKind::ContextPacket,
            context_packet_id,
            h(0xc3),
            h(0xd3),
        ),
    ];
    let mut store = MemoryStore::new();
    for (index, (kind, subject_id, outbox_id, payload_hash)) in subjects.into_iter().enumerate() {
        let mut request = outbox_request(subject_id, outbox_id, payload_hash);
        request.subject_kind = kind;
        enqueue_outbox(&db.pool, &request)
            .await
            .expect("enqueue non-memory outbox");
        process_outbox_by_id(
            &db.pool,
            "tenant-a",
            &mut store,
            outbox_id,
            Timestamp::new(50_000 + u64::try_from(index).expect("small index"), 0),
            "did:exo:outbox-worker",
            DagWriteMode::Normal,
        )
        .await
        .expect("commit non-memory outbox");
        assert!(
            subject_has_committed_finality(&db.pool, "tenant-a", "default", kind, subject_id)
                .await
                .expect("subject committed finality")
        );
    }
}

async fn seed_memory_subject(
    pool: &PgPool,
    subject_id: Hash256,
    genesis_hash: Hash256,
) -> sqlx::Result<()> {
    let receipt = append_receipt(
        pool,
        &ReceiptAppendRequest {
            tenant_id: "tenant-a".to_owned(),
            namespace: "default".to_owned(),
            subject_kind: SubjectKind::Memory,
            subject_id,
            expected_prev_receipt_hash: Hash256::ZERO,
            event_type: ReceiptEventType::IntakeCreated,
            actor_did: "did:exo:intake".to_owned(),
            event_hlc: Timestamp::new(1_000, subject_id.as_bytes()[0].into()),
            event_body_hash: genesis_hash,
            receipt_body: json!({"event": "intake_created"}),
        },
    )
    .await
    .expect("append genesis receipt");
    let metadata = json!({
        "decision": "allow",
        "text": "safe",
        "redaction_codes": [],
        "original_hash": "caac13844969e521bb8bfcf8bc706ad54bcce3e3f260368eda31bdb0542d00e1",
        "truncated": false,
        "byte_len": 4
    });
    sqlx::query(
        "INSERT INTO dagdb_memory_objects \
         (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, payload_hash, source_hash, \
          owner_did, controller_did, submitted_by_did, title, summary, keywords, risk_class, risk_bp, status, \
          validation_status, council_status, latest_receipt_hash, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'source', 'public_web', 'retrieval', $2, $3, \
                 'did:example:owner', 'did:example:controller', 'did:example:submitter', $4, $4, '[]'::jsonb, \
                 'R0', 0, 'routable', 'passed', 'not_required', $5, 1, 0, 1, 0)",
    )
    .bind(hb(subject_id))
    .bind(hb(h(0xd1)))
    .bind(hb(h(0xd2)))
    .bind(metadata)
    .bind(hb(receipt.receipt_hash))
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_catalog_subject(
    pool: &PgPool,
    subject_id: Hash256,
    genesis_hash: Hash256,
) -> sqlx::Result<()> {
    let receipt =
        append_genesis_receipt(pool, SubjectKind::Catalog, subject_id, genesis_hash).await;
    let metadata = safe_metadata();
    sqlx::query(
        "INSERT INTO dagdb_catalog_entries \
         (catalog_id, tenant_id, namespace, catalog_level, title, summary, keywords, payload_hash, source_hash, \
          status, validation_status, council_status, latest_receipt_hash, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 0, $2, $2, '[]'::jsonb, $3, $4, \
                 'routable', 'passed', 'not_required', $5, 1, 0, 1, 0)",
    )
    .bind(hb(subject_id))
    .bind(metadata)
    .bind(hb(h(0xe1)))
    .bind(hb(h(0xe2)))
    .bind(hb(receipt.receipt_hash))
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_route_subject(
    pool: &PgPool,
    subject_id: Hash256,
    genesis_hash: Hash256,
) -> sqlx::Result<()> {
    let receipt = append_genesis_receipt(pool, SubjectKind::Route, subject_id, genesis_hash).await;
    sqlx::query(
        "INSERT INTO dagdb_route_receipts \
         (route_id, tenant_id, namespace, requesting_agent_did, task_signature_hash, approved_scope_hash, \
          candidate_memory_ids, selected_memory_ids, route_score_bp, token_budget, token_estimate, risk_bp, \
          status, validation_status, council_status, stale_at_physical_ms, stale_at_logical, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'did:example:agent', $2, $3, '[]'::jsonb, '[]'::jsonb, \
                 9000, 4096, 256, 0, 'active', 'passed', 'not_required', 90_000, 0, $4, 1, 0)",
    )
    .bind(hb(subject_id))
    .bind(hb(h(0xe3)))
    .bind(hb(h(0xe4)))
    .bind(hb(receipt.receipt_hash))
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_context_subject(
    pool: &PgPool,
    subject_id: Hash256,
    route_id: Hash256,
    genesis_hash: Hash256,
) -> sqlx::Result<()> {
    let receipt =
        append_genesis_receipt(pool, SubjectKind::ContextPacket, subject_id, genesis_hash).await;
    sqlx::query(
        "INSERT INTO dagdb_context_packets \
         (context_packet_id, tenant_id, namespace, request_id, route_id, task_hash, requesting_agent_did, \
          memory_refs, packet_hash, token_budget, token_estimate, validation_status, council_status, \
          latest_receipt_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'request-1', $2, $3, 'did:example:agent', \
                 '[]'::jsonb, $4, 4096, 256, 'passed', 'not_required', $5, 1, 0)",
    )
    .bind(hb(subject_id))
    .bind(hb(route_id))
    .bind(hb(h(0xe5)))
    .bind(hb(h(0xe6)))
    .bind(hb(receipt.receipt_hash))
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_export_outbox_row(
    pool: &PgPool,
    outbox_id: Hash256,
    subject_id: Hash256,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO dagdb_dag_outbox \
         (outbox_id, tenant_id, namespace, subject_kind, subject_id, dag_write_id, dag_payload_hash, \
          dag_finality_status, created_at_physical_ms, created_at_logical, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, 'tenant-a', 'default', 'export', $2, $3, $4, 'pending', 1, 0, 1, 0)",
    )
    .bind(hb(outbox_id))
    .bind(hb(subject_id))
    .bind(format!("dagdb-export-finality-{outbox_id}"))
    .bind(hb(h(0xe7)))
    .execute(pool)
    .await?;
    Ok(())
}

async fn apply_tenant_rls_schema(pool: &PgPool) {
    sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
        .execute(pool)
        .await
        .expect("apply DAG DB graph schema");
    sqlx::raw_sql(DAGDB_EXPORT_SCHEMA_SQL)
        .execute(pool)
        .await
        .expect("apply DAG DB export schema");
    sqlx::raw_sql(DAGDB_PRD17_DEFAULT_ROUTE_SCHEMA_SQL)
        .execute(pool)
        .await
        .expect("apply PRD17 default-route schema");
    sqlx::raw_sql(DAGDB_PRD17_CONTEXT_PACKET_SCHEMA_SQL)
        .execute(pool)
        .await
        .expect("apply PRD17 context-packet schema");
    sqlx::raw_sql(DAGDB_PRD17_LIFECYCLE_SCHEMA_SQL)
        .execute(pool)
        .await
        .expect("apply PRD17 lifecycle schema");
    sqlx::raw_sql(DAGDB_TENANT_RLS_SCHEMA_SQL)
        .execute(pool)
        .await
        .expect("apply DAG DB tenant RLS schema");
}

async fn unbound_outbox_claim(
    pool: &PgPool,
    now: Timestamp,
) -> std::result::Result<Option<Vec<u8>>, sqlx::Error> {
    let lease_until_physical_ms = now
        .physical_ms
        .checked_add(30_000)
        .expect("fixture lease timestamp");
    sqlx::query_scalar::<_, Vec<u8>>(
        "UPDATE dagdb_dag_outbox \
         SET next_attempt_at_physical_ms = $3, next_attempt_at_logical = $2, \
             updated_at_physical_ms = $1, updated_at_logical = $2 \
         WHERE outbox_id = ( \
             SELECT outbox_id FROM dagdb_dag_outbox \
             WHERE dag_finality_status IN ('pending','failed') \
               AND attempt_count < max_attempts \
             ORDER BY next_attempt_at_physical_ms ASC NULLS FIRST, next_attempt_at_logical ASC NULLS FIRST, attempt_count ASC \
             LIMIT 1 \
             FOR UPDATE SKIP LOCKED) \
         RETURNING outbox_id",
    )
    .bind(i64::try_from(now.physical_ms).expect("fixture timestamp range"))
    .bind(i32::try_from(now.logical).expect("fixture logical range"))
    .bind(i64::try_from(lease_until_physical_ms).expect("fixture lease range"))
    .fetch_optional(pool)
    .await
}

async fn append_genesis_receipt(
    pool: &PgPool,
    subject_kind: SubjectKind,
    subject_id: Hash256,
    event_body_hash: Hash256,
) -> exo_dag_db_postgres::receipt::ReceiptAppendResult {
    append_receipt(
        pool,
        &ReceiptAppendRequest {
            tenant_id: "tenant-a".to_owned(),
            namespace: "default".to_owned(),
            subject_kind,
            subject_id,
            expected_prev_receipt_hash: Hash256::ZERO,
            event_type: ReceiptEventType::IntakeCreated,
            actor_did: "did:exo:intake".to_owned(),
            event_hlc: Timestamp::new(1_000, subject_id.as_bytes()[0].into()),
            event_body_hash,
            receipt_body: json!({"event": "intake_created"}),
        },
    )
    .await
    .expect("append genesis receipt")
}

fn safe_metadata() -> serde_json::Value {
    json!({
        "decision": "allow",
        "text": "safe",
        "redaction_codes": [],
        "original_hash": "caac13844969e521bb8bfcf8bc706ad54bcce3e3f260368eda31bdb0542d00e1",
        "truncated": false,
        "byte_len": 4
    })
}

fn outbox_request(
    subject_id: Hash256,
    outbox_id: Hash256,
    payload_hash: Hash256,
) -> OutboxEnqueueRequest {
    OutboxEnqueueRequest {
        outbox_id,
        tenant_id: "tenant-a".to_owned(),
        namespace: "default".to_owned(),
        subject_kind: SubjectKind::Memory,
        subject_id,
        dag_write_id: format!("dag-write-{outbox_id}"),
        dag_payload_hash: payload_hash,
        created_at: Timestamp::new(2_000 + u64::from(outbox_id.as_bytes()[0]), 0),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct OutboxSnapshot {
    status: String,
    attempt_count: i32,
    next_attempt_at: Option<Timestamp>,
    compensation_receipt_hash: Option<Hash256>,
}

async fn outbox_snapshot(pool: &PgPool, outbox_id: Hash256) -> OutboxSnapshot {
    let mut tx = begin_tenant_transaction(pool, "tenant-a")
        .await
        .expect("begin tenant-bound outbox snapshot");
    let row = sqlx::query(
        "SELECT dag_finality_status, attempt_count, next_attempt_at_physical_ms, next_attempt_at_logical, compensation_receipt_hash \
         FROM dagdb_dag_outbox WHERE tenant_id = 'tenant-a' AND outbox_id = $1",
    )
    .bind(hb(outbox_id))
    .fetch_one(&mut *tx)
    .await
    .expect("load outbox snapshot");
    tx.commit().await.expect("commit outbox snapshot");
    let next_physical: Option<i64> = row
        .try_get("next_attempt_at_physical_ms")
        .expect("next physical");
    let next_logical: Option<i32> = row
        .try_get("next_attempt_at_logical")
        .expect("next logical");
    let next_attempt_at = match (next_physical, next_logical) {
        (Some(physical), Some(logical)) => Some(Timestamp::new(
            u64::try_from(physical).expect("non-negative physical"),
            u32::try_from(logical).expect("non-negative logical"),
        )),
        _ => None,
    };
    let compensation: Option<Vec<u8>> = row
        .try_get("compensation_receipt_hash")
        .expect("compensation hash");
    OutboxSnapshot {
        status: row.try_get("dag_finality_status").expect("status"),
        attempt_count: row.try_get("attempt_count").expect("attempt count"),
        next_attempt_at,
        compensation_receipt_hash: compensation.map(hash_from_vec),
    }
}

async fn subject_finality_status(pool: &PgPool, subject_id: Hash256) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT dag_finality_status FROM dagdb_memory_objects WHERE memory_id = $1",
    )
    .bind(hb(subject_id))
    .fetch_one(pool)
    .await
    .expect("load subject finality")
}

fn h(byte: u8) -> Hash256 {
    Hash256::from_bytes([byte; 32])
}

fn hb(hash: Hash256) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

fn hash_from_vec(bytes: Vec<u8>) -> Hash256 {
    Hash256::from_bytes(bytes.try_into().expect("fixture hash length"))
}

struct TestDb {
    pool: PgPool,
    schema: String,
    database_url: String,
}

const RLS_TEST_ROLE_PASSWORD: &str = "dagdb_rls_test_password";

struct RlsCheckedPool {
    pool: PgPool,
    role_name: Option<String>,
}

impl RlsCheckedPool {
    async fn new(db: &TestDb) -> Self {
        if !pool_role_bypasses_rls(&db.pool).await {
            return Self {
                pool: db.pool.clone(),
                role_name: None,
            };
        }

        let role_name = format!("dagdb_rls_pool_{}", process::id());
        drop_rls_role_if_exists(&db.pool, &role_name).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {role_name} LOGIN PASSWORD '{RLS_TEST_ROLE_PASSWORD}'"
        )))
        .execute(&db.pool)
        .await
        .expect("create RLS checked pool role");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT USAGE ON SCHEMA {} TO {role_name}",
            db.schema
        )))
        .execute(&db.pool)
        .await
        .expect("grant schema usage to RLS checked pool role");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {role_name}",
            db.schema
        )))
        .execute(&db.pool)
        .await
        .expect("grant table privileges to RLS checked pool role");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT EXECUTE ON FUNCTION {}.dagdb_current_tenant_id() TO {role_name}",
            db.schema
        )))
        .execute(&db.pool)
        .await
        .expect("grant tenant helper execution to RLS checked pool role");

        let options = PgConnectOptions::from_str(&db.database_url)
            .expect("parse RLS checked pool database URL")
            .username(&role_name)
            .password(RLS_TEST_ROLE_PASSWORD)
            .options([("search_path", format!("{},public", db.schema))]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect RLS checked pool");
        Self {
            pool,
            role_name: Some(role_name),
        }
    }

    async fn cleanup(self, admin_pool: &PgPool) {
        if let Some(role_name) = self.role_name {
            self.pool.close().await;
            drop_rls_role_if_exists(admin_pool, &role_name).await;
        }
    }
}

async fn pool_role_bypasses_rls(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        .fetch_one(pool)
        .await
        .expect("query pool role RLS bypass state")
}

async fn drop_rls_role_if_exists(pool: &PgPool, role_name: &str) {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(role_name)
            .fetch_one(pool)
            .await
            .expect("query RLS checked pool role existence");
    if !exists {
        return;
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role_name}")))
        .execute(pool)
        .await
        .expect("drop RLS checked pool role privileges");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE {role_name}")))
        .execute(pool)
        .await
        .expect("drop RLS checked pool role");
}

impl TestDb {
    async fn maybe_new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var("EXO_DAGDB_TEST_DATABASE_URL") else {
            eprintln!("skipping DAG outbox postgres test: EXO_DAGDB_TEST_DATABASE_URL is not set");
            return None;
        };
        Some(Self::new_with_database_url(label, &database_url).await)
    }

    async fn new_with_database_url(label: &str, database_url: &str) -> Self {
        let schema = format!("dagdb_{label}_{}", process::id());
        let mut admin = PgConnection::connect(database_url)
            .await
            .expect("connect to EXO_DAGDB_TEST_DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(&mut admin)
        .await
        .expect("drop existing outbox test schema");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&mut admin)
            .await
            .expect("create outbox test schema");

        let scoped_url = database_url_with_search_path(database_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&scoped_url)
            .await
            .expect("connect outbox test pool");
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB schema");
        Self {
            pool,
            schema,
            database_url: database_url.to_owned(),
        }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let schema = self.schema.clone();
        let database_url = self.database_url.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("create cleanup runtime");
            runtime.block_on(async move {
                let mut conn = PgConnection::connect(&database_url)
                    .await
                    .expect("connect for outbox cleanup");
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP SCHEMA IF EXISTS {schema} CASCADE"
                )))
                .execute(&mut conn)
                .await
                .expect("drop outbox test schema");
            });
        })
        .join()
        .expect("join cleanup thread");
    }
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

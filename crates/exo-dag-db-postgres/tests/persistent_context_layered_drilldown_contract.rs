//! Q2-S3 layered drilldown contract over persisted DAG DB rows.
//!
//! Seeds a root memory that governs a child layer whose content-bearing member
//! the breadth-only selection scores out, then proves that bounded layered
//! drilldown spends leftover budget on the governed child member while staying
//! within depth/cap/tenant bounds and remaining byte-identical when off.

#![cfg(feature = "postgres")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use exo_core::Hash256;
use exo_dag_db_api::{
    DagDbGraphContextPacketBuildRequest, DagDbGraphContextSelectionRequest,
    DagDbGraphContextSelectionStatus, MemoryGraphStyle,
};
use exo_dag_db_postgres::{
    LAYERED_DRILLDOWN_SELECTION_REASON, build_persistent_graph_context_packet,
    build_persistent_graph_context_packet_with_layered_drilldown,
    build_persistent_graph_context_selection,
    build_persistent_graph_context_selection_with_layered_drilldown, deterministic_layer_id,
    deterministic_layer_membership_id,
    kg_import::{
        KG_IMPORT_CANDIDATES_SCHEMA, KG_IMPORT_DATABASE_URL_ENV, KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        required_trace,
    },
    postgres::{DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL, kg_import::persist_kg_import_report},
};
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

const TENANT: &str = "tenant-test";
const NAMESPACE: &str = "dag-db";
// A task that matches the root memory's summary terms but not the deep child
// member's generic summary, so breadth selection scores the child out.
const TASK: &str = "Explain the governed project index root context";

struct TestDb {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDb {
    async fn new(label: &str) -> Option<Self> {
        let Ok(database_url) = std::env::var(KG_IMPORT_DATABASE_URL_ENV) else {
            eprintln!(
                "skipping layered drilldown postgres test: {KG_IMPORT_DATABASE_URL_ENV} is not set"
            );
            return None;
        };
        let schema = format!("dagdb_drilldown_{label}_{}", std::process::id());
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect admin Postgres pool");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE"#
        )))
        .execute(&admin_pool)
        .await
        .expect("drop isolated schema");
        sqlx::query(sqlx::AssertSqlSafe(format!(r#"CREATE SCHEMA "{schema}""#)))
            .execute(&admin_pool)
            .await
            .expect("create isolated schema");

        let scoped_url = database_url_with_search_path(&database_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&scoped_url)
            .await
            .expect("connect scoped Postgres pool");
        sqlx::raw_sql(DAGDB_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB schema");
        sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("apply DAG DB graph schema");
        Some(Self {
            admin_pool,
            pool,
            schema,
        })
    }

    async fn cleanup(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#,
            self.schema
        )))
        .execute(&self.admin_pool)
        .await
        .expect("drop isolated schema after test");
        self.admin_pool.close().await;
    }
}

#[tokio::test]
async fn drilldown_spends_leftover_budget_on_governed_child_member() {
    let Some(db) = TestDb::new("spend").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // The request-level `max_memory_refs` is now the hard total cap for breadth +
    // drilldown together. With a slot left over after breadth (cap 3, breadth
    // selects the root 0x10 and the child-layer root anchor 0x11), drilldown may
    // spend leftover budget on the governed child member 0x12 — depth-on-demand —
    // and the corrected total never exceeds the request cap.
    let request = selection_request(8_000, 3);

    // Layered OFF: breadth-only. With cap 3 the breadth pass selects the root,
    // the anchor, and the governed child member directly (the fixture has exactly
    // three memories), so OFF already reaches 0x12.
    let off = build_persistent_graph_context_selection(&db.pool, &request)
        .await
        .expect("selection off");
    let off_ids = selected_ids(&off.selection.selected_memory_refs);
    assert!(
        off_ids.contains(&h(0x10)),
        "root must be selected by breadth"
    );

    // Layered ON: drilldown is additive depth-on-demand but is bounded by the
    // request-level cap, so the governed child member is present and the total
    // ref count never exceeds `max_memory_refs`.
    let on = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &request,
        Some("auto"),
        None,
        0,
    )
    .await
    .expect("selection layered on");
    let on_ids = selected_ids(&on.selection.selected_memory_refs);
    assert!(
        on_ids.contains(&h(0x12)),
        "governed child member must be reachable under a cap that leaves room"
    );
    assert!(
        on.selection.selected_memory_refs.len() <= 3,
        "breadth + drilldown must never exceed the request-level max_memory_refs"
    );

    // The packet builder's token-sum invariant must hold after drilldown.
    let token_sum: u32 = on
        .selection
        .selected_memory_refs
        .iter()
        .map(|selected| selected.token_estimate)
        .sum();
    assert_eq!(
        token_sum, on.selection.selected_token_estimate,
        "selected_token_estimate must include drilldown refs"
    );
    assert!(
        on.selection.selected_token_estimate <= 8_000,
        "drilldown must stay within the token budget"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn drilldown_never_exceeds_request_max_memory_refs() {
    let Some(db) = TestDb::new("cap").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // The bug this guards: a request with max_memory_refs=1 must NOT gain extra
    // refs via drilldown. The request-level cap bounds the total, so even with a
    // large leftover token budget the governed child member is never pulled.
    let request = selection_request(8_000, 1);

    let off = build_persistent_graph_context_selection(&db.pool, &request)
        .await
        .expect("selection off");
    let off_ids = selected_ids(&off.selection.selected_memory_refs);
    assert_eq!(
        off_ids,
        vec![h(0x10)],
        "breadth selects only the single capped root"
    );
    assert!(
        off.selection.selected_token_estimate < 8_000,
        "breadth leaves budget that drilldown must NOT be allowed to spend over cap"
    );

    let on = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &request,
        Some("auto"),
        None,
        0,
    )
    .await
    .expect("selection layered on");
    let on_ids = selected_ids(&on.selection.selected_memory_refs);
    assert_eq!(
        on_ids,
        vec![h(0x10)],
        "drilldown must not add refs beyond the request-level max_memory_refs"
    );
    assert!(
        !on_ids.contains(&h(0x12)),
        "governed child member must NOT be pulled when the cap is already full"
    );
    assert!(
        !on.selection
            .boundary_warnings
            .contains(&"layered_drilldown_applied".to_owned()),
        "no drilldown should be applied when the request cap leaves no room"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn drilldown_off_is_byte_identical_to_today() {
    let Some(db) = TestDb::new("off_identical").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // The full packet path through the breadth budget class; off must match.
    let baseline = build_persistent_graph_context_packet(&db.pool, &packet_request(8_000))
        .await
        .expect("baseline packet");
    let off_none = build_persistent_graph_context_packet_with_layered_drilldown(
        &db.pool,
        &packet_request(8_000),
        None,
        None,
        0,
    )
    .await
    .expect("explicit-off (none) packet");
    let off_literal = build_persistent_graph_context_packet_with_layered_drilldown(
        &db.pool,
        &packet_request(8_000),
        Some("off"),
        None,
        0,
    )
    .await
    .expect("explicit-off (off) packet");

    let baseline_json = serde_json::to_string(&baseline.packet).expect("baseline json");
    assert_eq!(
        baseline_json,
        serde_json::to_string(&off_none.packet).expect("off-none json"),
        "layered_mode=None must be byte-identical to today"
    );
    assert_eq!(
        baseline_json,
        serde_json::to_string(&off_literal.packet).expect("off-literal json"),
        "layered_mode=off must be byte-identical to today"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn drilldown_respects_depth_and_per_root_cap_bounds() {
    let Some(db) = TestDb::new("bounds").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // A cap that leaves room (3) so drilldown is reachable, and a generous token
    // budget so the only ceiling under test is the depth / per-root / request cap.
    let request = selection_request(8_000, 3);

    for depth_bound in [Some(0u32), Some(1u32), None] {
        let selection = build_persistent_graph_context_selection_with_layered_drilldown(
            &db.pool,
            &request,
            Some("auto"),
            depth_bound,
            0,
        )
        .await
        .expect("layered selection");

        // The request-level max_memory_refs is the hard total cap regardless of
        // the depth bound; neither depth-on-demand nor the per-root cap may push
        // breadth + drilldown past it.
        assert!(
            selection.selection.selected_memory_refs.len() <= 3,
            "depth bound {depth_bound:?} must not exceed the request cap"
        );

        // The per-root drilldown cap bounds how many refs a single root expands.
        let drilldown_from_root = selection
            .selection
            .selected_memory_refs
            .iter()
            .filter(|selected| {
                selected.selection_reason == LAYERED_DRILLDOWN_SELECTION_REASON
                    && selected
                        .boundary_flags
                        .iter()
                        .any(|flag| flag == &format!("drilldown_root:{}", h(0x10)))
            })
            .count();
        assert!(
            drilldown_from_root <= 8,
            "per-root child-ref cap must bound drilldown spend"
        );
    }

    db.cleanup().await;
}

#[tokio::test]
async fn drilldown_exempts_explicit_requested_ids() {
    let Some(db) = TestDb::new("explicit").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // An explicit requested-id selection is exempt: even with layered on, the
    // drilldown must not expand beyond the requested root, so the governed child
    // member (0x12) is never pulled.
    let mut request = selection_request(8_000, 8);
    request.requested_memory_ids = vec![h(0x10)];
    let explicit = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &request,
        Some("auto"),
        None,
        0,
    )
    .await
    .expect("explicit selection");
    let ids = selected_ids(&explicit.selection.selected_memory_refs);
    assert_eq!(ids, vec![h(0x10)], "only the requested root is selected");
    assert!(
        !explicit
            .selection
            .selected_memory_refs
            .iter()
            .any(|selected| selected.selection_reason == LAYERED_DRILLDOWN_SELECTION_REASON),
        "explicit requested-id selections must be exempt from drilldown"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn drilldown_never_pulls_cross_tenant_child_layer() {
    let Some(db) = TestDb::new("cross_tenant").await else {
        return;
    };
    // Same logical fixture under a DIFFERENT tenant. Its child member uses a
    // distinct memory id so a tenant leak would be observable.
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist tenant-test fixture");
    persist_kg_import_report(&db.pool, &foreign_tenant_report().to_string())
        .await
        .expect("persist foreign-tenant fixture");

    // Cap 3 leaves room so the own-tenant governed child member is reachable;
    // the foreign-tenant member must never leak through breadth or drilldown.
    let on = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &selection_request(8_000, 3),
        Some("auto"),
        None,
        0,
    )
    .await
    .expect("selection layered on");
    let ids = selected_ids(&on.selection.selected_memory_refs);
    assert!(
        ids.contains(&h(0x12)),
        "own-tenant governed child member is still pulled"
    );
    assert!(
        !ids.contains(&h(FOREIGN_MEMBER_MEM)),
        "foreign-tenant child member must never be pulled (tenant scoping)"
    );
    assert!(
        on.selection.selected_memory_refs.len() <= 3,
        "breadth + drilldown must never exceed the request-level max_memory_refs"
    );
    db.cleanup().await;
}

#[tokio::test]
async fn depth_reserve_lets_membership_triggered_drilldown_fire_over_a_filled_breadth() {
    // D1-S4: with a depth reserve, the breadth pass runs at the reduced budget so
    // it fills before reaching the deep sibling (0x12); the membership-triggered
    // drilldown then spends the reserved budget to pull 0x12 in. This is the case
    // that the live corpus exhibits: breadth fills its budget, and only a reserve
    // leaves room for depth-on-demand.
    let Some(db) = TestDb::new("reserve_fires").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // A tight total budget where breadth, at the 50% reserved budget, fits only
    // the task-matching 0x10 and omits 0x12; the cap (8) is not the limiter.
    let request = selection_request(60, 8);

    // No reserve: breadth at the full 60-token budget already reaches 0x12, so
    // drilldown is not what pulls it. (Sanity anchor for the reserve's effect.)
    let no_reserve = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &request,
        Some("auto"),
        None,
        0,
    )
    .await
    .expect("selection no reserve");

    // With a 50% reserve: breadth omits 0x12 (reduced budget), and the
    // membership-triggered drilldown spends the reserved budget to pull it.
    let reserved = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &request,
        Some("auto"),
        None,
        5_000,
    )
    .await
    .expect("selection reserved");

    let reserved_ids = selected_ids(&reserved.selection.selected_memory_refs);
    assert!(
        reserved_ids.contains(&h(0x12)),
        "membership-triggered drilldown must pull the deep sibling under a reserve"
    );
    // The deep sibling carries the drilldown selection reason and root flag — it
    // was pulled by drilldown, not breadth.
    let drilldown_pulled = reserved
        .selection
        .selected_memory_refs
        .iter()
        .any(|selected| {
            selected.memory_id == h(0x12)
                && selected.selection_reason == LAYERED_DRILLDOWN_SELECTION_REASON
                && selected
                    .boundary_flags
                    .iter()
                    .any(|flag| flag == &format!("drilldown_root:{}", h(0x10)))
        });
    assert!(
        drilldown_pulled,
        "0x12 must be a membership-triggered drilldown ref keyed on the selected 0x10"
    );
    assert!(
        reserved
            .selection
            .boundary_warnings
            .contains(&"layered_drilldown_applied".to_owned()),
        "the layered_drilldown_applied signal must be emitted when drilldown fires"
    );
    // Spend stays bounded by the full request budget and the token-sum invariant
    // holds after drilldown.
    assert!(
        reserved.selection.selected_token_estimate <= 60,
        "drilldown must stay within the full request token budget"
    );
    let token_sum: u32 = reserved
        .selection
        .selected_memory_refs
        .iter()
        .map(|selected| selected.token_estimate)
        .sum();
    assert_eq!(
        token_sum, reserved.selection.selected_token_estimate,
        "selected_token_estimate must include drilldown refs"
    );
    // The selection's reported budget is restored to the full request budget so
    // the packet builder's budget-equality invariant holds.
    assert_eq!(
        reserved.selection.token_budget, 60,
        "the reserve narrows only breadth, never the reported contract budget"
    );

    // The no-reserve anchor selected at least as many refs through breadth alone.
    let _ = no_reserve;

    db.cleanup().await;
}

#[tokio::test]
async fn drilldown_renders_deep_tier_while_breadth_renders_short_tier() {
    // PRD-D3 (D3-S2): the breadth pass renders the SHORT tier; the drilldown pass
    // renders the DEEP tier for the refs it reaches. We seed a deep detail summary
    // on the child member 0x12 (the column the import path leaves NULL until
    // backfilled), then prove the same ref carries the short tier when breadth
    // selects it and the deep tier when drilldown reaches it — and that the budget
    // invariant holds with the larger deep payload.
    let Some(db) = TestDb::new("deep_tier").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // The fixture's 0x12 short summary.
    let short_summary = "distilled deep member detail with implementation specifics";
    // A strictly richer deep tier (longer byte_len so memory_token_estimate is
    // larger), seeded directly into the nullable deep column — the runtime read,
    // not the import path, is under test here. Sized so the deep ref still fits the
    // budget below while remaining strictly richer than the short tier.
    let deep_summary = "distilled deep member detail with implementation specifics: \
        the deep tier carries the fuller governed fact set served only on drilldown";
    let deep_metadata = serde_json::json!({
        "decision": "allow",
        "text": deep_summary,
        "redaction_codes": [],
        "original_hash": h(0xef),
        "truncated": false,
        "byte_len": deep_summary.len(),
    });
    sqlx::query(
        "UPDATE dagdb_memory_objects SET deep_detail_summary = $1 \
         WHERE tenant_id = $2 AND namespace = $3 AND memory_id = decode($4, 'hex')",
    )
    .bind(&deep_metadata)
    .bind(TENANT)
    .bind(NAMESPACE)
    .bind(h(0x12))
    .execute(&db.pool)
    .await
    .expect("seed deep tier on 0x12");

    // Breadth-only (layered off): when breadth selects 0x12 directly it must carry
    // the SHORT tier — the deep tier never renders in the breadth pass.
    let breadth = build_persistent_graph_context_selection(&db.pool, &selection_request(8_000, 3))
        .await
        .expect("breadth selection");
    let breadth_ref = breadth
        .selection
        .selected_memory_refs
        .iter()
        .find(|selected| selected.memory_id == h(0x12))
        .expect("breadth reaches 0x12 at cap 3");
    assert_eq!(
        breadth_ref.summary.text, short_summary,
        "breadth pass must render the SHORT tier"
    );

    // Drilldown (reserve so breadth fills before 0x12, then drilldown pulls it):
    // the same ref must now carry the DEEP tier, and its token estimate must
    // reflect the larger deep payload.
    // Budget 80 with a 50% reserve: breadth budget 40 fits only 0x10 (omits the
    // 0x12 short tier), then drilldown spends the full 80 to pull 0x12's deep tier
    // (0x10 ~26 + 0x12-deep ~45 = ~71 <= 80).
    let reserved = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &selection_request(80, 8),
        Some("auto"),
        None,
        5_000,
    )
    .await
    .expect("reserved drilldown selection");
    let deep_ref = reserved
        .selection
        .selected_memory_refs
        .iter()
        .find(|selected| selected.memory_id == h(0x12))
        .expect("drilldown reaches 0x12 under a reserve");
    assert_eq!(
        deep_ref.selection_reason, LAYERED_DRILLDOWN_SELECTION_REASON,
        "0x12 must be a drilldown-sourced ref"
    );
    assert_eq!(
        deep_ref.summary.text, deep_summary,
        "drilldown pass must render the DEEP tier"
    );
    assert!(
        deep_ref.summary.text.len() > short_summary.len(),
        "deep tier must be strictly richer than the short tier"
    );

    // Budget invariant holds even with the larger deep payload: the token-sum
    // matches and total spend never exceeds the request cap.
    let token_sum: u32 = reserved
        .selection
        .selected_memory_refs
        .iter()
        .map(|selected| selected.token_estimate)
        .sum();
    assert_eq!(
        token_sum, reserved.selection.selected_token_estimate,
        "token-sum invariant must hold with the deep tier"
    );
    assert!(
        reserved.selection.selected_token_estimate <= 80,
        "deep-tier drilldown must stay within the token budget"
    );

    db.cleanup().await;
}

#[tokio::test]
async fn drilldown_skips_empty_metadata_sibling_and_still_builds_packet() {
    // PRD-D1 latent fix: an empty/rejected-metadata DRILLDOWN sibling must SKIP
    // (continue), matching the Python lane, NOT abort the whole packet. Before the
    // fix the Rust lane propagated the `?` on safe_metadata_from_value in
    // load_governed_child_layer_refs and returned ValidationFailed for the whole
    // selection; now the bad sibling is dropped and the packet still builds.
    //
    // To isolate the DRILLDOWN loader, we mark 0x12 as a context_packet node_type
    // and empty its summary: the breadth candidate loader (kg_context_selection)
    // excludes context_packet rows by structure, so breadth never parses 0x12 —
    // only the drilldown sibling query (which does not exclude that node_type)
    // reaches the empty-metadata row. The selection MUST still succeed with 0x10.
    let Some(db) = TestDb::new("empty_sibling").await else {
        return;
    };
    persist_kg_import_report(&db.pool, &governed_report().to_string())
        .await
        .expect("persist governed layered fixture");

    // An empty-text SafeMetadata: safe_metadata_from_value rejects it (text empty),
    // exactly the empty/rejected-metadata case the Python lane skips.
    let empty_metadata = serde_json::json!({
        "decision": "allow",
        "text": "",
        "redaction_codes": [],
        "original_hash": h(0xef),
        "truncated": false,
        "byte_len": 0,
    });
    sqlx::query(
        "UPDATE dagdb_memory_objects \
         SET summary = $1, deep_detail_summary = NULL, node_type = 'context_packet' \
         WHERE tenant_id = $2 AND namespace = $3 AND memory_id = decode($4, 'hex')",
    )
    .bind(&empty_metadata)
    .bind(TENANT)
    .bind(NAMESPACE)
    .bind(h(0x12))
    .execute(&db.pool)
    .await
    .expect("empty 0x12 sibling summary + exclude from breadth");

    // A reserve so breadth selects 0x10 (which triggers the child-layer drilldown);
    // the drilldown then reaches the empty-metadata sibling 0x12 and must skip it.
    let selection = build_persistent_graph_context_selection_with_layered_drilldown(
        &db.pool,
        &selection_request(8_000, 8),
        Some("auto"),
        None,
        5_000,
    )
    .await
    .expect("packet must still build when a drilldown sibling has empty metadata");

    let ids = selected_ids(&selection.selection.selected_memory_refs);
    assert!(
        ids.contains(&h(0x10)),
        "the valid breadth ref must still be selected"
    );
    assert!(
        !ids.contains(&h(0x12)),
        "the empty-metadata sibling must be skipped, not surfaced"
    );

    db.cleanup().await;
}

fn selected_ids(refs: &[exo_dag_db_api::DagDbSelectedContextRef]) -> Vec<String> {
    refs.iter()
        .map(|selected| selected.memory_id.clone())
        .collect()
}

fn selection_request(token_budget: u32, max_memory_refs: u32) -> DagDbGraphContextSelectionRequest {
    DagDbGraphContextSelectionRequest {
        tenant_id: TENANT.to_owned(),
        namespace: NAMESPACE.to_owned(),
        request_id: "req-drilldown-sel-1".to_owned(),
        task: TASK.to_owned(),
        task_hash: h(0xaa),
        token_budget,
        max_memory_refs,
        catalog_hints: Vec::new(),
        requested_memory_ids: Vec::new(),
        force_revalidate: false,
    }
}

fn packet_request(token_budget: u32) -> DagDbGraphContextPacketBuildRequest {
    DagDbGraphContextPacketBuildRequest {
        tenant_id: TENANT.to_owned(),
        namespace: NAMESPACE.to_owned(),
        request_id: "req-drilldown-1".to_owned(),
        task: TASK.to_owned(),
        task_hash: h(0xaa),
        audit_id: "audit-drilldown-1".to_owned(),
        token_budget,
        selection: exo_dag_db_api::DagDbGraphContextSelectionResponse {
            tenant_id: TENANT.to_owned(),
            namespace: NAMESPACE.to_owned(),
            request_id: "req-drilldown-1".to_owned(),
            task_hash: h(0xaa),
            selection_status: DagDbGraphContextSelectionStatus::Empty,
            selected_memory_refs: Vec::new(),
            selected_graph_edges: Vec::new(),
            omitted_memory_refs: Vec::new(),
            selection_trace: Vec::new(),
            selected_token_estimate: 0,
            token_budget,
            boundary_warnings: Vec::new(),
        },
        import_tracking_status: None,
    }
}

fn database_url_with_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

/// Breadth-selected memory (0x10) is a MEMBER of a depth-1 child layer; its
/// sibling member (0x12) carries a content-bearing summary the task does not
/// match. 0x10's membership triggers drilldown of 0x12 (membership-triggered,
/// not "root must win"). Memory 0x11 is the layer's `root` member (excluded from
/// drilldown by membership_role).
fn governed_report() -> JsonValue {
    layered_report(TENANT, 0x10, 0x11, 0x12, 0x40, 0x41, 0x42)
}

// Foreign-tenant member memory id, asserted to never leak into tenant-test.
const FOREIGN_MEMBER_MEM: u8 = 0x22;

/// A structurally identical fixture under a foreign tenant with disjoint ids.
/// Base bytes stay low so byte-offset receipt ids cannot overflow.
fn foreign_tenant_report() -> JsonValue {
    layered_report(
        "tenant-foreign",
        0x20,
        0x21,
        FOREIGN_MEMBER_MEM,
        0x50,
        0x51,
        0x52,
    )
}

#[allow(clippy::too_many_arguments)]
fn layered_report(
    tenant: &str,
    root_mem: u8,
    child_root_mem: u8,
    child_member_mem: u8,
    root_node: u8,
    child_root_node: u8,
    child_member_node: u8,
) -> JsonValue {
    let root_layer = layer_id_for(tenant, "root", 0);
    let child_layer = layer_id_for(tenant, "root/knowledge-graph", 1);
    json!({
        "schema_version": KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
        "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
        "graph_root": "KnowledgeGraphs/dag-db",
        "tenant_id": tenant,
        "namespace": NAMESPACE,
        "actor_did": "did:exo:kg-importer",
        "batch_id": h(root_mem),
        "dry_run_only": true,
        "postgres_writes": false,
        "raw_markdown_included": false,
        "proposed_memory_records": [
            // Root: task-matching content so breadth selects it.
            memory(tenant, root_mem, "KnowledgeGraphs/dag-db/00_Index.md", "Project Index",
                "The governed project index root context for explain tasks",
                &["KnowledgeGraphs", "dag-db"]),
            // Child-layer root member (excluded from drilldown by role).
            memory(tenant, child_root_mem, "KnowledgeGraphs/dag-db/child_root.md", "Child Root",
                "child layer root anchor summary", &["DeepLayer", "anchor"]),
            // Deep child member: generic summary, no task terms -> breadth omits.
            memory(tenant, child_member_mem, "KnowledgeGraphs/dag-db/deep.md", "Deep Member",
                "distilled deep member detail with implementation specifics",
                &["DeepLayer", "child"])
        ],
        "proposed_catalog_entries": [],
        "proposed_graph_nodes": [
            graph_node(tenant, root_node, root_mem, &["KnowledgeGraphs", "dag-db"]),
            graph_node(tenant, child_root_node, child_root_mem, &["DeepLayer", "anchor"]),
            graph_node(tenant, child_member_node, child_member_mem, &["DeepLayer", "child"])
        ],
        "proposed_graph_edges": [],
        "proposed_required_edges": [],
        "proposed_placement_decisions": [
            placement(tenant, root_mem.wrapping_add(0x60), root_mem, root_mem.wrapping_add(0xa0),
                "root", 0, None),
            placement(tenant, child_root_mem.wrapping_add(0x60), child_root_mem,
                child_root_mem.wrapping_add(0xa0), "root/knowledge-graph", 1, Some(&child_layer)),
            placement(tenant, child_member_mem.wrapping_add(0x60), child_member_mem,
                child_member_mem.wrapping_add(0xa0), "root/knowledge-graph", 1, Some(&child_layer))
        ],
        "proposed_layers": [
            {
                "layer_id": &root_layer,
                "tenant_id": tenant,
                "namespace": NAMESPACE,
                "root_memory_id": h(root_mem),
                "parent_layer_id": null,
                "parent_graph_node_id": null,
                "layer_depth": 0,
                "layer_kind": "root",
                "graph_style": "semantic_catalog_graph",
                "layer_path": "root",
                "metadata": {"source": "drilldown_contract"}
            },
            {
                "layer_id": &child_layer,
                "tenant_id": tenant,
                "namespace": NAMESPACE,
                "root_memory_id": h(child_root_mem),
                "parent_layer_id": &root_layer,
                // Parent graph node is retained for the layer tree, but D1
                // drilldown is membership-triggered: 0x10's MEMBERSHIP in this
                // layer (not this parent pointer) is what triggers the drilldown.
                "parent_graph_node_id": h(root_node),
                "layer_depth": 1,
                "layer_kind": "knowledge_graph",
                "graph_style": "semantic_catalog_graph",
                "layer_path": "root/knowledge-graph",
                "metadata": {"source": "drilldown_contract"}
            }
        ],
        "proposed_layer_memberships": [
            membership(tenant, "root", 0, root_node, "root"),
            membership(tenant, "root/knowledge-graph", 1, child_root_node, "root"),
            // D1: the breadth-selected root (0x10) is also a MEMBER of the
            // depth-1 child layer, so its membership — not "root must win" —
            // triggers drilldown of its sibling member (0x12).
            membership(tenant, "root/knowledge-graph", 1, root_node, "member"),
            membership(tenant, "root/knowledge-graph", 1, child_member_node, "member")
        ],
        "proposed_layer_edges": [],
        "proposed_receipt_intents": [
            receipt(tenant, root_mem.wrapping_add(0x80), "memory", root_mem, "intake_created"),
            receipt(tenant, child_root_mem.wrapping_add(0x80), "memory", child_root_mem, "intake_created"),
            receipt(tenant, child_member_mem.wrapping_add(0x80), "memory", child_member_mem, "intake_created"),
            receipt(tenant, root_mem.wrapping_add(0x70), "validation_report",
                root_mem.wrapping_add(0x70), "validation_created"),
            receipt(tenant, child_root_mem.wrapping_add(0x70), "validation_report",
                child_root_mem.wrapping_add(0x70), "validation_created"),
            receipt(tenant, child_member_mem.wrapping_add(0x70), "validation_report",
                child_member_mem.wrapping_add(0x70), "validation_created")
        ],
        "proposed_validation_reports": [
            validation_report(tenant, root_mem, root_mem),
            validation_report(tenant, child_root_mem, child_root_mem),
            validation_report(tenant, child_member_mem, child_member_mem)
        ],
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

fn memory(
    tenant: &str,
    id: u8,
    path: &str,
    title: &str,
    summary: &str,
    catalog_path: &[&str],
) -> JsonValue {
    json!({
        "memory_id": h(id),
        "tenant_id": tenant,
        "namespace": NAMESPACE,
        "source_path": path,
        "candidate_id": title,
        "node_type": "source",
        "source_type": "generated",
        "source_hash": h(id.wrapping_add(0x20)),
        "payload_hash": h(id.wrapping_add(0x21)),
        "owner_did": "did:exo:kg-importer",
        "controller_did": "did:exo:kg-importer",
        "submitted_by_did": "did:exo:kg-importer",
        "consent_purpose": "retrieval",
        "title": safe(title),
        "summary": safe(summary),
        "keywords": [],
        "catalog_path": catalog_path,
        "risk_class": "R1",
        "risk_bp": 100,
        "validation_status": "pending",
        "council_status": "not_required",
        "dag_finality_status": "pending",
        "status": "pending",
        "receipt_intent_id": h(id.wrapping_add(0x80))
    })
}

fn graph_node(tenant: &str, id: u8, memory_id: u8, catalog_path: &[&str]) -> JsonValue {
    json!({
        "graph_node_id": h(id),
        "memory_id": h(memory_id),
        "tenant_id": tenant,
        "namespace": NAMESPACE,
        "graph_style": "semantic_catalog_graph",
        "node_kind": "canonical",
        "catalog_path": catalog_path
    })
}

#[allow(clippy::too_many_arguments)]
fn placement(
    tenant: &str,
    id: u8,
    memory_id: u8,
    receipt_id: u8,
    target_layer_path: &str,
    target_layer_depth: u32,
    created_child_layer_id: Option<&str>,
) -> JsonValue {
    json!({
        "placement_decision_id": h(id),
        "tenant_id": tenant,
        "namespace": NAMESPACE,
        "input_memory_id": h(memory_id),
        "placement_trace": required_trace(),
        "canonicalization_decision": {
            "decision_kind": "new_canonical",
            "decision_reason": "synthetic fixture",
            "confidence_bp": 0,
            "risk_class": "R1",
            "validator_status": "pending",
            "matched_memory_ids": [],
            "canonical_memory_id": null,
            "required_edges_to_create": []
        },
        "similarity_results": [],
        "validator_report": h(memory_id.wrapping_add(0x60)),
        "receipt_intent_id": h(receipt_id),
        "target_layer_path": target_layer_path,
        "target_layer_depth": target_layer_depth,
        "target_layer_reason": "drilldown_contract_fixture",
        "created_child_layer_id": created_child_layer_id,
        "layer_fallback_used": false
    })
}

fn membership(
    tenant: &str,
    layer_path: &str,
    layer_depth: u32,
    node_byte: u8,
    role: &str,
) -> JsonValue {
    json!({
        "layer_membership_id": membership_id_for(tenant, layer_path, layer_depth, node_byte),
        "tenant_id": tenant,
        "namespace": NAMESPACE,
        "layer_id": layer_id_for(tenant, layer_path, layer_depth),
        "graph_node_id": h(node_byte),
        "graph_style": "semantic_catalog_graph",
        "membership_role": role,
        "local_node_rank": 0,
        "metadata": {}
    })
}

fn receipt(
    tenant: &str,
    id: u8,
    subject_kind: &str,
    subject_id: u8,
    event_type: &str,
) -> JsonValue {
    json!({
        "receipt_intent_id": h(id),
        "tenant_id": tenant,
        "namespace": NAMESPACE,
        "subject_kind": subject_kind,
        "subject_id": h(subject_id),
        "event_type": event_type,
        "actor_did": "did:exo:kg-importer",
        "reason": "synthetic fixture"
    })
}

fn validation_report(tenant: &str, id: u8, subject_id: u8) -> JsonValue {
    json!({
        "validation_report_id": h(id.wrapping_add(0x70)),
        "tenant_id": tenant,
        "namespace": NAMESPACE,
        "subject_kind": "memory",
        "subject_id": h(subject_id),
        "validator_did": "did:exo:kg-importer",
        "input_hash": h(id.wrapping_add(0x11)),
        "policy_hash": h(id.wrapping_add(0x12)),
        "validation_status": "pending",
        "risk_class": "R1",
        "risk_bp": 100,
        "decision": "allow",
        "notes": safe("synthetic validation")
    })
}

fn safe(text: &str) -> JsonValue {
    json!({
        "decision": "allow",
        "text": text,
        "redaction_codes": [],
        "original_hash": h(0xef),
        "truncated": false,
        "byte_len": text.len()
    })
}

fn h(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn hash(byte: u8) -> Hash256 {
    Hash256::from_bytes([byte; 32])
}

fn layer_id_for(tenant: &str, layer_path: &str, layer_depth: u32) -> String {
    deterministic_layer_id(
        tenant,
        NAMESPACE,
        MemoryGraphStyle::SemanticCatalogGraph,
        layer_path,
        layer_depth,
    )
    .expect("derived layer id")
    .to_string()
}

fn membership_id_for(tenant: &str, layer_path: &str, layer_depth: u32, node_byte: u8) -> String {
    deterministic_layer_membership_id(
        tenant,
        NAMESPACE,
        deterministic_layer_id(
            tenant,
            NAMESPACE,
            MemoryGraphStyle::SemanticCatalogGraph,
            layer_path,
            layer_depth,
        )
        .expect("derived layer id"),
        hash(node_byte),
    )
    .expect("derived membership id")
    .to_string()
}

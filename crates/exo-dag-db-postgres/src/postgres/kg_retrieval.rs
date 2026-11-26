//! Feature-gated Postgres retrieval preview over persisted KG import rows.
//!
//! This adapter is read-only. It does not activate routes, persist context
//! packets, expose gateway behavior, perform writeback, or export knowledge.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use exo_dag_db_api::SafeMetadata;
use serde_json::Value as JsonValue;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::{
    graph_context_selection::MAX_SELECTED_GRAPH_EDGES_PER_PACKET,
    kg_retrieval::{
        KG_CONTEXT_PACKET_PREVIEW_SCHEMA, KG_RETRIEVAL_DATABASE_URL_ENV, KgCitationDiagnostic,
        KgCitationHandle, KgContextPacketPreview, KgGraphEdgeRef, KgGraphPathSummary,
        KgLayerBudgetReport, KgLayerEdgeRef, KgMemoryRef, KgOmittedMemoryRef,
        KgRetrievalDiagnostics, KgRetrievalError, KgRetrievalRequest, KgRollupSummaryRef,
        KgSelectedLayerRef, KgValidationSummary, citation_handle, context_packet_preview_id,
        hex_from_hash_column, memory_token_estimate, route_hint_id,
    },
    layered_hygiene::LayerHygieneEdgeState,
};

/// Result alias for Postgres retrieval preview.
pub type Result<T> = std::result::Result<T, KgRetrievalError>;

/// Retrieve a compact KG context-packet preview using `EXO_DAGDB_TEST_DATABASE_URL`.
pub async fn retrieve_kg_context_packet_from_env(
    request: &KgRetrievalRequest,
) -> Result<KgContextPacketPreview> {
    let database_url = std::env::var(KG_RETRIEVAL_DATABASE_URL_ENV).map_err(|_| {
        KgRetrievalError::MissingDatabaseUrl {
            env_var: KG_RETRIEVAL_DATABASE_URL_ENV,
        }
    })?;
    retrieve_kg_context_packet_from_database_url(Some(database_url.as_str()), request).await
}

/// Retrieve a compact KG context-packet preview using an explicit database URL.
pub async fn retrieve_kg_context_packet_from_database_url(
    database_url: Option<&str>,
    request: &KgRetrievalRequest,
) -> Result<KgContextPacketPreview> {
    let Some(database_url) = database_url else {
        return Err(KgRetrievalError::MissingDatabaseUrl {
            env_var: KG_RETRIEVAL_DATABASE_URL_ENV,
        });
    };
    let pool = super::init_pool(database_url)
        .await
        .map_err(|source| KgRetrievalError::Init {
            source: Box::new(source),
        })?;
    let result = retrieve_kg_context_packet(&pool, request).await;
    pool.close().await;
    result
}

/// Retrieve a compact KG context-packet preview from an existing pool.
pub async fn retrieve_kg_context_packet(
    pool: &PgPool,
    request: &KgRetrievalRequest,
) -> Result<KgContextPacketPreview> {
    request.validate()?;
    let mut tx = super::begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(pg)?;
    let memories = load_memories(&mut tx, request).await?;
    let catalogs = load_catalogs(&mut tx, request).await?;
    let graph_nodes = load_graph_nodes(&mut tx, request).await?;
    let layer_plan = load_layer_selection_plan(&mut tx, request).await?;
    let validation_reports = load_validation_reports(&mut tx, request).await?;

    let preview = build_preview(
        &mut tx,
        request,
        memories,
        catalogs,
        graph_nodes,
        layer_plan,
        validation_reports,
    )
    .await?;
    tx.commit().await.map_err(pg)?;
    Ok(preview)
}

async fn build_preview(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
    memories: BTreeMap<String, RetrievedMemory>,
    catalogs: BTreeMap<String, RetrievedCatalog>,
    graph_nodes: BTreeMap<String, Vec<RetrievedGraphNode>>,
    mut layer_plan: LayerSelectionPlan,
    validation_reports: BTreeMap<String, Vec<String>>,
) -> Result<KgContextPacketPreview> {
    let mut warnings = Vec::new();
    push_warning(&mut warnings, "preview_only_not_production_route");
    push_warning(&mut warnings, "unresolved_review_items_not_active_edges");
    if layer_plan.flat_fallback_used {
        push_warning(&mut warnings, "flat_fallback_used_no_layer_evidence");
    }
    if layer_plan.depth_budget_truncated {
        push_warning(&mut warnings, "layer_depth_budget_truncated");
    }
    if layer_plan.layer_budget_truncated {
        push_warning(&mut warnings, "layer_count_budget_truncated");
    }
    if layer_plan.excluded_demoted_layer_edge_count > 0
        || layer_plan.excluded_tombstoned_layer_edge_count > 0
    {
        push_warning(&mut warnings, "layer_hygiene_exclusions_applied");
    }

    let requested = request
        .requested_memory_ids
        .iter()
        .enumerate()
        .map(|(index, memory_id)| (memory_id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let mut candidate_memory_ids = Vec::new();
    let mut omitted_memory_refs = Vec::new();
    for requested_id in &request.requested_memory_ids {
        if !memories.contains_key(requested_id) {
            push_warning(
                &mut warnings,
                format!("requested_memory_not_found:{requested_id}"),
            );
            omitted_memory_refs.push(KgOmittedMemoryRef {
                memory_id: requested_id.clone(),
                reason: "requested_memory_not_found".to_owned(),
                token_estimate_if_selected: None,
                catalog_path: Vec::new(),
                validation_status: None,
                risk_class: None,
            });
        }
    }

    for memory_id in sorted_candidate_memory_ids(request, &memories, &graph_nodes, &layer_plan) {
        let Some(memory) = memories.get(&memory_id) else {
            continue;
        };
        // A caller that names a memory by id in requested_memory_ids is asking for that
        // exact memory; honor retrievability-by-id even when it is not a member of any
        // selected catalog-cluster layer. Layer membership reflects source-tree clustering,
        // which a freshly written writeback child (or any layer-less corpus node) need not
        // have, so the layer filter must not silently drop an explicitly requested memory.
        let explicitly_requested = requested.contains_key(&memory_id);
        if !explicitly_requested
            && !layer_plan.flat_fallback_used
            && !layer_plan.memory_layers.contains_key(&memory_id)
        {
            omitted_memory_refs.push(omitted_memory_ref(
                &memory_id,
                memory,
                &graph_nodes,
                "outside_selected_layers",
            ));
            continue;
        }
        if !requested.is_empty() && !requested.contains_key(&memory_id) {
            omitted_memory_refs.push(omitted_memory_ref(
                &memory_id,
                memory,
                &graph_nodes,
                "requested_memory_filter_mismatch",
            ));
            continue;
        }
        if let Some(catalog_path) = &request.catalog_path
            && !catalog_path_matches(&memory_id, catalog_path, &graph_nodes)
        {
            omitted_memory_refs.push(omitted_memory_ref(
                &memory_id,
                memory,
                &graph_nodes,
                "catalog_path_filter_mismatch",
            ));
            continue;
        }
        if !memory_status_allowed(&memory.status) {
            omitted_memory_refs.push(omitted_memory_ref(
                &memory_id,
                memory,
                &graph_nodes,
                "advisory_or_review_only",
            ));
            continue;
        }
        if validation_status_blocked(&memory.validation_status) {
            omitted_memory_refs.push(omitted_memory_ref(
                &memory_id,
                memory,
                &graph_nodes,
                "validation_status_not_allowed",
            ));
            continue;
        }
        candidate_memory_ids.push(memory_id);
    }

    let max_refs = request.effective_max_memory_refs();
    let mut memory_refs = Vec::new();
    let mut omitted_memory_ids = Vec::new();
    let mut token_estimate = 0u32;
    let mut truncated_by_token_budget = false;
    let mut truncated_by_max_memory_refs = false;
    let mut selected_per_layer = BTreeMap::<String, u32>::new();
    for memory_id in &candidate_memory_ids {
        let Some(memory) = memories.get(memory_id) else {
            continue;
        };
        let selected_layer = layer_plan.best_memory_layer(memory_id);
        if let Some(layer) = selected_layer {
            let selected_count = selected_per_layer
                .get(&layer.layer_id)
                .copied()
                .unwrap_or_default();
            if selected_count >= request.effective_max_nodes_per_layer() {
                omitted_memory_ids.push(memory_id.clone());
                omitted_memory_refs.push(omitted_memory_ref(
                    memory_id,
                    memory,
                    &graph_nodes,
                    "layer_node_budget_exceeded",
                ));
                layer_plan.node_budget_truncated = true;
                continue;
            }
        }
        let next_estimate = memory_token_estimate(&memory.title, &memory.summary);
        if u32::try_from(memory_refs.len()).map_or(true, |count| count >= max_refs) {
            omitted_memory_ids.push(memory_id.clone());
            omitted_memory_refs.push(omitted_memory_ref(
                memory_id,
                memory,
                &graph_nodes,
                "max_memory_refs_exceeded",
            ));
            truncated_by_max_memory_refs = true;
            continue;
        }
        if token_estimate.saturating_add(next_estimate) > request.token_budget {
            omitted_memory_ids.push(memory_id.clone());
            omitted_memory_refs.push(omitted_memory_ref(
                memory_id,
                memory,
                &graph_nodes,
                "token_budget_exceeded",
            ));
            truncated_by_token_budget = true;
            continue;
        }
        token_estimate = token_estimate.saturating_add(next_estimate);
        let catalog = catalogs.get(memory_id);
        let nodes = graph_nodes.get(memory_id).cloned().unwrap_or_default();
        let catalog_path = nodes
            .first()
            .map(|node| split_catalog_path(&node.catalog_path))
            .unwrap_or_default();
        let graph_node_ids = nodes
            .iter()
            .map(|node| node.graph_node_id.clone())
            .collect();
        let validation_report_ids = validation_reports
            .get(memory_id)
            .cloned()
            .unwrap_or_default();
        let citation = citation_handle(
            &request.tenant_id,
            &request.namespace,
            memory_id,
            catalog.map(|entry| entry.catalog_id.as_str()),
        )?;
        memory_refs.push(KgMemoryRef {
            memory_id: memory_id.clone(),
            catalog_id: catalog.map(|entry| entry.catalog_id.clone()),
            source_path: None,
            catalog_path,
            layer_id: selected_layer.map(|layer| layer.layer_id.clone()),
            layer_path: selected_layer.map(|layer| layer.layer_path.clone()),
            layer_depth: selected_layer.map(|layer| layer.layer_depth),
            layer_kind: selected_layer.map(|layer| layer.layer_kind.clone()),
            layer_membership_role: selected_layer.map(|layer| layer.membership_role.clone()),
            layer_selection_reason: selected_layer
                .map(|layer| layer.memory_selection_reason.clone()),
            rollup_summary_ref: selected_layer.and_then(|layer| layer.rollup_summary_ref.clone()),
            title: memory.title.clone(),
            summary: memory.summary.clone(),
            latest_receipt_hash: memory.latest_receipt_hash.clone(),
            memory_status: memory.status.clone(),
            validation_status: memory.validation_status.clone(),
            risk_class: memory.risk_class.clone(),
            council_status: memory.council_status.clone(),
            dag_finality_status: memory.dag_finality_status.clone(),
            graph_node_ids,
            validation_report_ids,
            citation_handle: citation,
            token_estimate: next_estimate, // pragma-allowlist-secret
            selection_reasons: selection_reasons(
                request,
                memory_id,
                &nodes,
                selected_layer,
                validation_reports
                    .get(memory_id)
                    .is_some_and(|reports| !reports.is_empty()),
            ),
        });
        if let Some(layer) = selected_layer {
            selected_per_layer
                .entry(layer.layer_id.clone())
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }
    }
    if memory_refs.is_empty() {
        push_warning(&mut warnings, "no_matching_memory");
    }
    if !memory_refs.is_empty() {
        push_warning(&mut warnings, "origin_path_not_persisted");
    }
    if truncated_by_token_budget {
        push_warning(&mut warnings, "context_truncated_by_token_budget");
    }
    if truncated_by_max_memory_refs {
        push_warning(&mut warnings, "context_truncated_by_max_memory_refs");
    }
    if !layer_plan.flat_fallback_used && !memory_refs.is_empty() {
        push_warning(&mut warnings, "layer_metadata_available");
    }
    if layer_plan.node_budget_truncated {
        push_warning(&mut warnings, "layer_node_budget_truncated");
    }

    let selected_memory_ids = memory_refs
        .iter()
        .map(|memory| memory.memory_id.clone())
        .collect::<Vec<_>>();
    let selected_memory_id_set = selected_memory_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut graph_edges = load_graph_edges(tx, request, &selected_memory_ids).await?;
    if graph_edges.len() > MAX_SELECTED_GRAPH_EDGES_PER_PACKET {
        graph_edges.truncate(MAX_SELECTED_GRAPH_EDGES_PER_PACKET);
        push_warning(&mut warnings, "selected_graph_edges_truncated_by_budget");
    }
    let selected_layers = layer_plan.selected_layer_refs(&selected_per_layer)?;
    let selected_layer_edges = layer_plan.selected_layer_edge_refs()?;
    if layer_plan.layer_edge_budget_truncated {
        push_warning(&mut warnings, "selected_layer_edges_truncated_by_budget");
    }
    // PRD-D2 S2: index the persisted aggregate root summaries by layer_id so the
    // rollup builder surfaces the layer-policy v2 aggregate (when present)
    // instead of reusing the root member's own summary.
    let layer_aggregates = layer_plan.aggregate_summaries_by_layer();
    let rollup_summaries = build_rollup_summaries(
        &selected_layers,
        &memories,
        &selected_memory_id_set,
        &layer_aggregates,
    )?;
    let citation_handles =
        build_citation_handles(request, &memory_refs, &graph_edges, &validation_reports)?;
    let citation_diagnostics = build_citation_diagnostics(&memory_refs, &citation_handles);
    let graph_path_summary = graph_path_summary(&memory_refs, &graph_edges)?;
    enrich_missing_data_warnings(
        &mut warnings,
        &memory_refs,
        &graph_path_summary,
        &citation_diagnostics,
    );
    let route_hint = route_hint_id(request, &selected_memory_ids)?;
    let context_packet =
        context_packet_preview_id(request, &route_hint.to_string(), &selected_memory_ids)?;
    let mut validation_summary = validation_summary(&memory_refs)?;
    validation_summary.warning_count =
        u32::try_from(warnings.len()).map_err(|_| KgRetrievalError::InvalidRequest {
            reason: "warning count out of range".to_owned(),
        })?;
    let retrieval_diagnostics = retrieval_diagnostics(RetrievalDiagnosticsInput {
        request,
        memory_refs: &memory_refs,
        omitted_memory_refs: &omitted_memory_refs,
        graph_edges: &graph_edges,
        citation_handles: &citation_handles,
        warning_count: warnings.len(),
        token_estimate,
        layer_plan: &layer_plan,
        selected_layers: &selected_layers,
        selected_layer_edges: &selected_layer_edges,
    })?;
    let budget_report = layer_budget_report(
        request,
        &layer_plan,
        &selected_layers,
        &selected_layer_edges,
        &memory_refs,
        &graph_edges,
        truncated_by_token_budget,
    )?;

    Ok(KgContextPacketPreview {
        schema_version: KG_CONTEXT_PACKET_PREVIEW_SCHEMA.to_owned(),
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        context_packet_id: context_packet.to_string(),
        route_hint_id: route_hint.to_string(),
        memory_refs: memory_refs.clone(),
        graph_edges: graph_edges.clone(),
        selected_refs: memory_refs,
        selected_layers,
        selected_layer_edges,
        selected_graph_edges: graph_edges,
        rollup_summaries,
        budget_report,
        flat_fallback_used: layer_plan.flat_fallback_used,
        citation_handles,
        retrieval_diagnostics,
        validation_summary,
        graph_path_summary,
        citation_diagnostics,
        token_budget: request.token_budget,
        token_estimate,
        omitted_memory_ids,
        omitted_memory_refs,
        warnings,
        dry_run_or_preview_only: true,
    })
}

fn sorted_candidate_memory_ids(
    request: &KgRetrievalRequest,
    memories: &BTreeMap<String, RetrievedMemory>,
    graph_nodes: &BTreeMap<String, Vec<RetrievedGraphNode>>,
    layer_plan: &LayerSelectionPlan,
) -> Vec<String> {
    let mut ids = memories.keys().cloned().collect::<Vec<_>>();
    ids.sort_by(|left, right| {
        let left_requested = request
            .requested_memory_ids
            .iter()
            .position(|memory_id| memory_id == left);
        let right_requested = request
            .requested_memory_ids
            .iter()
            .position(|memory_id| memory_id == right);
        match (left_requested, right_requested) {
            (Some(left_index), Some(right_index)) => {
                left_index.cmp(&right_index).then_with(|| left.cmp(right))
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => {
                let left_layer = layer_plan.best_memory_layer(left);
                let right_layer = layer_plan.best_memory_layer(right);
                let left_catalog = request
                    .catalog_path
                    .as_ref()
                    .is_some_and(|path| catalog_path_matches(left, path, graph_nodes));
                let right_catalog = request
                    .catalog_path
                    .as_ref()
                    .is_some_and(|path| catalog_path_matches(right, path, graph_nodes));
                right_catalog
                    .cmp(&left_catalog)
                    .then_with(|| match (left_layer, right_layer) {
                        (Some(left_layer), Some(right_layer)) => left_layer
                            .traversal_rank
                            .cmp(&right_layer.traversal_rank)
                            .then(left_layer.local_node_rank.cmp(&right_layer.local_node_rank))
                            .then(right_layer.layer_depth.cmp(&left_layer.layer_depth)),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    })
                    .then_with(|| {
                        risk_rank(
                            memories
                                .get(left)
                                .map_or("", |memory| memory.risk_class.as_str()),
                        )
                        .cmp(&risk_rank(
                            memories
                                .get(right)
                                .map_or("", |memory| memory.risk_class.as_str()),
                        ))
                    })
                    .then_with(|| {
                        validation_rank(
                            memories
                                .get(left)
                                .map_or("", |memory| memory.validation_status.as_str()),
                        )
                        .cmp(&validation_rank(
                            memories
                                .get(right)
                                .map_or("", |memory| memory.validation_status.as_str()),
                        ))
                    })
                    .then_with(|| left.cmp(right))
            }
        }
    });
    ids
}

fn risk_rank(risk_class: &str) -> u8 {
    match risk_class {
        "R0" => 0,
        "R1" => 1,
        "R2" => 2,
        "R3" => 3,
        "R4" => 4,
        "R5" => 5,
        _ => 6,
    }
}

fn validation_rank(validation_status: &str) -> u8 {
    match validation_status {
        "passed" | "not_required" => 0,
        "pending" => 1,
        "needs_council" => 2,
        "failed" | "contradictory" | "expired" => 3,
        _ => 4,
    }
}

fn catalog_path_matches(
    memory_id: &str,
    catalog_path: &[String],
    graph_nodes: &BTreeMap<String, Vec<RetrievedGraphNode>>,
) -> bool {
    let expected = catalog_path.join("/");
    graph_nodes
        .get(memory_id)
        .is_some_and(|nodes| nodes.iter().any(|node| node.catalog_path == expected))
}

fn first_catalog_path(
    memory_id: &str,
    graph_nodes: &BTreeMap<String, Vec<RetrievedGraphNode>>,
) -> Vec<String> {
    graph_nodes
        .get(memory_id)
        .and_then(|nodes| nodes.first())
        .map(|node| split_catalog_path(&node.catalog_path))
        .unwrap_or_default()
}

fn omitted_memory_ref(
    memory_id: &str,
    memory: &RetrievedMemory,
    graph_nodes: &BTreeMap<String, Vec<RetrievedGraphNode>>,
    reason: &str,
) -> KgOmittedMemoryRef {
    KgOmittedMemoryRef {
        memory_id: memory_id.to_owned(),
        reason: reason.to_owned(),
        token_estimate_if_selected: Some(memory_token_estimate(&memory.title, &memory.summary)),
        catalog_path: first_catalog_path(memory_id, graph_nodes),
        validation_status: Some(memory.validation_status.clone()),
        risk_class: Some(memory.risk_class.clone()),
    }
}

fn memory_status_allowed(status: &str) -> bool {
    matches!(status, "pending" | "approved" | "routable")
}

fn validation_status_blocked(validation_status: &str) -> bool {
    matches!(validation_status, "failed" | "contradictory" | "expired")
}

fn selection_reasons(
    request: &KgRetrievalRequest,
    memory_id: &str,
    nodes: &[RetrievedGraphNode],
    selected_layer: Option<&RetrievedLayerMembership>,
    has_validation_report: bool,
) -> Vec<String> {
    let mut reasons = vec![
        "tenant_namespace_match".to_owned(),
        "selected_by_catalog_order".to_owned(),
        "within_token_budget".to_owned(),
        "validation_status_allowed".to_owned(),
        "has_citation_handle".to_owned(),
    ];
    if request
        .requested_memory_ids
        .iter()
        .any(|requested_id| requested_id == memory_id)
    {
        reasons.push("matched_requested_memory_id".to_owned());
    }
    if let Some(catalog_path) = &request.catalog_path {
        let expected = catalog_path.join("/");
        if nodes.iter().any(|node| node.catalog_path == expected) {
            reasons.push("matched_catalog_path".to_owned());
        }
    }
    if !nodes.is_empty() {
        reasons.push("has_graph_node".to_owned());
    }
    if let Some(layer) = selected_layer {
        reasons.push("has_layer_membership".to_owned());
        reasons.push(format!("layer_id:{}", layer.layer_id));
        reasons.push(format!("layer_path:{}", layer.layer_path));
        reasons.push(format!("layer_depth:{}", layer.layer_depth));
        reasons.push(format!("layer_kind:{}", layer.layer_kind));
        reasons.push(format!("layer_graph_style:{}", layer.graph_style));
        reasons.push(format!("membership_role:{}", layer.membership_role));
        reasons.push(layer.memory_selection_reason.clone());
    }
    if has_validation_report {
        reasons.push("has_validation_report".to_owned());
    }
    reasons.sort();
    reasons
}

fn push_warning(warnings: &mut Vec<String>, warning: impl Into<String>) {
    let warning = warning.into();
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

struct RetrievalDiagnosticsInput<'a> {
    request: &'a KgRetrievalRequest,
    memory_refs: &'a [KgMemoryRef],
    omitted_memory_refs: &'a [KgOmittedMemoryRef],
    graph_edges: &'a [KgGraphEdgeRef],
    citation_handles: &'a [KgCitationHandle],
    warning_count: usize,
    token_estimate: u32,
    layer_plan: &'a LayerSelectionPlan,
    selected_layers: &'a [KgSelectedLayerRef],
    selected_layer_edges: &'a [KgLayerEdgeRef],
}

fn retrieval_diagnostics(input: RetrievalDiagnosticsInput<'_>) -> Result<KgRetrievalDiagnostics> {
    Ok(KgRetrievalDiagnostics {
        selected_memory_count: usize_to_u32(input.memory_refs.len(), "selected memory count")?,
        omitted_memory_count: usize_to_u32(
            input.omitted_memory_refs.len(),
            "omitted memory count",
        )?,
        selected_graph_edge_count: usize_to_u32(
            input.graph_edges.len(),
            "selected graph edge count",
        )?,
        selected_layer_count: usize_to_u32(input.selected_layers.len(), "selected layer count")?,
        selected_layer_edge_count: usize_to_u32(
            input.selected_layer_edges.len(),
            "selected layer edge count",
        )?,
        active_layer_edge_count: usize_to_u32(
            input.layer_plan.active_layer_edge_count,
            "active layer edge count",
        )?,
        excluded_demoted_layer_edge_count: usize_to_u32(
            input.layer_plan.excluded_demoted_layer_edge_count,
            "excluded demoted layer edge count",
        )?,
        excluded_tombstoned_layer_edge_count: usize_to_u32(
            input.layer_plan.excluded_tombstoned_layer_edge_count,
            "excluded tombstoned layer edge count",
        )?,
        citation_handle_count: usize_to_u32(input.citation_handles.len(), "citation handle count")?,
        warning_count: usize_to_u32(input.warning_count, "warning count")?,
        token_budget: input.request.token_budget,
        token_estimate: input.token_estimate,
        max_layer_depth: input.request.effective_max_layer_depth(),
        max_layers_selected: input.request.effective_max_layers_selected(),
        max_nodes_per_layer: input.request.effective_max_nodes_per_layer(),
        max_layer_edges: input.request.effective_max_layer_edges(),
        layer_path_filter_applied: input.request.layer_path.is_some(),
        max_memory_refs_applied: input.request.max_memory_refs.is_some(),
        catalog_path_filter_applied: input.request.catalog_path.is_some(),
        requested_memory_filter_applied: !input.request.requested_memory_ids.is_empty(),
        flat_fallback_used: input.layer_plan.flat_fallback_used,
        depth_budget_truncated: input.layer_plan.depth_budget_truncated,
        layer_budget_truncated: input.layer_plan.layer_budget_truncated,
        node_budget_truncated: input.layer_plan.node_budget_truncated,
        layer_edge_budget_truncated: input.layer_plan.layer_edge_budget_truncated,
        deterministic_ordering: true,
        raw_markdown_returned: false,
        preview_only: true,
    })
}

fn layer_budget_report(
    request: &KgRetrievalRequest,
    layer_plan: &LayerSelectionPlan,
    selected_layers: &[KgSelectedLayerRef],
    selected_layer_edges: &[KgLayerEdgeRef],
    memory_refs: &[KgMemoryRef],
    graph_edges: &[KgGraphEdgeRef],
    token_budget_truncated: bool,
) -> Result<KgLayerBudgetReport> {
    Ok(KgLayerBudgetReport {
        max_layer_depth: request.effective_max_layer_depth(),
        max_layers_selected: request.effective_max_layers_selected(),
        max_nodes_per_layer: request.effective_max_nodes_per_layer(),
        max_memory_refs: request.effective_max_memory_refs(),
        max_layer_edges: request.effective_max_layer_edges(),
        selected_layer_count: usize_to_u32(selected_layers.len(), "selected layer count")?,
        selected_layer_edge_count: usize_to_u32(
            selected_layer_edges.len(),
            "selected layer edge count",
        )?,
        active_layer_edge_count: usize_to_u32(
            layer_plan.active_layer_edge_count,
            "active layer edge count",
        )?,
        excluded_demoted_layer_edge_count: usize_to_u32(
            layer_plan.excluded_demoted_layer_edge_count,
            "excluded demoted layer edge count",
        )?,
        excluded_tombstoned_layer_edge_count: usize_to_u32(
            layer_plan.excluded_tombstoned_layer_edge_count,
            "excluded tombstoned layer edge count",
        )?,
        selected_memory_ref_count: usize_to_u32(memory_refs.len(), "selected memory ref count")?,
        selected_graph_edge_count: usize_to_u32(graph_edges.len(), "selected graph edge count")?,
        depth_budget_truncated: layer_plan.depth_budget_truncated,
        layer_budget_truncated: layer_plan.layer_budget_truncated,
        node_budget_truncated: layer_plan.node_budget_truncated,
        layer_edge_budget_truncated: layer_plan.layer_edge_budget_truncated,
        token_budget_truncated,
        flat_fallback_used: layer_plan.flat_fallback_used,
    })
}

fn build_citation_handles(
    request: &KgRetrievalRequest,
    memory_refs: &[KgMemoryRef],
    graph_edges: &[KgGraphEdgeRef],
    validation_reports: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<KgCitationHandle>> {
    let mut handles = Vec::new();
    for memory in memory_refs {
        let graph_edge_ids = graph_edges
            .iter()
            .filter(|edge| {
                edge.from_memory_id == memory.memory_id || edge.to_memory_id == memory.memory_id
            })
            .map(|edge| edge.graph_edge_id.clone())
            .collect::<Vec<_>>();
        handles.push(KgCitationHandle {
            handle: citation_handle(
                &request.tenant_id,
                &request.namespace,
                &memory.memory_id,
                memory.catalog_id.as_deref(),
            )?,
            memory_id: memory.memory_id.clone(),
            catalog_id: memory.catalog_id.clone(),
            latest_receipt_hash: memory.latest_receipt_hash.clone(),
            graph_node_ids: memory.graph_node_ids.clone(),
            graph_edge_ids,
            validation_report_ids: validation_reports
                .get(&memory.memory_id)
                .cloned()
                .unwrap_or_default(),
        });
    }
    Ok(handles)
}

fn build_citation_diagnostics(
    memory_refs: &[KgMemoryRef],
    citation_handles: &[KgCitationHandle],
) -> Vec<KgCitationDiagnostic> {
    let mut diagnostics = Vec::new();
    for citation in citation_handles {
        let memory = memory_refs
            .iter()
            .find(|memory| memory.memory_id == citation.memory_id);
        let latest_receipt_hash = memory.map(|memory| memory.latest_receipt_hash.clone());
        let receipt_missing = latest_receipt_hash
            .as_ref()
            .is_none_or(|receipt| receipt == &"00".repeat(32));
        let (citation_status, reason) = if receipt_missing {
            ("missing_receipt", "latest_receipt_hash_missing")
        } else if citation.validation_report_ids.is_empty() {
            ("missing_validation", "validation_report_missing")
        } else if citation.graph_node_ids.is_empty() {
            ("partial", "graph_node_missing")
        } else if citation.graph_edge_ids.is_empty() {
            (
                "missing_graph_edge",
                "graph_edge_missing_or_memory_isolated",
            )
        } else {
            (
                "available",
                "citation_has_memory_catalog_receipt_validation_graph",
            )
        };
        diagnostics.push(KgCitationDiagnostic {
            citation_handle: citation.handle.clone(),
            memory_id: citation.memory_id.clone(),
            catalog_id: citation.catalog_id.clone(),
            validation_report_id: citation.validation_report_ids.first().cloned(),
            latest_receipt_hash,
            graph_node_ids: citation.graph_node_ids.clone(),
            graph_edge_ids: citation.graph_edge_ids.clone(),
            citation_status: citation_status.to_owned(),
            reason: reason.to_owned(),
        });
    }
    diagnostics.sort_by(|left, right| {
        left.memory_id
            .cmp(&right.memory_id)
            .then_with(|| left.citation_handle.cmp(&right.citation_handle))
    });
    diagnostics
}

fn graph_path_summary(
    memory_refs: &[KgMemoryRef],
    graph_edges: &[KgGraphEdgeRef],
) -> Result<KgGraphPathSummary> {
    let mut connected = BTreeSet::new();
    let mut graph_styles_seen = BTreeSet::new();
    let mut edge_kinds_seen = BTreeSet::new();
    for edge in graph_edges {
        connected.insert(edge.from_memory_id.clone());
        connected.insert(edge.to_memory_id.clone());
        graph_styles_seen.insert(edge.graph_style.clone());
        edge_kinds_seen.insert(edge.edge_kind.clone());
    }
    let isolated_count = memory_refs
        .iter()
        .filter(|memory| !connected.contains(&memory.memory_id))
        .count();
    Ok(KgGraphPathSummary {
        graph_edge_count: usize_to_u32(graph_edges.len(), "graph edge count")?,
        graph_styles_seen: graph_styles_seen.into_iter().collect(),
        edge_kinds_seen: edge_kinds_seen.into_iter().collect(),
        isolated_memory_count: usize_to_u32(isolated_count, "isolated memory count")?,
        connected_memory_count: usize_to_u32(connected.len(), "connected memory count")?,
        missing_edge_warning_count: usize_to_u32(isolated_count, "missing edge warning count")?,
    })
}

fn enrich_missing_data_warnings(
    warnings: &mut Vec<String>,
    memory_refs: &[KgMemoryRef],
    graph_path_summary: &KgGraphPathSummary,
    citation_diagnostics: &[KgCitationDiagnostic],
) {
    if memory_refs
        .iter()
        .any(|memory| memory.validation_report_ids.is_empty())
    {
        push_warning(warnings, "validation_report_missing");
    }
    if memory_refs
        .iter()
        .any(|memory| memory.graph_node_ids.is_empty())
    {
        push_warning(warnings, "graph_node_missing");
    }
    if graph_path_summary.missing_edge_warning_count > 0 {
        push_warning(warnings, "graph_edge_missing");
    }
    if citation_diagnostics
        .iter()
        .any(|diagnostic| diagnostic.citation_status == "missing_receipt")
    {
        push_warning(warnings, "receipt_missing");
    }
}

fn validation_summary(memory_refs: &[KgMemoryRef]) -> Result<KgValidationSummary> {
    let mut summary = KgValidationSummary {
        selected_memory_count: u32::try_from(memory_refs.len()).map_err(|_| {
            KgRetrievalError::InvalidRequest {
                reason: "selected memory count out of range".to_owned(),
            }
        })?,
        pending_count: 0,
        passed_count: 0,
        failed_count: 0,
        needs_council_count: 0,
        warning_count: 0,
        validation_status_counts: BTreeMap::new(),
        risk_class_counts: BTreeMap::new(),
        dag_finality_status_counts: BTreeMap::new(),
        council_status_counts: BTreeMap::new(),
    };
    for memory in memory_refs {
        increment_count(
            &mut summary.validation_status_counts,
            &memory.validation_status,
        );
        increment_count(&mut summary.risk_class_counts, &memory.risk_class);
        increment_count(
            &mut summary.dag_finality_status_counts,
            &memory.dag_finality_status,
        );
        increment_count(&mut summary.council_status_counts, &memory.council_status);
        match memory.validation_status.as_str() {
            "passed" => summary.passed_count = summary.passed_count.saturating_add(1),
            "failed" | "contradictory" | "expired" => {
                summary.failed_count = summary.failed_count.saturating_add(1);
            }
            "needs_council" => {
                summary.needs_council_count = summary.needs_council_count.saturating_add(1);
            }
            _ => summary.pending_count = summary.pending_count.saturating_add(1),
        }
    }
    Ok(summary)
}

fn increment_count(counts: &mut BTreeMap<String, u32>, key: &str) {
    counts
        .entry(key.to_owned())
        .and_modify(|count| *count = count.saturating_add(1))
        .or_insert(1);
}

fn usize_to_u32(value: usize, field: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| KgRetrievalError::InvalidRequest {
        reason: format!("{field} out of range"),
    })
}

async fn load_layer_selection_plan(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
) -> Result<LayerSelectionPlan> {
    let mut layers = load_layers(tx, request).await?;
    let all_layer_edges = load_layer_edges(tx, request).await?;
    let active_layer_edge_count = all_layer_edges
        .iter()
        .filter(|edge| edge.hygiene_state == LayerHygieneEdgeState::Active)
        .count();
    let excluded_demoted_layer_edge_count = all_layer_edges
        .iter()
        .filter(|edge| edge.hygiene_state == LayerHygieneEdgeState::Demoted)
        .count();
    let excluded_tombstoned_layer_edge_count = all_layer_edges
        .iter()
        .filter(|edge| edge.hygiene_state == LayerHygieneEdgeState::Tombstoned)
        .count();
    let active_layer_edges = all_layer_edges
        .iter()
        .filter(|edge| edge.hygiene_state == LayerHygieneEdgeState::Active)
        .cloned()
        .collect::<Vec<_>>();
    if layers.is_empty() {
        if request.layer_path.is_some() {
            return Err(KgRetrievalError::InvalidRequest {
                reason: "requested_layer_path_not_found".to_owned(),
            });
        }
        return Ok(LayerSelectionPlan::flat_fallback(request));
    }

    let max_depth = request.effective_max_layer_depth();
    let max_layers = request.effective_max_layers_selected();
    let mut layer_budget_truncated = false;
    let mut depth_budget_truncated = false;
    let mut selected_ids = BTreeSet::<String>::new();
    let mut queue = VecDeque::<(String, u32, String)>::new();
    if let Some(layer_path) = &request.layer_path {
        let Some(layer) = layers
            .values()
            .find(|layer| &layer.layer_path == layer_path)
            .cloned()
        else {
            return Err(KgRetrievalError::InvalidRequest {
                reason: "requested_layer_path_not_found".to_owned(),
            });
        };
        queue.push_back((layer.layer_id, 0, "requested_layer_path".to_owned()));
    } else {
        let mut root_layers = layers
            .values()
            .filter(|layer| layer.layer_depth == 0 || layer.layer_kind == "root")
            .cloned()
            .collect::<Vec<_>>();
        root_layers.sort_by(|left, right| {
            left.layer_path
                .cmp(&right.layer_path)
                .then(left.layer_id.cmp(&right.layer_id))
        });
        for layer in root_layers {
            queue.push_back((layer.layer_id, 0, "root_layer_start".to_owned()));
        }
    }

    while let Some((layer_id, relative_depth, reason)) = queue.pop_front() {
        if relative_depth > max_depth {
            depth_budget_truncated = true;
            continue;
        }
        if selected_ids.contains(&layer_id) {
            continue;
        }
        if usize_to_u32(selected_ids.len(), "selected layer count")? >= max_layers {
            layer_budget_truncated = true;
            continue;
        }
        let Some(layer) = layers.get_mut(&layer_id) else {
            return Err(KgRetrievalError::InvalidRequest {
                reason: "layer_edge_references_missing_layer".to_owned(),
            });
        };
        layer.traversal_rank = usize_to_u32(selected_ids.len(), "selected layer rank")?;
        layer.selection_reason = reason;
        selected_ids.insert(layer_id.clone());

        let mut outgoing = active_layer_edges
            .iter()
            .filter(|edge| {
                edge.from_layer_id == layer_id && layer_edge_traversable(&edge.edge_kind)
            })
            .cloned()
            .collect::<Vec<_>>();
        outgoing.sort_by(|left, right| {
            left.edge_kind
                .cmp(&right.edge_kind)
                .then(left.layer_edge_id.cmp(&right.layer_edge_id))
        });
        for edge in outgoing {
            if !layers.contains_key(&edge.to_layer_id) {
                return Err(KgRetrievalError::InvalidRequest {
                    reason: "layer_edge_references_missing_layer".to_owned(),
                });
            }
            if selected_ids.contains(&edge.to_layer_id) {
                continue;
            }
            let next_depth = relative_depth.saturating_add(1);
            if next_depth > max_depth {
                depth_budget_truncated = true;
                continue;
            }
            queue.push_back((
                edge.to_layer_id,
                next_depth,
                format!("traversed_layer_edge:{}", edge.edge_kind),
            ));
        }
    }

    if selected_ids.is_empty() {
        return Ok(LayerSelectionPlan::flat_fallback(request));
    }

    let mut selected_layers = layers
        .into_iter()
        .filter_map(|(layer_id, layer)| selected_ids.contains(&layer_id).then_some(layer))
        .collect::<Vec<_>>();
    selected_layers.sort_by(|left, right| {
        left.traversal_rank
            .cmp(&right.traversal_rank)
            .then(left.layer_depth.cmp(&right.layer_depth))
            .then(left.layer_path.cmp(&right.layer_path))
    });

    let mut selected_layer_edges = active_layer_edges
        .into_iter()
        .filter(|edge| {
            selected_ids.contains(&edge.from_layer_id) && selected_ids.contains(&edge.to_layer_id)
        })
        .collect::<Vec<_>>();
    selected_layer_edges.sort_by(|left, right| {
        left.layer_edge_id
            .cmp(&right.layer_edge_id)
            .then(left.from_layer_id.cmp(&right.from_layer_id))
            .then(left.to_layer_id.cmp(&right.to_layer_id))
    });
    let max_layer_edges = usize::try_from(request.effective_max_layer_edges()).map_err(|_| {
        KgRetrievalError::InvalidRequest {
            reason: "max_layer_edges out of range".to_owned(),
        }
    })?;
    let layer_edge_budget_truncated = selected_layer_edges.len() > max_layer_edges;
    selected_layer_edges.truncate(max_layer_edges);

    let mut memory_layers = load_layer_memberships(tx, request, &selected_ids).await?;
    let layer_rank = selected_layers
        .iter()
        .map(|layer| (layer.layer_id.clone(), layer.clone()))
        .collect::<BTreeMap<_, _>>();
    for memberships in memory_layers.values_mut() {
        for membership in &mut *memberships {
            let Some(layer) = layer_rank.get(&membership.layer_id) else {
                continue;
            };
            membership.traversal_rank = layer.traversal_rank;
            membership.memory_selection_reason = layer.selection_reason.clone();
            // PRD-D2 S2: resolve to the persisted aggregate handle when present.
            membership.rollup_summary_ref = Some(layer.resolved_rollup_summary_ref());
        }
        memberships.sort_by(|left, right| {
            left.traversal_rank
                .cmp(&right.traversal_rank)
                .then(left.local_node_rank.cmp(&right.local_node_rank))
                .then(right.layer_depth.cmp(&left.layer_depth))
                .then(left.layer_path.cmp(&right.layer_path))
        });
    }
    Ok(LayerSelectionPlan {
        selected_layers,
        selected_layer_edges,
        memory_layers,
        flat_fallback_used: false,
        depth_budget_truncated,
        layer_budget_truncated,
        node_budget_truncated: false,
        layer_edge_budget_truncated,
        active_layer_edge_count,
        excluded_demoted_layer_edge_count,
        excluded_tombstoned_layer_edge_count,
    })
}

fn layer_edge_traversable(edge_kind: &str) -> bool {
    matches!(
        edge_kind,
        "contains_subgraph" | "drills_down_to" | "cross_layer_ref" | "summarizes_layer"
    )
}

fn build_rollup_summaries(
    selected_layers: &[KgSelectedLayerRef],
    memories: &BTreeMap<String, RetrievedMemory>,
    selected_memory_ids: &BTreeSet<String>,
    layer_aggregates: &BTreeMap<String, RetrievedLayerAggregate>,
) -> Result<Vec<KgRollupSummaryRef>> {
    let mut rollups = Vec::new();
    for layer in selected_layers {
        // Membership-triggered (D1-S3): a rollup fires when the layer's root
        // memory was itself selected OR when any selected memory belongs to the
        // layer (`selected_memory_count > 0`) — the same membership signal that
        // triggers drilldown. This lights up the previously-inert rollup path on
        // corpora whose cluster roots never win breadth selection.
        // (PRD-D2 S2 deferred to this D1 sibling on WHEN the rollup fires; it
        // only changes WHAT it reads below.)
        let root_selected = selected_memory_ids.contains(&layer.root_memory_id);
        let membership_triggered = layer.selected_memory_count > 0;
        if !root_selected && !membership_triggered {
            continue;
        }
        let Some(memory) = memories.get(&layer.root_memory_id) else {
            continue;
        };
        // Rollups must not bypass memory-selection filters: only emit safe
        // metadata for root memories that pass the same status/validation
        // containment rules the breadth selection applies (kg_retrieval.rs:176,
        // 185). A membership-triggered rollup must never surface a root the
        // breadth pass would have filtered out. (PRD-D1 containment — runs
        // before the PRD-D2 aggregate read so a filtered root never surfaces
        // any summary, persisted aggregate or otherwise.)
        if !memory_status_allowed(&memory.status)
            || validation_status_blocked(&memory.validation_status)
        {
            continue;
        }
        // PRD-D2 S2: surface the persisted layer-policy v2 aggregate root
        // summary when the layer carries one — a faithful digest of the layer's
        // members — instead of reusing the root member's own (often stub)
        // summary. When no aggregate is persisted (unmigrated / not-yet-
        // re-derived layer) fall back to the prior root-member behavior. The
        // `rollup_summary_ref` resolves to the aggregate handle in the former
        // case and to the legacy layer-rollup handle in the latter.
        let (title, summary, selection_reason, rollup_summary_ref) =
            match layer_aggregates.get(&layer.layer_id) {
                Some(aggregate) => (
                    aggregate.title.clone(),
                    aggregate.summary.clone(),
                    "layer_aggregate_summary".to_owned(),
                    format!("layer-aggregate:{}", layer.layer_id),
                ),
                None => (
                    memory.title.clone(),
                    memory.summary.clone(),
                    "layer_root_memory_summary".to_owned(),
                    layer
                        .rollup_summary_ref
                        .clone()
                        .unwrap_or_else(|| format!("layer-rollup:{}", layer.layer_id)),
                ),
            };
        rollups.push(KgRollupSummaryRef {
            rollup_summary_ref,
            layer_id: layer.layer_id.clone(),
            layer_path: layer.layer_path.clone(),
            memory_id: layer.root_memory_id.clone(),
            title,
            summary,
            selection_reason,
        });
    }
    Ok(rollups)
}

async fn load_memories(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
) -> Result<BTreeMap<String, RetrievedMemory>> {
    let rows = sqlx::query(
        "SELECT memory_id, title, summary, risk_class, status, validation_status, \
                council_status, dag_finality_status, latest_receipt_hash \
         FROM dagdb_memory_objects \
         WHERE tenant_id = $1 AND namespace = $2 \
         ORDER BY memory_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;
    let mut memories = BTreeMap::new();
    for row in rows {
        let memory_id = hex_from_hash_column("memory_id", row.try_get("memory_id").map_err(pg)?)?;
        let title = safe_metadata_from_value(row.try_get("title").map_err(pg)?)?;
        let summary = safe_metadata_from_value(row.try_get("summary").map_err(pg)?)?;
        let latest_receipt_hash = hex_from_hash_column(
            "latest_receipt_hash",
            row.try_get("latest_receipt_hash").map_err(pg)?,
        )?;
        memories.insert(
            memory_id,
            RetrievedMemory {
                title,
                summary,
                risk_class: row.try_get("risk_class").map_err(pg)?,
                status: row.try_get("status").map_err(pg)?,
                validation_status: row.try_get("validation_status").map_err(pg)?,
                council_status: row.try_get("council_status").map_err(pg)?,
                dag_finality_status: row.try_get("dag_finality_status").map_err(pg)?,
                latest_receipt_hash,
            },
        );
    }
    Ok(memories)
}

async fn load_catalogs(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
) -> Result<BTreeMap<String, RetrievedCatalog>> {
    let rows = sqlx::query(
        "SELECT catalog_id, memory_id \
         FROM dagdb_catalog_entries \
         WHERE tenant_id = $1 AND namespace = $2 AND memory_id IS NOT NULL \
         ORDER BY memory_id, catalog_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;
    let mut catalogs = BTreeMap::new();
    for row in rows {
        let memory_id =
            hex_from_hash_column("catalog.memory_id", row.try_get("memory_id").map_err(pg)?)?;
        let catalog_id =
            hex_from_hash_column("catalog_id", row.try_get("catalog_id").map_err(pg)?)?;
        catalogs
            .entry(memory_id)
            .or_insert(RetrievedCatalog { catalog_id });
    }
    Ok(catalogs)
}

async fn load_graph_nodes(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
) -> Result<BTreeMap<String, Vec<RetrievedGraphNode>>> {
    let rows = sqlx::query(
        "SELECT graph_node_id, memory_id, catalog_path \
         FROM dagdb_graph_nodes \
         WHERE tenant_id = $1 AND namespace = $2 \
         ORDER BY memory_id, graph_node_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;
    let mut graph_nodes: BTreeMap<String, Vec<RetrievedGraphNode>> = BTreeMap::new();
    for row in rows {
        let memory_id = hex_from_hash_column(
            "graph_node.memory_id",
            row.try_get("memory_id").map_err(pg)?,
        )?;
        let graph_node_id =
            hex_from_hash_column("graph_node_id", row.try_get("graph_node_id").map_err(pg)?)?;
        let catalog_path = row
            .try_get::<Option<String>, _>("catalog_path")
            .map_err(pg)?
            .unwrap_or_default();
        graph_nodes
            .entry(memory_id)
            .or_default()
            .push(RetrievedGraphNode {
                graph_node_id,
                catalog_path,
            });
    }
    Ok(graph_nodes)
}

async fn load_layers(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
) -> Result<BTreeMap<String, RetrievedLayer>> {
    let rows = match sqlx::query(
        "SELECT layer_id, root_memory_id, parent_layer_id, parent_graph_node_id, \
                layer_depth, layer_kind, graph_style, layer_path, aggregate_summary \
         FROM dagdb_graph_layers \
         WHERE tenant_id = $1 AND namespace = $2 \
         ORDER BY layer_depth, layer_path, layer_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_undefined_table(&error) => {
            return Err(required_layer_schema_missing());
        }
        Err(error) => return Err(pg(error)),
    };
    let mut layers = BTreeMap::new();
    for row in rows {
        let layer_id = hex_from_hash_column("layer_id", row.try_get("layer_id").map_err(pg)?)?;
        let root_memory_id = hex_from_hash_column(
            "layer.root_memory_id",
            row.try_get("root_memory_id").map_err(pg)?,
        )?;
        let parent_layer_id = row
            .try_get::<Option<Vec<u8>>, _>("parent_layer_id")
            .map_err(pg)?
            .map(|hash| hex_from_hash_column("parent_layer_id", hash))
            .transpose()?;
        let parent_graph_node_id = row
            .try_get::<Option<Vec<u8>>, _>("parent_graph_node_id")
            .map_err(pg)?
            .map(|hash| hex_from_hash_column("parent_graph_node_id", hash))
            .transpose()?;
        let layer_depth: i32 = row.try_get("layer_depth").map_err(pg)?;
        // PRD-D2 S2: parse the persisted layer-policy v2 aggregate root summary
        // (nullable). When present the rollup path surfaces THIS aggregate
        // instead of reusing the root member's own (often stub) summary; when
        // absent (unmigrated / not-yet-re-derived layer) the rollup falls back
        // to the prior root-member behavior, so unmigrated rows stay valid.
        let aggregate_summary = row
            .try_get::<Option<JsonValue>, _>("aggregate_summary")
            .map_err(pg)?
            .map(parse_layer_aggregate_summary)
            .transpose()?
            .flatten();
        layers.insert(
            layer_id.clone(),
            RetrievedLayer {
                layer_id,
                root_memory_id,
                parent_layer_id,
                parent_graph_node_id,
                layer_depth: u32::try_from(layer_depth).map_err(|_| {
                    KgRetrievalError::InvalidRequest {
                        reason: "layer_depth out of range".to_owned(),
                    }
                })?,
                layer_kind: row.try_get("layer_kind").map_err(pg)?,
                graph_style: row.try_get("graph_style").map_err(pg)?,
                layer_path: row.try_get("layer_path").map_err(pg)?,
                traversal_rank: u32::MAX,
                selection_reason: "not_selected".to_owned(),
                rollup_summary_ref: None,
                aggregate_summary,
            },
        );
    }
    Ok(layers)
}

async fn load_layer_edges(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
) -> Result<Vec<RetrievedLayerEdge>> {
    let rows = match sqlx::query(
        "SELECT layer_edge_id, graph_style, from_layer_id, to_layer_id, edge_kind, receipt_hash, metadata \
         FROM dagdb_graph_layer_edges \
         WHERE tenant_id = $1 AND namespace = $2 \
         ORDER BY layer_edge_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_undefined_table(&error) => {
            return Err(required_layer_schema_missing());
        }
        Err(error) => return Err(pg(error)),
    };
    let mut edges = Vec::new();
    for row in rows {
        let receipt_hash = row
            .try_get::<Option<Vec<u8>>, _>("receipt_hash")
            .map_err(pg)?
            .map(|hash| hex_from_hash_column("layer_edge.receipt_hash", hash))
            .transpose()?;
        edges.push(RetrievedLayerEdge {
            layer_edge_id: hex_from_hash_column(
                "layer_edge_id",
                row.try_get("layer_edge_id").map_err(pg)?,
            )?,
            graph_style: row.try_get("graph_style").map_err(pg)?,
            from_layer_id: hex_from_hash_column(
                "layer_edge.from_layer_id",
                row.try_get("from_layer_id").map_err(pg)?,
            )?,
            to_layer_id: hex_from_hash_column(
                "layer_edge.to_layer_id",
                row.try_get("to_layer_id").map_err(pg)?,
            )?,
            edge_kind: row.try_get("edge_kind").map_err(pg)?,
            receipt_hash,
            hygiene_state: parse_layer_edge_hygiene_state(row.try_get("metadata").map_err(pg)?)?,
        });
    }
    Ok(edges)
}

async fn load_layer_memberships(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
    selected_layer_ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<RetrievedLayerMembership>>> {
    if selected_layer_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = match sqlx::query(
        "SELECT node.memory_id, membership.layer_id, layer.layer_path, layer.layer_depth, \
                layer.layer_kind, layer.graph_style, \
                membership.membership_role, membership.local_node_rank \
         FROM dagdb_graph_layer_memberships membership \
         JOIN dagdb_graph_layers layer \
           ON layer.tenant_id = membership.tenant_id \
          AND layer.namespace = membership.namespace \
          AND layer.layer_id = membership.layer_id \
         JOIN dagdb_graph_nodes node \
           ON node.tenant_id = membership.tenant_id \
          AND node.namespace = membership.namespace \
         AND node.graph_node_id = membership.graph_node_id \
         WHERE membership.tenant_id = $1 AND membership.namespace = $2 \
         ORDER BY node.memory_id, layer.layer_depth, layer.layer_path, \
                  membership.local_node_rank, membership.membership_role, membership.layer_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_undefined_table(&error) => {
            return Err(required_layer_schema_missing());
        }
        Err(error) => return Err(pg(error)),
    };
    let mut memberships: BTreeMap<String, Vec<RetrievedLayerMembership>> = BTreeMap::new();
    for row in rows {
        let memory_id = hex_from_hash_column(
            "layer_membership.memory_id",
            row.try_get("memory_id").map_err(pg)?,
        )?;
        let layer_id = hex_from_hash_column(
            "layer_membership.layer_id",
            row.try_get("layer_id").map_err(pg)?,
        )?;
        if !selected_layer_ids.contains(&layer_id) {
            continue;
        }
        let layer_depth: i32 = row.try_get("layer_depth").map_err(pg)?;
        let local_node_rank: i32 = row.try_get("local_node_rank").map_err(pg)?;
        memberships
            .entry(memory_id)
            .or_default()
            .push(RetrievedLayerMembership {
                layer_id,
                layer_path: row.try_get("layer_path").map_err(pg)?,
                layer_depth: u32::try_from(layer_depth).map_err(|_| {
                    KgRetrievalError::InvalidRequest {
                        reason: "layer_depth out of range".to_owned(),
                    }
                })?,
                layer_kind: row.try_get("layer_kind").map_err(pg)?,
                graph_style: row.try_get("graph_style").map_err(pg)?,
                membership_role: row.try_get("membership_role").map_err(pg)?,
                local_node_rank: u32::try_from(local_node_rank).map_err(|_| {
                    KgRetrievalError::InvalidRequest {
                        reason: "local_node_rank out of range".to_owned(),
                    }
                })?,
                traversal_rank: u32::MAX,
                memory_selection_reason: "selected_layer_member".to_owned(),
                rollup_summary_ref: None,
            });
    }
    Ok(memberships)
}

async fn load_validation_reports(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
) -> Result<BTreeMap<String, Vec<String>>> {
    let rows = sqlx::query(
        "SELECT validation_report_id, subject_id \
         FROM dagdb_validation_reports \
         WHERE tenant_id = $1 AND namespace = $2 AND subject_kind = 'memory' \
         ORDER BY subject_id, validation_report_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;
    let mut reports: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        let memory_id = hex_from_hash_column(
            "validation.subject_id",
            row.try_get("subject_id").map_err(pg)?,
        )?;
        let report_id = hex_from_hash_column(
            "validation_report_id",
            row.try_get("validation_report_id").map_err(pg)?,
        )?;
        reports.entry(memory_id).or_default().push(report_id);
    }
    Ok(reports)
}

async fn load_graph_edges(
    tx: &mut Transaction<'_, Postgres>,
    request: &KgRetrievalRequest,
    selected_memory_ids: &[String],
) -> Result<Vec<KgGraphEdgeRef>> {
    let selected = selected_memory_ids.iter().cloned().collect::<BTreeSet<_>>();
    if selected.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT graph_edge_id, graph_style, from_memory_id, to_memory_id, edge_kind, receipt_hash \
         FROM dagdb_graph_edges edge \
         WHERE edge.tenant_id = $1 AND edge.namespace = $2 \
           AND NOT EXISTS ( \
             SELECT 1 FROM dagdb_graph_edge_tombstones tombstone \
             WHERE tombstone.tenant_id = edge.tenant_id \
               AND tombstone.namespace = edge.namespace \
               AND tombstone.prior_edge_id = edge.graph_edge_id \
           ) \
         ORDER BY graph_edge_id",
    )
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(pg)?;
    let mut edges = Vec::new();
    for row in rows {
        let from_memory_id = hex_from_hash_column(
            "edge.from_memory_id",
            row.try_get("from_memory_id").map_err(pg)?,
        )?;
        let to_memory_id = hex_from_hash_column(
            "edge.to_memory_id",
            row.try_get("to_memory_id").map_err(pg)?,
        )?;
        if !selected.contains(&from_memory_id) || !selected.contains(&to_memory_id) {
            continue;
        }
        let receipt_hash = row
            .try_get::<Option<Vec<u8>>, _>("receipt_hash")
            .map_err(pg)?
            .map(|hash| hex_from_hash_column("edge.receipt_hash", hash))
            .transpose()?;
        edges.push(KgGraphEdgeRef {
            graph_edge_id: hex_from_hash_column(
                "graph_edge_id",
                row.try_get("graph_edge_id").map_err(pg)?,
            )?,
            from_memory_id,
            to_memory_id,
            edge_kind: row.try_get("edge_kind").map_err(pg)?,
            graph_style: row.try_get("graph_style").map_err(pg)?,
            receipt_hash,
        });
    }
    Ok(edges)
}

#[derive(Debug, Clone)]
struct RetrievedMemory {
    title: SafeMetadata,
    summary: SafeMetadata,
    risk_class: String,
    status: String,
    validation_status: String,
    council_status: String,
    dag_finality_status: String,
    latest_receipt_hash: String,
}

#[derive(Debug, Clone)]
struct RetrievedCatalog {
    catalog_id: String,
}

#[derive(Debug, Clone)]
struct RetrievedGraphNode {
    graph_node_id: String,
    catalog_path: String,
}

#[derive(Debug, Clone)]
struct RetrievedLayer {
    layer_id: String,
    root_memory_id: String,
    parent_layer_id: Option<String>,
    parent_graph_node_id: Option<String>,
    layer_depth: u32,
    layer_kind: String,
    graph_style: String,
    layer_path: String,
    traversal_rank: u32,
    selection_reason: String,
    rollup_summary_ref: Option<String>,
    /// PRD-D2 S2: persisted layer-policy v2 aggregate root summary, when the
    /// layer carries one. Surfaced by the rollup path instead of the root
    /// member's own summary.
    aggregate_summary: Option<RetrievedLayerAggregate>,
}

impl RetrievedLayer {
    /// PRD-D2 S2: resolve the rollup-summary handle for this layer. When the
    /// layer carries a persisted aggregate root summary the ref resolves to the
    /// aggregate handle (`layer-aggregate:{layer_id}`); otherwise it resolves to
    /// the explicit `rollup_summary_ref` or the legacy `layer-rollup:{layer_id}`
    /// handle, preserving prior behavior for unmigrated layers.
    fn resolved_rollup_summary_ref(&self) -> String {
        if self.aggregate_summary.is_some() {
            return format!("layer-aggregate:{}", self.layer_id);
        }
        self.rollup_summary_ref
            .clone()
            .unwrap_or_else(|| format!("layer-rollup:{}", self.layer_id))
    }
}

/// PRD-D2 S2: the safe-metadata-shaped aggregate root summary persisted on a
/// layer (`dagdb_graph_layers.aggregate_summary`). Parsed from the stored JSONB
/// object; both `title` and `summary` are `SafeMetadata` so the rollup surfaces
/// the same shape as a member summary.
#[derive(Debug, Clone)]
struct RetrievedLayerAggregate {
    title: SafeMetadata,
    summary: SafeMetadata,
}

#[derive(Debug, Clone)]
struct RetrievedLayerEdge {
    layer_edge_id: String,
    graph_style: String,
    from_layer_id: String,
    to_layer_id: String,
    edge_kind: String,
    receipt_hash: Option<String>,
    hygiene_state: LayerHygieneEdgeState,
}

#[derive(Debug, Clone)]
struct RetrievedLayerMembership {
    layer_id: String,
    layer_path: String,
    layer_depth: u32,
    layer_kind: String,
    graph_style: String,
    membership_role: String,
    local_node_rank: u32,
    traversal_rank: u32,
    memory_selection_reason: String,
    rollup_summary_ref: Option<String>,
}

#[derive(Debug, Clone)]
struct LayerSelectionPlan {
    selected_layers: Vec<RetrievedLayer>,
    selected_layer_edges: Vec<RetrievedLayerEdge>,
    memory_layers: BTreeMap<String, Vec<RetrievedLayerMembership>>,
    flat_fallback_used: bool,
    depth_budget_truncated: bool,
    layer_budget_truncated: bool,
    node_budget_truncated: bool,
    layer_edge_budget_truncated: bool,
    active_layer_edge_count: usize,
    excluded_demoted_layer_edge_count: usize,
    excluded_tombstoned_layer_edge_count: usize,
}

impl LayerSelectionPlan {
    fn flat_fallback(_request: &KgRetrievalRequest) -> Self {
        Self {
            selected_layers: Vec::new(),
            selected_layer_edges: Vec::new(),
            memory_layers: BTreeMap::new(),
            flat_fallback_used: true,
            depth_budget_truncated: false,
            layer_budget_truncated: false,
            node_budget_truncated: false,
            layer_edge_budget_truncated: false,
            active_layer_edge_count: 0,
            excluded_demoted_layer_edge_count: 0,
            excluded_tombstoned_layer_edge_count: 0,
        }
    }

    fn best_memory_layer(&self, memory_id: &str) -> Option<&RetrievedLayerMembership> {
        self.memory_layers
            .get(memory_id)
            .and_then(|memberships| memberships.first())
    }

    /// PRD-D2 S2: index each selected layer's persisted aggregate root summary
    /// by `layer_id`, for the rollup builder to surface in place of the root
    /// member's own summary.
    fn aggregate_summaries_by_layer(&self) -> BTreeMap<String, RetrievedLayerAggregate> {
        self.selected_layers
            .iter()
            .filter_map(|layer| {
                layer
                    .aggregate_summary
                    .clone()
                    .map(|aggregate| (layer.layer_id.clone(), aggregate))
            })
            .collect()
    }

    fn selected_layer_refs(
        &self,
        selected_per_layer: &BTreeMap<String, u32>,
    ) -> Result<Vec<KgSelectedLayerRef>> {
        let refs = self
            .selected_layers
            .iter()
            .map(|layer| {
                Ok(KgSelectedLayerRef {
                    layer_id: layer.layer_id.clone(),
                    layer_path: layer.layer_path.clone(),
                    layer_depth: layer.layer_depth,
                    layer_kind: layer.layer_kind.clone(),
                    graph_style: layer.graph_style.clone(),
                    root_memory_id: layer.root_memory_id.clone(),
                    parent_layer_id: layer.parent_layer_id.clone(),
                    parent_graph_node_id: layer.parent_graph_node_id.clone(),
                    selection_reason: layer.selection_reason.clone(),
                    selected_memory_count: *selected_per_layer.get(&layer.layer_id).unwrap_or(&0),
                    // PRD-D2 S2: resolve to the persisted aggregate handle when
                    // the layer carries an aggregate root summary.
                    rollup_summary_ref: Some(layer.resolved_rollup_summary_ref()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(refs)
    }

    fn selected_layer_edge_refs(&self) -> Result<Vec<KgLayerEdgeRef>> {
        Ok(self
            .selected_layer_edges
            .iter()
            .map(|edge| KgLayerEdgeRef {
                layer_edge_id: edge.layer_edge_id.clone(),
                from_layer_id: edge.from_layer_id.clone(),
                to_layer_id: edge.to_layer_id.clone(),
                edge_kind: edge.edge_kind.clone(),
                graph_style: edge.graph_style.clone(),
                receipt_hash: edge.receipt_hash.clone(),
                selection_reason: "selected_edge_between_selected_layers".to_owned(),
            })
            .collect())
    }
}

fn split_catalog_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn safe_metadata_from_value(value: JsonValue) -> Result<SafeMetadata> {
    serde_json::from_value(value).map_err(|error| KgRetrievalError::Json {
        reason: error.to_string(),
    })
}

/// PRD-D2 S2: parse the persisted aggregate root summary JSONB into its
/// safe-metadata-shaped title/summary.
///
/// Returns `Ok(None)` when the stored object does not carry both a `title` and
/// a `summary` key (legacy / partially-written rows) so retrieval degrades to
/// the prior root-member rollup rather than failing. Returns an error only when
/// the keys are present but malformed, so corruption fails closed.
fn parse_layer_aggregate_summary(value: JsonValue) -> Result<Option<RetrievedLayerAggregate>> {
    let JsonValue::Object(object) = value else {
        return Ok(None);
    };
    let (Some(title_value), Some(summary_value)) = (object.get("title"), object.get("summary"))
    else {
        return Ok(None);
    };
    let title = safe_metadata_from_value(title_value.clone())?;
    let summary = safe_metadata_from_value(summary_value.clone())?;
    Ok(Some(RetrievedLayerAggregate { title, summary }))
}

fn parse_layer_edge_hygiene_state(metadata: JsonValue) -> Result<LayerHygieneEdgeState> {
    let Some(state) = metadata.get("hygiene_state") else {
        return Err(KgRetrievalError::InvalidRequest {
            reason: "missing_layer_edge_hygiene_state".to_owned(),
        });
    };
    let Some(state) = state.as_str() else {
        return Err(KgRetrievalError::InvalidRequest {
            reason: "invalid_layer_edge_hygiene_state".to_owned(),
        });
    };
    state.parse().map_err(|_| KgRetrievalError::InvalidRequest {
        reason: "invalid_layer_edge_hygiene_state".to_owned(),
    })
}

fn required_layer_schema_missing() -> KgRetrievalError {
    KgRetrievalError::InvalidRequest {
        reason: "required_layer_schema_missing".to_owned(),
    }
}

fn pg(source: sqlx::Error) -> KgRetrievalError {
    KgRetrievalError::Postgres {
        source: Box::new(source),
    }
}

fn is_undefined_table(source: &sqlx::Error) -> bool {
    matches!(
        source,
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("42P01")
    )
}

#[cfg(test)]
mod tests {
    use exo_dag_db_api::SafeMetadataDecision;

    use super::*;

    fn memory(text: &str) -> RetrievedMemory {
        memory_with_status(text, "routable", "passed")
    }

    fn memory_with_status(text: &str, status: &str, validation_status: &str) -> RetrievedMemory {
        let metadata = SafeMetadata {
            decision: SafeMetadataDecision::Allow,
            text: text.to_owned(),
            redaction_codes: Vec::new(),
            original_hash: "c".repeat(64),
            truncated: false,
            byte_len: u32::try_from(text.len()).unwrap_or(0),
        };
        RetrievedMemory {
            title: metadata.clone(),
            summary: metadata,
            risk_class: "R1".to_owned(),
            status: status.to_owned(),
            validation_status: validation_status.to_owned(),
            council_status: "not_required".to_owned(),
            dag_finality_status: "pending".to_owned(),
            latest_receipt_hash: "d".repeat(64),
        }
    }

    fn selected_layer(
        layer_id: &str,
        root_memory_id: &str,
        selected_memory_count: u32,
    ) -> KgSelectedLayerRef {
        KgSelectedLayerRef {
            layer_id: layer_id.to_owned(),
            layer_path: "root".to_owned(),
            layer_depth: 0,
            layer_kind: "root".to_owned(),
            graph_style: "semantic_catalog_graph".to_owned(),
            root_memory_id: root_memory_id.to_owned(),
            parent_layer_id: None,
            parent_graph_node_id: None,
            selection_reason: "layer_path_filter".to_owned(),
            selected_memory_count,
            rollup_summary_ref: None,
        }
    }

    fn safe_meta(text: &str) -> SafeMetadata {
        SafeMetadata {
            decision: SafeMetadataDecision::Allow,
            text: text.to_owned(),
            redaction_codes: Vec::new(),
            original_hash: "e".repeat(64),
            truncated: false,
            byte_len: u32::try_from(text.len()).unwrap_or(0),
        }
    }

    fn aggregate(title: &str, summary: &str) -> RetrievedLayerAggregate {
        RetrievedLayerAggregate {
            title: safe_meta(title),
            summary: safe_meta(summary),
        }
    }

    #[test]
    fn rollup_summaries_exclude_layers_with_no_selected_member() {
        // A layer whose root is not selected AND has no selected member
        // (selected_memory_count == 0) must be excluded; the layer whose root is
        // selected stays.
        let selected_root = "a".repeat(64);
        let untouched_root = "b".repeat(64);
        let mut memories = BTreeMap::new();
        memories.insert(selected_root.clone(), memory("selected root"));
        memories.insert(untouched_root.clone(), memory("untouched root"));
        let layers = vec![
            selected_layer(&"1".repeat(64), &selected_root, 1),
            selected_layer(&"2".repeat(64), &untouched_root, 0),
        ];
        let selected_memory_ids = std::iter::once(selected_root.clone()).collect::<BTreeSet<_>>();
        let aggregates = BTreeMap::new();

        let rollups = build_rollup_summaries(&layers, &memories, &selected_memory_ids, &aggregates)
            .expect("rollup summaries");

        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].memory_id, selected_root);
        assert_eq!(rollups[0].summary.text, "selected root");
    }

    #[test]
    fn rollup_summaries_fire_when_a_selected_member_belongs_to_the_layer() {
        // Membership-triggered (D1-S3): the layer's root is NOT in the selected
        // set, but a selected memory belongs to the layer (selected_memory_count
        // > 0), so the rollup must fire and surface the root memory's summary.
        let cluster_root = "b".repeat(64);
        let mut memories = BTreeMap::new();
        memories.insert(cluster_root.clone(), memory("cluster root summary"));
        let layers = vec![selected_layer(&"2".repeat(64), &cluster_root, 1)];
        // The selected memory is a member, not the root itself.
        let selected_memory_ids = std::iter::once("f".repeat(64)).collect::<BTreeSet<_>>();
        let aggregates = BTreeMap::new();

        let rollups = build_rollup_summaries(&layers, &memories, &selected_memory_ids, &aggregates)
            .expect("rollup summaries");

        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].memory_id, cluster_root);
        assert_eq!(rollups[0].summary.text, "cluster root summary");
    }

    #[test]
    fn rollup_summaries_never_surface_a_status_blocked_root() {
        // Membership-triggering must NOT bypass the breadth selection's
        // status/validation containment: a layer whose root memory is blocked is
        // excluded even when a selected member triggers it.
        let blocked_root = "b".repeat(64);
        let mut memories = BTreeMap::new();
        memories.insert(
            blocked_root.clone(),
            memory_with_status("blocked root", "archived", "passed"),
        );
        let layers = vec![selected_layer(&"2".repeat(64), &blocked_root, 1)];
        let selected_memory_ids = std::iter::once("f".repeat(64)).collect::<BTreeSet<_>>();
        let aggregates = BTreeMap::new();

        let rollups = build_rollup_summaries(&layers, &memories, &selected_memory_ids, &aggregates)
            .expect("rollup summaries");

        assert!(
            rollups.is_empty(),
            "a membership-triggered rollup must not surface a status-blocked root"
        );
    }

    #[test]
    fn rollup_summaries_never_surface_a_status_blocked_root_carrying_an_aggregate() {
        // PRD-D2 review F5: containment must structurally PRECEDE the aggregate
        // read. A status-blocked root that ALSO carries a persisted aggregate must
        // still be excluded — the aggregate must never leak past the
        // status/validation gate. If a future reorder moved the aggregate read
        // (kg_retrieval.rs ~:1169) above the containment check (~:1157), this
        // blocked root would surface its aggregate digest and this test FAILS.
        let blocked_root = "b".repeat(64);
        let layer_id = "2".repeat(64);
        let mut memories = BTreeMap::new();
        memories.insert(
            blocked_root.clone(),
            memory_with_status("blocked root", "archived", "passed"),
        );
        let layers = vec![selected_layer(&layer_id, &blocked_root, 1)];
        let selected_memory_ids = std::iter::once("f".repeat(64)).collect::<BTreeSet<_>>();
        // The blocked layer DOES carry a persisted aggregate. Containment runs
        // first, so this aggregate must never be read or surfaced.
        let mut aggregates = BTreeMap::new();
        aggregates.insert(
            layer_id.clone(),
            aggregate(
                "Leaked Aggregate Title",
                "Leaked aggregate digest of members.",
            ),
        );

        let rollups = build_rollup_summaries(&layers, &memories, &selected_memory_ids, &aggregates)
            .expect("rollup summaries");

        assert!(
            rollups.is_empty(),
            "a status-blocked root must not surface its persisted aggregate; \
             containment must precede the aggregate read"
        );
        // Defensive: even if some row leaked, it must never carry the aggregate
        // digest (this is what a reorder of the aggregate read above containment
        // would produce).
        assert!(
            rollups
                .iter()
                .all(|r| r.summary.text != "Leaked aggregate digest of members."),
            "the blocked layer's aggregate digest leaked past containment"
        );
    }

    #[test]
    fn rollup_summaries_keep_selected_root_memories() {
        let root = "a".repeat(64);
        let mut memories = BTreeMap::new();
        memories.insert(root.clone(), memory("selected root"));
        let layers = vec![selected_layer(&"1".repeat(64), &root, 1)];
        let selected_memory_ids = std::iter::once(root.clone()).collect::<BTreeSet<_>>();
        let aggregates = BTreeMap::new();

        let rollups = build_rollup_summaries(&layers, &memories, &selected_memory_ids, &aggregates)
            .expect("rollup summaries");

        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].selection_reason, "layer_root_memory_summary");
    }

    #[test]
    fn rollup_summaries_surface_persisted_aggregate_not_stub_member() {
        // PRD-D2 S2: when a layer carries a persisted aggregate, the rollup
        // surfaces the aggregate digest, NOT the root member's own stub summary.
        let root = "a".repeat(64);
        let layer_id = "1".repeat(64);
        let mut memories = BTreeMap::new();
        // The root member's own summary is a stub (e.g. a license header).
        memories.insert(root.clone(), memory("Apache license header stub"));
        let layers = vec![selected_layer(&layer_id, &root, 1)];
        let selected_memory_ids = std::iter::once(root.clone()).collect::<BTreeSet<_>>();
        let mut aggregates = BTreeMap::new();
        aggregates.insert(
            layer_id.clone(),
            aggregate(
                "Crates Layer Aggregate",
                "Retrieval Module. Layer Policy. Identifier `PRD09`.",
            ),
        );

        let rollups = build_rollup_summaries(&layers, &memories, &selected_memory_ids, &aggregates)
            .expect("rollup summaries");

        assert_eq!(rollups.len(), 1);
        // The aggregate summary is surfaced, not the stub member summary.
        assert_eq!(
            rollups[0].summary.text,
            "Retrieval Module. Layer Policy. Identifier `PRD09`."
        );
        assert_eq!(rollups[0].title.text, "Crates Layer Aggregate");
        assert_eq!(rollups[0].selection_reason, "layer_aggregate_summary");
        assert_eq!(
            rollups[0].rollup_summary_ref,
            format!("layer-aggregate:{layer_id}")
        );
        // The stub member summary never appears.
        assert_ne!(rollups[0].summary.text, "Apache license header stub");
    }

    #[test]
    fn resolved_rollup_summary_ref_prefers_aggregate_handle() {
        let layer_id = "f".repeat(64);
        let mut layer = RetrievedLayer {
            layer_id: layer_id.clone(),
            root_memory_id: "a".repeat(64),
            parent_layer_id: None,
            parent_graph_node_id: None,
            layer_depth: 1,
            layer_kind: "source_subgraph".to_owned(),
            graph_style: "semantic_catalog_graph".to_owned(),
            layer_path: "root/crates".to_owned(),
            traversal_rank: 0,
            selection_reason: "layer_path_filter".to_owned(),
            rollup_summary_ref: None,
            aggregate_summary: None,
        };
        // No aggregate -> legacy handle.
        assert_eq!(
            layer.resolved_rollup_summary_ref(),
            format!("layer-rollup:{layer_id}")
        );
        // With aggregate -> aggregate handle.
        layer.aggregate_summary = Some(aggregate("t", "Definition line."));
        assert_eq!(
            layer.resolved_rollup_summary_ref(),
            format!("layer-aggregate:{layer_id}")
        );
    }
}

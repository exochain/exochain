//! DAG DB MCP tools — the canonical agent-facing surface.
//!
//! These twelve tools (`dagdb_intake`, `dagdb_route`,
//! `dagdb_get_context_packet`, `dagdb_validate`, `dagdb_submit_writeback`,
//! `dagdb_import`, `dagdb_export`, `dagdb_trust_check`,
//! `dagdb_council_decision`, `dagdb_receipt_lookup`, `dagdb_catalog_lookup`,
//! and `dagdb_route_lookup`) are the unified Rust home for the DAG DB MCP
//! surface (GAP-012 P1-C). They supersede the legacy, unversioned,
//! markdown-returning sidecar surface while keeping this upstream package
//! self-contained.
//!
//! Each tool's `input_schema` is BOUND to the versioned `exo-api` DAG DB
//! request DTOs plus explicit gateway signature-header carrier fields. A
//! schema-drift test (`tests::schemas_stay_bound_to_exo_api_dtos`) validates
//! the shared `exo-dag-db` JSON fixtures against the compiled schemas and
//! round-trips them through the DTOs, so a DTO field add/remove/rename fails
//! the test instead of silently drifting. Signature carrier fields are stripped
//! before DTO deserialization and are forwarded only as gateway headers.
//!
//! ## Runtime gateway boundary (T6) and the proxy
//!
//! Default node builds compile the DAG DB gateway proxy transport. When no
//! operator has configured a DAG DB gateway, every tool FAILS CLOSED with a
//! structured `dagdb_adapter_unconfigured` result before any HTTP request — it
//! never fabricates import/export/packet/writeback success.
//!
//! When `NodeContext` carries a complete gateway config, the tools deserialize
//! the validated MCP payload into the matching versioned DTO and invoke the SDK
//! `DagDbHttpClient`. The SDK owns the gateway headers, including
//! authorization, tenant, namespace, `{action}:{tenant}:{namespace}` authority
//! scope, and validated per-call signature headers. Missing config, scope
//! mismatches, or missing signature material fail closed with structured MCP
//! errors before any HTTP request is attempted.

#[cfg(feature = "dagdb-gateway-proxy")]
use std::{future::Future, thread};

#[cfg(feature = "dagdb-gateway-proxy")]
use exochain_sdk::dagdb::{
    BearerToken, DagDbAuthConfig, DagDbCatalogLookupRequest, DagDbClientError,
    DagDbContextPacketRequest, DagDbCouncilDecisionRequest, DagDbExportRequest, DagDbHttpClient,
    DagDbImportRequest, DagDbIntakeRequest, DagDbReceiptLookupRequest, DagDbRouteLookupRequest,
    DagDbRouteRequest, DagDbSignatureHeaders, DagDbTrustCheckRequest, DagDbValidateRequest,
    DagDbWritebackRequest,
};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MAX_SAFE_ID_BYTES: usize = 128;
const SAFE_ID_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$";
const DID_PATTERN: &str = "^did:[A-Za-z0-9][A-Za-z0-9._:-]{0,123}$";
const SAFE_PATH_PATTERN: &str =
    "^(?!/)(?!~)(?!.*\\\\)(?!.*(^|/)\\.\\.?(/|$))[A-Za-z0-9][A-Za-z0-9._/:-]{0,255}$";
const HASH256_PATTERN: &str = "^[0-9a-f]{64}$";
const DAGDB_ADAPTER_UNCONFIGURED: &str = "dagdb_adapter_unconfigured";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_GATEWAY_URL_UNCONFIGURED: &str = "dagdb_gateway_url_unconfigured";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_AUTH_UNCONFIGURED: &str = "dagdb_auth_unconfigured";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_TENANT_UNCONFIGURED: &str = "dagdb_tenant_unconfigured";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_NAMESPACE_UNCONFIGURED: &str = "dagdb_namespace_unconfigured";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_REQUEST_TENANT_MISSING: &str = "dagdb_request_tenant_missing";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_REQUEST_NAMESPACE_MISSING: &str = "dagdb_request_namespace_missing";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_TENANT_SCOPE_MISMATCH: &str = "dagdb_tenant_scope_mismatch";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_REQUEST_DECODE_FAILED: &str = "dagdb_request_decode_failed";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_SIGNATURE_MATERIAL_MISSING: &str = "dagdb_signature_material_missing";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_SIGNATURE_MATERIAL_INVALID: &str = "dagdb_signature_material_invalid";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_GATEWAY_REQUEST_FAILED: &str = "dagdb_gateway_request_failed";
#[cfg(feature = "dagdb-gateway-proxy")]
const DAGDB_RUNTIME_BRIDGE_FAILED: &str = "dagdb_runtime_bridge_failed";
const DAGDB_INTAKE_TOOL: &str = "dagdb_intake";
const DAGDB_ROUTE_TOOL: &str = "dagdb_route";
const DAGDB_GET_CONTEXT_PACKET_TOOL: &str = "dagdb_get_context_packet";
const DAGDB_VALIDATE_TOOL: &str = "dagdb_validate";
const DAGDB_SUBMIT_WRITEBACK_TOOL: &str = "dagdb_submit_writeback";
const DAGDB_IMPORT_TOOL: &str = "dagdb_import";
const DAGDB_EXPORT_TOOL: &str = "dagdb_export";
const DAGDB_TRUST_CHECK_TOOL: &str = "dagdb_trust_check";
const DAGDB_COUNCIL_DECISION_TOOL: &str = "dagdb_council_decision";
const DAGDB_RECEIPT_LOOKUP_TOOL: &str = "dagdb_receipt_lookup";
const DAGDB_CATALOG_LOOKUP_TOOL: &str = "dagdb_catalog_lookup";
const DAGDB_ROUTE_LOOKUP_TOOL: &str = "dagdb_route_lookup";
const MAX_ID_ARRAY_ITEMS: usize = 256;
const MAX_TOKEN_BUDGET: u64 = 1_000_000;
const SIGNATURE_HEX_CHARS: usize = 128;
const SIGNATURE_PATTERN: &str = "^[0-9a-f]{128}$";
const WRITE_SIGNATURE_HEADER: &str = "x-exo-write-signature";
const DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-default-route-approval-signature";
const DEFAULT_ROUTE_APPROVAL_DID_HEADER: &str = "x-exo-default-route-approval-did";
const DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-default-route-approval-timestamp";
const CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-context-packet-approval-signature";
const CONTEXT_PACKET_APPROVAL_DID_HEADER: &str = "x-exo-context-packet-approval-did";
const CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-context-packet-approval-timestamp";
const LIFECYCLE_SIGNATURE_HEADER: &str = "x-exo-lifecycle-signature";
const CONTINUATION_SIGNATURE_HEADER: &str = "x-exo-continuation-signature";
const LIFECYCLE_APPROVAL_DID_HEADER: &str = "x-exo-lifecycle-approval-did";
const CONTINUATION_APPROVAL_DID_HEADER: &str = "x-exo-continuation-approval-did";
const LIFECYCLE_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-lifecycle-approval-timestamp";
const CONTINUATION_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-continuation-approval-timestamp";
const IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-import-approval-signature";
const IMPORT_FINALITY_APPROVAL_DID_HEADER: &str = "x-exo-import-approval-did";
const IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-import-approval-timestamp";
const EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-export-approval-signature";
const EXPORT_FINALITY_APPROVAL_DID_HEADER: &str = "x-exo-export-approval-did";
const EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-export-approval-timestamp";
const KG_IMPORT_REPORT_SCHEMA: &str = "dagdb_kg_dry_run_import_report_v1";
const KG_IMPORT_CANDIDATES_SCHEMA: &str = "dagdb_markdown_kg_import_candidates_v1";
const ECHOED_STRING_FIELDS: &[(&str, &str)] = &[
    ("idempotency_key", "operation_id"),
    ("tenant_id", "tenant_id"),
    ("namespace", "namespace"),
    ("db_set_version", "db_set_version"),
];
const FORBIDDEN_ECHO_FRAGMENTS: &[&str] = &[
    "sk-proj-",
    "password",
    "token",
    "ghp_",
    "github_pat_",
    "xoxb-",
];

const NON_CLAIMS: &[&str] = &[
    "no_runtime_dagdb_operation_was_performed",
    "no_persistence_receipt_was_created",
    "no_export_artifact_was_created",
    "dagdb_runtime_gateway_is_not_configured_on_this_node",
];

fn safe_string_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_SAFE_ID_BYTES,
        "pattern": SAFE_ID_PATTERN,
        "description": description,
    })
}

fn optional_safe_string_schema(description: &str) -> Value {
    json!({
        "anyOf": [
            {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_SAFE_ID_BYTES,
                "pattern": SAFE_ID_PATTERN,
            },
            {
                "type": "null",
            }
        ],
        "description": description,
    })
}

fn did_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "minLength": 5,
        "maxLength": MAX_SAFE_ID_BYTES,
        "pattern": DID_PATTERN,
        "description": description,
    })
}

fn safe_path_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": SAFE_PATH_PATTERN,
        "description": description,
    })
}

fn hash_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "pattern": HASH256_PATTERN,
        "description": description,
    })
}

fn signature_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "minLength": SIGNATURE_HEX_CHARS,
        "maxLength": SIGNATURE_HEX_CHARS,
        "pattern": SIGNATURE_PATTERN,
        "description": description,
    })
}

fn approval_timestamp_schema(description: &str) -> Value {
    safe_string_schema(description)
}

fn token_budget_schema(description: &str) -> Value {
    json!({
        "type": "integer",
        "minimum": 0,
        "maximum": MAX_TOKEN_BUDGET,
        "description": description,
    })
}

fn optional_bool_schema(description: &str) -> Value {
    json!({
        "anyOf": [{"type": "boolean"}, {"type": "null"}],
        "description": description,
    })
}

fn optional_token_budget_schema(description: &str) -> Value {
    json!({
        "anyOf": [{"type": "integer", "minimum": 0, "maximum": MAX_TOKEN_BUDGET}, {"type": "null"}],
        "description": description,
    })
}

fn optional_safe_string_array_schema(description: &str) -> Value {
    json!({
        "anyOf": [
            {
                "type": "array",
                "maxItems": MAX_ID_ARRAY_ITEMS,
                "uniqueItems": true,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_SAFE_ID_BYTES,
                    "pattern": SAFE_ID_PATTERN,
                },
            },
            {"type": "null"}
        ],
        "description": description,
    })
}

fn optional_hash_array_schema(description: &str) -> Value {
    json!({
        "anyOf": [
            {
                "type": "array",
                "maxItems": MAX_ID_ARRAY_ITEMS,
                "uniqueItems": true,
                "items": hash_schema("64-character lowercase hex hash."),
            },
            {"type": "null"}
        ],
        "description": description,
    })
}

fn optional_safe_text_schema(description: &str) -> Value {
    json!({
        "anyOf": [{"type": "string", "maxLength": 4096}, {"type": "null"}],
        "description": description,
    })
}

fn common_properties() -> serde_json::Map<String, Value> {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "idempotency_key".to_owned(),
        safe_string_schema("Caller-supplied idempotency key for the DAG DB operation."),
    );
    properties.insert(
        "tenant_id".to_owned(),
        safe_string_schema("Tenant boundary for the requested DAG DB operation."),
    );
    properties.insert(
        "namespace".to_owned(),
        safe_string_schema("Namespace boundary for the requested DAG DB operation."),
    );
    properties.insert(
        "db_set_version".to_owned(),
        safe_string_schema("DAG DB set version for the requested operation."),
    );
    properties
}

fn safe_string_array_schema(description: &str) -> Value {
    json!({
        "type": "array",
        "maxItems": MAX_ID_ARRAY_ITEMS,
        "uniqueItems": true,
        "items": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_SAFE_ID_BYTES,
            "pattern": SAFE_ID_PATTERN,
        },
        "description": description,
    })
}

fn hash_array_schema(description: &str) -> Value {
    json!({
        "type": "array",
        "maxItems": MAX_ID_ARRAY_ITEMS,
        "uniqueItems": true,
        "items": hash_schema("64-character lowercase hex hash."),
        "description": description,
    })
}

fn empty_array_schema(description: &str) -> Value {
    json!({
        "type": "array",
        "maxItems": 0,
        "description": description,
    })
}

fn empty_object_schema(description: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "description": description,
    })
}

fn fixture_request_schema(
    tool_name: &str,
    fixture_name: &str,
    description: &str,
) -> ToolDefinition {
    let fixtures: Value = match serde_json::from_str(include_str!(
        "../../../fixtures/dagdb/all_dto_fixtures.json"
    )) {
        Ok(fixtures) => fixtures,
        Err(error) => panic!("DAG DB fixture set parses for MCP schema binding: {error}"),
    };
    let request = fixtures
        .get("requests")
        .and_then(|requests| requests.get(fixture_name))
        .unwrap_or_else(|| panic!("missing DAG DB request fixture {fixture_name}"));
    let Value::Object(fields) = request else {
        panic!("DAG DB request fixture {fixture_name} must be an object");
    };
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, value) in fields {
        properties.insert(name.clone(), schema_for_fixture_field(name, value));
        required.push(name.clone());
    }
    for header in required_signature_headers(tool_name).iter().copied() {
        properties.insert(header.to_owned(), schema_for_signature_header(header));
        required.push(header.to_owned());
    }
    ToolDefinition {
        name: tool_name.to_owned(),
        description: description.to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        }),
    }
}

fn schema_for_fixture_field(name: &str, value: &Value) -> Value {
    match value {
        Value::String(_) if name.ends_with("_did") || name == "requester_did" => {
            did_schema("DID field bound from the canonical DAG DB DTO fixture.")
        }
        Value::String(text)
            if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            hash_schema(
                "64-character lowercase hex hash field bound from the canonical DAG DB DTO fixture.",
            )
        }
        Value::String(_) => {
            safe_string_schema("String field bound from the canonical DAG DB DTO fixture.")
        }
        Value::Bool(_) => json!({"type": "boolean"}),
        Value::Number(number) if number.is_u64() || number.is_i64() => json!({"type": "integer"}),
        Value::Number(_) => json!({"type": "integer"}),
        Value::Array(items) => {
            let item_schema = items
                .iter()
                .find(|item| !item.is_null())
                .map(|item| schema_for_fixture_field(name, item))
                .unwrap_or_else(|| {
                    safe_string_schema("Array item bound from the canonical DAG DB DTO fixture.")
                });
            json!({
                "type": "array",
                "maxItems": MAX_ID_ARRAY_ITEMS,
                "items": item_schema,
            })
        }
        Value::Object(_) if name == "import_report" => import_report_schema(),
        Value::Object(_) => json!({
            "type": "object",
            "additionalProperties": true,
        }),
        Value::Null => json!({
            "anyOf": [
                {"type": "string", "maxLength": 4096},
                {"type": "boolean"},
                {"type": "integer"},
                {"type": "array", "maxItems": MAX_ID_ARRAY_ITEMS},
                {"type": "object"},
                {"type": "null"}
            ],
        }),
    }
}

fn schema_for_signature_header(header: &'static str) -> Value {
    match header {
        DEFAULT_ROUTE_APPROVAL_DID_HEADER
        | CONTEXT_PACKET_APPROVAL_DID_HEADER
        | LIFECYCLE_APPROVAL_DID_HEADER
        | CONTINUATION_APPROVAL_DID_HEADER
        | IMPORT_FINALITY_APPROVAL_DID_HEADER
        | EXPORT_FINALITY_APPROVAL_DID_HEADER => {
            did_schema("External finality authority DID forwarded as a gateway header.")
        }
        DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER
        | CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER
        | LIFECYCLE_APPROVAL_TIMESTAMP_HEADER
        | CONTINUATION_APPROVAL_TIMESTAMP_HEADER
        | IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER
        | EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER => approval_timestamp_schema(
            "External finality approval timestamp forwarded as a gateway header.",
        ),
        _ => signature_schema("Gateway signature header forwarded to the DAG DB runtime adapter."),
    }
}

fn import_report_schema() -> Value {
    json!({
        "type": "object",
        "description": "Strict REST-compatible DAG DB dry-run import report envelope accepted by the MCP runtime surface. This pass accepts the gateway/SDK fixture shape with empty proposed record arrays and rejects digest-only summaries.",
        "properties": {
            "schema_version": {
                "type": "string",
                "enum": [KG_IMPORT_REPORT_SCHEMA],
            },
            "source_candidates_schema_version": {
                "type": "string",
                "enum": [KG_IMPORT_CANDIDATES_SCHEMA],
            },
            "graph_root": safe_path_schema("Repository-relative knowledge graph root."),
            "tenant_id": safe_string_schema("Tenant boundary embedded in the dry-run import report."),
            "namespace": safe_string_schema("Namespace boundary embedded in the dry-run import report."),
            "actor_did": did_schema("DID that produced the dry-run import report."),
            "batch_id": hash_schema("64-character lowercase hex dry-run import batch ID."),
            "dry_run_only": {
                "type": "boolean",
                "enum": [true],
            },
            "postgres_writes": {
                "type": "boolean",
                "enum": [false],
            },
            "raw_markdown_included": {
                "type": "boolean",
                "enum": [false],
            },
            "proposed_memory_records": empty_array_schema("Proposed memory records. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_catalog_entries": empty_array_schema("Proposed catalog entries. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_graph_nodes": empty_array_schema("Proposed graph nodes. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_graph_edges": empty_array_schema("Proposed graph edges. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_required_edges": empty_array_schema("Proposed required edges. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_placement_decisions": empty_array_schema("Proposed placement decisions. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_receipt_intents": empty_array_schema("Proposed receipt intents. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_validation_reports": empty_array_schema("Proposed validation reports. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_governance_reviews": empty_array_schema("Proposed governance reviews. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_graph_view_refreshes": empty_array_schema("Proposed graph view refreshes. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_route_invalidations": empty_array_schema("Proposed route invalidations. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "proposed_subdag_boundaries": empty_array_schema("Proposed subdag boundaries. Empty fixture arrays are accepted by this bounded MCP schema pass."),
            "rollback_plan": empty_object_schema("Dry-run rollback plan metadata."),
            "placement_governance_summary": empty_object_schema("Dry-run placement governance metadata."),
            "review_items": empty_array_schema("Dry-run review items."),
            "warnings": empty_array_schema("Dry-run warnings."),
        },
        "required": [
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
            "proposed_memory_records",
            "proposed_catalog_entries",
            "proposed_graph_nodes",
            "proposed_graph_edges",
            "proposed_placement_decisions",
            "proposed_receipt_intents",
            "proposed_validation_reports"
        ],
        "additionalProperties": false,
    })
}

fn echoed_field_with_forbidden_fragment(params: &Value) -> Option<&'static str> {
    for (request_field, response_field) in ECHOED_STRING_FIELDS {
        let Some(value) = params.get(*request_field).and_then(Value::as_str) else {
            continue;
        };
        let normalized = value.to_ascii_lowercase();
        if FORBIDDEN_ECHO_FRAGMENTS
            .iter()
            .any(|fragment| normalized.contains(fragment))
        {
            return Some(*response_field);
        }
    }

    None
}

/// Structured fail-closed result when the DAG DB runtime gateway is not configured.
///
/// Returned whenever no DAG DB gateway is configured (the default). Never
/// claims any runtime effect.
fn mcp_json_error(message: &str, fields: Value) -> ToolResult {
    let mut body = match fields {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    body.insert("message".to_owned(), json!(message));
    ToolResult::error(Value::Object(body).to_string())
}

fn adapter_unconfigured_response(tool_name: &str, params: &Value) -> ToolResult {
    if let Some(field) = echoed_field_with_forbidden_fragment(params) {
        return mcp_json_error(
            "DAG DB request rejected before unsafe echo.",
            json!({
                "tool_status": "rejected_unsafe_echo_field",
                "tool": tool_name,
                "field": field,
            }),
        );
    }

    tracing::warn!(
        tool = %tool_name,
        "refusing DAG DB MCP call: no DAG DB gateway is configured"
    );

    mcp_json_error(
        "DAG DB runtime gateway is not configured on this node; no DAG DB operation was performed.",
        json!({
            "tool_status": DAGDB_ADAPTER_UNCONFIGURED,
            "tool": tool_name,
            "operation_id": params.get("idempotency_key").and_then(Value::as_str),
            "tenant_id": params.get("tenant_id").and_then(Value::as_str),
            "namespace": params.get("namespace").and_then(Value::as_str),
            "db_set_version": params.get("db_set_version").and_then(Value::as_str),
            "non_claims": NON_CLAIMS,
        }),
    )
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn fail_closed_response(
    tool_name: &str,
    tool_status: &str,
    message: &str,
    fields: Value,
) -> ToolResult {
    let mut body = match fields {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    body.insert("tool_status".to_owned(), json!(tool_status));
    body.insert("tool".to_owned(), json!(tool_name));
    body.insert("success_claimed".to_owned(), json!(false));
    mcp_json_error(message, Value::Object(body))
}

#[cfg(feature = "dagdb-gateway-proxy")]
#[derive(Debug)]
struct DagDbProxyScope {
    base_url: String,
    bearer_token: BearerToken,
    tenant_id: String,
    namespace: String,
}

#[cfg(feature = "dagdb-gateway-proxy")]
#[derive(Debug)]
enum DagDbRuntimeBridgeError {
    RuntimeInit(String),
    JoinPanic,
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn non_empty(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn non_empty_token(value: &Option<zeroize::Zeroizing<String>>) -> Option<BearerToken> {
    let token = value.as_ref()?.as_str().trim();
    if token.is_empty() {
        None
    } else {
        Some(BearerToken::new(token.to_owned()))
    }
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn require_request_scope<'a>(
    tool_name: &str,
    params: &'a Value,
    field: &'static str,
    missing_status: &'static str,
) -> Result<&'a str, ToolResult> {
    params
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            fail_closed_response(
                tool_name,
                missing_status,
                "DAG DB request scope is incomplete; no DAG DB operation was performed.",
                json!({
                    "missing_field": field,
                }),
            )
        })
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn is_signature_value(value: &str) -> bool {
    value.len() == SIGNATURE_HEX_CHARS
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn is_did_header_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.len() >= 5
        && value.len() <= MAX_SAFE_ID_BYTES
        && value.starts_with("did:")
        && bytes[4].is_ascii_alphanumeric()
        && bytes[5..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn is_approval_timestamp_header_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    !value.is_empty()
        && value.len() <= MAX_SAFE_ID_BYTES
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn required_signature_headers(tool_name: &str) -> &'static [&'static str] {
    match tool_name {
        DAGDB_INTAKE_TOOL
        | DAGDB_VALIDATE_TOOL
        | DAGDB_TRUST_CHECK_TOOL
        | DAGDB_COUNCIL_DECISION_TOOL => &[WRITE_SIGNATURE_HEADER],
        DAGDB_ROUTE_TOOL => &[
            WRITE_SIGNATURE_HEADER,
            DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
            DEFAULT_ROUTE_APPROVAL_DID_HEADER,
            DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
        ],
        DAGDB_SUBMIT_WRITEBACK_TOOL => &[
            WRITE_SIGNATURE_HEADER,
            LIFECYCLE_SIGNATURE_HEADER,
            CONTINUATION_SIGNATURE_HEADER,
            LIFECYCLE_APPROVAL_DID_HEADER,
            CONTINUATION_APPROVAL_DID_HEADER,
            LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
            CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
        ],
        DAGDB_GET_CONTEXT_PACKET_TOOL => &[
            WRITE_SIGNATURE_HEADER,
            CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
            CONTEXT_PACKET_APPROVAL_DID_HEADER,
            CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
        ],
        DAGDB_IMPORT_TOOL => &[
            WRITE_SIGNATURE_HEADER,
            IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            IMPORT_FINALITY_APPROVAL_DID_HEADER,
            IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
        ],
        DAGDB_EXPORT_TOOL => &[
            WRITE_SIGNATURE_HEADER,
            EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            EXPORT_FINALITY_APPROVAL_DID_HEADER,
            EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
        ],
        _ => &[],
    }
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn require_signature_param(
    tool_name: &str,
    params: &Value,
    header: &'static str,
) -> Result<String, ToolResult> {
    let Some(value) = params.get(header).and_then(Value::as_str) else {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_MISSING,
            "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
            json!({
                "missing_signature_header": header,
                "required_signature_headers": required_signature_headers(tool_name),
            }),
        ));
    };

    if value.trim().is_empty() {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_MISSING,
            "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
            json!({
                "missing_signature_header": header,
                "required_signature_headers": required_signature_headers(tool_name),
            }),
        ));
    }

    if !is_signature_value(value) {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_INVALID,
            "DAG DB gateway signature material is invalid; no DAG DB operation was performed.",
            json!({
                "invalid_signature_header": header,
                "expected_signature_format": "128 lowercase hex characters",
            }),
        ));
    }

    Ok(value.to_owned())
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn require_did_header_param(
    tool_name: &str,
    params: &Value,
    header: &'static str,
) -> Result<String, ToolResult> {
    let Some(value) = params.get(header).and_then(Value::as_str) else {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_MISSING,
            "DAG DB gateway finality authority material is incomplete; no DAG DB operation was performed.",
            json!({
                "missing_signature_header": header,
                "required_signature_headers": required_signature_headers(tool_name),
            }),
        ));
    };

    if value.trim().is_empty() {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_MISSING,
            "DAG DB gateway finality authority material is incomplete; no DAG DB operation was performed.",
            json!({
                "missing_signature_header": header,
                "required_signature_headers": required_signature_headers(tool_name),
            }),
        ));
    }

    if !is_did_header_value(value) {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_INVALID,
            "DAG DB gateway finality authority material is invalid; no DAG DB operation was performed.",
            json!({
                "invalid_signature_header": header,
                "expected_signature_format": "DID string matching did:<method-specific-id>",
            }),
        ));
    }

    Ok(value.to_owned())
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn require_approval_timestamp_param(
    tool_name: &str,
    params: &Value,
    header: &'static str,
) -> Result<String, ToolResult> {
    let Some(value) = params.get(header).and_then(Value::as_str) else {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_MISSING,
            "DAG DB gateway finality timestamp material is incomplete; no DAG DB operation was performed.",
            json!({
                "missing_signature_header": header,
                "required_signature_headers": required_signature_headers(tool_name),
            }),
        ));
    };

    let value = value.trim();
    if value.is_empty() {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_MISSING,
            "DAG DB gateway finality timestamp material is incomplete; no DAG DB operation was performed.",
            json!({
                "missing_signature_header": header,
                "required_signature_headers": required_signature_headers(tool_name),
            }),
        ));
    }

    if !is_approval_timestamp_header_value(value) {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_SIGNATURE_MATERIAL_INVALID,
            "DAG DB gateway finality timestamp material is invalid; no DAG DB operation was performed.",
            json!({
                "invalid_signature_header": header,
                "expected_signature_format": "bounded timestamp string using safe header characters",
            }),
        ));
    }

    Ok(value.to_owned())
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn signature_headers_for_tool(
    tool_name: &str,
    params: &Value,
) -> Result<Option<DagDbSignatureHeaders>, ToolResult> {
    match tool_name {
        DAGDB_INTAKE_TOOL
        | DAGDB_VALIDATE_TOOL
        | DAGDB_TRUST_CHECK_TOOL
        | DAGDB_COUNCIL_DECISION_TOOL => Ok(Some(DagDbSignatureHeaders::write(
            require_signature_param(tool_name, params, WRITE_SIGNATURE_HEADER)?,
        ))),
        DAGDB_ROUTE_TOOL => Ok(Some(DagDbSignatureHeaders::default_route(
            require_signature_param(tool_name, params, WRITE_SIGNATURE_HEADER)?,
            require_signature_param(tool_name, params, DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER)?,
            require_did_header_param(tool_name, params, DEFAULT_ROUTE_APPROVAL_DID_HEADER)?,
            require_approval_timestamp_param(
                tool_name,
                params,
                DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
            )?,
        ))),
        DAGDB_SUBMIT_WRITEBACK_TOOL => Ok(Some(DagDbSignatureHeaders::writeback(
            require_signature_param(tool_name, params, WRITE_SIGNATURE_HEADER)?,
            require_signature_param(tool_name, params, LIFECYCLE_SIGNATURE_HEADER)?,
            require_signature_param(tool_name, params, CONTINUATION_SIGNATURE_HEADER)?,
            require_did_header_param(tool_name, params, LIFECYCLE_APPROVAL_DID_HEADER)?,
            require_did_header_param(tool_name, params, CONTINUATION_APPROVAL_DID_HEADER)?,
            require_approval_timestamp_param(
                tool_name,
                params,
                LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
            )?,
            require_approval_timestamp_param(
                tool_name,
                params,
                CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
            )?,
        ))),
        DAGDB_GET_CONTEXT_PACKET_TOOL => Ok(Some(DagDbSignatureHeaders::context_packet(
            require_signature_param(tool_name, params, WRITE_SIGNATURE_HEADER)?,
            require_signature_param(tool_name, params, CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER)?,
            require_did_header_param(tool_name, params, CONTEXT_PACKET_APPROVAL_DID_HEADER)?,
            require_approval_timestamp_param(
                tool_name,
                params,
                CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
            )?,
        ))),
        DAGDB_IMPORT_TOOL => Ok(Some(DagDbSignatureHeaders::dagdb_import(
            require_signature_param(tool_name, params, WRITE_SIGNATURE_HEADER)?,
            require_signature_param(tool_name, params, IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER)?,
            require_did_header_param(tool_name, params, IMPORT_FINALITY_APPROVAL_DID_HEADER)?,
            require_approval_timestamp_param(
                tool_name,
                params,
                IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
            )?,
        ))),
        DAGDB_EXPORT_TOOL => Ok(Some(DagDbSignatureHeaders::dagdb_export(
            require_signature_param(tool_name, params, WRITE_SIGNATURE_HEADER)?,
            require_signature_param(tool_name, params, EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER)?,
            require_did_header_param(tool_name, params, EXPORT_FINALITY_APPROVAL_DID_HEADER)?,
            require_approval_timestamp_param(
                tool_name,
                params,
                EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
            )?,
        ))),
        DAGDB_RECEIPT_LOOKUP_TOOL | DAGDB_CATALOG_LOOKUP_TOOL | DAGDB_ROUTE_LOOKUP_TOOL => Ok(None),
        _ => Err(fail_closed_response(
            tool_name,
            DAGDB_REQUEST_DECODE_FAILED,
            "DAG DB tool dispatch target is unknown; no DAG DB operation was performed.",
            json!({}),
        )),
    }
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn proxy_dto_params(params: &Value) -> Value {
    let mut dto_params = params.clone();
    if let Value::Object(map) = &mut dto_params {
        for header in [
            WRITE_SIGNATURE_HEADER,
            DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
            DEFAULT_ROUTE_APPROVAL_DID_HEADER,
            DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
            CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
            CONTEXT_PACKET_APPROVAL_DID_HEADER,
            CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
            LIFECYCLE_SIGNATURE_HEADER,
            CONTINUATION_SIGNATURE_HEADER,
            LIFECYCLE_APPROVAL_DID_HEADER,
            CONTINUATION_APPROVAL_DID_HEADER,
            LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
            CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
            IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            IMPORT_FINALITY_APPROVAL_DID_HEADER,
            IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
            EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            EXPORT_FINALITY_APPROVAL_DID_HEADER,
            EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
        ] {
            map.remove(header);
        }
    }
    dto_params
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn configured_proxy_scope(
    tool_name: &str,
    params: &Value,
    context: &NodeContext,
) -> Result<DagDbProxyScope, ToolResult> {
    let Some(config) = context.dagdb_gateway.as_ref() else {
        return Err(adapter_unconfigured_response(tool_name, params));
    };

    let Some(base_url) = non_empty(&config.base_url) else {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_GATEWAY_URL_UNCONFIGURED,
            "DAG DB gateway URL is not configured; no DAG DB operation was performed.",
            json!({}),
        ));
    };
    let Some(bearer_token) = non_empty_token(&config.bearer_token) else {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_AUTH_UNCONFIGURED,
            "DAG DB gateway bearer auth is not configured; no DAG DB operation was performed.",
            json!({}),
        ));
    };
    let Some(tenant_id) = non_empty(&config.tenant_id) else {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_TENANT_UNCONFIGURED,
            "DAG DB gateway tenant scope is not configured; no DAG DB operation was performed.",
            json!({}),
        ));
    };
    let Some(namespace) = non_empty(&config.namespace) else {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_NAMESPACE_UNCONFIGURED,
            "DAG DB gateway namespace scope is not configured; no DAG DB operation was performed.",
            json!({}),
        ));
    };

    let request_tenant =
        require_request_scope(tool_name, params, "tenant_id", DAGDB_REQUEST_TENANT_MISSING)?;
    let request_namespace = require_request_scope(
        tool_name,
        params,
        "namespace",
        DAGDB_REQUEST_NAMESPACE_MISSING,
    )?;

    if request_tenant != tenant_id || request_namespace != namespace {
        return Err(fail_closed_response(
            tool_name,
            DAGDB_TENANT_SCOPE_MISMATCH,
            "DAG DB request tenant/namespace does not match the configured gateway auth scope; no DAG DB operation was performed.",
            json!({
                "request_tenant_id": request_tenant,
                "request_namespace": request_namespace,
                "configured_tenant_id": tenant_id,
                "configured_namespace": namespace,
            }),
        ));
    }

    Ok(DagDbProxyScope {
        base_url,
        bearer_token,
        tenant_id,
        namespace,
    })
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn parse_proxy_request<T>(tool_name: &str, params: &Value) -> Result<T, ToolResult>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(proxy_dto_params(params)).map_err(|error| {
        fail_closed_response(
            tool_name,
            DAGDB_REQUEST_DECODE_FAILED,
            "DAG DB request failed to decode into the SDK DTO; no DAG DB operation was performed.",
            json!({
                "decode_error": error.to_string(),
            }),
        )
    })
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn runtime_bridge_error_response(tool_name: &str, error: DagDbRuntimeBridgeError) -> ToolResult {
    let detail = match error {
        DagDbRuntimeBridgeError::RuntimeInit(error) => json!({
            "bridge_error": "runtime_init_failed",
            "detail": error,
        }),
        DagDbRuntimeBridgeError::JoinPanic => json!({
            "bridge_error": "runtime_thread_panicked",
        }),
    };

    fail_closed_response(
        tool_name,
        DAGDB_RUNTIME_BRIDGE_FAILED,
        "DAG DB async runtime bridge failed; no DAG DB success was claimed.",
        detail,
    )
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn client_error_response(tool_name: &str, error: DagDbClientError) -> ToolResult {
    let fields = match error {
        DagDbClientError::Transport(error) => json!({
            "error_kind": "transport",
            "detail": error.to_string(),
        }),
        DagDbClientError::Timeout(error) => json!({
            "error_kind": "timeout",
            "detail": error.to_string(),
        }),
        DagDbClientError::Server(error) => json!({
            "error_kind": "server",
            "status": error.status,
            "error_code": error.error_code,
            "gateway_message": error.message,
            "receipt_hash": error.receipt_hash,
            "validation_report_id": error.validation_report_id,
            "requires_council_review": error.requires_council_review,
        }),
        DagDbClientError::UnexpectedStatus { status, body } => json!({
            "error_kind": "unexpected_status",
            "status": status,
            "body_bytes": body.len(),
        }),
        DagDbClientError::Decode(error) => json!({
            "error_kind": "decode",
            "detail": error.to_string(),
        }),
        DagDbClientError::SchemaVersionMismatch { expected, actual } => json!({
            "error_kind": "schema_version_mismatch",
            "expected": expected,
            "actual": actual,
        }),
        DagDbClientError::InvalidAuthHeader { header } => json!({
            "error_kind": "invalid_auth_header",
            "header": header,
        }),
        DagDbClientError::MissingSignatureMaterial { header } => json!({
            "error_kind": "missing_signature_material",
            "header": header,
        }),
        DagDbClientError::InvalidSignatureHeader { header } => json!({
            "error_kind": "invalid_signature_header",
            "header": header,
        }),
        DagDbClientError::TenantNamespaceMismatch {
            request_tenant_id,
            request_namespace,
            auth_tenant_id,
            auth_namespace,
        } => json!({
            "error_kind": "tenant_namespace_mismatch",
            "request_tenant_id": request_tenant_id,
            "request_namespace": request_namespace,
            "auth_tenant_id": auth_tenant_id,
            "auth_namespace": auth_namespace,
        }),
    };

    fail_closed_response(
        tool_name,
        DAGDB_GATEWAY_REQUEST_FAILED,
        "DAG DB gateway request failed; no DAG DB success was claimed.",
        fields,
    )
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn run_async_proxy_call<F, T>(
    future: F,
) -> Result<Result<T, DagDbClientError>, DagDbRuntimeBridgeError>
where
    F: Future<Output = Result<T, DagDbClientError>> + Send + 'static,
    T: Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        return thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| DagDbRuntimeBridgeError::RuntimeInit(error.to_string()))?;
            Ok(runtime.block_on(future))
        })
        .join()
        .map_err(|_| DagDbRuntimeBridgeError::JoinPanic)?;
    }

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| DagDbRuntimeBridgeError::RuntimeInit(error.to_string()))?;
    Ok(runtime.block_on(future))
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn proxy_client(scope: DagDbProxyScope) -> Result<DagDbHttpClient, DagDbClientError> {
    DagDbHttpClient::new(
        scope.base_url,
        DagDbAuthConfig::new(scope.bearer_token, scope.tenant_id, scope.namespace),
    )
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn proxy_result<T>(
    tool_name: &str,
    call: impl Future<Output = Result<T, DagDbClientError>> + Send + 'static,
) -> ToolResult
where
    T: serde::Serialize + Send + 'static,
{
    match run_async_proxy_call(call) {
        Ok(Ok(response)) => ToolResult::json_success(&response),
        Ok(Err(error)) => client_error_response(tool_name, error),
        Err(error) => runtime_bridge_error_response(tool_name, error),
    }
}

#[cfg(feature = "dagdb-gateway-proxy")]
fn dispatch_configured(
    tool_name: &str,
    params: &Value,
    scope: DagDbProxyScope,
    signatures: Option<DagDbSignatureHeaders>,
) -> ToolResult {
    let client = match proxy_client(scope) {
        Ok(client) => client,
        Err(error) => return client_error_response(tool_name, error),
    };

    match tool_name {
        DAGDB_INTAKE_TOOL => {
            let request: DagDbIntakeRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client.intake_with_signatures(request, signatures).await
            })
        }
        DAGDB_ROUTE_TOOL => {
            let request: DagDbRouteRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client.route_with_signatures(request, signatures).await
            })
        }
        DAGDB_GET_CONTEXT_PACKET_TOOL => {
            let request: DagDbContextPacketRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client
                    .context_packet_with_signatures(request, signatures)
                    .await
            })
        }
        DAGDB_VALIDATE_TOOL => {
            let request: DagDbValidateRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client.validate_with_signatures(request, signatures).await
            })
        }
        DAGDB_SUBMIT_WRITEBACK_TOOL => {
            let request: DagDbWritebackRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client.writeback_with_signatures(request, signatures).await
            })
        }
        DAGDB_IMPORT_TOOL => {
            let request: DagDbImportRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client
                    .dagdb_import_with_signatures(request, signatures)
                    .await
            })
        }
        DAGDB_EXPORT_TOOL => {
            let request: DagDbExportRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client
                    .dagdb_export_with_signatures(request, signatures)
                    .await
            })
        }
        DAGDB_TRUST_CHECK_TOOL => {
            let request: DagDbTrustCheckRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client
                    .trust_check_with_signatures(request, signatures)
                    .await
            })
        }
        DAGDB_COUNCIL_DECISION_TOOL => {
            let request: DagDbCouncilDecisionRequest = match parse_proxy_request(tool_name, params)
            {
                Ok(request) => request,
                Err(result) => return result,
            };
            let Some(signatures) = signatures else {
                return fail_closed_response(
                    tool_name,
                    DAGDB_SIGNATURE_MATERIAL_MISSING,
                    "DAG DB gateway signature material is incomplete; no DAG DB operation was performed.",
                    json!({ "missing_signature_header": WRITE_SIGNATURE_HEADER }),
                );
            };
            proxy_result(tool_name, async move {
                client
                    .council_decision_with_signatures(request, signatures)
                    .await
            })
        }
        DAGDB_RECEIPT_LOOKUP_TOOL => {
            let request: DagDbReceiptLookupRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            proxy_result(
                tool_name,
                async move { client.receipt_lookup(request).await },
            )
        }
        DAGDB_CATALOG_LOOKUP_TOOL => {
            let request: DagDbCatalogLookupRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            proxy_result(
                tool_name,
                async move { client.catalog_lookup(request).await },
            )
        }
        DAGDB_ROUTE_LOOKUP_TOOL => {
            let request: DagDbRouteLookupRequest = match parse_proxy_request(tool_name, params) {
                Ok(request) => request,
                Err(result) => return result,
            };
            proxy_result(tool_name, async move { client.route_lookup(request).await })
        }
        _ => fail_closed_response(
            tool_name,
            DAGDB_REQUEST_DECODE_FAILED,
            "DAG DB tool dispatch target is unknown; no DAG DB operation was performed.",
            json!({}),
        ),
    }
}

/// Tool definition for `dagdb_intake`.
#[must_use]
pub fn intake_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_INTAKE_TOOL,
        "intake",
        "Submit a governed DAG DB intake request through the runtime MCP surface.",
    )
}

/// Tool definition for `dagdb_route`.
#[must_use]
pub fn route_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_ROUTE_TOOL,
        "route",
        "Persist a governed DAG DB route decision through the runtime MCP surface.",
    )
}

/// Tool definition for `dagdb_get_context_packet`.
///
/// Input schema is bound to `exo_api::dagdb::DagDbContextPacketRequest`.
#[must_use]
pub fn get_context_packet_definition() -> ToolDefinition {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "tenant_id".to_owned(),
        safe_string_schema("Tenant boundary for the context-packet request."),
    );
    properties.insert(
        "namespace".to_owned(),
        safe_string_schema("Namespace boundary for the context-packet request."),
    );
    properties.insert(
        "idempotency_key".to_owned(),
        safe_string_schema("Caller-supplied idempotency key for the context-packet request."),
    );
    properties.insert(
        "request_id".to_owned(),
        safe_string_schema("Caller-supplied context-packet request ID."),
    );
    properties.insert(
        "route_id".to_owned(),
        hash_schema("64-character lowercase hex route ID the packet is scoped to."),
    );
    properties.insert(
        "task_hash".to_owned(),
        hash_schema("64-character lowercase hex digest of the task the packet optimizes for."),
    );
    properties.insert(
        "requesting_agent_did".to_owned(),
        did_schema("DID of the agent requesting the context packet."),
    );
    properties.insert(
        "token_budget".to_owned(),
        token_budget_schema("Token budget the packet must fit within."),
    );
    properties.insert(
        "force_revalidate".to_owned(),
        optional_bool_schema("Force re-validation of cached packet contents."),
    );
    properties.insert(
        "max_memory_refs".to_owned(),
        optional_token_budget_schema("Maximum number of memory refs to return."),
    );
    properties.insert(
        "task".to_owned(),
        optional_safe_text_schema("Optional free-text task description for packet selection."),
    );
    properties.insert(
        "layered_mode".to_owned(),
        optional_safe_string_schema("Optional layered-context mode (`off`/`auto`/`required`)."),
    );
    properties.insert(
        "max_layer_depth".to_owned(),
        optional_token_budget_schema("Optional maximum layer traversal depth."),
    );
    properties.insert(
        "require_layer_evidence".to_owned(),
        optional_bool_schema("Fail closed when requested layer evidence is missing."),
    );
    properties.insert(
        "drilldown_reserve_bp".to_owned(),
        optional_token_budget_schema("Depth-on-demand reserve, in basis points of the budget."),
    );
    properties.insert(
        WRITE_SIGNATURE_HEADER.to_owned(),
        signature_schema("Gateway write signature forwarded as `x-exo-write-signature`."),
    );
    properties.insert(
        CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER.to_owned(),
        signature_schema(
            "External context-packet approval signature forwarded as `x-exo-context-packet-approval-signature`.",
        ),
    );
    properties.insert(
        CONTEXT_PACKET_APPROVAL_DID_HEADER.to_owned(),
        did_schema("External DID that signed the context-packet finality approval."),
    );
    properties.insert(
        CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER.to_owned(),
        approval_timestamp_schema(
            "External context-packet approval timestamp forwarded as `x-exo-context-packet-approval-timestamp`.",
        ),
    );

    ToolDefinition {
        name: DAGDB_GET_CONTEXT_PACKET_TOOL.to_owned(),
        description: "Retrieve a graph-routed DAG DB context packet for a task through the runtime MCP surface. When no gateway is configured this node fails closed with a structured `dagdb_adapter_unconfigured` result instead of fabricating a packet.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": [
                "tenant_id",
                "namespace",
                "idempotency_key",
                "request_id",
                "route_id",
                "task_hash",
                "requesting_agent_did",
                "token_budget",
                WRITE_SIGNATURE_HEADER,
                CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
                CONTEXT_PACKET_APPROVAL_DID_HEADER,
                CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER
            ],
            "additionalProperties": false,
        }),
    }
}

/// Tool definition for `dagdb_validate`.
#[must_use]
pub fn validate_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_VALIDATE_TOOL,
        "validate",
        "Persist a governed DAG DB validation report through the runtime MCP surface.",
    )
}

/// Tool definition for `dagdb_submit_writeback`.
///
/// Input schema is bound to `exo_api::dagdb::DagDbWritebackRequest`.
#[must_use]
pub fn submit_writeback_definition() -> ToolDefinition {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "tenant_id".to_owned(),
        safe_string_schema("Tenant boundary for the writeback request."),
    );
    properties.insert(
        "namespace".to_owned(),
        safe_string_schema("Namespace boundary for the writeback request."),
    );
    properties.insert(
        "idempotency_key".to_owned(),
        safe_string_schema("Caller-supplied idempotency key for the writeback request."),
    );
    properties.insert(
        "requesting_agent_did".to_owned(),
        did_schema("DID of the agent submitting the writeback."),
    );
    properties.insert(
        "parent_memory_ids".to_owned(),
        hash_array_schema("64-character lowercase hex parent memory IDs from the context packet."),
    );
    properties.insert(
        "answer_hash".to_owned(),
        hash_schema("64-character lowercase hex digest of the completed answer."),
    );
    properties.insert(
        "route_id".to_owned(),
        hash_schema("64-character lowercase hex route ID the writeback belongs to."),
    );
    properties.insert(
        "context_packet_id".to_owned(),
        hash_schema("64-character lowercase hex context packet ID the writeback cites."),
    );
    properties.insert(
        "validation_report_id".to_owned(),
        hash_schema("64-character lowercase hex validation report ID."),
    );
    properties.insert(
        "summary_text".to_owned(),
        optional_safe_text_schema("Optional bounded summary of the completed work."),
    );
    properties.insert(
        "citation_hashes".to_owned(),
        optional_hash_array_schema("Optional 64-character lowercase hex citation hashes."),
    );
    properties.insert(
        "safety_score_id".to_owned(),
        optional_safe_string_schema("Optional safety-score ID."),
    );
    properties.insert(
        "keyword_texts".to_owned(),
        optional_safe_string_array_schema("Optional keyword texts for later recall."),
    );
    properties.insert(
        "knowledge_class".to_owned(),
        optional_safe_string_schema("Optional typed-knowledge class (e.g. `decision`/`finding`)."),
    );
    properties.insert(
        "layered_mode".to_owned(),
        optional_safe_string_schema("Optional layered writeback mode."),
    );
    properties.insert(
        "target_layer_path".to_owned(),
        optional_safe_string_schema("Optional repo-local target layer path."),
    );
    properties.insert(
        "target_layer_depth".to_owned(),
        optional_token_budget_schema("Optional depth of the target layer path."),
    );
    properties.insert(
        "target_layer_reason".to_owned(),
        optional_safe_string_schema("Optional safe reason code for the target layer writeback."),
    );
    properties.insert(
        WRITE_SIGNATURE_HEADER.to_owned(),
        signature_schema("Gateway write signature forwarded as `x-exo-write-signature`."),
    );
    properties.insert(
        LIFECYCLE_SIGNATURE_HEADER.to_owned(),
        signature_schema("Gateway lifecycle signature forwarded as `x-exo-lifecycle-signature`."),
    );
    properties.insert(
        CONTINUATION_SIGNATURE_HEADER.to_owned(),
        signature_schema(
            "Gateway continuation signature forwarded as `x-exo-continuation-signature`.",
        ),
    );
    properties.insert(
        LIFECYCLE_APPROVAL_DID_HEADER.to_owned(),
        did_schema("External DID that signed the lifecycle finality approval."),
    );
    properties.insert(
        CONTINUATION_APPROVAL_DID_HEADER.to_owned(),
        did_schema("External DID that signed the continuation finality approval."),
    );
    properties.insert(
        LIFECYCLE_APPROVAL_TIMESTAMP_HEADER.to_owned(),
        approval_timestamp_schema(
            "External lifecycle approval timestamp forwarded as `x-exo-lifecycle-approval-timestamp`.",
        ),
    );
    properties.insert(
        CONTINUATION_APPROVAL_TIMESTAMP_HEADER.to_owned(),
        approval_timestamp_schema(
            "External continuation approval timestamp forwarded as `x-exo-continuation-approval-timestamp`.",
        ),
    );

    ToolDefinition {
        name: DAGDB_SUBMIT_WRITEBACK_TOOL.to_owned(),
        description: "Submit completed-task evidence to the DAG DB writeback endpoint through the runtime MCP surface, with context-packet lineage. When no gateway is configured this node fails closed with a structured `dagdb_adapter_unconfigured` result instead of fabricating a writeback receipt.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": [
                "tenant_id",
                "namespace",
                "idempotency_key",
                "requesting_agent_did",
                "parent_memory_ids",
                "answer_hash",
                "route_id",
                "context_packet_id",
                "validation_report_id",
                WRITE_SIGNATURE_HEADER,
                LIFECYCLE_SIGNATURE_HEADER,
                CONTINUATION_SIGNATURE_HEADER,
                LIFECYCLE_APPROVAL_DID_HEADER,
                CONTINUATION_APPROVAL_DID_HEADER,
                LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
                CONTINUATION_APPROVAL_TIMESTAMP_HEADER
            ],
            "additionalProperties": false,
        }),
    }
}

/// Tool definition for `dagdb_import`.
///
/// Input schema is bound to `exo_api::dagdb::DagDbImportRequest`.
#[must_use]
pub fn import_definition() -> ToolDefinition {
    let mut properties = common_properties();
    properties.insert(
        "source_hash".to_owned(),
        hash_schema("64-character digest for the approved import source material."),
    );
    properties.insert(
        "requester_did".to_owned(),
        did_schema("DID requesting the import operation."),
    );
    properties.insert("import_report".to_owned(), import_report_schema());
    properties.insert(
        WRITE_SIGNATURE_HEADER.to_owned(),
        signature_schema("Gateway write signature forwarded as `x-exo-write-signature`."),
    );
    properties.insert(
        IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER.to_owned(),
        signature_schema(
            "External import finality approval signature forwarded as `x-exo-import-approval-signature`.",
        ),
    );
    properties.insert(
        IMPORT_FINALITY_APPROVAL_DID_HEADER.to_owned(),
        did_schema("External DID that signed the import finality approval."),
    );
    properties.insert(
        IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER.to_owned(),
        approval_timestamp_schema(
            "External import finality approval timestamp forwarded as `x-exo-import-approval-timestamp`.",
        ),
    );

    ToolDefinition {
        name: DAGDB_IMPORT_TOOL.to_owned(),
        description: "Request a governed DAG DB import through the runtime MCP surface. When no gateway is configured this node fails closed with a structured `dagdb_adapter_unconfigured` result instead of fabricating persistence.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": [
                "tenant_id",
                "namespace",
                "idempotency_key",
                "db_set_version",
                "source_hash",
                "requester_did",
                "import_report",
                WRITE_SIGNATURE_HEADER,
                IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
                IMPORT_FINALITY_APPROVAL_DID_HEADER,
                IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER
            ],
            "additionalProperties": false,
        }),
    }
}

/// Tool definition for `dagdb_export`.
///
/// Input schema is bound to `exo_api::dagdb::DagDbExportRequest`.
#[must_use]
pub fn export_definition() -> ToolDefinition {
    let mut properties = common_properties();
    properties.insert(
        "requester_did".to_owned(),
        did_schema("DID requesting the export operation."),
    );
    properties.insert(
        "included_memory_ids".to_owned(),
        hash_array_schema("64-character lowercase hex memory IDs included in the export scope."),
    );
    properties.insert(
        "included_graph_styles".to_owned(),
        safe_string_array_schema("Graph styles included in the export scope."),
    );
    properties.insert(
        "included_writeback_idempotency_keys".to_owned(),
        safe_string_array_schema("Writeback idempotency keys included in the export scope."),
    );
    properties.insert(
        "source_commit_or_repo_ref".to_owned(),
        optional_safe_string_schema("Optional commit or repository ref for export provenance."),
    );
    properties.insert(
        "include_preview_context".to_owned(),
        json!({
            "type": "boolean",
            "description": "Whether preview-only context sections are requested.",
        }),
    );
    properties.insert(
        WRITE_SIGNATURE_HEADER.to_owned(),
        signature_schema("Gateway write signature forwarded as `x-exo-write-signature`."),
    );
    properties.insert(
        EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER.to_owned(),
        signature_schema(
            "External export finality approval signature forwarded as `x-exo-export-approval-signature`.",
        ),
    );
    properties.insert(
        EXPORT_FINALITY_APPROVAL_DID_HEADER.to_owned(),
        did_schema("External DID that signed the export finality approval."),
    );
    properties.insert(
        EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER.to_owned(),
        approval_timestamp_schema(
            "External export finality approval timestamp forwarded as `x-exo-export-approval-timestamp`.",
        ),
    );

    ToolDefinition {
        name: DAGDB_EXPORT_TOOL.to_owned(),
        description: "Request a governed DAG DB export through the runtime MCP surface. When no gateway is configured this node fails closed with a structured `dagdb_adapter_unconfigured` result instead of fabricating export artifacts.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": [
                "tenant_id",
                "namespace",
                "idempotency_key",
                "db_set_version",
                "requester_did",
                "included_memory_ids",
                "included_graph_styles",
                "included_writeback_idempotency_keys",
                "include_preview_context",
                WRITE_SIGNATURE_HEADER,
                EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
                EXPORT_FINALITY_APPROVAL_DID_HEADER,
                EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER
            ],
            "additionalProperties": false,
        }),
    }
}

/// Tool definition for `dagdb_trust_check`.
#[must_use]
pub fn trust_check_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_TRUST_CHECK_TOOL,
        "trust_check",
        "Persist a governed DAG DB agent trust-check request through the runtime MCP surface.",
    )
}

/// Tool definition for `dagdb_council_decision`.
#[must_use]
pub fn council_decision_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_COUNCIL_DECISION_TOOL,
        "council_decision",
        "Persist a governed DAG DB council decision through the runtime MCP surface.",
    )
}

/// Tool definition for `dagdb_receipt_lookup`.
#[must_use]
pub fn receipt_lookup_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_RECEIPT_LOOKUP_TOOL,
        "receipt_lookup",
        "Lookup a DAG DB receipt through the runtime MCP surface.",
    )
}

/// Tool definition for `dagdb_catalog_lookup`.
#[must_use]
pub fn catalog_lookup_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_CATALOG_LOOKUP_TOOL,
        "catalog_lookup",
        "Lookup a DAG DB catalog entry through the runtime MCP surface.",
    )
}

/// Tool definition for `dagdb_route_lookup`.
#[must_use]
pub fn route_lookup_definition() -> ToolDefinition {
    fixture_request_schema(
        DAGDB_ROUTE_LOOKUP_TOOL,
        "route_lookup",
        "Lookup a DAG DB route receipt through the runtime MCP surface.",
    )
}

/// Dispatch a tool through the current adapter boundary.
#[cfg(not(feature = "dagdb-gateway-proxy"))]
fn dispatch(tool_name: &str, params: &Value, _context: &NodeContext) -> ToolResult {
    adapter_unconfigured_response(tool_name, params)
}

/// Dispatch a tool through the configured SDK gateway proxy, or fail closed.
#[cfg(feature = "dagdb-gateway-proxy")]
fn dispatch(tool_name: &str, params: &Value, context: &NodeContext) -> ToolResult {
    if let Some(field) = echoed_field_with_forbidden_fragment(params) {
        return mcp_json_error(
            "DAG DB request rejected before unsafe echo.",
            json!({
                "tool_status": "rejected_unsafe_echo_field",
                "tool": tool_name,
                "field": field,
            }),
        );
    }

    let scope = match configured_proxy_scope(tool_name, params, context) {
        Ok(scope) => scope,
        Err(result) => return result,
    };

    let signatures = match signature_headers_for_tool(tool_name, params) {
        Ok(signatures) => signatures,
        Err(result) => return result,
    };

    dispatch_configured(tool_name, params, scope, signatures)
}

/// Execute `dagdb_intake`.
#[must_use]
pub fn execute_intake(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_INTAKE_TOOL, params, context)
}

/// Execute `dagdb_route`.
#[must_use]
pub fn execute_route(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_ROUTE_TOOL, params, context)
}

/// Execute `dagdb_get_context_packet`.
#[must_use]
pub fn execute_get_context_packet(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_GET_CONTEXT_PACKET_TOOL, params, context)
}

/// Execute `dagdb_validate`.
#[must_use]
pub fn execute_validate(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_VALIDATE_TOOL, params, context)
}

/// Execute `dagdb_submit_writeback`.
#[must_use]
pub fn execute_submit_writeback(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_SUBMIT_WRITEBACK_TOOL, params, context)
}

/// Execute `dagdb_import`.
#[must_use]
pub fn execute_import(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_IMPORT_TOOL, params, context)
}

/// Execute `dagdb_export`.
#[must_use]
pub fn execute_export(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_EXPORT_TOOL, params, context)
}

/// Execute `dagdb_trust_check`.
#[must_use]
pub fn execute_trust_check(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_TRUST_CHECK_TOOL, params, context)
}

/// Execute `dagdb_council_decision`.
#[must_use]
pub fn execute_council_decision(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_COUNCIL_DECISION_TOOL, params, context)
}

/// Execute `dagdb_receipt_lookup`.
#[must_use]
pub fn execute_receipt_lookup(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_RECEIPT_LOOKUP_TOOL, params, context)
}

/// Execute `dagdb_catalog_lookup`.
#[must_use]
pub fn execute_catalog_lookup(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_CATALOG_LOOKUP_TOOL, params, context)
}

/// Execute `dagdb_route_lookup`.
#[must_use]
pub fn execute_route_lookup(params: &Value, context: &NodeContext) -> ToolResult {
    dispatch(DAGDB_ROUTE_LOOKUP_TOOL, params, context)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "dagdb-gateway-proxy")]
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
    };

    use jsonschema::JSONSchema;
    use serde_json::Value;

    use super::*;
    #[cfg(feature = "dagdb-gateway-proxy")]
    use crate::mcp::context::DagDbGatewayConfig;

    const FIXTURES: &str = include_str!("../../../fixtures/dagdb/all_dto_fixtures.json");

    fn fixtures() -> Value {
        serde_json::from_str(FIXTURES).expect("DAG DB fixture set parses")
    }

    fn request_fixture(name: &str) -> Value {
        fixtures()
            .get("requests")
            .and_then(|requests| requests.get(name))
            .unwrap_or_else(|| panic!("missing request fixture {name}"))
            .clone()
    }

    #[test]
    fn mcp_dagdb_tool_surface_covers_full_rest_parity() {
        let definitions = [
            intake_definition(),
            route_definition(),
            get_context_packet_definition(),
            validate_definition(),
            submit_writeback_definition(),
            import_definition(),
            export_definition(),
            trust_check_definition(),
            council_decision_definition(),
            receipt_lookup_definition(),
            catalog_lookup_definition(),
            route_lookup_definition(),
        ];
        let names: Vec<String> = definitions
            .iter()
            .map(|definition| definition.name.clone())
            .collect();
        assert_eq!(
            names,
            vec![
                DAGDB_INTAKE_TOOL,
                DAGDB_ROUTE_TOOL,
                DAGDB_GET_CONTEXT_PACKET_TOOL,
                DAGDB_VALIDATE_TOOL,
                DAGDB_SUBMIT_WRITEBACK_TOOL,
                DAGDB_IMPORT_TOOL,
                DAGDB_EXPORT_TOOL,
                DAGDB_TRUST_CHECK_TOOL,
                DAGDB_COUNCIL_DECISION_TOOL,
                DAGDB_RECEIPT_LOOKUP_TOOL,
                DAGDB_CATALOG_LOOKUP_TOOL,
                DAGDB_ROUTE_LOOKUP_TOOL,
            ]
        );

        let executor_cases: [(fn(&Value, &NodeContext) -> ToolResult, &str); 12] = [
            (execute_intake, "intake"),
            (execute_route, "route"),
            (execute_get_context_packet, "context_packet"),
            (execute_validate, "validate"),
            (execute_submit_writeback, "writeback"),
            (execute_import, "import"),
            (execute_export, "export"),
            (execute_trust_check, "trust_check"),
            (execute_council_decision, "council_decision"),
            (execute_receipt_lookup, "receipt_lookup"),
            (execute_catalog_lookup, "catalog_lookup"),
            (execute_route_lookup, "route_lookup"),
        ];
        for (executor, fixture_name) in executor_cases {
            let params = match fixture_name {
                "import" => valid_import_params(),
                "export" => valid_export_params(),
                _ => request_fixture(fixture_name),
            };
            let result = executor(&params, &NodeContext::empty());
            assert!(
                result.is_error,
                "unconfigured DAG DB MCP executor {fixture_name} must fail closed"
            );
        }
    }

    fn schema_signature_value(byte: char) -> String {
        byte.to_string().repeat(SIGNATURE_HEX_CHARS)
    }

    fn add_required_signature_material(tool_name: &str, params: &mut Value) {
        match tool_name {
            DAGDB_INTAKE_TOOL
            | DAGDB_VALIDATE_TOOL
            | DAGDB_TRUST_CHECK_TOOL
            | DAGDB_COUNCIL_DECISION_TOOL => {
                params[WRITE_SIGNATURE_HEADER] = json!(schema_signature_value('a'));
            }
            DAGDB_ROUTE_TOOL => {
                params[WRITE_SIGNATURE_HEADER] = json!(schema_signature_value('a'));
                params[DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER] =
                    json!(schema_signature_value('b'));
                params[DEFAULT_ROUTE_APPROVAL_DID_HEADER] = json!("did:exo:route-authority");
                params[DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
            }
            DAGDB_GET_CONTEXT_PACKET_TOOL => {
                params[WRITE_SIGNATURE_HEADER] = json!(schema_signature_value('a'));
                params[CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER] =
                    json!(schema_signature_value('b'));
                params[CONTEXT_PACKET_APPROVAL_DID_HEADER] = json!("did:exo:context-authority");
                params[CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
            }
            DAGDB_SUBMIT_WRITEBACK_TOOL => {
                params[WRITE_SIGNATURE_HEADER] = json!(schema_signature_value('a'));
                params[LIFECYCLE_SIGNATURE_HEADER] = json!(schema_signature_value('b'));
                params[CONTINUATION_SIGNATURE_HEADER] = json!(schema_signature_value('c'));
                params[LIFECYCLE_APPROVAL_DID_HEADER] = json!("did:exo:lifecycle-authority");
                params[CONTINUATION_APPROVAL_DID_HEADER] = json!("did:exo:continuation-authority");
                params[LIFECYCLE_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
                params[CONTINUATION_APPROVAL_TIMESTAMP_HEADER] = json!("2026-06-20T00:00:01Z");
            }
            DAGDB_IMPORT_TOOL => {
                params[WRITE_SIGNATURE_HEADER] = json!(schema_signature_value('a'));
                params[IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER] =
                    json!(schema_signature_value('b'));
                params[IMPORT_FINALITY_APPROVAL_DID_HEADER] = json!("did:exo:import-authority");
                params[IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
            }
            DAGDB_EXPORT_TOOL => {
                params[WRITE_SIGNATURE_HEADER] = json!(schema_signature_value('a'));
                params[EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER] =
                    json!(schema_signature_value('b'));
                params[EXPORT_FINALITY_APPROVAL_DID_HEADER] = json!("did:exo:export-authority");
                params[EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
            }
            _ => {}
        }
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn response_fixture(name: &str) -> String {
        fixtures()
            .get("responses")
            .and_then(|responses| responses.get(name))
            .unwrap_or_else(|| panic!("missing response fixture {name}"))
            .to_string()
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn error_fixture(name: &str) -> String {
        fixtures()
            .get("errors")
            .and_then(|errors| errors.get(name))
            .unwrap_or_else(|| panic!("missing error fixture {name}"))
            .to_string()
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    struct CapturedRequest {
        request_line: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    struct TestServer {
        base_url: String,
        captured: mpsc::Receiver<CapturedRequest>,
        handle: thread::JoinHandle<()>,
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    impl TestServer {
        fn spawn(status_line: &'static str, body: impl Into<String>) -> Self {
            let body = body.into();
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test gateway");
            let addr = listener.local_addr().expect("test gateway addr");
            let base_url = format!("http://{addr}");
            let (tx, captured) = mpsc::channel();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept test gateway request");
                let request = read_request(&mut stream);
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write test gateway response");
                stream.flush().expect("flush test gateway response");
                tx.send(request).expect("send captured request");
            });
            Self {
                base_url,
                captured,
                handle,
            }
        }

        fn captured(self) -> CapturedRequest {
            let request = self.captured.recv().expect("captured request");
            self.handle.join().expect("test gateway thread exits");
            request
        }
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut buf = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 1024];
            let n = stream.read(&mut chunk).expect("read request bytes");
            assert!(n > 0, "connection closed before request headers");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos;
            }
        };
        let head = String::from_utf8(buf[..header_end].to_vec()).expect("utf8 request head");
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut headers = Vec::new();
        let mut content_length = 0_usize;
        for line in lines {
            if let Some((key, value)) = line.split_once(": ") {
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
                headers.push((key.to_owned(), value.to_owned()));
            }
        }
        let mut body_bytes = buf[header_end + 4..].to_vec();
        while body_bytes.len() < content_length {
            let mut chunk = [0_u8; 1024];
            let n = stream.read(&mut chunk).expect("read request body");
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8(body_bytes).expect("utf8 request body");
        CapturedRequest {
            request_line,
            headers,
            body,
        }
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn gateway_context(base_url: impl Into<String>) -> NodeContext {
        NodeContext {
            dagdb_gateway: Some(DagDbGatewayConfig::new(
                base_url,
                "super-secret-token-value",
                "tenant-a",
                "primary",
            )),
            ..NodeContext::empty()
        }
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn signature_value(byte: char) -> String {
        byte.to_string().repeat(SIGNATURE_HEX_CHARS)
    }

    fn approval_timestamp() -> &'static str {
        "2026-06-20T00:00:00Z"
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn add_write_signature(mut params: Value) -> Value {
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn add_route_signatures(mut params: Value) -> Value {
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params[DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER] = json!(signature_value('b'));
        params[DEFAULT_ROUTE_APPROVAL_DID_HEADER] = json!("did:exo:route-authority");
        params[DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn add_context_packet_signatures(mut params: Value) -> Value {
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params[CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER] = json!(signature_value('d'));
        params[CONTEXT_PACKET_APPROVAL_DID_HEADER] = json!("did:exo:context-authority");
        params[CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn add_writeback_signatures(mut params: Value) -> Value {
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params[LIFECYCLE_SIGNATURE_HEADER] = json!(signature_value('b'));
        params[CONTINUATION_SIGNATURE_HEADER] = json!(signature_value('c'));
        params[LIFECYCLE_APPROVAL_DID_HEADER] = json!("did:exo:finality-authority");
        params[CONTINUATION_APPROVAL_DID_HEADER] = json!("did:exo:finality-authority");
        params[LIFECYCLE_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
        params[CONTINUATION_APPROVAL_TIMESTAMP_HEADER] = json!("2026-06-20T00:00:01Z");
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn add_import_signatures(mut params: Value) -> Value {
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params[IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER] = json!(signature_value('b'));
        params[IMPORT_FINALITY_APPROVAL_DID_HEADER] = json!("did:exo:import-authority");
        params[IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn add_export_signatures(mut params: Value) -> Value {
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params[EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER] = json!(signature_value('b'));
        params[EXPORT_FINALITY_APPROVAL_DID_HEADER] = json!("did:exo:export-authority");
        params[EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER] = json!(approval_timestamp());
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn write_signature_expectations() -> Vec<(&'static str, String)> {
        vec![(WRITE_SIGNATURE_HEADER, signature_value('a'))]
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn route_signature_expectations() -> Vec<(&'static str, String)> {
        vec![
            (WRITE_SIGNATURE_HEADER, signature_value('a')),
            (
                DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
                signature_value('b'),
            ),
            (
                DEFAULT_ROUTE_APPROVAL_DID_HEADER,
                "did:exo:route-authority".to_owned(),
            ),
            (
                DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
                approval_timestamp().to_owned(),
            ),
        ]
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn import_signature_expectations() -> Vec<(&'static str, String)> {
        vec![
            (WRITE_SIGNATURE_HEADER, signature_value('a')),
            (
                IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
                signature_value('b'),
            ),
            (
                IMPORT_FINALITY_APPROVAL_DID_HEADER,
                "did:exo:import-authority".to_owned(),
            ),
            (
                IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
                approval_timestamp().to_owned(),
            ),
        ]
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn export_signature_expectations() -> Vec<(&'static str, String)> {
        vec![
            (WRITE_SIGNATURE_HEADER, signature_value('a')),
            (
                EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
                signature_value('b'),
            ),
            (
                EXPORT_FINALITY_APPROVAL_DID_HEADER,
                "did:exo:export-authority".to_owned(),
            ),
            (
                EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
                approval_timestamp().to_owned(),
            ),
        ]
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn context_packet_signature_expectations() -> Vec<(&'static str, String)> {
        vec![
            (WRITE_SIGNATURE_HEADER, signature_value('a')),
            (
                CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
                signature_value('d'),
            ),
            (
                CONTEXT_PACKET_APPROVAL_DID_HEADER,
                "did:exo:context-authority".to_owned(),
            ),
            (
                CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
                approval_timestamp().to_owned(),
            ),
        ]
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn writeback_signature_expectations() -> Vec<(&'static str, String)> {
        vec![
            (WRITE_SIGNATURE_HEADER, signature_value('a')),
            (LIFECYCLE_SIGNATURE_HEADER, signature_value('b')),
            (CONTINUATION_SIGNATURE_HEADER, signature_value('c')),
            (
                LIFECYCLE_APPROVAL_DID_HEADER,
                "did:exo:finality-authority".to_owned(),
            ),
            (
                CONTINUATION_APPROVAL_DID_HEADER,
                "did:exo:finality-authority".to_owned(),
            ),
            (
                LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
                approval_timestamp().to_owned(),
            ),
            (
                CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
                "2026-06-20T00:00:01Z".to_owned(),
            ),
        ]
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn scoped_import_params() -> Value {
        let mut params = valid_import_params();
        params["idempotency_key"] = json!("idem-import-1");
        params["tenant_id"] = json!("tenant-a");
        params["namespace"] = json!("primary");
        params["db_set_version"] = json!("dag_db-project_memory_v3");
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn scoped_export_params() -> Value {
        let mut params = valid_export_params();
        params["idempotency_key"] = json!("idem-export-1");
        params["tenant_id"] = json!("tenant-a");
        params["namespace"] = json!("primary");
        params["db_set_version"] = json!("dag_db-project_memory_v3");
        params
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn assert_live_proxy(
        execute: fn(&Value, &NodeContext) -> ToolResult,
        params: Value,
        response_fixture_name: &str,
        expected_path: &str,
        expected_scope: &str,
        expected_operation_id: &str,
        expected_signatures: Vec<(&'static str, String)>,
    ) {
        let server = TestServer::spawn("200 OK", response_fixture(response_fixture_name));
        let context = gateway_context(server.base_url.clone());

        let result = execute(&params, &context);
        assert!(
            !result.is_error,
            "live proxy result was an error: {result:?}"
        );
        let body = result_json(&result);
        assert!(
            body["schema_version"]
                .as_str()
                .expect("schema_version")
                .starts_with("dagdb_"),
            "live proxy returned DTO JSON: {body}"
        );

        let request = server.captured();
        assert!(
            request.request_line.starts_with(expected_path),
            "request line was {:?}",
            request.request_line
        );
        assert_eq!(
            request.header("authorization"),
            Some("Bearer super-secret-token-value")
        );
        assert_eq!(request.header("x-exo-tenant-id"), Some("tenant-a"));
        assert_eq!(request.header("x-exo-namespace"), Some("primary"));
        assert_eq!(
            request.header("x-exo-authority-scope"),
            Some(expected_scope)
        );
        for (header, expected) in expected_signatures {
            assert_eq!(request.header(header), Some(expected.as_str()));
        }
        let request_body: Value =
            serde_json::from_str(&request.body).expect("request body is DTO JSON");
        assert_eq!(request_body["idempotency_key"], expected_operation_id);
        assert_eq!(request_body["tenant_id"], "tenant-a");
        assert_eq!(request_body["namespace"], "primary");
        for signature_header in [
            WRITE_SIGNATURE_HEADER,
            DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
            DEFAULT_ROUTE_APPROVAL_DID_HEADER,
            DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
            CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
            CONTEXT_PACKET_APPROVAL_DID_HEADER,
            CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
            LIFECYCLE_SIGNATURE_HEADER,
            CONTINUATION_SIGNATURE_HEADER,
            LIFECYCLE_APPROVAL_DID_HEADER,
            CONTINUATION_APPROVAL_DID_HEADER,
            LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
            CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
            IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            IMPORT_FINALITY_APPROVAL_DID_HEADER,
            IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
            EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            EXPORT_FINALITY_APPROVAL_DID_HEADER,
            EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
        ] {
            assert!(
                !request.body.contains(signature_header),
                "signature transport header {signature_header} must not be forwarded in the DTO body: {}",
                request.body
            );
        }
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn assert_live_lookup_proxy(
        execute: fn(&Value, &NodeContext) -> ToolResult,
        params: Value,
        response_fixture_name: &str,
        expected_path_prefix: &str,
        expected_scope: &str,
    ) {
        let server = TestServer::spawn("200 OK", response_fixture(response_fixture_name));
        let context = gateway_context(server.base_url.clone());

        let result = execute(&params, &context);
        assert!(
            !result.is_error,
            "live lookup proxy result was an error: {result:?}"
        );
        let body = result_json(&result);
        assert!(
            body["schema_version"]
                .as_str()
                .expect("schema_version")
                .starts_with("dagdb_"),
            "live lookup proxy returned DTO JSON: {body}"
        );

        let request = server.captured();
        assert!(
            request.request_line.starts_with(expected_path_prefix),
            "request line was {:?}",
            request.request_line
        );
        assert_eq!(
            request.header("authorization"),
            Some("Bearer super-secret-token-value")
        );
        assert_eq!(request.header("x-exo-tenant-id"), Some("tenant-a"));
        assert_eq!(request.header("x-exo-namespace"), Some("primary"));
        assert_eq!(
            request.header("x-exo-authority-scope"),
            Some(expected_scope)
        );
        assert!(request.body.is_empty(), "GET body must be empty");
    }

    fn valid_import_params() -> Value {
        json!({
            "idempotency_key": "m60-import-001",
            "tenant_id": "dag_db-local",
            "namespace": "dag_db",
            "db_set_version": "project_memory_v3",
            "source_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "requester_did": "did:exo:requester",
            "import_report": {
                "schema_version": KG_IMPORT_REPORT_SCHEMA,
                "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
                "graph_root": "docs/dagdb/crate-restructure",
                "tenant_id": "dag_db-local",
                "namespace": "dag_db",
                "actor_did": "did:exo:kg-importer",
                "batch_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
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
            },
        })
    }

    fn valid_export_params() -> Value {
        json!({
            "idempotency_key": "m60-export-001",
            "tenant_id": "dag_db-local",
            "namespace": "dag_db",
            "db_set_version": "project_memory_v3",
            "requester_did": "did:exo:requester",
            "included_memory_ids": ["2222222222222222222222222222222222222222222222222222222222222222"],
            "included_graph_styles": ["chronological"],
            "included_writeback_idempotency_keys": ["writeback-001"],
            "include_preview_context": false,
        })
    }

    fn result_json(result: &ToolResult) -> Value {
        serde_json::from_str(result.content[0].text()).expect("tool result text is JSON")
    }

    fn assert_rejected_without_echo(mut params: Value, request_field: &str, unsafe_value: &str) {
        params[request_field] = json!(unsafe_value);

        let result = execute_export(&params, &NodeContext::empty());
        assert!(result.is_error);

        let raw = result_json(&result).to_string().to_ascii_lowercase();
        assert_eq!(
            result_json(&result)["tool_status"],
            "rejected_unsafe_echo_field"
        );
        assert!(
            !raw.contains(&unsafe_value.to_ascii_lowercase()),
            "rejection must not echo unsafe value: {raw}"
        );
    }

    #[test]
    fn import_tool_fails_closed_with_unconfigured_gateway_result() {
        let result = execute_import(&valid_import_params(), &NodeContext::empty());
        assert!(result.is_error);
        assert_eq!(
            result_json(&result)["message"],
            "DAG DB runtime gateway is not configured on this node; no DAG DB operation was performed."
        );
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_ADAPTER_UNCONFIGURED);
        assert_eq!(body["tool"], DAGDB_IMPORT_TOOL);
        assert_eq!(body["operation_id"], "m60-import-001");
        assert_eq!(body["tenant_id"], "dag_db-local");
        assert_eq!(body["namespace"], "dag_db");
        assert_eq!(body["db_set_version"], "project_memory_v3");
        assert!(
            body["non_claims"]
                .as_array()
                .expect("non_claims array")
                .contains(&json!("no_runtime_dagdb_operation_was_performed"))
        );

        let raw = body.to_string().to_ascii_lowercase();
        for forbidden in [
            "/users/",
            "source_body",
            "raw_prompt_body",
            "receipt_path",
            "export_artifact_path",
            "sk-proj-",
            "password",
        ] {
            assert!(
                !raw.contains(forbidden),
                "fail-closed response must not leak {forbidden}: {raw}"
            );
        }
    }

    #[test]
    fn export_tool_fails_closed_with_unconfigured_gateway_result() {
        let result = execute_export(&valid_export_params(), &NodeContext::empty());
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_ADAPTER_UNCONFIGURED);
        assert_eq!(body["tool"], DAGDB_EXPORT_TOOL);
        assert_eq!(body["operation_id"], "m60-export-001");
        assert!(
            body["non_claims"]
                .as_array()
                .expect("non_claims array")
                .contains(&json!("no_export_artifact_was_created"))
        );
    }

    #[test]
    fn context_packet_tool_fails_closed_with_unconfigured_gateway_result() {
        let result =
            execute_get_context_packet(&request_fixture("context_packet"), &NodeContext::empty());
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_ADAPTER_UNCONFIGURED);
        assert_eq!(body["tool"], DAGDB_GET_CONTEXT_PACKET_TOOL);
        assert_eq!(body["operation_id"], "idem-packet-1");
        assert_eq!(body["tenant_id"], "tenant-a");
    }

    #[test]
    fn writeback_tool_fails_closed_with_unconfigured_gateway_result() {
        let result = execute_submit_writeback(&request_fixture("writeback"), &NodeContext::empty());
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_ADAPTER_UNCONFIGURED);
        assert_eq!(body["tool"], DAGDB_SUBMIT_WRITEBACK_TOOL);
        assert_eq!(body["operation_id"], "idem-writeback-1");
        assert_eq!(body["tenant_id"], "tenant-a");
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_proxies_all_dagdb_mcp_tools_with_auth_and_tenant_scope() {
        assert_live_proxy(
            execute_intake,
            add_write_signature(request_fixture("intake")),
            "intake",
            "POST /api/v1/dag-db/intake ",
            "dagdb:intake:tenant-a:primary",
            "idem-intake-1",
            write_signature_expectations(),
        );
        assert_live_proxy(
            execute_route,
            add_route_signatures(request_fixture("route")),
            "route",
            "POST /api/v1/dag-db/route ",
            "dagdb:route:tenant-a:primary",
            "idem-route-1",
            route_signature_expectations(),
        );
        assert_live_proxy(
            execute_get_context_packet,
            add_context_packet_signatures(request_fixture("context_packet")),
            "context_packet",
            "POST /api/v1/dag-db/context-packet ",
            "dagdb:context_packet:tenant-a:primary",
            "idem-packet-1",
            context_packet_signature_expectations(),
        );
        assert_live_proxy(
            execute_validate,
            add_write_signature(request_fixture("validate")),
            "validate",
            "POST /api/v1/dag-db/validate ",
            "dagdb:validate:tenant-a:primary",
            "idem-validate-1",
            write_signature_expectations(),
        );
        assert_live_proxy(
            execute_submit_writeback,
            add_writeback_signatures(request_fixture("writeback")),
            "writeback",
            "POST /api/v1/dag-db/writeback ",
            "dagdb:writeback:tenant-a:primary",
            "idem-writeback-1",
            writeback_signature_expectations(),
        );
        assert_live_proxy(
            execute_import,
            add_import_signatures(scoped_import_params()),
            "import",
            "POST /api/v1/dag-db/import ",
            "dagdb:import:tenant-a:primary",
            "idem-import-1",
            import_signature_expectations(),
        );
        assert_live_proxy(
            execute_export,
            add_export_signatures(scoped_export_params()),
            "export",
            "POST /api/v1/dag-db/export ",
            "dagdb:export:tenant-a:primary",
            "idem-export-1",
            export_signature_expectations(),
        );
        assert_live_proxy(
            execute_trust_check,
            add_write_signature(request_fixture("trust_check")),
            "trust_check",
            "POST /api/v1/dag-db/trust-check ",
            "dagdb:trust_check:tenant-a:primary",
            "idem-trust-1",
            write_signature_expectations(),
        );
        assert_live_proxy(
            execute_council_decision,
            add_write_signature(request_fixture("council_decision")),
            "council_decision",
            "POST /api/v1/dag-db/council/decision ",
            "dagdb:council_decision:tenant-a:primary",
            "idem-council-1",
            write_signature_expectations(),
        );
        assert_live_lookup_proxy(
            execute_receipt_lookup,
            request_fixture("receipt_lookup"),
            "receipt_lookup",
            "GET /api/v1/dag-db/receipts/",
            "dagdb:receipt_lookup:tenant-a:primary",
        );
        assert_live_lookup_proxy(
            execute_catalog_lookup,
            request_fixture("catalog_lookup"),
            "catalog_lookup",
            "GET /api/v1/dag-db/catalog/",
            "dagdb:catalog_lookup:tenant-a:primary",
        );
        assert_live_lookup_proxy(
            execute_route_lookup,
            request_fixture("route_lookup"),
            "route_lookup",
            "GET /api/v1/dag-db/routes/",
            "dagdb:route_lookup:tenant-a:primary",
        );
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_missing_auth_fails_closed_before_http() {
        let context = NodeContext {
            dagdb_gateway: Some(DagDbGatewayConfig {
                base_url: Some("http://127.0.0.1:9".to_owned()),
                bearer_token: None,
                tenant_id: Some("tenant-a".to_owned()),
                namespace: Some("primary".to_owned()),
            }),
            ..NodeContext::empty()
        };

        let result = execute_get_context_packet(
            &add_context_packet_signatures(request_fixture("context_packet")),
            &context,
        );
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_AUTH_UNCONFIGURED);
        assert_eq!(body["success_claimed"], false);
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_missing_base_url_fails_closed_before_http() {
        let context = NodeContext {
            dagdb_gateway: Some(DagDbGatewayConfig {
                base_url: None,
                bearer_token: Some(zeroize::Zeroizing::new("token".to_owned())),
                tenant_id: Some("tenant-a".to_owned()),
                namespace: Some("primary".to_owned()),
            }),
            ..NodeContext::empty()
        };

        let result = execute_get_context_packet(
            &add_context_packet_signatures(request_fixture("context_packet")),
            &context,
        );
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_GATEWAY_URL_UNCONFIGURED);
        assert_eq!(body["tool"], DAGDB_GET_CONTEXT_PACKET_TOOL);
        assert_eq!(body["success_claimed"], false);
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_missing_tenant_fails_closed_before_http() {
        let context = NodeContext {
            dagdb_gateway: Some(DagDbGatewayConfig {
                base_url: Some("http://127.0.0.1:9".to_owned()),
                bearer_token: Some(zeroize::Zeroizing::new("token".to_owned())),
                tenant_id: None,
                namespace: Some("primary".to_owned()),
            }),
            ..NodeContext::empty()
        };

        let result = execute_get_context_packet(
            &add_context_packet_signatures(request_fixture("context_packet")),
            &context,
        );
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_TENANT_UNCONFIGURED);
        assert_eq!(body["success_claimed"], false);
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_missing_namespace_fails_closed_before_http() {
        let context = NodeContext {
            dagdb_gateway: Some(DagDbGatewayConfig {
                base_url: Some("http://127.0.0.1:9".to_owned()),
                bearer_token: Some(zeroize::Zeroizing::new("token".to_owned())),
                tenant_id: Some("tenant-a".to_owned()),
                namespace: None,
            }),
            ..NodeContext::empty()
        };

        let result = execute_get_context_packet(
            &add_context_packet_signatures(request_fixture("context_packet")),
            &context,
        );
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_NAMESPACE_UNCONFIGURED);
        assert_eq!(body["tool"], DAGDB_GET_CONTEXT_PACKET_TOOL);
        assert_eq!(body["success_claimed"], false);
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_missing_request_scope_fails_closed_before_http() {
        for (field, expected_status) in [
            ("tenant_id", DAGDB_REQUEST_TENANT_MISSING),
            ("namespace", DAGDB_REQUEST_NAMESPACE_MISSING),
        ] {
            let mut params = add_context_packet_signatures(request_fixture("context_packet"));
            params
                .as_object_mut()
                .expect("context packet params are an object")
                .remove(field);

            let result =
                execute_get_context_packet(&params, &gateway_context("http://127.0.0.1:9"));
            assert!(result.is_error);
            let body = result_json(&result);
            assert_eq!(body["tool_status"], expected_status);
            assert_eq!(body["missing_field"], field);
            assert_eq!(body["success_claimed"], false);
        }
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_scope_mismatch_fails_closed_before_http() {
        let context = NodeContext {
            dagdb_gateway: Some(DagDbGatewayConfig::new(
                "http://127.0.0.1:9",
                "token",
                "tenant-b",
                "primary",
            )),
            ..NodeContext::empty()
        };

        let result = execute_get_context_packet(
            &add_context_packet_signatures(request_fixture("context_packet")),
            &context,
        );
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_TENANT_SCOPE_MISMATCH);
        assert_eq!(body["request_tenant_id"], "tenant-a");
        assert_eq!(body["configured_tenant_id"], "tenant-b");
        assert_eq!(body["success_claimed"], false);
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    fn assert_missing_signature_fails_before_http(
        execute: fn(&Value, &NodeContext) -> ToolResult,
        params: Value,
        expected_missing_header: &str,
    ) {
        let context = gateway_context("http://127.0.0.1:9");

        let result = execute(&params, &context);
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_SIGNATURE_MATERIAL_MISSING);
        assert_eq!(body["missing_signature_header"], expected_missing_header);
        assert_eq!(body["success_claimed"], false);
        assert_ne!(
            body["tool_status"], DAGDB_GATEWAY_REQUEST_FAILED,
            "missing signature must fail before any gateway request"
        );
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_missing_signature_material_fails_closed_before_http() {
        assert_missing_signature_fails_before_http(
            execute_get_context_packet,
            request_fixture("context_packet"),
            WRITE_SIGNATURE_HEADER,
        );
        assert_missing_signature_fails_before_http(
            execute_get_context_packet,
            add_write_signature(request_fixture("context_packet")),
            CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
        );
        let mut context_without_approval_did =
            add_write_signature(request_fixture("context_packet"));
        context_without_approval_did[CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER] =
            json!(signature_value('d'));
        assert_missing_signature_fails_before_http(
            execute_get_context_packet,
            context_without_approval_did,
            CONTEXT_PACKET_APPROVAL_DID_HEADER,
        );
        let mut context_without_approval_timestamp =
            add_write_signature(request_fixture("context_packet"));
        context_without_approval_timestamp[CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER] =
            json!(signature_value('d'));
        context_without_approval_timestamp[CONTEXT_PACKET_APPROVAL_DID_HEADER] =
            json!("did:exo:context-authority");
        assert_missing_signature_fails_before_http(
            execute_get_context_packet,
            context_without_approval_timestamp,
            CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
        );
        assert_missing_signature_fails_before_http(
            execute_import,
            scoped_import_params(),
            WRITE_SIGNATURE_HEADER,
        );
        assert_missing_signature_fails_before_http(
            execute_export,
            scoped_export_params(),
            WRITE_SIGNATURE_HEADER,
        );

        let mut writeback_without_lifecycle = request_fixture("writeback");
        writeback_without_lifecycle[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        assert_missing_signature_fails_before_http(
            execute_submit_writeback,
            writeback_without_lifecycle,
            LIFECYCLE_SIGNATURE_HEADER,
        );

        let mut writeback_without_continuation = request_fixture("writeback");
        writeback_without_continuation[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        writeback_without_continuation[LIFECYCLE_SIGNATURE_HEADER] = json!(signature_value('b'));
        assert_missing_signature_fails_before_http(
            execute_submit_writeback,
            writeback_without_continuation,
            CONTINUATION_SIGNATURE_HEADER,
        );

        let mut writeback_without_lifecycle_authority = request_fixture("writeback");
        writeback_without_lifecycle_authority[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        writeback_without_lifecycle_authority[LIFECYCLE_SIGNATURE_HEADER] =
            json!(signature_value('b'));
        writeback_without_lifecycle_authority[CONTINUATION_SIGNATURE_HEADER] =
            json!(signature_value('c'));
        assert_missing_signature_fails_before_http(
            execute_submit_writeback,
            writeback_without_lifecycle_authority,
            LIFECYCLE_APPROVAL_DID_HEADER,
        );

        let mut writeback_without_continuation_authority = request_fixture("writeback");
        writeback_without_continuation_authority[WRITE_SIGNATURE_HEADER] =
            json!(signature_value('a'));
        writeback_without_continuation_authority[LIFECYCLE_SIGNATURE_HEADER] =
            json!(signature_value('b'));
        writeback_without_continuation_authority[CONTINUATION_SIGNATURE_HEADER] =
            json!(signature_value('c'));
        writeback_without_continuation_authority[LIFECYCLE_APPROVAL_DID_HEADER] =
            json!("did:exo:finality-authority");
        assert_missing_signature_fails_before_http(
            execute_submit_writeback,
            writeback_without_continuation_authority,
            CONTINUATION_APPROVAL_DID_HEADER,
        );

        let mut writeback_without_lifecycle_timestamp = request_fixture("writeback");
        writeback_without_lifecycle_timestamp[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        writeback_without_lifecycle_timestamp[LIFECYCLE_SIGNATURE_HEADER] =
            json!(signature_value('b'));
        writeback_without_lifecycle_timestamp[CONTINUATION_SIGNATURE_HEADER] =
            json!(signature_value('c'));
        writeback_without_lifecycle_timestamp[LIFECYCLE_APPROVAL_DID_HEADER] =
            json!("did:exo:finality-authority");
        writeback_without_lifecycle_timestamp[CONTINUATION_APPROVAL_DID_HEADER] =
            json!("did:exo:finality-authority");
        assert_missing_signature_fails_before_http(
            execute_submit_writeback,
            writeback_without_lifecycle_timestamp,
            LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
        );

        let mut writeback_without_continuation_timestamp = request_fixture("writeback");
        writeback_without_continuation_timestamp[WRITE_SIGNATURE_HEADER] =
            json!(signature_value('a'));
        writeback_without_continuation_timestamp[LIFECYCLE_SIGNATURE_HEADER] =
            json!(signature_value('b'));
        writeback_without_continuation_timestamp[CONTINUATION_SIGNATURE_HEADER] =
            json!(signature_value('c'));
        writeback_without_continuation_timestamp[LIFECYCLE_APPROVAL_DID_HEADER] =
            json!("did:exo:finality-authority");
        writeback_without_continuation_timestamp[CONTINUATION_APPROVAL_DID_HEADER] =
            json!("did:exo:finality-authority");
        writeback_without_continuation_timestamp[LIFECYCLE_APPROVAL_TIMESTAMP_HEADER] =
            json!(approval_timestamp());
        assert_missing_signature_fails_before_http(
            execute_submit_writeback,
            writeback_without_continuation_timestamp,
            CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
        );
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_blank_signature_material_fails_closed_with_required_headers() {
        let mut params = request_fixture("writeback");
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params[LIFECYCLE_SIGNATURE_HEADER] = json!("   ");
        params[CONTINUATION_SIGNATURE_HEADER] = json!(signature_value('c'));

        let result = execute_submit_writeback(&params, &gateway_context("http://127.0.0.1:9"));
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_SIGNATURE_MATERIAL_MISSING);
        assert_eq!(body["missing_signature_header"], LIFECYCLE_SIGNATURE_HEADER);
        assert_eq!(
            body["required_signature_headers"],
            json!([
                WRITE_SIGNATURE_HEADER,
                LIFECYCLE_SIGNATURE_HEADER,
                CONTINUATION_SIGNATURE_HEADER,
                LIFECYCLE_APPROVAL_DID_HEADER,
                CONTINUATION_APPROVAL_DID_HEADER,
                LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
                CONTINUATION_APPROVAL_TIMESTAMP_HEADER
            ])
        );
        assert_eq!(body["success_claimed"], false);
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_invalid_signature_material_fails_without_echoing_value() {
        let mut params = request_fixture("context_packet");
        let invalid_signature = "sk-proj-invalid-signature-value";
        params[WRITE_SIGNATURE_HEADER] = json!(invalid_signature);
        let result = execute_get_context_packet(&params, &gateway_context("http://127.0.0.1:9"));
        assert!(result.is_error);

        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_SIGNATURE_MATERIAL_INVALID);
        assert_eq!(body["invalid_signature_header"], WRITE_SIGNATURE_HEADER);
        assert_eq!(body["success_claimed"], false);
        assert!(
            !body.to_string().contains(invalid_signature),
            "invalid signature value must not be echoed: {body}"
        );
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_invalid_writeback_lifecycle_signature_fails_without_echoing_value() {
        let mut params = request_fixture("writeback");
        let invalid_signature = "invalid-lifecycle-signature";
        params[WRITE_SIGNATURE_HEADER] = json!(signature_value('a'));
        params[LIFECYCLE_SIGNATURE_HEADER] = json!(invalid_signature);
        params[CONTINUATION_SIGNATURE_HEADER] = json!(signature_value('c'));

        let result = execute_submit_writeback(&params, &gateway_context("http://127.0.0.1:9"));
        assert!(result.is_error);

        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_SIGNATURE_MATERIAL_INVALID);
        assert_eq!(body["invalid_signature_header"], LIFECYCLE_SIGNATURE_HEADER);
        assert_eq!(body["success_claimed"], false);
        assert!(
            !body.to_string().contains(invalid_signature),
            "invalid signature value must not be echoed: {body}"
        );
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn configured_gateway_decode_failure_returns_structured_error_before_http() {
        let mut params = add_context_packet_signatures(request_fixture("context_packet"));
        params["token_budget"] = json!("not-a-token-budget");

        let result = execute_get_context_packet(&params, &gateway_context("http://127.0.0.1:9"));
        assert!(result.is_error);

        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_REQUEST_DECODE_FAILED);
        assert_eq!(body["tool"], DAGDB_GET_CONTEXT_PACKET_TOOL);
        assert_eq!(body["success_claimed"], false);
        assert!(
            body["decode_error"]
                .as_str()
                .is_some_and(|error| !error.is_empty()),
            "decode failure should include a structured decode_error: {body}"
        );
    }

    #[cfg(feature = "dagdb-gateway-proxy")]
    #[test]
    fn gateway_error_envelope_maps_to_typed_mcp_error() {
        let server = TestServer::spawn("403 Forbidden", error_fixture("tenant_scope_mismatch"));
        let context = gateway_context(server.base_url.clone());

        let result = execute_get_context_packet(
            &add_context_packet_signatures(request_fixture("context_packet")),
            &context,
        );
        assert!(result.is_error);
        let body = result_json(&result);
        assert_eq!(body["tool_status"], DAGDB_GATEWAY_REQUEST_FAILED);
        assert_eq!(body["error_kind"], "server");
        assert_eq!(body["status"], 403);
        assert_eq!(body["error_code"], "tenant_scope_mismatch");
        assert_eq!(body["success_claimed"], false);

        let request = server.captured();
        assert_eq!(
            request.header("x-exo-authority-scope"),
            Some("dagdb:context_packet:tenant-a:primary")
        );
        assert_eq!(
            request.header(WRITE_SIGNATURE_HEADER),
            Some(signature_value('a').as_str())
        );
    }

    #[test]
    fn echoed_fields_reject_secret_like_fragments_without_echoing_them() {
        for (request_field, unsafe_value) in [
            ("idempotency_key", "sk-proj-abc"),
            ("tenant_id", "password-token"),
            ("namespace", "ghp_common-token-prefix"),
            ("db_set_version", "release-token-v1"),
        ] {
            assert_rejected_without_echo(valid_export_params(), request_field, unsafe_value);
        }
    }

    #[test]
    fn export_schema_accepts_null_source_commit_or_repo_ref() {
        let definition = export_definition();
        let validator =
            JSONSchema::compile(&definition.input_schema).expect("export schema compiles");
        let mut params = valid_export_params();
        add_required_signature_material(DAGDB_EXPORT_TOOL, &mut params);
        params["source_commit_or_repo_ref"] = Value::Null;

        let errors = validator
            .validate(&params)
            .err()
            .map(|errors| errors.map(|err| err.to_string()).collect::<Vec<_>>());
        assert!(
            errors.is_none(),
            "source_commit_or_repo_ref: null should validate, got: {errors:?}"
        );
    }

    #[test]
    fn import_report_schema_rejects_arbitrary_nested_payloads_before_dispatch() {
        let definition = import_definition();
        let validator =
            JSONSchema::compile(&definition.input_schema).expect("import schema compiles");

        for import_report in [
            json!({"raw_source_body": "must not be accepted"}),
            json!({
                "schema_version": KG_IMPORT_REPORT_SCHEMA,
                "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
                "source_path": "/Users/example/private.json",
            }),
            json!({
                "schema_version": KG_IMPORT_REPORT_SCHEMA,
                "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
                "batch_id": "not-a-hash",
            }),
            json!({
                "schema_version": KG_IMPORT_REPORT_SCHEMA,
                "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
                "sk-proj-secret-nested": "sk-proj-secret-value",
            }),
            json!({
                "schema_version": "sk-proj-secret-schema",
                "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
            }),
        ] {
            let mut params = valid_import_params();
            add_required_signature_material(DAGDB_IMPORT_TOOL, &mut params);
            params["import_report"] = import_report;
            assert!(
                validator.validate(&params).is_err(),
                "import_report payload must be rejected before dispatch: {params}"
            );
        }
    }

    #[test]
    fn definitions_are_strict_object_schemas() {
        for definition in [
            get_context_packet_definition(),
            submit_writeback_definition(),
            import_definition(),
            export_definition(),
        ] {
            assert_eq!(definition.input_schema["type"], "object");
            assert_eq!(definition.input_schema["additionalProperties"], false);
            for required in ["idempotency_key", "tenant_id", "namespace"] {
                assert!(
                    definition.input_schema["required"]
                        .as_array()
                        .expect("required array")
                        .contains(&json!(required)),
                    "{} must require {required}",
                    definition.name
                );
            }
        }
    }

    #[test]
    fn proxy_tool_schemas_require_gateway_signature_material() {
        assert_required_fields(
            get_context_packet_definition(),
            &[
                WRITE_SIGNATURE_HEADER,
                CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
                CONTEXT_PACKET_APPROVAL_DID_HEADER,
                CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
            ],
        );
        assert_required_fields(
            submit_writeback_definition(),
            &[
                WRITE_SIGNATURE_HEADER,
                LIFECYCLE_SIGNATURE_HEADER,
                CONTINUATION_SIGNATURE_HEADER,
                LIFECYCLE_APPROVAL_DID_HEADER,
                CONTINUATION_APPROVAL_DID_HEADER,
                LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
                CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
            ],
        );
        assert_required_fields(import_definition(), &[WRITE_SIGNATURE_HEADER]);
        assert_required_fields(export_definition(), &[WRITE_SIGNATURE_HEADER]);
    }

    fn assert_required_fields(definition: ToolDefinition, expected_fields: &[&str]) {
        let required = definition.input_schema["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{} schema must define required fields", definition.name));
        for field in expected_fields {
            assert!(
                required.contains(&json!(field)),
                "{} schema must require {field}",
                definition.name
            );
        }
    }

    #[test]
    fn import_report_schema_rejects_digest_only_summary() {
        let definition = import_definition();
        let validator =
            JSONSchema::compile(&definition.input_schema).expect("import schema compiles");
        let mut params = valid_import_params();
        add_required_signature_material(DAGDB_IMPORT_TOOL, &mut params);
        params["import_report"] = json!({
            "schema_version": KG_IMPORT_REPORT_SCHEMA,
            "source_candidates_schema_version": KG_IMPORT_CANDIDATES_SCHEMA,
            "report_hash": "2222222222222222222222222222222222222222222222222222222222222222",
        });

        assert!(
            validator.validate(&params).is_err(),
            "digest-only import reports must be rejected before dispatch"
        );
    }

    #[test]
    fn export_schema_rejects_non_hash_memory_ids() {
        let definition = export_definition();
        let validator =
            JSONSchema::compile(&definition.input_schema).expect("export schema compiles");
        let mut params = valid_export_params();
        add_required_signature_material(DAGDB_EXPORT_TOOL, &mut params);
        params["included_memory_ids"] = json!(["memory-001"]);

        assert!(
            validator.validate(&params).is_err(),
            "included_memory_ids must be 64-character lowercase hex hashes"
        );
    }

    // ---------------------------------------------------------------------
    // Schema-drift guard (GAP-012 P1-C, item 4): the MCP tool input schemas
    // must stay bound to the versioned exo-api DAG DB request DTOs. For each
    // tool we (a) parse the shared exo-dag-db request fixture into the DTO so a
    // DTO field rename/removal breaks here, and (b) validate the SAME fixture
    // against the compiled tool schema so a schema rename/removal breaks here.
    // Together a fixture that the DTO accepts but the schema rejects (or vice
    // versa) fails the test rather than drifting silently.
    // ---------------------------------------------------------------------
    #[test]
    fn schemas_stay_bound_to_exo_api_dtos() {
        use exo_api::dagdb::{DagDbContextPacketRequest, DagDbWritebackRequest};

        fn assert_bound<T: serde::de::DeserializeOwned>(
            definition: ToolDefinition,
            fixture_name: &str,
        ) {
            let fixture = request_fixture(fixture_name);

            // (a) The DTO accepts the fixture (binds the schema to the DTO via
            // the shared fixture as the single source of truth).
            let _dto: T = serde_json::from_value(fixture.clone()).unwrap_or_else(|err| {
                panic!("fixture {fixture_name} must deserialize into its exo-api DTO: {err}")
            });

            // (b) The compiled tool schema accepts the same DTO shape plus
            // transport-only signature carrier fields required by the MCP proxy.
            let mut schema_fixture = fixture;
            add_required_signature_material(&definition.name, &mut schema_fixture);
            let validator = JSONSchema::compile(&definition.input_schema)
                .unwrap_or_else(|err| panic!("{} schema compiles: {err}", definition.name));
            if let Err(errors) = validator.validate(&schema_fixture) {
                let msgs: Vec<String> = errors.map(|err| err.to_string()).collect();
                panic!(
                    "{} input schema must accept the exo-api {fixture_name} request fixture: {}",
                    definition.name,
                    msgs.join("; ")
                );
            }
        }

        assert_bound::<DagDbContextPacketRequest>(
            get_context_packet_definition(),
            "context_packet",
        );
        assert_bound::<DagDbWritebackRequest>(submit_writeback_definition(), "writeback");
        // The import/export fixtures live in the SDK helpers, not the shared
        // request fixture set, so build representative DTOs and round-trip them
        // through both the DTO and the schema here.
        assert_import_export_bound();
    }

    fn assert_import_export_bound() {
        use exo_api::dagdb::{DagDbExportRequest, DagDbImportRequest};

        let mut import_params = valid_import_params();
        let _import: DagDbImportRequest = serde_json::from_value(import_params.clone())
            .expect("import params deserialize into DagDbImportRequest");
        add_required_signature_material(DAGDB_IMPORT_TOOL, &mut import_params);
        let import_validator =
            JSONSchema::compile(&import_definition().input_schema).expect("import schema compiles");
        if let Err(errors) = import_validator.validate(&import_params) {
            let msgs: Vec<String> = errors.map(|err| err.to_string()).collect();
            panic!(
                "import schema must accept a valid DagDbImportRequest payload: {}",
                msgs.join("; ")
            );
        }

        let mut export_params = valid_export_params();
        let _export: DagDbExportRequest = serde_json::from_value(export_params.clone())
            .expect("export params deserialize into DagDbExportRequest");
        add_required_signature_material(DAGDB_EXPORT_TOOL, &mut export_params);
        let export_validator =
            JSONSchema::compile(&export_definition().input_schema).expect("export schema compiles");
        if let Err(errors) = export_validator.validate(&export_params) {
            let msgs: Vec<String> = errors.map(|err| err.to_string()).collect();
            panic!(
                "export schema must accept a valid DagDbExportRequest payload: {}",
                msgs.join("; ")
            );
        }
    }
}

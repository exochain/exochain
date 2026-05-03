//! Legal MCP tools — e-discovery search, privilege assertion, DGCL safe harbor,
//! and fiduciary duty compliance checking.

use exo_core::Did;
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MAX_SAFE_HARBOR_INTERESTED_PARTIES: usize = 1_000;
const MAX_LEGAL_DID_BYTES: usize = 512;
const MAX_LEGAL_ID_BYTES: usize = 256;
const MAX_LEGAL_QUERY_BYTES: usize = 4 * 1024;
const MAX_LEGAL_TEXT_BYTES: usize = 16 * 1024;

const MCP_LEGAL_SIMULATION_INITIATIVE: &str = "Initiatives/fix-mcp-legal-simulation-tools.md";

fn legal_runtime_unavailable(tool_name: &str) -> ToolResult {
    tracing::warn!(
        tool = %tool_name,
        "refusing MCP legal operation: no live legal/evidence runtime is attached"
    );
    ToolResult::error(
        json!({
            "error": "mcp_legal_runtime_unavailable",
            "tool": tool_name,
            "message": "This MCP legal tool has no live legal/evidence runtime attached, so it cannot search evidence, assert privilege, initiate safe harbor, or assess fiduciary duty. The `unaudited-mcp-simulation-tools` feature does not enable synthetic legal workflow state.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": MCP_LEGAL_SIMULATION_INITIATIVE,
            "refusal_source": format!("exo-node/mcp/tools/legal.rs::{tool_name}"),
        })
        .to_string(),
    )
}

fn required_bounded_nonempty_str<'a>(
    params: &'a Value,
    name: &str,
    max_bytes: usize,
) -> std::result::Result<&'a str, ToolResult> {
    match params.get(name).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => {
            validate_bounded_str(value, name, max_bytes)?;
            Ok(value)
        }
        Some(_) => Err(ToolResult::error(
            json!({"error": format!("{name} must not be empty")}).to_string(),
        )),
        None => Err(ToolResult::error(
            json!({"error": format!("missing required parameter: {name}")}).to_string(),
        )),
    }
}

fn optional_bounded_str<'a>(
    params: &'a Value,
    name: &str,
    max_bytes: usize,
) -> std::result::Result<Option<&'a str>, ToolResult> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(ToolResult::error(
            json!({"error": format!("{name} must be a string")}).to_string(),
        ));
    };
    validate_bounded_str(raw, name, max_bytes)?;
    Ok(Some(raw))
}

fn validate_bounded_str(
    value: &str,
    name: &str,
    max_bytes: usize,
) -> std::result::Result<(), ToolResult> {
    if value.len() > max_bytes {
        return Err(ToolResult::error(
            json!({"error": format!("{name} may contain at most {max_bytes} bytes")}).to_string(),
        ));
    }
    Ok(())
}

fn required_did_str<'a>(params: &'a Value, name: &str) -> std::result::Result<&'a str, ToolResult> {
    let raw = required_bounded_nonempty_str(params, name, MAX_LEGAL_DID_BYTES)?;
    if Did::new(raw).is_err() {
        return Err(ToolResult::error(
            json!({"error": format!("invalid {name} DID format")}).to_string(),
        ));
    }
    Ok(raw)
}

fn required_nonzero_u64(params: &Value, name: &str) -> std::result::Result<u64, ToolResult> {
    match params.get(name).and_then(Value::as_u64) {
        Some(value) if value > 0 => Ok(value),
        Some(_) => Err(ToolResult::error(
            json!({"error": format!("{name} must be a nonzero integer")}).to_string(),
        )),
        None => Err(ToolResult::error(
            json!({"error": format!("missing required parameter: {name}")}).to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// exochain_ediscovery_search
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_ediscovery_search`.
#[must_use]
pub fn ediscovery_search_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_ediscovery_search".to_owned(),
        description: "Search the evidence corpus for e-discovery purposes. Returns matching results with relevance scores.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_QUERY_BYTES,
                    "description": "Search query string."
                },
                "scope": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "Optional scope restriction (e.g. \"emails\", \"contracts\", \"all\")."
                },
                "date_range_start": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "Optional ISO-8601 start date for the search window."
                },
                "date_range_end": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "Optional ISO-8601 end date for the search window."
                },
                "search_id": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "Caller-supplied non-placeholder search ID."
                },
                "searched_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for the search."
                }
            },
            "required": ["query", "search_id", "searched_at_ms"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_ediscovery_search` tool.
#[must_use]
pub fn execute_ediscovery_search(params: &Value, _context: &NodeContext) -> ToolResult {
    if let Err(result) = required_bounded_nonempty_str(params, "query", MAX_LEGAL_QUERY_BYTES) {
        return result;
    }
    if let Err(result) = optional_bounded_str(params, "scope", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    if let Err(result) = required_bounded_nonempty_str(params, "search_id", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    if let Err(result) = required_nonzero_u64(params, "searched_at_ms") {
        return result;
    }
    if let Err(result) = optional_bounded_str(params, "date_range_start", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    if let Err(result) = optional_bounded_str(params, "date_range_end", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    legal_runtime_unavailable("exochain_ediscovery_search")
}

// ---------------------------------------------------------------------------
// exochain_assert_privilege
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_assert_privilege`.
#[must_use]
pub fn assert_privilege_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_assert_privilege".to_owned(),
        description:
            "Assert legal privilege over evidence, marking it as protected from disclosure."
                .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "evidence_id": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "ID of the evidence to assert privilege over."
                },
                "privilege_type": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "enum": ["attorney_client", "work_product", "deliberative"],
                    "description": "Type of privilege to assert."
                },
                "asserter_did": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_DID_BYTES,
                    "description": "DID of the person asserting privilege."
                },
                "assertion_id": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "Caller-supplied non-placeholder privilege assertion ID."
                },
                "asserted_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for assertion."
                }
            },
            "required": ["evidence_id", "privilege_type", "asserter_did", "assertion_id", "asserted_at_ms"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_assert_privilege` tool.
#[must_use]
pub fn execute_assert_privilege(params: &Value, _context: &NodeContext) -> ToolResult {
    if let Err(result) = required_bounded_nonempty_str(params, "evidence_id", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    let privilege_type =
        match required_bounded_nonempty_str(params, "privilege_type", MAX_LEGAL_ID_BYTES) {
            Ok(value) => value,
            Err(result) => return result,
        };
    if let Err(result) = required_did_str(params, "asserter_did") {
        return result;
    }
    if let Err(result) = required_bounded_nonempty_str(params, "assertion_id", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    if let Err(result) = required_nonzero_u64(params, "asserted_at_ms") {
        return result;
    }

    let valid_types = ["attorney_client", "work_product", "deliberative"];
    if !valid_types.contains(&privilege_type) {
        return ToolResult::error(
            json!({
                "error": "invalid privilege_type",
                "allowed": valid_types,
            })
            .to_string(),
        );
    }

    legal_runtime_unavailable("exochain_assert_privilege")
}

// ---------------------------------------------------------------------------
// exochain_initiate_safe_harbor
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_initiate_safe_harbor`.
#[must_use]
pub fn initiate_safe_harbor_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_initiate_safe_harbor".to_owned(),
        description: "Initiate a DGCL Section 144 safe harbor process for an interested-party transaction, creating disclosure requirements.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "initiator_did": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_DID_BYTES,
                    "description": "DID of the person initiating the safe harbor process."
                },
                "transaction_description": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_TEXT_BYTES,
                    "description": "Description of the transaction requiring safe harbor."
                },
                "interested_parties": {
                    "type": "array",
                    "items": { "type": "string", "maxLength": MAX_LEGAL_DID_BYTES },
                    "maxItems": MAX_SAFE_HARBOR_INTERESTED_PARTIES,
                    "description": "Array of DID strings for the interested parties."
                },
                "process_id": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "Caller-supplied non-placeholder safe-harbor process ID."
                },
                "initiated_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for initiation."
                }
            },
            "required": ["initiator_did", "transaction_description", "interested_parties", "process_id", "initiated_at_ms"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_initiate_safe_harbor` tool.
#[must_use]
pub fn execute_initiate_safe_harbor(params: &Value, _context: &NodeContext) -> ToolResult {
    if let Err(result) = required_did_str(params, "initiator_did") {
        return result;
    }
    if let Err(result) =
        required_bounded_nonempty_str(params, "transaction_description", MAX_LEGAL_TEXT_BYTES)
    {
        return result;
    }
    let interested_parties = match params.get("interested_parties").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: interested_parties (must be an array)"})
                    .to_string(),
            );
        }
    };
    if interested_parties.len() > MAX_SAFE_HARBOR_INTERESTED_PARTIES {
        return ToolResult::error(
            json!({
                "error": format!(
                    "interested_parties may contain at most {MAX_SAFE_HARBOR_INTERESTED_PARTIES} DIDs"
                )
            })
            .to_string(),
        );
    }
    if let Err(result) = required_bounded_nonempty_str(params, "process_id", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    if let Err(result) = required_nonzero_u64(params, "initiated_at_ms") {
        return result;
    }

    for (i, party) in interested_parties.iter().enumerate() {
        match party.as_str() {
            Some(s) => {
                let field = format!("interested_parties[{i}]");
                if let Err(result) = validate_bounded_str(s, &field, MAX_LEGAL_DID_BYTES) {
                    return result;
                }
                if Did::new(s).is_err() {
                    return ToolResult::error(
                        json!({"error": format!("invalid DID at interested_parties[{i}]")})
                            .to_string(),
                    );
                }
            }
            None => {
                return ToolResult::error(
                    json!({"error": format!("interested_parties[{i}] is not a string")})
                        .to_string(),
                );
            }
        }
    }

    legal_runtime_unavailable("exochain_initiate_safe_harbor")
}

// ---------------------------------------------------------------------------
// exochain_check_fiduciary_duty
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_check_fiduciary_duty`.
#[must_use]
pub fn check_fiduciary_duty_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_check_fiduciary_duty".to_owned(),
        description: "Check fiduciary duty compliance for a proposed action by an actor toward a beneficiary.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "actor_did": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_DID_BYTES,
                    "description": "DID of the actor whose fiduciary duty is being assessed."
                },
                "action": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_TEXT_BYTES,
                    "description": "Description of the proposed action."
                },
                "beneficiary_did": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_DID_BYTES,
                    "description": "DID of the beneficiary owed the fiduciary duty."
                },
                "check_id": {
                    "type": "string",
                    "maxLength": MAX_LEGAL_ID_BYTES,
                    "description": "Caller-supplied non-placeholder fiduciary check ID."
                },
                "checked_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for the check."
                }
            },
            "required": ["actor_did", "action", "beneficiary_did", "check_id", "checked_at_ms"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_check_fiduciary_duty` tool.
#[must_use]
pub fn execute_check_fiduciary_duty(params: &Value, _context: &NodeContext) -> ToolResult {
    if let Err(result) = required_did_str(params, "actor_did") {
        return result;
    }
    if let Err(result) = required_bounded_nonempty_str(params, "action", MAX_LEGAL_TEXT_BYTES) {
        return result;
    }
    if let Err(result) = required_did_str(params, "beneficiary_did") {
        return result;
    }
    if let Err(result) = required_bounded_nonempty_str(params, "check_id", MAX_LEGAL_ID_BYTES) {
        return result;
    }
    if let Err(result) = required_nonzero_u64(params, "checked_at_ms") {
        return result;
    }

    legal_runtime_unavailable("exochain_check_fiduciary_duty")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn assert_legal_runtime_unavailable(result: ToolResult, tool_name: &str) {
        assert!(
            result.is_error,
            "{tool_name} must refuse by default until legal/evidence stores are wired"
        );
        let text = result.content[0].text();
        assert!(text.contains("mcp_legal_runtime_unavailable"));
        assert!(text.contains(tool_name));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-legal-simulation-tools.md"));
        for forbidden in [
            "\"status\":\"completed\"",
            "\"status\":\"asserted\"",
            "\"status\":\"initiated\"",
            "\"overall_status\":\"requires_review\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "{tool_name} must not emit synthetic legal status field {forbidden}"
            );
        }
    }

    // -- ediscovery_search ----------------------------------------------------

    #[test]
    fn ediscovery_search_definition_valid() {
        let def = ediscovery_search_definition();
        assert_eq!(def.name, "exochain_ediscovery_search");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_ediscovery_search_refuses_without_legal_runtime_even_with_simulation_feature() {
        let params = json!({
            "query": "contract breach",
            "search_id": "search-001",
            "searched_at_ms": 1700000000000_u64,
        });
        let result = execute_ediscovery_search(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_ediscovery_search");
    }

    #[test]
    fn execute_ediscovery_search_with_scope() {
        let params = json!({
            "query": "merger",
            "scope": "emails",
            "date_range_start": "2025-01-01",
            "date_range_end": "2025-12-31",
            "search_id": "search-002",
            "searched_at_ms": 1700000000001_u64,
        });
        let result = execute_ediscovery_search(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_ediscovery_search");
    }

    #[test]
    fn execute_ediscovery_search_missing_query() {
        let result = execute_ediscovery_search(
            &json!({"search_id": "search-003", "searched_at_ms": 1700000000002_u64}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_ediscovery_search_missing_metadata() {
        let result =
            execute_ediscovery_search(&json!({"query": "contract breach"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    fn execute_ediscovery_search_refuses_by_default() {
        let params = json!({
            "query": "contract breach",
            "search_id": "search-001",
            "searched_at_ms": 1700000000000_u64,
        });
        let result = execute_ediscovery_search(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_ediscovery_search");
    }

    // -- assert_privilege -----------------------------------------------------

    #[test]
    fn assert_privilege_definition_valid() {
        let def = assert_privilege_definition();
        assert_eq!(def.name, "exochain_assert_privilege");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_assert_privilege_refuses_without_legal_runtime_even_with_simulation_feature() {
        let params = json!({
            "evidence_id": "ev123",
            "privilege_type": "attorney_client",
            "asserter_did": "did:exo:counsel",
            "assertion_id": "assertion-001",
            "asserted_at_ms": 1700000000010_u64,
        });
        let result = execute_assert_privilege(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_assert_privilege");
    }

    #[test]
    fn execute_assert_privilege_invalid_type() {
        let params = json!({
            "evidence_id": "ev123",
            "privilege_type": "invalid_type",
            "asserter_did": "did:exo:counsel",
            "assertion_id": "assertion-002",
            "asserted_at_ms": 1700000000011_u64,
        });
        let result = execute_assert_privilege(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_assert_privilege_invalid_did() {
        let params = json!({
            "evidence_id": "ev123",
            "privilege_type": "work_product",
            "asserter_did": "bad",
            "assertion_id": "assertion-003",
            "asserted_at_ms": 1700000000012_u64,
        });
        let result = execute_assert_privilege(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    fn execute_assert_privilege_refuses_by_default() {
        let params = json!({
            "evidence_id": "ev123",
            "privilege_type": "attorney_client",
            "asserter_did": "did:exo:counsel",
            "assertion_id": "assertion-001",
            "asserted_at_ms": 1700000000010_u64,
        });
        let result = execute_assert_privilege(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_assert_privilege");
    }

    // -- initiate_safe_harbor -------------------------------------------------

    #[test]
    fn initiate_safe_harbor_definition_valid() {
        let def = initiate_safe_harbor_definition();
        assert_eq!(def.name, "exochain_initiate_safe_harbor");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_initiate_safe_harbor_refuses_without_legal_runtime_even_with_simulation_feature() {
        let params = json!({
            "initiator_did": "did:exo:alice",
            "transaction_description": "Acquisition of subsidiary",
            "interested_parties": ["did:exo:bob", "did:exo:carol"],
            "process_id": "safe-harbor-001",
            "initiated_at_ms": 1700000000020_u64,
        });
        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_initiate_safe_harbor");
    }

    #[test]
    fn execute_initiate_safe_harbor_invalid_initiator() {
        let params = json!({
            "initiator_did": "bad",
            "transaction_description": "test",
            "interested_parties": [],
            "process_id": "safe-harbor-002",
            "initiated_at_ms": 1700000000021_u64,
        });
        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_initiate_safe_harbor_invalid_party() {
        let params = json!({
            "initiator_did": "did:exo:alice",
            "transaction_description": "test",
            "interested_parties": ["not-a-did"],
            "process_id": "safe-harbor-003",
            "initiated_at_ms": 1700000000022_u64,
        });
        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_initiate_safe_harbor_rejects_excessive_interested_parties() {
        let interested_parties: Vec<Value> = (0..=MAX_SAFE_HARBOR_INTERESTED_PARTIES)
            .map(|i| Value::String(format!("did:exo:party-{i}")))
            .collect();
        let params = json!({
            "initiator_did": "did:exo:alice",
            "transaction_description": "test",
            "interested_parties": interested_parties,
            "process_id": "safe-harbor-oversized",
            "initiated_at_ms": 1700000000023_u64,
        });

        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());

        assert!(result.is_error);
        assert!(
            result.content[0]
                .text()
                .contains("interested_parties may contain at most")
        );
    }

    #[test]
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    fn execute_initiate_safe_harbor_refuses_by_default() {
        let params = json!({
            "initiator_did": "did:exo:alice",
            "transaction_description": "Acquisition of subsidiary",
            "interested_parties": ["did:exo:bob", "did:exo:carol"],
            "process_id": "safe-harbor-001",
            "initiated_at_ms": 1700000000020_u64,
        });
        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_initiate_safe_harbor");
    }

    // -- check_fiduciary_duty -------------------------------------------------

    #[test]
    fn check_fiduciary_duty_definition_valid() {
        let def = check_fiduciary_duty_definition();
        assert_eq!(def.name, "exochain_check_fiduciary_duty");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_check_fiduciary_duty_refuses_without_legal_runtime_even_with_simulation_feature() {
        let params = json!({
            "actor_did": "did:exo:director",
            "action": "approve merger with personal interest",
            "beneficiary_did": "did:exo:shareholders",
            "check_id": "fiduciary-001",
            "checked_at_ms": 1700000000030_u64,
        });
        let result = execute_check_fiduciary_duty(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_check_fiduciary_duty");
    }

    #[test]
    fn execute_check_fiduciary_duty_invalid_actor() {
        let params = json!({
            "actor_did": "bad",
            "action": "something",
            "beneficiary_did": "did:exo:someone",
            "check_id": "fiduciary-002",
            "checked_at_ms": 1700000000031_u64,
        });
        let result = execute_check_fiduciary_duty(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_check_fiduciary_duty_missing_action() {
        let result = execute_check_fiduciary_duty(
            &json!({"actor_did": "did:exo:a", "beneficiary_did": "did:exo:b"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    fn execute_check_fiduciary_duty_refuses_by_default() {
        let params = json!({
            "actor_did": "did:exo:director",
            "action": "approve merger with personal interest",
            "beneficiary_did": "did:exo:shareholders",
            "check_id": "fiduciary-001",
            "checked_at_ms": 1700000000030_u64,
        });
        let result = execute_check_fiduciary_duty(&params, &NodeContext::empty());
        assert_legal_runtime_unavailable(result, "exochain_check_fiduciary_duty");
    }

    #[test]
    fn feature_gated_legal_errors_do_not_reflect_raw_untrusted_dids() {
        let source = include_str!("legal.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("tests marker present");
        for needle in [
            "invalid DID format: {asserter_did_str}",
            "invalid DID format: {initiator_did_str}",
            "invalid DID at interested_parties[{i}]: {s}",
            "invalid DID format: {actor_did_str}",
            "invalid DID format: {beneficiary_did_str}",
        ] {
            assert!(
                !production.contains(needle),
                "legal MCP tool errors must not reflect raw DID input: {needle}"
            );
        }
    }

    #[test]
    fn feature_gated_legal_tools_bound_untrusted_strings_before_copying() {
        let source = include_str!("legal.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("tests marker present");
        for needle in [
            "const MAX_LEGAL_DID_BYTES",
            "const MAX_LEGAL_ID_BYTES",
            "const MAX_LEGAL_QUERY_BYTES",
            "const MAX_LEGAL_TEXT_BYTES",
            "required_bounded_nonempty_str",
            "optional_bounded_str",
        ] {
            assert!(
                production.contains(needle),
                "legal MCP feature-on simulation inputs must be bounded before allocation: {needle}"
            );
        }
    }

    #[test]
    fn execute_initiate_safe_harbor_rejects_oversized_party_did_without_echoing_it() {
        let oversized = format!("did:exo:{}", "a".repeat(MAX_LEGAL_DID_BYTES + 1));
        let params = json!({
            "initiator_did": "did:exo:alice",
            "transaction_description": "test",
            "interested_parties": [oversized],
            "process_id": "safe-harbor-oversized-party",
            "initiated_at_ms": 1700000000024_u64,
        });

        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("interested_parties[0] may contain at most"));
        assert!(
            !text.contains("aaaa"),
            "oversized party DID must not be reflected into the error response"
        );
    }

    #[test]
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    fn default_build_source_guard_refuses_before_legal_status_json() {
        let source = include_str!("legal.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("tests marker present");
        for (function, tool_name) in [
            ("execute_ediscovery_search", "exochain_ediscovery_search"),
            ("execute_assert_privilege", "exochain_assert_privilege"),
            (
                "execute_initiate_safe_harbor",
                "exochain_initiate_safe_harbor",
            ),
            (
                "execute_check_fiduciary_duty",
                "exochain_check_fiduciary_duty",
            ),
        ] {
            assert!(
                production.contains(&format!("legal_runtime_unavailable(\"{tool_name}\")")),
                "{function} must fail closed through the legal runtime-unavailable path"
            );
        }
        for forbidden in [
            "\"status\": \"completed\"",
            "\"status\": \"asserted\"",
            "\"status\": \"initiated\"",
            "\"overall_status\": \"requires_review\"",
        ] {
            assert!(
                !production.contains(forbidden),
                "production legal MCP paths must not emit synthetic legal-status JSON: {forbidden}"
            );
        }
    }
}

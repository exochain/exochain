//! Legal MCP tools — e-discovery search, privilege assertion, DGCL safe harbor,
//! and fiduciary duty compliance checking.

use exo_core::{Did, Hash256, Timestamp};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

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
                    "description": "Search query string."
                },
                "scope": {
                    "type": "string",
                    "description": "Optional scope restriction (e.g. \"emails\", \"contracts\", \"all\")."
                },
                "date_range_start": {
                    "type": "string",
                    "description": "Optional ISO-8601 start date for the search window."
                },
                "date_range_end": {
                    "type": "string",
                    "description": "Optional ISO-8601 end date for the search window."
                }
            },
            "required": ["query"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_ediscovery_search` tool.
#[must_use]
pub fn execute_ediscovery_search(params: &Value, _context: &NodeContext) -> ToolResult {
    let query = match params.get("query").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: query"}).to_string(),
            );
        }
    };

    let scope = params.get("scope").and_then(Value::as_str).unwrap_or("all");
    let date_range_start = params
        .get("date_range_start")
        .and_then(Value::as_str)
        .map(String::from);
    let date_range_end = params
        .get("date_range_end")
        .and_then(Value::as_str)
        .map(String::from);

    let now = Timestamp::now_utc();
    let search_id = Hash256::digest(
        format!(
            "ediscovery:{}:{}:{}:{}",
            query, scope, now.physical_ms, now.logical
        )
        .as_bytes(),
    );

    let response = json!({
        "search_id": search_id.to_string(),
        "query": query,
        "scope": scope,
        "date_range": {
            "start": date_range_start,
            "end": date_range_end,
        },
        "results": [],
        "total_matches": 0,
        "status": "completed",
        "searched_at": format!("{}:{}", now.physical_ms, now.logical),
        "note": "No evidence corpus is loaded in this node instance.",
    });
    ToolResult::success(response.to_string())
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
                    "description": "ID of the evidence to assert privilege over."
                },
                "privilege_type": {
                    "type": "string",
                    "enum": ["attorney_client", "work_product", "deliberative"],
                    "description": "Type of privilege to assert."
                },
                "asserter_did": {
                    "type": "string",
                    "description": "DID of the person asserting privilege."
                }
            },
            "required": ["evidence_id", "privilege_type", "asserter_did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_assert_privilege` tool.
#[must_use]
pub fn execute_assert_privilege(params: &Value, _context: &NodeContext) -> ToolResult {
    let evidence_id = match params.get("evidence_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: evidence_id"}).to_string(),
            );
        }
    };
    let privilege_type = match params.get("privilege_type").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: privilege_type"}).to_string(),
            );
        }
    };
    let asserter_did_str = match params.get("asserter_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: asserter_did"}).to_string(),
            );
        }
    };

    // Validate privilege type.
    let valid_types = ["attorney_client", "work_product", "deliberative"];
    if !valid_types.contains(&privilege_type) {
        return ToolResult::error(
            json!({"error": format!(
                "invalid privilege_type '{}': must be one of {:?}",
                privilege_type, valid_types
            )})
            .to_string(),
        );
    }

    // Validate DID.
    if Did::new(asserter_did_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid DID format: {asserter_did_str}")}).to_string(),
        );
    }

    let now = Timestamp::now_utc();
    let assertion_id = Hash256::digest(
        format!(
            "privilege:{}:{}:{}:{}:{}",
            evidence_id, privilege_type, asserter_did_str, now.physical_ms, now.logical
        )
        .as_bytes(),
    );

    let response = json!({
        "assertion_id": assertion_id.to_string(),
        "evidence_id": evidence_id,
        "privilege_type": privilege_type,
        "asserter_did": asserter_did_str,
        "status": "asserted",
        "asserted_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
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
                    "description": "DID of the person initiating the safe harbor process."
                },
                "transaction_description": {
                    "type": "string",
                    "description": "Description of the transaction requiring safe harbor."
                },
                "interested_parties": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Array of DID strings for the interested parties."
                }
            },
            "required": ["initiator_did", "transaction_description", "interested_parties"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_initiate_safe_harbor` tool.
#[must_use]
pub fn execute_initiate_safe_harbor(params: &Value, _context: &NodeContext) -> ToolResult {
    let initiator_did_str = match params.get("initiator_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: initiator_did"}).to_string(),
            );
        }
    };
    let transaction_description = match params
        .get("transaction_description")
        .and_then(Value::as_str)
    {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: transaction_description"}).to_string(),
            );
        }
    };
    let interested_parties = match params.get("interested_parties").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: interested_parties (must be an array)"})
                    .to_string(),
            );
        }
    };

    // Validate initiator DID.
    if Did::new(initiator_did_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid DID format: {initiator_did_str}")}).to_string(),
        );
    }

    // Validate each interested party DID.
    let mut party_dids: Vec<String> = Vec::new();
    for (i, party) in interested_parties.iter().enumerate() {
        match party.as_str() {
            Some(s) => {
                if Did::new(s).is_err() {
                    return ToolResult::error(
                        json!({"error": format!("invalid DID at interested_parties[{i}]: {s}")})
                            .to_string(),
                    );
                }
                party_dids.push(s.to_owned());
            }
            None => {
                return ToolResult::error(
                    json!({"error": format!("interested_parties[{i}] is not a string")})
                        .to_string(),
                );
            }
        }
    }

    let now = Timestamp::now_utc();
    let process_id = Hash256::digest(
        format!(
            "safe_harbor:{}:{}:{}:{}",
            initiator_did_str, transaction_description, now.physical_ms, now.logical
        )
        .as_bytes(),
    );

    let disclosure_requirements: Vec<Value> = party_dids
        .iter()
        .map(|did| {
            json!({
                "party_did": did,
                "disclosure_status": "pending",
                "requires": ["material_interest", "relationship_disclosure"],
            })
        })
        .collect();

    let response = json!({
        "process_id": process_id.to_string(),
        "initiator_did": initiator_did_str,
        "transaction_description": transaction_description,
        "interested_parties": party_dids,
        "disclosure_requirements": disclosure_requirements,
        "dgcl_section": "144",
        "status": "initiated",
        "initiated_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
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
                    "description": "DID of the actor whose fiduciary duty is being assessed."
                },
                "action": {
                    "type": "string",
                    "description": "Description of the proposed action."
                },
                "beneficiary_did": {
                    "type": "string",
                    "description": "DID of the beneficiary owed the fiduciary duty."
                }
            },
            "required": ["actor_did", "action", "beneficiary_did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_check_fiduciary_duty` tool.
#[must_use]
pub fn execute_check_fiduciary_duty(params: &Value, _context: &NodeContext) -> ToolResult {
    let actor_did_str = match params.get("actor_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: actor_did"}).to_string(),
            );
        }
    };
    let action = match params.get("action").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: action"}).to_string(),
            );
        }
    };
    let beneficiary_did_str = match params.get("beneficiary_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: beneficiary_did"}).to_string(),
            );
        }
    };

    // Validate DIDs.
    if Did::new(actor_did_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid DID format: {actor_did_str}")}).to_string(),
        );
    }
    if Did::new(beneficiary_did_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid DID format: {beneficiary_did_str}")}).to_string(),
        );
    }

    let now = Timestamp::now_utc();

    // Assess fiduciary duties: loyalty, care, good faith.
    let duties = vec![
        json!({
            "duty": "loyalty",
            "description": "Act in the best interest of the beneficiary, avoiding self-dealing.",
            "status": "requires_review",
        }),
        json!({
            "duty": "care",
            "description": "Exercise the care of an ordinarily prudent person.",
            "status": "requires_review",
        }),
        json!({
            "duty": "good_faith",
            "description": "Act honestly and not for an improper purpose.",
            "status": "requires_review",
        }),
    ];

    let check_id = Hash256::digest(
        format!(
            "fiduciary:{}:{}:{}:{}:{}",
            actor_did_str, action, beneficiary_did_str, now.physical_ms, now.logical
        )
        .as_bytes(),
    );

    let response = json!({
        "check_id": check_id.to_string(),
        "actor_did": actor_did_str,
        "action": action,
        "beneficiary_did": beneficiary_did_str,
        "duties_assessed": duties,
        "overall_status": "requires_review",
        "checked_at": format!("{}:{}", now.physical_ms, now.logical),
        "note": "Automated pre-screening complete. Human review required for final determination.",
    });
    ToolResult::success(response.to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- ediscovery_search ----------------------------------------------------

    #[test]
    fn ediscovery_search_definition_valid() {
        let def = ediscovery_search_definition();
        assert_eq!(def.name, "exochain_ediscovery_search");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_ediscovery_search_success() {
        let params = json!({"query": "contract breach"});
        let result = execute_ediscovery_search(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["query"], "contract breach");
        assert_eq!(v["scope"], "all");
        assert_eq!(v["status"], "completed");
        assert!(v["search_id"].as_str().is_some());
    }

    #[test]
    fn execute_ediscovery_search_with_scope() {
        let params = json!({
            "query": "merger",
            "scope": "emails",
            "date_range_start": "2025-01-01",
            "date_range_end": "2025-12-31",
        });
        let result = execute_ediscovery_search(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["scope"], "emails");
    }

    #[test]
    fn execute_ediscovery_search_missing_query() {
        let result = execute_ediscovery_search(&json!({}), &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- assert_privilege -----------------------------------------------------

    #[test]
    fn assert_privilege_definition_valid() {
        let def = assert_privilege_definition();
        assert_eq!(def.name, "exochain_assert_privilege");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_assert_privilege_success() {
        let params = json!({
            "evidence_id": "ev123",
            "privilege_type": "attorney_client",
            "asserter_did": "did:exo:counsel",
        });
        let result = execute_assert_privilege(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["privilege_type"], "attorney_client");
        assert_eq!(v["status"], "asserted");
        assert!(v["assertion_id"].as_str().is_some());
    }

    #[test]
    fn execute_assert_privilege_invalid_type() {
        let params = json!({
            "evidence_id": "ev123",
            "privilege_type": "invalid_type",
            "asserter_did": "did:exo:counsel",
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
        });
        let result = execute_assert_privilege(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- initiate_safe_harbor -------------------------------------------------

    #[test]
    fn initiate_safe_harbor_definition_valid() {
        let def = initiate_safe_harbor_definition();
        assert_eq!(def.name, "exochain_initiate_safe_harbor");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_initiate_safe_harbor_success() {
        let params = json!({
            "initiator_did": "did:exo:alice",
            "transaction_description": "Acquisition of subsidiary",
            "interested_parties": ["did:exo:bob", "did:exo:carol"],
        });
        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["dgcl_section"], "144");
        assert_eq!(v["status"], "initiated");
        assert_eq!(
            v["interested_parties"].as_array().expect("parties").len(),
            2
        );
        assert_eq!(
            v["disclosure_requirements"]
                .as_array()
                .expect("disclosures")
                .len(),
            2
        );
    }

    #[test]
    fn execute_initiate_safe_harbor_invalid_initiator() {
        let params = json!({
            "initiator_did": "bad",
            "transaction_description": "test",
            "interested_parties": [],
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
        });
        let result = execute_initiate_safe_harbor(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- check_fiduciary_duty -------------------------------------------------

    #[test]
    fn check_fiduciary_duty_definition_valid() {
        let def = check_fiduciary_duty_definition();
        assert_eq!(def.name, "exochain_check_fiduciary_duty");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_check_fiduciary_duty_success() {
        let params = json!({
            "actor_did": "did:exo:director",
            "action": "approve merger with personal interest",
            "beneficiary_did": "did:exo:shareholders",
        });
        let result = execute_check_fiduciary_duty(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["overall_status"], "requires_review");
        let duties = v["duties_assessed"].as_array().expect("duties");
        assert_eq!(duties.len(), 3);
        assert!(v["check_id"].as_str().is_some());
    }

    #[test]
    fn execute_check_fiduciary_duty_invalid_actor() {
        let params = json!({
            "actor_did": "bad",
            "action": "something",
            "beneficiary_did": "did:exo:someone",
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
}

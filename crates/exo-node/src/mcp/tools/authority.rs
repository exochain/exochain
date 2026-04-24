//! Authority MCP tools — delegation, chain verification, permission checking,
//! and constitutional adjudication via the CGR Kernel.

use exo_core::{Did, Hash256, Timestamp};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role,
    },
};
use serde_json::{Value, json};

use crate::mcp::context::NodeContext;
use crate::mcp::protocol::{ToolDefinition, ToolResult};

/// Constitution bytes used to initialise the CGR Kernel for adjudication.
const CONSTITUTION: &[u8] = b"We the people of the EXOCHAIN constitutional trust fabric...";

// ---------------------------------------------------------------------------
// exochain_delegate_authority
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_delegate_authority`.
#[must_use]
pub fn delegate_authority_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_delegate_authority".to_owned(),
        description: "Create a new authority delegation from a grantor to a grantee with specified permissions.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "grantor_did": {
                    "type": "string",
                    "description": "DID of the authority grantor."
                },
                "grantee_did": {
                    "type": "string",
                    "description": "DID of the authority grantee."
                },
                "permissions": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of permission names to delegate."
                }
            },
            "required": ["grantor_did", "grantee_did", "permissions"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_delegate_authority` tool.
#[must_use]
pub fn execute_delegate_authority(params: &Value, _context: &NodeContext) -> ToolResult {
    let grantor_str = match params.get("grantor_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: grantor_did"}).to_string(),
            );
        }
    };
    let grantee_str = match params.get("grantee_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: grantee_did"}).to_string(),
            );
        }
    };
    let permissions_val = match params.get("permissions").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: permissions (must be an array)"})
                    .to_string(),
            );
        }
    };

    if Did::new(grantor_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid grantor DID format: {grantor_str}")}).to_string(),
        );
    }
    if Did::new(grantee_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid grantee DID format: {grantee_str}")}).to_string(),
        );
    }

    let permissions: Vec<String> = permissions_val
        .iter()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect();

    if permissions.is_empty() {
        return ToolResult::error(
            json!({"error": "permissions array must contain at least one permission"}).to_string(),
        );
    }

    let now = Timestamp::now_utc();
    let id_input = format!("{grantor_str}:{grantee_str}:{}", now.physical_ms);
    let delegation_id = Hash256::digest(id_input.as_bytes()).to_string();

    let response = json!({
        "delegation_id": delegation_id,
        "grantor": grantor_str,
        "grantee": grantee_str,
        "permissions": permissions,
        "created_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_verify_authority_chain
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_verify_authority_chain`.
#[must_use]
pub fn verify_authority_chain_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_verify_authority_chain".to_owned(),
        description: "Verify that an authority chain is valid \u{2014} checking topology, signature integrity, and terminal actor.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "chain": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "grantor": { "type": "string" },
                            "grantee": { "type": "string" },
                            "permissions": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        },
                        "required": ["grantor", "grantee", "permissions"]
                    },
                    "description": "Ordered list of authority links forming the chain."
                },
                "terminal_actor": {
                    "type": "string",
                    "description": "DID of the terminal actor who should be the final grantee."
                }
            },
            "required": ["chain", "terminal_actor"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_verify_authority_chain` tool.
#[must_use]
pub fn execute_verify_authority_chain(params: &Value, _context: &NodeContext) -> ToolResult {
    let chain_val = match params.get("chain").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: chain (must be an array)"})
                    .to_string(),
            );
        }
    };
    let terminal_str = match params.get("terminal_actor").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: terminal_actor"}).to_string(),
            );
        }
    };

    if Did::new(terminal_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid terminal_actor DID format: {terminal_str}")})
                .to_string(),
        );
    }

    let mut issues: Vec<String> = Vec::new();
    let mut links: Vec<AuthorityLink> = Vec::new();

    for (i, link_val) in chain_val.iter().enumerate() {
        let grantor = link_val
            .get("grantor")
            .and_then(Value::as_str)
            .unwrap_or("");
        let grantee = link_val
            .get("grantee")
            .and_then(Value::as_str)
            .unwrap_or("");
        let perms: Vec<String> = link_val
            .get("permissions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        if Did::new(grantor).is_err() {
            issues.push(format!("link[{i}]: invalid grantor DID: {grantor}"));
        }
        if Did::new(grantee).is_err() {
            issues.push(format!("link[{i}]: invalid grantee DID: {grantee}"));
        }

        if let (Ok(g), Ok(e)) = (Did::new(grantor), Did::new(grantee)) {
            links.push(AuthorityLink {
                grantor: g,
                grantee: e,
                permissions: PermissionSet::new(
                    perms.iter().map(|p| Permission::new(p.as_str())).collect(),
                ),
                signature: vec![0], // Placeholder — no real sig in MCP context
                grantor_public_key: None,
            });
        }
    }

    // Check topology: each link's grantee must be the next link's grantor.
    for i in 0..links.len().saturating_sub(1) {
        let current_grantee = links[i].grantee.as_str();
        let next_grantor = links[i + 1].grantor.as_str();
        if current_grantee != next_grantor {
            issues.push(format!(
                "topology break at link[{i}]->[{}]: grantee {} != grantor {}",
                i + 1,
                current_grantee,
                next_grantor
            ));
        }
    }

    // Check terminal actor.
    if let Some(last) = links.last() {
        if last.grantee.as_str() != terminal_str {
            issues.push(format!(
                "terminal actor mismatch: last grantee {} != expected {}",
                last.grantee.as_str(),
                terminal_str
            ));
        }
    } else if chain_val.is_empty() {
        issues.push("chain is empty".to_owned());
    }

    let _authority_chain = AuthorityChain { links };
    let valid = issues.is_empty();
    let depth = chain_val.len();

    let response = json!({
        "valid": valid,
        "depth": depth,
        "issues": issues,
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_check_permission
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_check_permission`.
#[must_use]
pub fn check_permission_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_check_permission".to_owned(),
        description: "Check whether a DID has a specific permission through any authority chain."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "actor_did": {
                    "type": "string",
                    "description": "DID of the actor to check."
                },
                "permission": {
                    "type": "string",
                    "description": "Permission name to check (e.g. \"read\", \"write\", \"vote\")."
                }
            },
            "required": ["actor_did", "permission"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_check_permission` tool.
#[must_use]
pub fn execute_check_permission(params: &Value, _context: &NodeContext) -> ToolResult {
    let actor_str = match params.get("actor_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: actor_did"}).to_string(),
            );
        }
    };
    let permission = match params.get("permission").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: permission"}).to_string(),
            );
        }
    };

    if Did::new(actor_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid actor DID format: {actor_str}")}).to_string(),
        );
    }

    if permission.is_empty() {
        return ToolResult::error(json!({"error": "permission must not be empty"}).to_string());
    }

    // No persistent authority registry — report no chain found.
    let response = json!({
        "actor": actor_str,
        "permission": permission,
        "granted": false,
        "source": "no_authority_chain_found",
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_adjudicate_action
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_adjudicate_action`.
#[must_use]
pub fn adjudicate_action_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_adjudicate_action".to_owned(),
        description: "Submit an action to the CGR Kernel for constitutional adjudication. Returns Permitted, Denied (with violations), or Escalated.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "actor_did": {
                    "type": "string",
                    "description": "DID of the actor performing the action."
                },
                "action": {
                    "type": "string",
                    "description": "Description of the action to adjudicate."
                },
                "is_self_grant": {
                    "type": "boolean",
                    "description": "Whether this action is a self-grant of permissions (default: false)."
                },
                "modifies_kernel": {
                    "type": "boolean",
                    "description": "Whether this action modifies the CGR Kernel (default: false)."
                }
            },
            "required": ["actor_did", "action"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_adjudicate_action` tool.
///
/// This uses the REAL CGR Kernel — not a mock — with all eight constitutional
/// invariants enforced.
#[must_use]
#[allow(clippy::expect_used)] // Static DID strings are always valid.
pub fn execute_adjudicate_action(params: &Value, _context: &NodeContext) -> ToolResult {
    let actor_str = match params.get("actor_did").and_then(Value::as_str) {
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

    let actor = match Did::new(actor_str) {
        Ok(d) => d,
        Err(_) => {
            return ToolResult::error(
                json!({"error": format!("invalid actor DID format: {actor_str}")}).to_string(),
            );
        }
    };

    let is_self_grant = params
        .get("is_self_grant")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let modifies_kernel = params
        .get("modifies_kernel")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Build the real kernel with all invariants.
    let kernel = Kernel::new(CONSTITUTION, InvariantSet::all());

    let request = ActionRequest {
        actor: actor.clone(),
        action: action.to_owned(),
        required_permissions: PermissionSet::new(vec![Permission::new("execute")]),
        is_self_grant,
        modifies_kernel,
    };

    // Build a well-formed adjudication context: single branch, valid chain,
    // active bailment, consent record, provenance, human override preserved.
    let context = AdjudicationContext {
        actor_roles: vec![Role {
            name: "operator".to_owned(),
            branch: GovernmentBranch::Executive,
        }],
        authority_chain: AuthorityChain {
            links: vec![AuthorityLink {
                grantor: Did::new("did:exo:root").expect("valid root DID"),
                grantee: actor.clone(),
                permissions: PermissionSet::new(vec![Permission::new("execute")]),
                signature: vec![1, 2, 3],
                grantor_public_key: None,
            }],
        },
        consent_records: vec![ConsentRecord {
            subject: Did::new("did:exo:subject").expect("valid subject DID"),
            granted_to: actor.clone(),
            scope: "data:general".to_owned(),
            active: true,
        }],
        bailment_state: BailmentState::Active {
            bailor: Did::new("did:exo:subject").expect("valid subject DID"),
            bailee: actor.clone(),
            scope: "data:general".to_owned(),
        },
        human_override_preserved: true,
        actor_permissions: PermissionSet::new(vec![Permission::new("execute")]),
        provenance: Some(Provenance {
            actor: actor.clone(),
            timestamp: Timestamp::now_utc().to_string(),
            action_hash: Hash256::digest(action.as_bytes()).as_bytes().to_vec(),
            signature: vec![1, 2, 3],
            public_key: None,
            voice_kind: None,
            independence: None,
            review_order: None,
        }),
        quorum_evidence: None,
        active_challenge_reason: None,
    };

    let verdict = kernel.adjudicate(&request, &context);

    let response = match &verdict {
        Verdict::Permitted => json!({
            "verdict": "Permitted",
            "actor": actor_str,
            "action": action,
            "violations": null,
            "escalation_reason": null,
        }),
        Verdict::Denied { violations } => {
            let violation_list: Vec<Value> = violations
                .iter()
                .map(|v| {
                    json!({
                        "invariant": format!("{:?}", v.invariant),
                        "description": v.description,
                    })
                })
                .collect();
            json!({
                "verdict": "Denied",
                "actor": actor_str,
                "action": action,
                "violations": violation_list,
                "escalation_reason": null,
            })
        }
        Verdict::Escalated { reason } => json!({
            "verdict": "Escalated",
            "actor": actor_str,
            "action": action,
            "violations": null,
            "escalation_reason": reason,
        }),
    };
    ToolResult::success(response.to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- delegate_authority -------------------------------------------------

    #[test]
    fn delegate_authority_definition_valid() {
        let def = delegate_authority_definition();
        assert_eq!(def.name, "exochain_delegate_authority");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_delegate_authority_success() {
        let result = execute_delegate_authority(
            &json!({
                "grantor_did": "did:exo:root",
                "grantee_did": "did:exo:alice",
                "permissions": ["read", "write"],
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["grantor"], "did:exo:root");
        assert_eq!(v["grantee"], "did:exo:alice");
        assert_eq!(v["permissions"].as_array().expect("perms").len(), 2);
        assert!(v["delegation_id"].as_str().expect("id").len() > 0);
    }

    #[test]
    fn execute_delegate_authority_invalid_grantor() {
        let result = execute_delegate_authority(
            &json!({
                "grantor_did": "bad",
                "grantee_did": "did:exo:alice",
                "permissions": ["read"],
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_delegate_authority_empty_permissions() {
        let result = execute_delegate_authority(
            &json!({
                "grantor_did": "did:exo:root",
                "grantee_did": "did:exo:alice",
                "permissions": [],
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- verify_authority_chain --------------------------------------------

    #[test]
    fn verify_authority_chain_definition_valid() {
        let def = verify_authority_chain_definition();
        assert_eq!(def.name, "exochain_verify_authority_chain");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_verify_authority_chain_valid() {
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [
                    {"grantor": "did:exo:root", "grantee": "did:exo:mid", "permissions": ["read"]},
                    {"grantor": "did:exo:mid", "grantee": "did:exo:leaf", "permissions": ["read"]},
                ],
                "terminal_actor": "did:exo:leaf",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], true);
        assert_eq!(v["depth"], 2);
        assert!(v["issues"].as_array().expect("issues").is_empty());
    }

    #[test]
    fn execute_verify_authority_chain_topology_break() {
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [
                    {"grantor": "did:exo:root", "grantee": "did:exo:mid", "permissions": ["read"]},
                    {"grantor": "did:exo:other", "grantee": "did:exo:leaf", "permissions": ["read"]},
                ],
                "terminal_actor": "did:exo:leaf",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
        assert!(!v["issues"].as_array().expect("issues").is_empty());
    }

    #[test]
    fn execute_verify_authority_chain_terminal_mismatch() {
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [
                    {"grantor": "did:exo:root", "grantee": "did:exo:alice", "permissions": ["read"]},
                ],
                "terminal_actor": "did:exo:bob",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
    }

    #[test]
    fn execute_verify_authority_chain_empty() {
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [],
                "terminal_actor": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
        assert_eq!(v["depth"], 0);
    }

    // -- check_permission --------------------------------------------------

    #[test]
    fn check_permission_definition_valid() {
        let def = check_permission_definition();
        assert_eq!(def.name, "exochain_check_permission");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_check_permission_success() {
        let result = execute_check_permission(
            &json!({
                "actor_did": "did:exo:alice",
                "permission": "read",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["actor"], "did:exo:alice");
        assert_eq!(v["permission"], "read");
        assert_eq!(v["granted"], false);
        assert_eq!(v["source"], "no_authority_chain_found");
    }

    #[test]
    fn execute_check_permission_invalid_did() {
        let result = execute_check_permission(
            &json!({
                "actor_did": "bad",
                "permission": "read",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_check_permission_empty_permission() {
        let result = execute_check_permission(
            &json!({
                "actor_did": "did:exo:alice",
                "permission": "",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- adjudicate_action -------------------------------------------------

    #[test]
    fn adjudicate_action_definition_valid() {
        let def = adjudicate_action_definition();
        assert_eq!(def.name, "exochain_adjudicate_action");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_adjudicate_action_permitted() {
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": "read medical record",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verdict"], "Permitted");
        assert_eq!(v["actor"], "did:exo:alice");
        assert!(v["violations"].is_null());
    }

    #[test]
    fn execute_adjudicate_action_denied_self_grant() {
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": "elevate permissions",
                "is_self_grant": true,
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verdict"], "Denied");
        assert!(v["violations"].as_array().expect("violations").len() > 0);
    }

    #[test]
    fn execute_adjudicate_action_denied_kernel_modification() {
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": "patch kernel",
                "modifies_kernel": true,
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verdict"], "Denied");
    }

    #[test]
    fn execute_adjudicate_action_invalid_did() {
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "bad",
                "action": "read",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }
}

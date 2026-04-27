//! Authority MCP tools — delegation, chain verification, permission checking,
//! and constitutional adjudication via the CGR Kernel.

// `needless_return` fires inside #[cfg(not(feature = "..."))]
// refusal blocks where the function body continues in the
// mutually-exclusive `#[cfg(feature = "...")]` branch.
#![allow(clippy::needless_return)]

#[cfg_attr(not(feature = "unaudited-mcp-simulation-tools"), allow(unused_imports))]
use exo_core::{Did, Hash256, Timestamp};
use exo_gatekeeper::{
    invariants::{
        ConstitutionalInvariant, InvariantContext, InvariantEngine, InvariantSet, enforce_all,
    },
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role,
    },
};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

/// Constitution bytes used to initialise the CGR Kernel for adjudication.
const CONSTITUTION: &[u8] = b"We the people of the EXOCHAIN constitutional trust fabric...";

#[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
fn authority_tool_refused(tool_name: &str) -> ToolResult {
    tracing::warn!(
        tool = %tool_name,
        "refusing MCP authority simulation tool: handler cannot create or adjudicate \
         authority without caller-supplied signed context. Build with \
         --features exo-node/unaudited-mcp-simulation-tools only for dev simulation. \
         Tracked in Initiatives/fix-mcp-authority-simulation-tools.md."
    );
    ToolResult::error(
        json!({
            "error": "mcp_authority_tool_disabled",
            "tool": tool_name,
            "message": "This MCP authority tool would otherwise return a \
                        simulation success without a signed authority store \
                        write or caller-supplied verified context. It is \
                        disabled by default to prevent AI agents from acting \
                        on false authority signals.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": "Initiatives/fix-mcp-authority-simulation-tools.md",
            "refusal_source": format!("exo-node/mcp/tools/authority.rs::{tool_name}"),
        })
        .to_string(),
    )
}

fn tool_error(code: &str, message: impl Into<String>) -> ToolResult {
    ToolResult::error(
        json!({
            "error": code,
            "message": message.into(),
            "initiative": "Initiatives/fix-mcp-authority-simulation-tools.md",
        })
        .to_string(),
    )
}

fn parse_required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing required parameter: {field}"))
}

fn parse_did_field(value: &Value, field: &str) -> Result<Did, String> {
    let raw = parse_required_str(value, field)?;
    Did::new(raw).map_err(|_| format!("invalid {field} DID format: {raw}"))
}

fn parse_hex_field(value: &Value, field: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let raw = parse_required_str(value, field)?;
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(trimmed).map_err(|err| format!("{field} is not valid hex: {err}"))?;
    if bytes.len() != expected_len {
        return Err(format!(
            "{field} must decode to {expected_len} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn parse_permission_set(value: &Value, field: &str) -> Result<PermissionSet, String> {
    let arr = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing required parameter: {field} (must be an array)"))?;
    let mut permissions = Vec::new();
    for (idx, permission) in arr.iter().enumerate() {
        let raw = permission
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{field}[{idx}] must be a non-empty string"))?;
        permissions.push(Permission::new(raw));
    }
    if permissions.is_empty() {
        return Err(format!("{field} must contain at least one permission"));
    }
    Ok(PermissionSet::new(permissions))
}

fn parse_authority_chain(value: &Value) -> Result<AuthorityChain, Vec<String>> {
    let Some(arr) = value.as_array() else {
        return Err(vec![
            "authority chain must be an array of signed links".to_owned(),
        ]);
    };
    if arr.is_empty() {
        return Err(vec!["authority chain is empty".to_owned()]);
    }

    let mut issues = Vec::new();
    let mut links = Vec::new();
    for (idx, link_val) in arr.iter().enumerate() {
        let grantor = match parse_did_field(link_val, "grantor") {
            Ok(did) => did,
            Err(err) => {
                issues.push(format!("link[{idx}]: {err}"));
                continue;
            }
        };
        let grantee = match parse_did_field(link_val, "grantee") {
            Ok(did) => did,
            Err(err) => {
                issues.push(format!("link[{idx}]: {err}"));
                continue;
            }
        };
        let permissions = match parse_permission_set(link_val, "permissions") {
            Ok(permissions) => permissions,
            Err(err) => {
                issues.push(format!("link[{idx}]: {err}"));
                continue;
            }
        };
        let signature = match parse_hex_field(link_val, "signature", 64) {
            Ok(signature) => signature,
            Err(err) => {
                issues.push(format!("link[{idx}]: {err}"));
                continue;
            }
        };
        let grantor_public_key = match parse_hex_field(link_val, "grantor_public_key", 32) {
            Ok(public_key) => public_key,
            Err(err) => {
                issues.push(format!("link[{idx}]: {err}"));
                continue;
            }
        };

        links.push(AuthorityLink {
            grantor,
            grantee,
            permissions,
            signature,
            grantor_public_key: Some(grantor_public_key),
        });
    }

    if issues.is_empty() {
        Ok(AuthorityChain { links })
    } else {
        Err(issues)
    }
}

fn validate_authority_chain(chain: &AuthorityChain, terminal_actor: &Did) -> Vec<String> {
    let engine = InvariantEngine::new(InvariantSet::with(vec![
        ConstitutionalInvariant::AuthorityChainValid,
    ]));
    let context = InvariantContext {
        actor: terminal_actor.clone(),
        actor_roles: Vec::new(),
        bailment_state: BailmentState::None,
        consent_records: Vec::new(),
        authority_chain: chain.clone(),
        is_self_grant: false,
        human_override_preserved: true,
        kernel_modification_attempted: false,
        quorum_evidence: None,
        provenance: None,
        actor_permissions: PermissionSet::default(),
        requested_permissions: PermissionSet::default(),
    };
    match enforce_all(&engine, &context) {
        Ok(()) => Vec::new(),
        Err(violations) => violations
            .into_iter()
            .map(|violation| violation.description)
            .collect(),
    }
}

fn parse_branch(value: &str) -> Result<GovernmentBranch, String> {
    match value {
        "Legislative" | "legislative" => Ok(GovernmentBranch::Legislative),
        "Executive" | "executive" => Ok(GovernmentBranch::Executive),
        "Judicial" | "judicial" => Ok(GovernmentBranch::Judicial),
        other => Err(format!("unknown government branch: {other}")),
    }
}

fn parse_roles(value: &Value) -> Result<Vec<Role>, String> {
    let arr = value
        .get("actor_roles")
        .and_then(Value::as_array)
        .ok_or_else(|| "context.actor_roles must be a non-empty array".to_owned())?;
    if arr.is_empty() {
        return Err("context.actor_roles must be a non-empty array".to_owned());
    }
    let mut roles = Vec::new();
    for (idx, role_val) in arr.iter().enumerate() {
        let name = parse_required_str(role_val, "name")
            .map_err(|err| format!("actor_roles[{idx}]: {err}"))?
            .to_owned();
        let branch_raw = parse_required_str(role_val, "branch")
            .map_err(|err| format!("actor_roles[{idx}]: {err}"))?;
        let branch =
            parse_branch(branch_raw).map_err(|err| format!("actor_roles[{idx}]: {err}"))?;
        roles.push(Role { name, branch });
    }
    Ok(roles)
}

fn parse_consent_records(value: &Value) -> Result<Vec<ConsentRecord>, String> {
    let arr = value
        .get("consent_records")
        .and_then(Value::as_array)
        .ok_or_else(|| "context.consent_records must be an array".to_owned())?;
    let mut records = Vec::new();
    for (idx, record_val) in arr.iter().enumerate() {
        records.push(ConsentRecord {
            subject: parse_did_field(record_val, "subject")
                .map_err(|err| format!("consent_records[{idx}]: {err}"))?,
            granted_to: parse_did_field(record_val, "granted_to")
                .map_err(|err| format!("consent_records[{idx}]: {err}"))?,
            scope: parse_required_str(record_val, "scope")
                .map_err(|err| format!("consent_records[{idx}]: {err}"))?
                .to_owned(),
            active: record_val
                .get("active")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("consent_records[{idx}]: active must be boolean"))?,
        });
    }
    Ok(records)
}

fn parse_bailment_state(value: &Value) -> Result<BailmentState, String> {
    let bailment = value
        .get("bailment_state")
        .ok_or_else(|| "context.bailment_state is required".to_owned())?;
    let state = parse_required_str(bailment, "state")?;
    match state {
        "none" | "None" => Ok(BailmentState::None),
        "active" | "Active" => Ok(BailmentState::Active {
            bailor: parse_did_field(bailment, "bailor")?,
            bailee: parse_did_field(bailment, "bailee")?,
            scope: parse_required_str(bailment, "scope")?.to_owned(),
        }),
        "suspended" | "Suspended" => Ok(BailmentState::Suspended {
            reason: parse_required_str(bailment, "reason")?.to_owned(),
        }),
        "terminated" | "Terminated" => Ok(BailmentState::Terminated),
        other => Err(format!("unknown bailment_state.state: {other}")),
    }
}

fn parse_provenance(value: &Value) -> Result<Provenance, String> {
    let provenance = value
        .get("provenance")
        .ok_or_else(|| "context.provenance is required".to_owned())?;
    Ok(Provenance {
        actor: parse_did_field(provenance, "actor")?,
        timestamp: parse_required_str(provenance, "timestamp")?.to_owned(),
        action_hash: parse_hex_field(provenance, "action_hash", 32)?,
        signature: parse_hex_field(provenance, "signature", 64)?,
        public_key: Some(parse_hex_field(provenance, "public_key", 32)?),
        voice_kind: None,
        independence: None,
        review_order: None,
    })
}

fn parse_verified_adjudication_context(
    context_value: &Value,
    actor: &Did,
) -> Result<AdjudicationContext, String> {
    let authority_chain_value = context_value
        .get("authority_chain")
        .ok_or_else(|| "context.authority_chain is required".to_owned())?;
    let authority_chain =
        parse_authority_chain(authority_chain_value).map_err(|issues| issues.join("; "))?;
    let issues = validate_authority_chain(&authority_chain, actor);
    if !issues.is_empty() {
        return Err(format!(
            "context.authority_chain is invalid: {}",
            issues.join("; ")
        ));
    }

    let human_override_preserved = context_value
        .get("human_override_preserved")
        .and_then(Value::as_bool)
        .ok_or_else(|| "context.human_override_preserved must be boolean".to_owned())?;

    Ok(AdjudicationContext {
        actor_roles: parse_roles(context_value)?,
        authority_chain,
        consent_records: parse_consent_records(context_value)?,
        bailment_state: parse_bailment_state(context_value)?,
        human_override_preserved,
        actor_permissions: parse_permission_set(context_value, "actor_permissions")?,
        provenance: Some(parse_provenance(context_value)?),
        quorum_evidence: None,
        active_challenge_reason: None,
    })
}

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
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        return authority_tool_refused("exochain_delegate_authority");
    }
    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        tracing::warn!(
            "UNAUDITED MCP authority simulation tool in use: \
             exochain_delegate_authority. Returns synthetic delegation_id \
             without signed store persistence. MUST NOT be enabled in production."
        );
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
                json!({"error": "permissions array must contain at least one permission"})
                    .to_string(),
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
                            },
                            "signature": {
                                "type": "string",
                                "description": "Hex Ed25519 signature over the canonical authority-link payload."
                            },
                            "grantor_public_key": {
                                "type": "string",
                                "description": "Hex Ed25519 public key for the grantor."
                            }
                        },
                        "required": ["grantor", "grantee", "permissions", "signature", "grantor_public_key"]
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

    let terminal = match Did::new(terminal_str) {
        Ok(terminal) => terminal,
        Err(_) => {
            return ToolResult::error(
                json!({"error": format!("invalid terminal_actor DID format: {terminal_str}")})
                    .to_string(),
            );
        }
    };

    let mut issues = Vec::new();
    let authority_chain = match parse_authority_chain(&Value::Array(chain_val.clone())) {
        Ok(chain) => chain,
        Err(parse_issues) => {
            issues.extend(parse_issues);
            AuthorityChain { links: Vec::new() }
        }
    };
    if issues.is_empty() {
        issues.extend(validate_authority_chain(&authority_chain, &terminal));
    }
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
                },
                "chain": {
                    "type": "array",
                    "description": "Signed authority chain to verify before checking permission."
                }
            },
            "required": ["actor_did", "permission", "chain"],
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

    let Some(chain_value) = params.get("chain") else {
        return tool_error(
            "mcp_signed_authority_chain_required",
            "exochain_check_permission requires a caller-supplied signed authority chain",
        );
    };
    let authority_chain = match parse_authority_chain(chain_value) {
        Ok(chain) => chain,
        Err(issues) => {
            return ToolResult::success(
                json!({
                    "actor": actor_str,
                    "permission": permission,
                    "granted": false,
                    "source": "invalid_authority_chain",
                    "issues": issues,
                })
                .to_string(),
            );
        }
    };
    let actor = match Did::new(actor_str) {
        Ok(actor) => actor,
        Err(_) => {
            return ToolResult::error(
                json!({"error": format!("invalid actor DID format: {actor_str}")}).to_string(),
            );
        }
    };
    let issues = validate_authority_chain(&authority_chain, &actor);
    if !issues.is_empty() {
        return ToolResult::success(
            json!({
                "actor": actor_str,
                "permission": permission,
                "granted": false,
                "source": "invalid_authority_chain",
                "issues": issues,
            })
            .to_string(),
        );
    }

    let requested = Permission::new(permission);
    let carries_permission = authority_chain
        .links
        .iter()
        .all(|link| link.permissions.contains(&requested));
    let response = json!({
        "actor": actor_str,
        "permission": permission,
        "granted": carries_permission,
        "source": "verified_signed_authority_chain",
        "issues": [],
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
                "required_permissions": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Permissions required by this action."
                },
                "is_self_grant": {
                    "type": "boolean",
                    "description": "Whether this action is a self-grant of permissions (default: false)."
                },
                "modifies_kernel": {
                    "type": "boolean",
                    "description": "Whether this action modifies the CGR Kernel (default: false)."
                },
                "context": {
                    "type": "object",
                    "description": "Caller-supplied verified adjudication context: roles, signed authority_chain, consent_records, bailment_state, actor_permissions, human_override_preserved, and signed provenance."
                }
            },
            "required": ["actor_did", "action", "required_permissions", "context"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_adjudicate_action` tool.
///
/// This uses the REAL CGR Kernel with all eight constitutional invariants
/// enforced over caller-supplied signed context. It refuses to fabricate
/// authority, consent, bailment, or provenance.
#[must_use]
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
    let context_value = match params.get("context") {
        Some(value) => value,
        None => {
            return tool_error(
                "mcp_verified_context_required",
                "exochain_adjudicate_action requires caller-supplied context with authority_chain, consent_records, bailment_state, actor_permissions, human_override_preserved, and provenance",
            );
        }
    };
    let context = match parse_verified_adjudication_context(context_value, &actor) {
        Ok(context) => context,
        Err(err) => return tool_error("mcp_verified_context_required", err),
    };
    let required_permissions = match parse_permission_set(params, "required_permissions") {
        Ok(permissions) => permissions,
        Err(err) => return tool_error("mcp_required_permissions_invalid", err),
    };

    // Build the real kernel with all invariants.
    let kernel = Kernel::new(CONSTITUTION, InvariantSet::all());

    let request = ActionRequest {
        actor: actor.clone(),
        action: action.to_owned(),
        required_permissions,
        is_self_grant,
        modifies_kernel,
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
    use exo_core::crypto;

    use super::*;

    fn signed_link_json(
        grantor: &str,
        grantee: &str,
        permissions: &[&str],
    ) -> (Value, exo_core::PublicKey) {
        let (public_key, secret_key) = crypto::generate_keypair();
        let permission_set = PermissionSet::new(
            permissions
                .iter()
                .map(|permission| Permission::new(*permission))
                .collect(),
        );
        let mut payload = Vec::new();
        payload.extend_from_slice(grantor.as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(grantee.as_bytes());
        payload.push(0x00);
        for permission in &permission_set.permissions {
            payload.extend_from_slice(permission.0.as_bytes());
            payload.push(0x00);
        }
        let message = Hash256::digest(&payload);
        let signature = crypto::sign(message.as_bytes(), &secret_key);
        (
            json!({
                "grantor": grantor,
                "grantee": grantee,
                "permissions": permissions,
                "signature": hex::encode(signature.to_bytes()),
                "grantor_public_key": hex::encode(public_key.as_bytes()),
            }),
            public_key,
        )
    }

    fn provenance_json(actor: &str, action: &str) -> Value {
        let (public_key, secret_key) = crypto::generate_keypair();
        let action_hash = Hash256::digest(action.as_bytes());
        let timestamp = "2026-04-26T23:50:00Z";
        let mut payload = Vec::new();
        payload.extend_from_slice(actor.as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(action_hash.as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(timestamp.as_bytes());
        let message = Hash256::digest(&payload);
        let signature = crypto::sign(message.as_bytes(), &secret_key);
        json!({
            "actor": actor,
            "timestamp": timestamp,
            "action_hash": hex::encode(action_hash.as_bytes()),
            "signature": hex::encode(signature.to_bytes()),
            "public_key": hex::encode(public_key.as_bytes()),
        })
    }

    fn adjudication_context_json(actor: &str, action: &str) -> Value {
        let (link, _) = signed_link_json("did:exo:root", actor, &["execute"]);
        json!({
            "actor_roles": [{"name": "operator", "branch": "Executive"}],
            "authority_chain": [link],
            "consent_records": [{
                "subject": "did:exo:subject",
                "granted_to": actor,
                "scope": "data:general",
                "active": true
            }],
            "bailment_state": {
                "state": "active",
                "bailor": "did:exo:subject",
                "bailee": actor,
                "scope": "data:general"
            },
            "human_override_preserved": true,
            "actor_permissions": ["execute"],
            "provenance": provenance_json(actor, action)
        })
    }

    // -- delegate_authority -------------------------------------------------

    #[test]
    fn delegate_authority_definition_valid() {
        let def = delegate_authority_definition();
        assert_eq!(def.name, "exochain_delegate_authority");
        assert!(!def.description.is_empty());
    }

    #[test]
    #[cfg(feature = "unaudited-mcp-simulation-tools")]
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
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["grantor"], "did:exo:root");
        assert_eq!(v["grantee"], "did:exo:alice");
        assert_eq!(v["permissions"].as_array().expect("perms").len(), 2);
        assert!(!v["delegation_id"].as_str().expect("id").is_empty());
    }

    #[test]
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    fn execute_delegate_authority_refuses_by_default() {
        let result = execute_delegate_authority(
            &json!({
                "grantor_did": "did:exo:root",
                "grantee_did": "did:exo:alice",
                "permissions": ["read", "write"],
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_authority_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-authority-simulation-tools.md"));
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
        let (link, _) = signed_link_json("did:exo:root", "did:exo:leaf", &["read"]);
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [link],
                "terminal_actor": "did:exo:leaf",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], true);
        assert_eq!(v["depth"], 1);
        assert!(v["issues"].as_array().expect("issues").is_empty());
    }

    #[test]
    fn execute_verify_authority_chain_rejects_unsigned_link() {
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [
                    {"grantor": "did:exo:root", "grantee": "did:exo:leaf", "permissions": ["read"]},
                ],
                "terminal_actor": "did:exo:leaf",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
        let issues = v["issues"].as_array().expect("issues");
        assert!(issues.iter().any(|issue| {
            issue
                .as_str()
                .is_some_and(|text| text.contains("signature"))
        }));
    }

    #[test]
    fn execute_verify_authority_chain_rejects_wrong_key() {
        let (mut link, _) = signed_link_json("did:exo:root", "did:exo:leaf", &["read"]);
        let (_, wrong_key) = crypto::generate_keypair();
        link["grantor_public_key"] = json!(hex::encode(wrong_key.as_bytes()));
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [link],
                "terminal_actor": "did:exo:leaf",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
        let issues = v["issues"].as_array().expect("issues");
        assert!(issues.iter().any(|issue| {
            issue
                .as_str()
                .is_some_and(|text| text.contains("cryptographically invalid"))
        }));
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
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
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
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
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
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
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
        let (link, _) = signed_link_json("did:exo:root", "did:exo:alice", &["read"]);
        let result = execute_check_permission(
            &json!({
                "actor_did": "did:exo:alice",
                "permission": "read",
                "chain": [link],
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["actor"], "did:exo:alice");
        assert_eq!(v["permission"], "read");
        assert_eq!(v["granted"], true);
        assert_eq!(v["source"], "verified_signed_authority_chain");
    }

    #[test]
    fn execute_check_permission_requires_signed_chain() {
        let result = execute_check_permission(
            &json!({
                "actor_did": "did:exo:alice",
                "permission": "read",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("chain"));
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
        let action = "read medical record";
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": action,
                "required_permissions": ["execute"],
                "context": adjudication_context_json("did:exo:alice", action)
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verdict"], "Permitted");
        assert_eq!(v["actor"], "did:exo:alice");
        assert!(v["violations"].is_null());
    }

    #[test]
    fn execute_adjudicate_action_requires_verified_context() {
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": "read medical record",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_verified_context_required"));
        assert!(text.contains("authority_chain"));
        assert!(text.contains("provenance"));
    }

    #[test]
    fn execute_adjudicate_action_denied_self_grant() {
        let action = "elevate permissions";
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": action,
                "required_permissions": ["execute"],
                "is_self_grant": true,
                "context": adjudication_context_json("did:exo:alice", action)
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verdict"], "Denied");
        assert!(!v["violations"].as_array().expect("violations").is_empty());
    }

    #[test]
    fn execute_adjudicate_action_denied_kernel_modification() {
        let action = "patch kernel";
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": action,
                "required_permissions": ["execute"],
                "modifies_kernel": true,
                "context": adjudication_context_json("did:exo:alice", action)
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
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

    #[test]
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    fn default_build_source_guard_rejects_authority_simulation_sentinels() {
        let source = include_str!("authority.rs");
        assert!(source.contains("authority_tool_refused(\"exochain_delegate_authority\")"));

        let adjudicate_body = source
            .split("pub fn execute_adjudicate_action")
            .nth(1)
            .expect("adjudication function present")
            .split("// ===========================================================================")
            .next()
            .expect("tests separator present");
        assert!(!adjudicate_body.contains("Timestamp::now_utc"));
        assert!(!adjudicate_body.contains("signature: vec![1, 2, 3]"));
        assert!(!adjudicate_body.contains("grantor_public_key: None"));
        assert!(adjudicate_body.contains("parse_verified_adjudication_context"));
    }
}

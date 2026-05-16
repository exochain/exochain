// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Authority MCP tools — delegation, chain verification, permission checking,
//! and constitutional adjudication via the CGR Kernel.

// `needless_return` fires inside #[cfg(not(feature = "..."))]
// refusal blocks where the function body continues in the
// mutually-exclusive `#[cfg(feature = "...")]` branch.
#![allow(clippy::needless_return)]

use exo_core::{Did, Hash256, PublicKey, Signature, hash::hash_structured};
#[cfg(test)]
use exo_gatekeeper::{authority_link_signature_message, provenance_signature_message};
use exo_gatekeeper::{
    invariants::{
        ConstitutionalInvariant, InvariantContext, InvariantEngine, InvariantSet, enforce_all,
    },
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role, TrustedAuthorityKeys, TrustedProvenanceKeys,
    },
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

/// Constitution bytes used to initialise the CGR Kernel for adjudication.
const CONSTITUTION: &[u8] = b"We the people of the EXOCHAIN constitutional trust fabric...";
const MAX_AUTHORITY_CHAIN_LINKS: usize = 5;
const MAX_AUTHORITY_DID_BYTES: usize = 512;
const MAX_AUTHORITY_ACTION_BYTES: usize = 16 * 1024;
const MAX_PERMISSION_SET_ENTRIES: usize = 64;
const MAX_PERMISSION_NAME_BYTES: usize = 256;
const ED25519_SIGNATURE_HEX_CHARS: usize = 128;
const ED25519_PUBLIC_KEY_HEX_CHARS: usize = 64;
const ADJUDICATION_CONTEXT_EVIDENCE_DOMAIN: &str = "exo.node.mcp.adjudication_context_evidence.v1";
const ADJUDICATION_CONTEXT_EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct AdjudicationContextEvidencePayload<'a> {
    domain: &'static str,
    schema_version: u32,
    actor: &'a Did,
    actor_roles: &'a [Role],
    authority_chain: &'a AuthorityChain,
    consent_records: &'a [ConsentRecord],
    bailment_state: &'a BailmentState,
    human_override_preserved: bool,
    actor_permissions: &'a PermissionSet,
    provenance: &'a Provenance,
}

struct ParsedAdjudicationContext {
    actor_roles: Vec<Role>,
    authority_chain: AuthorityChain,
    consent_records: Vec<ConsentRecord>,
    bailment_state: BailmentState,
    human_override_preserved: bool,
    actor_permissions: PermissionSet,
    provenance: Provenance,
}

struct AdjudicationContextEvidence {
    signer: Did,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

fn authority_tool_refused(tool_name: &str) -> ToolResult {
    tracing::warn!(
        tool = %tool_name,
        "refusing MCP authority simulation tool: handler cannot create or adjudicate \
         authority without caller-supplied signed context or signed store persistence. \
         The unaudited-mcp-simulation-tools feature does not enable mutating \
         synthetic delegation. \
         Tracked in Initiatives/fix-mcp-authority-simulation-tools.md."
    );
    ToolResult::error(
        json!({
            "error": "mcp_authority_tool_disabled",
            "tool": tool_name,
            "message": "This MCP authority tool would otherwise return a \
                        simulation success without a signed authority store \
                        write or caller-supplied verified context. It is \
                        disabled in every build until it is wired to signed \
                        authority-store persistence.",
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

fn validate_string_bytes(raw: &str, field: &str, max_bytes: usize) -> Result<(), String> {
    if raw.len() > max_bytes {
        return Err(format!("{field} may contain at most {max_bytes} bytes"));
    }
    Ok(())
}

fn invalid_did_message(field: &str) -> String {
    format!("invalid {field} DID format")
}

fn parse_did_str(raw: &str, field: &str) -> Result<Did, String> {
    validate_string_bytes(raw, field, MAX_AUTHORITY_DID_BYTES)?;
    Did::new(raw).map_err(|_| invalid_did_message(field))
}

fn parse_did_field(value: &Value, field: &str) -> Result<Did, String> {
    let raw = parse_required_str(value, field)?;
    parse_did_str(raw, field)
}

fn parse_hex_field(value: &Value, field: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let raw = parse_required_str(value, field)?;
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    let expected_hex_chars = expected_len * 2;
    if trimmed.len() != expected_hex_chars {
        return Err(format!(
            "{field} must be {expected_hex_chars} hex characters"
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|_| format!("{field} is not valid hex"))?;
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
    if arr.len() > MAX_PERMISSION_SET_ENTRIES {
        return Err(format!(
            "{field} may contain at most {MAX_PERMISSION_SET_ENTRIES} permission names"
        ));
    }
    let mut permissions = Vec::new();
    for (idx, permission) in arr.iter().enumerate() {
        let raw = permission
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{field}[{idx}] must be a non-empty string"))?;
        validate_string_bytes(raw, &format!("{field}[{idx}]"), MAX_PERMISSION_NAME_BYTES)?;
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
    if arr.len() > MAX_AUTHORITY_CHAIN_LINKS {
        return Err(vec![format!(
            "authority chain may contain at most {MAX_AUTHORITY_CHAIN_LINKS} signed links"
        )]);
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

fn validate_authority_chain(
    chain: &AuthorityChain,
    terminal_actor: &Did,
    trusted_authority_keys: &TrustedAuthorityKeys,
) -> Vec<String> {
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
        trusted_authority_keys: trusted_authority_keys.clone(),
        trusted_provenance_keys: Default::default(),
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
        _ => Err("unknown government branch".to_owned()),
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
        let role =
            Role::try_new(name, branch).map_err(|err| format!("actor_roles[{idx}]: {err}"))?;
        roles.push(role);
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
        _ => Err("unknown bailment_state.state".to_owned()),
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

fn parse_adjudication_context_parts(
    context_value: &Value,
) -> Result<ParsedAdjudicationContext, String> {
    let actor_roles = parse_roles(context_value)?;
    let consent_records = parse_consent_records(context_value)?;
    let bailment_state = parse_bailment_state(context_value)?;
    let human_override_preserved = context_value
        .get("human_override_preserved")
        .and_then(Value::as_bool)
        .ok_or_else(|| "context.human_override_preserved must be boolean".to_owned())?;
    let actor_permissions = parse_permission_set(context_value, "actor_permissions")?;
    let provenance = parse_provenance(context_value)?;
    let authority_chain_value = context_value
        .get("authority_chain")
        .ok_or_else(|| "context.authority_chain is required".to_owned())?;
    let authority_chain =
        parse_authority_chain(authority_chain_value).map_err(|issues| issues.join("; "))?;

    Ok(ParsedAdjudicationContext {
        actor_roles,
        authority_chain,
        consent_records,
        bailment_state,
        human_override_preserved,
        actor_permissions,
        provenance,
    })
}

fn adjudication_context_evidence_message(
    actor: &Did,
    context: &ParsedAdjudicationContext,
) -> exo_core::Result<Hash256> {
    hash_structured(&AdjudicationContextEvidencePayload {
        domain: ADJUDICATION_CONTEXT_EVIDENCE_DOMAIN,
        schema_version: ADJUDICATION_CONTEXT_EVIDENCE_SCHEMA_VERSION,
        actor,
        actor_roles: &context.actor_roles,
        authority_chain: &context.authority_chain,
        consent_records: &context.consent_records,
        bailment_state: &context.bailment_state,
        human_override_preserved: context.human_override_preserved,
        actor_permissions: &context.actor_permissions,
        provenance: &context.provenance,
    })
}

#[cfg(test)]
pub(crate) fn adjudication_context_evidence_message_from_json(
    context_value: &Value,
    actor: &Did,
) -> Result<Hash256, String> {
    let context = parse_adjudication_context_parts(context_value)?;
    adjudication_context_evidence_message(actor, &context)
        .map_err(|err| format!("context.context_evidence canonical payload failed: {err}"))
}

fn parse_adjudication_context_evidence(
    context_value: &Value,
) -> Result<AdjudicationContextEvidence, String> {
    let evidence = context_value
        .get("context_evidence")
        .ok_or_else(|| "context.context_evidence is required".to_owned())?;
    Ok(AdjudicationContextEvidence {
        signer: parse_did_field(evidence, "signer")
            .map_err(|err| format!("context.context_evidence: {err}"))?,
        public_key: parse_hex_field(evidence, "public_key", 32)
            .map_err(|err| format!("context.context_evidence: {err}"))?,
        signature: parse_hex_field(evidence, "signature", 64)
            .map_err(|err| format!("context.context_evidence: {err}"))?,
    })
}

fn validate_adjudication_context_evidence(
    context_value: &Value,
    actor: &Did,
    trusted_provenance_keys: &TrustedProvenanceKeys,
    context: &ParsedAdjudicationContext,
) -> Result<(), String> {
    let evidence = parse_adjudication_context_evidence(context_value)?;
    if evidence.signer != *actor {
        return Err("context.context_evidence signer must match actor".to_owned());
    }
    let trusted_keys = trusted_provenance_keys
        .get(&evidence.signer)
        .ok_or_else(|| {
            "context.context_evidence public_key is unresolved for signer DID".to_owned()
        })?;
    if !trusted_keys
        .iter()
        .any(|trusted_key| trusted_key.as_slice() == evidence.public_key.as_slice())
    {
        return Err("context.context_evidence public_key is not bound to signer DID".to_owned());
    }

    let public_key_bytes: [u8; 32] = evidence
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| "context.context_evidence public_key is not 32 bytes".to_owned())?;
    let signature_bytes: [u8; 64] = evidence
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "context.context_evidence signature is not 64 bytes".to_owned())?;
    let message = adjudication_context_evidence_message(actor, context)
        .map_err(|err| format!("context.context_evidence canonical payload failed: {err}"))?;
    let public_key = PublicKey::from_bytes(public_key_bytes);
    let signature = Signature::from_bytes(signature_bytes);
    if !exo_core::crypto::verify(message.as_bytes(), &signature, &public_key) {
        return Err(
            "context.context_evidence Ed25519 signature is cryptographically invalid".to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn parse_verified_adjudication_context(
    context_value: &Value,
    actor: &Did,
) -> Result<AdjudicationContext, String> {
    parse_verified_adjudication_context_with_trusted_keys(
        context_value,
        actor,
        TrustedAuthorityKeys::default(),
        TrustedProvenanceKeys::default(),
    )
}

pub(crate) fn parse_verified_adjudication_context_with_trusted_keys(
    context_value: &Value,
    actor: &Did,
    trusted_authority_keys: TrustedAuthorityKeys,
    trusted_provenance_keys: TrustedProvenanceKeys,
) -> Result<AdjudicationContext, String> {
    let context = parse_adjudication_context_parts(context_value)?;
    let issues = validate_authority_chain(&context.authority_chain, actor, &trusted_authority_keys);
    if !issues.is_empty() {
        return Err(format!(
            "context.authority_chain is invalid: {}",
            issues.join("; ")
        ));
    }
    validate_adjudication_context_evidence(
        context_value,
        actor,
        &trusted_provenance_keys,
        &context,
    )?;

    let ParsedAdjudicationContext {
        actor_roles,
        authority_chain,
        consent_records,
        bailment_state,
        human_override_preserved,
        actor_permissions,
        provenance,
    } = context;

    Ok(AdjudicationContext {
        actor_roles,
        authority_chain,
        consent_records,
        bailment_state,
        human_override_preserved,
        actor_permissions,
        trusted_authority_keys,
        trusted_provenance_keys,
        provenance: Some(provenance),
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
                    "maxLength": MAX_AUTHORITY_DID_BYTES,
                    "description": "DID of the authority grantor."
                },
                "grantee_did": {
                    "type": "string",
                    "maxLength": MAX_AUTHORITY_DID_BYTES,
                    "description": "DID of the authority grantee."
                },
                "permissions": {
                    "type": "array",
                    "maxItems": MAX_PERMISSION_SET_ENTRIES,
                    "items": {
                        "type": "string",
                        "maxLength": MAX_PERMISSION_NAME_BYTES
                    },
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
    let _ = params;
    authority_tool_refused("exochain_delegate_authority")
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
                    "maxItems": MAX_AUTHORITY_CHAIN_LINKS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "grantor": {
                                "type": "string",
                                "maxLength": MAX_AUTHORITY_DID_BYTES
                            },
                            "grantee": {
                                "type": "string",
                                "maxLength": MAX_AUTHORITY_DID_BYTES
                            },
                            "permissions": {
                                "type": "array",
                                "maxItems": MAX_PERMISSION_SET_ENTRIES,
                                "items": {
                                    "type": "string",
                                    "maxLength": MAX_PERMISSION_NAME_BYTES
                                }
                            },
                            "signature": {
                                "type": "string",
                                "minLength": ED25519_SIGNATURE_HEX_CHARS,
                                "maxLength": ED25519_SIGNATURE_HEX_CHARS,
                                "description": "Hex Ed25519 signature over the canonical authority-link payload."
                            },
                            "grantor_public_key": {
                                "type": "string",
                                "minLength": ED25519_PUBLIC_KEY_HEX_CHARS,
                                "maxLength": ED25519_PUBLIC_KEY_HEX_CHARS,
                                "description": "Hex Ed25519 public key for the grantor."
                            }
                        },
                        "required": ["grantor", "grantee", "permissions", "signature", "grantor_public_key"]
                    },
                    "description": "Ordered list of authority links forming the chain."
                },
                "terminal_actor": {
                    "type": "string",
                    "maxLength": MAX_AUTHORITY_DID_BYTES,
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
    let Some(chain_value @ Value::Array(chain_val)) = params.get("chain") else {
        return ToolResult::error(
            json!({"error": "missing required parameter: chain (must be an array)"}).to_string(),
        );
    };
    let depth = chain_val.len();
    let terminal_str = match params.get("terminal_actor").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: terminal_actor"}).to_string(),
            );
        }
    };

    let terminal = match parse_did_str(terminal_str, "terminal_actor") {
        Ok(terminal) => terminal,
        Err(err) => {
            return ToolResult::error(json!({"error": err}).to_string());
        }
    };

    let mut issues = Vec::new();
    let authority_chain = match parse_authority_chain(chain_value) {
        Ok(chain) => chain,
        Err(parse_issues) => {
            issues.extend(parse_issues);
            AuthorityChain { links: Vec::new() }
        }
    };
    if issues.is_empty() {
        issues.extend(validate_authority_chain(
            &authority_chain,
            &terminal,
            &TrustedAuthorityKeys::default(),
        ));
    }
    let valid = issues.is_empty();

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
                    "maxLength": MAX_AUTHORITY_DID_BYTES,
                    "description": "DID of the actor to check."
                },
                "permission": {
                    "type": "string",
                    "maxLength": MAX_PERMISSION_NAME_BYTES,
                    "description": "Permission name to check (e.g. \"read\", \"write\", \"vote\")."
                },
                "chain": {
                    "type": "array",
                    "maxItems": MAX_AUTHORITY_CHAIN_LINKS,
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

    if permission.is_empty() {
        return ToolResult::error(json!({"error": "permission must not be empty"}).to_string());
    }
    if let Err(err) = validate_string_bytes(permission, "permission", MAX_PERMISSION_NAME_BYTES) {
        return ToolResult::error(json!({"error": err}).to_string());
    }

    let actor = match parse_did_str(actor_str, "actor") {
        Ok(actor) => actor,
        Err(err) => return ToolResult::error(json!({"error": err}).to_string()),
    };

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
    let issues =
        validate_authority_chain(&authority_chain, &actor, &TrustedAuthorityKeys::default());
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
                    "maxLength": MAX_AUTHORITY_DID_BYTES,
                    "description": "DID of the actor performing the action."
                },
                "action": {
                    "type": "string",
                    "maxLength": MAX_AUTHORITY_ACTION_BYTES,
                    "description": "Description of the action to adjudicate."
                },
                "required_permissions": {
                    "type": "array",
                    "maxItems": MAX_PERMISSION_SET_ENTRIES,
                    "items": {
                        "type": "string",
                        "maxLength": MAX_PERMISSION_NAME_BYTES
                    },
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
                    "description": "Caller-supplied verified adjudication context: roles, signed authority_chain, consent_records, bailment_state, actor_permissions, human_override_preserved, signed provenance, and context_evidence signature."
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

    let actor = match parse_did_str(actor_str, "actor") {
        Ok(actor) => actor,
        Err(err) => {
            return ToolResult::error(json!({"error": err}).to_string());
        }
    };
    if let Err(err) = validate_string_bytes(action, "action", MAX_AUTHORITY_ACTION_BYTES) {
        return ToolResult::error(json!({"error": err}).to_string());
    }

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
                "exochain_adjudicate_action requires caller-supplied context with authority_chain, consent_records, bailment_state, actor_permissions, human_override_preserved, provenance, and context_evidence",
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
                        "invariant": v.invariant.id(),
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
        let mut link = AuthorityLink {
            grantor: Did::new(grantor).expect("valid grantor DID"),
            grantee: Did::new(grantee).expect("valid grantee DID"),
            permissions: permission_set,
            signature: Vec::new(),
            grantor_public_key: Some(public_key.as_bytes().to_vec()),
        };
        let message = authority_link_signature_message(&link).expect("canonical link payload");
        let signature = crypto::sign(message.as_bytes(), &secret_key);
        link.signature = signature.to_bytes().to_vec();
        (
            json!({
                "grantor": grantor,
                "grantee": grantee,
                "permissions": permissions,
                "signature": hex::encode(link.signature),
                "grantor_public_key": hex::encode(public_key.as_bytes()),
            }),
            public_key,
        )
    }

    fn provenance_json(actor: &str, action: &str) -> Value {
        let (public_key, secret_key) = crypto::generate_keypair();
        let action_hash = Hash256::digest(action.as_bytes());
        let timestamp = "2026-04-26T23:50:00Z";
        let mut provenance = Provenance {
            actor: Did::new(actor).expect("valid provenance actor DID"),
            timestamp: timestamp.to_string(),
            action_hash: action_hash.as_bytes().to_vec(),
            signature: Vec::new(),
            public_key: Some(public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let message =
            provenance_signature_message(&provenance).expect("canonical provenance payload");
        let signature = crypto::sign(message.as_bytes(), &secret_key);
        provenance.signature = signature.to_bytes().to_vec();
        json!({
            "actor": actor,
            "timestamp": timestamp,
            "action_hash": hex::encode(action_hash.as_bytes()),
            "signature": hex::encode(provenance.signature),
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

    fn assert_text_omits_raw_input(text: &str, raw_input: &str) {
        assert!(
            !text.contains(raw_input),
            "MCP error output must not reflect raw caller input: {text}"
        );
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
    fn execute_delegate_authority_refuses_synthetic_success_even_with_simulation_feature() {
        let params = json!({
                "grantor_did": "did:exo:root",
                "grantee_did": "did:exo:alice",
                "permissions": ["read", "write"],
        });
        let result = execute_delegate_authority(&params, &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_authority_tool_disabled"));
        assert!(!text.contains("delegation_id"));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
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
    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    fn execute_delegate_authority_invalid_grantor_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-grantor-{attacker_marker}");
        let result = execute_delegate_authority(
            &json!({
                "grantor_did": attacker_input,
                "grantee_did": "did:exo:alice",
                "permissions": ["read"],
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("mcp_authority_tool_disabled"));
    }

    #[test]
    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    fn execute_delegate_authority_rejects_non_string_permissions() {
        let result = execute_delegate_authority(
            &json!({
                "grantor_did": "did:exo:root",
                "grantee_did": "did:exo:alice",
                "permissions": ["read", 42, "write"],
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_authority_tool_disabled"));
        assert_text_omits_raw_input(text, "42");
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
    fn execute_verify_authority_chain_rejects_untrusted_embedded_grantor_key() {
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
        assert_eq!(v["valid"], false);
        assert_eq!(v["depth"], 1);
        let issues = v["issues"].as_array().expect("issues");
        assert!(issues.iter().any(|issue| {
            issue.as_str().is_some_and(|text| {
                text.contains("grantor_public_key is unresolved for grantor DID")
            })
        }));
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
            issue.as_str().is_some_and(|text| {
                text.contains("grantor_public_key is unresolved for grantor DID")
            })
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

    #[test]
    fn execute_verify_authority_chain_invalid_terminal_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-terminal-{attacker_marker}");
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [],
                "terminal_actor": attacker_input,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("terminal_actor"));
    }

    #[test]
    fn execute_verify_authority_chain_link_issue_omits_raw_did_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-grantor-{attacker_marker}");
        let result = execute_verify_authority_chain(
            &json!({
                "chain": [{
                    "grantor": attacker_input,
                    "grantee": "did:exo:leaf",
                    "permissions": ["read"],
                    "signature": "00".repeat(64),
                    "grantor_public_key": "00".repeat(32),
                }],
                "terminal_actor": "did:exo:leaf",
            }),
            &NodeContext::empty(),
        );

        assert!(!result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("grantor"));
    }

    #[test]
    fn parse_authority_chain_rejects_excessive_link_count() {
        let chain = Value::Array((0..=MAX_AUTHORITY_CHAIN_LINKS).map(|_| json!({})).collect());

        let issues = parse_authority_chain(&chain).expect_err("oversized chain must fail");

        assert_eq!(
            issues,
            vec![format!(
                "authority chain may contain at most {MAX_AUTHORITY_CHAIN_LINKS} signed links"
            )]
        );
    }

    #[test]
    fn parse_permission_set_rejects_excessive_permission_count() {
        let permissions: Vec<Value> = (0..=MAX_PERMISSION_SET_ENTRIES)
            .map(|idx| Value::String(format!("permission:{idx}")))
            .collect();
        let value = json!({ "permissions": permissions });

        let err = parse_permission_set(&value, "permissions")
            .expect_err("oversized permission set must fail");

        assert_eq!(
            err,
            format!(
                "permissions may contain at most {MAX_PERMISSION_SET_ENTRIES} permission names"
            )
        );
    }

    #[test]
    fn execute_verify_authority_chain_reports_excessive_link_count() {
        let chain: Vec<Value> = (0..=MAX_AUTHORITY_CHAIN_LINKS).map(|_| json!({})).collect();

        let result = execute_verify_authority_chain(
            &json!({
                "chain": chain,
                "terminal_actor": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );

        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
        assert_eq!(v["depth"], MAX_AUTHORITY_CHAIN_LINKS + 1);
        let issues = v["issues"].as_array().expect("issues");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].as_str().expect("issue text"),
            format!("authority chain may contain at most {MAX_AUTHORITY_CHAIN_LINKS} signed links")
        );
    }

    // -- check_permission --------------------------------------------------

    #[test]
    fn check_permission_definition_valid() {
        let def = check_permission_definition();
        assert_eq!(def.name, "exochain_check_permission");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_check_permission_rejects_untrusted_embedded_grantor_key() {
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
        assert_eq!(v["granted"], false);
        assert_eq!(v["source"], "invalid_authority_chain");
        let issues = v["issues"].as_array().expect("issues");
        assert!(issues.iter().any(|issue| {
            issue.as_str().is_some_and(|text| {
                text.contains("grantor_public_key is unresolved for grantor DID")
            })
        }));
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
    fn execute_check_permission_invalid_actor_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-actor-{attacker_marker}");
        let result = execute_check_permission(
            &json!({
                "actor_did": attacker_input,
                "permission": "read",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("actor"));
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
    fn execute_adjudicate_action_rejects_context_without_trusted_key_resolver() {
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
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_verified_context_required"));
        assert!(text.contains("grantor_public_key is unresolved for grantor DID"));
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
    fn execute_adjudicate_action_rejects_self_grant_context_without_trusted_key_resolver() {
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
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_verified_context_required"));
        assert!(text.contains("grantor_public_key is unresolved for grantor DID"));
    }

    #[test]
    fn execute_adjudicate_action_rejects_kernel_modification_context_without_trusted_key_resolver()
    {
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
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_verified_context_required"));
        assert!(text.contains("grantor_public_key is unresolved for grantor DID"));
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
    fn execute_adjudicate_action_invalid_actor_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-actor-{attacker_marker}");
        let result = execute_adjudicate_action(
            &json!({
                "actor_did": attacker_input,
                "action": "read",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("actor"));
    }

    #[test]
    fn execute_adjudicate_action_context_branch_error_omits_raw_input() {
        let action = "read medical record";
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("Executive-{attacker_marker}");
        let mut context = adjudication_context_json("did:exo:alice", action);
        context["actor_roles"][0]["branch"] = json!(attacker_input);

        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": action,
                "required_permissions": ["execute"],
                "context": context,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("actor_roles[0]"));
    }

    #[test]
    fn execute_adjudicate_action_context_role_name_error_omits_raw_input() {
        let action = "read medical record";
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("operator-{attacker_marker}");
        let mut context = adjudication_context_json("did:exo:alice", action);
        context["actor_roles"][0]["name"] = json!(attacker_input);

        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": action,
                "required_permissions": ["execute"],
                "context": context,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("actor_roles[0]"));
        assert!(text.contains("unknown governed role name"));
    }

    #[test]
    fn execute_adjudicate_action_context_bailment_state_error_omits_raw_input() {
        let action = "read medical record";
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("active-{attacker_marker}");
        let mut context = adjudication_context_json("did:exo:alice", action);
        context["bailment_state"]["state"] = json!(attacker_input);

        let result = execute_adjudicate_action(
            &json!({
                "actor_did": "did:exo:alice",
                "action": action,
                "required_permissions": ["execute"],
                "context": context,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("bailment_state"));
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
        let forbidden_timestamp = ["Timestamp::", "now_utc"].concat();
        assert!(!adjudicate_body.contains(&forbidden_timestamp));
        assert!(!adjudicate_body.contains("signature: vec![1, 2, 3]"));
        assert!(!adjudicate_body.contains("grantor_public_key: None"));
        assert!(adjudicate_body.contains("parse_verified_adjudication_context"));
    }

    #[test]
    fn adjudication_response_uses_stable_invariant_ids() {
        let source = include_str!("authority.rs");
        let adjudicate_body = source
            .split("pub fn execute_adjudicate_action")
            .nth(1)
            .expect("adjudication function present")
            .split("// ===========================================================================")
            .next()
            .expect("tests separator present");

        assert!(
            !adjudicate_body.contains("format!(\"{:?}\", v.invariant)"),
            "MCP adjudication output must not depend on Rust Debug invariant names"
        );
        assert!(
            adjudicate_body.contains("v.invariant.id()"),
            "MCP adjudication output must expose explicit stable invariant identifiers"
        );
    }
}

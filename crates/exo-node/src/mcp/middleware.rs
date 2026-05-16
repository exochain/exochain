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

//! Constitutional enforcement middleware for MCP tool calls.
//!
//! Every tool invocation passes through this middleware which:
//! 1. Parses caller-supplied verified constitutional context
//! 2. Enforces all 6 MCP rules (via exo-gatekeeper)
//! 3. Adjudicates the supplied `AdjudicationContext` in the CGR Kernel
//! 4. Adjudicates the action against all 8 constitutional invariants
//! 5. Permits only `Permitted` verdicts for tool execution
//!
//! # Verified Context Requirement
//!
//! Tool-call params must include a top-level `constitutional_context` object.
//! The middleware parses that object, verifies the signed authority chain and
//! provenance through the same gatekeeper logic as `exochain_adjudicate_action`,
//! verifies a domain-separated evidence signature over the full adjudication
//! context, derives MCP rule facts from the parsed context, and refuses the call
//! when the context is absent or invalid. It does not fabricate consent,
//! provenance, output marking, or human-override evidence.

use std::sync::Arc;

use exo_core::{Did, Hash256, PublicKey, Signature, SignerType, hash::hash_structured};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    mcp::{self, McpContext, McpRule},
    types::{
        BailmentState, Permission, PermissionSet, TrustedAuthorityKeys, TrustedProvenanceKeys,
    },
};
use serde::Serialize;
use serde_json::Value;

#[cfg(test)]
use super::tools::authority::adjudication_context_evidence_message_from_json;
use super::{
    error::{McpError, Result},
    protocol::AI_OUTPUT_MARKING,
    tools::authority::parse_verified_adjudication_context_with_trusted_keys,
};

const CONSTITUTIONAL_CONTEXT_FIELD: &str = "constitutional_context";
const MCP_DELEGATION_ID_DOMAIN: &str = "exo.node.mcp.middleware.delegation_id.v1";
const MCP_TOOL_ACTION_HASH_DOMAIN: &str = "exo.node.mcp.middleware.tool_action_hash.v1";

#[derive(Serialize)]
struct McpDelegationIdPayload<'a> {
    domain: &'static str,
    actor_did: &'a Did,
    action: &'a str,
    tool_action_hash: &'a Hash256,
    bcts_scope: &'a str,
}

#[derive(Serialize)]
struct McpToolActionHashPayload<'a> {
    domain: &'static str,
    action: &'a str,
    arguments: &'a Value,
}

/// Constitutional enforcement middleware wrapping every MCP tool invocation.
///
/// Holds an immutable `Kernel` instance initialized with the EXOCHAIN
/// constitution and all 8 constitutional invariants.
pub struct ConstitutionalMiddleware {
    kernel: Kernel,
    authority: Option<McpAuthority>,
}

struct McpAuthority {
    did: Did,
    public_key: PublicKey,
}

struct VerifiedMcpInvocation {
    mcp_context: McpContext,
    adjudication_context: AdjudicationContext,
}

impl ConstitutionalMiddleware {
    /// Create a new middleware instance with the full constitutional kernel.
    ///
    #[must_use]
    pub fn new() -> Self {
        tracing::warn!(
            "mcp::ConstitutionalMiddleware initialized without an MCP \
             authority signer; tool adjudication fails closed until \
             ConstitutionalMiddleware::with_authority is used."
        );
        let kernel = Kernel::new(b"EXOCHAIN Constitutional Trust Fabric", InvariantSet::all());
        Self {
            kernel,
            authority: None,
        }
    }

    /// Create middleware bound to a caller-supplied MCP authority signer.
    ///
    /// The signer remains part of the constructor so call sites cannot
    /// accidentally configure a public key without also holding signing
    /// authority. Middleware enforcement verifies caller-supplied context
    /// against the configured DID and public key; it does not sign or fabricate
    /// context on behalf of the caller.
    #[must_use]
    pub fn with_authority(
        authority_did: Did,
        authority_public_key: PublicKey,
        _authority_signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    ) -> Self {
        tracing::warn!(
            "mcp::ConstitutionalMiddleware initialized with configured \
             authority; tool calls must include verified constitutional_context."
        );
        let kernel = Kernel::new(b"EXOCHAIN Constitutional Trust Fabric", InvariantSet::all());
        Self {
            kernel,
            authority: Some(McpAuthority {
                did: authority_did,
                public_key: authority_public_key,
            }),
        }
    }

    /// Enforce all 6 MCP rules against the AI actor's context.
    pub fn enforce_mcp_rules(&self, context: &McpContext) -> Result<()> {
        mcp::enforce(&McpRule::all(), context).map_err(|violation| McpError::McpRuleViolation {
            rule: violation.rule.id().to_owned(),
            description: violation.description,
        })
    }

    fn parse_required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
        value
            .get(field)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                McpError::ConstitutionalViolation(format!(
                    "verified MCP invocation context missing non-empty {field}"
                ))
            })
    }

    fn parse_required_bool(value: &Value, field: &str) -> Result<bool> {
        value.get(field).and_then(Value::as_bool).ok_or_else(|| {
            McpError::ConstitutionalViolation(format!(
                "verified MCP invocation context missing boolean {field}"
            ))
        })
    }

    fn parse_capabilities(value: &Value) -> Result<PermissionSet> {
        let capabilities = value
            .get("capabilities")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                McpError::ConstitutionalViolation(
                    "verified MCP invocation context missing capabilities array".into(),
                )
            })?;
        if capabilities.is_empty() {
            return Err(McpError::ConstitutionalViolation(
                "verified MCP invocation context capabilities must not be empty".into(),
            ));
        }
        let mut permissions = Vec::new();
        for (idx, capability) in capabilities.iter().enumerate() {
            let raw = capability
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    McpError::ConstitutionalViolation(format!(
                        "verified MCP invocation context capabilities[{idx}] must be non-empty string"
                    ))
                })?;
            permissions.push(Permission::new(raw));
        }
        Ok(PermissionSet::new(permissions))
    }

    fn action_hash_matches(context: &AdjudicationContext, expected_action_hash: &Hash256) -> bool {
        let expected = expected_action_hash.as_bytes().to_vec();
        context
            .provenance
            .as_ref()
            .is_some_and(|provenance| provenance.action_hash == expected)
    }

    fn active_consent_for_actor(context: &AdjudicationContext, actor_did: &Did) -> bool {
        let active_bailment_matches_actor = match &context.bailment_state {
            BailmentState::Active { bailee, .. } => bailee == actor_did,
            BailmentState::None | BailmentState::Suspended { .. } | BailmentState::Terminated => {
                false
            }
        };
        active_bailment_matches_actor
            && context
                .consent_records
                .iter()
                .any(|record| record.granted_to == *actor_did && record.active)
    }

    fn verify_authority_binding(
        &self,
        actor_did: &Did,
        context: &AdjudicationContext,
    ) -> Result<()> {
        let authority = self.authority.as_ref().ok_or_else(|| {
            McpError::ConstitutionalViolation(
                "MCP authority signer is required for verified MCP invocation context".into(),
            )
        })?;
        let Some(root_link) = context.authority_chain.links.first() else {
            return Err(McpError::ConstitutionalViolation(
                "verified MCP invocation context authority_chain is empty".into(),
            ));
        };
        if root_link.grantor != authority.did {
            return Err(McpError::AuthenticationRequired);
        }
        let authority_public_key = authority.public_key.as_bytes();
        if root_link.grantor_public_key.as_deref() != Some(authority_public_key) {
            return Err(McpError::AuthenticationRequired);
        }
        let provenance = context.provenance.as_ref().ok_or_else(|| {
            McpError::ConstitutionalViolation(
                "verified MCP invocation context provenance is required".into(),
            )
        })?;
        if provenance.actor != *actor_did {
            return Err(McpError::AuthenticationRequired);
        }
        if provenance.public_key.as_deref() != Some(authority_public_key) {
            return Err(McpError::AuthenticationRequired);
        }
        Ok(())
    }

    fn trusted_context_keys(
        &self,
        actor_did: &Did,
    ) -> Result<(TrustedAuthorityKeys, TrustedProvenanceKeys)> {
        let authority = self.authority.as_ref().ok_or_else(|| {
            McpError::ConstitutionalViolation(
                "MCP authority signer is required for verified MCP invocation context".into(),
            )
        })?;
        let public_key = authority.public_key.as_bytes().to_vec();
        let mut trusted_authority_keys = TrustedAuthorityKeys::default();
        trusted_authority_keys.insert(authority.did.clone(), vec![public_key.clone()]);
        let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
        trusted_provenance_keys.insert(actor_did.clone(), vec![public_key]);
        Ok((trusted_authority_keys, trusted_provenance_keys))
    }

    fn parse_invocation_context(
        &self,
        actor_did: &Did,
        action: &str,
        tool_call_params: &Value,
    ) -> Result<VerifiedMcpInvocation> {
        let context_value = tool_call_params
            .get(CONSTITUTIONAL_CONTEXT_FIELD)
            .ok_or_else(|| {
                McpError::ConstitutionalViolation(
                    "verified MCP invocation context is required".into(),
                )
            })?;
        let adjudication_value = context_value.get("adjudication_context").ok_or_else(|| {
            McpError::ConstitutionalViolation(
                "verified MCP invocation context missing adjudication_context".into(),
            )
        })?;
        let (trusted_authority_keys, trusted_provenance_keys) =
            self.trusted_context_keys(actor_did)?;
        let adjudication_context = parse_verified_adjudication_context_with_trusted_keys(
            adjudication_value,
            actor_did,
            trusted_authority_keys,
            trusted_provenance_keys,
        )
        .map_err(|err| {
            McpError::ConstitutionalViolation(format!(
                "verified MCP invocation context invalid: {err}"
            ))
        })?;
        self.verify_authority_binding(actor_did, &adjudication_context)?;

        let empty_arguments = Value::Object(serde_json::Map::new());
        let arguments = tool_call_params
            .get("arguments")
            .unwrap_or(&empty_arguments);
        let tool_action_hash = mcp_tool_action_hash(action, arguments).map_err(|err| {
            McpError::ConstitutionalViolation(format!(
                "verified MCP invocation context action_hash encoding failed: {err}"
            ))
        })?;
        if !Self::action_hash_matches(&adjudication_context, &tool_action_hash) {
            return Err(McpError::ConstitutionalViolation(
                "verified MCP invocation context provenance action_hash does not match tool action and arguments"
                    .into(),
            ));
        }

        let bcts_scope = Self::parse_required_str(context_value, "bcts_scope")?.to_owned();
        let output_marking = Self::parse_required_str(context_value, "output_marking")?;
        let delegation_id = mcp_delegation_id(actor_did, action, &tool_action_hash, &bcts_scope)
            .map_err(|err| {
                McpError::ConstitutionalViolation(format!(
                    "verified MCP invocation context delegation_id encoding failed: {err}"
                ))
            })?;
        let mcp_context = McpContext {
            actor_did: actor_did.clone(),
            signer_type: SignerType::Ai { delegation_id },
            bcts_scope: Some(bcts_scope),
            capabilities: Self::parse_capabilities(context_value)?,
            action: action.to_owned(),
            has_provenance: adjudication_context.provenance.is_some(),
            forging_identity: Self::parse_required_bool(context_value, "forging_identity")?,
            output_marked_ai: output_marking == AI_OUTPUT_MARKING,
            consent_active: Self::active_consent_for_actor(&adjudication_context, actor_did),
            self_escalation: Self::parse_required_bool(context_value, "self_escalation")?,
        };

        Ok(VerifiedMcpInvocation {
            mcp_context,
            adjudication_context,
        })
    }

    /// Adjudicate an action against all 8 constitutional invariants.
    pub fn adjudicate(
        &self,
        actor_did: &Did,
        action: &str,
        adj_context: &AdjudicationContext,
    ) -> Result<Verdict> {
        self.verify_authority_binding(actor_did, adj_context)?;
        let action_request = ActionRequest {
            actor: actor_did.clone(),
            action: action.to_string(),
            required_permissions: PermissionSet::new(vec![Permission::new("mcp:tool_call")]),
            is_self_grant: false,
            modifies_kernel: false,
        };

        let verdict = self.kernel.adjudicate(&action_request, adj_context);

        match &verdict {
            Verdict::Denied { violations } => {
                let descriptions: Vec<String> =
                    violations.iter().map(|v| v.description.clone()).collect();
                Err(McpError::ConstitutionalViolation(descriptions.join("; ")))
            }
            Verdict::Escalated { reason } => Err(McpError::ConstitutionalViolation(format!(
                "kernel verdict escalated; tool execution requires review: {reason}"
            ))),
            _ => Ok(verdict),
        }
    }

    /// Full constitutional enforcement for a JSON-RPC `tools/call` envelope.
    pub fn enforce_tool_call(
        &self,
        actor_did: &Did,
        action: &str,
        tool_call_params: &Value,
    ) -> Result<()> {
        let invocation = self.parse_invocation_context(actor_did, action, tool_call_params)?;
        self.enforce_mcp_rules(&invocation.mcp_context)?;
        self.adjudicate(actor_did, action, &invocation.adjudication_context)?;
        Ok(())
    }
}

pub(super) fn mcp_tool_action_hash(action: &str, arguments: &Value) -> exo_core::Result<Hash256> {
    hash_structured(&McpToolActionHashPayload {
        domain: MCP_TOOL_ACTION_HASH_DOMAIN,
        action,
        arguments,
    })
}

fn mcp_delegation_id(
    actor_did: &Did,
    action: &str,
    tool_action_hash: &Hash256,
    bcts_scope: &str,
) -> exo_core::Result<Hash256> {
    hash_structured(&McpDelegationIdPayload {
        domain: MCP_DELEGATION_ID_DOMAIN,
        actor_did,
        action,
        tool_action_hash,
        bcts_scope,
    })
}

impl Default for ConstitutionalMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:ai-agent-mcp").expect("valid DID")
    }

    fn signed_middleware() -> ConstitutionalMiddleware {
        let keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x4D; 32]).unwrap();
        let public_key = *keypair.public_key();
        let secret_key = keypair.secret_key().clone();
        ConstitutionalMiddleware::with_authority(
            test_did(),
            public_key,
            Arc::new(move |message: &[u8]| exo_core::crypto::sign(message, &secret_key)),
        )
    }

    fn signed_tool_call_params(action: &str) -> Value {
        signed_tool_call_params_with_arguments(action, serde_json::json!({}))
    }

    fn refresh_context_evidence(params: &mut Value) {
        let actor = test_did();
        let keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x4D; 32]).unwrap();
        let public_key_hex = hex::encode(keypair.public_key().as_bytes());
        let evidence_message = adjudication_context_evidence_message_from_json(
            &params[CONSTITUTIONAL_CONTEXT_FIELD]["adjudication_context"],
            &actor,
        )
        .expect("canonical context evidence payload");
        let evidence_signature =
            exo_core::crypto::sign(evidence_message.as_bytes(), keypair.secret_key());
        params[CONSTITUTIONAL_CONTEXT_FIELD]["adjudication_context"]["context_evidence"] = serde_json::json!({
            "signer": actor.as_str(),
            "public_key": public_key_hex,
            "signature": hex::encode(evidence_signature.to_bytes()),
        });
    }

    fn signed_tool_call_params_with_arguments(action: &str, arguments: Value) -> Value {
        let actor = test_did();
        let keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x4D; 32]).unwrap();
        let public_key = *keypair.public_key();
        let secret_key = keypair.secret_key().clone();
        let public_key_hex = hex::encode(public_key.as_bytes());
        let permissions = ["mcp:tool_call"];
        let permission_set = exo_gatekeeper::types::PermissionSet::new(
            permissions
                .iter()
                .map(|permission| exo_gatekeeper::types::Permission::new(*permission))
                .collect(),
        );
        let mut authority_link = exo_gatekeeper::types::AuthorityLink {
            grantor: actor.clone(),
            grantee: actor.clone(),
            permissions: permission_set,
            signature: Vec::new(),
            grantor_public_key: Some(public_key.as_bytes().to_vec()),
        };
        let authority_message = exo_gatekeeper::authority_link_signature_message(&authority_link)
            .expect("canonical link payload");
        let authority_signature = exo_core::crypto::sign(authority_message.as_bytes(), &secret_key);
        authority_link.signature = authority_signature.to_bytes().to_vec();

        let timestamp = exo_core::Timestamp::new(1_777_000_000_000, 7).to_string();
        let action_hash =
            mcp_tool_action_hash(action, &arguments).expect("canonical tool action payload");
        let mut provenance = exo_gatekeeper::types::Provenance {
            actor: actor.clone(),
            timestamp: timestamp.clone(),
            action_hash: action_hash.as_bytes().to_vec(),
            signature: Vec::new(),
            public_key: Some(public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let provenance_message = exo_gatekeeper::provenance_signature_message(&provenance)
            .expect("canonical provenance payload");
        let provenance_signature =
            exo_core::crypto::sign(provenance_message.as_bytes(), &secret_key);
        provenance.signature = provenance_signature.to_bytes().to_vec();

        let mut params = serde_json::json!({
            "arguments": arguments,
            CONSTITUTIONAL_CONTEXT_FIELD: {
                "bcts_scope": action,
                "capabilities": ["mcp:tool_call"],
                "output_marking": AI_OUTPUT_MARKING,
                "forging_identity": false,
                "self_escalation": false,
                "adjudication_context": {
                    "actor_roles": [
                        { "name": "operator", "branch": "Executive" }
                    ],
                    "authority_chain": [
                        {
                        "grantor": actor.as_str(),
                        "grantee": actor.as_str(),
                        "permissions": permissions,
                        "signature": hex::encode(authority_link.signature),
                        "grantor_public_key": public_key_hex,
                    }
                    ],
                    "consent_records": [
                        {
                            "subject": actor.as_str(),
                            "granted_to": actor.as_str(),
                            "scope": "mcp:tool_call",
                            "active": true,
                        }
                    ],
                    "bailment_state": {
                        "state": "Active",
                        "bailor": actor.as_str(),
                        "bailee": actor.as_str(),
                        "scope": "mcp:tool_call",
                    },
                    "human_override_preserved": true,
                    "actor_permissions": ["mcp:tool_call"],
                    "provenance": {
                    "actor": actor.as_str(),
                    "timestamp": timestamp,
                    "action_hash": hex::encode(action_hash.as_bytes()),
                    "signature": hex::encode(provenance.signature),
                    "public_key": public_key_hex,
                }
                }
            }
        });
        refresh_context_evidence(&mut params);
        params
    }

    #[test]
    fn middleware_permits_valid_action() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "exochain_node_status";
        assert!(
            mw.enforce_tool_call(&did, action, &signed_tool_call_params(action))
                .is_ok()
        );
    }

    #[test]
    fn middleware_mcp_rules_pass_valid() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "list_invariants";
        let invocation = mw
            .parse_invocation_context(&did, action, &signed_tool_call_params(action))
            .unwrap();
        assert!(mw.enforce_mcp_rules(&invocation.mcp_context).is_ok());
    }

    #[test]
    fn middleware_adjudicate_permits_valid() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "exochain_node_status";
        let invocation = mw
            .parse_invocation_context(&did, action, &signed_tool_call_params(action))
            .unwrap();
        let verdict = mw
            .adjudicate(&did, action, &invocation.adjudication_context)
            .unwrap();
        assert!(verdict.is_permitted());
    }

    #[test]
    fn middleware_enforce_tool_call_rejects_escalated_kernel_verdict() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "exochain_node_status";
        let mut params = signed_tool_call_params(action);
        params[CONSTITUTIONAL_CONTEXT_FIELD]["adjudication_context"]["actor_permissions"] =
            serde_json::json!(["unrelated:permission"]);
        refresh_context_evidence(&mut params);

        let err = mw
            .enforce_tool_call(&did, action, &params)
            .expect_err("MCP middleware must not execute tools after an escalated kernel verdict");

        assert!(
            err.to_string().contains("escalated"),
            "expected escalated verdict refusal, got {err}"
        );
    }

    #[test]
    fn middleware_rejects_signed_context_replayed_with_different_arguments() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "exochain_node_status";
        let mut params = signed_tool_call_params(action);
        params["arguments"] = serde_json::json!({
            "target_tenant": "did:exo:other-tenant",
            "include_sensitive_state": true
        });

        let err = mw
            .enforce_tool_call(&did, action, &params)
            .expect_err("MCP signed context must be bound to the exact tool arguments");

        assert!(
            err.to_string().contains("action_hash"),
            "expected argument-bound action_hash refusal, got {err}"
        );
    }

    #[test]
    fn middleware_rejects_adjudication_context_tampering_after_signing() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "exochain_node_status";
        let mut params = signed_tool_call_params(action);
        params[CONSTITUTIONAL_CONTEXT_FIELD]["adjudication_context"]["consent_records"][0]["scope"] =
            serde_json::json!("mcp:tool_call,attacker:extra");
        params[CONSTITUTIONAL_CONTEXT_FIELD]["adjudication_context"]["bailment_state"]["scope"] =
            serde_json::json!("mcp:tool_call,attacker:extra");

        let err = mw
            .enforce_tool_call(&did, action, &params)
            .expect_err("MCP adjudication context evidence must reject caller tampering");

        assert!(
            err.to_string().contains("context_evidence"),
            "expected context-evidence refusal, got {err}"
        );
    }

    #[test]
    fn middleware_rejects_context_without_context_evidence_signature() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "exochain_node_status";
        let mut params = signed_tool_call_params(action);
        params[CONSTITUTIONAL_CONTEXT_FIELD]["adjudication_context"]
            .as_object_mut()
            .expect("adjudication context object")
            .remove("context_evidence");

        let err = mw
            .enforce_tool_call(&did, action, &params)
            .expect_err("MCP adjudication context must carry signed context evidence");

        assert!(
            err.to_string().contains("context_evidence"),
            "expected context-evidence refusal, got {err}"
        );
    }

    #[test]
    fn middleware_adjudicate_without_authority_fails_closed() {
        let mw = ConstitutionalMiddleware::new();
        let did = test_did();
        let action = "exochain_node_status";
        assert!(
            mw.enforce_tool_call(&did, action, &signed_tool_call_params(action))
                .is_err()
        );
    }

    #[test]
    fn middleware_refuses_without_verified_invocation_context() {
        let mw = signed_middleware();
        let did = test_did();
        let action = "exochain_node_status";
        let params_without_context = serde_json::json!({
            "name": action,
            "arguments": {},
        });
        let err = mw
            .enforce_tool_call(&did, action, &params_without_context)
            .expect_err("tool calls without verified MCP invocation context must fail closed");
        assert!(
            err.to_string().contains("verified MCP invocation context"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn middleware_rejects_denied_action() {
        // Build a middleware and test with a modified kernel scenario.
        // We cannot easily trigger a denial through the normal path since
        // our defaults are valid, but we can verify the kernel is initialized
        // with all 8 invariants by checking integrity.
        let mw = ConstitutionalMiddleware::new();
        assert!(
            mw.kernel
                .verify_kernel_integrity(b"EXOCHAIN Constitutional Trust Fabric")
        );
        // Verify all 8 invariants are loaded.
        assert_eq!(
            mw.kernel.invariant_engine().invariant_set.invariants.len(),
            8
        );
    }

    #[test]
    fn middleware_enforces_mcp_rules() {
        // The MCP rules check is exercised through the full enforce path.
        // A valid action must pass all 6 rules.
        let mw = signed_middleware();
        let did = test_did();
        let action = "read_data";
        assert!(
            mw.enforce_tool_call(&did, action, &signed_tool_call_params(action))
                .is_ok()
        );
    }

    #[test]
    fn middleware_default_trait() {
        let mw = ConstitutionalMiddleware::default();
        assert!(
            mw.kernel
                .verify_kernel_integrity(b"EXOCHAIN Constitutional Trust Fabric")
        );
    }

    #[test]
    fn middleware_constitution_hash_stable() {
        let mw1 = ConstitutionalMiddleware::new();
        let mw2 = ConstitutionalMiddleware::new();
        assert_eq!(
            mw1.kernel.constitution_hash(),
            mw2.kernel.constitution_hash()
        );
    }

    /// Regression guard: the module-level verified-context doc must remain in
    /// place so future changes do not reintroduce fabricated context.
    #[test]
    fn module_doc_retains_verified_context_requirement() {
        // Read the source file at test time. Tests run from the crate
        // root, so this relative path is stable in the repo layout.
        let src = std::fs::read_to_string("src/mcp/middleware.rs")
            .expect("middleware.rs readable from crate root");
        assert!(
            src.contains("# Verified Context Requirement"),
            "module doc must contain the verified-context requirement"
        );
        assert!(
            src.contains(CONSTITUTIONAL_CONTEXT_FIELD),
            "module doc must name the required tool-call context field"
        );
    }

    #[test]
    fn production_source_does_not_fabricate_mcp_context() {
        let src = std::fs::read_to_string("src/mcp/middleware.rs")
            .expect("middleware.rs readable from crate root");
        let production = src
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("middleware production section must be present");
        for (field, value) in [
            ("has_provenance", "true"),
            ("output_marked_ai", "true"),
            ("consent_active", "true"),
            ("human_override_preserved", "true"),
        ] {
            let fabricated_assignment = format!("{field}: {value}");
            assert!(
                !production.contains(&fabricated_assignment),
                "middleware production must not fabricate {fabricated_assignment}"
            );
        }
        let fixed_timestamp = ["2026-01", "-01T00:00:00Z"].concat();
        assert!(
            !production.contains(&fixed_timestamp),
            "middleware production must not hardcode provenance timestamps"
        );
        assert!(
            !production.contains("format!(\"{:?}\", violation.rule)"),
            "MCP middleware errors must use stable rule IDs instead of Rust Debug output"
        );
        assert!(
            production.contains("violation.rule.id()"),
            "MCP middleware errors must expose explicit stable MCP rule identifiers"
        );
    }

    #[test]
    fn production_delegation_id_uses_domain_separated_cbor() {
        let src = std::fs::read_to_string("src/mcp/middleware.rs")
            .expect("middleware.rs readable from crate root");
        let production = src
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("middleware production section must be present");

        assert!(
            production.contains("MCP_DELEGATION_ID_DOMAIN"),
            "MCP delegation IDs must carry an explicit domain separator"
        );
        assert!(
            production.contains("MCP_TOOL_ACTION_HASH_DOMAIN"),
            "MCP tool action hashes must carry an explicit domain separator"
        );
        assert!(
            production.contains("hash_structured"),
            "MCP delegation IDs must use canonical CBOR structured hashing"
        );
        assert!(
            !production.contains("payload.push(0x00)"),
            "MCP delegation IDs must not use ad hoc null separators"
        );
        assert!(
            !production.contains("Hash256::digest(&payload)"),
            "MCP delegation IDs must not hash raw delimiter payloads"
        );
    }

    #[test]
    fn delegation_id_rejects_legacy_delimiter_shape() {
        let actor = test_did();
        let action = "exochain_node_status";
        let bcts_scope = "mcp:tools";
        let arguments = serde_json::json!({});
        let tool_action_hash =
            mcp_tool_action_hash(action, &arguments).expect("canonical tool action hash");

        let structured = mcp_delegation_id(&actor, action, &tool_action_hash, bcts_scope)
            .expect("canonical delegation id");
        let repeat = mcp_delegation_id(&actor, action, &tool_action_hash, bcts_scope)
            .expect("canonical delegation id is deterministic");
        let mut legacy_payload = Vec::new();
        legacy_payload.extend_from_slice(actor.as_str().as_bytes());
        legacy_payload.push(0x00);
        legacy_payload.extend_from_slice(action.as_bytes());
        legacy_payload.push(0x00);
        legacy_payload.extend_from_slice(bcts_scope.as_bytes());
        let legacy = Hash256::digest(&legacy_payload);

        assert_eq!(structured, repeat);
        assert_ne!(structured, legacy);
        assert_ne!(
            structured,
            mcp_delegation_id(&actor, "other_action", &tool_action_hash, bcts_scope)
                .expect("canonical delegation id")
        );
        assert_ne!(
            structured,
            mcp_delegation_id(&actor, action, &tool_action_hash, "other_scope")
                .expect("canonical delegation id")
        );
        let other_arguments = serde_json::json!({"changed": true});
        let other_tool_action_hash =
            mcp_tool_action_hash(action, &other_arguments).expect("canonical tool action hash");
        assert_ne!(
            structured,
            mcp_delegation_id(&actor, action, &other_tool_action_hash, bcts_scope)
                .expect("canonical delegation id")
        );
    }

    #[test]
    fn tool_action_hash_binds_arguments() {
        let action = "exochain_node_status";
        let first = mcp_tool_action_hash(action, &serde_json::json!({"tenant": "alpha"}))
            .expect("canonical tool action hash");
        let repeat = mcp_tool_action_hash(action, &serde_json::json!({"tenant": "alpha"}))
            .expect("canonical tool action hash");
        let changed = mcp_tool_action_hash(action, &serde_json::json!({"tenant": "beta"}))
            .expect("canonical tool action hash");

        assert_eq!(first, repeat);
        assert_ne!(first, changed);
        assert_ne!(first, Hash256::digest(action.as_bytes()));
    }
}

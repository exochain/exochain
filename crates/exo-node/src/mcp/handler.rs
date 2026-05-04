//! MCP server handler — processes JSON-RPC requests from AI clients.
//!
//! The `McpServer` is the main entry point for handling MCP protocol messages.
//! It dispatches JSON-RPC requests to the appropriate handlers, enforces
//! constitutional constraints through the middleware, and returns properly
//! formatted JSON-RPC responses.

use std::{collections::BTreeMap, sync::Arc};

use exo_core::{Did, PublicKey, Signature};
use serde_json::Value;

use super::{
    context::NodeContext,
    error::McpError,
    middleware::ConstitutionalMiddleware,
    prompts::PromptRegistry,
    protocol::{
        INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, InitializeParams, InitializeResult,
        JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND, PARSE_ERROR, PromptsCapability,
        ResourcesCapability, ServerCapabilities, ServerInfo, ToolResult, ToolsCapability,
    },
    resources::ResourceRegistry,
    tools::ToolRegistry,
};

/// Maximum accepted JSON-RPC message size for all MCP transports.
///
/// The limit is intentionally well below Axum's default body limit so the
/// protocol handler and HTTP transport enforce the same deterministic bound.
pub const MAX_JSON_RPC_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_PROMPT_NAME_BYTES: usize = 128;
const MAX_PROMPT_ARGUMENT_COUNT: usize = 16;
const MAX_PROMPT_ARGUMENT_KEY_BYTES: usize = 64;
const MAX_PROMPT_ARGUMENT_VALUE_BYTES: usize = 4 * 1024;

fn serialize_json_rpc_response(response: &JsonRpcResponse) -> String {
    match serde_json::to_string(response) {
        Ok(serialized) => serialized,
        Err(error) => {
            tracing::error!(err = %error, "failed to serialize JSON-RPC response");
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":{INTERNAL_ERROR},\"message\":\"internal error: failed to serialize JSON-RPC response\"}}}}"
            )
        }
    }
}

fn json_rpc_internal_error(id: Option<Value>, public_message: &'static str) -> JsonRpcResponse {
    JsonRpcResponse::error(id, INTERNAL_ERROR, public_message.to_string())
}

/// MCP server that processes JSON-RPC messages from AI clients.
///
/// Each server instance is bound to a specific actor DID, ensuring that
/// all tool invocations are constitutionally adjudicated for that actor.
pub struct McpServer {
    actor_did: Did,
    registry: ToolRegistry,
    resources: ResourceRegistry,
    prompts: PromptRegistry,
    middleware: ConstitutionalMiddleware,
    context: NodeContext,
}

impl McpServer {
    /// Create a new MCP server with a configured authority signer for
    /// constitutional adjudication.
    #[must_use]
    pub fn with_authority(
        actor_did: Did,
        authority_did: Did,
        authority_public_key: PublicKey,
        authority_signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    ) -> Self {
        Self {
            actor_did,
            registry: ToolRegistry::default(),
            resources: ResourceRegistry::default(),
            prompts: PromptRegistry::default(),
            middleware: ConstitutionalMiddleware::with_authority(
                authority_did,
                authority_public_key,
                authority_signer,
            ),
            context: NodeContext::empty(),
        }
    }

    /// Create a new MCP server bound to a live node context.
    ///
    /// Tools that support live queries (node status, checkpoints, event
    /// lookup) will read from the context's reactor state and DAG store
    /// rather than returning templated responses. Used when the MCP
    /// server is embedded in a running node.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_context(actor_did: Did, context: NodeContext) -> Self {
        Self {
            actor_did,
            registry: ToolRegistry::default(),
            resources: ResourceRegistry::default(),
            prompts: PromptRegistry::default(),
            middleware: ConstitutionalMiddleware::new(),
            context,
        }
    }

    /// Create a context-bound MCP server with a configured authority signer.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_context_and_authority(
        actor_did: Did,
        context: NodeContext,
        authority_did: Did,
        authority_public_key: PublicKey,
        authority_signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    ) -> Self {
        Self {
            actor_did,
            registry: ToolRegistry::default(),
            resources: ResourceRegistry::default(),
            prompts: PromptRegistry::default(),
            middleware: ConstitutionalMiddleware::with_authority(
                authority_did,
                authority_public_key,
                authority_signer,
            ),
            context,
        }
    }

    /// Returns a reference to the runtime context.
    #[must_use]
    #[allow(dead_code)]
    pub fn context(&self) -> &NodeContext {
        &self.context
    }

    /// Returns the actor DID string.
    #[must_use]
    pub fn actor_did(&self) -> &str {
        self.actor_did.as_str()
    }

    /// Returns the number of registered tools.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.registry.list().len()
    }

    /// Handle a raw JSON-RPC message string.
    ///
    /// Returns `Some(response)` for requests (messages with an `id`),
    /// and `None` for notifications (messages without an `id`).
    #[must_use]
    pub fn handle_message(&self, message: &str) -> Option<String> {
        if message.len() > MAX_JSON_RPC_MESSAGE_BYTES {
            let resp = JsonRpcResponse::error(None, INVALID_REQUEST, "request too large".into());
            return Some(serialize_json_rpc_response(&resp));
        }

        let request: JsonRpcRequest = match serde_json::from_str(message) {
            Ok(req) => req,
            Err(e) => {
                tracing::debug!(err = %e, "failed to parse MCP JSON-RPC request");
                let resp = JsonRpcResponse::error(
                    None,
                    PARSE_ERROR,
                    "parse error: invalid JSON-RPC request".into(),
                );
                return Some(serialize_json_rpc_response(&resp));
            }
        };

        // Notifications (no id) don't get responses.
        // Process notification side-effects (none for now) and return.
        request.id.as_ref()?;

        let response = self.dispatch(&request);
        Some(serialize_json_rpc_response(&response))
    }

    /// Dispatch a parsed JSON-RPC request to the appropriate handler.
    fn dispatch(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "notifications/initialized" => {
                // This is a notification but sometimes sent with an id.
                JsonRpcResponse::success(request.id.clone(), Value::Null)
            }
            "tools/list" => self.handle_tools_list(request),
            "tools/call" => self.handle_tools_call(request),
            "resources/list" => self.handle_resources_list(request),
            "resources/read" => self.handle_resources_read(request),
            "prompts/list" => self.handle_prompts_list(request),
            "prompts/get" => self.handle_prompts_get(request),
            "ping" => self.handle_ping(request),
            _ => JsonRpcResponse::error(
                request.id.clone(),
                METHOD_NOT_FOUND,
                format!("method not found: {}", request.method),
            ),
        }
    }

    /// Handle `initialize` — returns server capabilities.
    fn handle_initialize(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        // Validate params if provided.
        if let Some(ref params) = request.params {
            if serde_json::from_value::<InitializeParams>(params.clone()).is_err() {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "invalid initialize params".into(),
                );
            }
        }

        let result = InitializeResult {
            protocol_version: "2024-11-05".into(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: false,
                }),
                resources: Some(ResourcesCapability {
                    subscribe: false,
                    list_changed: false,
                }),
                prompts: Some(PromptsCapability {
                    list_changed: false,
                }),
            },
            server_info: ServerInfo {
                name: "exochain-mcp".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
        };

        match serde_json::to_value(&result) {
            Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
            Err(error) => {
                tracing::error!(err = %error, "failed to serialize MCP initialize result");
                json_rpc_internal_error(request.id.clone(), "internal error")
            }
        }
    }

    /// Handle `tools/list` — returns all registered tools.
    fn handle_tools_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut tools: Vec<Value> = Vec::new();
        for tool in self.registry.list() {
            match serde_json::to_value(tool) {
                Ok(value) => tools.push(value),
                Err(error) => {
                    tracing::error!(
                        err = %error,
                        tool = %tool.name,
                        "failed to serialize MCP tool definition"
                    );
                    return json_rpc_internal_error(request.id.clone(), "internal error");
                }
            }
        }

        JsonRpcResponse::success(request.id.clone(), serde_json::json!({ "tools": tools }))
    }

    /// Handle `tools/call` — dispatch to a specific tool with constitutional enforcement.
    fn handle_tools_call(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params = match &request.params {
            Some(p) => p,
            None => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "missing params for tools/call".into(),
                );
            }
        };

        let tool_name = match params.get("name").and_then(|n| n.as_str()) {
            Some(name) => name,
            None => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "missing 'name' in tools/call params".into(),
                );
            }
        };

        let tool_params = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        // Constitutional enforcement before tool execution.
        if let Err(error) = self
            .middleware
            .enforce_tool_call(&self.actor_did, tool_name, params)
        {
            tracing::warn!(
                err = %error,
                tool = %tool_name,
                "MCP constitutional enforcement rejected tool call"
            );
            let error_result = ToolResult::error("constitutional enforcement failed");
            return match serde_json::to_value(&error_result) {
                Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                Err(error) => {
                    tracing::error!(
                        err = %error,
                        "failed to serialize MCP constitutional enforcement error result"
                    );
                    json_rpc_internal_error(request.id.clone(), "internal error")
                }
            };
        }

        // Execute the tool.
        match self
            .registry
            .execute(tool_name, &tool_params, &self.context)
        {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                Err(error) => {
                    tracing::error!(err = %error, tool = %tool_name, "failed to serialize MCP tool result");
                    json_rpc_internal_error(request.id.clone(), "internal error")
                }
            },
            Err(McpError::ToolNotFound(name)) => {
                let error_result = ToolResult::error(format!("Tool not found: {name}"));
                match serde_json::to_value(&error_result) {
                    Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                    Err(error) => {
                        tracing::error!(
                            err = %error,
                            tool = %name,
                            "failed to serialize MCP tool-not-found result"
                        );
                        json_rpc_internal_error(request.id.clone(), "internal error")
                    }
                }
            }
            // Schema validation failure surfaces as a standard JSON-RPC
            // INVALID_PARAMS so clients can distinguish a malformed call
            // from a runtime failure (A-020).
            Err(McpError::InvalidParams(msg)) => JsonRpcResponse::error(
                request.id.clone(),
                INVALID_PARAMS,
                format!("invalid params for tool `{tool_name}`: {msg}"),
            ),
            Err(error) => {
                tracing::error!(err = %error, tool = %tool_name, "MCP tool execution failed");
                json_rpc_internal_error(request.id.clone(), "internal error")
            }
        }
    }

    /// Handle `resources/list` — return all registered resource definitions.
    fn handle_resources_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut resources: Vec<Value> = Vec::new();
        for resource in self.resources.list() {
            match serde_json::to_value(resource) {
                Ok(value) => resources.push(value),
                Err(error) => {
                    tracing::error!(
                        err = %error,
                        uri = %resource.uri,
                        "failed to serialize MCP resource definition"
                    );
                    return json_rpc_internal_error(request.id.clone(), "internal error");
                }
            }
        }

        JsonRpcResponse::success(
            request.id.clone(),
            serde_json::json!({ "resources": resources }),
        )
    }

    /// Handle `resources/read` — return the body of a resource by URI.
    fn handle_resources_read(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params = match &request.params {
            Some(p) => p,
            None => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "missing params for resources/read".into(),
                );
            }
        };

        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri,
            None => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "missing 'uri' in resources/read params".into(),
                );
            }
        };

        match self.resources.read(uri, &self.context) {
            Some(content) => match serde_json::to_value(&content) {
                Ok(value) => JsonRpcResponse::success(
                    request.id.clone(),
                    serde_json::json!({ "contents": [value] }),
                ),
                Err(error) => {
                    tracing::error!(
                        err = %error,
                        uri = %uri,
                        "failed to serialize MCP resource content"
                    );
                    json_rpc_internal_error(request.id.clone(), "internal error")
                }
            },
            None => JsonRpcResponse::error(
                request.id.clone(),
                INVALID_REQUEST,
                format!("resource not found: {uri}"),
            ),
        }
    }

    /// Handle `prompts/list` — return all registered prompt definitions.
    fn handle_prompts_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut prompts: Vec<Value> = Vec::new();
        for prompt in self.prompts.list() {
            match serde_json::to_value(prompt) {
                Ok(value) => prompts.push(value),
                Err(error) => {
                    tracing::error!(
                        err = %error,
                        prompt = %prompt.name,
                        "failed to serialize MCP prompt definition"
                    );
                    return json_rpc_internal_error(request.id.clone(), "internal error");
                }
            }
        }

        JsonRpcResponse::success(
            request.id.clone(),
            serde_json::json!({ "prompts": prompts }),
        )
    }

    /// Handle `prompts/get` — return a rendered prompt result.
    fn handle_prompts_get(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params = match &request.params {
            Some(p) => p,
            None => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "missing params for prompts/get".into(),
                );
            }
        };

        let name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "missing 'name' in prompts/get params".into(),
                );
            }
        };
        if name.len() > MAX_PROMPT_NAME_BYTES {
            return JsonRpcResponse::error(
                request.id.clone(),
                INVALID_PARAMS,
                format!("prompt name may contain at most {MAX_PROMPT_NAME_BYTES} bytes"),
            );
        }

        let mut args: BTreeMap<String, String> = BTreeMap::new();
        if let Some(arg_value) = params.get("arguments") {
            let Some(obj) = arg_value.as_object() else {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "prompt arguments must be an object".into(),
                );
            };
            if obj.len() > MAX_PROMPT_ARGUMENT_COUNT {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    format!("prompts/get accepts at most {MAX_PROMPT_ARGUMENT_COUNT} arguments"),
                );
            }
            for (key, value) in obj {
                if key.len() > MAX_PROMPT_ARGUMENT_KEY_BYTES {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        INVALID_PARAMS,
                        format!(
                            "prompt argument names may contain at most {MAX_PROMPT_ARGUMENT_KEY_BYTES} bytes"
                        ),
                    );
                }
                let string_value = match value {
                    Value::String(s) => s.clone(),
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
                if string_value.len() > MAX_PROMPT_ARGUMENT_VALUE_BYTES {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        INVALID_PARAMS,
                        format!(
                            "prompt argument '{key}' may contain at most {MAX_PROMPT_ARGUMENT_VALUE_BYTES} bytes"
                        ),
                    );
                }
                args.insert(key.clone(), string_value);
            }
        }

        match self.prompts.get(name, &args) {
            Some(result) => match serde_json::to_value(&result) {
                Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                Err(error) => {
                    tracing::error!(
                        err = %error,
                        prompt = %name,
                        "failed to serialize MCP prompt result"
                    );
                    json_rpc_internal_error(request.id.clone(), "internal error")
                }
            },
            None => JsonRpcResponse::error(
                request.id.clone(),
                INVALID_REQUEST,
                format!("prompt not found: {name}"),
            ),
        }
    }

    /// Handle `ping` — returns pong.
    fn handle_ping(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse::success(request.id.clone(), serde_json::json!({}))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mcp::protocol::{AI_OUTPUT_GENERATOR, AI_OUTPUT_MARKING};

    fn test_server() -> McpServer {
        let did = Did::new("did:exo:test-ai-agent").expect("valid DID");
        let keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x4D; 32]).unwrap();
        let public_key = *keypair.public_key();
        let secret_key = keypair.secret_key().clone();
        McpServer::with_authority(
            did.clone(),
            did,
            public_key,
            Arc::new(move |message: &[u8]| exo_core::crypto::sign(message, &secret_key)),
        )
    }

    fn constitutional_context(actor_did: &str, action: &str) -> Value {
        let actor = Did::new(actor_did).expect("valid DID");
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
        let action_hash = exo_core::Hash256::digest(action.as_bytes());
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

        serde_json::json!({
            "bcts_scope": action,
            "capabilities": ["mcp:tool_call"],
            "output_marking": AI_OUTPUT_MARKING,
            "forging_identity": false,
            "self_escalation": false,
            "adjudication_context": {
                "actor_roles": [
                    { "name": "mcp-agent", "branch": "Judicial" }
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
                        "scope": "mcp:tools",
                        "active": true,
                    }
                ],
                "bailment_state": {
                    "state": "Active",
                    "bailor": actor.as_str(),
                    "bailee": actor.as_str(),
                    "scope": "mcp:tools",
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
        })
    }

    fn tool_call_params(name: &str, arguments: Value) -> Value {
        serde_json::json!({
            "name": name,
            "arguments": arguments,
            "constitutional_context": constitutional_context("did:exo:test-ai-agent", name),
        })
    }

    #[test]
    fn handler_with_context() {
        // An McpServer built with an empty NodeContext should behave
        // identically to one built with `new`.
        let did = Did::new("did:exo:test-ai-agent").expect("valid DID");
        let server = McpServer::with_context(did, NodeContext::empty());
        assert_eq!(server.actor_did(), "did:exo:test-ai-agent");
        assert_eq!(server.tool_count(), 40);
        assert!(!server.context().has_store());
    }

    #[test]
    fn handler_initialize() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client" }
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "exochain-mcp");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn handler_tools_list() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 40, "expected 3+5+4+5+4+4+4+4+4+3 = 40 tools");
        // Tools are in BTreeMap order (alphabetical).
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"exochain_node_status"));
        assert!(names.contains(&"exochain_create_identity"));
        assert!(names.contains(&"exochain_propose_bailment"));
        assert!(names.contains(&"exochain_create_decision"));
        assert!(names.contains(&"exochain_adjudicate_action"));
    }

    #[test]
    fn handler_tools_call_node_status() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": tool_call_params("exochain_node_status", serde_json::json!({}))
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        // The result is a ToolResult with content.
        let content = result["content"].as_array().unwrap();
        assert!(!content.is_empty());
        assert_eq!(content[0]["type"], "text");
        let text = content[0]["text"].as_str().unwrap();
        let status: Value = serde_json::from_str(text).unwrap();
        assert_eq!(status["node"], "exochain");
    }

    #[test]
    fn handler_tools_call_unknown() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": tool_call_params("nonexistent_tool", serde_json::json!({}))
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        // Unknown tools return a ToolResult with is_error: true.
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        assert_eq!(result["is_error"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("not found"));
    }

    #[test]
    fn handler_invalid_json() {
        let server = test_server();
        let response = server.handle_message("not json at all{{{").unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        let error = parsed.error.unwrap();
        assert_eq!(error.code, PARSE_ERROR);
        assert_eq!(error.message, "parse error: invalid JSON-RPC request");
    }

    #[test]
    fn handler_rejects_oversized_json_rpc_message_before_parsing() {
        let server = test_server();
        let oversized = " ".repeat((64 * 1024) + 1);

        let response = server.handle_message(&oversized).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        let error = parsed.error.expect("oversized message must fail");

        assert_eq!(error.code, INVALID_REQUEST);
        assert_eq!(error.message, "request too large");
    }

    #[test]
    fn handler_production_source_fails_closed_on_serialization_errors() {
        let source = include_str!("handler.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("handler production section must be present");

        assert!(
            !production.contains("unwrap_or_default()"),
            "MCP handler must not hide JSON-RPC serialization failures behind empty strings"
        );
        assert!(
            !production.contains(".filter_map(|"),
            "MCP handler list endpoints must not silently drop unserializable entries"
        );
    }

    #[test]
    fn handler_internal_errors_do_not_echo_internal_details_to_clients() {
        let source = include_str!("handler.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("handler production section must be present");

        assert!(
            !production.contains("serialization error: {e}"),
            "MCP JSON-RPC internal serialization failures must be logged, not echoed to clients"
        );
        assert!(
            !production.contains("tool execution error: {e}"),
            "MCP tool execution internals must be logged, not echoed to clients"
        );
        assert!(
            !production.contains("serialization error: {ser_err}"),
            "MCP tool-result serialization internals must be logged, not echoed to clients"
        );
        assert!(
            !production.contains("Constitutional enforcement failed: {e}"),
            "MCP constitutional enforcement internals must be logged, not echoed to clients"
        );
    }

    #[test]
    fn handler_constitutional_enforcement_errors_do_not_echo_internal_details() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 500,
            "method": "tools/call",
            "params": {
                "name": "exochain_node_status",
                "arguments": {},
                "constitutional_context": {
                    "bcts_scope": "SensitiveTenantScopeShouldNotEcho"
                }
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.expect("tool result");
        assert_eq!(result["is_error"], true);
        let text = result["content"][0]["text"].as_str().expect("text content");

        assert_eq!(text, "constitutional enforcement failed");
        assert!(!text.contains("verified MCP invocation context"));
        assert!(!text.contains("SensitiveTenantScopeShouldNotEcho"));
    }

    #[test]
    fn handler_ping() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "ping"
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        assert!(parsed.result.is_some());
    }

    #[test]
    fn handler_unknown_method() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "nonexistent/method"
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn handler_notification_returns_none() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        .to_string();

        let response = server.handle_message(&msg);
        assert!(response.is_none());
    }

    #[test]
    fn handler_resources_list() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/list"
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 6, "expected 6 registered resources");
        let uris: Vec<&str> = resources.iter().filter_map(|r| r["uri"].as_str()).collect();
        assert!(uris.contains(&"exochain://constitution"));
        assert!(uris.contains(&"exochain://invariants"));
        assert!(uris.contains(&"exochain://mcp-rules"));
        assert!(uris.contains(&"exochain://node/status"));
        assert!(uris.contains(&"exochain://tools"));
        assert!(uris.contains(&"exochain://readme"));
    }

    #[test]
    fn handler_resources_read() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 70,
            "method": "resources/read",
            "params": { "uri": "exochain://constitution" }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.is_empty());
        assert_eq!(contents[0]["uri"], "exochain://constitution");
    }

    #[test]
    fn handler_resources_read_unknown_uri() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 71,
            "method": "resources/read",
            "params": { "uri": "exochain://does-not-exist" }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn handler_resources_read_missing_uri() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 72,
            "method": "resources/read",
            "params": {}
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn handler_prompts_list() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 80,
            "method": "prompts/list"
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 4, "expected 4 registered prompts");
        let names: Vec<&str> = prompts.iter().filter_map(|p| p["name"].as_str()).collect();
        assert!(names.contains(&"governance_review"));
        assert!(names.contains(&"compliance_check"));
        assert!(names.contains(&"evidence_analysis"));
        assert!(names.contains(&"constitutional_audit"));
    }

    #[test]
    fn handler_prompts_get() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 81,
            "method": "prompts/get",
            "params": {
                "name": "governance_review",
                "arguments": {
                    "decision_id": "dec-100",
                    "decision_title": "Sample decision"
                }
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let messages = result["messages"].as_array().unwrap();
        assert!(!messages.is_empty());
        let text = messages[0]["content"]["text"].as_str().unwrap();
        assert!(text.contains("dec-100"));
        assert!(text.contains("Sample decision"));
    }

    #[test]
    fn handler_prompts_get_rejects_oversized_argument_value() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 84,
            "method": "prompts/get",
            "params": {
                "name": "constitutional_audit",
                "arguments": {
                    "scope": "node",
                    "focus": "x".repeat(MAX_PROMPT_ARGUMENT_VALUE_BYTES + 1)
                }
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        let error = parsed.error.expect("oversized prompt argument must fail");
        assert_eq!(error.code, INVALID_PARAMS);
        assert_eq!(
            error.message,
            format!(
                "prompt argument 'focus' may contain at most {MAX_PROMPT_ARGUMENT_VALUE_BYTES} bytes"
            )
        );
    }

    #[test]
    fn handler_prompts_get_rejects_oversized_name() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 85,
            "method": "prompts/get",
            "params": {
                "name": "x".repeat(MAX_PROMPT_NAME_BYTES + 1),
                "arguments": {}
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        let error = parsed.error.expect("oversized prompt name must fail");
        assert_eq!(error.code, INVALID_PARAMS);
        assert_eq!(
            error.message,
            format!("prompt name may contain at most {MAX_PROMPT_NAME_BYTES} bytes")
        );
    }

    #[test]
    fn handler_prompts_get_rejects_non_object_arguments() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 86,
            "method": "prompts/get",
            "params": {
                "name": "governance_review",
                "arguments": ["decision_id", "dec-1"]
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        let error = parsed.error.expect("non-object prompt arguments must fail");
        assert_eq!(error.code, INVALID_PARAMS);
        assert_eq!(error.message, "prompt arguments must be an object");
    }

    #[test]
    fn handler_prompts_get_rejects_too_many_arguments() {
        let server = test_server();
        let mut arguments = serde_json::Map::new();
        for idx in 0..=MAX_PROMPT_ARGUMENT_COUNT {
            arguments.insert(format!("arg_{idx}"), serde_json::json!("value"));
        }
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 87,
            "method": "prompts/get",
            "params": {
                "name": "governance_review",
                "arguments": serde_json::Value::Object(arguments)
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        let error = parsed.error.expect("too many prompt arguments must fail");
        assert_eq!(error.code, INVALID_PARAMS);
        assert_eq!(
            error.message,
            format!("prompts/get accepts at most {MAX_PROMPT_ARGUMENT_COUNT} arguments")
        );
    }

    #[test]
    fn handler_prompts_get_rejects_oversized_argument_name() {
        let server = test_server();
        let mut arguments = serde_json::Map::new();
        arguments.insert(
            "x".repeat(MAX_PROMPT_ARGUMENT_KEY_BYTES + 1),
            serde_json::json!("value"),
        );
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 88,
            "method": "prompts/get",
            "params": {
                "name": "governance_review",
                "arguments": serde_json::Value::Object(arguments)
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        let error = parsed
            .error
            .expect("oversized prompt argument name must fail");
        assert_eq!(error.code, INVALID_PARAMS);
        assert_eq!(
            error.message,
            format!(
                "prompt argument names may contain at most {MAX_PROMPT_ARGUMENT_KEY_BYTES} bytes"
            )
        );
    }

    #[test]
    fn handler_prompts_get_unknown() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 82,
            "method": "prompts/get",
            "params": {
                "name": "does-not-exist",
                "arguments": {}
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn handler_prompts_get_missing_name() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 83,
            "method": "prompts/get",
            "params": {}
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn handler_initialize_advertises_prompts() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 90,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client" }
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        let result = parsed.result.unwrap();
        assert!(result["capabilities"]["prompts"].is_object());
        assert!(result["capabilities"]["resources"].is_object());
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn handler_tools_call_missing_params() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call"
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn handler_tools_call_missing_name() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": { "arguments": {} }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn handler_tools_call_list_invariants() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": tool_call_params("exochain_list_invariants", serde_json::json!({}))
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        // is_error is skipped when false, so the field is absent.
        assert!(result.get("is_error").is_none() || result["is_error"] == false);
    }

    #[test]
    fn handler_tools_call_list_mcp_rules() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": tool_call_params("exochain_list_mcp_rules", serde_json::json!({}))
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        // is_error is skipped when false, so the field is absent.
        assert!(result.get("is_error").is_none() || result["is_error"] == false);
    }

    #[test]
    fn handler_tools_call_marks_result_as_ai_generated() {
        let server = test_server();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": tool_call_params("exochain_list_mcp_rules", serde_json::json!({}))
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        assert_eq!(result["metadata"]["generatedBy"], AI_OUTPUT_GENERATOR);
        assert_eq!(result["metadata"]["outputMarking"], AI_OUTPUT_MARKING);
    }
}

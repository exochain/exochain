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
        ResourcesCapability, ServerCapabilities, ServerInfo, ToolContent, ToolResult,
        ToolsCapability,
    },
    resources::ResourceRegistry,
    tools::ToolRegistry,
};

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
        let request: JsonRpcRequest = match serde_json::from_str(message) {
            Ok(req) => req,
            Err(e) => {
                let resp = JsonRpcResponse::error(None, PARSE_ERROR, format!("parse error: {e}"));
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
            Err(e) => JsonRpcResponse::error(
                request.id.clone(),
                INTERNAL_ERROR,
                format!("serialization error: {e}"),
            ),
        }
    }

    /// Handle `tools/list` — returns all registered tools.
    fn handle_tools_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut tools: Vec<Value> = Vec::new();
        for tool in self.registry.list() {
            match serde_json::to_value(tool) {
                Ok(value) => tools.push(value),
                Err(e) => {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        INTERNAL_ERROR,
                        format!("tool definition serialization error: {e}"),
                    );
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
        if let Err(e) = self.middleware.enforce(&self.actor_did, tool_name) {
            let error_result = ToolResult {
                content: vec![ToolContent::Text {
                    text: format!("Constitutional enforcement failed: {e}"),
                }],
                is_error: true,
            };
            return match serde_json::to_value(&error_result) {
                Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                Err(ser_err) => JsonRpcResponse::error(
                    request.id.clone(),
                    INTERNAL_ERROR,
                    format!("serialization error: {ser_err}"),
                ),
            };
        }

        // Execute the tool.
        match self
            .registry
            .execute(tool_name, &tool_params, &self.context)
        {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                Err(e) => JsonRpcResponse::error(
                    request.id.clone(),
                    INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                ),
            },
            Err(McpError::ToolNotFound(name)) => {
                let error_result = ToolResult {
                    content: vec![ToolContent::Text {
                        text: format!("Tool not found: {name}"),
                    }],
                    is_error: true,
                };
                match serde_json::to_value(&error_result) {
                    Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                    Err(ser_err) => JsonRpcResponse::error(
                        request.id.clone(),
                        INVALID_REQUEST,
                        format!("tool not found: {name} (serialization error: {ser_err})"),
                    ),
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
            Err(e) => JsonRpcResponse::error(
                request.id.clone(),
                INTERNAL_ERROR,
                format!("tool execution error: {e}"),
            ),
        }
    }

    /// Handle `resources/list` — return all registered resource definitions.
    fn handle_resources_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let mut resources: Vec<Value> = Vec::new();
        for resource in self.resources.list() {
            match serde_json::to_value(resource) {
                Ok(value) => resources.push(value),
                Err(e) => {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        INTERNAL_ERROR,
                        format!("resource definition serialization error: {e}"),
                    );
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
                Err(e) => JsonRpcResponse::error(
                    request.id.clone(),
                    INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                ),
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
                Err(e) => {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        INTERNAL_ERROR,
                        format!("prompt definition serialization error: {e}"),
                    );
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

        let mut args: BTreeMap<String, String> = BTreeMap::new();
        if let Some(arg_value) = params.get("arguments") {
            if let Some(obj) = arg_value.as_object() {
                for (k, v) in obj {
                    let string_value = match v {
                        Value::String(s) => s.clone(),
                        Value::Null => String::new(),
                        other => other.to_string(),
                    };
                    args.insert(k.clone(), string_value);
                }
            }
        }

        match self.prompts.get(name, &args) {
            Some(result) => match serde_json::to_value(&result) {
                Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                Err(e) => JsonRpcResponse::error(
                    request.id.clone(),
                    INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                ),
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
            "params": {
                "name": "exochain_node_status",
                "arguments": {}
            }
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
            "params": {
                "name": "nonexistent_tool",
                "arguments": {}
            }
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
        assert_eq!(parsed.error.unwrap().code, PARSE_ERROR);
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
            "params": {
                "name": "exochain_list_invariants",
                "arguments": {}
            }
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
            "params": {
                "name": "exochain_list_mcp_rules",
                "arguments": {}
            }
        })
        .to_string();

        let response = server.handle_message(&msg).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        // is_error is skipped when false, so the field is absent.
        assert!(result.get("is_error").is_none() || result["is_error"] == false);
    }
}

//! MCP protocol types — JSON-RPC 2.0 message structures.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// Standard JSON-RPC error codes.
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// MCP Initialize request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub roots: Option<Value>,
    #[serde(default)]
    pub sampling: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
}

/// MCP Initialize response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(default, rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesCapability {
    #[serde(default)]
    pub subscribe: bool,
    #[serde(default, rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsCapability {
    #[serde(default, rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// MCP Tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// MCP Tool call result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToolContent {
    #[serde(rename = "text")]
    Text { text: String },
}

impl ToolContent {
    /// Extract the text payload regardless of variant.
    #[must_use]
    #[allow(dead_code)] // Used in tool tests.
    pub fn text(&self) -> &str {
        match self {
            ToolContent::Text { text } => text,
        }
    }
}

impl ToolResult {
    /// Create a successful result with a single text content item.
    #[must_use]
    pub fn success(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: false,
        }
    }

    /// Create an error result with a single text content item.
    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: true,
        }
    }

    /// Create a JSON success result, failing closed if serialization fails.
    #[must_use]
    pub fn json_success<T>(payload: &T) -> Self
    where
        T: Serialize + ?Sized,
    {
        match serde_json::to_string_pretty(payload) {
            Ok(text) => Self::success(text),
            Err(err) => Self::error(
                serde_json::json!({
                    "error": "mcp_tool_result_serialization_failed",
                    "message": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

/// MCP Resource definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Used when MCP resources are implemented.
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// MCP Resource content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Used when MCP resources are implemented.
pub struct ResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl ResourceContent {
    /// Create JSON resource content, failing closed if serialization fails.
    #[must_use]
    pub fn json<T>(uri: impl Into<String>, payload: &T) -> Self
    where
        T: Serialize + ?Sized,
    {
        let uri = uri.into();
        let text = match serde_json::to_string_pretty(payload) {
            Ok(text) => text,
            Err(err) => serde_json::json!({
                "error": "mcp_resource_serialization_failed",
                "uri": uri.clone(),
                "message": err.to_string(),
            })
            .to_string(),
        };

        Self {
            uri,
            mime_type: Some("application/json".into()),
            text: Some(text),
        }
    }
}

/// MCP Prompt definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Used when MCP prompts are implemented.
pub struct PromptDefinition {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub arguments: Vec<PromptArgument>,
}

/// A named argument for an MCP prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Used when MCP prompts are implemented.
pub struct PromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// A message inside a prompt result (role + content).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Used when MCP prompts are implemented.
pub struct PromptMessage {
    pub role: String,
    pub content: PromptContent,
}

/// The content of a prompt message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PromptContent {
    #[serde(rename = "text")]
    Text { text: String },
}

impl PromptContent {
    /// Extract the text payload regardless of variant.
    #[must_use]
    #[allow(dead_code)] // Used in tests.
    pub fn text(&self) -> &str {
        match self {
            PromptContent::Text { text } => text,
        }
    }
}

/// The result returned by `prompts/get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Used when MCP prompts are implemented.
pub struct PromptResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<PromptMessage>,
}

impl JsonRpcResponse {
    #[must_use]
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn error(id: Option<Value>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn error_with_data(id: Option<Value>, code: i32, message: String, data: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: Some(data),
            }),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_request() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(Value::Number(1.into())),
            method: "tools/list".into(),
            params: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: JsonRpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jsonrpc, "2.0");
        assert_eq!(parsed.method, "tools/list");
        assert_eq!(parsed.id, Some(Value::Number(1.into())));
        assert!(parsed.params.is_none());
    }

    #[test]
    fn serialize_deserialize_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"test"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "tools/call");
        assert!(req.params.is_some());
    }

    #[test]
    fn serialize_success_response() {
        let resp = JsonRpcResponse::success(
            Some(Value::Number(1.into())),
            serde_json::json!({"status": "ok"}),
        );
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.result.is_some());
        assert!(parsed.error.is_none());
    }

    #[test]
    fn serialize_error_response() {
        let resp = JsonRpcResponse::error(
            Some(Value::Number(1.into())),
            METHOD_NOT_FOUND,
            "method not found".into(),
        );
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.result.is_none());
        assert!(parsed.error.is_some());
        let err = parsed.error.unwrap();
        assert_eq!(err.code, METHOD_NOT_FOUND);
        assert_eq!(err.message, "method not found");
        assert!(err.data.is_none());
    }

    #[test]
    fn serialize_error_response_with_data() {
        let resp = JsonRpcResponse::error_with_data(
            Some(Value::Number(1.into())),
            INVALID_PARAMS,
            "invalid params".into(),
            serde_json::json!({"field": "name"}),
        );
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&json).unwrap();
        let err = parsed.error.unwrap();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.data.is_some());
    }

    #[test]
    fn initialize_result_serialization() {
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
                prompts: None,
            },
            server_info: ServerInfo {
                name: "exochain-mcp".into(),
                version: "0.1.0".into(),
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["protocolVersion"], "2024-11-05");
        assert_eq!(json["serverInfo"]["name"], "exochain-mcp");
        // prompts should be absent (skip_serializing_if)
        assert!(json.get("capabilities").unwrap().get("prompts").is_none());
    }

    #[test]
    fn tool_definition_serialization() {
        let tool = ToolDefinition {
            name: "test_tool".into(),
            description: "A test tool".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "test_tool");
        assert_eq!(json["inputSchema"]["type"], "object");
    }

    #[test]
    fn tool_result_no_error_skips_field() {
        let result = ToolResult {
            content: vec![ToolContent::Text {
                text: "hello".into(),
            }],
            is_error: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("is_error"));
        assert!(!json.contains("isError"));
    }

    #[test]
    fn tool_result_with_error() {
        let result = ToolResult {
            content: vec![ToolContent::Text {
                text: "error occurred".into(),
            }],
            is_error: true,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["is_error"], true);
    }

    struct FailingSerialize;

    impl serde::Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    #[test]
    fn tool_result_json_success_fails_closed_on_serialization_error() {
        let result = ToolResult::json_success(&FailingSerialize);
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_tool_result_serialization_failed"));
        assert!(text.contains("intentional serialization failure"));
        assert_ne!(text, "{}");
    }

    #[test]
    fn resource_content_json_fails_closed_on_serialization_error() {
        let content = ResourceContent::json("exochain://test", &FailingSerialize);
        let text = content.text.expect("error JSON present");
        assert!(text.contains("mcp_resource_serialization_failed"));
        assert!(text.contains("exochain://test"));
        assert!(text.contains("intentional serialization failure"));
        assert_ne!(text, "{}");
    }

    #[test]
    fn mcp_json_emitters_do_not_fallback_to_empty_objects() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for path in [
            "src/mcp/tools/node.rs",
            "src/mcp/resources/node_status.rs",
            "src/mcp/resources/invariants.rs",
            "src/mcp/resources/mcp_rules.rs",
            "src/mcp/resources/tools_summary.rs",
        ] {
            let source = std::fs::read_to_string(manifest_dir.join(path)).unwrap();
            assert!(
                !source.contains("unwrap_or_else(|_| \"{}\".to_string())"),
                "{path} must fail closed instead of suppressing serialization errors as {{}}"
            );
        }
    }

    #[test]
    fn tool_content_text_tag() {
        let content = ToolContent::Text {
            text: "hello".into(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hello");
    }

    #[test]
    fn resource_definition_optional_fields() {
        let resource = ResourceDefinition {
            uri: "exochain://node/status".into(),
            name: "Node Status".into(),
            description: None,
            mime_type: None,
        };
        let json = serde_json::to_string(&resource).unwrap();
        assert!(!json.contains("description"));
        assert!(!json.contains("mimeType"));
    }

    #[test]
    fn request_without_id_is_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.method, "notifications/initialized");
    }
}

//! Identity MCP tools — DID creation, resolution, risk assessment, signature
//! verification, and agent passport retrieval.

use exo_core::{Did, crypto};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MAX_IDENTITY_EVIDENCE_TYPES: usize = 32;
const ED25519_PUBLIC_KEY_HEX_CHARS: usize = 64;
const ED25519_SIGNATURE_HEX_CHARS: usize = 128;
const MAX_SIGNATURE_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_MESSAGE_HEX_CHARS: usize = MAX_SIGNATURE_MESSAGE_BYTES * 2;

fn parse_evidence_types(params: &Value) -> Result<Vec<String>, ToolResult> {
    let Some(value) = params.get("evidence_types") else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(ToolResult::error(
            json!({"error": "evidence_types must be an array of strings"}).to_string(),
        ));
    };
    if values.len() > MAX_IDENTITY_EVIDENCE_TYPES {
        return Err(ToolResult::error(
            json!({
                "error": format!(
                    "evidence_types length {} exceeds maximum {}",
                    values.len(),
                    MAX_IDENTITY_EVIDENCE_TYPES
                )
            })
            .to_string(),
        ));
    }

    let mut evidence_types = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(evidence_type) = value.as_str() else {
            return Err(ToolResult::error(
                json!({"error": format!("evidence_types[{idx}] must be a string")}).to_string(),
            ));
        };
        evidence_types.push(evidence_type.to_owned());
    }
    Ok(evidence_types)
}

fn identity_runtime_unavailable(tool_name: &str) -> ToolResult {
    tracing::warn!(
        tool = %tool_name,
        "refusing MCP identity operation: no live identity runtime is attached"
    );
    ToolResult::error(
        json!({
            "error": "mcp_identity_runtime_unavailable",
            "tool": tool_name,
            "message": "This MCP identity tool has no live identity registry, key store, risk evidence store, or passport resolver attached. The `unaudited-mcp-simulation-tools` feature does not enable synthetic identity creation, format-only resolution, risk scoring, or passport state.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": "Initiatives/fix-mcp-simulation-tools.md",
            "refusal_source": format!("exo-node/mcp/tools/identity.rs::{tool_name}"),
        })
        .to_string(),
    )
}

fn hex_param_error(message: String) -> ToolResult {
    ToolResult::error(json!({ "error": message }).to_string())
}

fn required_hex_param<'a>(params: &'a Value, field: &str) -> Result<&'a str, ToolResult> {
    params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| hex_param_error(format!("missing required parameter: {field}")))
}

fn decode_hex_param(field: &str, value: &str) -> Result<Vec<u8>, ToolResult> {
    if value.len() % 2 != 0 {
        return Err(hex_param_error(format!(
            "{field} must contain an even number of hex characters"
        )));
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(hex_param_error(format!("{field} must be valid hex")));
    }
    hex::decode(value).map_err(|_| hex_param_error(format!("{field} must be valid hex")))
}

fn decode_exact_hex_param(
    params: &Value,
    field: &str,
    expected_hex_chars: usize,
) -> Result<Vec<u8>, ToolResult> {
    let value = required_hex_param(params, field)?;
    if value.len() != expected_hex_chars {
        return Err(hex_param_error(format!(
            "{field} must be exactly {expected_hex_chars} hex characters"
        )));
    }
    decode_hex_param(field, value)
}

fn decode_bounded_hex_param(
    params: &Value,
    field: &str,
    max_hex_chars: usize,
) -> Result<Vec<u8>, ToolResult> {
    let value = required_hex_param(params, field)?;
    if value.len() > max_hex_chars {
        return Err(hex_param_error(format!(
            "{field} length {} exceeds maximum {max_hex_chars} hex characters",
            value.len()
        )));
    }
    decode_hex_param(field, value)
}

// ---------------------------------------------------------------------------
// exochain_create_identity
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_create_identity`.
#[must_use]
pub fn create_identity_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_create_identity".to_owned(),
        description: "Create a new DID identity with an Ed25519 keypair. Returns the DID, public key, and initial verification method.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "label": {
                    "type": "string",
                    "description": "Optional human-readable label for this identity."
                }
            },
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_create_identity` tool.
#[must_use]
pub fn execute_create_identity(params: &Value, _context: &NodeContext) -> ToolResult {
    if params.get("label").is_some_and(|value| !value.is_string()) {
        return ToolResult::error(json!({"error": "label must be a string"}).to_string());
    }
    identity_runtime_unavailable("exochain_create_identity")
}

// ---------------------------------------------------------------------------
// exochain_resolve_identity
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_resolve_identity`.
#[must_use]
pub fn resolve_identity_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_resolve_identity".to_owned(),
        description: "Resolve a DID to its current document state, showing verification methods, service endpoints, and revocation status.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "did": {
                    "type": "string",
                    "description": "The DID to resolve (e.g. did:exo:abc123)."
                }
            },
            "required": ["did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_resolve_identity` tool.
#[must_use]
pub fn execute_resolve_identity(params: &Value, _context: &NodeContext) -> ToolResult {
    let did_str = match params.get("did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: did"}).to_string(),
            );
        }
    };
    if Did::new(did_str).is_err() {
        return ToolResult::error(json!({"error": "invalid DID format"}).to_string());
    }
    identity_runtime_unavailable("exochain_resolve_identity")
}

// ---------------------------------------------------------------------------
// exochain_assess_risk
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_assess_risk`.
#[must_use]
pub fn assess_risk_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_assess_risk".to_owned(),
        description: "Assess the identity risk score for a DID based on available evidence. Returns a risk attestation with score and contributing factors.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "did": {
                    "type": "string",
                    "description": "The DID to assess."
                },
                "evidence_types": {
                    "type": "array",
                    "items": { "type": "string" },
                    "maxItems": MAX_IDENTITY_EVIDENCE_TYPES,
                    "description": "Types of evidence to factor into the assessment (e.g. [\"kyc\", \"biometric\", \"social\"])."
                }
            },
            "required": ["did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_assess_risk` tool.
#[must_use]
pub fn execute_assess_risk(params: &Value, _context: &NodeContext) -> ToolResult {
    let did_str = match params.get("did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: did"}).to_string(),
            );
        }
    };
    if Did::new(did_str).is_err() {
        return ToolResult::error(json!({"error": "invalid DID format"}).to_string());
    }
    if let Err(error) = parse_evidence_types(params) {
        return error;
    }
    identity_runtime_unavailable("exochain_assess_risk")
}

// ---------------------------------------------------------------------------
// exochain_verify_signature
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_verify_signature`.
#[must_use]
pub fn verify_signature_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_verify_signature".to_owned(),
        description: "Verify an Ed25519 signature against a public key. Returns whether the signature is valid.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "public_key_hex": {
                    "type": "string",
                    "minLength": ED25519_PUBLIC_KEY_HEX_CHARS,
                    "maxLength": ED25519_PUBLIC_KEY_HEX_CHARS,
                    "description": "Hex-encoded Ed25519 public key (32 bytes / 64 hex chars)."
                },
                "message_hex": {
                    "type": "string",
                    "maxLength": MAX_SIGNATURE_MESSAGE_HEX_CHARS,
                    "description": "Hex-encoded message that was signed."
                },
                "signature_hex": {
                    "type": "string",
                    "minLength": ED25519_SIGNATURE_HEX_CHARS,
                    "maxLength": ED25519_SIGNATURE_HEX_CHARS,
                    "description": "Hex-encoded Ed25519 signature (64 bytes / 128 hex chars)."
                }
            },
            "required": ["public_key_hex", "message_hex", "signature_hex"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_verify_signature` tool.
#[must_use]
pub fn execute_verify_signature(params: &Value, _context: &NodeContext) -> ToolResult {
    let pk_bytes =
        match decode_exact_hex_param(params, "public_key_hex", ED25519_PUBLIC_KEY_HEX_CHARS) {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };
    let msg_bytes =
        match decode_bounded_hex_param(params, "message_hex", MAX_SIGNATURE_MESSAGE_HEX_CHARS) {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };
    let sig_bytes =
        match decode_exact_hex_param(params, "signature_hex", ED25519_SIGNATURE_HEX_CHARS) {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let public_key = exo_core::PublicKey::from_bytes(pk_arr);

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = exo_core::Signature::from_bytes(sig_arr);

    let valid = crypto::verify(&msg_bytes, &signature, &public_key);

    let response = json!({
        "valid": valid,
        "algorithm": "Ed25519",
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_get_passport
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_get_passport`.
#[must_use]
pub fn get_passport_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_get_passport".to_owned(),
        description: "Get the full agent passport for a DID \u{2014} a comprehensive trust profile including identity, delegations, consent, and standing.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "did": {
                    "type": "string",
                    "description": "The DID to retrieve the passport for."
                }
            },
            "required": ["did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_get_passport` tool.
#[must_use]
pub fn execute_get_passport(params: &Value, _context: &NodeContext) -> ToolResult {
    let did_str = match params.get("did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: did"}).to_string(),
            );
        }
    };
    if Did::new(did_str).is_err() {
        return ToolResult::error(json!({"error": "invalid DID format"}).to_string());
    }
    identity_runtime_unavailable("exochain_get_passport")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_identity_runtime_unavailable(result: ToolResult, tool_name: &str) {
        assert!(
            result.is_error,
            "{tool_name} must refuse until a live identity runtime is attached"
        );
        let text = result.content[0].text();
        assert!(text.contains("mcp_identity_runtime_unavailable"));
        assert!(text.contains(tool_name));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-simulation-tools.md"));
        for forbidden in [
            "public_key_hex",
            "verification_method_id",
            "resolution_status",
            "risk_score",
            "risk_level",
            "\"known\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "{tool_name} must not emit synthetic identity state field {forbidden}"
            );
        }
    }

    // -- create_identity ---------------------------------------------------

    #[test]
    fn create_identity_definition_valid() {
        let def = create_identity_definition();
        assert_eq!(def.name, "exochain_create_identity");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_create_identity_refuses_without_identity_runtime_even_with_simulation_feature() {
        let result = execute_create_identity(&json!({"label": "test-id"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_create_identity");
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_create_identity_refuses_by_default() {
        let result = execute_create_identity(&json!({"label": "test-id"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_create_identity");
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_create_identity_default_label_refuses_without_identity_runtime() {
        let result = execute_create_identity(&json!({}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_create_identity");
    }

    #[test]
    fn identity_simulation_did_prefix_avoids_hash_string_byte_slicing() {
        let source = include_str!("identity.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production source");

        assert!(
            !production.contains("to_string()[..16]"),
            "Hash256 display output must not be byte-sliced for simulated DID prefixes"
        );
    }

    // -- resolve_identity --------------------------------------------------

    #[test]
    fn resolve_identity_definition_valid() {
        let def = resolve_identity_definition();
        assert_eq!(def.name, "exochain_resolve_identity");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_resolve_identity_refuses_without_identity_runtime_even_with_simulation_feature() {
        let result =
            execute_resolve_identity(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_resolve_identity");
    }

    #[test]
    fn execute_resolve_identity_invalid_did() {
        let result = execute_resolve_identity(&json!({"did": "not-a-did"}), &NodeContext::empty());
        assert!(result.is_error);
        assert!(!result.content[0].text().contains("resolution_status"));
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_resolve_identity_refuses_by_default() {
        let result =
            execute_resolve_identity(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_resolve_identity");
    }

    #[test]
    fn execute_resolve_identity_missing_did() {
        let result = execute_resolve_identity(&json!({}), &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- assess_risk -------------------------------------------------------

    #[test]
    fn assess_risk_definition_valid() {
        let def = assess_risk_definition();
        assert_eq!(def.name, "exochain_assess_risk");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_assess_risk_refuses_without_identity_runtime_even_with_simulation_feature() {
        let result = execute_assess_risk(&json!({"did": "did:exo:target"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_assess_risk");
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_assess_risk_with_evidence_refuses_without_identity_runtime() {
        let result = execute_assess_risk(
            &json!({"did": "did:exo:target", "evidence_types": ["kyc", "biometric", "social"]}),
            &NodeContext::empty(),
        );
        assert_identity_runtime_unavailable(result, "exochain_assess_risk");
    }

    #[test]
    fn identity_simulation_evidence_types_are_bounded_before_collection() {
        let source = include_str!("identity.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production source");

        assert!(
            production.contains("MAX_IDENTITY_EVIDENCE_TYPES"),
            "MCP identity simulation risk evidence arrays must have an explicit bound"
        );
        assert!(
            production.contains("parse_evidence_types"),
            "MCP identity simulation risk evidence parsing must use a bounded parser"
        );
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_assess_risk_rejects_excessive_evidence_types() {
        let evidence_types: Vec<Value> = (0..=MAX_IDENTITY_EVIDENCE_TYPES)
            .map(|idx| Value::String(format!("evidence-{idx}")))
            .collect();

        let result = execute_assess_risk(
            &json!({"did": "did:exo:target", "evidence_types": evidence_types}),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("evidence_types"),
            "oversized evidence refusal should name the offending field"
        );
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_assess_risk_rejects_non_string_evidence_type() {
        let result = execute_assess_risk(
            &json!({"did": "did:exo:target", "evidence_types": ["kyc", 7]}),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("evidence_types[1]"),
            "typed parse failure should identify the offending array index"
        );
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_assess_risk_refuses_by_default() {
        let result = execute_assess_risk(&json!({"did": "did:exo:target"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_assess_risk");
    }

    #[test]
    fn execute_assess_risk_invalid_did() {
        let result = execute_assess_risk(&json!({"did": "bad"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn identity_simulation_invalid_did_errors_do_not_reflect_input() {
        let source = include_str!("identity.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production source");

        assert!(
            !production.contains("invalid DID format: {did_str}"),
            "MCP identity simulation errors must not reflect caller-controlled DIDs"
        );
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_assess_risk_invalid_did_error_omits_input() {
        let did = "bad<script>";
        let result = execute_assess_risk(&json!({"did": did}), &NodeContext::empty());

        assert!(result.is_error);
        assert!(
            !result.content[0].text().contains(did),
            "invalid DID error must not echo attacker-controlled input"
        );
    }

    // -- verify_signature --------------------------------------------------

    #[test]
    fn verify_signature_definition_valid() {
        let def = verify_signature_definition();
        assert_eq!(def.name, "exochain_verify_signature");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn verify_signature_definition_bounds_hex_inputs() {
        let def = verify_signature_definition();
        let properties = def.input_schema["properties"]
            .as_object()
            .expect("properties object");

        assert_eq!(properties["public_key_hex"]["minLength"], 64);
        assert_eq!(properties["public_key_hex"]["maxLength"], 64);
        assert_eq!(properties["message_hex"]["maxLength"], 128 * 1024);
        assert_eq!(properties["signature_hex"]["minLength"], 128);
        assert_eq!(properties["signature_hex"]["maxLength"], 128);
    }

    #[test]
    fn execute_verify_signature_valid() {
        let (pk, sk) = crypto::generate_keypair();
        let message = b"test message";
        let sig = crypto::sign(message, &sk);

        let params = json!({
            "public_key_hex": hex::encode(pk.as_bytes()),
            "message_hex": hex::encode(message),
            "signature_hex": hex::encode(sig.to_bytes()),
        });
        let result = execute_verify_signature(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], true);
        assert_eq!(v["algorithm"], "Ed25519");
    }

    #[test]
    fn execute_verify_signature_invalid() {
        let (pk, _sk) = crypto::generate_keypair();
        let params = json!({
            "public_key_hex": hex::encode(pk.as_bytes()),
            "message_hex": hex::encode(b"msg"),
            "signature_hex": hex::encode([0u8; 64]),
        });
        let result = execute_verify_signature(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
    }

    #[test]
    fn execute_verify_signature_bad_hex() {
        let result = execute_verify_signature(
            &json!({
                "public_key_hex": "not-hex",
                "message_hex": "00",
                "signature_hex": "00",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_verify_signature_rejects_oversized_message_without_echoing_it() {
        let (pk, _sk) = crypto::generate_keypair();
        let oversized = "aa".repeat((64 * 1024) + 1);
        let result = execute_verify_signature(
            &json!({
                "public_key_hex": hex::encode(pk.as_bytes()),
                "message_hex": oversized,
                "signature_hex": hex::encode([0u8; 64]),
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("message_hex"));
        assert!(text.contains("exceeds maximum"));
        assert!(!text.contains("aaaaaa"));
    }

    #[test]
    fn execute_verify_signature_rejects_oversized_key_without_echoing_it() {
        let oversized = "aa".repeat(33);
        let result = execute_verify_signature(
            &json!({
                "public_key_hex": oversized,
                "message_hex": "00",
                "signature_hex": hex::encode([0u8; 64]),
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("public_key_hex"));
        assert!(text.contains("exactly 64 hex characters"));
        assert!(!text.contains("aaaaaaaa"));
    }

    // -- get_passport ------------------------------------------------------

    #[test]
    fn get_passport_definition_valid() {
        let def = get_passport_definition();
        assert_eq!(def.name, "exochain_get_passport");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_get_passport_refuses_without_identity_runtime_even_with_simulation_feature() {
        let result = execute_get_passport(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_get_passport");
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_get_passport_refuses_by_default() {
        let result = execute_get_passport(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert_identity_runtime_unavailable(result, "exochain_get_passport");
    }

    #[test]
    fn execute_get_passport_invalid_did() {
        let result = execute_get_passport(&json!({"did": "bad"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_get_passport_missing_did() {
        let result = execute_get_passport(&json!({}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn identity_tools_do_not_fabricate_state_without_runtime() {
        let src = include_str!("identity.rs")
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production source");

        for (function, tool_name) in [
            ("execute_create_identity", "exochain_create_identity"),
            ("execute_resolve_identity", "exochain_resolve_identity"),
            ("execute_assess_risk", "exochain_assess_risk"),
            ("execute_get_passport", "exochain_get_passport"),
        ] {
            let body = src
                .split(&format!("pub fn {function}"))
                .nth(1)
                .expect("function section")
                .split("\n// ---------------------------------------------------------------------------")
                .next()
                .expect("function body");
            assert!(
                body.contains(&format!("identity_runtime_unavailable(\"{tool_name}\")")),
                "{function} must fail closed through the identity runtime-unavailable path"
            );
            for forbidden in [
                "crypto::generate_keypair",
                "\"public_key_hex\"",
                "\"verification_method_id\"",
                "\"resolution_status\"",
                "\"risk_score\"",
                "\"risk_level\"",
                "\"known\"",
            ] {
                assert!(
                    !body.contains(forbidden),
                    "{function} must not emit synthetic identity state: {forbidden}"
                );
            }
        }
    }
}

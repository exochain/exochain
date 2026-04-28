//! Identity MCP tools — DID creation, resolution, risk assessment, signature
//! verification, and agent passport retrieval.

use exo_core::crypto;
#[cfg(feature = "unaudited-mcp-simulation-tools")]
use exo_core::{Did, Hash256};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

#[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
fn identity_tool_refused(tool_name: &str, reason: &str) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_identity_tool_disabled",
            "tool": tool_name,
            "message": reason,
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": "Initiatives/fix-mcp-simulation-tools.md",
        })
        .to_string(),
    )
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
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        identity_tool_refused(
            "exochain_create_identity",
            "This MCP identity tool generates key material and returns a DID \
             without persisting the secret key or registering identity state. \
             It is disabled by default to avoid false identity-creation \
             success signals.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let label = params
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or("default");

        let (public_key, _secret_key) = crypto::generate_keypair();

        let pk_hex = hex::encode(public_key.as_bytes());

        // Build a DID from the hash of the public key.
        let pk_hash = Hash256::digest(public_key.as_bytes());
        let did_id = &pk_hash.to_string()[..16];
        let did_string = format!("did:exo:{did_id}");

        let method_id = format!("{did_string}#key-1");

        let response = json!({
            "did": did_string,
            "public_key_hex": pk_hex,
            "verification_method_id": method_id,
            "label": label,
        });
        ToolResult::success(response.to_string())
    }
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
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        identity_tool_refused(
            "exochain_resolve_identity",
            "This MCP identity tool only validates DID format and does not \
             query a live identity registry. It is disabled by default until \
             registry-backed DID resolution is wired.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let did_str = match params.get("did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: did"}).to_string(),
                );
            }
        };

        let valid_format = Did::new(did_str).is_ok();

        let resolution_status = if valid_format {
            "format_valid"
        } else {
            "invalid_format"
        };

        let response = json!({
            "did": did_str,
            "valid_format": valid_format,
            "did_method": "exo",
            "resolution_status": resolution_status,
        });
        ToolResult::success(response.to_string())
    }
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
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        identity_tool_refused(
            "exochain_assess_risk",
            "This MCP identity tool computes a synthetic risk score from \
             caller-supplied labels instead of verified evidence in a live \
             risk store. It is disabled by default until evidence-backed risk \
             assessment is wired.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let did_str = match params.get("did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: did"}).to_string(),
                );
            }
        };

        if Did::new(did_str).is_err() {
            return ToolResult::error(
                json!({"error": format!("invalid DID format: {did_str}")}).to_string(),
            );
        }

        let evidence_types: Vec<String> = params
            .get("evidence_types")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        // Compute a risk score based on evidence: each evidence type reduces risk
        // by 150 basis points from a baseline of 750 (high-ish).
        let baseline: i64 = 750;
        let reduction = i64::try_from(evidence_types.len()).unwrap_or(0) * 150;
        let risk_score = baseline.saturating_sub(reduction).max(0);

        let risk_level = match risk_score {
            0..=200 => "low",
            201..=500 => "medium",
            501..=800 => "high",
            _ => "critical",
        };

        let factors: Vec<Value> = evidence_types
            .iter()
            .map(|et| {
                json!({
                    "type": et,
                    "impact": "reduces_risk",
                    "weight_bps": 150,
                })
            })
            .collect();

        let response = json!({
            "did": did_str,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "factors": factors,
            "assessed_at": Value::Null,
            "assessed_at_source": "unavailable_no_risk_store",
        });
        ToolResult::success(response.to_string())
    }
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
                    "description": "Hex-encoded Ed25519 public key (32 bytes / 64 hex chars)."
                },
                "message_hex": {
                    "type": "string",
                    "description": "Hex-encoded message that was signed."
                },
                "signature_hex": {
                    "type": "string",
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
    let pk_hex = match params.get("public_key_hex").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: public_key_hex"}).to_string(),
            );
        }
    };
    let msg_hex = match params.get("message_hex").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: message_hex"}).to_string(),
            );
        }
    };
    let sig_hex = match params.get("signature_hex").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: signature_hex"}).to_string(),
            );
        }
    };

    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(e) => {
            return ToolResult::error(
                json!({"error": format!("invalid public_key_hex: {e}")}).to_string(),
            );
        }
    };
    let msg_bytes = match hex::decode(msg_hex) {
        Ok(b) => b,
        Err(e) => {
            return ToolResult::error(
                json!({"error": format!("invalid message_hex: {e}")}).to_string(),
            );
        }
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(e) => {
            return ToolResult::error(
                json!({"error": format!("invalid signature_hex: {e}")}).to_string(),
            );
        }
    };

    if pk_bytes.len() != 32 {
        return ToolResult::error(
            json!({"error": "public key must be exactly 32 bytes"}).to_string(),
        );
    }
    if sig_bytes.len() != 64 {
        return ToolResult::error(
            json!({"error": "signature must be exactly 64 bytes"}).to_string(),
        );
    }

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
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        identity_tool_refused(
            "exochain_get_passport",
            "This MCP identity tool returns a synthetic empty passport without \
             querying identity, delegation, consent, or standing stores. It is \
             disabled by default until live passport resolution is wired.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let did_str = match params.get("did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: did"}).to_string(),
                );
            }
        };

        if Did::new(did_str).is_err() {
            return ToolResult::error(
                json!({"error": format!("invalid DID format: {did_str}")}).to_string(),
            );
        }

        let response = json!({
            "did": did_str,
            "known": false,
            "identity": {
                "verification_methods": [],
                "service_endpoints": [],
                "revoked": false,
            },
            "delegations": {
                "active_grants": [],
                "received_grants": [],
            },
            "consent": {
                "active_bailments": [],
                "pending_proposals": [],
            },
            "standing": {
                "risk_level": "unassessed",
                "challenges": [],
                "governance_participation": 0,
            },
        });
        ToolResult::success(response.to_string())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- create_identity ---------------------------------------------------

    #[test]
    fn create_identity_definition_valid() {
        let def = create_identity_definition();
        assert_eq!(def.name, "exochain_create_identity");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_create_identity_returns_did() {
        let result = execute_create_identity(&json!({"label": "test-id"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        let did = v["did"].as_str().expect("did field");
        assert!(did.starts_with("did:exo:"));
        assert_eq!(v["label"], "test-id");
        assert!(v["public_key_hex"].as_str().expect("hex").len() == 64);
        assert!(
            v["verification_method_id"]
                .as_str()
                .expect("method_id")
                .contains("#key-1")
        );
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_create_identity_refuses_by_default() {
        let result = execute_create_identity(&json!({"label": "test-id"}), &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_identity_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-simulation-tools.md"));
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_create_identity_default_label() {
        let result = execute_create_identity(&json!({}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["label"], "default");
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
    fn execute_resolve_identity_valid_did() {
        let result =
            execute_resolve_identity(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid_format"], true);
        assert_eq!(v["resolution_status"], "format_valid");
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_resolve_identity_invalid_did() {
        let result = execute_resolve_identity(&json!({"did": "not-a-did"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid_format"], false);
        assert_eq!(v["resolution_status"], "invalid_format");
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_resolve_identity_refuses_by_default() {
        let result =
            execute_resolve_identity(&json!({"did": "did:exo:alice"}), &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_identity_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-simulation-tools.md"));
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
    fn execute_assess_risk_no_evidence() {
        let result = execute_assess_risk(&json!({"did": "did:exo:target"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["risk_score"], 750);
        assert_eq!(v["risk_level"], "high");
        assert_eq!(v["factors"].as_array().expect("factors").len(), 0);
        assert!(v["assessed_at"].is_null());
        assert_eq!(v["assessed_at_source"], "unavailable_no_risk_store");
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_assess_risk_with_evidence() {
        let result = execute_assess_risk(
            &json!({"did": "did:exo:target", "evidence_types": ["kyc", "biometric", "social"]}),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        // 750 - 3*150 = 300
        assert_eq!(v["risk_score"], 300);
        assert_eq!(v["risk_level"], "medium");
        assert_eq!(v["factors"].as_array().expect("factors").len(), 3);
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_assess_risk_refuses_by_default() {
        let result = execute_assess_risk(&json!({"did": "did:exo:target"}), &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_identity_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-simulation-tools.md"));
    }

    #[test]
    fn execute_assess_risk_invalid_did() {
        let result = execute_assess_risk(&json!({"did": "bad"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- verify_signature --------------------------------------------------

    #[test]
    fn verify_signature_definition_valid() {
        let def = verify_signature_definition();
        assert_eq!(def.name, "exochain_verify_signature");
        assert!(!def.description.is_empty());
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

    // -- get_passport ------------------------------------------------------

    #[test]
    fn get_passport_definition_valid() {
        let def = get_passport_definition();
        assert_eq!(def.name, "exochain_get_passport");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_get_passport_success() {
        let result = execute_get_passport(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["did"], "did:exo:alice");
        assert_eq!(v["known"], false);
        assert!(v.get("identity").is_some());
        assert!(v.get("delegations").is_some());
        assert!(v.get("consent").is_some());
        assert!(v.get("standing").is_some());
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_get_passport_refuses_by_default() {
        let result = execute_get_passport(&json!({"did": "did:exo:alice"}), &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_identity_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-simulation-tools.md"));
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

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn default_identity_tools_do_not_fabricate_state_before_gate() {
        let src = include_str!("identity.rs")
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production source");

        for function in [
            "execute_create_identity",
            "execute_resolve_identity",
            "execute_assess_risk",
            "execute_get_passport",
        ] {
            let section = src
                .split(&format!("pub fn {function}"))
                .nth(1)
                .expect("function section");
            let before_feature_branch = section
                .split("#[cfg(feature = \"unaudited-mcp-simulation-tools\")]")
                .next()
                .expect("default branch");

            assert!(
                before_feature_branch.contains("identity_tool_refused"),
                "{function} must refuse before any unaudited simulation behavior"
            );
            assert!(
                !before_feature_branch.contains("crypto::generate_keypair"),
                "{function} must not generate key material in the default build"
            );
            assert!(
                !before_feature_branch.contains("\"risk_score\""),
                "{function} must not synthesize risk output in the default build"
            );
            assert!(
                !before_feature_branch.contains("\"known\""),
                "{function} must not synthesize passport output in the default build"
            );
        }
    }
}

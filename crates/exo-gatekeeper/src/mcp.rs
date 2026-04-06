//! Model Context Protocol (MCP) enforcement.
//!
//! Ensures AI systems operating within the EXOCHAIN fabric respect
//! constitutional boundaries on autonomy, identity, and consent.
//!
//! **Key design**: The `SignerType` enum is part of the signed payload,
//! not a caller-set flag. An AI key uses prefix `0x02` in all signed
//! payloads, so even if an AI has valid key material, it cannot produce
//! a signature that could be mistaken for a human (`0x01`) signature.

use exo_core::{Did, SignerType};
use serde::{Deserialize, Serialize};

use crate::types::PermissionSet;

// ---------------------------------------------------------------------------
// MCP rules
// ---------------------------------------------------------------------------

/// Constitutional rules governing AI behavior within the EXOCHAIN fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpRule {
    Mcp001BctsScope,
    Mcp002NoSelfEscalation,
    Mcp003ProvenanceRequired,
    Mcp004NoIdentityForge,
    Mcp005Distinguishable,
    Mcp006ConsentBoundaries,
}

impl McpRule {
    #[must_use]
    pub fn all() -> Vec<McpRule> {
        vec![
            McpRule::Mcp001BctsScope,
            McpRule::Mcp002NoSelfEscalation,
            McpRule::Mcp003ProvenanceRequired,
            McpRule::Mcp004NoIdentityForge,
            McpRule::Mcp005Distinguishable,
            McpRule::Mcp006ConsentBoundaries,
        ]
    }

    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            McpRule::Mcp001BctsScope => "AI must operate within BCTS scope",
            McpRule::Mcp002NoSelfEscalation => "AI cannot self-escalate capabilities",
            McpRule::Mcp003ProvenanceRequired => "AI actions require provenance metadata",
            McpRule::Mcp004NoIdentityForge => "AI cannot forge identity or signatures",
            McpRule::Mcp005Distinguishable => "AI outputs must be distinguishable from human",
            McpRule::Mcp006ConsentBoundaries => "AI must respect consent boundaries",
        }
    }
}

// ---------------------------------------------------------------------------
// MCP context — uses cryptographic SignerType, not a bool flag
// ---------------------------------------------------------------------------

/// Context describing an AI actor's action, used for MCP rule enforcement.
#[derive(Debug, Clone)]
pub struct McpContext {
    pub actor_did: Did,
    /// Cryptographic signer type — embedded in the signed payload.
    /// Replaces the old `is_ai: bool` with a type that is part of the
    /// signature itself, preventing AI impersonation of human signers.
    pub signer_type: SignerType,
    pub bcts_scope: Option<String>,
    pub capabilities: PermissionSet,
    pub action: String,
    pub has_provenance: bool,
    pub forging_identity: bool,
    pub output_marked_ai: bool,
    pub consent_active: bool,
    pub self_escalation: bool,
}

impl McpContext {
    /// Whether this actor is an AI (derived from the cryptographic signer type).
    #[must_use]
    pub fn is_ai(&self) -> bool {
        self.signer_type.is_ai()
    }
}

// ---------------------------------------------------------------------------
// MCP violation
// ---------------------------------------------------------------------------

/// A violation produced when an AI action breaches an MCP rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpViolation {
    pub rule: McpRule,
    pub description: String,
    pub evidence: Vec<String>,
    pub severity: u8,
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Check all given MCP rules against the context, returning the first violation (if any).
pub fn enforce(rules: &[McpRule], context: &McpContext) -> Result<(), McpViolation> {
    if !context.is_ai() {
        return Ok(());
    }
    for rule in rules {
        check_rule(*rule, context)?;
    }
    Ok(())
}

fn check_rule(rule: McpRule, ctx: &McpContext) -> Result<(), McpViolation> {
    match rule {
        McpRule::Mcp001BctsScope => {
            if ctx.bcts_scope.is_none() {
                return Err(McpViolation {
                    rule,
                    description: "AI operating outside BCTS scope".into(),
                    evidence: vec![format!("actor: {}", ctx.actor_did)],
                    severity: 5,
                });
            }
            Ok(())
        }
        McpRule::Mcp002NoSelfEscalation => {
            if ctx.self_escalation {
                return Err(McpViolation {
                    rule,
                    description: "AI attempted self-escalation".into(),
                    evidence: vec![
                        format!("actor: {}", ctx.actor_did),
                        format!("action: {}", ctx.action),
                    ],
                    severity: 5,
                });
            }
            Ok(())
        }
        McpRule::Mcp003ProvenanceRequired => {
            if !ctx.has_provenance {
                return Err(McpViolation {
                    rule,
                    description: "AI action lacks provenance".into(),
                    evidence: vec![format!("action: {}", ctx.action)],
                    severity: 4,
                });
            }
            Ok(())
        }
        McpRule::Mcp004NoIdentityForge => {
            if ctx.forging_identity {
                return Err(McpViolation {
                    rule,
                    description: "AI attempted identity forge".into(),
                    evidence: vec![format!("actor: {}", ctx.actor_did)],
                    severity: 5,
                });
            }
            Ok(())
        }
        McpRule::Mcp005Distinguishable => {
            if !ctx.output_marked_ai {
                return Err(McpViolation {
                    rule,
                    description: "AI output not marked".into(),
                    evidence: vec![format!("action: {}", ctx.action)],
                    severity: 3,
                });
            }
            Ok(())
        }
        McpRule::Mcp006ConsentBoundaries => {
            if !ctx.consent_active {
                return Err(McpViolation {
                    rule,
                    description: "AI operating without consent".into(),
                    evidence: vec![format!("actor: {}", ctx.actor_did)],
                    severity: 5,
                });
            }
            Ok(())
        }
    }
}

/// Build a signable message that embeds the signer type.
/// This ensures the signer type is cryptographically bound to the signature.
#[must_use]
pub fn build_signed_payload(signer_type: &SignerType, message: &[u8]) -> Vec<u8> {
    let mut payload = signer_type.to_payload_prefix();
    payload.extend_from_slice(message);
    payload
}

/// Verify that a signature was produced with the claimed signer type.
/// The signer type prefix is prepended to the message before verification.
#[must_use]
pub fn verify_typed_signature(
    signer_type: &SignerType,
    message: &[u8],
    signature: &exo_core::Signature,
    public_key: &exo_core::PublicKey,
) -> bool {
    let payload = build_signed_payload(signer_type, message);
    exo_core::crypto::verify(&payload, signature, public_key)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::{Hash256, crypto::KeyPair};

    use super::*;
    use crate::types::Permission;

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    fn valid_ai() -> McpContext {
        McpContext {
            actor_did: did("did:exo:ai-agent-1"),
            signer_type: SignerType::Ai {
                delegation_id: Hash256::digest(b"delegation-1"),
            },
            bcts_scope: Some("data:medical".into()),
            capabilities: PermissionSet::new(vec![Permission::new("read")]),
            action: "summarize".into(),
            has_provenance: true,
            forging_identity: false,
            output_marked_ai: true,
            consent_active: true,
            self_escalation: false,
        }
    }

    fn human() -> McpContext {
        McpContext {
            actor_did: did("did:exo:human-1"),
            signer_type: SignerType::Human,
            bcts_scope: None,
            capabilities: PermissionSet::default(),
            action: "anything".into(),
            has_provenance: false,
            forging_identity: false,
            output_marked_ai: false,
            consent_active: false,
            self_escalation: false,
        }
    }

    #[test]
    fn all_pass_valid_ai() {
        assert!(enforce(&McpRule::all(), &valid_ai()).is_ok());
    }
    #[test]
    fn human_exempt() {
        assert!(enforce(&McpRule::all(), &human()).is_ok());
    }

    #[test]
    fn mcp001_fail() {
        let mut c = valid_ai();
        c.bcts_scope = None;
        let e = enforce(&[McpRule::Mcp001BctsScope], &c).unwrap_err();
        assert_eq!(e.rule, McpRule::Mcp001BctsScope);
        assert_eq!(e.severity, 5);
    }
    #[test]
    fn mcp001_pass() {
        assert!(enforce(&[McpRule::Mcp001BctsScope], &valid_ai()).is_ok());
    }

    #[test]
    fn mcp002_fail() {
        let mut c = valid_ai();
        c.self_escalation = true;
        assert_eq!(
            enforce(&[McpRule::Mcp002NoSelfEscalation], &c)
                .unwrap_err()
                .rule,
            McpRule::Mcp002NoSelfEscalation
        );
    }
    #[test]
    fn mcp002_pass() {
        assert!(enforce(&[McpRule::Mcp002NoSelfEscalation], &valid_ai()).is_ok());
    }

    #[test]
    fn mcp003_fail() {
        let mut c = valid_ai();
        c.has_provenance = false;
        let e = enforce(&[McpRule::Mcp003ProvenanceRequired], &c).unwrap_err();
        assert_eq!(e.rule, McpRule::Mcp003ProvenanceRequired);
        assert_eq!(e.severity, 4);
    }
    #[test]
    fn mcp003_pass() {
        assert!(enforce(&[McpRule::Mcp003ProvenanceRequired], &valid_ai()).is_ok());
    }

    #[test]
    fn mcp004_fail() {
        let mut c = valid_ai();
        c.forging_identity = true;
        assert_eq!(
            enforce(&[McpRule::Mcp004NoIdentityForge], &c)
                .unwrap_err()
                .rule,
            McpRule::Mcp004NoIdentityForge
        );
    }
    #[test]
    fn mcp004_pass() {
        assert!(enforce(&[McpRule::Mcp004NoIdentityForge], &valid_ai()).is_ok());
    }

    #[test]
    fn mcp005_fail() {
        let mut c = valid_ai();
        c.output_marked_ai = false;
        let e = enforce(&[McpRule::Mcp005Distinguishable], &c).unwrap_err();
        assert_eq!(e.rule, McpRule::Mcp005Distinguishable);
        assert_eq!(e.severity, 3);
    }
    #[test]
    fn mcp005_pass() {
        assert!(enforce(&[McpRule::Mcp005Distinguishable], &valid_ai()).is_ok());
    }

    #[test]
    fn mcp006_fail() {
        let mut c = valid_ai();
        c.consent_active = false;
        assert_eq!(
            enforce(&[McpRule::Mcp006ConsentBoundaries], &c)
                .unwrap_err()
                .rule,
            McpRule::Mcp006ConsentBoundaries
        );
    }
    #[test]
    fn mcp006_pass() {
        assert!(enforce(&[McpRule::Mcp006ConsentBoundaries], &valid_ai()).is_ok());
    }

    #[test]
    fn first_violation_returned() {
        let mut c = valid_ai();
        c.bcts_scope = None;
        c.has_provenance = false;
        assert_eq!(
            enforce(
                &[McpRule::Mcp001BctsScope, McpRule::Mcp003ProvenanceRequired],
                &c
            )
            .unwrap_err()
            .rule,
            McpRule::Mcp001BctsScope
        );
    }
    #[test]
    fn empty_rules_pass() {
        assert!(enforce(&[], &valid_ai()).is_ok());
    }
    #[test]
    fn all_six_rules() {
        assert_eq!(McpRule::all().len(), 6);
    }
    #[test]
    fn descriptions_non_empty() {
        for r in McpRule::all() {
            assert!(!r.description().is_empty());
        }
    }

    // -- Cryptographic AI identity binding tests --

    #[test]
    fn ai_cannot_impersonate_human() {
        // An AI signs a message with the AI prefix, then tries to verify
        // it as a human-signed message. This MUST fail.
        let kp = KeyPair::generate();
        let message = b"important governance vote";

        // AI signs with AI prefix
        let ai_type = SignerType::Ai {
            delegation_id: Hash256::digest(b"session-1"),
        };
        let ai_payload = build_signed_payload(&ai_type, message);
        let ai_sig = kp.sign(&ai_payload);

        // Verify as AI — should succeed
        assert!(verify_typed_signature(
            &ai_type,
            message,
            &ai_sig,
            kp.public_key()
        ));

        // Try to verify same signature as human — MUST fail
        assert!(!verify_typed_signature(
            &SignerType::Human,
            message,
            &ai_sig,
            kp.public_key()
        ));
    }

    #[test]
    fn human_signature_cannot_be_replayed_as_ai() {
        let kp = KeyPair::generate();
        let message = b"budget approval";

        // Human signs
        let human_payload = build_signed_payload(&SignerType::Human, message);
        let human_sig = kp.sign(&human_payload);

        // Verify as human — should succeed
        assert!(verify_typed_signature(
            &SignerType::Human,
            message,
            &human_sig,
            kp.public_key()
        ));

        // Try to verify as AI — MUST fail
        let ai_type = SignerType::Ai {
            delegation_id: Hash256::digest(b"d"),
        };
        assert!(!verify_typed_signature(
            &ai_type,
            message,
            &human_sig,
            kp.public_key()
        ));
    }

    #[test]
    fn different_delegation_ids_produce_different_signatures() {
        let kp = KeyPair::generate();
        let message = b"action";

        let ai1 = SignerType::Ai {
            delegation_id: Hash256::digest(b"delegation-A"),
        };
        let ai2 = SignerType::Ai {
            delegation_id: Hash256::digest(b"delegation-B"),
        };

        let payload1 = build_signed_payload(&ai1, message);
        let payload2 = build_signed_payload(&ai2, message);
        assert_ne!(payload1, payload2);

        let sig1 = kp.sign(&payload1);
        // sig1 verifies under ai1 but NOT under ai2
        assert!(verify_typed_signature(
            &ai1,
            message,
            &sig1,
            kp.public_key()
        ));
        assert!(!verify_typed_signature(
            &ai2,
            message,
            &sig1,
            kp.public_key()
        ));
    }

    #[test]
    fn signer_type_prefix_bytes() {
        assert_eq!(SignerType::Human.prefix_byte(), 0x01);
        let ai = SignerType::Ai {
            delegation_id: Hash256::ZERO,
        };
        assert_eq!(ai.prefix_byte(), 0x02);
        assert_eq!(ai.to_payload_prefix().len(), 33); // 1 prefix + 32 hash
    }

    #[test]
    fn signer_type_is_checks() {
        assert!(SignerType::Human.is_human());
        assert!(!SignerType::Human.is_ai());
        let ai = SignerType::Ai {
            delegation_id: Hash256::ZERO,
        };
        assert!(ai.is_ai());
        assert!(!ai.is_human());
    }

    #[test]
    fn context_is_ai_derived() {
        assert!(valid_ai().is_ai());
        assert!(!human().is_ai());
    }
}

//! Constitutional enforcement middleware for MCP tool calls.
//!
//! Every tool invocation passes through this middleware which:
//! 1. Builds an `McpContext` from the calling actor's identity
//! 2. Enforces all 6 MCP rules (via exo-gatekeeper)
//! 3. Builds an `AdjudicationContext` for the CGR Kernel
//! 4. Adjudicates the action against all 8 constitutional invariants
//! 5. Returns Permitted/Denied/Escalated verdict
//!
//! # Audit status — Onyx pass 3, RED #3 (defense-in-depth notice)
//!
//! The `McpContext` and `AdjudicationContext` built below carry
//! **hardcoded-true** constitutional booleans:
//!
//!   - `has_provenance: true`
//!   - `consent_active: true`
//!   - `output_marked_ai: true`
//!   - `human_override_preserved: true`
//!   - authority chain: configured MCP authority → actor
//!   - provenance: configured MCP authority signature over the tool action
//!
//! These sentinels mean the middleware cannot actually fail on
//! `ProvenancePresent`, `ConsentRequired`, or `HumanOverride` —
//! those invariants rubber-stamp every call. The semantic checks
//! that DO fire are the structural ones (`NoSelfGrant`,
//! `KernelModification`, `SeparationOfPowers`) because those look
//! at fields the caller supplies (`is_self_grant`, `modifies_kernel`,
//! `actor_roles`).
//!
//! **Current blast radius: bounded by the gate on RED #2.** Governance MCP
//! tools that would otherwise simulate decisions, votes, quorum, decision
//! status, or amendments refuse by default behind the
//! `unaudited-mcp-simulation-tools` feature flag. Non-synthetic read-only
//! tools (`exochain_list_invariants`, etc.) are the only callers the
//! middleware currently rubber-stamps, and they can't mutate governance
//! fabric.
//!
//! **When RED #2 is resolved (real reactor wiring), this middleware
//! MUST be promoted from node-level authority to live delegated authority.**
//! A rewrite must either:
//!   (a) accept real `McpContext` / `AdjudicationContext` from the
//!       caller and verify the embedded signatures/provenance, or
//!   (b) decline to adjudicate (return Err) when it cannot construct
//!       a real context and refuse the mutating action at the handler
//!       layer.
//!
//! Tracked in `Initiatives/fix-mcp-simulation-tools.md`. This
//! module-level doc exists so the stub context is visible to anyone
//! reading the code — DO NOT remove the audit-status section when
//! adjusting this middleware.

use std::sync::Arc;

use exo_core::{Did, Hash256, PublicKey, Signature, SignerType};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    mcp::{self, McpContext, McpRule},
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role,
    },
};

use super::error::{McpError, Result};

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
    signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
}

impl ConstitutionalMiddleware {
    /// Create a new middleware instance with the full constitutional kernel.
    ///
    /// **Emits a loud warning** about the stub adjudication context.
    /// See module-level docs under `# Audit status` for why this
    /// middleware cannot currently detect provenance/consent/authority
    /// violations — those invariants rubber-stamp every call.
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
    /// The authority is used to sign the canonical authority/provenance payload
    /// hashes that the gatekeeper verifies. The surrounding MCP context still
    /// carries hardcoded consent/provenance booleans until
    /// `fix-mcp-simulation-tools.md` is resolved.
    #[must_use]
    pub fn with_authority(
        authority_did: Did,
        authority_public_key: PublicKey,
        authority_signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    ) -> Self {
        tracing::warn!(
            "mcp::ConstitutionalMiddleware initialized with configured \
             authority signer but hardcoded MCP context booleans \
             (has_provenance/consent_active/human_override_preserved). \
             Mutating tools MUST remain gated separately. Tracked in \
             Initiatives/fix-mcp-simulation-tools.md."
        );
        let kernel = Kernel::new(b"EXOCHAIN Constitutional Trust Fabric", InvariantSet::all());
        Self {
            kernel,
            authority: Some(McpAuthority {
                did: authority_did,
                public_key: authority_public_key,
                signer: authority_signer,
            }),
        }
    }

    /// Enforce all 6 MCP rules against the AI actor's context.
    ///
    /// Builds an `McpContext` with reasonable defaults for an AI agent
    /// operating within the MCP protocol and verifies all rules pass.
    pub fn enforce_mcp_rules(&self, actor_did: &Did, action: &str) -> Result<()> {
        let ctx = McpContext {
            actor_did: actor_did.clone(),
            signer_type: SignerType::Ai {
                delegation_id: Hash256::digest(b"mcp-session"),
            },
            bcts_scope: Some(action.to_string()),
            capabilities: PermissionSet::new(vec![Permission::new("mcp:tool_call")]),
            action: action.to_string(),
            has_provenance: true,
            forging_identity: false,
            output_marked_ai: true,
            consent_active: true,
            self_escalation: false,
        };

        mcp::enforce(&McpRule::all(), &ctx).map_err(|violation| McpError::McpRuleViolation {
            rule: format!("{:?}", violation.rule),
            description: violation.description,
        })
    }

    fn signed_authority_link(authority: &McpAuthority, grantee: &Did) -> AuthorityLink {
        let permissions = PermissionSet::new(vec![Permission::new("mcp:tool_call")]);

        let mut payload = Vec::new();
        payload.extend_from_slice(authority.did.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(grantee.as_str().as_bytes());
        payload.push(0x00);
        for permission in &permissions.permissions {
            payload.extend_from_slice(permission.0.as_bytes());
            payload.push(0x00);
        }
        let message = Hash256::digest(&payload);
        let signature = (authority.signer)(message.as_bytes());

        AuthorityLink {
            grantor: authority.did.clone(),
            grantee: grantee.clone(),
            permissions,
            signature: signature.to_bytes().to_vec(),
            grantor_public_key: Some(authority.public_key.as_bytes().to_vec()),
        }
    }

    fn signed_provenance(authority: &McpAuthority, actor: &Did, action: &str) -> Provenance {
        let timestamp = "2026-01-01T00:00:00Z".to_owned();
        let action_hash = Hash256::digest(action.as_bytes()).as_bytes().to_vec();

        let mut payload = Vec::new();
        payload.extend_from_slice(actor.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&action_hash);
        payload.push(0x00);
        payload.extend_from_slice(timestamp.as_bytes());
        let message = Hash256::digest(&payload);
        let signature = (authority.signer)(message.as_bytes());

        Provenance {
            actor: actor.clone(),
            timestamp,
            action_hash,
            signature: signature.to_bytes().to_vec(),
            public_key: Some(authority.public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        }
    }

    /// Adjudicate an action against all 8 constitutional invariants.
    ///
    /// Builds an `ActionRequest` and `AdjudicationContext` with reasonable
    /// defaults (single Judicial role, valid authority chain from root to
    /// actor, active bailment, provenance present) and returns the kernel
    /// verdict.
    pub fn adjudicate(&self, actor_did: &Did, action: &str) -> Result<Verdict> {
        let action_request = ActionRequest {
            actor: actor_did.clone(),
            action: action.to_string(),
            required_permissions: PermissionSet::new(vec![Permission::new("mcp:tool_call")]),
            is_self_grant: false,
            modifies_kernel: false,
        };

        let authority = self.authority.as_ref().ok_or_else(|| {
            McpError::ConstitutionalViolation(
                "MCP authority signer is required for kernel adjudication".into(),
            )
        })?;
        if actor_did != &authority.did {
            return Err(McpError::AuthenticationRequired);
        }

        let adj_context = AdjudicationContext {
            actor_roles: vec![Role {
                name: "mcp-agent".into(),
                branch: GovernmentBranch::Judicial,
            }],
            authority_chain: AuthorityChain {
                links: vec![Self::signed_authority_link(authority, actor_did)],
            },
            consent_records: vec![ConsentRecord {
                subject: authority.did.clone(),
                granted_to: actor_did.clone(),
                scope: "mcp:tools".into(),
                active: true,
            }],
            bailment_state: BailmentState::Active {
                bailor: authority.did.clone(),
                bailee: actor_did.clone(),
                scope: "mcp:tools".into(),
            },
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![Permission::new("mcp:tool_call")]),
            provenance: Some(Self::signed_provenance(authority, actor_did, action)),
            quorum_evidence: None,
            active_challenge_reason: None,
        };

        let verdict = self.kernel.adjudicate(&action_request, &adj_context);

        match &verdict {
            Verdict::Denied { violations } => {
                let descriptions: Vec<String> =
                    violations.iter().map(|v| v.description.clone()).collect();
                Err(McpError::ConstitutionalViolation(descriptions.join("; ")))
            }
            _ => Ok(verdict),
        }
    }

    /// Full constitutional enforcement: MCP rules + kernel adjudication.
    ///
    /// Returns `Ok(())` only if both the 6 MCP rules and the 8 kernel
    /// invariants pass. An escalated verdict is treated as permissible
    /// (the action proceeds but is flagged for review).
    pub fn enforce(&self, actor_did: &Did, action: &str) -> Result<()> {
        self.enforce_mcp_rules(actor_did, action)?;
        self.adjudicate(actor_did, action)?;
        Ok(())
    }
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

    #[test]
    fn middleware_permits_valid_action() {
        let mw = signed_middleware();
        let did = test_did();
        assert!(mw.enforce(&did, "exochain_node_status").is_ok());
    }

    #[test]
    fn middleware_mcp_rules_pass_valid() {
        let mw = ConstitutionalMiddleware::new();
        let did = test_did();
        assert!(mw.enforce_mcp_rules(&did, "list_invariants").is_ok());
    }

    #[test]
    fn middleware_adjudicate_permits_valid() {
        let mw = signed_middleware();
        let did = test_did();
        let verdict = mw.adjudicate(&did, "exochain_node_status").unwrap();
        assert!(verdict.is_permitted());
    }

    #[test]
    fn middleware_adjudicate_without_authority_fails_closed() {
        let mw = ConstitutionalMiddleware::new();
        let did = test_did();
        assert!(mw.adjudicate(&did, "exochain_node_status").is_err());
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
        let mw = ConstitutionalMiddleware::new();
        let did = test_did();
        // This should succeed — all MCP context defaults are compliant.
        assert!(mw.enforce_mcp_rules(&did, "read_data").is_ok());
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

    /// Regression guard: the module-level `# Audit status` doc must
    /// remain in place. It's the only durable signal to future readers
    /// that this middleware cannot detect provenance/consent/authority
    /// violations. If someone "cleans up" the doc they must re-add it.
    #[test]
    fn module_doc_retains_audit_status_section() {
        // Read the source file at test time. Tests run from the crate
        // root, so this relative path is stable in the repo layout.
        let src = std::fs::read_to_string("src/mcp/middleware.rs")
            .expect("middleware.rs readable from crate root");
        assert!(
            src.contains("# Audit status"),
            "module doc must contain '# Audit status' audit notice; \
             see RED #3 fix commit. Do not remove this section."
        );
        assert!(
            src.contains("hardcoded-true") || src.contains("hardcoded true"),
            "audit doc must name the stub behavior explicitly"
        );
        assert!(
            src.contains("unaudited-mcp-simulation-tools"),
            "audit doc must link to the RED #2 feature flag"
        );
        assert!(
            src.contains("fix-mcp-simulation-tools.md"),
            "audit doc must link to the remediation initiative"
        );
    }
}

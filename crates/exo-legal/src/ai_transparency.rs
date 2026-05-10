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

//! AI transparency reporting module.
//!
//! Aggregates AI agent actions, delegation events, and MCP enforcement
//! outcomes into a structured [`AiTransparencyReport`] suitable for
//! regulatory submission under EU AI Act Article 13 and GDPR Article 22.
//!
//! # Clearance requirement
//!
//! [`generate_report`] is a sensitive operation — the report reveals which
//! AI agents hold delegated authority. Callers must pass a
//! [`VerifiedAuthorityClearance`] created by [`verify_authority_clearance`],
//! which verifies the requesting actor's authority chain before any report
//! can be generated.

use std::fmt;

use exo_authority::{AuthorityChain, AuthorityLink, AuthorityRevocation, DelegateeKind, chain};
use exo_core::{Did, PublicKey, Timestamp, hash::hash_structured};
use exo_gatekeeper::mcp_audit::{
    McpAuditLog, McpEnforcementOutcome, verify_chain as verify_mcp_audit_chain,
};
use serde::{Deserialize, Serialize};

use crate::error::{LegalError, Result};

const AUTHORITY_CLEARANCE_DOMAIN: &str = "exo.legal.ai_transparency.authority_clearance.v1";
const AUTHORITY_CLEARANCE_SCHEMA_VERSION: u16 = 1;
const AI_DELEGATION_GRANT_DOMAIN: &str = "exo.legal.ai_transparency.ai_delegation_grant.v1";
const AI_DELEGATION_GRANT_SCHEMA_VERSION: u16 = 1;
const AI_DELEGATION_REVOCATION_DOMAIN: &str =
    "exo.legal.ai_transparency.ai_delegation_revocation.v1";
const AI_DELEGATION_REVOCATION_SCHEMA_VERSION: u16 = 1;
const DEBUG_REDACTED: &str = "<redacted>";

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

/// Verified authority-chain evidence authorizing report generation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityClearanceEvidence {
    pub requester: Did,
    pub verified_at: Timestamp,
    pub chain_root: Did,
    pub chain_leaf: Did,
    pub chain_depth: usize,
    pub chain_hash: [u8; 32],
}

impl fmt::Debug for AuthorityClearanceEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityClearanceEvidence")
            .field("requester", &DEBUG_REDACTED)
            .field("verified_at", &self.verified_at)
            .field("chain_root", &DEBUG_REDACTED)
            .field("chain_leaf", &DEBUG_REDACTED)
            .field("chain_depth", &self.chain_depth)
            .field("chain_hash", &self.chain_hash)
            .finish()
    }
}

/// Authority clearance artifact that can only be created by successful chain
/// verification through [`verify_authority_clearance`].
#[derive(Debug, Clone)]
pub struct VerifiedAuthorityClearance {
    evidence: AuthorityClearanceEvidence,
}

impl VerifiedAuthorityClearance {
    /// Return the serializable evidence captured after verification.
    #[must_use]
    pub fn evidence(&self) -> &AuthorityClearanceEvidence {
        &self.evidence
    }
}

/// Summary of a single AI agent delegation event.
#[derive(Clone, Serialize, Deserialize)]
pub struct AiDelegationEvent {
    pub delegator: Did,
    pub delegatee: Did,
    /// The model identifier — may be redacted in compliance reports.
    pub model_id: String,
    pub granted_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub depth: usize,
    pub authority_chain_root: Did,
    pub authority_chain_leaf: Did,
    pub authority_chain_depth: usize,
    pub authority_chain_hash: [u8; 32],
    pub authority_link_hash: [u8; 32],
}

impl fmt::Debug for AiDelegationEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiDelegationEvent")
            .field("delegator", &DEBUG_REDACTED)
            .field("delegatee", &DEBUG_REDACTED)
            .field("model_id", &DEBUG_REDACTED)
            .field("granted_at", &self.granted_at)
            .field("expires_at", &self.expires_at)
            .field("depth", &self.depth)
            .field("authority_chain_root", &DEBUG_REDACTED)
            .field("authority_chain_leaf", &DEBUG_REDACTED)
            .field("authority_chain_depth", &self.authority_chain_depth)
            .field("authority_chain_hash", &self.authority_chain_hash)
            .field("authority_link_hash", &self.authority_link_hash)
            .finish()
    }
}

/// Verified AI delegation artifact that can only be created by authority-chain
/// verification through [`verify_ai_delegation_grant`].
#[derive(Debug, Clone)]
pub struct VerifiedAiDelegationGrant {
    event: AiDelegationEvent,
}

impl VerifiedAiDelegationGrant {
    /// Return the serializable event evidence captured after verification.
    #[must_use]
    pub fn event(&self) -> &AiDelegationEvent {
        &self.event
    }
}

/// Summary of a verified AI agent delegation revocation.
#[derive(Clone, Serialize, Deserialize)]
pub struct AiDelegationRevocationEvent {
    pub delegator: Did,
    pub delegatee: Did,
    /// The model identifier — may be redacted in compliance reports.
    pub model_id: String,
    pub granted_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Timestamp,
    pub revoker: Did,
    pub depth: usize,
    pub authority_chain_root: Did,
    pub authority_chain_leaf: Did,
    pub authority_chain_depth: usize,
    pub authority_chain_hash: [u8; 32],
    pub authority_link_hash: [u8; 32],
    pub revocation_hash: [u8; 32],
}

impl fmt::Debug for AiDelegationRevocationEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiDelegationRevocationEvent")
            .field("delegator", &DEBUG_REDACTED)
            .field("delegatee", &DEBUG_REDACTED)
            .field("model_id", &DEBUG_REDACTED)
            .field("granted_at", &self.granted_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .field("revoker", &DEBUG_REDACTED)
            .field("depth", &self.depth)
            .field("authority_chain_root", &DEBUG_REDACTED)
            .field("authority_chain_leaf", &DEBUG_REDACTED)
            .field("authority_chain_depth", &self.authority_chain_depth)
            .field("authority_chain_hash", &self.authority_chain_hash)
            .field("authority_link_hash", &self.authority_link_hash)
            .field("revocation_hash", &self.revocation_hash)
            .finish()
    }
}

/// Verified AI delegation revocation artifact that can only be created by
/// authority-chain and signed-revocation verification through
/// [`verify_ai_delegation_revocation`].
#[derive(Debug, Clone)]
pub struct VerifiedAiDelegationRevocation {
    event: AiDelegationRevocationEvent,
}

impl VerifiedAiDelegationRevocation {
    /// Return the serializable event evidence captured after verification.
    #[must_use]
    pub fn event(&self) -> &AiDelegationRevocationEvent {
        &self.event
    }
}

/// Per-rule MCP enforcement outcome summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOutcomeSummary {
    pub rule: String,
    pub allowed: u64,
    pub blocked: u64,
    pub escalated: u64,
}

/// A structured AI transparency report for a single tenant and time period.
///
/// Satisfies EU AI Act Article 13 (transparency) and provides the record
/// required by GDPR Article 22(4) for automated decision-making with
/// significant effects.
#[derive(Clone, Serialize, Deserialize)]
pub struct AiTransparencyReport {
    pub tenant_id: Did,
    pub period_start: Timestamp,
    pub period_end: Timestamp,
    /// Governance regime under which this report was generated.
    /// e.g. "EU-AI-ACT", "NIST-AI-RMF", "CCPA"
    pub legal_jurisdiction: String,
    /// Total number of actions performed by AI agents during the period.
    pub ai_agent_action_count: u64,
    /// Verified AI delegation grants recorded during the period.
    pub ai_delegation_grants: Vec<AiDelegationEvent>,
    /// Verified AI delegation revocations recorded during the period.
    pub ai_delegation_revocations: Vec<AiDelegationRevocationEvent>,
    /// Per-rule breakdown of MCP enforcement outcomes.
    pub mcp_rule_outcomes: Vec<McpOutcomeSummary>,
    /// Head hash of the MCP audit log after full-chain verification.
    pub mcp_audit_head_hash: [u8; 32],
    /// Verified report-generation authority evidence.
    pub authority_clearance: AuthorityClearanceEvidence,
}

impl fmt::Debug for AiTransparencyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiTransparencyReport")
            .field("tenant_id", &DEBUG_REDACTED)
            .field("period_start", &self.period_start)
            .field("period_end", &self.period_end)
            .field("legal_jurisdiction", &self.legal_jurisdiction)
            .field("ai_agent_action_count", &self.ai_agent_action_count)
            .field("ai_delegation_grants", &self.ai_delegation_grants)
            .field("ai_delegation_revocations", &self.ai_delegation_revocations)
            .field("mcp_rule_outcomes", &self.mcp_rule_outcomes)
            .field("mcp_audit_head_hash", &self.mcp_audit_head_hash)
            .field("authority_clearance", &self.authority_clearance)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

/// Generate an AI transparency report for the given tenant and time period.
/// Parameters for [`generate_report`].
pub struct ReportParams<'a> {
    pub tenant_id: &'a Did,
    pub period_start: Timestamp,
    pub period_end: Timestamp,
    pub legal_jurisdiction: &'a str,
    pub mcp_log: &'a McpAuditLog,
    /// Verified AI delegation grants admitted through signed authority chains.
    pub ai_delegation_grants: Vec<VerifiedAiDelegationGrant>,
    /// Verified AI delegation revocations admitted through signed revocation artifacts.
    pub ai_delegation_revocations: Vec<VerifiedAiDelegationRevocation>,
    /// Verified authority-chain clearance for the actor generating the report.
    pub authority_clearance: &'a VerifiedAuthorityClearance,
}

/// Generate an AI transparency report for the given tenant and time period.
///
/// # Clearance requirement
///
/// `params.authority_clearance` must be created by
/// [`verify_authority_clearance`], which performs real authority-chain
/// verification and binds the resulting chain evidence into the report.
///
/// # Errors
///
/// - [`LegalError::InvalidStateTransition`] if the MCP audit chain is broken,
///   the report action count cannot be represented, or the audit head hash
///   cannot be computed.
pub fn generate_report(params: ReportParams<'_>) -> Result<AiTransparencyReport> {
    let ReportParams {
        tenant_id,
        period_start,
        period_end,
        legal_jurisdiction,
        mcp_log,
        ai_delegation_grants,
        ai_delegation_revocations,
        authority_clearance,
    } = params;

    verify_mcp_audit_chain(mcp_log).map_err(|e| LegalError::InvalidStateTransition {
        reason: format!("MCP audit chain verification failed before transparency report: {e}"),
    })?;

    // Count total AI agent actions from MCP audit log within period.
    let ai_agent_action_count = u64::try_from(
        mcp_log
            .records
            .iter()
            .filter(|r| r.timestamp >= period_start && r.timestamp <= period_end)
            .count(),
    )
    .map_err(|_| LegalError::InvalidStateTransition {
        reason: "AI agent action count cannot be represented in transparency report".into(),
    })?;

    // Aggregate MCP rule outcomes.
    let mcp_rule_outcomes = aggregate_mcp_outcomes(mcp_log, period_start, period_end);
    let mcp_audit_head_hash =
        mcp_log
            .head_hash()
            .map_err(|e| LegalError::InvalidStateTransition {
                reason: format!("MCP audit head hash failed before transparency report: {e}"),
            })?;

    Ok(AiTransparencyReport {
        tenant_id: tenant_id.clone(),
        period_start,
        period_end,
        legal_jurisdiction: legal_jurisdiction.to_owned(),
        ai_agent_action_count,
        ai_delegation_grants: ai_delegation_grants
            .into_iter()
            .map(|grant| grant.event().clone())
            .collect(),
        ai_delegation_revocations: ai_delegation_revocations
            .into_iter()
            .map(|revocation| revocation.event().clone())
            .collect(),
        mcp_rule_outcomes,
        mcp_audit_head_hash,
        authority_clearance: authority_clearance.evidence().clone(),
    })
}

/// Verify report-generation authority clearance and return a non-synthesizable
/// artifact for [`ReportParams`].
///
/// # Errors
///
/// Returns [`LegalError::InvalidStateTransition`] if the timestamp is zero, the
/// chain leaf is not the requester, the authority chain fails verification, or
/// the chain evidence cannot be canonicalized.
pub fn verify_authority_clearance<F>(
    requester: &Did,
    authority_chain: &AuthorityChain,
    verified_at: Timestamp,
    resolve_key: F,
) -> Result<VerifiedAuthorityClearance>
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    if verified_at == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "authority clearance verification timestamp must be non-zero".into(),
        });
    }

    let chain_root =
        authority_chain
            .root()
            .cloned()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "authority clearance chain must not be empty".into(),
            })?;
    let chain_leaf =
        authority_chain
            .leaf()
            .cloned()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "authority clearance chain must not be empty".into(),
            })?;

    if &chain_leaf != requester {
        return Err(LegalError::InvalidStateTransition {
            reason: format!(
                "authority clearance requester {} does not match chain leaf {}",
                requester.as_str(),
                chain_leaf.as_str()
            ),
        });
    }

    chain::verify_chain(authority_chain, &verified_at, resolve_key).map_err(|e| {
        LegalError::InvalidStateTransition {
            reason: format!("authority clearance chain verification failed: {e}"),
        }
    })?;

    Ok(VerifiedAuthorityClearance {
        evidence: AuthorityClearanceEvidence {
            requester: requester.clone(),
            verified_at,
            chain_root,
            chain_leaf,
            chain_depth: authority_chain.depth(),
            chain_hash: hash_authority_clearance_chain(authority_chain)?,
        },
    })
}

/// Verify an authority chain and extract an AI delegation grant from its leaf.
///
/// Returns `Ok(None)` after successful chain verification when the leaf
/// delegatee is not an AI agent. This keeps human and legacy delegations out of
/// AI transparency grant lists without trusting caller-supplied flags.
///
/// # Errors
///
/// Returns [`LegalError::InvalidStateTransition`] if the timestamp is zero, the
/// chain is empty, the chain fails signature/scope verification, or the grant
/// evidence cannot be canonicalized.
pub fn verify_ai_delegation_grant<F>(
    authority_chain: &AuthorityChain,
    verified_at: Timestamp,
    resolve_key: F,
) -> Result<Option<VerifiedAiDelegationGrant>>
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    if verified_at == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "AI delegation grant verification timestamp must be non-zero".into(),
        });
    }

    chain::verify_chain(authority_chain, &verified_at, resolve_key).map_err(|e| {
        LegalError::InvalidStateTransition {
            reason: format!("AI delegation authority chain verification failed: {e}"),
        }
    })?;

    let chain_root =
        authority_chain
            .root()
            .cloned()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "AI delegation authority chain must not be empty".into(),
            })?;
    let chain_leaf =
        authority_chain
            .leaf()
            .cloned()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "AI delegation authority chain must not be empty".into(),
            })?;
    let leaf_link =
        authority_chain
            .links
            .last()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "AI delegation authority chain must not be empty".into(),
            })?;

    let DelegateeKind::AiAgent { model_id } = &leaf_link.delegatee_kind else {
        return Ok(None);
    };

    Ok(Some(VerifiedAiDelegationGrant {
        event: AiDelegationEvent {
            delegator: leaf_link.delegator_did.clone(),
            delegatee: leaf_link.delegate_did.clone(),
            model_id: model_id.clone(),
            granted_at: leaf_link.created,
            expires_at: leaf_link.expires,
            depth: leaf_link.depth,
            authority_chain_root: chain_root,
            authority_chain_leaf: chain_leaf,
            authority_chain_depth: authority_chain.depth(),
            authority_chain_hash: hash_ai_delegation_chain(authority_chain)?,
            authority_link_hash: hash_authority_link(leaf_link)?,
        },
    }))
}

/// Verify an authority chain and signed revocation artifact, then extract an
/// AI delegation revocation from the chain leaf.
///
/// Returns `Ok(None)` after successful chain and revocation verification when
/// the revoked leaf delegatee is not an AI agent. This keeps human and legacy
/// delegation revocations out of AI transparency lists without trusting caller
/// supplied flags or counts.
///
/// # Errors
///
/// Returns [`LegalError::InvalidStateTransition`] if the verification timestamp
/// is zero, the revocation is in the future relative to verification, the
/// authority chain is empty or invalid at the revocation time, the signed
/// revocation artifact is invalid, the revocation does not bind to the chain
/// leaf, or the event evidence cannot be canonicalized.
pub fn verify_ai_delegation_revocation<F>(
    authority_chain: &AuthorityChain,
    revocation: &AuthorityRevocation,
    verified_at: Timestamp,
    resolve_key: F,
) -> Result<Option<VerifiedAiDelegationRevocation>>
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    if verified_at == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "AI delegation revocation verification timestamp must be non-zero".into(),
        });
    }
    if revocation.revoked_at > verified_at {
        return Err(LegalError::InvalidStateTransition {
            reason: "AI delegation revocation must not be in the future relative to verification"
                .into(),
        });
    }

    chain::verify_chain(authority_chain, &revocation.revoked_at, &resolve_key).map_err(|e| {
        LegalError::InvalidStateTransition {
            reason: format!("AI delegation revocation authority chain verification failed: {e}"),
        }
    })?;
    revocation
        .verify(&resolve_key)
        .map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("AI delegation revocation signature verification failed: {e}"),
        })?;

    let chain_root =
        authority_chain
            .root()
            .cloned()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "AI delegation revocation authority chain must not be empty".into(),
            })?;
    let chain_leaf =
        authority_chain
            .leaf()
            .cloned()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "AI delegation revocation authority chain must not be empty".into(),
            })?;
    let leaf_link =
        authority_chain
            .links
            .last()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "AI delegation revocation authority chain must not be empty".into(),
            })?;

    if &revocation.revoked_link != leaf_link {
        return Err(LegalError::InvalidStateTransition {
            reason: "AI delegation revocation artifact does not match authority chain leaf".into(),
        });
    }
    if revocation.revoked_link_hash
        != AuthorityLink::id(leaf_link).map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("AI delegation revocation leaf hash failed: {e}"),
        })?
    {
        return Err(LegalError::InvalidStateTransition {
            reason: "AI delegation revocation hash does not match authority chain leaf".into(),
        });
    }

    let DelegateeKind::AiAgent { model_id } = &leaf_link.delegatee_kind else {
        return Ok(None);
    };

    Ok(Some(VerifiedAiDelegationRevocation {
        event: AiDelegationRevocationEvent {
            delegator: leaf_link.delegator_did.clone(),
            delegatee: leaf_link.delegate_did.clone(),
            model_id: model_id.clone(),
            granted_at: leaf_link.created,
            expires_at: leaf_link.expires,
            revoked_at: revocation.revoked_at,
            revoker: revocation.revoker_did.clone(),
            depth: leaf_link.depth,
            authority_chain_root: chain_root,
            authority_chain_leaf: chain_leaf,
            authority_chain_depth: authority_chain.depth(),
            authority_chain_hash: hash_ai_delegation_revocation_chain(authority_chain)?,
            authority_link_hash: hash_authority_link(leaf_link)?,
            revocation_hash: hash_authority_revocation(revocation)?,
        },
    }))
}

fn aggregate_mcp_outcomes(
    log: &McpAuditLog,
    period_start: Timestamp,
    period_end: Timestamp,
) -> Vec<McpOutcomeSummary> {
    use std::collections::BTreeMap;

    let mut counts: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();

    for record in log
        .records
        .iter()
        .filter(|r| r.timestamp >= period_start && r.timestamp <= period_end)
    {
        let rule_key = record.rule.id().to_owned();
        let entry = counts.entry(rule_key).or_insert((0, 0, 0));
        match record.outcome {
            McpEnforcementOutcome::Allowed => entry.0 = entry.0.saturating_add(1),
            McpEnforcementOutcome::Blocked => entry.1 = entry.1.saturating_add(1),
            McpEnforcementOutcome::Escalated => entry.2 = entry.2.saturating_add(1),
        }
    }

    counts
        .into_iter()
        .map(|(rule, (allowed, blocked, escalated))| McpOutcomeSummary {
            rule,
            allowed,
            blocked,
            escalated,
        })
        .collect()
}

#[derive(Serialize)]
struct AuthorityClearanceHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    authority_chain: &'a AuthorityChain,
}

#[derive(Serialize)]
struct AiDelegationGrantHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    authority_chain: &'a AuthorityChain,
}

#[derive(Serialize)]
struct AiDelegationRevocationHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    authority_chain: &'a AuthorityChain,
}

fn hash_authority_clearance_chain(authority_chain: &AuthorityChain) -> Result<[u8; 32]> {
    let payload = AuthorityClearanceHashPayload {
        domain: AUTHORITY_CLEARANCE_DOMAIN,
        schema_version: AUTHORITY_CLEARANCE_SCHEMA_VERSION,
        authority_chain,
    };
    hash_structured(&payload)
        .map(|hash| *hash.as_bytes())
        .map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("authority clearance canonical CBOR hash failed: {e}"),
        })
}

fn hash_ai_delegation_chain(authority_chain: &AuthorityChain) -> Result<[u8; 32]> {
    let payload = AiDelegationGrantHashPayload {
        domain: AI_DELEGATION_GRANT_DOMAIN,
        schema_version: AI_DELEGATION_GRANT_SCHEMA_VERSION,
        authority_chain,
    };
    hash_structured(&payload)
        .map(|hash| *hash.as_bytes())
        .map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("AI delegation grant canonical CBOR hash failed: {e}"),
        })
}

fn hash_ai_delegation_revocation_chain(authority_chain: &AuthorityChain) -> Result<[u8; 32]> {
    let payload = AiDelegationRevocationHashPayload {
        domain: AI_DELEGATION_REVOCATION_DOMAIN,
        schema_version: AI_DELEGATION_REVOCATION_SCHEMA_VERSION,
        authority_chain,
    };
    hash_structured(&payload)
        .map(|hash| *hash.as_bytes())
        .map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("AI delegation revocation canonical CBOR hash failed: {e}"),
        })
}

fn hash_authority_link(link: &AuthorityLink) -> Result<[u8; 32]> {
    link.id()
        .map(|hash| *hash.as_bytes())
        .map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("AI delegation authority link hash failed: {e}"),
        })
}

fn hash_authority_revocation(revocation: &AuthorityRevocation) -> Result<[u8; 32]> {
    revocation
        .id()
        .map(|hash| *hash.as_bytes())
        .map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("AI delegation authority revocation hash failed: {e}"),
        })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_authority::{AuthorityChain, AuthorityLink, Permission};
    use exo_core::{Did, Signature, Timestamp, crypto::KeyPair};
    use exo_gatekeeper::{
        McpRule,
        mcp_audit::{McpAuditLog, McpEnforcementOutcome, append, create_record},
    };
    use uuid::Uuid;

    use super::*;

    fn did(s: &str) -> Did {
        Did::new(&format!("did:exo:{s}")).expect("valid DID")
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn audit_id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn verified_clearance(requester: &Did) -> VerifiedAuthorityClearance {
        let root = did("root-authority");
        let root_key = KeyPair::generate();
        let link =
            signed_authority_link(&root, requester, DelegateeKind::Human, &root_key, 0, None);

        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };
        verify_authority_clearance(requester, &chain, ts(2_000), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        })
        .expect("authority clearance must verify")
    }

    fn signed_authority_link(
        delegator: &Did,
        delegate: &Did,
        delegatee_kind: DelegateeKind,
        signing_key: &KeyPair,
        depth: usize,
        expires: Option<Timestamp>,
    ) -> AuthorityLink {
        let mut link = AuthorityLink {
            delegator_did: delegator.clone(),
            delegate_did: delegate.clone(),
            scope: vec![Permission::Read],
            created: ts(1_000),
            expires,
            signature: Signature::empty(),
            depth,
            delegatee_kind,
        };
        let payload = link
            .signing_payload()
            .expect("authority link signing payload");
        link.signature = signing_key.sign(&payload);
        link
    }

    fn verified_ai_grant() -> VerifiedAiDelegationGrant {
        let root = did("grant-root");
        let agent = did("agent-1");
        let root_key = KeyPair::generate();
        let link = signed_authority_link(
            &root,
            &agent,
            DelegateeKind::AiAgent {
                model_id: "claude-sonnet-4-6".into(),
            },
            &root_key,
            0,
            Some(ts(3_000)),
        );
        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };

        verify_ai_delegation_grant(&chain, ts(2_000), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        })
        .expect("AI delegation grant verification succeeds")
        .expect("AI delegation grant is present")
    }

    fn verified_ai_revocation() -> VerifiedAiDelegationRevocation {
        let root = did("revocation-root");
        let agent = did("agent-revoked");
        let root_key = KeyPair::generate();
        let link = signed_authority_link(
            &root,
            &agent,
            DelegateeKind::AiAgent {
                model_id: "claude-sonnet-4-6-revoked".into(),
            },
            &root_key,
            0,
            Some(ts(3_000)),
        );
        let revocation = AuthorityRevocation::for_link(
            link.clone(),
            &root,
            &ts(2_000),
            root_key.public_key(),
            |payload| root_key.sign(payload),
        )
        .expect("authority revocation signs");
        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };

        verify_ai_delegation_revocation(&chain, &revocation, ts(2_500), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        })
        .expect("AI delegation revocation verification succeeds")
        .expect("AI delegation revocation is present")
    }

    fn make_log_with_records() -> McpAuditLog {
        let mut log = McpAuditLog::new();
        let r1 = create_record(
            &log,
            audit_id(0xE001),
            ts(10_000),
            McpRule::Mcp001BctsScope,
            did("agent"),
            McpEnforcementOutcome::Allowed,
            None,
        )
        .expect("deterministic MCP audit record");
        append(&mut log, r1).expect("append deterministic MCP audit record");
        let r2 = create_record(
            &log,
            audit_id(0xE002),
            ts(10_001),
            McpRule::Mcp002NoSelfEscalation,
            did("agent"),
            McpEnforcementOutcome::Blocked,
            None,
        )
        .expect("deterministic MCP audit record");
        append(&mut log, r2).expect("append deterministic MCP audit record");
        log
    }

    #[test]
    fn generate_report_rejects_tampered_mcp_audit_chain() {
        let mut log = make_log_with_records();
        log.records[1].chain_hash = [0xAA; 32];
        let tenant = did("tenant");
        let clearance = verified_clearance(&tenant);

        let result = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: vec![],
            authority_clearance: &clearance,
        });

        assert!(
            result.is_err(),
            "transparency reports must not aggregate over a broken MCP audit chain"
        );
    }

    #[test]
    fn generate_report_action_count_does_not_use_u64_max_sentinel() {
        let source = include_str!("ai_transparency.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("tests section marker present");
        let generate_report = production
            .split("pub fn generate_report")
            .nth(1)
            .expect("generate_report definition present")
            .split("// Aggregate MCP rule outcomes.")
            .next()
            .expect("generate_report action count section boundary present");

        assert!(
            !generate_report.contains("unwrap_or(u64::MAX)"),
            "AI transparency action counts must fail closed instead of emitting a u64::MAX sentinel"
        );
    }

    #[test]
    fn generate_report_source_does_not_accept_caller_supplied_clearance_boolean() {
        let source = include_str!("ai_transparency.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("tests section marker present");

        assert!(
            !production.contains("clearance_verified: bool"),
            "authority clearance must be a verified artifact, not a caller-supplied boolean"
        );
        assert!(
            !production.contains("if !clearance_verified"),
            "report generation must not trust a naked clearance boolean"
        );
    }

    #[test]
    fn generate_report_source_does_not_accept_raw_ai_delegation_event_vector() {
        let source = include_str!("ai_transparency.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("tests section marker present");
        let report_params = production
            .split("pub struct ReportParams<'a>")
            .nth(1)
            .expect("ReportParams definition present")
            .split("/// Generate an AI transparency report for the given tenant and time period.")
            .next()
            .expect("ReportParams definition boundary present");

        assert!(
            !report_params.contains("ai_delegation_grants: Vec<AiDelegationEvent>"),
            "ReportParams must require verified AI delegation grant artifacts, not raw events"
        );
    }

    #[test]
    fn generate_report_source_does_not_accept_raw_ai_delegation_revocation_count() {
        let source = include_str!("ai_transparency.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("tests section marker present");
        let report_params = production
            .split("pub struct ReportParams<'a>")
            .nth(1)
            .expect("ReportParams definition present")
            .split("/// Generate an AI transparency report for the given tenant and time period.")
            .next()
            .expect("ReportParams definition boundary present");

        assert!(
            !report_params.contains("ai_delegation_revocations: u64"),
            "ReportParams must require verified AI delegation revocation artifacts, not raw counts"
        );
    }

    #[test]
    fn aggregate_mcp_outcomes_uses_saturating_counter_arithmetic() {
        let source = include_str!("ai_transparency.rs");
        let production = match source
            .split("// ===========================================================================")
            .next()
        {
            Some(production) => production,
            None => panic!("tests section marker must be present"),
        };
        let aggregate = match production.split("fn aggregate_mcp_outcomes").nth(1) {
            Some(aggregate) => aggregate,
            None => panic!("aggregate_mcp_outcomes definition must be present"),
        };
        let aggregate = match aggregate.split("#[derive(Serialize)]").next() {
            Some(aggregate) => aggregate,
            None => panic!("aggregate_mcp_outcomes boundary must be present"),
        };

        assert!(
            aggregate.contains("saturating_add(1)"),
            "MCP outcome counters must saturate instead of overflowing"
        );
        assert!(
            !aggregate.contains("+= 1"),
            "MCP outcome counters must not use direct += arithmetic"
        );
        assert!(
            !aggregate.contains("format!(\"{:?}\", record.rule)"),
            "MCP outcome report keys must use stable rule IDs instead of Rust Debug output"
        );
        assert!(
            aggregate.contains("record.rule.id()"),
            "MCP outcome aggregation must bind reports to explicit stable rule identifiers"
        );
    }

    #[test]
    fn ai_delegation_event_debug_redacts_model_and_identity_fields() {
        let event = AiDelegationEvent {
            delegator: did("sensitive-delegator"),
            delegatee: did("sensitive-agent"),
            model_id: "sensitive-model-v2".into(),
            granted_at: ts(1_000),
            expires_at: Some(ts(2_000)),
            depth: 1,
            authority_chain_root: did("sensitive-root"),
            authority_chain_leaf: did("sensitive-leaf"),
            authority_chain_depth: 2,
            authority_chain_hash: [0xA1; 32],
            authority_link_hash: [0xB2; 32],
        };

        let debug = format!("{event:?}");

        for leaked in [
            "sensitive-model-v2",
            "did:exo:sensitive-delegator",
            "did:exo:sensitive-agent",
            "did:exo:sensitive-root",
            "did:exo:sensitive-leaf",
        ] {
            assert!(
                !debug.contains(leaked),
                "Debug output must redact sensitive value {leaked}"
            );
        }
        assert!(
            debug.contains("<redacted>"),
            "Debug output must make redaction explicit"
        );
    }

    #[test]
    fn ai_transparency_report_debug_redacts_nested_model_and_identity_fields() {
        let tenant = did("sensitive-tenant");
        let report = AiTransparencyReport {
            tenant_id: tenant,
            period_start: ts(1_000),
            period_end: ts(2_000),
            legal_jurisdiction: "EU-AI-ACT".into(),
            ai_agent_action_count: 1,
            ai_delegation_grants: vec![AiDelegationEvent {
                delegator: did("report-sensitive-delegator"),
                delegatee: did("report-sensitive-agent"),
                model_id: "report-sensitive-model".into(),
                granted_at: ts(1_100),
                expires_at: None,
                depth: 1,
                authority_chain_root: did("report-sensitive-root"),
                authority_chain_leaf: did("report-sensitive-leaf"),
                authority_chain_depth: 2,
                authority_chain_hash: [0xC3; 32],
                authority_link_hash: [0xD4; 32],
            }],
            ai_delegation_revocations: vec![AiDelegationRevocationEvent {
                delegator: did("revocation-sensitive-delegator"),
                delegatee: did("revocation-sensitive-agent"),
                model_id: "revocation-sensitive-model".into(),
                granted_at: ts(1_100),
                expires_at: None,
                revoked_at: ts(1_500),
                revoker: did("revocation-sensitive-revoker"),
                depth: 1,
                authority_chain_root: did("revocation-sensitive-root"),
                authority_chain_leaf: did("revocation-sensitive-leaf"),
                authority_chain_depth: 2,
                authority_chain_hash: [0xE5; 32],
                authority_link_hash: [0xF6; 32],
                revocation_hash: [0x07; 32],
            }],
            mcp_rule_outcomes: vec![],
            mcp_audit_head_hash: [0x18; 32],
            authority_clearance: AuthorityClearanceEvidence {
                requester: did("clearance-sensitive-requester"),
                verified_at: ts(1_200),
                chain_root: did("clearance-sensitive-root"),
                chain_leaf: did("clearance-sensitive-leaf"),
                chain_depth: 2,
                chain_hash: [0x29; 32],
            },
        };

        let debug = format!("{report:?}");

        for leaked in [
            "did:exo:sensitive-tenant",
            "report-sensitive-model",
            "did:exo:report-sensitive-delegator",
            "did:exo:report-sensitive-agent",
            "revocation-sensitive-model",
            "did:exo:revocation-sensitive-revoker",
            "did:exo:clearance-sensitive-requester",
        ] {
            assert!(
                !debug.contains(leaked),
                "report Debug output must redact sensitive value {leaked}"
            );
        }
        assert!(
            debug.contains("<redacted>"),
            "report Debug output must make redaction explicit"
        );
    }

    #[test]
    fn verify_authority_clearance_requires_requester_to_match_chain_leaf() {
        let root = did("root-authority");
        let requester = did("reporter");
        let other = did("other");
        let root_key = KeyPair::generate();
        let mut link = AuthorityLink {
            delegator_did: root.clone(),
            delegate_did: other,
            scope: vec![Permission::Read],
            created: ts(1_000),
            expires: None,
            signature: Signature::empty(),
            depth: 0,
            delegatee_kind: DelegateeKind::Human,
        };
        let payload = link
            .signing_payload()
            .expect("authority link signing payload");
        link.signature = root_key.sign(&payload);

        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };
        let result = verify_authority_clearance(&requester, &chain, ts(2_000), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        });

        assert!(result.is_err());
    }

    #[test]
    fn generate_report_with_clearance_succeeds() {
        let log = make_log_with_records();
        let tenant = did("tenant");
        let clearance = verified_clearance(&tenant);
        let report = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: vec![],
            authority_clearance: &clearance,
        })
        .expect("report generation should succeed");
        assert_eq!(report.ai_agent_action_count, 2);
        assert_eq!(report.legal_jurisdiction, "EU-AI-ACT");
        assert_eq!(report.authority_clearance.requester, tenant);
        assert_eq!(
            report.mcp_audit_head_hash,
            log.head_hash().expect("MCP audit head hash")
        );
    }

    #[test]
    fn mcp_outcomes_aggregated_correctly() {
        let log = make_log_with_records();
        let tenant = did("tenant");
        let clearance = verified_clearance(&tenant);
        let report = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "NIST-AI-RMF",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: vec![],
            authority_clearance: &clearance,
        })
        .expect("ok");
        // One Allowed for Mcp001, one Blocked for Mcp002
        let mcp001 = report
            .mcp_rule_outcomes
            .iter()
            .find(|o| o.rule == "mcp-001-bcts-scope")
            .expect("mcp-001-bcts-scope must appear");
        assert_eq!(mcp001.allowed, 1);
        assert_eq!(mcp001.blocked, 0);
        let mcp002 = report
            .mcp_rule_outcomes
            .iter()
            .find(|o| o.rule == "mcp-002-no-self-escalation")
            .expect("mcp-002-no-self-escalation must appear");
        assert_eq!(mcp002.blocked, 1);
    }

    #[test]
    fn verify_ai_delegation_grant_from_human_link_returns_none() {
        let root = did("grant-root");
        let human = did("human-bob");
        let root_key = KeyPair::generate();
        let link = signed_authority_link(&root, &human, DelegateeKind::Human, &root_key, 0, None);
        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };

        let result = verify_ai_delegation_grant(&chain, ts(2_000), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        })
        .expect("human authority chain still verifies");

        assert!(result.is_none());
    }

    #[test]
    fn verify_ai_delegation_grant_from_ai_link_returns_verified_event() {
        let grant = verified_ai_grant();
        let event = grant.event();
        assert_eq!(event.model_id, "claude-sonnet-4-6");
        assert_eq!(event.depth, 0);
        assert_eq!(event.authority_chain_root, did("grant-root"));
        assert_eq!(event.authority_chain_leaf, did("agent-1"));
        assert_eq!(event.authority_chain_depth, 1);
        assert_ne!(event.authority_chain_hash, [0u8; 32]);
        assert_ne!(event.authority_link_hash, [0u8; 32]);
    }

    #[test]
    fn verify_ai_delegation_grant_rejects_tampered_signature() {
        let root = did("grant-root");
        let agent = did("agent-1");
        let root_key = KeyPair::generate();
        let mut link = signed_authority_link(
            &root,
            &agent,
            DelegateeKind::AiAgent {
                model_id: "claude-sonnet-4-6".into(),
            },
            &root_key,
            0,
            None,
        );
        link.signature = Signature::from_bytes([0xA5; 64]);
        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };

        let result = verify_ai_delegation_grant(&chain, ts(2_000), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        });

        assert!(result.is_err());
    }

    #[test]
    fn verify_ai_delegation_revocation_from_ai_link_returns_verified_event() {
        let revocation = verified_ai_revocation();
        let event = revocation.event();
        assert_eq!(event.model_id, "claude-sonnet-4-6-revoked");
        assert_eq!(event.depth, 0);
        assert_eq!(event.revoked_at, ts(2_000));
        assert_eq!(event.revoker, did("revocation-root"));
        assert_eq!(event.authority_chain_root, did("revocation-root"));
        assert_eq!(event.authority_chain_leaf, did("agent-revoked"));
        assert_eq!(event.authority_chain_depth, 1);
        assert_ne!(event.authority_chain_hash, [0u8; 32]);
        assert_ne!(event.authority_link_hash, [0u8; 32]);
        assert_ne!(event.revocation_hash, [0u8; 32]);
    }

    #[test]
    fn verify_ai_delegation_revocation_from_human_link_returns_none() {
        let root = did("human-revocation-root");
        let human = did("human-revoked");
        let root_key = KeyPair::generate();
        let link = signed_authority_link(
            &root,
            &human,
            DelegateeKind::Human,
            &root_key,
            0,
            Some(ts(3_000)),
        );
        let revocation = AuthorityRevocation::for_link(
            link.clone(),
            &root,
            &ts(2_000),
            root_key.public_key(),
            |payload| root_key.sign(payload),
        )
        .expect("authority revocation signs");
        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };

        let result = verify_ai_delegation_revocation(&chain, &revocation, ts(2_500), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        })
        .expect("human revocation authority chain still verifies");

        assert!(result.is_none());
    }

    #[test]
    fn verify_ai_delegation_revocation_rejects_tampered_signature() {
        let root = did("tampered-revocation-root");
        let agent = did("tampered-agent");
        let root_key = KeyPair::generate();
        let wrong_key = KeyPair::generate();
        let link = signed_authority_link(
            &root,
            &agent,
            DelegateeKind::AiAgent {
                model_id: "tampered-model".into(),
            },
            &root_key,
            0,
            Some(ts(3_000)),
        );
        let mut revocation = AuthorityRevocation::for_link(
            link.clone(),
            &root,
            &ts(2_000),
            root_key.public_key(),
            |payload| root_key.sign(payload),
        )
        .expect("authority revocation signs");
        let payload = revocation
            .signing_payload()
            .expect("revocation signing payload");
        revocation.signature = wrong_key.sign(&payload);
        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };

        let result = verify_ai_delegation_revocation(&chain, &revocation, ts(2_500), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        });

        assert!(result.is_err());
    }

    #[test]
    fn generate_report_with_verified_ai_delegation_grant_succeeds() {
        let log = McpAuditLog::new();
        let tenant = did("tenant");
        let clearance = verified_clearance(&tenant);
        let grant = verified_ai_grant();
        let expected_chain_hash = grant.event().authority_chain_hash;

        let report = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![grant],
            ai_delegation_revocations: vec![],
            authority_clearance: &clearance,
        })
        .expect("verified AI delegation grant should be accepted");

        assert_eq!(report.ai_delegation_grants.len(), 1);
        assert_eq!(
            report.ai_delegation_grants[0].authority_chain_hash,
            expected_chain_hash
        );
    }

    #[test]
    fn generate_report_with_verified_ai_delegation_revocation_succeeds() {
        let log = McpAuditLog::new();
        let tenant = did("tenant");
        let clearance = verified_clearance(&tenant);
        let revocation = verified_ai_revocation();
        let expected_revocation_hash = revocation.event().revocation_hash;

        let report = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: vec![revocation],
            authority_clearance: &clearance,
        })
        .expect("verified AI delegation revocation should be accepted");

        assert_eq!(report.ai_delegation_revocations.len(), 1);
        assert_eq!(
            report.ai_delegation_revocations[0].revocation_hash,
            expected_revocation_hash
        );
    }

    #[test]
    fn period_filtering_applies() {
        let mut log = McpAuditLog::new();
        // MCP audit records use caller-supplied HLC timestamps beyond this report window.
        let r = create_record(
            &log,
            audit_id(0xE003),
            ts(500),
            McpRule::Mcp001BctsScope,
            did("agent"),
            McpEnforcementOutcome::Allowed,
            None,
        )
        .expect("deterministic MCP audit record");
        append(&mut log, r).expect("append deterministic MCP audit record");

        // Period that excludes the record (past epoch)
        let tenant = did("tenant");
        let clearance = verified_clearance(&tenant);
        let report = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(1), // very narrow window in the past
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: vec![],
            authority_clearance: &clearance,
        })
        .expect("ok");
        // Record's timestamp from now_utc() will not fall in [0, 1ms]
        assert_eq!(report.ai_agent_action_count, 0);
    }
}

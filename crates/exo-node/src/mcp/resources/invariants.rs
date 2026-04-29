//! `exochain://invariants` — the 8 constitutional invariants as JSON.

use exo_gatekeeper::invariants::ConstitutionalInvariant;
use serde_json::Value;

use crate::mcp::{
    context::NodeContext,
    protocol::{ResourceContent, ResourceDefinition},
};

/// Build the resource definition.
#[must_use]
pub fn definition() -> ResourceDefinition {
    ResourceDefinition {
        uri: "exochain://invariants".into(),
        name: "Constitutional Invariants".into(),
        description: Some(
            "The 8 constitutional invariants enforced by the CGR Kernel on every \
             action. Returned as a JSON object with a `count` field and an \
             `invariants` array containing index, name, and description for each."
                .into(),
        ),
        mime_type: Some("application/json".into()),
    }
}

/// Canonical stable name for a `ConstitutionalInvariant`.
pub(crate) fn name(inv: &ConstitutionalInvariant) -> &'static str {
    match inv {
        ConstitutionalInvariant::SeparationOfPowers => "SeparationOfPowers",
        ConstitutionalInvariant::ConsentRequired => "ConsentRequired",
        ConstitutionalInvariant::NoSelfGrant => "NoSelfGrant",
        ConstitutionalInvariant::HumanOverride => "HumanOverride",
        ConstitutionalInvariant::KernelImmutability => "KernelImmutability",
        ConstitutionalInvariant::AuthorityChainValid => "AuthorityChainValid",
        ConstitutionalInvariant::QuorumLegitimate => "QuorumLegitimate",
        ConstitutionalInvariant::ProvenanceVerifiable => "ProvenanceVerifiable",
    }
}

/// Human-readable description for a `ConstitutionalInvariant`.
pub(crate) fn description(inv: &ConstitutionalInvariant) -> &'static str {
    match inv {
        ConstitutionalInvariant::SeparationOfPowers => {
            "No single actor may hold legislative + executive + judicial power \
             simultaneously. Roles must be split across government branches to \
             prevent unilateral consolidation of authority."
        }
        ConstitutionalInvariant::ConsentRequired => {
            "No action proceeds without an active bailment consent record linking \
             the actor to the resource being acted on. Consent may be revoked at \
             any time, immediately terminating derived authority."
        }
        ConstitutionalInvariant::NoSelfGrant => {
            "An actor cannot expand its own permissions. Any permission grant \
             must originate from a party that already holds that permission and \
             whose authority chain is independently valid."
        }
        ConstitutionalInvariant::HumanOverride => {
            "Emergency human intervention must always be possible. No automated \
             policy, smart contract, or AI rule may disable the human override \
             path — if it does, the kernel denies the action."
        }
        ConstitutionalInvariant::KernelImmutability => {
            "The kernel's constitution and invariant set cannot be modified after \
             creation. Amendments flow through a separate proposal process that \
             produces a new kernel; the existing kernel stays byte-for-byte stable."
        }
        ConstitutionalInvariant::AuthorityChainValid => {
            "Every authority chain from the root of trust down to the actor must \
             be cryptographically valid, unbroken, and carry permissions sufficient \
             to support the requested action."
        }
        ConstitutionalInvariant::QuorumLegitimate => {
            "Decisions that require a quorum must present evidence meeting the \
             declared threshold (typically 2/3 of validators) and the evidence \
             itself must be verifiable against the committed validator set."
        }
        ConstitutionalInvariant::ProvenanceVerifiable => {
            "Every action must carry a provenance record — actor DID, timestamp, \
             action hash, and signature — that can be independently verified. \
             Missing or unverifiable provenance triggers denial."
        }
    }
}

/// Build the pretty-printed JSON payload for the 8 invariants.
pub(crate) fn build_payload() -> Value {
    let invariants: Vec<Value> = [
        ConstitutionalInvariant::SeparationOfPowers,
        ConstitutionalInvariant::ConsentRequired,
        ConstitutionalInvariant::NoSelfGrant,
        ConstitutionalInvariant::HumanOverride,
        ConstitutionalInvariant::KernelImmutability,
        ConstitutionalInvariant::AuthorityChainValid,
        ConstitutionalInvariant::QuorumLegitimate,
        ConstitutionalInvariant::ProvenanceVerifiable,
    ]
    .iter()
    .enumerate()
    .map(|(i, inv)| {
        serde_json::json!({
            "index": i + 1,
            "name": name(inv),
            "description": description(inv),
        })
    })
    .collect();

    serde_json::json!({
        "count": invariants.len(),
        "invariants": invariants,
    })
}

/// Read the resource contents.
#[must_use]
pub fn read(_context: &NodeContext) -> ResourceContent {
    let payload = build_payload();
    ResourceContent::json("exochain://invariants", &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_has_uri() {
        let def = definition();
        assert_eq!(def.uri, "exochain://invariants");
        assert_eq!(def.mime_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn read_returns_8_invariants() {
        let content = read(&NodeContext::empty());
        let text = content.text.expect("text present");
        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(parsed["count"], 8);
        let invariants = parsed["invariants"].as_array().expect("array");
        assert_eq!(invariants.len(), 8);
        assert_eq!(invariants[0]["name"], "SeparationOfPowers");
        assert_eq!(invariants[7]["name"], "ProvenanceVerifiable");
    }

    #[test]
    fn every_invariant_has_description() {
        let payload = build_payload();
        for inv in payload["invariants"].as_array().unwrap() {
            let desc = inv["description"].as_str().unwrap();
            assert!(!desc.is_empty());
        }
    }
}

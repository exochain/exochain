//! `constitutional_audit` — audit a system state against the 8 invariants.

use std::collections::BTreeMap;

use crate::mcp::protocol::{
    PromptArgument, PromptContent, PromptDefinition, PromptMessage, PromptResult,
};

/// Build the prompt definition.
#[must_use]
pub fn definition() -> PromptDefinition {
    PromptDefinition {
        name: "constitutional_audit".into(),
        description: "Audit a system state or point-in-time snapshot against \
                      all 8 constitutional invariants. Produces a detailed \
                      per-invariant report with evidence and a remediation \
                      plan for any failing checks."
            .into(),
        arguments: vec![
            PromptArgument {
                name: "scope".into(),
                description: Some(
                    "Scope of the audit — 'node', 'tenant:<id>', 'case:<id>', or 'full'.".into(),
                ),
                required: true,
            },
            PromptArgument {
                name: "timestamp".into(),
                description: Some("ISO-8601 timestamp for the point-in-time snapshot.".into()),
                required: false,
            },
            PromptArgument {
                name: "auditor_did".into(),
                description: Some("DID of the auditor running the review.".into()),
                required: false,
            },
            PromptArgument {
                name: "focus".into(),
                description: Some(
                    "Optional focus area — e.g. 'consent', 'authority', 'quorum'.".into(),
                ),
                required: false,
            },
        ],
    }
}

/// Build the filled-in prompt result.
#[must_use]
pub fn get(args: &BTreeMap<String, String>) -> PromptResult {
    let scope = args
        .get("scope")
        .cloned()
        .unwrap_or_else(|| "<scope>".into());
    let timestamp = args
        .get("timestamp")
        .cloned()
        .unwrap_or_else(|| "<latest>".into());
    let auditor_did = args
        .get("auditor_did")
        .cloned()
        .unwrap_or_else(|| "<unknown>".into());
    let focus = args
        .get("focus")
        .cloned()
        .unwrap_or_else(|| "all 8 invariants".into());

    let user_text = format!(
        r#"You are conducting a constitutional audit of the EXOCHAIN fabric.

Scope: {scope}
Snapshot timestamp: {timestamp}
Auditor DID: {auditor_did}
Focus: {focus}

Load the kernel context before auditing:
- `exochain_node_status` — consensus round, height, validator set
- `exochain_list_invariants` — canonical invariant list
- `exochain_get_checkpoint` at the cited timestamp (or latest)
- `exochain_list_bailments` for the scope; if it returns
  `mcp_consent_registry_unavailable`, record that no live consent registry was
  available for the audit
- Read resource `exochain://constitution` and BLAKE3-hash it to confirm
  the kernel hash matches the current binary

Then audit each of the 8 invariants in this exact order, with this
structure per invariant:

**1. SeparationOfPowers**
- Status: PASS / WARN / FAIL
- Evidence: concrete tool output or ledger entries
- Impact if FAIL: which actors hold conflicting branches, severity

**2. ConsentRequired**
- Status: PASS / WARN / FAIL
- Evidence: active bailment count, any dangling revoked records
- Impact if FAIL: list actions that executed post-revocation

**3. NoSelfGrant**
- Status: PASS / WARN / FAIL
- Evidence: any delegation where grantor == grantee or chain cycles
- Impact if FAIL: affected permissions

**4. HumanOverride**
- Status: PASS / WARN / FAIL
- Evidence: presence of override path, test invocation result
- Impact if FAIL: list automated policies that bypass human veto

**5. KernelImmutability**
- Status: PASS / WARN / FAIL
- Evidence: constitution hash match, any attempted kernel modifications
- Impact if FAIL: which fields diverged, since when

**6. AuthorityChainValid**
- Status: PASS / WARN / FAIL
- Evidence: sampled chains from recent actions, verification results
- Impact if FAIL: broken chains, orphaned permissions

**7. QuorumLegitimate**
- Status: PASS / WARN / FAIL
- Evidence: recent decisions that claimed quorum, threshold check
- Impact if FAIL: decisions that committed without sufficient votes

**8. ProvenanceVerifiable**
- Status: PASS / WARN / FAIL
- Evidence: sampled actions from the audit window, missing-provenance count
- Impact if FAIL: affected actions, remediation path

### Overall audit verdict

- GREEN — every invariant PASS
- YELLOW — at least one WARN, no FAIL
- RED — one or more FAIL; governance escalation required

### Remediation plan

For every WARN or FAIL, list the concrete MCP tool calls or governance
actions required to restore the invariant.

### Report provenance

Finish with your auditor DID, timestamp of audit execution, and the
BLAKE3 hash of this report's canonical JSON form. File the report via
`exochain_submit_event` so future audits can cross-reference it."#
    );

    PromptResult {
        description: Some(format!(
            "Constitutional audit of scope '{scope}' at {timestamp}"
        )),
        messages: vec![PromptMessage {
            role: "user".into(),
            content: PromptContent::Text { text: user_text },
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_requires_scope() {
        let def = definition();
        assert_eq!(def.name, "constitutional_audit");
        let scope_arg = def.arguments.iter().find(|a| a.name == "scope").unwrap();
        assert!(scope_arg.required);
    }

    #[test]
    fn get_fills_scope() {
        let mut args = BTreeMap::new();
        args.insert("scope".into(), "tenant:acme".into());
        let result = get(&args);
        let text = result.messages[0].content.text();
        assert!(text.contains("tenant:acme"));
    }
}

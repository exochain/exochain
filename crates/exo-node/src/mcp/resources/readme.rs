//! `exochain://readme` — quick-reference guide for AI agents.

use crate::mcp::{
    context::NodeContext,
    protocol::{ResourceContent, ResourceDefinition},
};

/// Markdown quick-reference returned by the readme resource.
pub const README_TEXT: &str = r#"# EXOCHAIN MCP Server — AI Agent Quick Reference

You are talking to the embedded MCP server of an EXOCHAIN node. Every tool
call you make is **constitutionally adjudicated** — the server enforces 6
MCP rules and 8 kernel invariants on every action. Read this document first.

## 1. How to authenticate

- The server is bound to a specific actor DID on startup (`exochain mcp --actor-did did:exo:...`).
- You do not re-authenticate per call. Instead, every tool invocation carries:
  - Your actor DID
  - A cryptographic `SignerType::Ai { delegation_id }` stamp (0x02 prefix)
  - Provenance metadata (action hash, timestamp, signature)
- The middleware rejects actions that attempt to present an AI signer as a
  human signer — the `SignerType` is part of the signed payload, not a flag.
- Read `exochain://constitution` to see the root-of-trust text, and hash it
  with BLAKE3 to verify the kernel hash independently.

## 2. Tool domains (40 tools)

- **node (3)** — `exochain_node_status`, `exochain_list_invariants`,
  `exochain_list_mcp_rules`. Start here.
- **identity (5)** — Create/resolve DIDs, verify signatures, pull agent
  passports, run a basic risk score.
- **consent (4)** — Propose bailments, check consent, list active bailments,
  terminate consent. `ConsentRequired` (invariant #2) means nothing works
  without active consent.
- **governance (5)** — Create decisions, cast votes, check quorum, inspect
  status, propose amendments. These tools refuse by default unless
  `unaudited-mcp-simulation-tools` is enabled, because they are not wired to
  the live governance store/reactor yet.
- **authority (4)** — Delegate authority, verify chains, check permissions,
  run kernel adjudication. `AuthorityChainValid` (invariant #6) is checked
  here.
- **ledger (4)** — Submit events to the DAG, read events, verify inclusion,
  fetch checkpoints.
- **proofs (4)** — Create/verify evidence bundles, chain-of-custody checks,
  Merkle proofs, CGR proofs.
- **legal (4)** — eDiscovery search, privilege assertion, safe-harbor
  initiation, fiduciary-duty checks. These tools refuse by default unless
  `unaudited-mcp-simulation-tools` is enabled, because they are not wired to
  a live legal/evidence store yet.
- **escalation (4)** — Threat evaluation, case escalation, triage,
  feedback recording.
- **messaging (3)** — Encrypted send/receive, death-trigger configuration.

For the full list with parameter counts call `resources/read`
on `exochain://tools`.

## 3. Constitutional constraints you must respect

The kernel enforces 8 invariants on **every** action. Read
`exochain://invariants` for the full list. The highlights:

1. **Separation of Powers** — You cannot hold legislative + executive +
   judicial roles at once. MCP agents are assigned the `Judicial` branch.
2. **Consent Required** — No active bailment → denial. Always check
   `exochain_check_consent` before acting on a resource.
3. **No Self-Grant** — You cannot widen your own permissions. Delegation
   must come from an authority chain rooted in a human signer.
4. **Human Override** — Your actions must remain reversible by a human
   operator. Never configure a path that disables override.
5. **Kernel Immutability** — The kernel's constitution is immutable.
   Amendments produce a *new* kernel; they never rewrite the current one.
6. **Authority Chain Valid** — Every action needs a cryptographically
   valid chain from root to actor.
7. **Quorum Legitimate** — Consensus decisions must meet the 2/3 threshold
   with verifiable evidence.
8. **Provenance Verifiable** — Every action emits a provenance record.

## 4. MCP rule summary

Read `exochain://mcp-rules` for the authoritative list. In short:

| ID       | Rule                         | Failure mode                     |
|----------|------------------------------|----------------------------------|
| MCP-001  | BCTS scope required          | No scope → denied                |
| MCP-002  | No self-escalation           | Widening own perms → denied      |
| MCP-003  | Provenance required          | Missing metadata → denied        |
| MCP-004  | No identity forge            | Signer-type mismatch → denied    |
| MCP-005  | AI outputs distinguishable   | Unmarked output → denied         |
| MCP-006  | Consent boundaries           | Revoked scope → denied           |

## 5. Working patterns

- **Always call `exochain_node_status` first** — this tells you whether
  you're talking to a live consensus node or a standalone stdio session.
- **Before any write-like action**, call `exochain_check_consent` and
  `exochain_verify_authority_chain` on the actor. If either fails, stop.
- **For reviews and audits**, use the prompts `governance_review`,
  `compliance_check`, `evidence_analysis`, `constitutional_audit` via
  `prompts/get`. They hand you a structured template filled with your
  arguments.
- **For every escalation**, call `exochain_escalate_case` with a clear
  reason. Never attempt self-escalation (MCP-002).

## 6. Errors are structured

Tool errors return `{ "is_error": true, "content": [{ "text": "..." }] }`.
Adjudication failures are surfaced as `Constitutional enforcement failed:
<reason>` so you can distinguish protocol errors from governance denials.

## 7. Further reading

- `exochain://constitution` — root-of-trust text
- `exochain://invariants` — 8 constitutional invariants (JSON)
- `exochain://mcp-rules` — 6 MCP enforcement rules (JSON)
- `exochain://node/status` — live node status snapshot (JSON)
- `exochain://tools` — all 40 tool definitions (JSON)

Stay inside your BCTS scope. Never forge identity. When in doubt,
escalate to a human operator via `exochain_escalate_case`.
"#;

/// Build the resource definition.
#[must_use]
pub fn definition() -> ResourceDefinition {
    ResourceDefinition {
        uri: "exochain://readme".into(),
        name: "AI Agent Quick-Reference".into(),
        description: Some(
            "Markdown quick-reference for AI agents connecting to this MCP \
             server: authentication model, tool-domain overview, constitutional \
             constraints, MCP rule summary, and recommended working patterns."
                .into(),
        ),
        mime_type: Some("text/markdown".into()),
    }
}

/// Read the resource contents.
#[must_use]
pub fn read(_context: &NodeContext) -> ResourceContent {
    ResourceContent {
        uri: "exochain://readme".into(),
        mime_type: Some("text/markdown".into()),
        text: Some(README_TEXT.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_has_uri() {
        let def = definition();
        assert_eq!(def.uri, "exochain://readme");
        assert_eq!(def.mime_type.as_deref(), Some("text/markdown"));
    }

    #[test]
    fn read_returns_non_empty_markdown() {
        let content = read(&NodeContext::empty());
        let text = content.text.expect("text present");
        assert!(text.contains("# EXOCHAIN MCP Server"));
        assert!(text.contains("exochain://constitution"));
        assert!(text.contains("MCP-001"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("live legal/evidence store"));
    }
}

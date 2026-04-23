# exoguard pilot smoke checklist

Point a stock OpenAI SDK at the exoguard facade URL — no client changes.

1. Send 5 benign prompts → all succeed; 5 DAG anchors written; 5 `Allowed` audit records.
2. Send a prompt containing a synthetic MRN → blocked with HTTP 451 + audit-record ID.
3. GraphQL `dlpRejection(id)` returns full bucket verdicts, scan findings, and policy citations.
4. Alert webhook receives the `Blocked` event within 2 s.
5. Rotate the OpenRouter key mid-session → no client-visible error.
6. Live `updateExoguardConfig` via GraphQL → next request uses new policy; the config change itself appears as an audit record.
7. Tamper with a stored `dlp_original_payloads` row → `verify_chain()` returns the first broken-link index.
8. Submit an AI-signed payload (`SignerType::Ai`) attempting to issue a human-only policy decision → blocked by Mcp004NoIdentityForge.
9. Attempt `updateExoguardConfig` without a valid operator delegation → blocked; `McpAuditRecord` tagged `domain=exoguard_ops, outcome=Blocked`.
10. Attempt `rotateOpenRouterKey` with a single operator signature → blocked by Mcp009QuorumOps; retry with two distinct signatures in-window → allowed.
11. `exo-node n0-genesis --dry-run` against empty Postgres reproduces the committed `infra/railway/n0-genesis.receipt.json` signature.
12. CI `railway-deploy` posts `deployExoguard` MCP call *before* `railway up`; resulting audit-record ID appears in the Railway deployment env.
13. Corrupt an `McpAuditRecord` row → background `verify_chain()` fires `integrity_violation` webhook within one check interval.

# Receipt Taxonomy

Status: starter taxonomy
Created: 2026-04-26

## Purpose

Receipts make actions legible to clients, CTOs, auditors, agents, and the
ExoChain trust substrate.

Each receipt should have:

- a machine-verifiable form
- a human-readable form
- evidence references
- actor and authority context
- tenant context
- risk classification

## Receipt Classes

| Class | Purpose |
|---|---|
| Identity Receipt | Actor identity created, bound, rotated, or revoked |
| Authority Receipt | Role, delegation, scope, or agent passport changed |
| Consent Receipt | Client or user consent granted, narrowed, revoked, or expired |
| Decision Receipt | Decision proposed, reviewed, approved, rejected, or amended |
| Evidence Receipt | Evidence captured, classified, linked, or sealed |
| Agent Action Receipt | Agent performed a scoped action |
| Work Product Receipt | Artifact created or changed |
| Review Receipt | Human or council review completed |
| Deployment Receipt | Environment deployment attempted, succeeded, failed, or rolled back |
| Override Receipt | Human override invoked |
| Incident Receipt | Security, reliability, or governance incident logged |
| Crosscheck Receipt | Claim checked against evidence and confidence assigned |

## Machine Form

```json
{
  "receipt_type": "agent_action",
  "receipt_version": "commandbase.receipt.v1",
  "tenant_id": "org_...",
  "workspace_id": "wrk_...",
  "actor": {
    "id": "agent_...",
    "type": "agent",
    "did": "did:exo:..."
  },
  "authority": {
    "source": "agent_passport",
    "scope": ["task:update"],
    "delegated_by": "usr_...",
    "expires_at": null
  },
  "action": {
    "verb": "created",
    "object_type": "implementation_plan",
    "object_id": "plan_..."
  },
  "risk": {
    "tier": "medium",
    "approval_required": true,
    "approval_state": "pending"
  },
  "evidence": [
    {
      "type": "document",
      "id": "ev_...",
      "hash": "..."
    }
  ],
  "timestamp": "2026-04-26T00:00:00Z",
  "signature": "..."
}
```

## Human Form

```text
On April 26, 2026, Agent X created a proposed implementation plan for Client Y
under authority delegated by CTO Z. The action was classified as medium risk,
requires CTO review, and is not approved for deployment.
```

## Receipt States

- pending: action expects a receipt, but verification is not complete
- issued: receipt exists and is stored
- verified: signature and payload match
- contested: receipt is under review
- superseded: newer receipt narrows, revokes, or replaces it
- invalid: receipt failed verification

## Product Rule

CommandBase may display and cache receipt summaries, but ExoChain should be the
source of truth for audit-critical receipts.

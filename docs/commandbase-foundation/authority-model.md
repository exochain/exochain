# Authority Model

Status: starter governance model
Created: 2026-04-26

## Operating Structure

Model AVC as a governed fractional CTO collective and AI transformation studio:

```text
Founder / Principal Governor
  -> AVC Collective
    -> Named CTOs / Operating Partners
      -> Client Portfolios
        -> Client Orgs
          -> Engagements
            -> Projects
              -> Agents / Tasks / Decisions / Evidence / Receipts
```

Do not hard-code one legal structure. Use both legal and operating entities.

## Core Entities

- ExoChain Foundation / Ecosystem: doctrine, substrate, trust fabric.
- AVC / Apex Velocity Catalysts: commercial fractional CTO and governed AI
  implementation business.
- CommandBase.ai: control plane product.
- Client organizations: customers receiving services.
- CTO members: operators with delegated authority.
- Agents: non-human actors operating under explicit authority.
- Auditors and observers: evidence reviewers.

## MVP Roles

| Role | Description | MVP |
|---|---|---|
| Founder Governor | Bob-level authority across portfolio | Yes |
| Platform Admin | Manages tenants, auth, billing, integrations | Yes |
| AVC CTO Member | Fractional CTO/operator delivering outcomes | Yes |
| Client Executive Sponsor | Reviews roadmap, decisions, risks, outcomes | Yes |
| Client Technical Owner | Reviews technical work, approvals, evidence | Yes |
| Autonomous Agent | Executes scoped tasks under authority | Yes |
| Auditor / Evidence Reviewer | Reviews receipts and evidence | Yes |
| Client Engineer | Participates in implementation | Later |
| Investor / Board Observer | Portfolio progress and governance visibility | Later |
| Public User | Public Decision Forum / Crosschecked modes | Later |

## Authority Claim Shape

Every mutating action should resolve to this shape:

```json
{
  "actor_id": "usr_or_agent_...",
  "actor_type": "human|agent|service",
  "tenant_id": "org_...",
  "workspace_id": "wrk_...",
  "authority_source": "role|delegation|decision|emergency_override",
  "authority_scope": ["task:create", "decision:propose"],
  "target_type": "task|decision|agent|receipt|evidence|deployment",
  "target_id": "object_...",
  "risk_tier": "low|medium|high|critical",
  "approval_requirement": "none|ctomember|founder|council|client",
  "evidence_refs": [],
  "receipt_expected": true
}
```

## Agent Passport

Every autonomous agent needs an agent passport:

```text
Agent ID
Name
Role
Model/provider
Runtime
Authority scope
Budget
Allowed tools
Forbidden actions
Human supervisor
Risk tier
Receipt history
Performance history
Revocation status
```

Agents cannot act outside their passport. Passport changes require human
approval and an ExoChain receipt.

## Revocation

Authority must be revocable at these levels:

- user membership
- role assignment
- delegation
- agent passport
- tool permission
- integration credential
- engagement access
- client org access

Revocation should be receipt-backed and should invalidate pending work where
the revoked authority was required.

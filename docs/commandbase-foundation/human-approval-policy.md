# Human Approval Policy

Status: starter policy
Created: 2026-04-26

## Default Posture

Start conservative. Autonomy expands only after evidence proves the system can
operate safely.

Human approval is required for anything involving authority, money, production,
client trust, sensitive data, external communication, safety, or regulated
workflows.

## Approval Gates

| Action | Approval Required |
|---|---|
| Create or modify an agent | Yes |
| Grant new authority to an agent | Yes |
| Access client data | Yes |
| Use sensitive or regulated data | Yes |
| Send client-facing communication | Yes |
| Merge to main | Yes |
| Deploy to production | Yes |
| Change auth, billing, tenant, or permissions | Yes |
| Spend over budget threshold | Yes |
| Create legal or compliance claims | Yes |
| Delete data | Yes |
| Modify receipts or evidence | Never directly allowed |
| Override governance control | Yes, escalated receipt |
| Health, safety, medical, or security recommendations | Yes |
| Change ExoChain trust, consent, authority, or receipt code | Highest level |

## Risk Tiers

Low risk:

- draft notes
- local UI copy
- internal task updates
- non-client-visible summaries

Medium risk:

- client work planning
- agent task assignment
- decision proposals
- internal evidence classification

High risk:

- client-facing deliverables
- production-impacting changes
- tenant permission changes
- material budget changes
- security-sensitive recommendations

Critical risk:

- production deploy
- deletion
- authority expansion
- legal, compliance, health, safety, or regulated claims
- ExoChain trust substrate changes

## ExoForge Authority Ladder

Phase 1 - PR only:

- may create issues
- may draft plans
- may create branches
- may open PRs
- may run tests
- may propose fixes
- may not merge
- may not deploy
- may not alter production secrets
- may not approve itself

Phase 2 - supervised merge:

- may merge only after green tests, CTO approval, receipt issuance, and rollback
  path documentation

Phase 3 - controlled deploy:

- may deploy low-risk changes only after policy check, receipt verification,
  smoke tests, canary or rollback confirmation, and environment classification

Phase 4 - continuous governed development:

- allowed only after repeated successful evidence-backed operation

## Emergency Override

Emergency override must:

- identify the human actor
- state reason and scope
- define expiry
- preserve evidence
- create an escalated receipt
- notify affected stakeholders
- create a follow-up review item

Emergency override cannot directly mutate receipts or delete evidence.

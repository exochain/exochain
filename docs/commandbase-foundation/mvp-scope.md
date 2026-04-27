# CommandBase MVP Scope

Status: starter MVP plan
Created: 2026-04-26

## Objective

Build CommandBase for Enterprise AVC first. The MVP should make the AVC
fractional CTO collective more effective at selling and delivering governed AI
implementation work.

The MVP should not attempt to become a generic autonomous business launcher.

## First Paid Offer

Governed Intelligence Accelerator, also usable as Governed Automation
Accelerator.

```text
8-12 week engagement
-> AI governance assessment
-> workflow selection
-> governed automation implementation
-> agent-assisted delivery
-> evidence and receipt layer
-> executive reporting
-> handoff or retainer
```

## MVP Screens

1. Setup AVC
2. Invite CTOs
3. Create client
4. Create engagement
5. Define governance model
6. Add agent roster
7. Create first project
8. Open decision
9. Assign agent task
10. Review output
11. Issue receipt
12. Generate weekly client brief

## MVP Capabilities

Tenant and identity:

- create portfolio, venture, customer org, workspace
- invite users
- assign roles
- bind or generate ExoChain DID in background

Engagement operations:

- create client org
- create engagement
- create project
- create goals
- create tasks
- assign CTO and agents

Governance:

- decision log
- approval requests
- evidence attachments
- receipt status
- human approval gates

Agent operations:

- agent passport
- budget
- allowed tools
- forbidden actions
- task assignment
- status and heartbeat

Reporting:

- weekly client brief
- decisions made
- work completed
- risks and blockers
- receipts issued
- budget consumed
- next actions

## Out Of Scope For MVP

- autonomous production deploys
- DID-first login UX
- public marketplace
- public Decision Forum network
- Crosschecked standalone
- VitalLock
- LiveSafe
- health or safety workflows
- regulated data workflows
- self-approving ExoForge automation

## Definition Of Done

The MVP is done when AVC can run one real engagement through CommandBase:

```text
Client created
-> engagement created
-> governance model selected
-> agent roster created
-> first decision opened
-> first agent task assigned
-> output reviewed
-> receipt issued or receipt-pending state blocks completion
-> weekly client brief generated
```

Required checks:

- unit tests
- API contract tests
- tenant isolation tests
- role and approval gate tests
- receipt verification path tests
- Playwright flow for the end-to-end MVP path
- Railway deployment smoke tests

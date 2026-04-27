# CommandBase Architecture Plan

Status: starter architecture
Created: 2026-04-26

## Product Order

Build in this order:

1. CommandBase.ai
2. Decision Forum embedded module
3. Crosschecked.ai embedded verification workflows
4. Decision.Forum standalone
5. VitalLock
6. LiveSafe

VitalLock and LiveSafe should not be first because they will likely involve
higher-risk health, safety, sensitive identity, consent, and evidence workflows.

## System Roles

```text
CommandBase
  product shell, UX, client operations, CTO workflows, agent dashboard

ExoChain
  identity, authority, consent, signed receipts, provenance, audit truth

ExoForge
  governed software development loop, PR creation, validation, deployment
  proposal

Decision Forum
  deliberation, approvals, council views, contestability

Crosschecked
  claim, evidence, panel review, confidence, receipt
```

## Tenant Model

Use this schema as the product spine:

```text
Portfolio
  -> Venture/App
    -> Customer Org
      -> Workspace
        -> Engagement
          -> Project
            -> Goal
              -> Decision
              -> Task
              -> Agent
              -> Evidence
              -> Receipt
```

Every table should be scoped to the narrowest relevant tenant boundary and
should include enough lineage to audit cross-object relationships.

## First Customer Org

Customer Zero is AVC, the fractional CTO and governed AI implementation
collective.

```text
Portfolio: ExoChain Ecosystem
Venture/App: CommandBase.ai
Customer Org: Apex Velocity Catalysts / AVC Collective
Workspace: Enterprise AVC Command Center
```

## Shared Account Strategy

User-facing identity should be neutral: ExoID or `exo.id`.

Phase 1:

- email login
- passkeys
- Google, Microsoft, GitHub OAuth
- organization invitations
- role-based access control
- ExoChain DID generated or bound silently underneath

Phase 2:

- user-visible ExoChain identity
- actor DID on receipts
- visible authority chains
- portable consent artifacts

Phase 3:

- DID-first for advanced users, auditors, governance participants, and
  cross-app identity

## Deployment Strategy

Use one portfolio Railway project for beta:

```text
Railway project: exoapps-beta
Environments:
  development
  staging
  production

Services:
  commandbase-web
  commandbase-api
  commandbase-worker
  exochain-client-gateway
  shared-auth
  postgres
  redis
```

Later split high-risk apps into dedicated production projects:

```text
commandbase-prod
decisionforum-prod
crosschecked-prod
vitallock-prod
livesafe-prod
```

Production CommandBase should use Postgres before real client data. SQLite or
embedded storage is acceptable only for local development and prototypes.

## Trust Boundary

CommandBase can store product state:

- dashboards
- workflows
- client records
- notifications
- UI state
- local drafts
- reporting views

ExoChain must verify and record:

- identity
- authority
- consent
- signed receipts
- provenance
- constitutional decisions
- audit-critical facts
- governance outcomes

CommandBase should never become the source of truth for audit-critical facts.

## First Screens

AVC command center:

- portfolio overview
- clients
- engagements
- CTOs
- agents
- decisions
- receipts
- evidence
- risks
- budgets
- deployments
- escalations

Client portal:

- current work
- decisions needing approval
- shipped value
- risks and blockers
- evidence
- receipts
- budget consumed
- next actions

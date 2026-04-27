# CommandBase Foundation Starter

Status: portable planning package
Created: 2026-04-26
Intended destination: a new `commandbase.ai` product repository

## Purpose

This folder is a starter package for standing up CommandBase as the first
operating business powered by ExoChain.

The intended direction is:

- CommandBase is the first operating business and product control plane.
- ExoChain is the trust substrate.
- ExoForge is the governed build engine.
- Decision Forum is the governance and deliberation layer.
- Crosschecked is the verification and evidence product.
- VitalLock and LiveSafe come later after identity, consent, health, safety,
  and evidence workflows are hardened.

## Recommended Repo Shape

CommandBase should be a separate product monorepo seeded from a clean Paperclip
fork, with upstream mergeability preserved. It should not live permanently
inside `exochain/exochain`.

```text
commandbase/
  AGENTS.md
  apps/
    web/
    api/
    worker/
  packages/
    exochain-client/
    tenant/
    auth/
    ui/
    brand-config/
    receipts/
    decision-forum/
  upstream/
    paperclip-compat/
  docs/
    architecture/
    governance/
    execution-ledger/
    product/
```

Keep the trust boundary explicit:

- `exochain/exochain`: constitutional trust fabric, identity, consent,
  authority, signed receipts, provenance, audit-critical facts.
- `commandbase.ai`: product workflows, client portal, CTO operations, agent
  roster, reporting, user-facing UX.
- `exoforge`: governed SDLC automation that observes, proposes, implements,
  tests, and submits.
- `decision.forum`: deliberation and approval UX, embedded first and standalone
  later.
- `crosschecked.ai`: claim and evidence verification.

## Files To Copy First

- `AGENTS.md` - project operating instructions for humans and AI agents.
- `architecture.md` - portfolio and CommandBase system architecture.
- `authority-model.md` - actor, tenant, and authority model.
- `human-approval-policy.md` - gates for agents, production, client trust, and
  sensitive operations.
- `receipt-taxonomy.md` - receipt classes and human-readable receipt format.
- `mvp-scope.md` - Customer Zero scope and out-of-scope boundaries.
- `avc-customer-zero-workflows.md` - first workflows for the AVC collective.
- `exoforge-session-protocol.md` - governed AI development session protocol.
- `execution-ledger-template.md` - per-session ledger template.

## Doctrine

Every exoapp should follow this operational doctrine:

```text
Intent
-> Authority Check
-> Risk Classification
-> Execution
-> Evidence Capture
-> ExoChain Receipt
-> Decision Review
-> ExoForge Improvement Loop
```

## First Commercial Wedge

The first paid offer should be the AVC Governed Intelligence Accelerator, also
usable as the Governed Automation Accelerator:

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

CommandBase should support selling and delivering that offer before attempting
to sell an abstract autonomous business launcher.

## Source Context

- Paperclip: https://github.com/paperclipai/paperclip
- ExoForge: https://github.com/exochain/exoforge
- ExoChain: https://github.com/exochain/exochain

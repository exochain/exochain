---
name: exochain-implement-feature
description: |
  Implement a council-approved feature in the ExoChain codebase.
  Works across the full stack: Rust WASM crate, Node.js services,
  React UI widgets, PostgreSQL schema, and Docker infrastructure.
argument-hint: "[approved-backlog-item-json]"
---

## Context

You are the ExoChain Implementation Agent. You receive council-approved backlog items and implement them across the ExoChain full stack. You operate within a git worktree for isolation.

## Repository Structure

```
exochain/
├── crates/                    # Rust workspace (16 crates)
│   ├── exo-core/              # Crypto, HLC, BCTS, types
│   ├── exo-gatekeeper/        # CGR kernel, invariant enforcement
│   ├── exo-governance/        # Decision engine, constitution
│   ├── exo-identity/          # PACE, Shamir, DID
│   ├── exo-authority/         # Delegation chains
│   ├── exo-consent/           # Bailment, consent policies
│   ├── exo-legal/             # Legal records, provenance
│   ├── exo-escalation/        # Escalation workflows
│   ├── decision-forum/        # Full governance app (15 modules)
│   └── exochain-wasm/         # WASM bindings (9 modules, 45 functions)
├── demo/
│   ├── services/              # 7 Node.js services
│   │   ├── gateway-api/       # Port 3000 — orchestrator
│   │   ├── identity-service/  # Port 3001
│   │   ├── consent-service/   # Port 3002
│   │   ├── governance-engine/ # Port 3003
│   │   ├── decision-forge/    # Port 3004
│   │   ├── provenance-writer/ # Port 3006
│   │   └── audit-api/         # Port 3007
│   ├── web/src/               # React UI
│   │   ├── App.jsx            # Widget grid + all widget renderers
│   │   └── index.css          # Dark theme CSS
│   ├── packages/
│   │   ├── exochain-wasm/     # npm WASM wrapper
│   │   └── shared/            # DB pool, router, helpers
│   └── infra/
│       ├── docker-compose.yml
│       └── postgres/init/     # Schema + seed SQL
```

## Implementation Guidelines

1. **Rust changes**: Modify the appropriate crate, add WASM bindings in `exochain-wasm`
2. **Service changes**: Update the relevant Node.js service in `demo/services/`
3. **UI changes**: Modify `demo/web/src/App.jsx` — add/update widget renderers
4. **Schema changes**: Add migration in `demo/infra/postgres/init/`
5. **Always**: Run `cargo check` for Rust, verify WASM builds

## Constitutional Compliance

Every implementation must:
- Preserve all 8 constitutional invariants
- Not introduce floating-point arithmetic
- Maintain BCTS state machine integrity
- Use approved crypto primitives only
- Include audit trail for state changes
- Respect delegation ceilings for AI actions

## Your Task

Implement the feature described in $ARGUMENTS. Follow the ExoChain coding standards:
- Rust: No `unsafe`, canonical CBOR, BTreeMap over HashMap
- Node.js: ESM, async/await, proper error handling
- React: Functional components, hooks only
- SQL: Idempotent migrations

Create all necessary files, run validation, and prepare for PR.

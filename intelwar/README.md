<!--
Copyright 2026 Exochain Foundation / IntelWar Project

Licensed under the Apache License, Version 2.0 for constitutional docs and
`intelwar-core`. Adjacent product shells under `apps/` and `services/` are
UNLICENSED proprietary surfaces — see ADJACENT-SURFACE-INTAKE.md.
-->

# IntelWar

Consent-governed, provenance-rich, multi-intelligence **Living Log** for
strategic wisdom — built on **EXOCHAIN v0.2.3** primitives.

IntelWar does not reinvent the trust fabric. It composes:

| Layer | EXOCHAIN primitive | IntelWar use |
|-------|-------------------|--------------|
| Consent | `exo-consent` bailment + gatekeeper `ConsentRequired` | Every Log append is consent-gated |
| Authority | `exo-authority` + gatekeeper `AuthorityChainValid` | Delegation path for append actors |
| Adjudication | CGR Kernel (`exo-gatekeeper`) | 8 EXOCHAIN invariants + 8 IntelWar overlays |
| Provenance | gatekeeper `Provenance` + `exo-proofs` envelopes | Receipts for every attested act |
| Ledger | `exo-dag` append | Immutable causal Living Log |
| Multi-intelligence | `VoiceKind` / AVC / decision-forum human gate | Transparent AI vs human attribution |
| Governance tooling | `exoforge/` triage patterns | Project self-governance loop |
| Browser / .ai / .tv | `exochain-wasm` | Client invariant checks + viewers |

## Canonical documents (read in this order)

1. [`docs/CURSOR_AGENT_HANDOFF.md`](docs/CURSOR_AGENT_HANDOFF.md) — **start here** for agent sessions
2. [`INTELWAR_CONSTITUTION.md`](INTELWAR_CONSTITUTION.md) — living governance compact
3. [`docs/INTELWAR_INVARIANTS_v1.md`](docs/INTELWAR_INVARIANTS_v1.md) — 8 IntelWar invariants
4. [`docs/LIVING_LOG_DATA_MODEL.md`](docs/LIVING_LOG_DATA_MODEL.md) — CBOR + receipt schema
5. [`docs/INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md`](docs/INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md) — primitive mapping
6. [`ADJACENT-SURFACE-INTAKE.md`](ADJACENT-SURFACE-INTAKE.md) — trust boundary

## Layout

```
intelwar/
├── INTELWAR_CONSTITUTION.md
├── ADJACENT-SURFACE-INTAKE.md
├── DEPENDENCY_PLAN.md
├── docs/                         # Constitution, invariants, Log, handoff
├── crates/intelwar-core/         # Rust Living Log adapter (workspace member)
├── apps/intelwar-net/            # Railway-ready React MVP (adjacent)
├── services/log-api/             # Minimal Node Living Log API (adjacent)
├── tools/                        # Triage + perpetual-motion emitters
└── wasm/                         # exochain-wasm integration hooks
```

## Quick start

```bash
# From repo root (branch `intelwar`, tag baseline v0.2.3)
cargo test -p intelwar-core

# Adjacent MVP (local)
cd intelwar/services/log-api && npm install && npm start
cd intelwar/apps/intelwar-net && npm install && npm run dev
```

Deploy target for the web shell: **intelwar.net** (Railway via `apps/intelwar-net/railway.json`).

## Classification

- **`crates/intelwar-core`** — core runtime adapter (calls CGR Kernel + DAG).
- **`apps/`, `services/`, `tools/`** — adjacent surfaces; no trust claims by proximity.
- Constitutional enforcement is proven only when the adapter path is exercised
  and fail-closed behavior is tested.

## Substrate pin

- EXOCHAIN: **v0.2.3** (`a50a15fd`)
- Workspace package version: `0.2.3`

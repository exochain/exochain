# IntelWar Dependency Plan (EXOCHAIN v0.2.3)

## Strategy

**Workspace path integration** for `intelwar-core` (chosen):

- Add `intelwar/crates/intelwar-core` to root `Cargo.toml` `members`.
- Depend on published-version-aligned path crates at `=0.2.3`.
- Keep JS apps/services outside the Rust workspace (like `demo/`, `cybermedica/`).

Alternative (not chosen for bootstrap): consume crates.io `exochain-*` once
0.2.3 is published; keep the same package names and semver pins.

## Direct Rust dependencies (`intelwar-core`)

| Crate | Package name | Role |
|-------|--------------|------|
| exo-core | `exochain-core` | Did, Hash256, Timestamp, crypto, CBOR hashing |
| exo-gatekeeper | `exochain-gatekeeper` | Kernel, Provenance, invariants |
| exo-dag | `exochain-dag` | Append-only DAG |
| decision-forum | `exochain-decision-forum` | DecisionObject + human gate for IW-4 doctrine evidence (PM-003) |
| exo-consent | `exochain-consent` | Planned: `ConsentGate` deeper wiring (currently gatekeeper `BailmentState`) |
| serde / ciborium / thiserror / blake3 / uuid | workspace | Serialization & errors |

Optional later: `exochain-proofs`, `exochain-avc`, `exochain-authority` when AVC receipts leave scaffold stage.

## WASM / JS

| Surface | Integration |
|---------|-------------|
| `intelwar/wasm` | Documented hooks to `crates/exochain-wasm` exports |
| `apps/intelwar-net` | Fetch Living Log from `services/log-api`; stub `.ai` / `.tv` |
| `services/log-api` | In-memory Log + optional subprocess/fixture from core tests |

## Version pin

All EXOCHAIN crates: **0.2.3** matching `[workspace.package] version`.

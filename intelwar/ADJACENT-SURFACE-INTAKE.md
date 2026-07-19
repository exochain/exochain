# IntelWar Adjacent Surface Intake

IntelWar spans a **core runtime adapter** (`intelwar/crates/intelwar-core`) and
**adjacent product shells** (`apps/`, `services/`, most of `tools/`). This intake
covers the adjacent surfaces. The Rust adapter is Apache-2.0 workspace code and
must obey EXOCHAIN `AGENTS.md` determinism and invariant rules.

## Accountability

- Owner: IntelWar founding eng / Exochain Foundation collaborator on duty
- Accountable maintainer: branch maintainer for `intelwar`
- Deployment status: `customer-zero` / public Railway shell (target custom domain: intelwar.net)
- Deploy runbook: `docs/RAILWAY_DEPLOY.md` (PM-007)

## Trust boundary

- Constitutional trust claims allowed: **only** when a tested call path into
  `intelwar-core` / EXOCHAIN Kernel succeeds. The React/Node MVP may **describe**
  the path and show simulated Log rows labeled `simulated: true`, but must not
  claim enforcement by proximity.
- Core state access: adjacent services may hold an in-memory or file-backed
  demo Log. They cannot mint consent, authority, provenance, or governance
  outcomes outside Kernel adjudication.
- Exact boundary:
  - Adapter: `intelwar/crates/intelwar-core` → `exo-gatekeeper`, `exo-dag`, …
  - WASM hooks: `intelwar/wasm/` → `crates/exochain-wasm` / demo wrapper
  - Adjacent: `intelwar/apps/intelwar-net`, `intelwar/services/log-api`

## Validation and operations

- Surface test commands:
  - `cargo test -p intelwar-core`
  - `npm --prefix intelwar/services/log-api test` (when present)
  - `npm --prefix intelwar/apps/intelwar-net test` (when present)
- CI gate (proposed): add focused job for `intelwar-core`; keep adjacent apps
  out of `cargo --workspace` deny/doc unless explicitly expanded.
- Runtime configuration source: Railway service variables outside Git
  (`VITE_LOG_API_URL`, optional `INTELWAR_CORE_BIN` / `INTELWAR_DAGDB_*`).
- Secrets inventory: no production signing keys in the public shell by default.
  Demo consent is local fixture only. Never share core bootstrap / emergency
  override credentials with the MVP.
- Rollback/disablement: undeploy Railway services or remove custom domain; rebuild
  web without `VITE_LOG_API_URL` is blocked (fail closed). Core DAG state remains
  outside adjacent rollback.

## Licensing

- `intelwar/crates/intelwar-core` + constitutional docs: Apache-2.0
- `apps/`, `services/` (except documented exceptions): UNLICENSED proprietary
  adjacent software until commercial terms exist

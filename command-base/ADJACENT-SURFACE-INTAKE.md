# CommandBase Adjacent Surface Intake

CommandBase is an adjacent operational surface. It is not the canonical
EXOCHAIN Rust trust fabric.

## Accountability

- Owner: EXOCHAIN maintainers
- Accountable maintainer: repository maintainer on duty for CommandBase changes
- Deployment status: customer-zero

## Trust Boundary

- Constitutional trust claims allowed: limited. CommandBase may claim EXOCHAIN
  participation only for runtime paths that call the canonical Rust API or the
  generated EXOCHAIN WASM package and have tests proving fail-closed behavior.
- Core state access: CommandBase may call generated EXOCHAIN WASM bindings and
  local service adapters. It must not mint, cache, or simulate consent,
  authority, provenance, or governance outcomes outside tested core or adapter
  calls.
- Exact boundary: `command-base/app` is an Express/SQLite application and
  `command-base/worker` is an adjacent worker. The trusted enforcement boundary
  remains the canonical EXOCHAIN Rust crates, generated WASM bindings, and any
  tested runtime adapter they call.

## Validation

- Surface test commands: `npm --prefix command-base/app run dependency-policy:check`,
  `npm --prefix command-base/app audit --audit-level=moderate`, and focused
  Node tests under `command-base/app/services/*.test.js` when service code
  changes.
- CI gate: CommandBase dependency policy and audit checks must fail on known
  moderate-or-higher dependency advisories, deprecated upload parser major
  versions, or stale package-lock metadata.
- Runtime configuration source: environment variables, local SQLite path
  configuration, and package metadata in `command-base/app` and
  `command-base/worker`.
- Secrets inventory: no production signing keys, bootstrap tokens, tenant
  secrets, emergency override credentials, or production API keys are permitted
  in this directory. Runtime secrets must be supplied outside git through
  deployment-specific secret stores.
- Rollback or disablement path: stop the CommandBase app or worker, remove it
  from deployment routing, or disable upload endpoints at the reverse proxy.
  Canonical EXOCHAIN Rust crates and runtime state remain unaffected.

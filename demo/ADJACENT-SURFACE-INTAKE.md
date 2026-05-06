# EXOCHAIN Demo Adjacent Surface Intake

This directory is an adjacent prototype surface. It is not the canonical
EXOCHAIN Rust trust fabric.

## Accountability

- Owner: EXOCHAIN maintainers
- Accountable maintainer: repository maintainer on duty for demo changes
- Deployment status: prototype

## Trust Boundary

- Constitutional trust claims allowed: no. Demo apps may describe themselves as
  demonstrations of EXOCHAIN APIs, but they must not claim constitutional
  enforcement unless the runtime path calls the canonical Rust API or generated
  WASM binding and the behavior is covered by tests.
- Core state access: demo services may call the generated
  `@exochain/exochain-wasm` package for local demonstrations. They must not
  write EXOCHAIN core state, signatures, credentials, governance outcomes,
  consent records, or provenance records outside the canonical Rust runtime.
- Exact boundary: `demo/packages/exochain-wasm` is a JavaScript wrapper around
  generated WASM artifacts from `crates/exochain-wasm`. The generated Rust/WASM
  output remains the enforcement boundary; demo services are callers, not
  authorities.

## Validation

- Surface test commands: `npm --prefix demo run build:wasm`,
  `npm --prefix demo run test:wasm`, `npm --prefix demo test`, and
  `npm --prefix demo audit --audit-level=moderate`.
- CI gate: WASM/JS bridge verification, demo workspace tests, dependency audit,
  and repo hygiene gates must fail on license drift, bridge export drift, stale
  workspace lock metadata, or known moderate-or-higher dependency advisories.
- Runtime configuration source: environment variables and local demo service
  package metadata only.
- Secrets inventory: no production signing keys, bootstrap tokens, tenant
  secrets, emergency override credentials, or production API keys are permitted
  in this directory. Demo-only local variables must be supplied outside git.
- Rollback or disablement path: remove the demo package from demo service
  dependencies or stop the demo compose/service; canonical EXOCHAIN Rust crates
  and runtime state remain unaffected.

# CrossChecked Adjacent Surface Intake

CrossChecked is an adjacent prototype application. It is not the canonical
EXOCHAIN Rust trust fabric.

## Accountability

- Owner: EXOCHAIN maintainers
- Accountable maintainer: repository maintainer on duty for CrossChecked changes
- Deployment status: prototype

## Trust Boundary

- Constitutional trust claims allowed: no. CrossChecked may describe itself as
  an EXOCHAIN-adjacent prototype, but it must not claim constitutional
  enforcement unless a runtime path calls a tested EXOCHAIN core API, WASM
  binding, or runtime adapter and fails closed when that boundary rejects or is
  unavailable.
- Core state access: none in the current app build.
- Exact boundary: `demo/apps/crosschecked` is a Vite/React app shell. The
  trusted enforcement boundary remains the canonical EXOCHAIN Rust crates,
  generated WASM bindings, and any tested runtime adapter they call.

## Validation

- Surface test commands: `npm --prefix demo/apps/crosschecked run surface-policy:check`,
  `npm --prefix demo/apps/crosschecked run build`, and
  `npm --prefix demo/apps/crosschecked audit --audit-level=moderate`.
- CI gate: CrossChecked policy, build, and audit checks must fail on unsupported
  EXOCHAIN trust claims, missing adjacent-surface intake, or known
  moderate-or-higher dependency advisories.
- Runtime configuration source: Vite environment variables and API proxy
  configuration only.
- Secrets inventory: no production signing keys, bootstrap tokens, tenant
  secrets, emergency override credentials, or production API keys are permitted
  in this directory.
- Rollback or disablement path: do not deploy the app, remove it from routing,
  or disable its hosting target. Canonical EXOCHAIN Rust crates and runtime
  state remain unaffected.

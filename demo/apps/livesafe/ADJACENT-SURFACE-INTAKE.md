# LiveSafe Adjacent Surface Intake

LiveSafe is an adjacent prototype application. It is not the canonical EXOCHAIN
Rust trust fabric.

## Accountability

- Owner: EXOCHAIN maintainers
- Accountable maintainer: repository maintainer on duty for LiveSafe changes
- Deployment status: prototype

## Trust Boundary

- Constitutional trust claims allowed: no. LiveSafe may describe itself as an
  EXOCHAIN-adjacent prototype, but it must not claim constitutional enforcement
  unless a runtime path calls a tested EXOCHAIN core API, WASM binding, or
  runtime adapter and fails closed when that boundary rejects or is unavailable.
- Core state access: none in the current app build. Browser-side crypto and
  EXOCHAIN trust-fabric operations are disabled fail-closed until a tested
  browser adapter is wired in.
- Exact boundary: `demo/apps/livesafe` is a Vite/React app shell. The trusted
  enforcement boundary remains the canonical EXOCHAIN Rust crates, generated
  WASM bindings, and any tested runtime adapter they call.

## Validation

- Surface test commands: `npm --prefix demo/apps/livesafe run surface-policy:check`,
  `npm --prefix demo/apps/livesafe run build`, and
  `npm --prefix demo/apps/livesafe audit --audit-level=moderate`.
- CI gate: LiveSafe policy, build, and audit checks must fail on unsupported
  EXOCHAIN trust claims, disabled raw-secret WASM entrypoint calls, missing
  adjacent-surface intake, or known moderate-or-higher dependency advisories.
- Runtime configuration source: Vite environment variables and API proxy
  configuration only.
- Secrets inventory: no production signing keys, bootstrap tokens, tenant
  secrets, emergency override credentials, or production API keys are permitted
  in this directory. Browser-held secrets must not be generated or persisted
  unless a tested EXOCHAIN browser adapter explicitly supports that flow.
- Rollback or disablement path: do not deploy the app, remove it from routing,
  or disable its hosting target. Canonical EXOCHAIN Rust crates and runtime
  state remain unaffected.

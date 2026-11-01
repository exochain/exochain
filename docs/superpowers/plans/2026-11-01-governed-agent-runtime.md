# Governed Agent Runtime Implementation Plan

> For agentic workers: use superpowers:executing-plans to implement task by task.

**Goal:** Connect model deliberation to reviewed, pre-authorized MCP execution.
**Architecture:** Extend AVC action response attestations, consume them in LYNK,
then compose the existing live adapters in a bounded agent runner.
**Tech Stack:** Existing Rust/Axum/CBOR/Ed25519 and TypeScript/Node, no new dependencies.
**Spec:** `docs/superpowers/specs/2026-11-01-governed-agent-runtime-design.md`

## Global Constraints

- No new permission grants, kernel changes, or locally minted EXOCHAIN receipts.
- Canonical CBOR for new commitments; integers only; host-supplied HLC timestamps.
- Maximum iterations 25; explicit successful stop and escalation conditions.
- No secrets, raw arguments, or model/tool output in journals or receipt metadata.
- Execute on branch `codex/governed-agent-runtime`; no merge or deployment.

## Review Focus

- Mutation between authorization and dispatch must not change the executed request.
- A signed response for a different tool, tenant, argument or key must fail closed.
- Concurrent workers and restarts must not duplicate an uncertain side effect.
- Cancellation and receipt outages must stop subsequent actions.
- Malformed or self-approving model output must not become execution authority.

### Task 1: Authenticate generic AVC receipt responses

Files: `crates/exo-node/src/avc.rs`, node receipt fixtures/tests.
Produces: optional `action_response_attestation` on finalized generic Allow receipts;
domain `exo.avc.action.receipt_response.attestation.v1`, existing response payload.

- [ ] Add failing tests for attestation binding, tamper rejection and no-finality denial.
- [ ] Run focused node tests and observe failure.
- [ ] Reuse canonical CBOR and the existing transactional receipt path to sign.
- [ ] Run focused node tests and existing receipt tests, commit core change.

### Task 2: Gate MCP dispatch and retain durable attempt claims

Files: LYNK `action-authorization.ts`, `execution-journal.ts`, `mcp.ts`, `http.ts`,
`types.ts`, `wire.ts`, `attestation.ts`, `index.ts`, relevant tests and examples.
Consumes: Task 1 signed response. Produces: production MCP proxy that requires
signed request material and durable atomic claim; retains existing receipt gate.

- [ ] Write failing tests for missing/denied/tampered authorization, exact request
      binding, duplicate/concurrent claims, restart, cancellation and mutation.
- [ ] Run tests to observe missing protection.
- [ ] Implement preflight using `/api/v1/avc/receipts/emit`, pinned-key verification,
      request snapshot, durable journal and no redirect/automatic retry.
- [ ] Run `npm test`, commit adapter enforcement.

### Task 3: Run bounded reviewed agents through LYNK

Files: LYNK `agent.ts`, `agent-model.ts`, exported types, tests, README and examples.
Consumes: Task 2 MCP proxy plus existing receipted model clients.
Produces: planner/reviewer loop with declared bounds, reviewed completion and
structured escalation, using production adapters and host signing configuration.

- [ ] Write failing tests for reviewed execution/completion, rejected review,
      forged/invalid proposals, repeated failures, exhausted limits and cancellation.
- [ ] Implement structured model adapter and runner without granting authority.
- [ ] Run package test/build/coverage/artifact/pack checks and relevant Rust gates.
- [ ] Review complete diff independently, correct material findings, commit and
      create a draft PR with precise scope, validation and limitations.

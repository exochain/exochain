<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Post-Audit Whole-System Remediation Plan - 2026-07-08

## Summary

This plan converts the 2026-07-08 whole-system adversarial audit into a test-driven implementation roadmap. It is planning-only: it records the fixed goal, P0/P1 findings, execution sequence, repo standards, test-first requirements, and completion gates for later code-change PRs.

The path to a goal-ready system is to fix core contract truth first, repair consumers against that contract, isolate adjacent-surface hardening into separate PRs, and then prove deployment, release, observability, and final end-to-end workflows with current evidence.

Planning source packet:

| Input | Evidence status | Source |
| --- | --- | --- |
| System/project | EVIDENCED | `exochain/exochain` at commit `2cf66b377d32fbdbba4228812ac8af29e0068c04`. |
| Fixed end goal | INFERRED | `README.md` trust-fabric claims and `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md`. |
| Audit findings | EVIDENCED | `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md`. |
| Preexisting plans | EVIDENCED | `docs/audit/AVC-TRUST-RECEIPT-ISSUES-696-700-PLAN.md`, `docs/dagdb/runtime-activation/rollback-canary-observability.md`, `GAP-REGISTRY.md`. |
| Repo standards | EVIDENCED | `AGENTS.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`, `Cargo.toml`. |
| Constraints | EVIDENCED | `AGENTS.md` core-vs-adjacent classification and commit/PR isolation rules. |
| Missing evidence | EVIDENCED | Live health probes timed out; full test, DB, release, and security suites were not run. |

Exit criterion: The plan states the audit-to-implementation objective, the source packet, and the evidence boundary.

## Locked Decisions

1. Canonical audit record path: `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md`.
2. Canonical implementation plan path: `docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`.
3. This PR is documentation-only and does not claim that any audit finding has been implemented.
4. Later code execution uses separate PRs for EXOCHAIN core, core runtime adapter, adjacent-surface hardening, deployment/release, and documentation/evidence guard changes unless a single validation boundary requires combining them.
5. The strict inferred system goal remains: EXOCHAIN operates as a verifiable, privacy-preserving, production-credible trust fabric across evidenced core, adapter, user, SDK, agent, deployment, and evidence surfaces.
6. `P0-01` remains only provisionally addressed by this plan until maintainers accept the strict inferred goal or provide a replacement fixed goal.
7. The first execution chunk freezes the accepted system goal and classifies every touched surface before code changes.
8. The second execution chunk creates a generated or mechanically checked route and contract inventory before changing web, SDK, MCP, DAG DB, or docs consumers.
9. Adjacent CommandBase and LifeSafe fixes do not claim to remediate EXOCHAIN core vulnerabilities unless tests prove a core adapter boundary is involved.
10. GraphQL remains unavailable for production integration until the explicitly unaudited feature is audited or LifeSafe is moved to supported REST/AVC paths.
11. DAG DB route truth must be resolved by source, generated route inventory, discovery/OpenAPI, docs, SDK, MCP, and tests agreeing.
12. Production-readiness claims remain forbidden until release artifacts, deployment digest, live health/readiness evidence, and end-to-end validation artifacts exist.
13. No implementation chunk may rely on narrative proof packets, imported logs, or local-only proof paths as the sole completion evidence.
14. All implementation chunks write tests or source guards before production code changes.

Exit criterion: Ambiguous scope, sequencing, classification, and claim-boundary decisions are fixed.

## Deferred Phases

| Deferred item | Activation trigger |
| --- | --- |
| Full production certification | All P0 chunks pass, release artifacts are published or explicitly scoped out, live deployment probes succeed, and end-to-end user journeys pass against the release candidate. |
| GraphQL production enablement | A dedicated GraphQL audit PR proves authentication, authorization, consent, provenance, proof-verification, and resolver safety for every enabled operation. |
| DAG DB cheaper-and-better claim | A repeated blinded benchmark plus provider billing evidence proves the threshold currently marked not accepted in the README. |
| Hardware TEE production attestation | Real hardware quote fixtures, trust-root collateral, stale-collateral negative tests, and platform-security review are committed. |
| Adjacent product constitutional trust claims | Surface intake records and fail-closed adapter tests prove the adjacent surface invokes verified core APIs and cannot simulate trust state. |

Exit criterion: Every deferred phase has a concrete activation trigger and is not required for the first execution PR.

## Requirements Specification

### Functional

1. A future execution agent can map every P0 and P1 audit finding to a chunk, tests, affected paths, and completion evidence.
2. Contract drift must be resolved through a route/contract inventory that compares gateway routes, DAG DB routes, web calls, SDK calls, MCP tools, discovery, and documentation.
3. Web, TypeScript SDK, and Python SDK behavior must be validated against the default gateway before claiming developer workflow success.
4. DAG DB route count, signature boundary, RLS, MCP proxy, SDK proxy, and runtime docs must agree before any production DAG DB claim.
5. CommandBase hardening must address command construction, file ingestion, LLM disclosure, credential vault storage, auth bootstrap, npm hygiene, and soft receipts.
6. LifeSafe hardening must address PHI encryption failure, legacy metadata authorization, route import startup behavior, DB TLS/logging, and EXOCHAIN adapter status truth.
7. Deployment and release proof must include current health/readiness evidence, image or release identity, signed release status where claimed, SBOM/SLSA status where claimed, and rollback/canary evidence for deployment claims.
8. Documentation must stop using stale counts, stale live-health dates, stale route counts, and proxy metrics as production proof.

### Non-Functional

1. All future code fixes preserve determinism, no-unsafe constraints, no-float constraints, and `BTreeMap`/canonical serialization rules where Rust core behavior is touched.
2. Adjacent-surface changes preserve core regression firewall requirements.
3. Failure paths fail closed and expose operator-visible evidence without leaking secrets, raw signatures, raw medical data, bearer tokens, private keys, or database URLs.
4. Tests prove behavior, not only mock calls or coverage numbers.
5. Implementation remains surgical: no parallel router, duplicate SDK, duplicate trust path, or second source of truth may be created.

### Compatibility

1. Existing public route prefixes are preserved unless the route inventory chunk explicitly marks a route unsupported and updates consumers in the same adapter PR.
2. Existing SDK package names, module exports, and transport abstractions remain stable unless a breaking-change decision is separately approved.
3. Existing docs under `docs/audit/` remain historical records; new plan files do not rewrite prior records.
4. Adjacent CommandBase and LifeSafe changes do not expand their trust claims by proximity.
5. Release and deployment docs preserve current Docker, Railway, and CI entrypoints while correcting unverified claims.

### Observability

1. Each execution PR records path classification, tests run, tests not run, evidence produced, and remaining risks.
2. Contract inventory output becomes a merge-blocking artifact for route/consumer drift.
3. CommandBase and LifeSafe hardening expose explicit failure states for receipt, anchor, encryption, authorization, and adapter failures.
4. Deployment proof captures timestamped health, readiness, DB-health, image/release identity, and rollback or fail-closed results.
5. Documentation freshness checks capture repo truth metrics, route counts, CI gate counts, and live-health evidence dates.

Exit criterion: Functional, non-functional, compatibility, and observability requirements are explicit and testable.

## Post-Audit Remediation Contract

| claim | scope | proof command or check |
| --- | --- | --- |
| The audit record exists and is bounded to current `main` evidence. | `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md` | `rg -n "2cf66b377d32fbdbba4228812ac8af29e0068c04|Evidence status labels|P0 Findings" docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md`. |
| The remediation plan is planning-only. | `docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md` | `rg -n "planning-only|does not claim" docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`. |
| All P0/P1 findings are assigned to chunks. | This plan | `rg -n "P0-01|P0-02|P0-03|P0-04|P0-05|P0-06|P0-07|P1-01|P1-02|P1-03|P1-04|P1-05|P1-06" docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`. |
| Core and adjacent work are isolated. | `AGENTS.md`, this plan | `rg -n "separate PRs|Adjacent CommandBase|LifeSafe hardening|core regression firewall" docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`. |
| Goal truth is the first execution dependency. | Slice 1 | `rg -n "Slice 1: Goal Freeze and Surface Classification" docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`. |
| Route truth is the second execution dependency. | Slice 2 | `rg -n "Slice 2: Route and Contract Truth Inventory" docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`. |
| The docs index points to the audit and plan. | `docs/INDEX.md` | `rg -n "Whole-System Audit|Post-Audit Whole-System Remediation Plan" docs/INDEX.md`. |

Definitions:

- `route and contract inventory` means a generated or mechanically checked artifact that compares `exo-gateway` routes, DAG DB routes, discovery/OpenAPI route listings, web API calls, TypeScript SDK calls, Python SDK calls, Rust SDK HTTP calls, MCP DAG DB tools, and docs route claims.
- `adjacent surface` means the category defined in `AGENTS.md`: CommandBase, LifeSafe, customer-zero apps, websites, demos, dashboards, generated prototypes, or product shells that are not the canonical Rust trust fabric.
- `completion evidence` means command output, test output, generated artifact, HTTP probe output, deployment digest, release URL, source guard output, or reviewer verdict committed or linked in the PR.

Exit criterion: Every claim used by this planning PR has a scope and proof command or check.

## Implementation Slices

Sub-Agent Delegation Protocol: A future execution orchestrator may delegate discovery, code changes, and review to sub-agents only with bounded briefs. Each brief must include objective, path classification, allowed write scope, forbidden write scope, first failing test, acceptance criteria, verification commands, and a rejection rule for work that fabricates capability, violates `AGENTS.md`, touches unrelated files, or lacks test evidence.

### Slice 1: Goal Freeze and Surface Classification

Goal: Convert the inferred audit goal into an accepted repository goal and classify every future changed path under `AGENTS.md`.

Allowed write scope: `docs/audit/**`, `README.md`, `AGENTS.md`, `GAP-REGISTRY.md`, governance records, and PR descriptions for later execution PRs.

Requirements: Address `P0-01`. No implementation PR may claim the whole system meets its goal until the goal is accepted, revised through a requirement-change proposal, or explicitly marked blocked.

Specification: The accepted goal record states the system-level goal, non-negotiable acceptance criteria, in-scope surfaces, out-of-scope surfaces, adjacent-surface trust boundaries, evidence required for success, and what cannot be claimed yet.

Test plan: Add a source guard or documentation check that fails when the accepted goal record is missing, lacks acceptance criteria, or omits `AGENTS.md` path classification for touched paths.

Exit criterion: Future implementation PRs have a maintainer-accepted goal and path-classification boundary before code edits.

### Slice 2: Route and Contract Truth Inventory

Goal: Create the canonical route and contract inventory that all API consumers and docs must match.

Allowed write scope: `tools/**`, `crates/exo-gateway/tests/**`, `crates/exo-api/tests/**`, `web/src/lib/**`, `packages/exochain-sdk/**`, `packages/exochain-py/**`, `crates/exo-node/src/mcp/tools/**`, `docs/dagdb/**`, `docs/audit/**`, `.github/workflows/ci.yml` when adding the guard.

Requirements: Address `P0-02`, `P0-03`, `P0-04`, `P1-01`, `P1-03`, and `P1-04`. Use existing route tables and tests rather than a hand-maintained parallel source.

Specification: The inventory reports every gateway route, every DAG DB route, every web/SDK/MCP route consumer, every documented DAG DB route claim, and whether each entry is `mounted`, `consumer-only`, `reserved`, `refused`, or `unsupported`.

Test plan: Write a failing route inventory test or script first. The first failure must show at least the current DAG DB five-vs-twelve conflict and web health route mismatch.

Exit criterion: The route inventory fails on current drift before implementation and passes after source, docs, and consumers agree.

### Slice 3: Gateway, Web, and SDK Contract Repair

Goal: Repair browser and SDK developer journeys against the canonical gateway contract from Slice 1.

Allowed write scope: `web/src/lib/**`, `web/src/pages/**`, `web/src/**/*.test.*`, `packages/exochain-sdk/**`, `packages/exochain-py/**`, `crates/exo-gateway/src/server.rs`, `crates/exo-gateway/tests/**`, docs that describe the changed contracts.

Requirements: Address `P0-04` and `P1-01` without adding duplicate route aliases unless the route inventory marks an alias as a deliberate compatibility route.

Specification: Web health uses `/health`, web decision/agent/user/audit/tenant calls match mounted routes, SDK high-level methods either call mounted routes or return explicit unsupported errors documented in the SDK.

Test plan: Add web-gateway contract tests, TypeScript SDK transport tests, Python client tests, and a gateway route assertion. The tests must fail on current mismatched paths.

Exit criterion: Web, TypeScript SDK, and Python SDK route tests pass against the default gateway contract.

### Slice 4: DAG DB Runtime Truth and Boundary Hardening

Goal: Make DAG DB route count, signature requirements, RLS, SDK/MCP proxy behavior, and runtime docs truthful and test-backed.

Allowed write scope: `crates/exo-gateway/src/dagdb.rs`, `crates/exo-gateway/tests/**`, `crates/exo-dag-db-*/**`, `crates/exo-node/src/mcp/tools/dagdb.rs`, `crates/exochain-sdk/src/dagdb.rs`, `docs/dagdb/**`, `INTEGRATION.md`, `README.md`.

Requirements: Address `P0-03`, `P1-03`, and DAG DB route/signature/RLS findings from the audit. Preserve the no-billing-savings and thesis-not-accepted boundary.

Specification: If twelve routes remain mounted, docs, discovery, OpenAPI, SDK, MCP, and tests must say twelve. If only five production routes are intended, the remaining routes must be unmounted or explicitly refused and tests must prove that behavior.

Test plan: Add failing tests for mounted route inventory, missing write-signature behavior, tenant/RLS isolation, no-pool fail-closed behavior, and MCP/SDK configured proxy results.

Exit criterion: DAG DB route truth is single-sourced and runtime authorization boundaries are covered by focused tests.

### Slice 5: CommandBase Adjacent-Surface Security Hardening

Goal: Fix CommandBase security and reliability risks without claiming core remediation by proximity.

Allowed write scope: `command-base/**`, CommandBase-owned docs, CommandBase-owned CI or package hygiene scripts.

Requirements: Address `P0-05` and `P1-06`. Include an adjacent-surface intake record with owner, deployment status, trust boundary, secrets inventory, test command, and rollback/disablement path.

Specification: Shell interpolation is replaced with safe process APIs or rejected input; file ingestion is restricted to allowed workspace roots; raw file content sent to LLM is bounded and visible to operators; credentials are encrypted or delegated to a supported secret store; local bootstrap cannot be spoofed through proxy headers; receipt persistence failures fail loudly or mark the operation degraded instead of returning soft success.

Test plan: Add failing tests for shell metacharacter injection, out-of-root file read, plaintext vault row content, proxy-spoofed localhost bootstrap, and soft receipt acceptance.

Exit criterion: CommandBase negative security tests pass and the surface remains classified as adjacent unless adapter tests prove core enforcement.

### Slice 6: LifeSafe Privacy and Adapter Boundary Hardening

Goal: Fix LifeSafe PHI/privacy risks and make EXOCHAIN anchoring status truthful.

Allowed write scope: `livesafe/**`, LifeSafe-owned docs, LifeSafe-owned CI.

Requirements: Address `P0-06` and `P1-02`. Include or update LifeSafe surface intake.

Specification: Medical upload fails or rolls back on encryption failure; legacy record-request routes require subscriber authorization and deny cross-subscriber access; DB TLS configuration avoids `rejectUnauthorized: false` outside documented development exceptions; DB URL logs are redacted; route import failures fail startup or produce unhealthy readiness; default EXOCHAIN integration does not point to unaudited GraphQL as if it were production.

Test plan: Add failing tests for encryption failure, unauthenticated legacy metadata access, cross-subscriber metadata access, DB URL redaction, route import failure, and GraphQL refusal behavior.

Exit criterion: LifeSafe privacy/security tests pass and public trust claims remain disabled until adapter evidence exists.

### Slice 7: Deployment, Release, and Evidence Freshness

Goal: Replace stale production and release claims with current, reproducible evidence gates.

Allowed write scope: `tools/**`, `.github/workflows/**`, `Dockerfile`, `docker-compose*.yml`, `railway.json`, `deploy/**`, `docs/guides/**`, `README.md`, `SECURITY.md`, `VERSIONING.md`, `docs/INDEX.md`, `docs/audit/**`.

Requirements: Address `P0-07`, `P1-04`, and `P1-05`.

Specification: Repo truth counts, route counts, CI gate counts, live health evidence dates, release publication status, SBOM/SLSA status, and deployment docs are generated or source-guarded. Live URL claims include timestamp, command, HTTP status, and failure handling.

Test plan: Add source guards that fail on stale counts, stale route claims, stale live-health claims, nonexistent root commands, wrong compose contexts, and unverified release publication claims.

Exit criterion: Documentation and release/deployment claims are checked by reproducible commands.

### Slice 8: Observability and End-to-End Assembly

Goal: Prove the whole system goal with end-to-end journeys after the blocking contract, security, and evidence chunks land.

Allowed write scope: e2e test harnesses, CI workflows, docs/audit final proof packet, and observability configs for gateway, DAG DB, web, SDKs, CommandBase, and LifeSafe where already owned.

Requirements: Cover the system-level acceptance criteria in `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md`.

Specification: E2E tests cover browser governance, SDK developer flow, DAG DB agent/MCP flow, receipt/finality path, deployment health/rollback path, and adjacent-surface failure boundaries. Observability captures failures without leaking secrets.

Test plan: Add Playwright/API tests, SDK integration tests, DAG DB live-Postgres tests, MCP configured-proxy tests, deployment smoke tests, and failure-injection tests for unavailable DB/gateway/provider paths.

Exit criterion: A final assembly proof packet shows every non-negotiable acceptance criterion has direct evidence or an explicit unresolved blocker.

Exit criterion: Every implementation slice has a goal, write scope, requirements, specification, test plan, and observable completion condition.

## Test Plan

### Baseline Commands

```bash
bash tools/repo_truth.sh
bash tools/test_repo_truth.sh
bash tools/test_gap_registry_truth.sh
bash tools/check_systemic_integrity_claims.sh
rg -n "Whole-System Audit|Post-Audit Whole-System Remediation Plan" docs/INDEX.md
```

### Per-Slice Commands

Slice 1:

```bash
rg -n "system-level goal|non-negotiable acceptance criteria|EXOCHAIN core|Core runtime adapter|Adjacent surface" docs/audit README.md AGENTS.md
```

Slice 2:

```bash
bash tools/test_route_contract_truth.sh
cargo test -p exo-gateway route_inventory
```

Slice 3:

```bash
(cd web && npm test -- --run)
(cd packages/exochain-sdk && npm test)
(cd packages/exochain-py && pytest)
cargo test -p exo-gateway decision agents users audit
```

Slice 4:

```bash
cargo test -p exo-gateway --features production-db dagdb
cargo test -p exo-dag-db-postgres --features postgres
cargo test -p exo-node dagdb --features dagdb-gateway-proxy
cargo test -p exochain-sdk dagdb --features http-client
```

Slice 5:

```bash
(cd command-base/app && npm test)
bash tools/test_npm_core_package_hygiene.sh
```

Slice 6:

```bash
(cd livesafe && npm test)
bash tools/test_livesafe_railway_deploy_ref_guard
```

Slice 7:

```bash
bash tools/repo_truth.sh
bash tools/test_repo_truth.sh
bash tools/test_audit_policy_docs.sh
bash tools/verify_live_node_claim.sh https://exochain-production.up.railway.app
```

Slice 8:

```bash
cargo test --workspace --lib
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
cargo deny check
cargo audit
```

### Final Agent-Runnable Sequence

```bash
bash tools/repo_truth.sh
bash tools/test_repo_truth.sh
bash tools/test_gap_registry_truth.sh
bash tools/check_systemic_integrity_claims.sh
rg -n "Whole-System Audit|Post-Audit Whole-System Remediation Plan" docs/INDEX.md
```

### Operator-Only Steps

1. Run current live deployment health, readiness, and DB-health probes from the operator network.
2. Confirm GitHub release, SBOM, SLSA, crates.io, npm, and PyPI publication status where public release claims are made.
3. Provide real production canary, rollback, and deployment digest artifacts before production-readiness claims are restored.

Exit criterion: Baseline, per-slice, final agent-runnable, and operator-only validation commands are explicit.

## Definition of Done

1. `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md` exists with scope, commands, findings, and final truthful progress statement.
2. `docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md` exists with locked decisions, deferred phases, requirements, contract, slices, tests, completion gates, and post-implementation review.
3. `docs/INDEX.md` links to both new audit artifacts.
4. `docs/INDEX.md` uses the current generated repo-truth metrics for crates, Rust LOC, listed tests, and CI gate count.
5. No code behavior is modified by this planning PR.
6. Every P0 audit finding is assigned to a future execution slice.
7. Every P1 audit finding is assigned to a future execution slice.
8. The plan states that future implementation must be test-first.
9. The plan states that core, runtime-adapter, adjacent-surface, deployment, and evidence work must be isolated unless validation requires combining them.
10. The plan states that adjacent surfaces cannot claim EXOCHAIN core remediation by proximity.
11. The plan forbids production-readiness claims until current evidence exists.
12. The plan includes goal freeze and surface classification as the first execution dependency.
13. The plan includes route/contract truth as the second execution dependency.
14. The plan includes CommandBase and LifeSafe as adjacent-surface hardening slices.
15. The plan includes deployment, release, and evidence freshness as a required slice.
16. The plan includes final end-to-end assembly only after blocking slices land.
17. `bash tools/repo_truth.sh` has been run for this PR.
18. `bash tools/test_repo_truth.sh` has been run for this PR.
19. `bash tools/test_gap_registry_truth.sh` has been run for this PR.
20. `bash tools/check_systemic_integrity_claims.sh` has been run for this PR.
21. A post-implementation review runs before push or deployment for every later code-change chunk.

Exit criterion: The planning PR is complete only when the audit record, plan, index links, truth commands, and no-code-change boundary are all verified.

## Post-Implementation Review

When the Definition of Done is met and the checkpoint commit is created, a post-implementation review pass runs before push or deployment. The pass walks code review, test coverage, hardening, end-to-end verification, and documentation. Blockers found in the review are fixed and the relevant layers re-run before ship.

Review scope: `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md`, `docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`, `docs/INDEX.md`, and future execution slices named in this plan.

Review trigger: Definition of Done met and checkpoint commit created.

Review verdict gate: Ship | Fix blockers and re-run | Hand back to planning.

Exit criterion: The post-implementation review scope, trigger, and verdict gate are explicit and require review before push or deployment.

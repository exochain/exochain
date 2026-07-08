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

# Post-Audit Frozen System Goal - 2026-07-08

## Status

Status: proposed for maintainer acceptance.

Source audit: `docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md`.

Source plan: `docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md`.

This record freezes the inferred system goal used by post-audit execution. It does not certify that the goal is achieved.

Exit criterion: The record status, source audit, source plan, and non-certification boundary are explicit.

## System-Level Goal

EXOCHAIN operates as a verifiable, privacy-preserving, production-credible trust fabric that supports identity adjudication, data sovereignty, deterministic finality, constitutional governance, agent and tool control, SDK and application integration, deployment operation, and user trust across evidenced surfaces.

Exit criterion: The system-level goal is stated as a single fixed target for post-audit execution.

## Non-Negotiable Acceptance Criteria

1. Core invariants are enforced on every claim-producing path, not only in isolated library tests.
2. Browser, SDK, API, MCP, and deployment users can complete documented workflows without route mismatches, missing feature flags, or hidden local-only state.
3. Consent, authority, governance, receipt, finality, and provenance claims are backed by durable evidence and fail closed when that evidence is absent.
4. Adjacent surfaces cannot claim EXOCHAIN constitutional trust unless they call verified core APIs and pass adapter-boundary tests.
5. Sensitive-data surfaces preserve confidentiality, authorization, and failure visibility.
6. Production and readiness claims are current, reproducible, and tied to tests, command output, release artifacts, deployment evidence, or reviewer evidence.
7. Documentation, discovery, SDKs, route inventories, MCP tools, and runtime routers agree.

Exit criterion: The non-negotiable acceptance criteria are enumerated and testable.

## Surface Classification Boundary

Every future implementation PR must classify each touched path as one of the following `AGENTS.md` categories:

| Classification | Paths and surfaces |
| --- | --- |
| EXOCHAIN core | Rust workspace crates, governance/runtime logic, canonical cryptography, DAG, consent, authority, gatekeeper, node, gateway, SDK, WASM, proofs, tenant, messaging, CI gates, and constitutional governance artifacts. |
| Core runtime adapter | Code that directly exposes or transports core invariants across APIs, MCP, WASM, P2P, persistence, deployment, SDK, or runtime documentation. |
| Adjacent surface | CommandBase, LifeSafe, customer-zero apps, websites, demos, dashboards, generated prototypes, product shells, and other code that is not itself the canonical Rust trust fabric. |
| Imported evidence | External HTML reports, zip files, screenshots, logs, generated scans, consultant readouts, prompts, and audit excerpts used as evidence inputs rather than source-of-truth code. |
| Third-party/vendor | Vendored packages, generated dependency trees, build artifacts, archives, or upstream code not owned by EXOCHAIN. |

Core, core runtime adapter, adjacent-surface, imported-evidence, and third-party/vendor work must be isolated unless the PR proves that a single validation boundary requires combining them.

Exit criterion: The path classification categories and isolation rule are explicit.

## Claim Boundaries

Future work must not claim production-ready, goal-ready, or end-to-end achieved status until every non-negotiable acceptance criterion has direct evidence.

Future work must not claim an adjacent surface is protected by EXOCHAIN constitutional enforcement unless the surface calls a verified core API and tests prove fail-closed behavior when the core API rejects, times out, or is unavailable.

Future work must not claim DAG DB is cheaper and better than raw context unless the benchmark and billing evidence required by the audit exists.

Future work must not claim GraphQL is a production integration surface while the default gateway refuses GraphQL and the feature remains explicitly unaudited.

Future work must not claim a live deployment is healthy from stale probe evidence.

Exit criterion: Forbidden success claims and trust-by-proximity claims are explicitly blocked.

## Evidence Required Before Success Claims

Direct evidence for any success claim must include at least one applicable artifact:

- Passing unit, integration, contract, end-to-end, security, privacy, reliability, or regression test output.
- Command output from repository guards or CI-equivalent checks.
- Release artifacts, signed tag evidence, SBOM or SLSA evidence, registry publication evidence, or deployment digest evidence where release or deployment is claimed.
- Current health, readiness, DB-health, canary, rollback, and monitoring evidence where production operation is claimed.
- Adversarial reviewer evidence for requirement, test, security, privacy, integration, and final assembly claims.

Plans, draft PRs, local demos, screenshots, narrative proof packets, imported logs, soft receipts, and stale measurements are not sufficient success evidence by themselves.

Exit criterion: The record names evidence that can support success claims and evidence that cannot support success claims alone.

## Requirement Change Process

Changing the frozen goal or any non-negotiable acceptance criterion requires a requirement-change proposal.

The requirement-change proposal must state:

1. Original requirement.
2. Proposed replacement.
3. Capability lost, narrowed, delayed, or altered.
4. Risk of changing the requirement.
5. Risk of not changing the requirement.
6. Required maintainer or governance approval.
7. Tests, docs, and evidence records that must change if accepted.

Until a requirement-change proposal is approved, execution continues against this frozen goal.

Exit criterion: Requirement changes are blocked unless the required proposal and approval path exist.

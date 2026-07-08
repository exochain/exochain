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

# Whole-System Adversarial Audit - 2026-07-08

## Scope

Repository: `https://github.com/exochain/exochain`

Audited commit: `2cf66b377d32fbdbba4228812ac8af29e0068c04`

Default branch at audit time: `origin/main`

Audit boundary: repository contents plus point-in-time probes to the live URL named by `README.md`. No prior project memory was used.

Evidence status labels:

- `EVIDENCED`: directly supported by source, docs, tests, local command output, or HTTP probe output.
- `INFERRED`: reasonably inferred from evidenced material.
- `ASSUMED`: planning assumption requiring verification.
- `UNKNOWN`: not determinable from available material.
- `CONTRADICTED`: conflicting evidence exists in the repository or local observations.

Exit criterion: The audited repository, commit, branch, scope, and evidence labels are explicit.

## Verification Commands Run

```bash
bash tools/repo_truth.sh
bash tools/test_repo_truth.sh
bash tools/test_gap_registry_truth.sh
bash tools/check_systemic_integrity_claims.sh
/usr/bin/curl -sS -m 15 -w '\nHTTP %{http_code}\n' https://exochain-production.up.railway.app/health
/usr/bin/curl -sS -m 15 -w '\nHTTP %{http_code}\n' https://exochain-production.up.railway.app/ready
/usr/bin/curl -sS -m 15 -w '\nHTTP %{http_code}\n' https://exochain-production.up.railway.app/health/db
```

Observed results:

- `tools/repo_truth.sh`: `31` crates, `469` Rust source files, `384772` Rust LOC, `6228` listed tests, `23` numbered CI gate jobs plus the required aggregator, `114` implemented / `3` partial / `2` planned traceability items, and `17` mitigated threats.
- `tools/test_repo_truth.sh`: passed.
- `tools/test_gap_registry_truth.sh`: passed.
- `tools/check_systemic_integrity_claims.sh`: passed.
- Live `health`, `ready`, and `health/db` probes timed out after `15` seconds from the audit environment and returned HTTP `000`.

Tests not run:

- Full Rust workspace tests.
- DB-backed integration tests.
- npm, vitest, Playwright, Python, and release workflow suites.
- Cryptographic review, penetration tests, external registry publication checks, and production canary drills.

Exit criterion: The commands actually run and the commands not run are both recorded.

## Executive Verdict

Overall status: Partially achieved under a strict repo-derived goal; unknown against an unstated user or business goal.

Overall score: `58/100` provisional for the strict repo-derived trust-fabric goal. The score is not a production certification.

Plain-English verdict: EXOCHAIN has substantial engineering work, explicit fail-closed patterns, a large Rust workspace, truth scripts, traceability material, threat coverage, and CI/release scaffolding. The whole system cannot honestly be called achieved or production-ready across all discovered surfaces. The strongest blockers are cross-surface contract drift, stale or conflicting production claims, UI and SDK paths that do not match the gateway router, adjacent-surface security/privacy risks, missing current production evidence, and several surfaces that are default-off, fail-closed, unaudited, or only partially wired.

Exit criterion: The audit verdict states current fit, score boundary, and the reason the system cannot be called fully achieved.

## Frozen System Goal

Strict inferred system-level goal: EXOCHAIN operates as a verifiable, privacy-preserving, production-credible trust fabric that supports identity adjudication, data sovereignty, deterministic finality, constitutional governance, agent/tool control, SDK/app integration, deployment operation, and user trust across evidenced surfaces.

Non-negotiable acceptance criteria:

1. Core invariants are enforced on every claim-producing path, not only in isolated library tests.
2. Browser, SDK, API, MCP, and deployment users can complete documented workflows without route mismatches, missing feature flags, or hidden local-only state.
3. Consent, authority, governance, receipt, finality, and provenance claims are backed by durable evidence and fail closed when that evidence is absent.
4. Adjacent surfaces cannot claim EXOCHAIN constitutional trust unless they call verified core APIs and pass adapter-boundary tests.
5. Sensitive-data surfaces preserve confidentiality, authorization, and failure visibility.
6. Production/readiness claims are current, reproducible, and tied to release artifacts, deployment digests, tests, logs, and monitoring.
7. Documentation, discovery, SDKs, OpenAPI or route inventories, MCP tools, and runtime routers agree.

Exit criterion: The inferred end goal and acceptance criteria are stated without weakening the repo's trust-fabric claims.

## Surface Inventory

| Surface | Classification | Status | Evidence | Criticality |
| --- | --- | --- | --- | --- |
| Rust workspace and core crates | EXOCHAIN core | EVIDENCED | `Cargo.toml`, `AGENTS.md`, `tools/repo_truth.sh` | P0 |
| `exo-gateway` REST API | Core runtime adapter | EVIDENCED | `crates/exo-gateway/src/server.rs` | P0 |
| DAG DB gateway runtime | Core runtime adapter | CONTRADICTED | `README.md`, `INTEGRATION.md`, `crates/exo-gateway/src/dagdb.rs` | P0 |
| `exo-node` runtime and AVC/economy APIs | EXOCHAIN core | EVIDENCED | `crates/exo-node/src/*` | P0 |
| MCP tools | Core runtime adapter | EVIDENCED | `crates/exo-node/src/mcp/*` | P1 |
| GraphQL gateway | Core runtime adapter | EVIDENCED | `crates/exo-gateway/Cargo.toml`, `crates/exo-gateway/src/graphql.rs` | P1 |
| Decision Forum web UI | Adjacent surface / adapter consumer | EVIDENCED | `web/src/lib/api.ts` | P0 |
| TypeScript SDK | Core runtime adapter | EVIDENCED | `packages/exochain-sdk/src/client.ts` | P1 |
| Python SDK | Core runtime adapter | EVIDENCED | `packages/exochain-py/exochain/client.py` | P1 |
| LYNK LLM proxy | Core runtime adapter / AI surface | EVIDENCED | `packages/exochain-llm-proxy/*` | P1 |
| CommandBase | Adjacent surface | EVIDENCED | `command-base/app/server.js`, `command-base/app/routes/settings.js` | P0 if exposed |
| LifeSafe | Adjacent surface | EVIDENCED | `livesafe/server/index.js`, `livesafe/server/routes/records.js` | P0 if in scope |
| Site and contact intake | Adjacent surface | EVIDENCED | `site/*` | P2 |
| Demo platform | Adjacent surface | EVIDENCED | `demo/*` | P3 |
| CI, release, deployment | EXOCHAIN core / operations | EVIDENCED | `.github/workflows/*`, `Dockerfile`, `docker-compose.yml`, `railway.json` | P0 |
| Docs, governance, proof packets | Governance artifacts | EVIDENCED / CONTRADICTED | `README.md`, `docs/*`, `governance/*`, `GAP-REGISTRY.md` | P0 |

Exit criterion: Each discovered surface is classified under `AGENTS.md` path categories and assigned a criticality.

## P0 Findings

| ID | Finding | Evidence status | Evidence | Required disposition |
| --- | --- | --- | --- | --- |
| P0-01 | The real target outcome was not supplied in the external audit prompt; success criteria were inferred from repository claims. | EVIDENCED | Audit input contained an unfilled `SYSTEM-LEVEL END GOAL` placeholder. | Add a frozen goal and acceptance criteria before implementation can claim success. |
| P0-02 | Gateway, web UI, SDKs, DAG DB docs, MCP tools, and adapters do not share a canonical route and contract source. | EVIDENCED | `web/src/lib/api.ts`, `packages/exochain-sdk/src/client.ts`, `packages/exochain-py/exochain/client.py`, `crates/exo-gateway/src/server.rs`, `crates/exo-gateway/src/dagdb.rs`. | Create generated route/contract inventory and fix consumers. |
| P0-03 | DAG DB production route claims are internally inconsistent. | CONTRADICTED | `README.md` and `INTEGRATION.md` claim five mounted routes; `crates/exo-gateway/src/dagdb.rs` mounts twelve. | Resolve source/docs/discovery/MCP/SDK route truth. |
| P0-04 | Decision Forum web calls gateway paths that are absent or differently named. | EVIDENCED | `web/src/lib/api.ts` vs `crates/exo-gateway/src/server.rs`. | Add web-gateway contract tests and repair route calls or gateway routes. |
| P0-05 | CommandBase has high-risk command construction, file-to-LLM disclosure, plaintext vault storage, local-auth bootstrap, and soft receipt behavior. | EVIDENCED | `command-base/app/server.js`, `command-base/app/routes/settings.js`, `command-base/app/services/cqi-orchestrator.js`. | Quarantine as adjacent and fix in a separate adjacent-surface hardening PR. |
| P0-06 | LifeSafe handles medical/emergency data while retaining privacy/security risks. | EVIDENCED | `livesafe/server/index.js`, `livesafe/server/routes/records.js`. | Quarantine as adjacent and fix in a separate LifeSafe privacy PR. |
| P0-07 | No current evidence proved production health, release publication, or full e2e operation. | EVIDENCED / UNKNOWN | Live probes timed out; `README.md` says no GitHub Release or crates.io publication verified. | Add release/deployment evidence gates and remove stale claims. |

Exit criterion: Every P0 finding is listed with evidence and a required disposition.

## P1 Findings

| ID | Finding | Evidence status | Evidence | Required disposition |
| --- | --- | --- | --- | --- |
| P1-01 | TypeScript SDK and Python SDK high-level methods call routes not evidenced in the gateway route table. | EVIDENCED | `packages/exochain-sdk/src/client.ts`, `packages/exochain-py/exochain/client.py`, `crates/exo-gateway/src/server.rs`. | SDK-gateway contract tests and implementation alignment. |
| P1-02 | GraphQL is default-refused because the feature is explicitly unaudited, while LifeSafe defaults to `/graphql`. | EVIDENCED | `crates/exo-gateway/Cargo.toml`, `crates/exo-gateway/src/graphql.rs`, `livesafe/server/utils/exochain-client.js`. | Either route LifeSafe to supported REST/AVC or audit GraphQL separately. |
| P1-03 | MCP and proof/governance claims are broader than current fail-closed or red-registry state. | EVIDENCED | `GAP-REGISTRY.md`, `crates/exo-node/src/mcp/*`. | Add bounded language and mutation/effect tests before capability claims. |
| P1-04 | Documentation metrics and gate counts drift from generated truth. | CONTRADICTED | `docs/INDEX.md`, `README.md`, `tools/repo_truth.sh`. | Generate or guard docs truth. |
| P1-05 | Production proof packets rely on imported/narrative evidence and local proof paths. | EVIDENCED | `docs/proof/*`, `docs/dagdb/full-migration/*`. | Require raw artifact hashes, workflow run IDs, and deployment digests. |
| P1-06 | Adjacent Node package hygiene does not cover CommandBase. | EVIDENCED | `command-base/app/package.json`, `tools/test_npm_core_package_hygiene.sh`, `.github/workflows/ci.yml`. | Add adjacent-package hygiene gate or quarantine policy. |

Exit criterion: Every P1 finding is listed with evidence and a required disposition.

## Goalpost Movement Findings

1. Do not treat Rust workspace test counts as proof of whole-system readiness.
2. Do not treat fail-closed unavailable paths as capability completion.
3. Do not treat local demos, local proofs, imported proof packets, or narrative logs as production proof.
4. Do not treat DAG DB compression as proof of cheaper-and-better agent memory; the repository states that thesis is not accepted.
5. Do not treat adjacent apps as constitutionally protected by proximity.
6. Do not treat GraphQL as an available production integration path while the default gateway refuses it.
7. Do not claim production deployment health from a 2026-05-09 probe without current evidence.

Exit criterion: The audit identifies the goalpost movement patterns that future PRs must avoid.

## Required Remediation Themes

1. Freeze the system goal and acceptance criteria.
2. Generate or enforce a single route and contract source of truth.
3. Repair gateway, web, SDK, MCP, and DAG DB contract drift.
4. Fix CommandBase security and receipt-durability risks in an adjacent-surface PR.
5. Fix LifeSafe privacy/security risks in an adjacent-surface PR.
6. Add release, deployment, live-health, and evidence freshness gates.
7. Add observability and failure visibility for soft or async trust paths.
8. Keep core, runtime-adapter, adjacent-surface, deployment, and documentation work isolated unless a single validation boundary requires combining them.

Exit criterion: The audit's required remediation themes are stated as implementation-planning inputs.

## Final Truthful Progress Statement

EXOCHAIN currently has a substantial Rust core, explicit safety-oriented design in several paths, many listed tests, and useful truth-check scripts, but the repository does not prove a successful whole system. The current evidence supports "partially implemented with strong core foundations and serious integration, documentation, deployment, and adjacent-surface security gaps"; it does not support "production-ready trust fabric" or "end-to-end goal achieved."

Exit criterion: The final progress statement avoids production-readiness, goal-achievement, and trust-by-proximity overclaims.

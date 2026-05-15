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

# Gauntlet Secrets and Config Validation - 2026-05-15

This record validates selected Wally Fipps Gauntlet secrets/configuration
findings against current `main`. The source artifacts remain imported evidence
and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`
- `/Users/bobstewart/Library/Mobile Documents/com~apple~CloudDocs/Exochain-audit-report-run2.html`

Validation target:

- branch: `main`
- commit: `068468e8a6876a406b6317ba8e7ed14adf45d626`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `docker-compose.yml` | Core runtime adapter | Local EXOCHAIN gateway/API compose contract with required runtime secrets. |
| `docker-compose.ci.yml` | Core runtime adapter | CI-only Postgres fixture using isolated test credentials. |
| `.github/workflows/ci.yml` | EXOCHAIN core | Gate 9 hygiene and adjacent demo secret-boundary source guard. |
| `.gitignore` | EXOCHAIN core | Repo hygiene boundary for local env files and generated artifacts. |
| `crates/exo-node/src/auth.rs`, `crates/exo-node/src/main.rs` | Core runtime adapter | Admin bearer-token generation, persistence, and startup logging. |
| `tools/sybil-cli/graph_schema.py` | EXOCHAIN core support tool | Sybil graph tooling used by governance analysis. |
| `demo/packages/shared/` | Adjacent surface | Prototype demo shared DB helper; not canonical EXOCHAIN core. |
| `demo/services/audit-api/` | Adjacent surface | Prototype demo audit API; validates protected governance writes locally. |
| `demo/EXOCHAIN_SURFACE_INTAKE.md` | Adjacent-surface intake | Ownership, trust boundary, secret inventory, test command, and CI gate for `demo/`. |
| `command-base/` | Adjacent surface | CommandBase is not covered by this demo-focused adjacent remediation commit. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-012 hardcoded DB password in root compose | Stale / already remediated | `docker-compose.yml` requires `POSTGRES_PASSWORD` through `${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD...}`. The literal `test` password appears only in `docker-compose.ci.yml`, which is explicitly CI-only and paired with the Gate 13 test database URL. |
| F-013 JWT secret soft fallback in root compose | Stale / already remediated | `docker-compose.yml` requires `JWT_SECRET` and `LIVESAFE_JWT_SECRET` through fail-fast compose guards rather than development defaults. |
| F-014 DB connection string fallback in demo package | Reproduced and remediated | `demo/packages/shared/src/index.js` no longer embeds `postgres://exochain:exochain_dev@localhost:5432/exochain` or any `DATABASE_URL ||` fallback. `getPool()` now fails closed when `DATABASE_URL` is missing or blank. |
| F-015 Neo4j password literal in `sybil-cli` | Stale / already remediated | `tools/sybil-cli/graph_schema.py` reads `NEO4J_URI`, `NEO4J_USERNAME`, and `NEO4J_PASSWORD` from required environment variables and fails closed when any are missing. |
| F-016 `GOVERNANCE_API_TOKEN` degrades to open | Stale / already remediated for the checked demo route | `demo/services/audit-api` stores a missing token as `null` and rejects protected governance writes unless the bearer token matches the configured runtime secret. |
| F-017 `.gitignore` missing `.env` exclusion | Stale / already remediated | `.gitignore` excludes `.env` and `*.env.local`; Gate 9 rejects tracked env files except examples. |
| F-018 admin bearer token logged plaintext | Stale / already remediated | Node startup stores the admin token in zeroizing storage, writes it through the restrictive auth writer, and source guards reject logging even partial token material. |
| F-019 changelog claims A-043 fix without matching code | Stale / already remediated | The A-043 changelog entry matches current root compose fail-fast secret guards and the current `.env` hygiene rule. |
| F-020 webhook secret seeded as empty string | Adjacent CommandBase finding, not remediated in this commit | Current matches are under `command-base/`, which is adjacent surface code with a separate intake. This branch did not blend CommandBase changes with the demo DB fallback fix. |

## Commands Run

All commands below completed with exit code 0 unless explicitly noted.

```bash
node --test demo/packages/shared/src/index.test.js
bash tools/test_demo_shared_secret_boundaries.sh
bash tools/test_sybil_cli_secret_boundaries.sh
cargo test -p exo-node admin_token -- --nocapture
node --test command-base/app/lib/auth.security.test.js
npm --prefix demo test -- --project services services/audit-api/src/index.test.js
git ls-files '*.env' '.env*'
```

`node --test demo/packages/shared/src/index.test.js` was first run before the
production change and failed because `getPool()` did not throw when
`DATABASE_URL` was absent. The same command passed after removing the fallback.

The first sandboxed run of the demo audit-api Vitest command failed with
`listen EPERM` while binding an ephemeral local port. The same command passed
when rerun with local bind permission.

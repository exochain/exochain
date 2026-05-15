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

# Gauntlet Deploy Readiness Validation - 2026-05-15

This record preserves the current-main disposition for Wally Fipps Gauntlet
F-075. The source artifacts remain imported evidence and were not committed as
source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `ade233c3ae472c1dc1cbd4a81b88f77c3e66cb73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `Dockerfile` | Core runtime adapter | Production container contract for the node/gateway binary. |
| `deploy/Dockerfile.node` | Core runtime adapter | Single-binary node deployment image contract. |
| `railway.json` | Core runtime adapter | Railway production deployment health-check contract. |
| `tools/test_deployment_readiness_probes.sh` | Core runtime adapter | Source guard for deployment readiness probes. |
| `crates/exo-gateway/src/server.rs` | Core runtime adapter | `/health`, `/ready`, and `/health/db` runtime behavior. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Disposition

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-075 deploy health checks use `/health` instead of dependency-validating `/ready` | Stale / already remediated | `railway.json` sets `"healthcheckPath": "/ready"`, `Dockerfile` and `deploy/Dockerfile.node` probe `/ready`, and `tools/test_deployment_readiness_probes.sh` rejects production health checks that target `/health`. Runtime tests prove `/ready` and `/health/db` return 503 when no DB pool is configured. |

## Commands Run

All commands below completed with exit code 0.

```bash
bash tools/test_deployment_readiness_probes.sh
cargo test -p exo-gateway ready_without_db_returns_503 -- --nocapture
cargo test -p exo-gateway health_db_without_pool_returns_503 -- --nocapture
```

## Notes

No production code change was required because the reported liveness-only deploy
probe configuration did not reproduce against current `main`.

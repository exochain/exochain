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

# Gauntlet Runtime Hardening Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet runtime hardening findings. The source artifacts remain imported
evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `28e8e8c7cba64633b8de31b39af7bc1701801c73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-gateway/src/server.rs` | Core runtime adapter | External HTTP gateway around core adjudication, auth, readiness, rate limiting, headers, and TLS startup. |
| `crates/exo-node/src/main.rs` | Core runtime adapter | Production node process supervision and startup orchestration. |
| `crates/exo-consent/src/gatekeeper.rs` | EXOCHAIN core | Consent enforcement and access-audit state. |
| `crates/exo-node/src/mcp/tools/messaging.rs` | Core runtime adapter | MCP encrypted-message tool boundary. |
| `Dockerfile`, `railway.json` | Core runtime adapter | Production deployment contract for node/gateway readiness and DB-enabled gateway binary. |
| `tools/test_docker_production_db_feature.sh`, `tools/test_deployment_readiness_probes.sh` | CI gate | Source guards for deployment feature flags and readiness probes. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-059 No rate limiting on Rust gateway | Stale / already remediated | `GatewayRateLimiter` is wired through `apply_gateway_layers`, uses deterministic `BTreeMap` state, derives time from the gateway HLC path, keys clients from socket `ConnectInfo<SocketAddr>`, and returns `429` with `Retry-After` when the configured window is exceeded. Extra merged routes receive the same layers. |
| F-082 Background tasks fire-and-forget | Stale / already remediated | Node startup uses `BackgroundTasks` backed by `tokio::task::JoinSet`, registers critical tasks with `spawn_critical`, reports panic or unexpected exit through `next_failure`, and races task failure against HTTP serving in `tokio::select!`. The production-source guard rejects raw `tokio::spawn(` in startup. |
| F-114 TLS config ignored, plain TCP | Stale / already remediated | Gateway startup validates TLS paths, installs the Rustls ring crypto provider, loads PEM material with `RustlsConfig::from_pem_file`, and binds TLS with `axum_server::bind_rustls` whenever `tls_config` is present. Plain TCP remains only for absent TLS config. |
| F-116 No gateway security headers | Stale / already remediated | `attach_gateway_security_headers` is installed in `apply_gateway_layers` and sets `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`, and `Permissions-Policy` on gateway responses. |
| F-141 ConsentGate does not emit AccessLogged before release | Stale / already remediated | `ConsentGate::check` appends a durable `ConsentAccessLogEntry` before returning the decision, and snapshots preserve access-log sequence state across restore. |
| F-162 Hash substituted for encryption | Stale / already remediated | MCP messaging tools now fail closed with `mcp_messaging_delivery_unavailable` until real storage, key resolution, and transport are attached. Send, receive, and death-trigger paths do not hash plaintext, do not return delivery-shaped success, and do not reflect raw plaintext in error output. |
| F-168 Dockerfile missing production-db | Stale / already remediated | The production Dockerfile builds `exo-gateway` with `--features exo-gateway/production-db`; Railway and Docker health checks use `/ready`, so DB dependency failures stop rollout. |

## Commands Run

All commands below completed with exit code 0.

```bash
git fetch --prune
git pull --ff-only
cargo test -p exo-gateway gateway_rate_limit -- --nocapture
cargo test -p exo-gateway gateway_layers_attach_security_headers -- --nocapture
cargo test -p exo-gateway tls -- --nocapture
cargo test -p exo-node background_task -- --nocapture
cargo test -p exo-consent access_log -- --nocapture
cargo test -p exo-node encrypted -- --nocapture
bash tools/test_docker_production_db_feature.sh
bash tools/test_deployment_readiness_probes.sh
git diff --check
```

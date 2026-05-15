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

# Gauntlet Resilience Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet resilience findings. The source artifacts remain imported evidence and
were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `19137fabfe470972e756bfd9319d9bef9be2c90b`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-gateway/src/db.rs` | Core runtime adapter | PostgreSQL pool initialization, migration, and bounded database access. |
| `crates/exo-node/src/telegram.rs` | Core runtime adapter | Operator Telegram adjutant transport and polling loop. |
| `crates/exo-node/src/main.rs` | Core runtime adapter | Node startup configuration and consensus reactor wiring. |
| `crates/exo-node/src/sentinels.rs` | Core runtime adapter | Runtime liveness and health sentinel checks. |
| `crates/exo-node/src/network.rs` | Core runtime adapter | P2P gossipsub publish boundary. |
| `crates/exo-node/src/challenges.rs` | Core runtime adapter | Challenge/dispute HTTP store access boundary. |
| `crates/exo-gatekeeper/src/combinator.rs` | EXOCHAIN core | Deterministic combinator reduction and timeout-budget enforcement. |
| `crates/exo-node/src/holons.rs` | Core runtime adapter | Default-off Holon runtime manager configuration. |
| `command-base/...` | Adjacent surface | CommandBase logging findings are not EXOCHAIN core and are not covered by this core/runtime-adapter record. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-081 `init_pool` panics on DB failure | Stale / already remediated | Gateway `init_pool` returns `Result<PgPool, DbInitError>`, maps connect and migration failures into typed errors, avoids `expect`, and logs success through `tracing`. |
| F-083 Telegram `reqwest::Client` has no global timeout | Stale / already remediated | `Adjutant::new` builds the HTTP client with `reqwest::Client::builder()` and `TELEGRAM_HTTP_TIMEOUT_SECS`. |
| F-084 reactor round timeout fixed at 5 seconds with no stall detection | Stale / already remediated for the reported fixed-timeout path | Node CLI accepts bounded `--round-timeout-ms` for `start` and `join`; startup wires the configured value into `ReactorConfig`; liveness sentinel tests detect stalled consensus rounds after a baseline. |
| F-085 challenge-store `lock().unwrap()` reachable in production handlers | Stale / already remediated | Challenge handlers route store access through `with_challenge_store_blocking`, map poisoned locks to `500`, and a source guard rejects direct `.lock()` in async handlers. |
| F-086 no retry on P2P gossipsub publish | Stale / already remediated | `NetworkHandle::publish` retries through `NETWORK_PUBLISH_MAX_ATTEMPTS`, waits for acknowledgement with `NETWORK_PUBLISH_ACK_TIMEOUT_MS`, and reports the final network-layer failure. |
| F-087 `Combinator::Timeout` is only decorative | Stale / already remediated for deterministic runtime semantics | Timeout is enforced as a deterministic reduction-unit budget and rejects inner reductions that exceed the configured budget. It deliberately does not read wall-clock time. |
| F-088 database pool has no explicit timeout | Stale / already remediated | Gateway pool initialization sets `.acquire_timeout(Duration::from_secs(DB_POOL_ACQUIRE_TIMEOUT_SECS))`, bounding waits for pooled or newly opened SQLx connections. |
| F-089 `HolonManagerConfig::default()` uses `expect` for hardcoded DIDs | Stale / already remediated | Production Holon runtime is default-off and source guards reject `impl Default for HolonManagerConfig` and default authority keypair helpers in production code. |
| F-091 Telegram poll loop has no backoff | Stale / already remediated | Failed Telegram polls are distinguished from successful empty long-poll responses and sleep for `TELEGRAM_POLL_FAILURE_BACKOFF_MS` before retry. |

## Commands Run

All commands below completed with exit code 0.

```bash
git pull --ff-only origin main
cargo test -p exo-gateway init_pool -- --nocapture
cargo test -p exo-gateway pool_initialization_sets_explicit_connection_acquire_timeout -- --nocapture
cargo test -p exo-node adjutant -- --nocapture
cargo test -p exo-node round_timeout -- --nocapture
cargo test -p exo-node liveness_check -- --nocapture
cargo test -p exo-node network_handle_publish -- --nocapture
cargo test -p exo-node challenge_async_handlers_use_blocking_store_access -- --nocapture
cargo test -p exo-gatekeeper timeout_rejects_inner_reduction_over_deterministic_budget -- --nocapture
```

## Notes

F-082 is tracked in the runtime-hardening validation slice. F-090 references
CommandBase adjacent-surface logging and should remain isolated from EXOCHAIN
core remediation unless that surface receives a complete intake record.

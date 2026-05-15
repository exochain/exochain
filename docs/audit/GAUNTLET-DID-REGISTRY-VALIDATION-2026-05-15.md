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

# Gauntlet DID Registry Validation - 2026-05-15

This record preserves the current-main disposition for Wally Fipps Gauntlet
F-053. The source artifacts remain imported evidence and were not committed as
source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `b169c9cb8008ffcab7fd0870a3a80018c85193ba`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-identity/src/registry.rs` | EXOCHAIN core | DID registry trait, local bounded cache, proof verification, and registry invariants. |
| `crates/exo-identity/src/error.rs` | EXOCHAIN core | Typed registry-capacity error boundary. |
| `crates/exo-gateway/src/server.rs` | Core runtime adapter | Runtime DID registration and lookup path. |
| `crates/exo-gateway/src/db.rs` | Core runtime adapter | PostgreSQL DID document persistence helpers and migration source guards. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Disposition

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-053 `LocalDidRegistry` is in-memory with no DB backing and grows without bound | Stale / already remediated | `LocalDidRegistry` has `MAX_LOCAL_DID_REGISTRY_DOCUMENTS` and returns `IdentityError::RegistryCapacityExceeded` when full. Gateway registration persists through `db::insert_did_document` when `AppState` has a PostgreSQL pool, then caches locally; source guards reject auth/register paths that write only to `LocalDidRegistry`. The gateway also tests the local-capacity 503 fallback for no-DB mode. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-identity registry_capacity -- --nocapture
cargo test -p exo-identity registry -- --nocapture
cargo test -p exo-gateway db_configured_identity_paths_do_not_depend_on_local_did_memory -- --nocapture
cargo test -p exo-gateway did_documents_have_durable_schema_and_persistence_helpers -- --nocapture
cargo test -p exo-gateway auth_register_returns_503_when_local_did_registry_capacity_is_exhausted -- --nocapture
```

## Notes

No production code change was required because the reported unbounded,
memory-only registry failure did not reproduce against current `main`.

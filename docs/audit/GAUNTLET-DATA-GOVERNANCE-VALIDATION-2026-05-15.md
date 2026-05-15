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

# Gauntlet Data Governance Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet data-integrity and data-governance findings. The source artifacts
remain imported evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `70528116c7997f5f4ca96a9d54c6b4e6541f2fa1`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-dag/src/pg_store.rs`, `crates/exo-dag/migrations/*` | EXOCHAIN core | PostgreSQL-backed DAG store and committed-height persistence. |
| `crates/exo-gateway/src/db.rs`, `crates/exo-gateway/migrations/*` | Core runtime adapter | Production DB adapter for users, decisions, audit entries, identity erasure, consent records, and scan receipts. |
| `crates/exo-consent/src/gatekeeper.rs` | EXOCHAIN core | Consent gate state, revocation log, access log, and snapshot restore boundary. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-046 `mark_committed` TOCTOU race | Stale / already remediated | `PostgresStore::mark_committed` performs one atomic `INSERT ... SELECT ... WHERE EXISTS` statement and maps `rows_affected() == 0` to `DagError::NodeNotFound`; no separate `contains` preflight remains. |
| F-047 Parent byte array panic on wrong length | Stale / already remediated | PostgreSQL DAG hash and parent decoding uses `<[u8; 32]>::try_from` and returns a store error on wrong-width storage instead of panicking via `copy_from_slice`. |
| F-048 Schema management gaps | Stale / already remediated | `PostgresStore::migrate` uses `sqlx::migrate!("./migrations")`; DAG tables are in `crates/exo-dag/migrations/20260515000001_create_dag_postgres_store.sql`, and gateway audit tables/indexes are tracked in gateway migrations. |
| F-049 `insert_decision` / `upsert_decision` duplication | Stale / already remediated | Current write helpers split create-vs-upsert semantics: `create_decision` uses `ON CONFLICT (tenant_id, id_hash) DO NOTHING` and reports `AlreadyExists`, while upsert paths update only the tenant-scoped record. |
| F-050 `update_decision` discards `PgQueryResult` | Stale / already remediated | `update_decision` inspects `rows_affected()` and returns `DecisionUpdateError::MissingDecision` when no tenant-scoped row matches. |
| F-051 list decisions/users return all rows unscoped | Stale / already remediated | `list_users_db`, `list_agents_db`, `list_decisions_db`, `find_decision`, and write helpers require `tenant_id`, bind it before row limits, and use tenant-scoped predicates. |
| F-052 `ConsentGate` in-memory only, revocations lost on restart | Stale / already remediated at the current owned boundary | `ConsentGateSnapshot` carries revoked bailment IDs, revocation logs, access logs, and sequence counters; restore filters stale revoked registrations and prevents revoked bailment replay. Runtime gateway consent adjudication loads active consent rows from PostgreSQL rather than relying on an opaque process-local `ConsentGate`. |
| F-054 identity erasure only clears in-memory state | Stale / already remediated | `erase_gateway_identity` tombstones DID documents and deletes user, agent, session, identity score, enrollment, LifeSafe, scan receipt, consent, authority, delegation, dashboard, feedback, and conflict rows in one transaction. |
| F-056 scan receipt location stored without consent | Stale / already remediated | `insert_scan_receipt` rejects nonzero latitude/longitude writes unless an active `scan.location` consent record exists for the subject and subscriber. |
| F-057 password hash and salt returned in user rows | Stale / already remediated | Public user lookup/list APIs return `PublicUserRow` and select only non-secret columns; source guards reject selecting `password_hash` or `salt` in those APIs. |

## Commands Run

All commands below completed with exit code 0.

```bash
git fetch --prune
git pull --ff-only
cargo test -p exo-dag --features postgres pg_store -- --nocapture
cargo test -p exo-gateway tenant_scope -- --nocapture
cargo test -p exo-gateway missing_rows -- --nocapture
cargo test -p exo-gateway password_material -- --nocapture
cargo test -p exo-gateway identity_erasure -- --nocapture
cargo test -p exo-gateway location_consent -- --nocapture
cargo test -p exo-gateway load_consent_records -- --nocapture
cargo test -p exo-consent snapshot -- --nocapture
cargo test -p exo-gateway create_decision_inserts_once_without_upsert_overwrite -- --nocapture
git diff --check
```

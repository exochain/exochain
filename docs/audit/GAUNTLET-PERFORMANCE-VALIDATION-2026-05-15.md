# GAUNTLET Performance Validation - 2026-05-15

## Scope

Imported evidence:

- `/Users/bobstewart/Downloads/Exochain Gauntlet Findings.zip`
- `/Users/bobstewart/Library/Mobile Documents/com~apple~CloudDocs/Exochain-audit-report-run2.html`

The imported evidence was treated as untrusted hypothesis data. No imported
report, archive, screenshot, or generated scanner output is committed by this
remediation.

## Path Classification

| Path | Classification | Notes |
| --- | --- | --- |
| `crates/exo-gateway/src/graphql.rs` | Core runtime adapter | GraphQL resolver surface for gateway governance reads and disabled mutation scaffolding. |
| `crates/exo-gateway/src/db.rs` | Core runtime adapter | Database helper and migration source guards for gateway runtime queries. |
| `crates/exo-gateway/migrations/*.sql` | Core runtime adapter | Production database query-index contract. |
| `crates/exo-dag/src/dag.rs` | EXOCHAIN core | DAG verification and ancestry logic. |
| `crates/exo-consensus/src/session.rs` | EXOCHAIN core | Deliberation round finalization logic. |
| `docs/audit/GAUNTLET-PERFORMANCE-VALIDATION-2026-05-15.md` | EXOCHAIN core governance artifact | Triage and verification record. |

## Findings

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-094 GraphQL AppState behind single mutex | Remediated in this branch | `SharedGraphqlState` is now `Arc<AsyncRwLock<AppState>>`; query/subscription paths use read guards and mutation paths use write guards. The HLC is isolated behind a small internal `StdMutex<HybridClock>` because `HybridClock` is `Send` but not `Sync`; that lock is not the shared GraphQL state bottleneck and is used only for timestamp generation. |
| F-095 `verify_node` calls `ancestors()` full BFS per verification | Stale / already remediated | `verify_node_cycle_check_does_not_materialize_full_ancestor_list` proves `verify_node` no longer calls `ancestors(dag, &node.hash)` or scans a materialized ancestor vector. |
| F-096 scan/consent/trustee list helpers unbounded | Stale / already remediated | `fetch_all_database_helpers_have_explicit_row_limits` proves all reviewed `fetch_all` helpers, including `list_scan_receipts`, `list_consent_anchors`, and `list_trustee_shards`, bind `MAX_DB_LIST_ROWS`. |
| F-097 `execute_round` clones full rounds vector on finalize | Stale / already remediated | `production_finalization_moves_rounds_without_cloning_full_history` proves `DeliberationSession::finalize` consumes the session and does not clone the full round history. |
| F-098 missing database indexes | Stale / already remediated | `gateway_runtime_query_filters_have_migration_indexes` proves runtime query filters have migrations for tenant, decision, delegation, and audit indexes. |
| F-099 GraphQL decisions query scans all in-memory records | Remediated in this branch | `AppState` now maintains deterministic tenant and tenant+status `BTreeSet` indexes, and the `decisions` resolver calls `decision_ids_for_query` before pagination instead of scanning `decisions.values()`. |

## TDD Evidence

Red tests before implementation:

```text
cargo test -p exo-gateway graphql_app_state_uses_reader_writer_lock_not_single_mutex -- --nocapture
```

Failed as expected because current `main` still exposed `Arc<Mutex<AppState>>`.

```text
cargo test -p exo-gateway graphql_decisions_query_uses_tenant_indexes_before_pagination -- --nocapture
```

Failed as expected because current `main` did not maintain tenant/status decision indexes and the resolver scanned `decisions.values()`.

Green validation after implementation:

```text
cargo test -p exo-gateway graphql_ -- --nocapture
cargo test -p exo-gateway decision_indexes_scope_queries_by_tenant_and_status -- --nocapture
cargo test -p exo-gateway --features unaudited-gateway-graphql-api query_decisions_clamps_oversized_offset -- --nocapture
cargo test -p exo-dag verify_node_cycle_check_does_not_materialize_full_ancestor_list -- --nocapture
cargo test -p exo-gateway fetch_all_database_helpers_have_explicit_row_limits -- --nocapture
cargo test -p exo-gateway gateway_runtime_query_filters_have_migration_indexes -- --nocapture
cargo test -p exo-gateway user_and_decision_list_queries_require_tenant_scope -- --nocapture
cargo test -p exo-consensus production_finalization_moves_rounds_without_cloning_full_history -- --nocapture
cargo test -p exo-gateway
cargo test -p exo-gateway --features unaudited-gateway-graphql-api graphql_ -- --nocapture
cargo clippy -p exo-gateway --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

All commands exited successfully. `cargo fmt` emits stable-toolchain warnings
for nightly-only `rustfmt.toml` options, but exits zero.

## Bypass Search

- Sibling GraphQL query resolvers now take read guards and still call the
  default-off execution guard.
- GraphQL mutation resolvers still fail closed before state mutation unless the
  unaudited feature is explicitly enabled, and write paths now update decision
  indexes when inserting decisions or changing decision status.
- Database-backed gateway list helpers remain tenant scoped and row limited;
  this GraphQL in-memory index remediation does not change the DB contract.
- No adjacent surfaces were changed.

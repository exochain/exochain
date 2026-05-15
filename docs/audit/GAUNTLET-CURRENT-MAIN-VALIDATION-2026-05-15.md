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

# Gauntlet Current-Main Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet findings that were re-verified after syncing `main` on 2026-05-15.
The source artifacts remain imported evidence and were not committed as source
files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `3acbb19cbaaa5a2382fd847b15fc6aeed0d0ba73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-core/`, `crates/exo-authority/`, `crates/exo-dag/` | EXOCHAIN core | Cryptographic, BCTS, authority, and DAG enforcement. |
| `crates/exo-gatekeeper/` | EXOCHAIN core | Constitutional invariant kernel and BCTS adjudication adapter. |
| `crates/exo-gateway/`, `crates/exo-node/src/mcp/` | Core runtime adapter | Exposes core trust decisions through HTTP, GraphQL, DB, and MCP paths. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-021 DAG append skips signature/CGR proof verification | Stale / already remediated for current DAG append model | `validated_append` verifies canonical hash, parent existence, creator public key resolution, and creator signature. The reported PROVEN-event CGR field does not exist in the current `DagNode` model. |
| F-022 BFT vote signatures not verified | Stale / already remediated | Production reactor paths use verified proposal/vote/commit APIs; legacy unchecked APIs are test-only and deprecated. |
| F-023 `Signature::as_bytes()` returns zero sentinel | Stale / already remediated | `Signature::as_bytes()` panics for Empty, PostQuantum, and Hybrid, and callers have fallible / algorithm-aware alternatives. |
| F-031 MCP CGR proof verifier reports success without verification | Stale / already remediated | `exochain_verify_cgr_proof` refuses hash-only claims until proof bytes, public inputs, checkpoint roots, validator signatures, and a production verifier are wired. |
| F-034 BCTS transition bypasses kernel adjudication | Stale / already remediated | BCTS transitions invoke a `BctsTransitionAdjudicator` before HLC consumption or state mutation; gatekeeper provides `KernelBctsAdjudicator`. |
| F-045 corrupt signature decode silently becomes `Signature::Empty` | Stale / already remediated | PostgreSQL DAG signature decoding returns an error on invalid stored bytes. |
| F-092 audit trail unbounded | Stale / already remediated | Audit lookup is scoped by `decision_id` and `tenant_id`, ordered, and limited by `MAX_DB_LIST_ROWS`. |
| F-093 / F-096 list helpers unbounded | Stale / already remediated | Fetch-all list helpers use explicit SQL `LIMIT` clauses and bind `MAX_DB_LIST_ROWS`. |
| F-103 empty authority chain grants permission | Stale / already remediated | `verify_chain` rejects empty chains; `has_permission` returns `false` for empty chains before any `.all()` evaluation. |
| F-104 negative persisted timestamp casts to large unsigned value | Stale / already remediated | PostgreSQL DAG timestamp decode uses checked conversions and rejects negative storage values. |
| F-112 GraphQL Playground exposed in production | Stale / already remediated | GraphQL is default-off unless `unaudited-gateway-graphql-api` is explicitly enabled; router source guards reject playground HTML wiring. |
| F-113 GraphQL lacks depth/introspection limits | Stale / already remediated | Executable schema builder disables introspection and sets depth and complexity limits. |
| F-132 non-HLC runtime timestamps | Stale / already remediated for checked core/runtime paths | Focused source guards reject direct wall-clock usage in exo-node/exo-gateway runtime paths. |
| F-030 / F-032 old proof/anchor stubs | Current path not found | The reported `proof.rs` / `anchor.rs` paths and named types were not present as current owned Rust source. |

## Commands Run

All commands below completed with exit code 0.

```bash
git fetch origin --prune
git pull --ff-only
cargo test -p exo-core transition_invokes_adjudicator_before_state_mutation -- --nocapture
cargo test -p exo-core transition_supplies_canonical_request_to_adjudicator -- --nocapture
cargo test -p exo-core transition_source_invokes_adjudicator_before_hlc_and_mutation -- --nocapture
cargo test -p decision-forum full_lifecycle_adjudicated_at_each_transition -- --nocapture
cargo test -p decision-forum denied_forum_decision_correlates_with_kernel_denial -- --nocapture
cargo test -p exo-core signature -- --nocapture
cargo test -p exo-dag --features postgres decode_signature_rejects_invalid_stored_bytes -- --nocapture
cargo test -p exo-authority has_permission_empty_chain -- --nocapture
cargo test -p exo-authority verify_empty_chain -- --nocapture
cargo test -p exo-dag --features postgres decode_timestamp_rejects_negative_storage_values -- --nocapture
cargo test -p exo-node default_runtime_sources_do_not_read_wall_clock_directly -- --nocapture
cargo test -p exo-node production_source_has_no_float_wall_clock_or_hashset_escape_hatches -- --nocapture
cargo test -p exo-gateway gateway_server_runtime_sources_do_not_read_wall_clock_directly -- --nocapture
cargo test -p exo-gateway gateway_rate_limit_source_uses_hlc_btreemap_and_socket_identity -- --nocapture
cargo test -p exo-gateway gateway_vote_audit_path_does_not_call_chrono_utc_now -- --nocapture
cargo test -p exo-gateway spline_compiled_rust_sources_do_not_use_float_or_wall_clock_time -- --nocapture
cargo test -p exo-gateway graphql_schema_builder_disables_introspection_and_limits_query_cost -- --nocapture
cargo test -p exo-gateway graphql_router_does_not_expose_playground_html -- --nocapture
cargo test -p exo-gateway graphql_post_default_off_returns_403_with_initiative -- --nocapture
cargo test -p exo-gateway --features unaudited-gateway-graphql-api schema_introspection_queries_are_disabled -- --nocapture
cargo test -p exo-gateway --features unaudited-gateway-graphql-api schema_rejects_queries_over_complexity_limit -- --nocapture
cargo test -p exo-node execute_verify_cgr_proof_refuses_hash_only_claims -- --nocapture
cargo test -p exo-node execute_verify_cgr_proof_refusal_does_not_echo_caller_inputs -- --nocapture
cargo test -p exo-gateway fetch_all_database_helpers_have_explicit_row_limits -- --nocapture
cargo test -p exo-gateway user_and_decision_list_queries_require_tenant_scope -- --nocapture
cargo test -p exo-gateway audit_entry_lookup_requires_decision_and_tenant_scope -- --nocapture
```

## Next Triage Targets

Continue with live-current verification before edits:

- GraphQL/REST authentication and authorization findings not covered by default-off guards.
- Adjacent-surface trust-claim intake records for any deployed non-core surfaces.
- Remaining high-confidence core cryptographic verification reports that still map to current owned paths.

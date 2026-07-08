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

# EXOCHAIN WASM Integration Contract

## Overview

The EXOCHAIN WASM bridge compiles the Rust constitutional trust fabric into a
WebAssembly package for JavaScript consumers. The current public bridge is
source-counted by CI Gate 22 at **157 Rust `#[wasm_bindgen]` exports** and
smoke-tested by the Node bridge verification harness before the aggregator gate
can pass.

The bridge is a core runtime adapter. Consumers may present EXOCHAIN trust
claims only when they call the relevant WASM or core API path and tests prove
fail-closed behavior when the adapter rejects, times out, or is unavailable.

## Source And Artifacts

- Rust source: `crates/exochain-wasm/src/`
- Generated Node package: `packages/exochain-wasm/wasm/`
- Bridge verification harness: `packages/exochain-wasm/test/bridge_verification.mjs`
- CI gates: `.github/workflows/ci.yml` Gates 20, 21, and 22

## Verification

```bash
cargo test -p exochain-wasm
wasm-pack build crates/exochain-wasm --target nodejs --out-dir ../../packages/exochain-wasm/wasm
node packages/exochain-wasm/test/bridge_verification.mjs
```

## Adapter Boundary

WASM consumers must not mint, cache, or simulate consent, authority,
provenance, governance outcomes, settlement authority, or constitutional
invariant results outside the Rust adapter. Adjacent surfaces such as
CommandBase and ExoForge remain adjacent unless the runtime path invokes the
tested adapter and the surface has its own fail-closed tests.

## Governance Monitoring Attestation

Continuous governance monitoring uses the Rust governance-monitor verifier
through the WASM bridge:

- `wasm_governance_findings_digest(findings_json)` computes the canonical
  findings digest.
- `wasm_verify_governance_attestation(signer_did, findings_json,
  signature_json, signer_public_key_hex)` verifies that the signed envelope
  matches the submitted findings before ingestion.

The audit API rejects missing, mismatched, or invalid attestations before any
database write. This completes the T-14 adapter path and aligns the threat
matrix with the implementation.

## DAG DB Runtime Adapter Contract (split `exo-dag-db-*` crates)

**Status: PR #695 REST runtime activation evidence is PR-head scoped** — this
section is the integration contract for the split `exo-dag-db-*`
graph-governed agent-memory crates. Current PR-head evidence is supplied by the
PR checks and PR body; rollout evidence is tracked in
[`docs/dagdb/runtime-activation/rollback-canary-observability.md`](docs/dagdb/runtime-activation/rollback-canary-observability.md).
Do not treat stale local branch heads, old check runs, or old coverage numbers as
evidence for later unpushed fixes.

### Runtime boundary

`exo-dag-db-*` is the governed DAG DB runtime adapter surface. The production
router mounts exactly `POST /api/v1/dag-db/route`,
`POST /api/v1/dag-db/context-packet`, `POST /api/v1/dag-db/writeback`,
`POST /api/v1/dag-db/import`, and `POST /api/v1/dag-db/export`; the
`exo-gateway` default feature set includes `production-db`, and the `exo-node`
default feature set inherits `exo-gateway/default`. A functional governed runtime
still requires a configured Postgres pool and tenant/session authority. Without
that runtime state the routes fail closed, normally with `503
database_unavailable`, rather than fabricating persistence.

The served persistent REST paths are default route, context packet build,
writeback, import, and export. The writeback persistence path is routed through
the `DagDbGatekeeperService` (`crates/exo-gatekeeper/src/dagdb_gate.rs`) consent,
Ed25519, and invariant chain. Import/export are live routes only with distinct
import/export consent plus route-bound signature material; missing or mismatched
consent/signatures fail closed (for example `403 consent_denied` on authorization
denial), so writeback-only consent cannot authorize them. Intake, validate,
trust-check, council decision, receipt lookup, catalog lookup, and route lookup
DTO surfaces are not mounted in the production router until live governed
persistence exists for them; those requests therefore do not have runtime error
contracts on the served router.
Consumers must not write the `dagdb_*` tables directly; the raw
`exo_dag_db_postgres::postgres::*` functions are not a public,
governance-bearing surface.

### LYNK LLM usage custody boundary

The EXOCHAIN LYNK Protocol receipt adapter uses receipt minimization by default:
AVC LLM/MCP usage receipts store hashes, usage counters, safe metadata, custody
policy hashes, and receipt/finality links, not raw prompts, completions, tool
arguments, tool results, raw object URIs, provider keys, bearer tokens, KMS
material, or other decryptable payload material. This is an adapter policy, not
a global claim that DAG DB never stores data.

DAG DB can store governed tenant data when `dagdb_custody` is explicitly
authorized by consent, policy evidence, signatures, idempotency, RLS, and served
route or persistence API checks. The full LYNK custody contract is documented in
[`docs/dagdb/llm-usage-custody.md`](docs/dagdb/llm-usage-custody.md).

The four PRD-D5 gate methods (`persist_lifecycle_action`, `persist_default_route`,
`persist_continuation_record`, `persist_context_packet_record`) are now reached
from served REST paths: default route persistence calls
`persist_default_route`, context packet build calls
`persist_context_packet_record`, and writeback persists lifecycle plus
continuation records. The method-boundary security-regression coverage remains
the `gatekeeper-lifecycle-surfaces-gated` check; route-level proof for the
current PR head is supplied by PR checks and the source-of-truth runtime
activation plan.

### Fail-closed guarantees

- Writes are authorized only against real `exo-consent` / `exo-identity` state; an
  unconfigured resolver fails closed (no dev fabricated identity, no deterministic
  signing key in the shipping path). (T1/T2 — landed.)
- The three served mutation surfaces (writeback / import / export) fail closed
  (503, `database_unavailable`) when no database pool is configured. Writeback
  was previously a synthetic 201 scaffold; it now matches import/export. (T6 —
  landed.)
- **Constitutional invariant enforcement on the served writeback path enforces
  the *constructible* invariant subset**, not the full
  `InvariantEngine::all()`. The enforced set (`dagdb_invariant_set` in
  `dagdb_gate.rs`) is: `ConsentRequired`, `SeparationOfPowers`, `NoSelfGrant`,
  `HumanOverride`, `KernelImmutability`, `QuorumLegitimate`. Two invariants are
  deliberately **not** run through the engine on this path:
  - `ProvenanceVerifiable` — enforced directly and unconditionally via the gate's
    Ed25519 signature check (`verify_write_signature`) over the canonical payload
    hash, i.e. the same cryptographic binding, just not re-run through the engine.
  - `AuthorityChainValid` — **documented-as-future**: the dag-db consent schema
    stores a bailment + consent grant, not a per-link Ed25519-signed delegation
    chain, so an `InvariantContext` built from it has an empty authority chain.
    Running this invariant would fail-closed-block *every* legitimate dag-db
    write (a deadlock, not enforcement). Authorization on this path is instead
    established by the tenant-scoped consent grant (`ConsentRequired`) plus the
    route-layer session-authority binding. Loading a signed authority chain into
    the resolver to enable engine-level `AuthorityChainValid` is a follow-up.

  This is narrower than the prior claim that "all mutation surfaces enforce the
  constitutional `InvariantEngine`" — that claim is corrected here to the honest
  enforced subset.

### Tenant isolation (PR #695 activation evidence)

Tenant isolation is enforced at the storage layer by a `tenant_id` + `namespace`
pair carried on every row. Content-addressed rows (`dagdb_receipts.receipt_hash`,
`dagdb_memory_objects.memory_id`, `dagdb_catalog_entries.catalog_id`,
`dagdb_context_packet_records.packet_id`, …) use the **global 32-byte hash as the
primary key**, so a given hash maps to exactly one row owned by exactly one
tenant. P1-E hardened three layers:

- **By-hash read predicates (landed).** The data-returning by-hash reads now
  carry an explicit `AND tenant_id = $ AND namespace = $` (or project scope for
  packets) so a caller presenting another tenant's hash gets *not found* rather
  than fetching the cross-tenant row: `verify_export_record_row`,
  `verify_export_receipt_row`, and the export evidence memory read in
  `crates/exo-dag-db-postgres/src/postgres/kg_export.rs`, plus the context-packet replay
  guard in `crates/exo-dag-db-postgres/src/postgres/context_packet_persistence.rs`. The
  cross-tenant case is proven fail-closed by
  `export_evidence_read_is_tenant_scoped_cross_tenant_by_hash_fails_closed`
  (`tests/kg_export_persistence_contract.rs`).
  - The `ensure_*_match` / `row_mismatch` write-consistency guards in
    `kg_import` / `kg_writeback` intentionally read by the **global hash only**
    (no tenant predicate) and then compare the full scope+content in Rust. This
    is *already* fail-closed: a cross-tenant hash collision is rejected with a
    `Conflict`, and the row contents never reach the caller. Adding a tenant
    predicate there would convert that rejection into a silent `None → Ok →
    ON CONFLICT DO NOTHING` no-op write — a regression — so those reads are left
    as the global-hash consistency check by design. The residual is a weak
    existence-oracle (a caller can tell a hash *exists* under some tenant via the
    `Conflict` vs. proceed distinction), tracked as a follow-up below.
- **Write-time identity validation (landed).** `tenant_id` and `namespace` are
  validated and required to be in canonical, charset-safe form
  (`[A-Za-z0-9_:.-]`, non-empty, ≤128 bytes, no untrimmed whitespace) at the
  import and writeback write entrypoints
  (`KgImportDryRunReport::validate`, `KgWritebackDryRunReport::validate_for_persistence`),
  routed through `exo_dag_db_core::tenant::normalize_tenant_id`. Malformed or ambiguous
  identities fail closed before any write, preventing *new* divergence.
- **Canonical tenant constant (landed).** `exo_dag_db_core::tenant::LOCAL_DEV_TENANT_ID
  = "dag_db-local"` and `LOCAL_DEV_NAMESPACE = "dag_db"` are the single source of
  truth. The underscore form was chosen as canonical because it is what the
  shipping write paths (`exo_gateway::dagdb` local-dev mount and
  `continuation_packet`) already persist. Both `continuation_packet` and the
  gateway local-dev constants now route through this `const`. The hyphen form
  `dag-db-local` only ever
  appears in test fixtures and one smoke binary
  (`bin/dagdb_agent_brain_writeback_growth_smoke.rs`); no shipping write path
  emits it.

#### Tracked follow-ups

- **Existing-data reconciliation (no destructive rewrite).** Corpus memory is
  **append-only** — rows already written under a non-canonical `tenant_id` (e.g.
  a stray `dag-db-local`) must **not** be rewritten/deleted. Reconciliation is a
  forward-only operation: (1) audit `SELECT DISTINCT tenant_id, namespace FROM
  dagdb_memory_objects` (and the other scoped tables) to enumerate any divergent
  partitions; (2) if a divergent partition exists, supersede its rows into the
  canonical tenant via the normal append/supersession path (new rows + receipts),
  never an in-place `UPDATE`. The local dev stack currently writes only the
  canonical `dag_db-local`, so no reconciliation is outstanding there; this
  procedure is the contract for any environment that already wrote the hyphen
  form.
- **Row-Level Security (implementation and PR #695 evidence recorded).** RLS is the
  defense-in-depth layer for tenant isolation. The migration
  `crates/exo-dag-db-postgres/migrations/20260619000001_enable_dagdb_tenant_rls.sql`
  enables and forces RLS on the tenant-scoped DAG DB tables with a
  `dagdb_tenant_isolation` policy keyed by `current_setting('exo.tenant_id',
  true)`. Runtime code binds that tenant context inside transactions with
  `bind_tenant_context` / `begin_tenant_transaction`; namespace remains enforced
  by the existing query predicates and DTO scope. Runtime/RLS evidence for the
  current PR head is supplied by PR checks and the PR body; local verification
  commands include `RUSTFLAGS='-D warnings' cargo test -p exo-gateway dagdb --features production-db`
  and `RUSTFLAGS='-D warnings' cargo test -p exo-dag-db-postgres --features postgres --test dagdb_tenant_rls_live_path_contract -- --nocapture`.
  Coverage evidence remains scoped: coverage claims must cite the exact producing
  command, package set, exclusions, numerator, and denominator, and must not be
  described as universal production coverage.

### Provisioning

The dag-db schema is applied by a single ledgered migrator on gateway startup
(T4): `exo_gateway::db::init_pool` runs the gateway's own migrations, then calls
`exo_dag_db_postgres::postgres::run_migrations_in_schema` to provision the dag-db tables
into a dedicated `dagdb` Postgres schema. The migration SQL is **embedded in the
binary** at compile time by `sqlx::migrate!`, so the deploy image needs **no
Dockerfile change** to copy `crates/exo-dag-db-postgres/migrations/` — provisioning is
purely from the compiled binary. A fresh container must answer at least one of
the five mounted DAG DB REST calls after startup; if the dag-db migration fails, startup
aborts (fail closed) so the gateway never serves dag-db routes against an
unprovisioned schema.

The dedicated `dagdb` schema holds the dag-db tables **and** their own
`_sqlx_migrations` ledger. This is required because sqlx 0.8 hardcodes the
migration-tracking table name and the gateway and dag-db crates reuse the same
integer migration versions (`20260505000001`, `20260602000001`) for different
SQL; a shared `public._sqlx_migrations` would collide on version with a
mismatched checksum and abort startup. The gateway pool's `search_path` is set to
`public,dagdb` so bare-named gateway queries resolve in `public` and bare-named
dag-db queries resolve in `dagdb`. Local launch flows no longer apply a divergent
psql glob for the dag-db schema; the gateway binary is the single authoritative
provisioning path.

**Existing-store cutover (operational residual).** A store previously provisioned
by the old psql glob holds its dag-db tables in `public`. After this change the
migrator creates an empty `dagdb` copy, and because `search_path` lists `public`
first, bare dag-db queries keep resolving to the existing `public` data — no read
data loss, but the `dagdb` copy stays unused until a one-time data migration moves
the rows (or the deployment is recreated on a fresh database). Fresh deploys have
no `public` dag-db tables and resolve cleanly to `dagdb`. The offline dev/benchmark
tools (`kg_export` / `kg_import` / `writeback_sign`) use the dag-db crate's own
`init_pool` without the gateway's `search_path`, so they operate on `public`; this
divergence on fresh deploys is tracked as a follow-up, out of scope here.

### Versioned v1 REST wire contract

Every response body for the five active production-mounted DAG DB REST endpoints
carries a stable `schema_version` string so a non-Rust integrator can detect the
wire-contract version directly from the response. The constants are owned by
`exo-api` (`crates/exo-api/src/dagdb.rs`,
`DAGDB_*_RESPONSE_SCHEMA_VERSION`) and are the single source of truth.

Active runtime contracts mounted by the production router:

| Mounted endpoint | Response DTO | `schema_version` |
| --- | --- | --- |
| `POST /api/v1/dag-db/route` | `DagDbRouteResponse` | `dagdb_route_response_v1` |
| `POST /api/v1/dag-db/context-packet` | `DagDbContextPacketResponse` | `dagdb_context_packet_response_v1` |
| `POST /api/v1/dag-db/writeback` | `DagDbWritebackResponse` | `dagdb_writeback_response_v1` |
| `POST /api/v1/dag-db/import` | `DagDbImportResponse` | `dagdb_import_response_v1` |
| `POST /api/v1/dag-db/export` | `DagDbExportResponse` | `dagdb_export_response_v1` |

Reserved DTO-only contracts are defined for future governed persistence paths,
but are not mounted production routes:

| Reserved DTO surface | Response DTO | `schema_version` |
| --- | --- | --- |
| `POST /api/v1/dag-db/intake` | `DagDbIntakeResponse` | `dagdb_intake_response_v1` |
| `POST /api/v1/dag-db/validate` | `DagDbValidateResponse` | `dagdb_validate_response_v1` |
| `POST /api/v1/dag-db/trust-check` | `DagDbTrustCheckResponse` | `dagdb_trust_check_response_v1` |
| `POST /api/v1/dag-db/council/decision` | `DagDbCouncilDecisionResponse` | `dagdb_council_decision_response_v1` |
| `GET /api/v1/dag-db/receipts/{hash}` | `DagDbReceiptLookupResponse` | `dagdb_receipt_lookup_response_v1` |
| `GET /api/v1/dag-db/catalog/{id}` | `DagDbCatalogLookupResponse` | `dagdb_catalog_lookup_response_v1` |
| `GET /api/v1/dag-db/routes/{id}` | `DagDbRouteLookupResponse` | `dagdb_route_lookup_response_v1` |

Request bodies and the shared `DagDbErrorEnvelope` are **not** versioned in v1.

#### Machine contract (codegen source)

`docs/dagdb/api/openapi.json` is an OpenAPI 3.1 document covering every route,
request body, response body, and the error envelope. It is the artifact a
non-Rust integrator codegens from. It is hand-authored from the `exo-api` DTOs
and covered by `crates/exo-api/tests/openapi_sync.rs` when main integration runs it:
every fixture in `crates/exo-dag-db-api/fixtures/json/all_dto_fixtures.json`
validates against its component schema (and each fixture is independently
round-trip-asserted against its Rust DTO, so the spec's field set cannot drift
from the DTO's), and each documented `schema_version` `const` equals both the
Rust constant and the fixture value. Response schemas use
`additionalProperties: false` to mirror `#[serde(deny_unknown_fields)]`.

#### v1 `DagDbContextPacketResponse` vs. the internal `DagDbGraphContextPacket`

The REST `/context-packet` response (`DagDbContextPacketResponse`) is the
**canonical, versioned v1 contract**. The internal builder emits a richer,
separately-versioned `DagDbGraphContextPacket` (`dagdb_graph_context_packet_v1`)
that is never returned over HTTP. To close the previously-undocumented
divergence, the v1 REST response now surfaces the load-bearing rich fields that
the governed (persistent) path already has in scope
(`context_packet_response_from_persistent`,
`crates/exo-gateway/src/dagdb.rs`):

- `selected_graph_edges` — the selected graph edges (`DagDbSelectedGraphEdgeRef`).
- `citation_refs` — the packet's citation references.
- `packet_metrics` — token-budget / selection / savings-status metrics.
- `boundaries` — the blocked-claim boundaries (repository-test-level flags).
- `packet_markdown` — the rendered agent-facing markdown.

These are populated on the governed `production-db` path and are empty/`null` on
the no-database **scaffold** path (which has no built packet); they are
optional+`skip_serializing_if` so a scaffold response omits them. The v1 REST
contract therefore exposes the full internal packet's user-facing surface except
`agent_usage_instructions` and the packet's own `schema_version`/`task` echo,
which are **documented-as-follow-up**: surfacing `agent_usage_instructions` over
REST is a tracked addition for a future minor (additive, non-breaking) revision.
Consumers that need the byte-exact internal packet should treat
`DagDbGraphContextPacket` as the internal contract and the REST response as the
governed projection of it.

### Honest scope

`exo-dag-db` delivers deterministic, graph-governed cross-agent retention/recall
with measured context compression. It does **not** yet claim to be cheaper *and*
better than raw context: the rigorous benchmark fails cost-vs-neutral and the 80%
token-reduction floor, and the proof gate returns not-accepted. See `T3` and the
shipped DAG DB docs under `docs/dagdb/`.

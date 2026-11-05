# EXOCHAIN v0.3.0 EXO-DAG-DB inclusion assessment

Status: **DRAFT conditional inclusion intake; non-operative**

Decision: include the EXO-DAG-DB capability in the v0.3.0 successor plan if,
and only if, a commit-to-commit reconciliation proves that the private overlay
adds necessary, verified behavior to the canonical split-crate EXOCHAIN DAG DB
runtime without regressing its constitutional, tenant, authority, packaging,
or evidence boundaries. A wholesale repository overlay or merge is prohibited.

This assessment is based on read-only GitHub and local-tree inspection. It
does not authorize cloning, fetching, merging, source development, issue or PR
mutation, secret access, deployment, publication, or release operations.

## Observed repository bindings

### Public EXOCHAIN

- Repository: [`exochain/exochain`](https://github.com/exochain/exochain)
- Visibility: public
- Default branch: `main`
- Observed `main` head:
  `86e9a029b7a62417b658b04d0def7a979e21fc8b`

### Private EXO-DAG-DB overlay

- Repository:
  [`mstewartbz/EXO-DAG-DB`](https://github.com/mstewartbz/EXO-DAG-DB)
- Visibility returned by GitHub: private
- Default branch: `main`
- Observed `main` head:
  `df1070344e1d959a89b4100e83e21ff2a340eaa5`
- Head commit message states that EXOCHAIN public `main` at
  `86e9a029b7a62417b658b04d0def7a979e21fc8b` was synchronized while the private
  DAG DB overlay was preserved.
- Open pull requests returned by the read-only query: `0`
- Open issues returned by the read-only query: `5`
- Combined commit statuses returned for the exact private head: `0`
- Pull-request-triggered workflow runs returned for the exact private head: `0`

The absence of returned statuses or runs is not evidence that CI failed, but it
also cannot establish an exact-head green build. Fresh independently retained
verification is mandatory before any inclusion decision.

### Local v0.3.0 development checkout

- Observed branch: `bob-stewart/EXOCHAINv0.3.0Evidence-GradeTrustRelease`
- Observed commit:
  `c5f1b17571e25e2fec2c71f384467748da00af74`
- The checkout is not clean because of unrelated `intelwar/` work and is not
  an authorized integration worktree.
- The checkout already contains the canonical split DAG DB architecture:
  `exo-dag-db-api`, `exo-dag-db-core`, `exo-dag-db-graph`,
  `exo-dag-db-domain`, `exo-dag-db-retrieval`, `exo-dag-db-exchange`,
  `exo-dag-db-postgres`, and `exo-dag-db-lab`, plus bridge paths in
  `exo-api`, `exo-gateway`, `exo-node`, `exo-gatekeeper`, and
  `exochain-sdk`.

## Material architectural finding

The private repository README describes one canonical `crates/exo-dag-db`
crate. The local v0.3.0 tree and governing `AGENTS.md` define an eight-crate
split architecture and forbid parallel implementations. Both describe the
same five mounted REST operations:

- `POST /api/v1/dag-db/route`
- `POST /api/v1/dag-db/context-packet`
- `POST /api/v1/dag-db/writeback`
- `POST /api/v1/dag-db/import`
- `POST /api/v1/dag-db/export`

Therefore, “include EXO-DAG-DB” must mean reconcile verified private-overlay
behavior into the existing canonical split crates and adapters. It must not
mean copying the monolithic crate beside them, replacing the release tree with
the private repository, or importing private history wholesale.

## Open private-repository findings that govern inclusion

| Issue | Classification | Required v0.3.0 treatment |
| --- | --- | --- |
| [#134 — TRUST-001: context-packet lineage and local DB authority](https://github.com/mstewartbz/EXO-DAG-DB/issues/134) | Core runtime adapter, P1 | Release blocker for DAG DB inclusion. Prove exact server-issued packet membership, alias scope, parentless observed-evidence rules, and one database authority across gateway and tooling. |
| [#142 — WRITEBACK-POOL-001: fail closed with no persistence pool](https://github.com/mstewartbz/EXO-DAG-DB/issues/142) | Core runtime adapter, P1 | Release blocker. A production-db writeback without a pool must return sanitized `503 database_unavailable` and must never mint IDs, receipts, or success. |
| [#143 — HTTP-PROXY-001: ambient proxy leakage](https://github.com/mstewartbz/EXO-DAG-DB/issues/143) | Runtime transport security, P1 | Release blocker. Authenticated supported loopback traffic must bypass hostile ambient proxies with zero proxy-observed headers, signatures, or bodies. |
| [#144 — CI-001: database security regressions in Gate 13](https://github.com/mstewartbz/EXO-DAG-DB/issues/144) | CI/evidence enforcement, P1 | Release blocker. Every database-required security regression must execute exactly once and fail the aggregate on omission or failure. |
| [#148 — LiveSafe React Router advisory](https://github.com/mstewartbz/EXO-DAG-DB/issues/148) | Adjacent LiveSafe surface | Do not import it into the core DAG DB commit. Preserve the fail-closed audit and resolve through a separate adjacent-surface lane; never weaken or allowlist the advisory to make DAG DB green. |

An issue being open does not prove the defect remains in the latest bytes, and
a merged commit does not prove the issue is resolved. Each finding must first
be reproduced against the exact integration candidate. If it no longer
reproduces, the verifier must bind the correcting commit and regression test.

## Required reconciliation lane

The successor plan may authorize this lane only after G00 is lawfully closed
and formal DRAFT authoring is separately authorized. The lane must use a new,
clean, isolated worktree and the following sequence:

1. Freeze the canonical EXOCHAIN candidate commit and the private
   `df1070344e1d959a89b4100e83e21ff2a340eaa5` source commit.
2. Prove that the authorized private source contains both frozen commits and
   that `86e9a029b7a62417b658b04d0def7a979e21fc8b` is the approved ancestry/base
   for `df1070344e1d959a89b4100e83e21ff2a340eaa5`. A commit message is not this
   proof. If graph ancestry is absent, an independent verifier must instead
   freeze and compare a complete file-level manifest of the public base as
   represented in the private source. If neither proof is available,
   inclusion stops; no overlay, merge, fallback copy, or private-history import
   is permitted.
3. Produce a complete path and semantic inventory of private-only changes
   since the synchronized public commit
   `86e9a029b7a62417b658b04d0def7a979e21fc8b`.
4. Classify every delta as EXOCHAIN core, core runtime adapter, adjacent
   surface, imported evidence, or third-party/vendor.
5. Map each accepted monolithic-crate behavior to exactly one canonical
   split-crate owner. Reject duplicate functions, routes, schemas, stores,
   migrations, prompts, and architecture layers.
6. Write a failing regression or deterministic source guard against the
   canonical release candidate before porting each missing behavior.
7. Implement only the smallest missing behavior. Preserve public DTOs, route
   paths, response schemas, tenant-plus-namespace scope, canonical migrations,
   fail-closed errors, and existing claim caveats.
8. Verify focused crates, live-Postgres integration, RLS, authority, consent,
   signature, idempotency, proxy, MCP/SDK, migration, packaging, and full
   workspace gates.
9. Obtain distinct read-only SPEC, QUAL, ADV, and VER decisions on the same
   frozen commit and evidence manifest.

The writer may not merge, push, close issues, alter branch protection, access
secrets, deploy, publish, or make release claims under this intake.

## Tests-first release acceptance matrix

### Provenance and anti-duplication

- Complete commit-to-commit diff inventory from the public synchronized base
  to private head.
- Exact mapping from each accepted private change to its split-crate owner and
  requirement.
- Deterministic bypass search proving no monolithic duplicate or sibling
  ingress survives.
- License and private-material review proving only authorized source enters the
  public or release artifact boundary.

### Runtime integrity

- The five mounted routes are the only production DAG DB REST surface.
- Missing Postgres, tenant/session authority, consent, signatures, finality, or
  route-specific configuration fails closed before durable mutation.
- Server-issued context-packet membership and lineage are verified; caller
  supplied packet or parent identities cannot self-authorize.
- Import, export, and writeback consent purposes remain distinct.
- Idempotency replay is deterministic and conflicting material is rejected.
- Every tenant-owned live table is protected by tenant-bound transactions and
  non-bypass RLS tests; namespace predicates remain enforced.
- Supported loopback authenticated traffic exposes zero requests or secrets to
  hostile ambient proxies.
- Logs, health, status, receipts, and errors contain no raw bearer tokens,
  private keys, raw signatures, or tenant data leaks.

### Migration and compatibility

- Fresh-database migration, upgrade from the v0.2.3-supported schema, rollback,
  and retry-after-interruption are tested with exact schema inventories.
- Public DTO schema versions and the five route paths remain compatible.
- MCP configured proxy uses the live gateway and fails closed when
  unconfigured; SDK construction matches the same wire contract.
- The split-crate dependency graph remains acyclic and respects the EXOCHAIN
  core dependency order.
- Release packages build for downstream consumers without relying on the
  workspace lockfile.

### Evidence and operations

- Exact-head CI must be run or independently reproduced; branch history,
  commit messages, an earlier PR, and an empty status response are not green
  evidence.
- Gate 13 executes every `needs_db=true` security regression exactly once and
  reports total, selected, passed, failed, and skipped counts.
- Two byte-identical verification runs bind the same source, schema, test,
  route, and evidence inventories.
- Canary, health, observability, and rollback evidence is required before any
  production-runtime activation claim.
- The existing caveat remains: repository/runtime tests do not prove the DAG
  DB “cheaper and better” thesis or billing savings.

## Conditional inclusion decision

`CONDITIONAL_GO_TO_PLAN`

EXO-DAG-DB should be treated as integral to the v0.3.0 runtime candidate, but
only through the controlled reconciliation above. Any surviving P1 finding,
duplicate architecture, unclassified private delta, source-provenance failure,
test regression, non-determinism, secret exposure, or Council rejection makes
the DAG DB inclusion gate fail closed. The rest of v0.3.0 may proceed only if
the successor charter explicitly states whether DAG DB is release-critical or
an independently shippable component and binds the consequences of exclusion.

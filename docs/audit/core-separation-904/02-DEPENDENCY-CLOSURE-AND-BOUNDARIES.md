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

# Clean-separation audit (#904), part 2: crate dependency closure and the Decision Forum and economy boundaries

**Status: DRAFT audit evidence. Not panel-reviewed. Not a split plan, not a
release record, and not a cryptographic certification.**

Issue #904 asks for "a dependency-closed inventory of trust-fabric crates,
code, tests, CI, deployment inputs, and docs" and asks the audit to
"explicitly decide the Decision Forum/workflow and economy boundary". This
record covers the Rust crate part of that inventory: the declared workspace
dependency graph at the audited commit and the closure each crate needs. It
then proposes a boundary for each of the two areas.

**The boundary is proposed, not decided.** An audit author cannot make a
maintainer decision. Until the Architecture panel records a decision on the
three items in the "Decision status" table, the boundary requirement of #904
is open and should be treated as blocking the `--execute` cutover in #903.

It builds on part 1 (`01-INVENTORY-AND-PATH-CLASSIFICATION.md`), which proposes
a class for every path. "Core-class" and "adapter-class" below mean the class
part 1 proposes for a crate directory.

## What this record does and does not establish

It establishes what each workspace crate **declares** as a dependency on
another workspace crate, and where source files name the boundary crates.
Nothing was compiled. It does not establish:

- that any subset of crates builds or passes tests on its own (part 5, from CI);
- a closure over third-party crates, non-manifest inputs such as fixtures and
  migrations, CI, deployment inputs or JavaScript packages (parts 4 and 5;
  the leads found here are forwarded as observations);
- what feature unification does when several crates are built together;
- which code inside a crate is product material (part 3);
- any licence position (part 4). Statements quoted from `README.md` are
  quoted as repository claims, not as evidence that they are correct.

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` |
| Edge list | `docs/audit/core-separation-904/workspace-dependency-edges.tsv` |
| Edge list SHA-256 | `75461d53596549b9adc52b1dbdf1d9c3bb3d98fa7eece89e6e04ba8429094e4c` |
| Extractor | `docs/audit/core-separation-904/dependency_graph.py` |
| Input | `cargo metadata --no-deps --offline --format-version 1` (cargo 1.96.0) |

`cargo metadata --no-deps` reads manifests only. It resolves no registry
dependency and compiles nothing.

## Method

1. Read every workspace member's declared dependencies from `cargo metadata`
   and keep the edges that point at another workspace member. Record kind
   (normal, dev, build), whether the edge is optional, which feature of the
   dependent crate enables it, and any target `cfg`.
2. Compute closures over normal edges (there are no build edges). The **hard
   closure** follows only non-optional edges. The **default closure** also
   follows optional edges that the dependent crate's default features enable.
   Both are given for native targets and, where they differ, for `wasm32` and
   `zkvm`.
3. List dev edges separately. They do not enter the closures above, so the
   closures describe building a crate, not testing it.
4. Read the manifests of crates outside the workspace (`exclude` list and
   `fuzz/`) by hand, since `cargo metadata` does not report them.
5. Search `crates/**/*.rs` for the library names of the boundary crates
   (`decision_forum`, `exo_economy`, `exo_catapult`, `exo_messaging`,
   `exo_consensus`) and read each match site.

The extractor does not record the features one crate requests of another or
`default-features = false`. Where those matter, the manifest line is cited.

## Workspace shape

The workspace has 33 members. `crates/` holds 35 directories; the other two,
`exo-cgr-methods` and `exo-cgr-prover`, are in the workspace `exclude` list
with `exo-cgr-methods/guest` and `livesafe`.

| Edge kind | Count |
| --- | ---: |
| Normal, required | 146 |
| Normal, optional (feature-gated) | 5 |
| Dev only | 6 |
| Build | 0 |
| **Total** | **157** |

Four of the required normal edges are target-specific (all from
`exo-gatekeeper`; see F-1).

The five optional edges, each enabled by a default feature of the crate that
declares it:

| From | To | Enabled by |
| --- | --- | --- |
| `exo-gatekeeper` | `exo-api` | `runtime` |
| `exo-gatekeeper` | `exo-consent` | `runtime` |
| `exo-gatekeeper` | `exo-identity` | `runtime` |
| `exo-gateway` | `exo-dag-db-postgres` | `production-db` |
| `exo-node` | `exochain-sdk` | `dagdb-gateway-proxy` |

The six dev edges: `exo-escalation` to `exo-gatekeeper`; `exo-gatekeeper` to
`exo-api` and `exo-core`; `exo-node` to `exo-verify`; `exo-verify` to
`exo-authority` and `exo-dag`.

## Direct workspace dependencies

Required normal edges only. "Dependents" counts workspace crates that require
the crate; the reproduction section gives the command.

| Crate | Part 1 class | Requires | Dependents |
| --- | --- | --- | ---: |
| `exo-core` | core | none | 31 |
| `exo-identity` | core | `exo-core` | 14 |
| `exo-consent` | core | `exo-core` | 8 |
| `exo-authority` | core | `exo-core`, `exo-identity` | 11 |
| `exo-dag` | core | `exo-core` | 3 |
| `exo-proofs` | core | `exo-core` | 2 |
| `exo-economy` | core (boundary) | `exo-core` | 3 |
| `exo-tenant` | core | `exo-core`, `exo-identity` | 0 |
| `exo-messaging` | core | `exo-core`, `exo-identity` | 1 |
| `exo-avc` | core | `exo-authority`, `exo-core` | 6 |
| `exo-pdp` | core | `exo-authority`, `exo-core` | 2 |
| `exo-root` | core | `exo-authority`, `exo-core` | 1 |
| `exo-verify` | core | `exo-avc`, `exo-core` | 1 |
| `exo-governance` | core | `exo-authority`, `exo-consent`, `exo-core`, `exo-identity` | 6 |
| `exo-escalation` | core | `exo-core`, `exo-governance`, `exo-identity` | 3 |
| `exo-catapult` | core (boundary) | `exo-authority`, `exo-consent`, `exo-core`, `exo-escalation`, `exo-identity` | 1 |
| `exo-gatekeeper` | core | `exo-core`, `exo-dag-db-core`, `exo-dag-db-domain`, `exo-dag-db-exchange`, `exo-dag-db-postgres` | 6 |
| `exo-legal` | core | `exo-authority`, `exo-core`, `exo-gatekeeper`, `exo-governance`, `exo-identity` | 4 |
| `decision-forum` | core (boundary) | `exo-authority`, `exo-consent`, `exo-core`, `exo-gatekeeper`, `exo-governance`, `exo-identity`, `exo-legal` | 3 |
| `exo-consensus` | core (boundary) | `decision-forum`, `exo-core` | 0 |
| `exo-dag-db-api` | adapter | none | 9 |
| `exo-dag-db-core` | adapter | `exo-core`, `exo-dag-db-api` | 7 |
| `exo-dag-db-graph` | adapter | `exo-core`, `exo-dag-db-api` | 5 |
| `exo-dag-db-domain` | adapter | `exo-authority`, `exo-avc`, `exo-consent`, `exo-core`, `exo-dag-db-api`, `exo-dag-db-core`, `exo-dag-db-graph`, `exo-identity` | 6 |
| `exo-dag-db-retrieval` | adapter | `exo-core`, `exo-dag-db-api`, `exo-dag-db-core`, `exo-dag-db-domain`, `exo-dag-db-graph` | 3 |
| `exo-dag-db-exchange` | adapter | `exo-authority`, `exo-avc`, `exo-consent`, `exo-core`, `exo-dag-db-api`, `exo-dag-db-core`, `exo-dag-db-domain`, `exo-dag-db-graph`, `exo-dag-db-retrieval` | 4 |
| `exo-dag-db-postgres` | adapter | `exo-core`, `exo-dag`, `exo-dag-db-api`, `exo-dag-db-core`, `exo-dag-db-domain`, `exo-dag-db-exchange`, `exo-dag-db-graph`, `exo-dag-db-retrieval` | 2 |
| `exo-dag-db-lab` | adapter | `exo-core` and all seven other `exo-dag-db-*` crates | 0 |
| `exo-api` | adapter | `exo-core`, `exo-dag-db-api`, `exo-identity` | 3 |
| `exo-gateway` | adapter | `decision-forum`, `exo-api`, `exo-consent`, `exo-core`, `exo-dag-db-core`, `exo-dag-db-domain`, `exo-dag-db-exchange`, `exo-gatekeeper`, `exo-governance`, `exo-identity`, `exo-legal` | 1 |
| `exochain-sdk` | adapter | `exo-avc`, `exo-core`, `exo-dag-db-api`, `exo-economy`, `exo-gatekeeper`, `exo-identity` | 0 |
| `exo-node` | adapter | `exo-api`, `exo-authority`, `exo-avc`, `exo-consent`, `exo-core`, `exo-dag`, `exo-economy`, `exo-escalation`, `exo-gatekeeper`, `exo-gateway`, `exo-governance`, `exo-identity`, `exo-legal`, `exo-pdp`, `exo-proofs`, `exo-root`, `exo-verify` | 0 |
| `exochain-wasm` | adapter | `decision-forum`, `exo-api`, `exo-authority`, `exo-avc`, `exo-catapult`, `exo-consent`, `exo-core`, `exo-dag`, `exo-economy`, `exo-escalation`, `exo-gatekeeper`, `exo-governance`, `exo-identity`, `exo-legal`, `exo-messaging`, `exo-pdp`, `exo-proofs` | 0 |

Crates outside the workspace, read from their manifests:

| Manifest | Path dependencies | Notes |
| --- | --- | --- |
| `crates/exo-cgr-methods/Cargo.toml` | none | Build dependency `risc0-build`; `[package.metadata.risc0] methods = ["guest"]` |
| `crates/exo-cgr-methods/guest/Cargo.toml` | `exo-gatekeeper`, `exo-proofs` | Both with `default-features = false` |
| `crates/exo-cgr-prover/Cargo.toml` | `exo-gatekeeper`, `exo-proofs`, optional `exo-cgr-methods` | Takes `exo-gatekeeper` with default features, so F-1 and F-2 apply to it |
| `fuzz/Cargo.toml` | `exo-core`, `exo-governance` | |
| `livesafe/Cargo.toml` | none on `crates/` | |

No `Cargo.toml` under `crates/` was found with a path dependency that leaves
`crates/` (text search for `path =`).

## Closure of the core-class crates

Taking the 20 core-class workspace crates as roots:

| Closure | Workspace crates in it | Adapter-class crates pulled in |
| --- | ---: | --- |
| Native, hard | 27 | The seven `exo-dag-db-*` crates other than `exo-dag-db-lab` |
| Native, default | 28 | Those seven plus `exo-api` |

In neither closure do the core-class crates reach `exo-gateway`, `exo-node`,
`exochain-sdk`, `exochain-wasm` or `exo-dag-db-lab`.

All seven DAG DB crates enter through `exo-gatekeeper`. Workspace crates
reached by each crate that depends on it, excluding the crate itself:

| Crate | Native hard | Native default | `wasm32`/`zkvm` hard |
| --- | ---: | ---: | ---: |
| `exo-gatekeeper` | 13 | 14 | 1 |
| `exo-legal` | 15 | 16 | 6 |
| `decision-forum` | 16 | 17 | 7 |
| `exo-consensus` | 17 | 18 | 8 |

Every other core-class crate reaches six or fewer workspace crates and no
DAG DB crate: `exo-core` 0; `exo-consent`, `exo-dag`, `exo-economy`,
`exo-identity`, `exo-proofs` 1; `exo-authority`, `exo-messaging`,
`exo-tenant` 2; `exo-avc`, `exo-pdp`, `exo-root` 3; `exo-governance`,
`exo-verify` 4; `exo-escalation` 5; `exo-catapult` 6.

Two consequences of the kernel's DAG DB edges:

- **Without them the kernel's hard closure is `exo-core` alone** (the
  `wasm32`/`zkvm` column). On native targets it reaches `exo-authority`,
  `exo-avc`, `exo-consent`, `exo-identity` and `exo-dag` only through the
  DAG DB crates.
- **The dependency runs both ways across the proposed class line.**
  `exo-gatekeeper` (core-class) requires `exo-dag-db-domain`,
  `exo-dag-db-exchange` and `exo-dag-db-postgres`; those require
  `exo-authority`, `exo-avc`, `exo-consent`, `exo-identity` and `exo-dag`
  (core-class). Placing the DAG DB crates in a different repository from the
  core would make the two repositories depend on each other.

Testing differs from building: `exo-escalation` has a dev edge to
`exo-gatekeeper`, so its tests take the kernel's whole closure although its
build reaches five crates.

## Findings

Dispositions use the repository's vocabulary (`patch`, `adjacent_patch`,
`no_change`). Cutover status is in the summary table.

### F-1. The kernel crate's manifest requires the DAG DB crates and `sqlx` on native targets

`crates/exo-gatekeeper/Cargo.toml` lines 63 to 68 declare, for every target
except `wasm32` and `zkvm`, required dependencies on `exo-dag-db-core`,
`exo-dag-db-domain`, `exo-dag-db-exchange`, `exo-dag-db-postgres` (requesting
its `postgres` feature) and `sqlx`. The workspace `sqlx` entry enables
`runtime-tokio-rustls`, `postgres`, `uuid`, `json`, `macros` and `migrate`.

The source is gated more narrowly than the manifest. One module uses these
crates, `src/dagdb_gate.rs`, and `src/lib.rs` lines 36 to 41 compile it only
under `feature = "runtime"` **and** the target condition. The dependencies
themselves are not optional, so a native build with
`--no-default-features` still takes them although no code uses them.

What follows:

- Seven `exo-dag-db-*` crates are inside the declared closure of the kernel
  crate, and through it of `exo-legal`, `decision-forum` and `exo-consensus`.
- Part 1 proposes those seven crates as "core runtime adapter", following
  v0.2.6 and the `AGENTS.md` section that calls DAG DB a runtime adapter.
  Today they are not separable from the kernel crate.
- Because `exo-gatekeeper` requests `exo-dag-db-postgres/postgres`
  unconditionally, turning off `exo-gateway`'s `production-db` feature does
  not by itself give a native build without the Postgres code.
- Copying the seven crates into the core repository resolves the missing-file
  problem. It does not answer whether a Postgres client belongs in the
  kernel crate's dependency set, which is a Security panel question.

Remedies, smallest first: make the four DAG DB dependencies and `sqlx`
optional and enable them from `runtime` or a new feature (manifest only); or
move `dagdb_gate` out of the kernel crate, which changes a published API,
since `lib.rs` lines 60 to 68 re-export `DagDbGatekeeperService` and seven
other items.

Proposed disposition: `patch`.

### F-2. `exo-gatekeeper` takes `exo-api` by default

The `runtime` feature is in the crate's default set and enables `exo-api`, an
adapter-class crate. The kernel module (`src/kernel.rs`) is compiled only
under `runtime`. Among the manifests read, only `exo-cgr-methods/guest` sets
`default-features = false` on `exo-gatekeeper`.

Proposed disposition: `no_change` if the panel accepts `exo-api` as part of
the core repository. As with F-1, inclusion fixes the missing-file problem and
leaves the class question from part 1 open.

### F-3. Decision Forum is required, ungated, by the gateway, consensus and WASM crates

| Dependent | What it uses | Where |
| --- | --- | --- |
| `exo-gateway` | `DecisionObject`, `DecisionObjectInput`, `DecisionClass`, `ActorKind`, `Vote`, `VoteChoice`; `quorum::{QuorumRegistry, QuorumCheckResult, check_quorum_with_verified_humans, verify_quorum_precondition}` | `src/handlers.rs:35`, `src/server.rs:40`, `src/db.rs:25`; test `tests/decision_forum_integration.rs` |
| `exo-consensus` | Production code: `DecisionClass` only (`src/panel.rs:17`). Test code uses more types. | Tests: `src/lib.rs:58`, `src/session.rs:441`, `tests/presidential_c2_bridge.rs` |
| `exochain-wasm` | 45 `#[wasm_bindgen]` exports in one module | `src/decision_forum_bindings.rs` |

`exo-node` requires `exo-gateway`, so the node binary's declared closure
includes Decision Forum. `exo-consensus` production code uses one four-variant
enum from the crate and for that takes its whole closure.

The repository describes the crate in two ways, and this record does not
resolve the tension:

- as a core primitive: `README.md` line 377, "`crates/decision-forum` remains
  an Apache-2.0 core primitive; it does not license the Decision Forum
  product";
- as an application: its manifest description, "constitutional governance
  application layer"; and `src/lib.rs` line 19, "the USER-FACING governance
  application that orchestrates all lower-level exochain primitives".

The imports above show which items the gateway uses. They do not show whether
those items, or the rest of the crate, are product material; that is part 3.

Proposed disposition: `no_change` under the proposed boundary (below).

### F-4. `decision-forum` declares four dependencies its source does not name

Its manifest requires `exo-authority`, `exo-consent`, `exo-identity` and
`exo-legal`, and lists all four under `[package.metadata.cargo-machete]
ignored` with the comment "used via re-exports or trait bounds". A text search
of `crates/decision-forum/src` and `tests` finds no `exo_authority::`,
`exo_consent::`, `exo_identity::` or `exo_legal::` path. Of the workspace
crates it declares, only `exo_core`, `exo_gatekeeper` and `exo_governance`
are named.

A text search cannot rule out use through a re-export, so this is a lead. If
all four are unused, removing them takes one crate, `exo-legal`, out of the
Decision Forum closure; the other three stay reachable through
`exo-governance`. Confirming it needs `cargo machete` run with the ignore list
removed, or a CI build without the four lines.

Proposed disposition: `patch`. It is cleanup, not a condition of the boundary.

### F-5. No core-class crate requires the economy crate; three adapters require it ungated

`crates/exo-economy` requires one workspace crate, `exo-core`, and three
third-party crates (`ciborium`, `serde`, `thiserror`). Three adapter-class
crates require it, none behind a feature:

| Dependent | What it uses | Where |
| --- | --- | --- |
| `exo-node` | Economy types, store traits and anchors; an `/api/v1/economy/*` router merged unconditionally | `src/economy.rs`, `src/store.rs`, `src/store/store_postgres.rs`, `src/main.rs:1383-1463` |
| `exochain-sdk` | Public re-export `pub mod economy` | `src/lib.rs:178`, `src/economy.rs:64` |
| `exochain-wasm` | 4 `#[wasm_bindgen]` exports | `src/economy_bindings.rs` |

Limits of that result:

- It is a manifest result. `crates/exo-consent/src/contract.rs` line 38
  defines `LICENSURE_USAGE_ACCOUNTING_POLICY = "exo-economy-use-event-v1"`, so
  a core-class crate names an economy policy identifier without depending on
  the crate.
- `README.md` says AVC validity "does not consult pricing or settlement
  state". The graph is consistent with that (`exo-avc` and `exo-verify` do not
  reach `exo-economy`) but a dependency graph cannot prove runtime behaviour.
- The crate publicly re-exports items from a module named `honorgood`
  (`src/lib.rs` lines 95 and 129). Whether that is product material is part 3.
- The economy surface is published API. The workspace sets `publish = true`,
  and `README.md` line 122 says the Rust SDK, TypeScript SDK and WASM bridge
  "expose stable core economy" surfaces. Gating it changes those surfaces and
  what `packages/` builds against.

Proposed disposition: `no_change` under the proposed boundary (below).

### F-6. Four core-class crates are outside the node and gateway closures

`exo-catapult` and `exo-messaging` each have one dependent, `exochain-wasm`
(20 and 12 `#[wasm_bindgen]` exports). `exo-tenant` and `exo-consensus` have
none. None of the four is in the declared normal closure of `exo-node` or
`exo-gateway`.

This is a reachability result only. Leaving any of them out would still need
workspace manifest changes, would change the WASM package's exports for
`exo-catapult` and `exo-messaging`, and would stop publishing a crate. Whether
a build succeeds without them is for CI in part 5.

Proposed disposition: `no_change` in this part.

### F-7. `AGENTS.md` and `crates/README.md` describe a different graph

`AGENTS.md` "Dependency Order":

- places `decision-forum` at the top, below `exo-gateway`; in the manifests
  `exo-gateway`, `exo-consensus` and `exochain-wasm` depend on it;
- lists `exo-tenant` on the tier above `decision-forum`; nothing depends on
  `exo-tenant`;
- shows `exo-governance`, `exo-escalation` and `exo-legal` under
  `exo-gatekeeper`; only `exo-legal` requires it (`exo-escalation` has a dev
  edge);
- says `exo-gatekeeper` "depends on most of" identity, consent, authority, DAG
  and proofs. That is wrong for direct dependencies and close for the native
  transitive closure, which reaches four of the five through DAG DB.

`crates/README.md`:

- says `exo-gatekeeper` "depends only on exo-core" (see F-1);
- counts "twenty in total"; the workspace has 33 members;
- lists `exochain-sdk` dependencies that do not match its manifest (actual:
  `exo-avc`, `exo-core`, `exo-dag-db-api`, `exo-economy`, `exo-gatekeeper`,
  `exo-identity`);
- says `exochain-wasm` "depends on every `exo-*` crate"; it does not require
  `exo-tenant`, `exo-consensus`, `exo-root`, `exo-verify`, `exo-gateway`,
  `exo-node` or any `exo-dag-db-*` crate.

Proposed disposition: `patch` (documentation). The split plan should be drawn
from the manifests, not from these descriptions.

### F-8. Workspace tests read fixtures from an excluded crate

`crates/exo-proofs/tests/riscz_real_receipt.rs` line 25 and a test in
`crates/exo-node/src/mcp/tools/proofs.rs` (line 1664) read files from
`crates/exo-cgr-prover/fixtures/`. `exo-cgr-prover` is excluded from the
workspace, generates those fixtures with its own binary, and depends on
`exo-cgr-methods`, whose build uses `risc0-build` and the `guest` crate.

So exclusion from the workspace does not put these three directories outside
the test inventory of two workspace crates. Each fixture needs a decision:
copied with the core, supplied from elsewhere, or regenerated.

Proposed disposition: `patch`, pending part 5 (how the tests run in CI) and
part 6 (provenance of the committed receipts).

## Proposed boundaries

These proposals rest on dependency evidence only. They state what the graph
allows without code change and what each alternative would cost. They do not
show that either crate is free of product material or correctly licensed.

### Decision Forum and workflow

| Option | What it means | Change needed before the split |
| --- | --- | --- |
| A. Crate with the core, product surfaces left behind | Copy `crates/decision-forum`. Leave `web/`, `tools/sybil-cli/` and `docs/decision-forum/` in the legacy repository. | None |
| B. Crate with the core, optional in its consumers | As A, plus a feature in `exo-gateway` and `exochain-wasm` so a build can omit it. | Yes; changes gateway routes and the WASM package's exports |
| C. Crate leaves the core | Remove or gate the consumers' use as in B, and take the crate out. | Yes; as B, and the published crate changes home |
| D. Split the crate | Move the decision-object and quorum items the gateway uses into a core crate, re-export them from `decision-forum` for compatibility, and move the remainder out. | Yes; new published API |

**Proposal: option A as a provisional compatibility choice.** It is the only
option that needs no code change, and F-3 shows the gateway's decision and
quorum handlers are written against this crate. That is an argument about
cost and risk at cutover, not a finding that the crate is a clean core
primitive. If the panel judges that the crate must not ship in the core, the
graph shows what that requires (options B to D), and the panel may make it a
condition of the split.

Conditions on option A:

1. Part 3 examines the crate's modules (`fiduciary_package`, `tnc_enforcer`,
   `terms`, `self_governance`, `workflow` and the rest) for product material.
2. Part 4 confirms the crate's licence position against
   `governance/commercial-product-licensing.json`.
3. The split record says, in those words, that the Decision Forum crate is
   included and the Decision Forum product is not.

`exo-consensus`: it requires `decision-forum`, so it cannot be built without
it today. It has no dependent, so it could also be left out, or decoupled by
moving the four-variant `DecisionClass` enum into a crate both already
require. Proposal: it travels with `decision-forum` under option A.

Workflow: `crates/decision-forum/src/workflow.rs` describes itself as
"Syntaxis workflow integration" and is bound by `exochain-wasm`; under option
A it travels with the crate. `tools/syntaxis/` (12 paths) is a code generator
that no crate manifest references. Proposal: it stays with the legacy
repository unless part 5 finds it is a build or CI input.

### Economy

| Option | What it means | Change needed before the split |
| --- | --- | --- |
| A. Crate with the core, always built | Copy `crates/exo-economy`; the three adapters keep requiring it. | None |
| B. Crate with the core, optional in the adapters | As A, plus a feature in `exo-node`, `exochain-sdk` and `exochain-wasm` so a slim build omits it. | Yes; changes the node's routes and store, the SDK's public API, the WASM exports and the TypeScript packages built on them |
| C. Crate leaves the core | As B with the feature off, and the crate moved out. | Yes; as B, and the published crate changes home |

**Proposal: option A as a provisional compatibility choice, with option B
tracked separately.** The graph result is narrow: no core-class crate requires
`exo-economy`, and it requires only `exo-core`, so including it adds no
dependency to any other core-class crate. It does keep economy routes,
storage and public API in the node, SDK and WASM builds. Option B's direct
code sites are in three adapter crates; its downstream effect on published
APIs and clients has not been inventoried. Issue #902 is titled "Make the
economy layer optional for a slim trust-fabric build"; its text was not
reviewed for this record. Until an option B change lands and CI shows a build
without the crate, no slim-build claim should be made.

Conditions on option A:

1. Part 3 dispositions the `honorgood` module and re-exports, and the
   HonorGood-named root and `docs/` files.
2. Part 4 confirms the licence position of the crate, `.exochain/` economy
   configuration and `governance/commercial-product-licensing.json`.

### Decision status

| Item | Proposed | Decision owner | Open conditions | Status |
| --- | --- | --- | --- | --- |
| `crates/decision-forum`, its gateway routes and WASM bindings, `workflow.rs` | With the core (option A) | Architecture panel | Parts 3 and 4 | Pending |
| `crates/exo-consensus` | With `decision-forum` | Architecture panel | Follows the row above | Pending |
| `web/`, `tools/sybil-cli/`, `docs/decision-forum/` | Legacy repository | Architecture panel | Part 1 judgment rows | Pending |
| `tools/syntaxis/` | Legacy repository | Architecture panel | Part 5 | Pending |
| `crates/exo-economy`, node routes, SDK module, WASM bindings | With the core (option A); optional later (option B) | Architecture panel | Parts 3 and 4 | Pending |
| Seven `exo-dag-db-*` crates and `exo-api` | With the core, since the kernel crate requires them (F-1, F-2) | Architecture and Security panels | F-1 remedy; part 1 class question | Pending |
| `exo-cgr-prover`, `exo-cgr-methods` and fixtures | Not proposed here | Architecture panel | F-8; parts 5 and 6 | Pending |
| `exo-catapult`, `exo-messaging`, `exo-tenant` | Not proposed here | Architecture panel | Part 3 for `exo-catapult` | Pending |

## Findings summary

"Boundary decision" says whether the finding waits on a row of the decision
status table. A finding marked "Yes" there should be treated as blocking the
#903 cutover until the panel records that decision.

| ID | Finding | Proposed disposition | Boundary decision needed | Later-part evidence needed |
| --- | --- | --- | --- | --- |
| F-1 | Kernel manifest requires seven DAG DB crates and `sqlx` on native targets | `patch` | Yes | No |
| F-2 | Kernel crate takes `exo-api` by default | `no_change` if accepted | Yes | No |
| F-3 | Decision Forum required ungated by gateway, consensus and WASM | `no_change` under option A | Yes | Parts 3, 4 |
| F-4 | Four declared Decision Forum dependencies not named in source | `patch` | No | Part 5 (CI check) |
| F-5 | No core-class crate requires economy; three adapters require it ungated | `no_change` under option A | Yes | Parts 3, 4 |
| F-6 | Four core-class crates outside the node and gateway closures | `no_change` | No | Part 3 for `exo-catapult` |
| F-7 | `AGENTS.md` and `crates/README.md` differ from the manifests | `patch` | No | No |
| F-8 | Workspace tests read fixtures from an excluded crate | `patch` | Yes | Parts 5, 6 |

Effect on part 1: F-1 and F-2 bear on the adapter question part 1 raises. For
the seven DAG DB crates and `exo-api`, "core runtime adapter" describes their
role, not their separability from the kernel crate.

## Observations forwarded to later parts

| ID | Observation | Evidence | Goes to |
| --- | --- | --- | --- |
| O-14 | 34 Rust files in 12 crates contain `CARGO_MANIFEST_DIR` or a `../../` path. These are search candidates, not confirmed cross-crate reads: some resolve inside the same crate (for example a crate's own `migrations/`), and one writes fixtures. The paths have not been resolved or classified, apart from the two in F-8. | Search of `crates/**/*.rs` | Part 5 |
| O-15 | 22 `package.json` files contain `exochain-wasm` or `@exochain/`, including ones under `demo/`, `command-base/`, `exoforge/` and `tools/syntaxis/`. Matches include package names, so this is not a dependency graph. | Search of `package.json` files | Part 5 |
| O-16 | Seven files under `tools/` and `.github/workflows/release.yml` contain a boundary crate's package name. | Search of `tools/`, `.github/`, `deploy/`, `Dockerfile` | Part 5 |
| O-17 | Gateway migrations include `20260426000001_livesafe_composite_basis_points.sql`. | `crates/exo-gateway/migrations/` | Part 3 |

## Limits

- Declared dependencies between workspace crates at one commit. Nothing was
  compiled, so no claim here says a subset builds or passes tests.
- Closures follow normal edges. Dev edges are listed but not closed over, so
  the test closure of each crate is not given.
- Third-party crates were not analysed beyond naming `sqlx` in F-1. The
  security weight of the kernel crate's third-party set is not assessed.
- The extractor does not record requested features or `default-features`, and
  feature unification across a multi-crate build is not analysed.
- Source searches are text searches. They find a crate's library name; they
  do not resolve re-exports, macros or generated code.
- Non-manifest inputs (fixtures, migrations, documents read by tests), CI,
  deployment inputs and JavaScript packages are not closed over here.
- The boundary proposals rest on dependency evidence only. Product, licence
  and build evidence from parts 3 to 5 can change them.

## Reproduction

From a checkout of the audited commit, with this record's directory present:

```bash
cargo metadata --no-deps --offline --format-version 1 > meta.json
python3 docs/audit/core-separation-904/dependency_graph.py < meta.json | sha256sum
```

The digest must equal the edge-list SHA-256 above. Dependents of each crate:

```bash
awk -F'\t' '$3=="normal" && $4=="no" {print $2}' \
  docs/audit/core-separation-904/workspace-dependency-edges.tsv | sort | uniq -c
```

The closure sizes are a transitive walk of the same rows; no script for them
is committed. Nothing is compiled.

## Path classification of this record

| Path | Classification |
| --- | --- |
| `docs/audit/core-separation-904/02-DEPENDENCY-CLOSURE-AND-BOUNDARIES.md` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/dependency_graph.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/workspace-dependency-edges.tsv` | EXOCHAIN core (governance evidence) |

Core regression statement: this record adds three files under `docs/audit/`.
It changes nothing under `crates/`, `packages/`, `governance/`, `tools/`,
`.github/` or any deployment file, and it does not edit `GAP-REGISTRY.md`.

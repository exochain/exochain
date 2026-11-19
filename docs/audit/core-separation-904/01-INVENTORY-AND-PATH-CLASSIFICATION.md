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

# Clean-separation audit (#904), part 1: pinned inventory and proposed path partition

**Status: DRAFT audit evidence. Not panel-reviewed. Not a split plan, not a
release record, and not a cryptographic certification.**

This is the first of seven records for issue #904, "Audit the trust-fabric
core for clean separation before the repository split". It fixes the audited
commit and proposes a class for every tracked path under the five classes in
the `AGENTS.md` section "Required Classification". Later parts build on this
inventory:

| Part | Subject |
| --- | --- |
| 1 (this record) | Pinned inventory and proposed path partition |
| 2 | Dependency closure; Decision Forum and economy boundary |
| 3 | Product fingerprints inside non-adjacent paths, with dispositions |
| 4 | Licence and notice inventory |
| 5 | Build, CI, deployment and release coupling |
| 6 | History and provenance disclosure |
| 7 | Findings register and council input |

## What this record does and does not establish

It is a **proposed partition**. Only 329 of the 3,175 paths carry a class that
maintainers assigned to that exact path. Every other class in the inventory is
this audit's extension of an existing record, its reading of `AGENTS.md`, or
its own judgment, and needs panel confirmation.

It does **not** decide what is copied into a new core repository, and a class
does not determine inclusion. Paths proposed as "core runtime adapter" are
presumed in scope for the dependency closure in part 2 exactly as core paths
are. A path proposed as "EXOCHAIN core" can still carry product material; a
path proposed as "adjacent surface" can still be a build input of a core
crate. Those questions belong to parts 2, 3 and 5.

No claim in this record says the core is product-free or that any path is
Apache-2.0. Licence terms are part 4.

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` (`main`, "feat(avc): offline level-3 receipt verification (exochain-verify) (#912)") |
| Tracked paths | 3,175 |
| Path-list SHA-256 | `fcdd05e4f5f8605cc6f23e2753bc932c6950052458be7c75280c7a36b4f32093` |
| Inventory | `docs/audit/core-separation-904/path-classification.tsv` |
| Inventory SHA-256 | `0640fb42fa7d2b69ff13599d9e2ee25ea825bfa8cd4553a0ef5a7ac280d79667` |
| Classifier | `docs/audit/core-separation-904/classify_paths.py` |

The path list is the byte output of
`git -c core.quotepath=off ls-tree -r --name-only <commit>`. The tree holds
3,100 blobs with mode `100644` and 75 with mode `100755`. It has no symlinks,
no gitlinks and no `.gitmodules`, so no tracked path points outside this list.

## Method

1. **Exact-path precedent.** `governance/releases/v0.2.6/PATH-CLASSIFICATION.md`
   classifies 329 paths. All 329 exist at the audited commit and keep the
   class that record gives them (rule id `P0`, basis `precedent-exact`).
2. **Ordered rules.** Every other path takes the class of the first matching
   rule in the table below.
3. **Basis.** Each row records why it has its proposed class:

   | Basis | Meaning | Needs panel confirmation |
   | --- | --- | --- |
   | `precedent-exact` | The v0.2.6 inventory classifies this exact path. | No, apart from the conflicts listed below |
   | `precedent-family` | An in-repo record classifies the directory or family the path belongs to. Extending it to this path is this audit's inference. | Yes |
   | `rule` | The `AGENTS.md` class definition names this kind of path. | Yes |
   | `judgment` | This audit's call. | Yes |

4. **Flags.** Mechanical markers for later parts:
   - `name:<product>`: a product name appears in the full repository-relative
     path (directories included) of a row not proposed as adjacent. No file
     content was searched.
   - `boundary:<area>`: the path matches a boundary area, whatever its class.
     Issue #904 names two boundaries, Decision Forum/workflow and economy.
     `boundary:catapult`, and the inclusion of `crates/exo-consensus/` under
     `boundary:decision-forum`, are this audit's additions.
   - `agents-text-names-core`, `conflict:*`, `rule-would-say:*`: disagreements
     between sources, explained in the next two sections.
   - `product-guard`, `mixed-content`, `generated`, `agent-artifact`, `binary`:
     descriptive markers.

The classifier reads no clock, network or random source, and its output is
sorted. It stops if the input has a duplicate path, if a path matches no rule,
or if a v0.2.6 path is absent. Two runs over the same path list produced the
same SHA-256.

### Rule table

Rules apply in this order. `P0` overrides all of them.

| Rule | Paths | Proposed class | Basis |
| --- | --- | --- | --- |
| V1 | `Cargo.lock`, `package-lock.json` at any depth | third-party/vendor | precedent-family |
| V2 | `tools/python-release-requirements.lock` | third-party/vendor | precedent-family |
| V3 | `packages/*/dist/`, `packages/*/dist-test/` | third-party/vendor | precedent-family |
| V4 | `demo/coverage/` | third-party/vendor | judgment |
| A1 | `livesafe/` | adjacent surface | precedent-family |
| A2 | `cybermedica/` | adjacent surface | precedent-family |
| A3 | `command-base/` | adjacent surface | precedent-family |
| A4 | `demo/` | adjacent surface | precedent-family |
| A5 | `exoforge/` | adjacent surface | precedent-family |
| A6 | `.archon/` | adjacent surface | precedent-family |
| A7 | `site/` | adjacent surface | rule |
| A8 | `web/` | adjacent surface | judgment |
| A9 | `gap/` | adjacent surface | judgment |
| A10 | `docs/commandbase-foundation/` | adjacent surface | judgment |
| A11 | `docs/heartfield/` | adjacent surface | precedent-family |
| A12 | `docs/decision-forum/` | adjacent surface | judgment |
| A13 | `scripts/livesafe-*` | adjacent surface | judgment |
| A14 | `.github/workflows/livesafe-*` | adjacent surface | judgment |
| A15 | `.github/workflows/exoforge-*`, `.github/ISSUE_TEMPLATE/` | adjacent surface | precedent-family |
| A16 | `.claude/`, `.cursor/`, `.superpowers/` | adjacent surface | judgment |
| A17 | `tools/sybil-cli/` | adjacent surface | judgment |
| R1 | `crates/exo-api`, `exo-gateway`, `exo-node`, `exochain-sdk`, `exochain-wasm` | core runtime adapter | precedent-family |
| R2 | `crates/exo-dag-db-*` | core runtime adapter | precedent-family |
| R3 | `packages/` (owned source) | core runtime adapter | precedent-family |
| R4 | `.github/workflows/retire-*` | core runtime adapter | judgment |
| R5 | Root `Dockerfile`, `railway.json`, `init-db.sh`, `docker-compose*.yml`, `.dockerignore`, `.env.example` | core runtime adapter | rule |
| R6 | `deploy/` | core runtime adapter | rule |
| R7 | `artifacts/trust/` | core runtime adapter | judgment |
| C3p | `tools/test_livesafe_*`, `test_commandbase_*`, `test_heartfield_*`, `test_demo_*` | EXOCHAIN core | precedent-family |
| R8 | Top-level `tools/` files whose name contains `release`, `publish`, `recover`, `retire`, `transport`, `cratesio`, `sbom`, `sealed` or `stage_llm` | core runtime adapter | precedent-family |
| R8b | Top-level `tools/` files whose name contains `wasm_npm`, `railway`, `docker`, `deployment`, `live_node`, `public_route`, `public_exochain_route`, `root-trust`, `root_trust`, `avc_emit`, `avc_rfc3161` or `llm_usage` | core runtime adapter | judgment |
| R9 | `docs/guides/` | core runtime adapter | precedent-family |
| R9b | `docs/dagdb/`, `docs/reference/` | core runtime adapter | judgment |
| R10 | `INTEGRATION.md` | core runtime adapter | judgment |
| C1 | `crates/` (remaining) | EXOCHAIN core | precedent-family |
| C2 | `fuzz/` | EXOCHAIN core | precedent-family |
| C2b | `tla/`, `tests/` | EXOCHAIN core | judgment |
| C3 | `tools/cross-impl-test/`, `tools/test_*` (remaining) | EXOCHAIN core | precedent-family |
| C3b | `tools/` (remaining) | EXOCHAIN core | judgment |
| C4 | `governance/releases/` | EXOCHAIN core | precedent-family |
| C4b | `governance/` (remaining) | EXOCHAIN core | rule |
| C5 | `docs/audit/`, `docs/superpowers/` | EXOCHAIN core | precedent-family |
| C5b | `docs/` (remaining) | EXOCHAIN core | judgment |
| C6 | `.github/` (remaining) | EXOCHAIN core | judgment |
| C7 | `.cargo/audit.toml` | EXOCHAIN core | precedent-family |
| C7b | `.cargo/` (remaining), `.exochain/` | EXOCHAIN core | judgment |
| C8 | `Initiatives/` | EXOCHAIN core | precedent-family |
| C8b | `agents/` | EXOCHAIN core | judgment |
| C9 | Root files (remaining) | EXOCHAIN core | judgment |

Rule C3p keeps the guards that test an adjacent product's boundary with the
core in the core class, following the supply-chain validation record's
treatment of `tools/test_*`. They carry the `product-guard` flag because a
core repository without those products would have nothing for them to guard.

Sources for the `precedent-family` rules:

| Source | Rules it supports |
| --- | --- |
| `governance/releases/v0.2.6/PATH-CLASSIFICATION.md` | V1, V2, V3, R1, R2, R3, R8, R9, C1, C2, C4, C5, C8 |
| `docs/audit/GAUNTLET-SUPPLY-CHAIN-VALIDATION-2026-05-15.md` | A3, C3, C3p, C7 |
| `docs/audit/codex-security-findings-2026-05-16-triage.md` | A4, A6, A15 |
| `docs/quality/archon-avc-quality-matrix.md` | A6 |
| `exoforge/EXOCHAIN_SURFACE_INTAKE.md` | A5 |
| `docs/heartfield/INTAKE.md` | A11 |
| `AGENTS.md` note that `livesafe/` is a proprietary subtree excluded from the workspace | A1 |
| `cybermedica/docs/implementation/PATH_CLASSIFICATION.md` | A2 |

## `AGENTS.md` text versus the v0.2.6 record

The `AGENTS.md` definition of "EXOCHAIN core" lists "node, gateway, SDK,
WASM" and "CI gates". The v0.2.6 record, the only per-path inventory in the
repository, classes the files of those crates and the two main workflows as
"core runtime adapter".

This record follows v0.2.6 and marks every affected row with
`agents-text-names-core`:

| Paths | Rows | Basis |
| --- | ---: | --- |
| `crates/exo-gateway/`, `crates/exo-node/`, `crates/exochain-sdk/`, `crates/exochain-wasm/` | 159 | 30 precedent-exact, 129 precedent-family |
| `.github/workflows/ci.yml`, `.github/workflows/release.yml` | 2 | precedent-exact |
| **Total** | **161** | |

The choice does not change what later parts examine, because adapter paths are
in scope for the dependency closure either way. It does change the headline
totals: read the `AGENTS.md` text literally and these 161 rows move from
adapter to core. **The panel is asked to say which source governs.**

## Conflicts between in-repo records

Where two in-repo records give one path different classes, this record applies
one policy: the v0.2.6 exact-path class wins, because it is the newer record
and the only one written per path. Where v0.2.6 is silent, the v0.2.6
convention for that kind of file is extended. Each conflict is flagged in the
inventory and listed here for the panel.

| Path | Proposed here | Source followed | Other record says |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | core runtime adapter | v0.2.6 exact | Supply-chain validation record: core |
| `Cargo.lock` | third-party/vendor | v0.2.6 exact | Supply-chain validation record: core |
| `cybermedica/package-lock.json` | third-party/vendor | v0.2.6 lockfile convention (V1) | CyberMedica subtree record: adjacent surface |
| `tools/test_*` release, publish and transport guards (R8) | core runtime adapter | v0.2.6 family | Supply-chain validation record: `tools/test_*` core |

Eight v0.2.6 exact classes also differ from what this record's own rule table
would assign. The v0.2.6 class was kept (`rule-would-say:*`):

| Path | v0.2.6 class | Rule table would say |
| --- | --- | --- |
| `.github/workflows/ci.yml`, `.github/workflows/release.yml` | core runtime adapter | core (C6) |
| `crates/exo-pdp/src/http.rs` | core runtime adapter | core (C1) |
| `packages/exochain-wasm/wasm/package.json` | third-party/vendor | adapter (R3) |
| `tools/test_gateway_db_ci.sh`, `tools/test_github_actions_pinned.sh`, `tools/test_python_sdk_ci_boundary.sh`, `tools/test_verify_npm_registry_attestation.sh` | core runtime adapter | core (C3) |
| `tools/verify_npm_registry_attestation.mjs` | core runtime adapter | core (C3b) |

## Proposed totals

| Proposed class | Paths | Share |
| --- | ---: | ---: |
| EXOCHAIN core | 625 | 19.7% |
| Core runtime adapter | 620 | 19.5% |
| Adjacent surface | 1,680 | 52.9% |
| Imported evidence | 0 | 0.0% |
| Third-party/vendor | 250 | 7.9% |
| **Total** | **3,175** | |

"Imported evidence" is currently assigned to no path. That is not a finding
that none exists: this record did not review any file's provenance (part 6).

| Basis | Paths | Share |
| --- | ---: | ---: |
| precedent-exact | 329 | 10.4% |
| precedent-family | 2,294 | 72.3% |
| rule | 173 | 5.4% |
| judgment | 379 | 11.9% |

### Paths per rule

| Rule | Paths | Rule | Paths | Rule | Paths | Rule | Paths |
| --- | ---: | --- | ---: | --- | ---: | --- | ---: |
| P0 | 329 | A10 | 10 | R3 | 70 | C3 | 34 |
| V1 | 11 | A11 | 4 | R4 | 1 | C3b | 20 |
| V2 | 0 | A12 | 5 | R5 | 8 | C4 | 85 |
| V3 | 119 | A13 | 1 | R6 | 5 | C4b | 16 |
| V4 | 32 | A14 | 2 | R7 | 4 | C5 | 39 |
| A1 | 482 | A15 | 4 | C3p | 7 | C5b | 78 |
| A2 | 385 | A16 | 3 | R8 | 24 | C6 | 2 |
| A3 | 256 | A17 | 16 | R8b | 11 | C7 | 1 |
| A4 | 180 | R1 | 156 | R9 | 13 | C7b | 5 |
| A5 | 15 | R2 | 154 | R9b | 18 | C8 | 5 |
| A6 | 13 | | | R10 | 1 | C8b | 5 |
| A7 | 144 | | | C1 | 233 | C9 | 17 |
| A8 | 83 | | | C2 | 4 | | |
| A9 | 59 | | | C2b | 6 | | |

The counts sum to 3,175. `P0` splits as core 68, adapter 155, adjacent 18,
vendor 88. V2 matches nothing beyond its one path, which v0.2.6 already
classifies exactly.

## Top-level rollup

| Path | Core | Adapter | Adjacent | Imported | Vendor | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| (root files) | 23 | 9 | 0 | 0 | 1 | 33 |
| `.archon/` | 0 | 0 | 13 | 0 | 0 | 13 |
| `.cargo/` | 2 | 0 | 0 | 0 | 0 | 2 |
| `.claude/` | 0 | 0 | 1 | 0 | 0 | 1 |
| `.cursor/` | 0 | 0 | 1 | 0 | 0 | 1 |
| `.exochain/` | 4 | 0 | 0 | 0 | 0 | 4 |
| `.github/` | 2 | 3 | 6 | 0 | 0 | 11 |
| `.superpowers/` | 0 | 0 | 1 | 0 | 0 | 1 |
| `Initiatives/` | 6 | 0 | 0 | 0 | 0 | 6 |
| `agents/` | 5 | 0 | 0 | 0 | 0 | 5 |
| `artifacts/` | 0 | 4 | 0 | 0 | 0 | 4 |
| `command-base/` | 0 | 0 | 256 | 0 | 1 | 257 |
| `crates/` | 282 | 354 | 0 | 0 | 1 | 637 |
| `cybermedica/` | 0 | 0 | 385 | 0 | 1 | 386 |
| `demo/` | 0 | 0 | 180 | 0 | 37 | 217 |
| `deploy/` | 0 | 5 | 0 | 0 | 0 | 5 |
| `docs/` | 121 | 34 | 19 | 0 | 0 | 174 |
| `exoforge/` | 0 | 0 | 15 | 0 | 0 | 15 |
| `fuzz/` | 5 | 0 | 0 | 0 | 1 | 6 |
| `gap/` | 0 | 0 | 59 | 0 | 0 | 59 |
| `governance/` | 105 | 0 | 0 | 0 | 0 | 105 |
| `livesafe/` | 0 | 0 | 500 | 0 | 5 | 505 |
| `packages/` | 0 | 121 | 0 | 0 | 199 | 320 |
| `scripts/` | 0 | 0 | 1 | 0 | 0 | 1 |
| `site/` | 0 | 0 | 144 | 0 | 1 | 145 |
| `tests/` | 1 | 0 | 0 | 0 | 0 | 1 |
| `tla/` | 5 | 0 | 0 | 0 | 0 | 5 |
| `tools/` | 64 | 90 | 16 | 0 | 2 | 172 |
| `web/` | 0 | 0 | 83 | 0 | 1 | 84 |
| **Total** | **625** | **620** | **1,680** | **0** | **250** | **3,175** |

## Crate rollup

All 35 directories under `crates/`, plus `crates/README.md` (core). The
"Boundary" column marks crates whose place in the core part 2 has to settle.
`decision-forum` and `exo-economy` are the two boundaries issue #904 names;
`exo-consensus` and `exo-catapult` are this audit's additions.

| Crate directory | Proposed class | Paths | Boundary |
| --- | --- | ---: | --- |
| `decision-forum` | EXOCHAIN core | 21 | decision-forum (issue) |
| `exo-api` | core runtime adapter | 28 | |
| `exo-authority` | EXOCHAIN core | 7 | |
| `exo-avc` | EXOCHAIN core | 13 | |
| `exo-catapult` | EXOCHAIN core | 13 | catapult (audit) |
| `exo-cgr-methods` | EXOCHAIN core (1 lockfile vendor) | 6 | |
| `exo-cgr-prover` | EXOCHAIN core | 5 | |
| `exo-consensus` | EXOCHAIN core | 14 | decision-forum (audit) |
| `exo-consent` | EXOCHAIN core | 7 | |
| `exo-core` | EXOCHAIN core | 14 | |
| `exo-dag` | EXOCHAIN core | 14 | |
| `exo-dag-db-api` | core runtime adapter | 6 | |
| `exo-dag-db-core` | core runtime adapter | 8 | |
| `exo-dag-db-domain` | core runtime adapter | 27 | |
| `exo-dag-db-exchange` | core runtime adapter | 11 | |
| `exo-dag-db-graph` | core runtime adapter | 6 | |
| `exo-dag-db-lab` | core runtime adapter | 26 | |
| `exo-dag-db-postgres` | core runtime adapter | 67 | |
| `exo-dag-db-retrieval` | core runtime adapter | 15 | |
| `exo-economy` | EXOCHAIN core | 21 | economy (issue) |
| `exo-escalation` | EXOCHAIN core | 11 | |
| `exo-gatekeeper` | EXOCHAIN core | 14 | |
| `exo-gateway` | core runtime adapter | 35 | |
| `exo-governance` | EXOCHAIN core | 15 | |
| `exo-identity` | EXOCHAIN core | 13 | |
| `exo-legal` | EXOCHAIN core | 16 | |
| `exo-messaging` | EXOCHAIN core | 8 | |
| `exo-node` | core runtime adapter | 92 | |
| `exo-pdp` | EXOCHAIN core (1 file adapter by v0.2.6) | 14 | |
| `exo-proofs` | EXOCHAIN core | 17 | |
| `exo-root` | EXOCHAIN core | 11 | |
| `exo-tenant` | EXOCHAIN core | 10 | |
| `exo-verify` | EXOCHAIN core | 19 | |
| `exochain-sdk` | core runtime adapter | 13 | |
| `exochain-wasm` | core runtime adapter | 19 | |

## Flag counts

| Flag | Rows | By proposed class |
| --- | ---: | --- |
| `boundary:decision-forum` | 151 | core 35, adapter 2, adjacent 113, vendor 1 |
| `boundary:economy` | 63 | core 46, adapter 4, adjacent 11, vendor 2 |
| `boundary:workflow` | 24 | core 14, adjacent 10 |
| `boundary:catapult` | 19 | core 14, adapter 1, adjacent 4 |
| `agents-text-names-core` | 161 | adapter 161 |
| `generated` | 228 | |
| `agent-artifact` | 27 | |
| `product-guard` | 7 | core 7 |
| `mixed-content` | 7 | adjacent 7 |

`name:<product>` rows, all on paths not proposed as adjacent:

| Product name | Under `crates/` | Elsewhere |
| --- | ---: | ---: |
| crosschecked | 26 | 3 |
| zerodentity | 16 | 3 |
| catapult | 14 | 1 |
| livesafe | 5 | 10 |
| honorgood | 1 | 10 |
| exoforge | 1 | 1 |
| commandbase | 0 | 5 |
| archon | 0 | 4 |
| cybermedica | 0 | 1 |
| heartfield | 0 | 1 |

## Judgment rows that need panel confirmation

379 paths rest on this audit's judgment. Grouped:

| Paths | Count | Proposed class | Why it is a judgment |
| --- | ---: | --- | --- |
| `web/` | 83 | adjacent surface | `web/package.json` names the package as the Decision Forum web UI. No in-repo record classifies `web/`. Its class follows the Decision Forum boundary decision in part 2. |
| `gap/` | 59 | adjacent surface | Its README describes an incubator workspace. No intake record or prior classification. Seven `gap/ULTRAPLAN-GAP-*` files discuss core gaps and are flagged `mixed-content` for part 3. |
| Other `docs/` subtrees (C5b, excluding `docs/c2/`) | 49 | EXOCHAIN core | Only `docs/audit/`, `docs/superpowers/` and `docs/guides/` have precedent. `docs/economy/` and `docs/honorgood/` follow the economy boundary decision in part 2. Three of these documents carry a product-name flag (O-11). |
| `demo/coverage/` | 32 | third-party/vendor | Generated coverage report, classed as generated output. The alternative is "imported evidence", since it is tool output committed to the tree. |
| `docs/c2/` | 29 | EXOCHAIN core | Mission command-and-control protocol documents read by a scheduled workflow. Could be argued adjacent. |
| `tools/syntaxis/`, `tools/codegen/`, six top-level `tools/` scripts (C3b) | 20 | EXOCHAIN core | `AGENTS.md` names `syntaxis` and `codegen` as workspace tooling; none was classified per path before. `tools/syntaxis/` also carries `boundary:workflow`. |
| `docs/dagdb/`, `docs/reference/` | 18 | core runtime adapter | Documentation takes the class of what it documents, as the v0.2.6 record does for an adapter runbook. |
| Root files (C9) | 17 | EXOCHAIN core | `AGENTS.md` does not class root files individually. Includes `LICENSE`, `AGENTS.md`, `deny.toml`, two PRDs, two PDFs, `HONOR_GOOD_COMPACT.md` and `AVC_MISSION_ECONOMICS_COMPACT.md`; the last two follow the economy boundary decision. |
| `tools/sybil-cli/` | 16 | adjacent surface | Its README describes a "SYBIL Codex + decision.forum" MVP that is "crosschecked.ai-ready". No prior classification. |
| Deployment and smoke scripts in `tools/` (R8b) | 11 | core runtime adapter | Selected by file-name keyword, not by a prior record. |
| `docs/commandbase-foundation/`, `docs/decision-forum/` | 15 | adjacent surface | Product documentation follows its product. |
| `tla/`, `tests/` | 6 | EXOCHAIN core | Formal models and a root test; not named in any record. |
| `.cargo/config.toml`, `.exochain/` | 5 | EXOCHAIN core | Build and repository configuration. `.exochain/` holds economy and HonorGood configuration, so it follows part 2. |
| `agents/` | 5 | EXOCHAIN core | Agent role definitions; `Initiatives/` has v0.2.6 precedent, `agents/` does not. |
| `artifacts/trust/` | 4 | core runtime adapter | A trust bundle the root `Dockerfile` copies into the image; treated as a deployment input. |
| `.claude/`, `.cursor/`, `.superpowers/` | 3 | adjacent surface | Developer and agent tool state, classed with `.archon/`. |
| `.github/workflows/livesafe-*`, `scripts/livesafe-railway-smoke.sh` | 3 | adjacent surface | Automation that serves one adjacent product. |
| `.github/CODEOWNERS`, `.github/workflows/presidential-daily-attention.yml` | 2 | EXOCHAIN core | Repository governance and a scheduled governance workflow; neither is a build gate. |
| `.github/workflows/retire-0.2.3.yml` | 1 | core runtime adapter | A release-retirement workflow, classed with the release tooling. |
| `INTEGRATION.md` | 1 | core runtime adapter | Documents the adapter surfaces. |

## Observations forwarded to later parts

These are recorded for traceability. They are **not** dispositioned findings;
each is taken up in the part named. "Class" is the proposed class of the paths
the observation concerns.

| ID | Class | Observation | Evidence | Goes to |
| --- | --- | --- | --- | --- |
| O-1 | all | 1,680 of 3,175 tracked paths are proposed as adjacent surface and 250 as vendor or generated. These are path counts in today's repository, not a size estimate for a new one: class does not decide inclusion, and counts say nothing about bytes or build weight. | Totals table | Part 7 |
| O-2 | core | Four core-class crates carry a boundary flag (69 paths): `decision-forum` and `exo-economy`, which the issue names, and `exo-consensus` and `exo-catapult`, which this audit adds. | Crate rollup | Part 2 |
| O-3 | core, adapter | Product names appear in the paths of 101 rows not proposed as adjacent: 63 under `crates/`, 38 elsewhere (one row matches two names). Path matches only; content was not searched. | Flag counts | Part 3 |
| O-4 | vendor | Generated output is tracked: 119 paths under `packages/*/dist` and `dist-test` beyond those listed in v0.2.6, and 32 under `demo/coverage/`. | Rules V3, V4 | Part 5 |
| O-5 | adjacent | 17 files named `hipaa-request-*.pdf` (65,032 bytes in total) are tracked under `livesafe/server/letters/` in a public repository. `git log --diff-filter=A` shows all 17 added by commit `985cd9ba` (2026-07-04), a commit that relocates the LiveSafe app into this repository, so their earlier history is elsewhere. Their content was **not opened** for this record. Whether they hold real personal or health data is unverified. | `git ls-tree -r -l`; `git log --diff-filter=A -- 'livesafe/server/letters/*.pdf'` | Parts 3 and 6 |
| O-6 | mixed | Eight v0.2.6 exact classes differ from this record's rule table and were kept. | Conflicts section | Part 7 |
| O-7 | core, adapter | In-repo records disagree on four points, including whether `ci.yml` and `Cargo.lock` are core. | Conflicts section | Part 7 |
| O-8 | adjacent, core | 27 paths are agent or tool artifacts (`.archon/`, `.claude/`, `.cursor/`, `.superpowers/`, `agents/`, `Initiatives/`). | `agent-artifact` flag | Part 3 |
| O-9 | none | No path is currently assigned "imported evidence". Provenance review is incomplete: no file was checked for being an unlabelled external report or scanner output. | Totals table | Part 6 |
| O-10 | all | No document under `governance/`, `docs/audit/` or `docs/quality/`, and none of the per-surface intake files cited above, classifies every top-level directory. Other locations were not searched. | Sources table | Part 7 |
| O-11 | core, adapter | Four product-named documents are not proposed as adjacent: `docs/execution-ledger/2026-05-10-commandbase.md`, `docs/0DENTITY-APP-SPEC.md` and `docs/catapult-integration-report.md` (core by C5b), and `docs/guides/ARCHON-INTEGRATION.md` (adapter by R9). | `name:*` flag | Part 3 |
| O-12 | core | Seven core-class guards exist only to test an adjacent product's boundary. | `product-guard` flag | Part 5 |
| O-13 | adapter | `AGENTS.md` text and the v0.2.6 record disagree on the class of 161 rows. | `AGENTS.md` section above | Part 7 |

## Limits

- Tracked files at one commit only. Untracked files, other branches, tags,
  release assets and history are outside this record.
- Classes were assigned by path. The only file content read to support a
  proposed class was: the four in-repo classification records and the intake
  files in the sources table, `AGENTS.md`, `gap/README.md`,
  `tools/sybil-cli/README.md`, `web/package.json`, the root `Dockerfile`, and
  `.github/workflows/presidential-daily-attention.yml`.
- A proposed class is not a licence statement and not a copy decision.
- Flags are path matches. A path with no flag can still hold product material.
- 2,846 of 3,175 rows (everything except `precedent-exact`) are this audit's
  proposal and are not maintainer decisions until a panel confirms them.

## Reproduction

From a checkout of the audited commit, with this record's directory present:

```bash
git -c core.quotepath=off ls-tree -r --name-only e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e > paths.txt
sha256sum paths.txt
python3 docs/audit/core-separation-904/classify_paths.py \
  governance/releases/v0.2.6/PATH-CLASSIFICATION.md < paths.txt | sha256sum
```

The two digests must equal the path-list and inventory SHA-256 values in the
"Audited source" table. Nothing is compiled.

## Path classification of this record

| Path | Classification |
| --- | --- |
| `docs/audit/core-separation-904/01-INVENTORY-AND-PATH-CLASSIFICATION.md` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/classify_paths.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/path-classification.tsv` | EXOCHAIN core (governance evidence) |

Core regression statement: this record adds three files under `docs/audit/`.
It changes nothing under `crates/`, `packages/`, `governance/`, `tools/`,
`.github/` or any deployment file, and it does not edit `GAP-REGISTRY.md`.

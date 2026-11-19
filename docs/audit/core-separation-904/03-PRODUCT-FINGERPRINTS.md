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

# Clean-separation audit (#904), part 3: product fingerprints in the proposed core

**Status: DRAFT audit evidence. Not panel-reviewed. Not a split plan, not a
release record, and not a cryptographic certification.**

Issue #904 asks the audit to "identify product fingerprints and stray
references, config, examples, assets, CI paths, and agent artifacts from
LiveSafe, CyberMedica, CommandBase, or other non-core subtrees". This record
searches every path that part 1 does not propose as adjacent surface for the
names of products and adjacent subtrees, reads the match sites in code, CI
and configuration, and proposes a disposition for the groups it read.

It builds on part 1 (`01-INVENTORY-AND-PATH-CLASSIFICATION.md`, the proposed
class of every path) and part 2 (`02-DEPENDENCY-CLOSURE-AND-BOUNDARIES.md`,
findings F-1 to F-8). Findings here continue that numbering.

## What this record does and does not establish

It establishes where the listed names occur in the files part 1 proposes to
keep, and, for the sites it read in code, CI and configuration, what the
occurrence is. It does not establish:

- **that the proposed core is product-free.** A name search finds names. It
  does not find product logic that carries no product name, and the term
  list is not complete: two review passes each found names the previous
  list missed;
- that any file is correctly licensed (part 4). Where a finding mentions
  Apache-2.0 it means the file carries that header, nothing more;
- that anything builds or passes tests with the adjacent trees absent
  (part 5, from CI). Statements that a test "reads" an adjacent file, or
  would fail without it, are read from source, not observed;
- that any finding is a security vulnerability. Several touch
  authentication and data erasure; they are reported as coupling to a named
  product, and no bypass was looked for or found;
- anything about the content of the 14 binary files that were not scanned,
  or of the 1,680 adjacent-class paths (a few of which sit in directories
  the core would keep; see "Coverage by issue category").

Dispositions are proposals for the panels named in part 2. None is a decision.

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` |
| Match list | `docs/audit/core-separation-904/product-fingerprints.tsv` |
| Match list SHA-256 | `92b105d61be0ae1a9e9bf0b275663270d9961be92e7825bf40c8b5c1da347a5b` |
| Scanner | `docs/audit/core-separation-904/fingerprint_scan.py` |
| Input | `path-classification.tsv` from part 1 and the working tree at the audited commit |

## Method

1. Take every path in part 1's classification whose proposed class is not
   "adjacent surface": 625 core, 620 core runtime adapter and 250
   third-party/vendor, 1,495 in all.
2. For each, count case-insensitive matches of 32 patterns in the file's
   text: 23 names and 9 patterns for a reference to an adjacent top-level
   directory as a path. Also test each name against the path itself. The
   match list has one row per file and term, with the count and the first
   matching line.
3. Read the match sites in `crates/`, `.github/`, `.exochain/`, `packages/`,
   `tools/` and the root configuration files. Matches in `docs/` and
   `governance/` were counted and sampled, not read one by one.
4. Group what was read into findings.

Where the names came from, in three passes:

- First pass: `governance/commercial-product-licensing.json` (Decision Forum,
  LegalDyne, CyberMedica, LiveSafe, CrossChecked); `AGENTS.md` (CommandBase,
  crosschecked.ai, livesafe.ai); the adjacent top-level directories and the
  names part 1 flagged (ExoForge, Heartfield, HonorGood, Archon, 0dentity).
- Second pass, from reading match sites: Paperclip, Apex Velocity, LYNK,
  Telegram.
- Third pass, from review: VitalLock, Syntaxis, `decision-forge` and
  cognitiveplane; the literal spelling "0dentity", which the first pattern
  (`zerodentity`) did not match; and the hyphenated form `decision-forum`.

Each pass found names the one before missed. The list should be read as the
names found so far.

## Results by term

479 of the 1,495 files have at least one row. 380 have a match on a term
other than the five set aside below: 233 core, 118 adapter, 29 vendor.

Counts are raw pattern matches. They contain false positives (the path
patterns match prose and URLs) and the search has false negatives (names not
on the list, other spellings, binary content).

| Term | Core | Adapter | Vendor | Files | Matches |
| --- | ---: | ---: | ---: | ---: | ---: |
| `decision-forum`, `decision_forum`, "decision.forum", "Decision Forum" (includes the crate name and the Rust identifier) | 80 | 29 | 3 | 112 | 466 |
| 0dentity (`0dentity`, `zerodentity`, `odentity`) | 32 | 41 | 0 | 73 | 1,649 |
| LiveSafe | 40 | 20 | 7 | 67 | 1,138 |
| CommandBase | 55 | 12 | 0 | 67 | 398 |
| CrossChecked | 32 | 28 | 2 | 62 | 911 |
| ExoForge | 46 | 13 | 2 | 61 | 325 |
| HonorGood | 30 | 10 | 6 | 46 | 230 |
| Archon | 30 | 11 | 3 | 44 | 312 |
| Syntaxis | 29 | 4 | 1 | 34 | 297 |
| Apex Velocity | 15 | 3 | 0 | 18 | 66 |
| Paperclip | 15 | 2 | 0 | 17 | 46 |
| CyberMedica | 11 | 3 | 1 | 15 | 94 |
| VitalLock | 9 | 2 | 2 | 13 | 23 |
| LegalDyne | 10 | 0 | 0 | 10 | 23 |
| `decision-forge` | 1 | 1 | 6 | 8 | 20 |
| Heartfield | 4 | 0 | 0 | 4 | 23 |
| `sybil-cli` | 1 | 2 | 0 | 3 | 7 |
| cognitiveplane | 1 | 1 | 0 | 2 | 2 |
| "customer zero" | 2 | 0 | 0 | 2 | 5 |
| "gap incubator" | 1 | 0 | 0 | 1 | 1 |
| Path `demo/` | 21 | 5 | 2 | 28 | 135 |
| Path `command-base/` | 20 | 5 | 0 | 25 | 145 |
| Path `web/` | 10 | 5 | 6 | 21 | 78 |
| Path `livesafe/` | 18 | 2 | 0 | 20 | 128 |
| Path `exoforge/` | 13 | 2 | 0 | 15 | 26 |
| Path `cybermedica/` | 7 | 3 | 1 | 11 | 35 |
| Path `gap/` | 5 | 0 | 0 | 5 | 6 |
| Path `site/` | 1 | 3 | 0 | 4 | 20 |

Files whose own path contains a name (134 rows): CrossChecked 29,
`decision-forum` 23, 0dentity 19, LiveSafe 15, Syntaxis 14, HonorGood 11,
CommandBase 5, Archon 4, LYNK 4, ExoForge 2, `decision-forge` 2, and one each
for CyberMedica, Heartfield, Paperclip, `sybil-cli`, Telegram and VitalLock.

Five terms are set aside from the product count, with the reason:

| Term | Files | Why set aside |
| --- | ---: | --- |
| LYNK | 86 | The repository presents it as its own protocol: `EXOCHAIN_LYNK_PROTOCOL_NAME = "EXOCHAIN LYNK Protocol"` (`crates/exo-avc/src/llm_usage_receipt.rs:25`), shipped as `packages/exochain-llm-proxy`. It is not in the licensing register. Self-description is not proof of class, so this is proposed `no_change` subject to the panel confirming LYNK is a core name. |
| Path `Initiatives/` | 25 | An in-repository directory of fix records that part 1 proposes as core. |
| HIPAA or PHI | 7 | In code this is a generic sensitivity marker (`Phi`, `crates/exo-dag-db-api/src/lib.rs:65-66`). |
| Telegram | 9 | A third-party service, not a product of the repository. The integration itself is in F-12. |
| Binary, not scanned | 14 | See "Not scanned". |

Files with a product-term match, by area:

| Area | Files | Matches |
| --- | ---: | ---: |
| `crates/exo-node` | 39 | 2,328 |
| `crates/exo-avc` | 4 | 337 |
| `crates/exo-economy` | 11 | 177 |
| `crates/exo-api` | 20 | 141 |
| `crates/exo-gateway` | 9 | 116 |
| `crates/decision-forum` | 21 | 49 |
| `crates/exochain-sdk` | 3 | 37 |
| `crates/exochain-wasm` | 7 | 33 |
| `crates/exo-identity` | 1 | 32 |
| `crates/exo-dag-db-postgres` | 7 | 30 |
| `crates/exo-catapult` | 6 | 21 |
| Eight other crates (`exo-legal`, `exo-governance`, `exo-consent`, `exo-core`, `exo-consensus`, `exo-tenant`, `exo-messaging`, `exo-pdp`) | 14 | 22 |
| `crates/README.md` | 1 | 6 |
| `docs/` | 88 | 1,735 |
| `tools/` | 48 | 592 |
| `governance/` | 30 | 323 |
| Root files | 22 | 269 |
| `packages/` | 10 | 28 |
| `.exochain/` | 4 | 23 |
| `.github/` | 3 | 40 |
| `agents/`, `tla/`, `deploy/` | 7 | 14 |
| Vendor-class files inside adjacent trees (see F-21) | 22 | 246 |

Nineteen crate directories under `crates/` have a product-term match. The
other 16 have none **on these 32 patterns**, which is not the same as having
no product material.

## Findings

Dispositions use the repository's vocabulary (`patch`, `adjacent_patch`,
`no_change`). "Published API" means a `pub` item in a crate of a workspace
that sets `publish = true`. Where a finding says a change is breaking, that
is a reason the panel must choose, not a recommendation to rename.

### F-9. A core-class crate's public API is named for LiveSafe

`crates/exo-avc` (core-class) has a public module
`livesafe_public_output_ceremony` (`src/lib.rs:109`) and re-exports 23
LiveSafe-named items from it and from `public_output_authorization.rs`
(`src/lib.rs:127-155`): constants, types and functions such as
`mint_livesafe_public_adapter_output_authorization_proof`. One constant fixes
the subject: `LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT =
"livesafe.ai"` (`src/public_output_authorization.rs:46`).

The names continue through the adapters:

| Where | What |
| --- | --- |
| `crates/exochain-sdk/src/avc.rs:41-54` | Re-exports LiveSafe-named items in the public SDK |
| `crates/exo-node/src/auth.rs:45-46` | Route `/api/v1/avc/livesafe/public-adapter-output-authorization` |
| `crates/exo-node/src/auth.rs:96-119`, `181-191`, `395-396` | An optional bearer credential accepted on that one route, alongside the admin bearer |
| `crates/exo-node/src/main.rs:52`, `src/cli.rs:276-278` | Module `livesafe_public_output_ceremony_cli` and CLI command `livesafe-public-output-ceremony` |
| `crates/exo-avc/tests/livesafe_public_output_ceremony_tests.rs` | Tests |

LiveSafe is in the licensing register as a commercial product with
`apache_by_proximity: false`. The files carry Apache-2.0 headers; whether a
product-named scheme under that header is a licence problem is part 4.

Security note: this is a credential whose scope is one product's route in
the node's authentication middleware. It is product coupling in a
security-critical file. Nothing here shows a bypass.

Options: accept as a named integration and document it; generalise the names
(a breaking change to a published API and a route); or move the scheme behind
a feature or into its own crate.

Proposed disposition: `patch`, form to be chosen by the Architecture panel.

### F-10. CrossChecked anchor types, routes, a credential, storage and a CLI command are in two adapter crates

`crates/exo-api` has `pub mod crosschecked_anchor` (`src/lib.rs:21`),
described as "Commitment-only CrossChecked anchor wire types". Its fixture
directory `fixtures/crosschecked-anchor-v1/` has 13 files: five CBOR files,
six raw key, hash and signature files, a README and a manifest. There is an
example, three test files and a test support module.

`crates/exo-node` adds `crosschecked_anchor_http` and
`crosschecked_anchor_store` (`src/lib.rs:21-22`), an owner CLI command
`crosschecked-anchor-authority` (`src/cli.rs:208-231`), three test files and
a support module. Its authentication middleware holds a second scoped
credential, `crosschecked_anchor` (`src/auth.rs:97`), and checks the
CrossChecked anchor routes against that credential before any other rule
(`src/auth.rs:385-388`).

`tools/cross-impl-test/` carries a matching fixture. A feature named
`unaudited-crosschecked-receipt-anchor` remains in `exo-node` and
`ci.yml:1045`; its manifest comment says it is a compatibility name that
enables nothing.

The term has 768 content matches in the text files of three crates; the
binary CBOR fixtures were not searched. CrossChecked is in the
licensing register as an "external proprietary product".

Proposed disposition: `patch`, form to be chosen by the Architecture panel
(same options as F-9). Removing it means editing the authentication
middleware.

### F-11. The gateway schema has four LiveSafe tables, and the erasure path deletes from all four

`crates/exo-gateway/migrations/20260316000001_initial_schema.sql` has a block
headed "LiveSafe tables" (from line 114) that creates `livesafe_identities`,
`scan_receipts`, `consent_anchors` and `trustee_shard_status`.

| Where | What |
| --- | --- |
| `crates/exo-gateway/migrations/20260426000001_livesafe_composite_basis_points.sql` | Alters `livesafe_identities` (part 2, O-17) |
| `crates/exo-gateway/src/db.rs`, section "LiveSafe tables" from line 1430 | `insert_livesafe_identity`, `get_livesafe_identity`, `LiveSafeIdentityRow`, `insert_scan_receipt` ("Insert a LiveSafe scan receipt record") |
| `crates/exo-gateway/src/db.rs:497-522` | The erasure transaction deletes from all four tables |
| `crates/exo-gateway/src/db.rs:163`; `src/server.rs:2782-2783` | Erasure reports `livesafe_identities_deleted` |
| `crates/exo-dag-db-postgres/migrations/…000004…`, `…000005…`, `tests/migration_contract.rs` | One LiveSafe match each, in gateway legacy-table contracts |
| `docker-compose.yml:57-65` | Service `livesafe-api`, build context `../livesafe` |
| `init-db.sh:18-30` | Creates a `livesafe` database |
| `.env.example:40-42` | `LIVESAFE_JWT_SECRET` |

The only callers found for the two `livesafe_identity` functions outside
`db.rs` are in a test (`crates/exo-gateway/tests/spline_amber_hygiene.rs`).
Callers of `insert_scan_receipt` were not traced.

Data-handling note: three of the four tables have neutral names, so a rename
of the one LiveSafe-named table would leave LiveSafe-defined data in the core
gateway. Dropping tables without changing the erasure code would break the
erasure transaction. Any change needs a new migration, the erasure-path
change in the same change, and a decision on who is responsible for existing
rows. Applied migrations cannot be deleted.

Proposed disposition: `patch` for the compose service, `init-db.sh` and
`.env.example`; the tables, functions and erasure path wait on the
Architecture and Security panels.

### F-12. The node binary hosts application surfaces with no feature gate

`crates/exo-node/src/main.rs` declares these modules:

| Module | Self-description | How it is wired |
| --- | --- | --- |
| `exoforge` (`src/exoforge.rs`) | "ExoForge — Autonomous Build Orchestration Engine" | Router merged unconditionally (`main.rs:1461`): `/exoforge` dashboard, `/api/v1/forge/*` |
| `zerodentity` (15 files) | "0dentity — sovereign identity scoring application" | Four routers merged unconditionally (`main.rs:1464-1467`): `/0dentity`, `/api/v1/0dentity/*`, a dashboard |
| `telegram` (`src/telegram.rs`) | "Telegram adjutant — agentic chief-of-staff" | Compiled unconditionally; not a router. Its header says it starts only if two environment variables are set |

Both routed surfaces have their own branches in security-relevant code:

- `crates/exo-node/src/auth.rs:233-234` hard-codes `/exoforge` and
  `/api/v1/forge/` as sensitive read paths.
- `crates/exo-node/src/auth.rs:239` defines
  `is_zerodentity_local_signed_write`; requests it matches pass the bearer
  middleware (`auth.rs:390-392`). What the handlers then check was not
  reviewed here.
- `crates/exo-pdp/src/x402.rs:136` (core-class): `is_never_paywalled_path`
  returns true for any path containing `/api/v1/0dentity/`.

Part 1 proposes `exoforge/` (the top-level directory) as adjacent; the node
module of the same name stays in the binary. 0dentity is not in the licensing
register and calls itself an application; whether it is a product is not
recorded anywhere this audit read. It has its own CI coverage job
(`ci.yml:820-852`), two feature flags that gate parts of it, a migration in
`crates/exo-dag-db-postgres`
(`20260623000003_create_zerodentity_record_schema.sql`), and matches in
`exo-gateway` and `exochain-sdk`.

Removing any of these surfaces means editing the authentication middleware
and, for 0dentity, a core-class payment-gating function.

Proposed disposition: `patch` for the ExoForge module, since its subtree is
proposed adjacent. None proposed for 0dentity and Telegram until the panel
says whether they are core.

### F-13. The economy crate's public API includes named arrangements

This addresses the condition part 2 placed on the economy boundary.

`crates/exo-economy/src/honorgood.rs` describes itself as "Canonical HonorGood
fixtures and Apex Velocity Catalyst policy templates". It has eight public
functions, re-exported from the crate root (`src/lib.rs:129-134`):

- `archon_exoforge_ruleset`, `archon_exoforge_legacy_receipt`
- `paperclip_commandbase_ruleset`, `paperclip_commandbase_legacy_receipt`
- `apex_velocity_catalyst_client_services_ruleset`,
  `apex_velocity_catalyst_software_channel_ruleset`,
  `apex_velocity_catalyst_client_services_mission`
- `zero_launch_mission_settlement_reason`

They build rulesets that name receiving systems ("ExoForge", "CommandBase")
and treasuries ("Archon", "Paperclip") with fixed share values in basis
points. The two legacy receipts are built with `settlement_eligible: false`
(`honorgood.rs:166`, `199`), so this record does not say any arrangement has
been executed.

The names are also in the crate's core types, outside that module:

- `MissionType::ApexVelocityCatalystClientServices` and
  `ApexVelocityCatalystSoftwareChannel` (`src/mission.rs:42-43`)
- `RulesetScope::ApexVelocityCatalystCohort` (`src/ruleset.rs:73`)
- the type `HonorGoodRuleset` (`src/ruleset.rs:186`)

They reach `crates/exochain-sdk/src/economy.rs`,
`crates/exochain-wasm/src/economy_bindings.rs`,
`crates/exo-node/src/economy.rs` and `store.rs`, the TypeScript SDK
(`packages/exochain-sdk/src/client.ts`, `types.ts`, `validation.ts`) and
`.exochain/honorgood.yml`, which points at intake files in `command-base/` and
`exoforge/`. The other CommandBase matches in the crate (`adoption.rs`,
`mission.rs`, `price.rs`, `quote.rs`) are in test modules.

So the crate's published API is not name-neutral. Moving `honorgood.rs` out
would leave the enum variants and the type name; those are serialised public
types, so changing them is a breaking change.

Proposed disposition: `patch`. This record proposes that the panel decide the
fixtures, the enum variants and the type name together before the crate is
included; that is a proposal, not an established requirement.

### F-14. `exo-catapult` exposes CommandBase integration metadata

`commandbase_profile: Option<String>` is a public optional field on two agent
types (`crates/exo-catapult/src/agent.rs:66-67`, `83`), and
`commandbase_profile_name` is a public function
(`src/integration.rs:159-163`). Three modules describe themselves as a
"Paperclip concept adapted for ExoChain" (`budget.rs:17`, `goal.rs:17`,
`heartbeat.rs:17`). `crates/exochain-wasm/src/catapult_bindings.rs` sets
the field to `None` (lines 194 and 215).

This is the evidence part 2 (F-6) asked for: one optional field and one
helper function named for an adjacent product. It does not show the crate
depends on CommandBase.

Proposed disposition: `patch` if the crate travels with the core; none needed
if the panel leaves it out.

### F-15. Two gateway unit tests read files from five adjacent trees

Two tests in `crates/exo-gateway/src/dagdb.rs` (test module from line 9334),
`dagdb_full_migration_source_hygiene_guard` and
`dagdb_full_migration_coverage_gate_contract`, read through a `repo_file`
helper:

- `command-base/worker/package.json`, `command-base/worker/index.js`,
  `command-base/worker/worker-db.js`, `command-base/app/package.json`
- `site/src/lib/contact-submissions.ts`
- `web/src/lib/dagdbDurableState.test.ts`, `web/package.json`
- `demo/package.json` and `demo/services/<name>/src/index.js` for a list of
  services that includes `crosschecked-api`, `decision-forge`, `livesafe-api`
  and `vitallock-api`
- `cybermedica/package.json`

All five trees are proposed adjacent. As with F-8, the gateway crate's own
test suite depends on files the split would leave behind. Nothing was run, so
how the tests behave without the files is inferred from source.

Proposed disposition: `patch`; these assertions belong with the trees they
inspect.

### F-16. Guard scripts and CI steps inspect adjacent trees, some alongside core checks

Part 1 (O-12) counted seven core-class guards that test an adjacent product.
The scan finds 48 files under `tools/` with a product-term match. Scripts
whose subject includes an adjacent tree: `test_commandbase_dispatch_identity.sh`,
`test_commandbase_release_hardening.sh`, `test_livesafe_demo_security.sh`,
`test_livesafe_railway_deploy_ref_guard.sh`,
`test_demo_adjacent_boundaries.sh`, `test_demo_wasm_adapter_boundary.sh`,
`test_heartfield_adjacent_intake.sh`, `test_sybil_cli_secret_boundaries.sh`,
`test_gap_syntaxis_yaml_parse.sh`, `test_github_issue_workflow_boundaries.sh`,
`test_archon_avc_quality_matrix.sh`, `test_proprietary_license_boundaries.sh`
and `test_lynk_receipt_privacy.sh`.

A script that names an adjacent directory is not necessarily all adjacent. At
least two mix assertions: `test_proprietary_license_boundaries.sh:100-107`
checks `crates/exo-consent` and `crates/exo-economy`, and
`test_lynk_receipt_privacy.sh` checks core receipt code as well as `site/`.

`.github/workflows/ci.yml` runs several of these (lines 408-411, 504-505,
520-521, 526-527, 540-541), checks `web/dist/` and `demo/web/dist/`
(line 380), and copies the WASM package into `demo/packages/exochain-wasm/`
to run a demo test (lines 995-997).

After a split an adjacent assertion either fails or passes without checking
anything. The full list of CI steps is part 5.

Proposed disposition: per assertion, not per script. Adjacent assertions move
with their subject (`adjacent_patch`); core assertions stay; the workflow
keeps only steps whose subject is still present (`patch`).

### F-17. The Decision Forum crate: what a name search can and cannot say

Part 2 asked this part to examine `crates/decision-forum` for product
material. The evidence:

- The repository describes the crate two ways. Its own `src/lib.rs:19` says
  "the USER-FACING governance application that orchestrates all lower-level
  exochain primitives". The licensing register lists a commercial product
  "Decision Forum" whose `apache_core_primitive` is `crates/decision-forum`.
  An application and a primitive are different claims about the same crate.
- Its 17 source files (9,145 lines) name one other name on the list,
  Syntaxis (`src/workflow.rs:17`, "Syntaxis workflow integration";
  `src/lib.rs:37`). `tools/syntaxis/` is core-class and `gap/syntaxis/` is
  adjacent.
- Module headers describe governance requirements by identifier (GOV-001 to
  GOV-013, TNC-01 to TNC-10, LEG-008, LEG-012) and metrics (M1 to M12).
  `fiduciary_package.rs` builds a "Structured Fiduciary Defense Package" for
  a Business Judgment Rule analysis; `terms.rs` is "Terms and conditions
  management".

A name search cannot sort those modules into reusable enforcement and
application orchestration. That needs someone to read 9,145 lines against a
stated definition of "primitive", which this part did not do. **The part 2
condition is not discharged.** It goes to the Architecture panel as an open
question.

Outside the crate, the name appears in core-class files: imports of
`decision_forum::decision_object::DecisionClass` in `crates/exo-consensus`
(`src/panel.rs:17` in production code; `src/lib.rs:58` and
`src/session.rs:441` in test code), which is the crate dependency part 2
records; doc comments in
`crates/exo-core/src/events.rs:232` and
`crates/exo-governance/src/custody.rs:17`; test code in `crates/exo-legal`
(`cert_902_11.rs:327`, `bundle.rs:913`, both inside test modules); the
heading of the gateway's first migration ("EXOCHAIN decision.forum
persistence layer"); and `Dockerfile:21`, which recommends
`forum.exochain.io` as a separate service.

Proposed disposition: `no_change` in this part. It blocks because the panel
decision is pending, not because of a name.

### F-18. Smaller code references

| Where | What | Proposed |
| --- | --- | --- |
| `crates/exo-consent/src/contract.rs:1237` | A test helper sets `licensed_product` to "CyberMedica" | `patch` (neutral fixture name) |
| `crates/exo-identity/tests/livesafe_integration.rs` | Test file titled "LiveSafe.ai ↔ EXOCHAIN Integration Tests"; it exercises PACE and Shamir APIs | `patch` (rename) |
| `crates/exo-tenant/src/metering.rs:28` | Doc comment "HonorGood zero-fee metrology" | With F-13 |
| `packages/exochain-wasm/test/bridge_verification.mjs` | Names from F-13 in a test | With F-13 |
| `Cargo.toml:53-59` | Comment about, and `exclude` entry for, `livesafe` | `patch` at split |
| `.gitignore`, `.dockerignore` | Entries for `command-base/`, `demo/`, `web/`, VitalLock | `patch` at split |
| `README.md:145`, `docs/guides/architecture-overview.md:48` | "Adjacent cockpit adapter for cognitiveplane.ai" | With F-19 |

### F-19. Root documents, `docs/` and `governance/` name the products throughout

Twenty-two root files, 88 files under `docs/` and 30 under `governance/`
match. They include `README.md`, `CHANGELOG.md`, `AGENTS.md`, two root PRDs,
two root "compact" documents (`HONOR_GOOD_COMPACT.md`,
`AVC_MISSION_ECONOMICS_COMPACT.md`), `docs/0DENTITY-APP-SPEC.md`,
`docs/honorgood/`, `docs/economy/` and release records under
`governance/releases/`.

From sampling, they are of three kinds, which the split should treat
differently. This is a proposed scheme, not a per-file classification:

- living documents that describe the repository (README, AGENTS.md,
  CONTRIBUTING): rewrite at the split;
- product documents (HonorGood, mission economics, 0dentity spec): follow the
  panel's decision on F-12 and F-13;
- dated records (release records, audit reports, execution ledger,
  changelog): rewriting them would alter history. Proposed `no_change`, with
  the findings register (part 7) recording that they name products that have
  moved and where those went.

Proposed disposition: `patch` for the first kind; the others as stated. The
per-file sort is owed to part 7.

### F-20. A core-class crate's key-exchange context is named for VitalLock

`crates/exo-messaging` (core-class, published) defines
`const MESSAGE_KEX_CONTEXT: &[u8] = b"vitallock-message-v1"` in
`src/compose.rs:40` and `src/open.rs:36`, cites the same value in
`src/kex.rs:180`, and describes its envelope as "the wire format for
VitalLock messages" (`src/envelope.rs:17`). VitalLock is a demo application
(`demo/apps/vitallock`, `demo/services/vitallock-api`), which part 1 proposes
as adjacent.

The doc comment is cosmetic. The constant is not: it is a context string in
key derivation, so changing it makes new output incompatible with messages
produced under the old value. This is a naming and compatibility finding.
It is not evidence of a cryptographic weakness.

The first two scan passes missed this because VitalLock was not on the list.

Proposed disposition: `no_change` to the constant unless the Security panel
decides a versioned migration is worth it; `patch` for the doc comment. The
panel should record that a core wire constant carries a demo product's name.

### F-21. Vendor-class files inside adjacent trees

Twenty-two files that part 1 classes as third-party/vendor sit inside
adjacent trees and match: lockfiles under `livesafe/`, `cybermedica/`,
`command-base/`, `web/` and `demo/`, and generated coverage output under
`demo/coverage/`. The coverage HTML is generated, not vendored.

They would leave with their trees, so they are not core fingerprints. They
are counted here because the scan covers every non-adjacent class.

Proposed disposition: `adjacent_patch` (they follow their tree); forwarded to
part 1 as a classification question for `demo/coverage/`.

## Coverage by issue category

The issue lists categories. This table says what this part found for each
and what is left.

| Category | Found in the proposed core | Finding | Not covered here |
| --- | --- | --- | --- |
| Product fingerprints in code | Public APIs, routes, credentials, schema, a wire constant | F-9 to F-14, F-17, F-18, F-20 | Unnamed product logic |
| Stray references in documents | 140 root, `docs/` and `governance/` files | F-19 | Per-file sort (part 7) |
| Config | `.exochain/honorgood.yml`, `provenance.yml`, `mission_economics.yml`, `mcp.example.json`; `docker-compose.yml`, `init-db.sh`, `.env.example`; `Cargo.toml`, `.gitignore`, `.dockerignore`; `deploy/RAILWAY-HANDOFF.md` | F-11, F-13, F-18 | The three `.exochain/` files other than `honorgood.yml` follow F-13 but were not read line by line |
| Examples | `crates/exo-api/examples/generate_crosschecked_anchor_fixtures.rs`; `docs/economy/examples/` (named legacy receipts) | F-10, F-13 | `packages/*/examples` matched only LYNK |
| Assets | Binary fixtures named for CrossChecked; two root PDFs | F-10; "Not scanned" | Content of all 14 binaries |
| CI paths | `ci.yml` steps for adjacent trees; `release.yml` LYNK jobs | F-16, O-20 | Full CI inventory (part 5) |
| Agent artifacts | Core-class: `AGENTS.md`, `agents/*/AGENTS.md` (one has a `Co-Authored-By: Paperclip` line, `agents/graphql-engineer/AGENTS.md:92`; one references an ExoForge workflow) | F-19 | See next table |

Adjacent-class files that sit in directories the core would keep. Part 1
already proposes them as adjacent; they were not content-scanned here, and
the split must remove them from otherwise-kept directories:

| Location | Adjacent-class paths |
| --- | ---: |
| `.archon/` (agent commands and workflows) | 13 |
| `.claude/`, `.cursor/`, `.superpowers/` | 1 each |
| `.github/workflows/` (`livesafe-*`, `exoforge-*`) | 3 |
| `.github/ISSUE_TEMPLATE/` | 3 |
| `scripts/` (`livesafe-*`) | 1 |
| `docs/commandbase-foundation/`, `docs/decision-forum/`, `docs/heartfield/` | 10, 5, 4 |
| `tools/sybil-cli/` | 16 |

## Not scanned

Fourteen files contain a NUL byte and were not searched:

| Files | Count |
| --- | ---: |
| `EXOCHAIN_Specification_v2.2.pdf`, `EXOCHAIN_Whitepaper_v1.0.pdf` (root) | 2 |
| `crates/exo-api/fixtures/crosschecked-anchor-v1/*.cbor` | 5 |
| `crates/exo-verify/fixtures/offline-bundle/` (two `.cbor`, one `.der`) | 3 |
| `crates/exo-cgr-prover/fixtures/*.cbor` | 2 |
| `demo/coverage/` images | 2 |

Binary files with no NUL byte (for example the raw key and signature files
in F-10) were decoded as text, which finds nothing useful in them.

The two PDFs are the specification and whitepaper. Their text was not
extracted, so whether they name products is unknown. That is fingerprint
work, not licence work, and it is **open**: it needs a text extraction pass
before the split record can say anything about them.

## Findings summary

| ID | Finding | Proposed disposition | Blocks cutover, and why | Later-part evidence |
| --- | --- | --- | --- | --- |
| F-9 | LiveSafe-named API in `exo-avc`, SDK, node route, credential, CLI | `patch` | Yes: product name in published API and a route; form undecided | Part 4 |
| F-10 | CrossChecked anchor in `exo-api` and `exo-node`, with a credential | `patch` | Yes: same reason | Part 4 |
| F-11 | Four LiveSafe tables, erasure path, root deployment files | `patch`; tables pending | Yes: schema and erasure need one coordinated decision | Part 5 |
| F-12 | ExoForge, 0dentity and Telegram surfaces in the node | `patch` for ExoForge | Yes: whether 0dentity and Telegram are core is undecided | No |
| F-13 | Named arrangements in the economy crate's API and enums | `patch` | Yes: bears on the economy boundary | Part 4 |
| F-14 | CommandBase metadata in `exo-catapult` | `patch` if kept | Only if the crate is kept | No |
| F-15 | Two gateway unit tests read 19 files in five adjacent trees | `patch` | Blocks a green core test run (inferred) | Part 5 |
| F-16 | Guards and CI steps that inspect adjacent trees | per assertion | Blocks a green core CI run (inferred) | Part 5 |
| F-17 | Decision Forum crate: not resolved by a name search | `no_change` here | Yes: panel decision pending | Part 4 |
| F-18 | Smaller code references | `patch` | No | No |
| F-19 | Documents name the products | `patch` for living documents | No | Part 7 |
| F-20 | VitalLock in a core key-exchange context | `no_change` to the constant | Needs a recorded Security panel decision | No |
| F-21 | Vendor-class files inside adjacent trees | `adjacent_patch` | No | Part 1 question |

Effect on part 2's three conditions:

- **Economy (`honorgood` module): addressed.** F-13 shows the named items are
  in the module and in core enums. Part 2's option A (crate travels
  unchanged) would publish them from the core.
- **Decision Forum modules: not discharged** (F-17).
- **`exo-catapult`: addressed** (F-14); the coupling is narrow.

## Observations forwarded to later parts

| ID | Observation | Evidence | Goes to |
| --- | --- | --- | --- |
| O-18 | `docker-compose.yml` builds `livesafe-api` from `../livesafe`, a path outside the repository root as written. | `docker-compose.yml:57-59` | Part 5 |
| O-19 | `tarpaulin.toml` excludes `crates/exo-node/src/telegram.rs` from coverage as an external-service integration. | `tarpaulin.toml:30`, `75` | Part 5 |
| O-20 | `.github/workflows/release.yml` has LYNK package jobs from line 3120 (the range was not fully read), and eleven files under `tools/` match LYNK: release tooling and privacy and boundary guards. If LYNK is core they stay. | Match list | Part 5 |
| O-21 | Tracked generated copies under `packages/*/dist` repeat names from F-13. | Six `packages/exochain-sdk/dist*` rows | Part 4 |
| O-22 | LegalDyne is in the licensing register; its ten matching files are documents and one guard, none in crates. | Match list | Part 4 |
| O-23 | A personal account name appears in a source URL in three non-adjacent files (`crates/exo-economy/src/honorgood.rs`, `crates/exochain-wasm/src/economy_bindings.rs`, `packages/exochain-wasm/test/bridge_verification.mjs`). A maintainer's user name appears in 32 non-adjacent files, mostly as local filesystem paths in audit records, release records and `demo/coverage/`. Neither is a product name; both are disclosure questions. | Text search for the two names over the 1,495 scanned paths | Part 6 |

## Limits

- A case-insensitive text search for 32 patterns, plus the same names
  against file paths. It does not find product material that carries none of
  those names.
- The term list is not complete. It grew in three passes, each finding names
  the last one missed. Second-level names inside adjacent trees
  (`demo/apps/*`, `demo/services/*`, `gap/*`) were added only where a
  reviewer or a match site surfaced them.
- Counts are raw pattern matches, with false positives and false negatives.
  The path patterns match prose, URLs and unrelated directories of the same
  name.
- Match sites were read in code, CI, packages, tools and root configuration.
  Matches in `docs/` and `governance/` (118 files) were sampled.
- The 1,680 adjacent-class paths were not content-scanned, including the 58
  that sit in otherwise-kept directories.
- Nothing was compiled or run. Statements about what a test reads, a route
  serves or a middleware allows come from the source text.
- Whether a named item is a problem is a licence and product judgment (part 4
  and the panels). This record reports the names and where they are.

## Reproduction

From a checkout of the audited commit with a clean working tree and this
record's directory present:

```bash
python3 docs/audit/core-separation-904/fingerprint_scan.py \
  docs/audit/core-separation-904/path-classification.tsv . | sha256sum
```

The digest must equal the match-list SHA-256 above. File counts per term:

```bash
awk -F'\t' 'NR>1 {print $3}' \
  docs/audit/core-separation-904/product-fingerprints.tsv | sort | uniq -c
```

## Path classification of this record

| Path | Classification |
| --- | --- |
| `docs/audit/core-separation-904/03-PRODUCT-FINGERPRINTS.md` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/fingerprint_scan.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/product-fingerprints.tsv` | EXOCHAIN core (governance evidence) |

Core regression statement: this record adds three files under `docs/audit/`.
It changes nothing under `crates/`, `packages/`, `governance/`, `tools/`,
`.github/` or any deployment file, and it does not edit `GAP-REGISTRY.md`.

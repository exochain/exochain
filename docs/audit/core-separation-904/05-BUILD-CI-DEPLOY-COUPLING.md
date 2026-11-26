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

# Clean-separation audit (#904), part 5: build, CI, deployment and release coupling

**Status: DRAFT audit evidence. Not panel-reviewed. Not a split plan, not a
build certification, and not a cryptographic certification.**

Issue #904 asks the audit to "verify clean reproducible build/test behavior
without accidental dependencies on excluded siblings", and its acceptance
criteria ask for findings covering "builds, CI/CD". This record lists where
the build, the CI gates, the container images, the deployment files and the
release workflow of the proposed core read paths that part 1 proposes as
adjacent, and what the CI run for the audited commit shows.

**The issue's verification was not completed.** No Rust code was compiled for
this record and no CI run exists for a tree with the siblings removed. What
is established is narrower: which gates name sibling paths, which guard
scripts fail when the siblings are deleted, and which gates cannot be assessed
without a CI run. F-40 states what is still needed.

It builds on part 1 (proposed class of every path), part 2 (dependency
closure, F-1 to F-8), part 3 (product names in the proposed core, F-9 to
F-21) and part 4 (licence inventory, F-22 to F-30). Findings continue that
numbering.

## What this record does and does not establish

It establishes, at the audited commit:

- which CI jobs, guard scripts, Rust tests, container files and deployment
  files name a path that part 1 proposes as adjacent or that lies in one of
  the six product trees;
- the result of the CI run GitHub recorded for the audited commit;
- for the guard commands that could be run on the audit machine, whether each
  passes in an unmodified export and in an export with the sibling paths
  deleted.

It does not establish:

- that the proposed core builds or passes its tests without the siblings.
  The compile gates were not run in either tree (F-40);
- that any build is reproducible. No build was repeated and no two outputs
  were compared (F-38);
- which checks are required before a merge. The repository settings visible
  to the audit token showed none; settings the token cannot see are possible
  (F-32);
- what any published crate, package or image contains. No archive or image
  was built, pulled or inspected (F-39);
- how the hosted services are configured. Deployment facts here are read
  from tracked files, not from the hosting provider;
- anything about the adjacent products' own build health beyond one CI
  result that is reported as observed (O-30).

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` |
| Coupling scan | `docs/audit/core-separation-904/build-coupling.tsv` |
| Coupling scan SHA-256 | `e9f97eb41180ff5e35b46080ea3cec1677c430947c66bcbc523e2491b4dca5f5` |
| Rust path literals | `docs/audit/core-separation-904/rust-path-reads.tsv` |
| Rust path literals SHA-256 | `a6b8b11430dfd7d96c08bf900d1edc97852dfbf0a1aad5e901aacd419bfadd1a` |
| Scripts | `build_coupling_scan.py`, `rust_path_reads.py` in the same directory |
| Experiment results | `docs/audit/core-separation-904/sibling-removal-results.tsv` |
| Experiment results SHA-256 | `144e38988936f3b46a578b0055f97cc36131119e047f0fd6c9778a95f09a9793` |
| Experiment harness | `sibling_removal_prep.py`, `sibling_removal_run.sh` in the same directory |
| Input | `path-classification.tsv` from part 1 and the working tree at the audited commit |
| CI run read | "EXOCHAIN Constitutional CI" run `44003950227` (push to `main`, 2026-11-17T02:34:08Z) |
| Second run read | "LiveSafe Railway Deploy" run `44003950278` (same commit) |

"Sibling", "adjacent tree" and "product tree" below mean the six top-level
directories `command-base/`, `cybermedica/`, `demo/`, `livesafe/`, `site/`
and `web/`. "Adjacent-class path" means any path part 1 proposes as
`adjacent surface`, which also includes, among others, `.archon/`,
`exoforge/`, `gap/`, `docs/decision-forum/`, `tools/sybil-cli/`,
`scripts/livesafe-railway-smoke.sh` and three workflow files. Both
are proposals from part 1, not decisions.

## Method

1. **Coupling scan.** `build_coupling_scan.py` reads the four workflow files
   that are not adjacent-class, the container and compose files, `deploy/`,
   `.cargo/`, the root `Cargo.toml`, `tarpaulin.toml`, `deny.toml` and
   `rustfmt.toml`, every `build.rs`, and each file under `tools/` that one of
   those workflows names (one level; a tool called only by another tool is
   not followed). For every token that equals a tracked file, a tracked
   directory, or a top-level directory name, it writes one row with the
   classes of the target. 1,392 rows from 110 source files.
2. **Rust path literals.** `rust_path_reads.py` tests every string literal
   in `crates/**/*.rs` and `fuzz/` against the tracked paths, resolved
   relative to the file, relative to the crate, and from the repository
   root. A row means the literal resolves to a tracked path outside the
   file's own crate. It does not prove the path is opened. 45 rows.
3. **CI run.** The job list and the logs of the failed jobs of run
   `44003950227` were read through the GitHub API.
4. **Repository settings.** Branch protection for `main` and the repository
   rulesets were requested through the same API.
5. **Sibling-removal experiment.** The guard commands in `ci.yml` that
   compile nothing were run twice on the audit machine: in a byte-exact
   export of the audited commit, and in the same export with 1,726 paths
   deleted (every adjacent-class path, plus the vendor-class paths inside
   the six product trees: `command-base/`, `cybermedica/`, `demo/`,
   `livesafe/`, `site/` and `web/`). `cargo`, `npm`, `docker` and the network tools
   were replaced by stubs that exit 97, so nothing was compiled or
   downloaded. A guard that passes in the first tree and fails in the second
   depends on a deleted path. A guard that fails in both could not be
   assessed on this machine. The harness is tracked: `sibling_removal_prep.py`
   builds the removal list and the guard list, and `sibling_removal_run.sh`
   runs them. The exit code of every guard in each tree is in
   `sibling-removal-results.tsv` (SHA-256
   `144e38988936f3b46a578b0055f97cc36131119e047f0fd6c9778a95f09a9793`), from
   one run of that harness on the audit machine. The per-guard logs are not
   tracked, so the failure messages quoted below are the auditors' reading
   of those logs. The removal list has SHA-256
   `743d71ce28ff58ce8e24f5b3ac96903b457af64086c5b05007edf58e220e4d6c` and is
   derivable from `path-classification.tsv` by the rule above. During the
   run a Python launcher wrote an untracked `Python/` cache directory into
   both trees, so later guards ran on trees with that one extra directory.
6. **Reading.** Every finding below was checked against the cited file and
   line.

## The pipeline at the audited commit

Seven workflow files are tracked. Part 1 proposes three as core runtime
adapter, one as core and three as adjacent:

| Workflow | Part 1 class | Trigger | What it does |
| --- | --- | --- | --- |
| `ci.yml` (1,168 lines) | adapter | push, pull request, `workflow_call` | 27 gate jobs, then `all-gates` and `release-candidate` |
| `release.yml` (6,674 lines) | adapter | `workflow_dispatch` | Calls `ci.yml`, then two jobs bound to the `release` and `release-second` environments, signed-tag check, build, SBOM, attestation and publication. Whether those environments have required reviewers was not verified |
| `presidential-daily-attention.yml` | core | not analysed here | Read by the scan only |
| `retire-0.2.3.yml` | adapter | not analysed here | Read by the scan only |
| `livesafe-ci.yml` | adjacent | changes under `livesafe/` | LiveSafe build and tests |
| `livesafe-railway-deploy.yml` | adjacent | push to `main` on listed paths | Deploys the node and LiveSafe (F-36) |
| `exoforge-triage.yml` | adjacent | not analysed here | Issue triage |

`ci.yml` pins its actions by commit SHA, sets `RUSTFLAGS: -D warnings`, and
ends with `all-gates` (lines 1108-1141), which needs all 27 gate jobs.
`release-candidate` needs `all-gates`.

The scan found 92 files under `tools/` that a non-adjacent workflow names:
73 from `ci.yml` only, 15 from `release.yml` only, 2 from both, and one each
from the other two. Part 1 proposes 58 of them as core runtime adapter, 33
as core and one as vendor.

## Findings

Dispositions use the repository's vocabulary (`patch`, `adjacent_patch`,
`no_change`) and are proposals. "Pending" means this record does not settle
the point and names who does.

### F-31. CI is not green at the audited commit: Gates 6 and 7 fail on dependency advisories

Run `44003950227` concluded `failure`. Two jobs failed and two were skipped
as a result; the other 36 job instances succeeded.

| Job | Result | Cause in the log |
| --- | --- | --- |
| Gate 6, Cargo Audit (`ci.yml:299`) | failed | "5 vulnerabilities found", "2 denied warnings" |
| Gate 7, Cargo Deny (`ci.yml:327`) | failed | `advisories FAILED, bans ok, licenses ok, sources ok` |
| All Constitutional Gates | skipped | needs Gates 6 and 7 |
| Release Candidate Readiness | skipped | needs All Constitutional Gates |

The advisories the two logs name:

| Crate | Advisory |
| --- | --- |
| `libp2p-gossipsub` 0.49.4 | RUSTSEC-2026-0534, RUSTSEC-2026-0536 |
| `libp2p-quic` 0.13.0 | RUSTSEC-2026-0525 |
| `libsqlite3-sys` 0.30.1 | RUSTSEC-2026-0459 |
| `quinn-udp` 0.5.14 | RUSTSEC-2026-0538 |
| `pin-utils` 0.1.0 | RUSTSEC-2026-0441 (unmaintained) |
| `rustix` 1.1.2 | RUSTSEC-2026-0486 |

The run list for this workflow on `main` shows success at the four
preceding runs (`3d0941be` on 2026-10-23, `c4ea410f` and `2be25492` on
2026-11-01, `0d3dafd1` on 2026-11-05; run `41973463555`). The audited
commit is the only commit between `0d3dafd1` and itself. Between the two,
`Cargo.lock` gains one package, the workspace's own `exochain-verify`
0.4.0 (668 to 669 packages); every crate in the table above has the same
version at both commits, and `deny.toml` and `.cargo/audit.toml` are
unchanged. So the failure does not come from the audited commit's changes:
the same dependency set passed on 2026-11-05 and failed on 2026-11-17, and
what changed is the advisory database. The first draft of this record said
this "was not determined"; it was corrected after review.

The advisory database keeps moving. A later run of the same workflow, on a push to
this pull request's own branch (`audit/904-core-separation` at `d0287be4`;
run `44915232517`, 2026-11-21), also reports
RUSTSEC-2026-0543: `chrono` 0.4.44 is unmaintained, with no safe upgrade,
and it is in the core closure (`exochain-core`, `exochain-gateway`,
`exochain-node`, `exochain-verify`). It is not in the audited run, which
the table above describes.

One part of the cause is visible. `deny.toml:75-81` ignores `pin-utils`
under the placeholder id `RUSTSEC-0000-0000` (added by commit `bfbfc902` on
2026-11-05, tracked as issue #894). In the audited run `cargo deny` reports
that id as "advisory not found in any advisory database" and "advisory was
not encountered", and fails `pin-utils` under `RUSTSEC-2026-0441`. So the
recorded exception no longer matches the advisory it was written for.

What this settles from part 4: the `licenses` check of `cargo deny` passed
at the audited commit, so the `ring` clarification F-23 asked about does not
fail the step. The difference between the licensing position document and
`deny.toml` (F-23) is unchanged.

Why it matters for the split. There is no green CI baseline at the commit
this audit describes. Gates 1 and 2 (build and test, siblings present) did
succeed; what fails is advisory compliance. A later claim that "the core
passes CI after the split" needs a baseline that passes before it. The
advisories are in networking and storage dependencies of the proposed core,
not in any sibling.

Proposed disposition: `patch` (core maintainers: update or record a reviewed
exception per advisory, and correct the `pin-utils` id). **Blocking** for
any "green CI" or advisory-compliance claim at this commit. Not caused by
the monorepo layout.

### F-32. No required status checks were visible on `main`

The branch API returned `protection.enabled: false` with an empty list of
required status checks and `enforcement_level: "off"`. The rulesets API
returned an empty list.

This is what the audit token could see. A ruleset or setting that the token
is not allowed to read would not appear, so this is not proof that nothing
is enforced. It is consistent with the audited commit being on `main` while
its CI run is failing, but a commit can also reach `main` green and fail
afterwards when new advisories are published.

Why it matters for the split. If no check is required, "CI enforces the
boundary" describes a convention, not a control. That affects F-33 and F-40:
a core-only CI job only protects the boundary if it is required.

Proposed disposition: pending. A repository administrator confirms the
settings; the security panel decides which gates are required.

### F-33. At least twelve guard steps in Gates 7, 9 and 21 fail when the adjacent paths are removed

Eighteen CI-invoked tools name a path in a product tree or an adjacent-class
path, not counting bare directory names. Sixteen read specific paths; two
(`tools/test_github_actions_pinned.sh`, `tools/write_ci_candidate.py`) only
list `.github/workflows/`.

Results of the sibling-removal experiment for those tools:

| Guard (`tools/`) | `ci.yml` line | Unmodified export | Siblings deleted | What the failure names |
| --- | ---: | --- | --- | --- |
| `test_security_critical_dependencies_pinned.sh` | 329 | pass | **fail** | `livesafe/Cargo.lock` |
| `test_demo_adjacent_boundaries.sh` | 407 | pass | **fail** | `demo/LICENSE` |
| `test_livesafe_demo_security.sh` | 409 | pass | **fail** | `demo/apps/livesafe` |
| `test_commandbase_release_hardening.sh` | 411 | pass | **fail** | `command-base/` files |
| `test_github_issue_workflow_boundaries.sh` | 422 | pass | **fail** | `.github/workflows/exoforge-triage.yml` |
| `test_sybil_cli_secret_boundaries.sh` | 505 | pass | **fail** | `tools/sybil-cli/` |
| `check_systemic_integrity_claims.sh` | 517 | pass | **fail** | `docs/decision-forum/SYSTEM-DOCUMENTATION.md` |
| `test_livesafe_railway_deploy_ref_guard.sh` | 527 | pass | **fail** | `.github/workflows/livesafe-railway-deploy.yml` |
| `test_agent_prompt_boundaries.sh` | 537 | pass | **fail** | `.archon/` command and workflow files |
| `test_agent_workflow_bounds.sh` | 539 | pass | **fail** | `.archon/workflows/*.yaml` |
| `test_archon_avc_quality_matrix.sh` | 541 | pass | **fail** | `.archon/workflows/exochain-self-improvement-cycle.yaml` |
| `test_demo_wasm_adapter_boundary.sh` | 992 | pass | **fail** | `demo/` package files |
| `test_proprietary_license_boundaries.sh` | 405 | fail | fail | Not assessed here. It passed in the CI run. In the second tree its message is "livesafe/LICENSE is missing" |
| `test_repo_truth.sh` | 503 | fail | fail | Not assessed: it calls `cargo` |
| `test_github_actions_pinned.sh` | 418 | fail | fail | Not assessed: needs `ruby` |
| `test_gap_syntaxis_yaml_parse.sh` | 521 | pass | pass | Not assessed: without `ruby` it skips the parse. It printed a "No such file" error for `gap/syntaxis/protocols/*.yaml` in the second tree |
| `test_gap_stub_ci_guard.sh` | 416 | pass | pass | Tolerates a missing `web/src` |
| `write_ci_candidate.py` | 1160 | not run | not run | Runs only after `all-gates` |

The harness ran 81 `ci.yml` lines, which hold 76 distinct guard commands
(`test_coverage_policy.sh --check-engine` appears on four lines,
`test_gateway_db_ci.sh` and `test_repo_truth.sh` on two each; every repeat
gave the same result as the first). Across the 76 commands: 22 pass in both trees, 12 pass in the
first and fail in the second (the rows above), and 42 fail in both and could
not be assessed on the audit machine. No guard failed in the first tree and
passed in the second. The 42 are mostly release-tooling tests. Three of them
name a sibling or adjacent-class path in the scan (lines 405, 418 and 503
above); the other 39 name none, which is the scan's evidence, not a run.

Two of the unassessed guards depend on the siblings by their source:
`test_proprietary_license_boundaries.sh` reads `livesafe/` and
`cybermedica/` files, and `test_repo_truth.sh:189` checks
`demo/packages/exochain-wasm/package.json`. `test_repo_truth.sh` also runs
in the cross-platform job (Gate 16, `ci.yml:809`). So the observed count of
twelve is a lower bound, and Gate 16 is likely coupled as well (from source,
not run).

Ten of the twelve are steps of the hygiene job (Gate 9, `ci.yml:353-545`).
`test_security_critical_dependencies_pinned.sh` is a step of the Gate 7 job
and opens `livesafe/Cargo.lock` (script line 239).
`test_demo_wasm_adapter_boundary.sh` is a step of the Gate 21 job (F-34).

Seven of the twelve fail on adjacent-class paths outside the six product
trees (`.archon/` three times, `tools/sybil-cli/`, `docs/decision-forum/`,
`exoforge-triage.yml`, `livesafe-railway-deploy.yml`). They depend on part
1's proposal for those paths, which is a narrower and less settled question
than the product trees. The other five fail inside product trees.

Part 1 flagged seven guards as existing only to test a product's boundary
(O-12), and part 3 raised the group as F-16. The experiment turns that
inference into an observed result for the guards that could be run.

The guards split into three kinds, which need different handling:

- **Product guards** test the product itself
  (`test_commandbase_release_hardening.sh`, `test_livesafe_demo_security.sh`,
  `test_demo_adjacent_boundaries.sh`,
  `test_livesafe_railway_deploy_ref_guard.sh`). They leave with the product.
- **Boundary guards** test that the core does not treat a product as core
  (`test_proprietary_license_boundaries.sh`, parts of `test_repo_truth.sh`).
  After a split the assertion changes from "this path is marked proprietary"
  to "this path is absent".
- **Core guards with one product input**
  (`test_security_critical_dependencies_pinned.sh`,
  `check_systemic_integrity_claims.sh`). Only the product input moves.

The remaining guards follow the classification of what they read, which
this record does not decide: the three `.archon/` guards (which enforce the
agent-workflow rules in `AGENTS.md`), `test_sybil_cli_secret_boundaries.sh`,
`test_github_issue_workflow_boundaries.sh` and
`test_demo_wasm_adapter_boundary.sh` (F-34). If the paths stay adjacent, the
guards go with them; if part 1's proposal changes, they stay.

A separate risk: some checks would pass after a split while testing
nothing. `test_gap_stub_ci_guard.sh` tolerates a missing `web/src`, the
tracked-artifact check at `ci.yml:380` passes when `web/dist/` and
`demo/web/dist/` do not exist, and `test_beta_codeowners.sh` asserts
`/demo/` routes in `.github/CODEOWNERS` (lines 48-49). Part 3 raised this
under F-16. Each needs a decision to remove or rewrite it, or CI goes green
on checks that no longer check anything.

Proposed disposition: `patch` for the boundary and mixed guards,
`adjacent_patch` for the product guards, pending classification for the
rest. **Blocking** for a green core CI run: Gates 7, 9 and 21 are all in
`all-gates`.

### F-34. Gate 21 runs code from `demo/` against the core-built WASM

The `test-bridge` job (`ci.yml:989-997`) runs the core bridge check, then
`tools/test_demo_wasm_adapter_boundary.sh`, then copies the WASM package
built by Gate 20 into `demo/packages/exochain-wasm/wasm/` and runs
`node demo/packages/exochain-wasm/test.mjs`. This is the only place a
non-adjacent workflow runs code from a product tree. One other step names
product-tree paths directly: the tracked-artifact check at `ci.yml:380`
(F-33).

`demo/LICENSE` carves `demo/packages/exochain-wasm` out of the proprietary
notice as Apache-2.0 (part 4), and part 1 proposes it as adjacent with the
rest of `demo/`. So the path is licensed like core, placed like a product,
and exercised by a core gate.

Proposed disposition: pending a classification decision for
`demo/packages/exochain-wasm` (part 1 owner, panel). If it stays adjacent,
`adjacent_patch`: the two steps move to the demo's own CI. If it becomes
core, it moves out of `demo/`. **Blocking** for a green core CI run either
way until decided: Gate 21 is in `all-gates`.

### F-35. Four CI jobs run two gateway unit tests that read five product trees

`crates/exo-gateway/src/dagdb.rs` contains two unit tests that read product
files, both named in part 3's F-15:

- `dagdb_full_migration_source_hygiene_guard` (lines 9411-9511);
- `dagdb_full_migration_coverage_gate_contract` (from line 9514).

Their helper `repo_file` (line 9402) joins `CARGO_MANIFEST_DIR/../..` with a
path and panics if the file cannot be read. The Rust scan finds 14 literal
occurrences across the two tests, which are 9 distinct files: 4 in
`command-base/`, 2 in `web/`, and one each in `site/`, `cybermedica/` and
`demo/`. The first test also builds ten more paths with `format!`
(`demo/services/{service}/src/index.js`, lines 9479-9491), which the scan
cannot see. That is 19 distinct product files.

Both tests are inside `#[cfg(test)] mod tests` (line 9334) and not behind a
feature, so they are compiled into the default test build. From `ci.yml`, at
least these steps run them:

| Step | Line |
| --- | --- |
| Gate 2, `cargo test --workspace` and `--release` | 80, 82 |
| Gate 3, `cargo tarpaulin` over the workspace | 227 |
| DB integration job, `cargo test -p exochain-gateway --lib --features production-db` | 690 |
| Gate 23 feature matrix, the `exochain-gateway` entry of `cargo test -p ... --features ...` | 1086 |

That these steps fail without the five trees is **inferred from the source**.
It was not run.

Of the 45 path literals the Rust scan found, 44 are in test code and this
file is the only one that reaches a product tree. The other cross-crate test
reads go to paths that are proposed core, adapter or vendor (among them
`docs/`, `governance/`, `tools/`, `tests/`, `artifacts/`, `packages/` and
other crates). The one literal outside test code
(`crates/exo-node/src/mcp/tools/proofs.rs:37`) is a document name in a
message. This partly resolves part 2's O-14: 18 files in 7 crates name a
tracked path outside their own crate by a whole literal. Paths assembled
from parts are not found by the scan, as the ten above show, so other
assembled reads cannot be ruled out.

Proposed disposition: `patch` for both tests (move the product assertions to
the products' own checks, or delete them once the trees are gone).
**Blocking** for a green core test run (inferred).

### F-36. Deployment ties the node to LiveSafe in both directions

Read from tracked files only.

| Coupling | Evidence |
| --- | --- |
| A change to core crates triggers the product deploy workflow | `livesafe-railway-deploy.yml:23-30`: paths include `crates/exo-avc/**`, `crates/exo-node/**` and the root `railway.json` |
| That workflow deploys the node as well as LiveSafe | Same file, lines 85-94, 140-151, 197-208: `railway up` for `EXOCHAIN_NODE_SERVICE_ID`, then for `LIVESAFE_SERVICE_ID` |
| Both services are in one hosting project | Same file, lines 57-62: one `RAILWAY_PROJECT_ID`, two service IDs |
| Both uploads are the repository root | `railway up . --path-as-root` for each service; no `.railwayignore` is tracked |
| The node's deploy environments are named for the product | `environment: livesafe-development`, `livesafe-staging`, `livesafe-production` (lines 77, 105, 162) |
| The node deploy waits on the product's CI | Line 68 calls `livesafe-ci.yml`; all three deploy jobs need it (lines 75, 103, 160) |
| The node deploy is accepted by a product smoke test | Lines 98, 155, 212 run `scripts/livesafe-railway-smoke.sh` (adjacent-class), which checks both services |
| The root compose file builds a LiveSafe service | `docker-compose.yml:57-65`, context `../livesafe` (part 3 O-18) |
| The root database bootstrap creates the LiveSafe database | `init-db.sh:18-30`, mounted at `docker-compose.yml:35` |

At the audited commit the "LiveSafe Railway Deploy" run (`44003950278`)
failed at "Run LiveSafe quality gate", and its three deploy jobs were
skipped. So on that commit a product check stopped this deployment path for
the node. No other tracked GitHub workflow that deploys the node was found.
Two tracked runbooks describe other routes: a manual `railway up` and the
hosting provider's own deploy-on-merge setting
(`deploy/RAILWAY-HANDOFF.md:121-130`, `deploy/NODE-ZERO.md:48`, `106-109`).
Whether either is in use, and how it relates to this workflow, cannot be
read from the repository.

Why it matters for the split. After a split the only tracked automated
deployment of the node sits in a product workflow, and that workflow names
core crate paths that will no longer exist beside it. Which repository
owns the hosting project, its environments and its secrets is an
operational decision this record cannot make. It also extends part 3's F-11
(root deployment files).

Proposed disposition: `patch` for the root compose file and `init-db.sh`
(remove the LiveSafe service and database); `adjacent_patch` for the
workflow and its smoke script; the hosting split is pending (operations
owner, security panel). **Blocking** until an owner confirms a deployment
mechanism for the node that does not pass through a product.

### F-37. The container images copy only proposed-core paths

Both image definitions build from a small, fixed set of paths:

| File | Copies | Builds |
| --- | --- | --- |
| `Dockerfile` | `Cargo.toml`, `Cargo.lock`, `crates/`, `crates/exo-gateway/migrations`, `artifacts/trust/avc-exo-ceremony-2026`, `deploy/entrypoint.sh` | `exochain` and `exo-gateway` with `exochain-gateway/production-db` |
| `deploy/Dockerfile.node` | `Cargo.toml`, `Cargo.lock`, `crates/`, `deploy/entrypoint.sh` | `exochain` |

No product-tree path is copied. Read with part 2 (no workspace crate depends
on a path outside `crates/`), this is the strongest evidence in this record
that the release build of the two binaries does not need the siblings. It is
evidence from the file, not from a build: no image was built here.

Paths are not content. The copied `crates/exo-gateway/migrations` includes
LiveSafe schema (`20260316000001_initial_schema.sql`,
`20260426000001_livesafe_composite_basis_points.sql`; part 3's F-11), so the
image is built from proposed-core paths but is not product-free.

Two smaller points. The root `.dockerignore` excludes `target/`, `.git/`,
`node_modules/`, `web/node_modules/`, `.claude/` and `*.md`, so the product
trees are sent to the builder as context even though nothing copies them.
And `Cargo.toml:58-63` excludes `livesafe` from the workspace; once that
directory is gone the entry is dead configuration.

Proposed disposition: `no_change` for the image definitions; `patch` for
the `exclude` entry and comment after the split. Not blocking.

### F-38. Reproducibility is not established: toolchains differ and most builds do not use the lockfile strictly

| Where | Toolchain | `--locked` |
| --- | --- | --- |
| `ci.yml` gate jobs | 1.98.1 (formatting: `nightly-2026-09-21`; SBOM job: 1.97.1) | Not on `cargo build --workspace --release` (65), `cargo test --workspace` (80, 82) or `cargo clippy` (261). Present on tool installs and one macOS test (802) |
| `release.yml` | 1.97.1 | Present on the workspace release build (533) and the metadata calls |
| `Dockerfile`, `deploy/Dockerfile.node` | `rust:1.90-slim-bookworm`, by tag | Not on `cargo build` (42; 35) |
| `Cargo.toml:68` | `rust-version = "1.85"` | n/a |
| Repository root | No `rust-toolchain` or `rust-toolchain.toml` file | n/a |

So the commit that CI tests is compiled with one compiler, a release of it
with another, and the deployed image with a third. Without `--locked`, a
build may update `Cargo.lock` when the lockfile and the manifests disagree,
instead of failing. The base images are named by tag, not by digest, so the
same file can produce different images over time.

`release.yml` has a `reproduce-crates` job (line 1919). It rebuilds the
crate archives and compares the manifest and each `.crate` file with `cmp`
against the earlier preflight output (from line 2112), and crate
publication needs it. It is skipped on a dry run. The job was not read in
full and no run of it was inspected. It covers crate archives, not binaries
or images.

None of this is caused by the siblings. It is reported because the issue
asks for "reproducible build/test behavior", and a split that copies this
configuration carries the same gaps.

Proposed disposition: `patch` (one pinned toolchain used by CI, release and
the images, `--locked` on the CI and image builds, base images by digest).
These remove known sources of difference. They do not prove
reproducibility, which needs repeated builds and a comparison of outputs.
Not blocking for the split; **blocking** for a "reproducible build" claim.

### F-39. The release workflow names no product tree, and inherits every CI coupling

A search of `release.yml` for the six product-tree paths and for LiveSafe,
CyberMedica, CommandBase, CrossChecked and LegalDyne found none. The one
product-related match is the crate name `exochain-decision-forum` in a list
of crates (line 5320), which is part 2's boundary-crate question, not a
sibling path. Its jobs publish five kinds of artefact: crates, the WASM
npm package, the `exochain-llm-proxy` npm package (LYNK, from line 3122; part
3 O-20), the SDK npm package, and the Python package, then a GitHub release.

Its first job is `ci` (lines 62-64), which calls `ci.yml`, and both approval
jobs need it (lines 150, 166). A called workflow fails if any of its jobs
fail. So:

- a release from the audited commit would stop at `ci` because of F-31
  (inferred from the workflow; no release was attempted);
- a release from a core-only tree would stop at `ci` because of F-33, F-34
  and F-35 until those are patched (inferred, on the same basis as those
  findings).

Crate publication also needs the WASM, LYNK, SDK and Python preparation
jobs (`release.yml:2154` onward). If a later decision moves any of those
packages out of the core, the crate release path changes with it.

Part 4's open points remain open: what each published archive contains
(F-26) and whether third-party notices travel with it (F-24) can only be
settled by inspecting built archives, which this record did not do. Part 2's
O-16 (boundary crate names in release tooling) was not resolved further.

Proposed disposition: `no_change` to `release.yml` for the split itself,
conditional on the package classifications staying as proposed; pending for
package contents (part 6 or a release dry run on CI).

### F-40. The issue's verification is still owed: no build or test has run without the siblings

This record shows where the gates name sibling paths. It does not show that
the remaining gates pass once those are patched, because that needs the
compile gates to run on a tree without the siblings. The audit machine is
not permitted to compile the workspace, and the audit branch has not been
pushed.

The necessary next experiment: a CI job, on a draft pull request, that
checks out the commit, deletes the paths part 1 proposes as adjacent, and
runs the gates on what is left. To cover what this record found it has to
include at least Gates 1, 2, 3, 4, 7, 8, 9, 16, 20, 21 and 23, the DB
integration job (the `production-db` configuration of F-35) and both image
builds. Each failure is then either a coupling this record lists or one it
missed. The job does not exist; this is a proposal. The removal list is not
tracked; it would be regenerated from `path-classification.tsv` by the rule
in Method item 5.

One passing run would show that those gates pass without the siblings at
one commit. It would not show reproducibility (F-38), and it covers only the
configurations it runs. Kept and made a required check (F-32), such a job
would stop new sibling dependencies from entering the tested gates.

Proposed disposition: `patch` (add the job; core maintainers and the Build
Lead for runner placement). **Blocking** for the issue's acceptance
criterion.

## Findings summary

| ID | Finding | Proposed disposition | Blocks cutover, and why |
| --- | --- | --- | --- |
| F-31 | CI fails at the audited commit on Gates 6 and 7 (advisories); build, test and the licences check passed | `patch` | Yes: no green CI baseline |
| F-32 | No required checks visible on `main` | Pending: administrator, security panel | Controls F-33 and F-40 |
| F-33 | At least twelve guard steps in Gates 7, 9 and 21 fail without the adjacent paths; Gate 16 likely | `patch`; `adjacent_patch` for product guards; rest pending classification | Yes: green core CI |
| F-34 | Gate 21 runs `demo/` code | Pending classification | Yes: green core CI |
| F-35 | Four CI jobs run two tests that read 19 product files (inferred) | `patch` | Yes: green core tests |
| F-36 | The only tracked automated node deployment runs through the LiveSafe workflow and hosting project | `patch`, `adjacent_patch`; hosting pending | Yes, until an independent mechanism is confirmed |
| F-37 | Images copy only proposed-core paths (which include LiveSafe schema) | `no_change`; `patch` dead config | No |
| F-38 | Three compiler versions (and a nightly for formatting), little `--locked`, images by tag | `patch` | Blocks a "reproducible" claim only |
| F-39 | Release names no product tree; inherits CI couplings | `no_change`; contents pending | Through F-31, F-33 to F-35 |
| F-40 | No CI job builds or tests the core without the sibling trees; the deploy image build compiles two binaries from `crates/` alone but runs no tests | `patch` (CI job) | Yes: acceptance criterion |

## Items earlier parts sent here

| Item | From | Status after this record |
| --- | --- | --- |
| F-4, unused Decision Forum dependencies | Part 2 | Gate 11 (`cargo machete`, `ci.yml:616`) succeeded in the run read. So the check as configured does not report them. Why (ignore list or detection limit) was not examined |
| F-11, root deployment files | Part 3 | Extended by F-36. The four LiveSafe tables were not examined here |
| F-15, gateway unit tests | Part 3 | F-35 |
| F-16 and O-12, guards that inspect products | Parts 3, 1 | F-33 |
| O-4, tracked build output | Part 1 | Gate 9 checks that `web/dist/` and `demo/web/dist/` are not tracked (`ci.yml:380`). No check on `packages/*/dist` was found. Not resolved |
| O-14, `CARGO_MANIFEST_DIR` candidates | Part 2 | Partly resolved in F-35: whole-literal paths only |
| O-15, `package.json` files naming `exochain-wasm` or `@exochain/` | Part 2 | Resolved as O-31 |
| O-16, boundary crate names in release tooling | Part 2 | Not resolved (F-39) |
| O-18, `../livesafe` compose context | Part 3 | F-36 |
| O-19, coverage exclusion of `telegram.rs` | Part 3 | Confirmed present; no change proposed here. Stays with part 3's decision on the Telegram adapter |
| O-20, LYNK release jobs | Part 3 | F-39. They stay if LYNK is core |
| F-23, `cargo deny` result | Part 4 | F-31: licences passed, advisories failed |
| F-24, F-26, notices and package contents | Part 4 | Still open (F-39) |
| O-26, no npm or Python licence check | Part 4 | Unchanged. None was found in `ci.yml` |

## Observations forwarded to later parts

Forwarding records where the question goes. It does not settle it.

| ID | Observation | Evidence | Goes to |
| --- | --- | --- | --- |
| O-29 | Six scan rows, covering three targets (two lockfiles and the `demo/coverage` directory), point into a product tree at paths that are vendor-class, not adjacent-class. A filter on class alone missed `livesafe/Cargo.lock`; the experiment found it. Counts in this record are by directory as well as by class. | `build-coupling.tsv`; `ci.yml:329` | Part 7 (method) |
| O-30 | The LiveSafe quality gate failed at the audited commit. The cause was not read. | Run `44003950278` | LiveSafe owner |
| O-31 | No non-adjacent `package.json` depends on a product tree. Two adjacent packages depend on the core WASM build output by relative path (`command-base/app` and `exoforge`, both `file:` links to `packages/exochain-wasm/wasm`). Ten `demo/services/*` packages take `@exochain/exochain-wasm` from the demo's own npm workspace. One adjacent build script compiles core source directly: `demo/apps/vitallock/package.json:8` runs `wasm-pack build crates/exochain-wasm`. After a split the two `file:` links and that script break and need a replacement, of which a published package is one option. Only dependency fields and this one script were checked; other scripts were not. | 32 tracked `package.json` files read | Adjacent owners; part 7 (integration standard) |
| O-32 | `livesafe-railway-deploy.yml` records hosting project, environment and service identifiers in a tracked file. They are identifiers, not credentials. Whether they should be tracked in a public repository is a separate question. | `livesafe-railway-deploy.yml:57-62` | Security panel |
| O-33 | The hygiene job mixes repository-wide guards with product guards in one job, so a product failure and a core failure are reported as the same gate. | `ci.yml:353-545` | Part 7 |
| O-34 | Two non-adjacent workflows (`presidential-daily-attention.yml`, `retire-0.2.3.yml`) were scanned but not read for this record. | Scan | Part 7 |

## Limits

- Nothing was compiled. Statements about what a Rust build or test needs are
  read from source and from the CI run, and are marked "inferred" where no
  run supports them.
- One CI run per workflow was read, for the audited commit. Earlier runs
  were listed by result only.
- Repository settings are as visible to the audit token (F-32).
- The coupling scan matches tokens against tracked paths. It misses paths
  built at run time from variables, globs, and tools called only by other
  tools. A bare directory name such as `demo` or `site` matches ordinary
  words, so bare matches were not counted as evidence.
- The scan reads the four non-adjacent workflows. The three adjacent
  workflows were read directly, for F-36 only.
- The Rust literal scan does not prove a path is opened, and does not see
  paths assembled from parts.
- The experiment ran on Windows under Git Bash without `ruby` and with
  compile and network tools stubbed. Guards that need those, or POSIX file
  flags the platform lacks, fail in both trees and say nothing either way.
  It ran only `ci.yml` lines that end in a single `bash tools/...` or
  `python3 tools/...` command, 76 after removing duplicates; guards invoked
  any other way were not run. Its harness and exit codes are tracked; its
  logs are not.
- The results table is from one machine and one run. On another platform
  the guards that fail in both trees here may behave differently.
- Test code outside Rust that CI runs (the LYNK npm tests, the Python SDK
  tests, the WASM bridge check) was not scanned for sibling paths.
- The experiment's removal list follows part 1's proposal. A different
  boundary gives a different list.
- Deployment facts are from tracked files. The hosting provider's
  configuration was not inspected.
- No image, crate archive or npm or Python package was built or inspected.
- Cross-references to parts 1 to 4 rely on those records as written.

## Reproduction

From a checkout of the audited commit whose working tree is clean apart from
this audit directory's untracked files:

```bash
python3 docs/audit/core-separation-904/build_coupling_scan.py \
  docs/audit/core-separation-904/path-classification.tsv . | sha256sum
```

The digest must equal the coupling scan SHA-256 above.

```bash
python3 docs/audit/core-separation-904/rust_path_reads.py \
  docs/audit/core-separation-904/path-classification.tsv . | sha256sum
```

The digest must equal the Rust path literals SHA-256 above.

The CI results, with read access to the repository:

```bash
gh run view 44003950227 --repo exochain/exochain --json conclusion,jobs
```

```bash
gh run view 44003950227 --repo exochain/exochain --log-failed
```

```bash
gh run view 44003950278 --repo exochain/exochain --json conclusion,jobs
```

```bash
gh run list --repo exochain/exochain --workflow ci.yml --branch main --limit 6
```

```bash
gh api repos/exochain/exochain/branches/main --jq .protection
```

```bash
gh api repos/exochain/exochain/rulesets
```

The experiment, from the repository root, with an empty directory outside
the repository as the second argument:

```bash
bash docs/audit/core-separation-904/sibling_removal_run.sh . /path/to/empty-directory
```

It compiles nothing and needs no network. It prints the SHA-256 of the
removal list and of its `results.tsv`. The removal-list digest must equal
the one in Method item 5. The results digest equals that of
`sibling-removal-results.tsv` only on a machine that fails the same guards
for the same platform reasons as the audit machine (Windows, Git Bash, no
`ruby`); elsewhere, compare the rows that pass in the first tree.

## Path classification of this record

| Path | Classification |
| --- | --- |
| `docs/audit/core-separation-904/05-BUILD-CI-DEPLOY-COUPLING.md` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/build_coupling_scan.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/build-coupling.tsv` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/rust_path_reads.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/rust-path-reads.tsv` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/sibling_removal_prep.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/sibling_removal_run.sh` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/sibling-removal-results.tsv` | EXOCHAIN core (governance evidence) |

Core regression statement: this record adds eight files under `docs/audit/`.
It changes nothing under `crates/`, `packages/`, `governance/`, `tools/`,
`.github/` or any deployment file, and it does not edit `GAP-REGISTRY.md`.

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

# 0.2.6 security-remediation release candidate

This is an intended, unpublished release candidate. It prepares source and
release controls; it does not create or claim a git tag, GitHub Release,
registry publication, deployment, production runtime verification, Article 26
certification, or v0.3.0 closure.

Status: core source and release-control implementation is committed at
`368721a1ea3577481cf73cdee6d811623159faec`. Exact-head core and feature-matrix
gates, coverage thresholds, all 62 CI-derived shell guards, and the separate
LiveSafe quality/build/image gates passed at that checkpoint. Complete scan
`429b3137-c1ad-49c9-8fd8-ea7baf030d69` of source head `76d7ea4e` found one
additional High release-credential boundary outside the imported report.
Initial correction `111f7955b9599159edb104ee9a6dec7dc5924e30` binds every
credential consumer to `release`; follow-up correction
`b5dcb89bf88a243196213a1a2b7c4f1ed1c2b888` closes a YAML 1.1/1.2 parser-
differential bypass in that regression guard. Its focused guard and
`actionlint` checks pass. Candidate completion remains blocked until
`CARGO_REGISTRY_TOKEN` and `NPM_TOKEN` are moved exclusively from repository
scope into the protected `release` environment, publisher prerequisites are
verified, and exact-head gates and final review are rerun. Successful repository
metadata on 2026-09-08 identifies `exochain` as a User owner, so inherited
organization secrets are not applicable. This resolves the earlier inheritance
uncertainty, not the still-open repository-secret custody finding.
Provider CI, Windows runtime evidence, tag, publication, deployment, and
runtime readback remain unproven.

The dated 2026-09-08 checkpoint below records the later helper correction and
macOS ACL mitigation work. Earlier checkpoint results retain their original
source ranges and do not establish validation of these later changes.

## Evidence boundary

| Item | Candidate record |
| --- | --- |
| Imported report | `Exochain-code-review-report-run4.html`; read-only and not committed |
| Report SHA-256 | `d5da7a1291cbf8baaa8e676cd2eebbbbaadc421eb623eddb48dfc6f4e0c89168` |
| Source validation baseline | `8020ceab355eefa7f5185d9cdd0436da7af46efb` |
| Committed implementation checkpoint | `368721a1ea3577481cf73cdee6d811623159faec` |
| Scan-reviewed source head | `76d7ea4e6e13159b011c43df60ecbf5252fe7a5e`; complete scan found one additional High CI/CD finding |
| Protected-environment binding | `111f7955b9599159edb104ee9a6dec7dc5924e30` |
| YAML parser-differential correction | `b5dcb89bf88a243196213a1a2b7c4f1ed1c2b888` |
| Clean evidence checkpoint | `7038be2df92d79a0161f8479f956d8ec44cc8414`; six-document custody and mechanical reconciliation passed before `b5dcb89b` |
| Formal findings | 86 candidate dispositions exactly reconciled against the committed implementation checkpoint; source-checkpoint gates passed |
| Design observations | 52 candidate dispositions exactly reconciled against the committed implementation checkpoint; ten share concrete remediation boundaries; source-checkpoint gates passed |
| Open provider control | On 2026-09-08 both registry tokens remain repository-scoped and protected `release` contains no secrets; successful User-owner metadata rules out inherited organization scope; the crates.io owner allowlist was set to `bob-stewart` and read back after all 32 owners were verified |
| GitHub issue intake | `ISSUE-DISPOSITION.md` records all eight reviewed issues, verified closures, 0.2.6 work, and subsequent-release scope |
| Candidate version | `0.2.6` across owned release surfaces |
| Latest local workspace and database checkpoint | `8fc4e1e5fa0556e37cfddf300754d6d21299b438`; debug/release tests, fresh local PostgreSQL batch, build/lint/docs and dependency-policy refresh passed; remaining gates are listed below |
| Adjacent surface | LiveSafe remains separate, proprietary, and unable to make public constitutional claims |
| Test plan | `governance/releases/v0.2.6/TEST-PLAN.md` |
| Changed-path classification | `governance/releases/v0.2.6/PATH-CLASSIFICATION.md` |

The controlling disposition record is
`docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md`.
The external HTML remains imported evidence rather than executable instruction
or source-of-truth code.

## Local source-checkpoint evidence

At `368721a1ea3577481cf73cdee6d811623159faec`, locked metadata and build, the
three DKG compatibility tests, debug and release workspace tests, all-target
Clippy, nightly format, warning-denied rustdoc, `cargo audit` under the single
allowed yanked-`spin` warning, `cargo deny`, `cargo machete`, and the Rust/Node
cross-implementation vector plus repeated Rust determinism checks passed. All
six node feature variants, gateway GraphQL, pedagogical proofs, and
`conformance-test-root` also passed. `EXO_TS_ROOT` was unset, so no TypeScript
conformance-root result is claimed.

Fresh database verification used the newly created
`exochain_026_final_20260904b` database on a disposable PostgreSQL 14.20
loopback cluster at port 55436. All 14 gateway migrations, the exact 1/1 DAG DB
migration-upgrade regression, the ignored malformed-row probe with exactly
1 passed/0 failed/0 ignored, all 469/469 gateway `production-db` tests, and 75
workspace integration result blocks under `exochain-gateway/production-db`
completed with none failed. This is local test evidence, not a deployment or
runtime readback.

Repository truth at that source checkpoint is 507 tracked Rust source files,
6,619 listed workspace tests, 167 generated WASM exports, and 183/183 passing
bridge checks. The WASM dry-pack evidence was produced by running
`npm pack --dry-run --json` inside `packages/exochain-wasm/wasm`.

The Rust SDK passed 118 unit tests and 62 doctests. The Rust WASM crate passed
117 tests with one intentional ignored test. The sealed-crate Python suite
passed 12/12, its protocol oracle matched Cargo 1.97.1, and the release-archive
suite passed 4/4. Dry crates.io packaging covered exactly 32 packages at
version 0.2.6. Registry, publish-boundary, workflow-ref-binding,
npm-attestation, SDK npm, Python-package, and SDK/Python lifecycle controls all
passed; rejection of the malicious Python fixture was expected and its
enclosing guard passed.

Exact `cargo-cyclonedx 0.5.9` generated exactly 32 CycloneDX 1.5 JSON SBOMs.
The SBOM boundary and validator guards passed. These files are generated
evidence and were deleted before the evidence commit. These checks neither
publish packages nor establish registry/provider acceptance.

The adjacent LiveSafe surface passed `npm --prefix livesafe run quality`: four
dependency audits reported zero vulnerabilities, context lint/typecheck
passed, Vitest passed 157 files and 555 tests, Rust format and Clippy passed,
and 129 Rust tests passed. `npm --prefix livesafe run build` passed for the
1,695-module client and 84-module responder; its 903.82 kB chunk warning was
non-fatal. `docker build -f livesafe/Dockerfile livesafe` passed with image
manifest `sha256:22447dbd6e9ded27edf84fd692cd02cdc4b007fc479089f203edaf23107095ab`.

Codex Security scan `32dbfc47-dbb7-4488-83fd-a02dd5925458` completed and sealed
with zero findings over the baseline through `fd526fdb`, covering 181/181
canonical items and 315/315 paths. This is preliminary evidence only because
later commits are outside its range. A fresh scan must cover the committed
evidence head.

Complete scan `429b3137-c1ad-49c9-8fd8-ea7baf030d69` covered the baseline
through source head `76d7ea4e` and validated one High
CWE-732/CWE-284 release-credential finding. The four crates.io/npm jobs used
repository-scoped registry tokens without directly crossing the protected
environment. Commit `111f7955` adds `environment: release` to each consumer
and a semantic regression guard; the guard rejects the scan-reviewed vulnerable
source head. Independent review then produced two `actionlint`-valid fixtures
that the guard at `111f7955` incorrectly accepted because Psych collapsed YAML
1.1 keys that GitHub treats as distinct. Commit `b5dcb89b` quotes the legitimate
top-level `on` key and audits the lossless YAML AST before decoding, rejecting
ambiguous or duplicate mapping keys, aliases, anchors, merge keys, and explicit
tags. Both collision forms are retained as negative regression fixtures and the
focused release guard plus `actionlint` pass. Live provider metadata still
showed both tokens at repository scope and none in `release`, while organization
Actions-secret applicability was unresolved at that checkpoint. The 2026-09-08
owner metadata resolves inheritance as not applicable, but the token placement
is unchanged. Source declarations alone therefore do not establish exclusive
approval-gated custody. No claim of finding closure is made until the §11
provider checks in `TEST-PLAN.md` prove exclusive environment-secret custody.

Exact-head tarpaulin passed at the source checkpoint with 90.86% workspace
coverage (47,746/52,547), 83.00% ZeroDentity coverage (1,870/2,253), 100%
`exo-root` coverage (1,146/1,146, including 325/325 DKG lines), and 100%
root-genesis portal coverage (65/65). All 62 shell guards discovered from
`.github/workflows/ci.yml` ran serially and exited zero. The intentionally
malicious npm and Python verifier fixtures produced expected negative
diagnostics only inside their guards; both guards contained them and passed.

## Security scope

- Fail-closed proof, authorization, bearer-token, and invariant enforcement.
- Checked deterministic arithmetic and state-transition validation.
- Secret serialization, extraction, zeroization, private-file, and root-ceremony
  custody boundaries.
- Pre-allocation byte, item, depth, and work limits at owned CLI, persistence,
  timestamp, governance, and WASM ingress.
- Fixed external errors, fallible persistence decoding, validated and bounded
  SDK targets, and collision-resistant decision identifiers across Rust,
  TypeScript, and Python. Canonical Rust lookup IDs retain their shipped path
  bytes and public builder signatures; invalid values become one fixed safe
  segment, while TypeScript rejects invalid hash/DID path inputs before fetch
  without reflecting them in diagnostics.
  For title, description, and proposer strings accepted by all three SDKs, Rust,
  TypeScript, and Python `DecisionBuilder` use full BLAKE3 over the same canonical
  CBOR v2 decision frame.
- Adjacent LiveSafe overflow and dependency remediation in a separate commit and
  validation lane.
- LYNK receipt responses cryptographically bind the exact submitted validation,
  subject/adapter authorization material, LLM usage evidence, receipt, and
  EXOCHAIN finality tuple to the configured validator identity; unknown nested
  request fields and replay under changed authorization inputs fail closed.
- Release publication consumes sealed, independently reproduced Cargo archives;
  npm and PyPI resumptions require exact artifact bytes plus repository/workflow/
  commit provenance; SDK npm and Python lifecycle lanes are explicit rather than
  inferred from the WASM or LYNK package lanes. Immediately before a needed npm
  publication, the publisher must also prove the exact canonical owner. Only
  the exact `@exochain/sdk` package may use a registry-proven 404 as a scoped
  first-publication exception; the established WASM and LLM proxy packages
  fail closed if owner authority cannot be proven.
- Every crates.io/npm registry-secret consumer directly declares
  `environment: release`; the secrets themselves must exist only at that
  protected environment scope so branch-authored workflow changes cannot
  bypass approval.

## Release identity invariant

The validated release-input job emits the sanitized version, tag, commit SHA,
and immutable trusted checkout ref. The live signed-tag gate additionally emits
the exact signature-verified annotated-tag object ID and its peeled commit.
Approval and all artifact/publication jobs consume that identity.

```text
dry run: input version = workspace/manifests = 0.2.6
         checked-out HEAD = trusted commit = workflow-dispatch SHA

live:    input version = workspace/manifests = 0.2.6
         annotated signed v0.2.6 tag peeled commit
           = checked-out HEAD = trusted commit = workflow-dispatch SHA
```

Every release checkout must initially be clean, including untracked files.
Immediately before each release build, archive, SBOM, attestation, Cargo
dry-run/publish, WASM build/prepare/dry-pack/publish, LYNK
coverage/build/dry-pack/publish, artifact upload, and GitHub Release side
effect, the workflow rebinds every trusted identity input from immutable
workflow expressions at step scope and neutralizes `BASH_ENV`. It loads the
combined guard and both child guards from the workflow-dispatch commit with Git
replacement objects disabled, then rechecks the immutable HEAD and applicable
tag branch. Mutable checkout copies of those guards cannot authorize a side
effect. The source guard also rejects assume-unchanged and skip-worktree index
flags that could conceal tracked drift.
After a step intentionally creates or downloads untracked artifacts, the guard
still rejects every tracked or staged source change while permitting those
untracked outputs. Live guards re-fetch the named remote tag and require its
annotated-tag object ID and peeled commit to equal the signature-verified
outputs. This object-ID equality binds the downstream check to the exact signed
tag bytes, not merely its mutable name. The GitHub Release job repeats both the
source and remote-tag comparison immediately before creation and binds its
target fallback to the validated commit. A missing, deleted, lightweight,
unsigned, unverifiable, retargeted, mismatched, or tracked-dirty source fails
closed. Dry runs emit no tag identity and do not fetch or require a tag.

The signature-verification keyring must contain exactly one primary key: the
configured release fingerprint. Legitimate signing subkeys for that primary
remain supported. Machine-readable `VALIDSIG` evidence must identify the
configured primary as the actual signer's primary; an additional bundled
primary or a tag signed by that second signer fails closed.

Native Cargo builds and preflight `cargo publish --dry-run` calls use `--locked`
and do not permit `--allow-dirty`. Live crate publication does not reconstruct
or repackage source: it sends only the exact preflight `.crate` bytes through a
captured, no-redirect, bounded-response uploader whose metadata/framing is
checked against the pinned Cargo 1.97.1 protocol. Each retry revalidates the
sealed archive hash and metadata without reopening repository manifests.
`wasm-pack` receives `--locked` through its Cargo options. The
pinned `cargo-cyclonedx` 0.5.9 CLI does not expose Cargo's `--locked` option,
so its job first runs locked metadata and rejects any `Cargo.lock` mutation
before SBOM upload or attestation.

## Version graph

- 32 publishable Rust crates resolve to `0.2.6`.
- The excluded CGR method, guest, and prover packages are `0.2.6`.
- All 158 exact first-party path dependency pins are `=0.2.6`.
- Root, CGR guest, and fuzz locks retain their respective first-party package
  inventories at `0.2.6`; the fuzz package itself remains `0.0.0`.
- Rust, TypeScript, Python, generated SDK, WASM, and LLM proxy package/protocol
  versions are `0.2.6`.
- LiveSafe package versions and `public_claims_allowed: false` are unchanged.

## Observed 0.2.5 provider history

Read-only checks completed at `2026-08-29T03:44:56Z`:

| Provider | Observation |
| --- | --- |
| Git remote | No `refs/tags/v0.2.5` or peeled tag ref |
| GitHub Releases | `v0.2.5` release not found |
| crates.io | All 32 publishable package/version endpoints returned HTTP 404 with an explicit User-Agent |
| npm WASM | `@exochain/exochain-wasm@0.2.5` returned E404 |
| npm LLM proxy | `@exochain/llm-proxy@0.2.5` returned E404 |
| Provider controls | `exochain-core@0.2.4` returned HTTP 200; both npm packages resolved at `0.2.4` |

At the recorded timestamp, those provider observations supported the conclusion
that `0.2.5` had not been published and that `v0.2.4` was the latest published
release (GitHub published `2026-08-18T17:15:29Z`; the annotated remote tag
peeled to `9ad6068a73a3ae7963b736b0e4b7790970adf754`). This is historical evidence,
not a current provider readback or release authorization.

## Candidate test plan

The complete executable acceptance contract, thresholds, evidence separation,
and native macOS and Windows closure requirements are in
`governance/releases/v0.2.6/TEST-PLAN.md`. The exact per-path classification and
LiveSafe intake record are in
`governance/releases/v0.2.6/PATH-CLASSIFICATION.md`.

Source preparation requires all of the following before the candidate commit is
accepted:

```bash
cargo metadata --no-deps --format-version 1 --locked
cargo metadata --manifest-path fuzz/Cargo.toml --locked --offline --format-version 1
cargo metadata --manifest-path crates/exo-cgr-methods/guest/Cargo.toml --locked --offline --format-version 1
bash tools/test_release_version_alignment.sh
bash tools/test_release_signed_tag_trust_boundary.sh
bash tools/test_release_version_input_boundary.sh
bash tools/test_release_workflow_ref_binding.sh
bash tools/test_release_reusable_ci_boundary.sh
bash tools/test_release_sbom_boundary.sh
bash tools/test_release_dry_run_boundaries.sh
bash tools/test_release_publish_boundaries.sh
bash tools/test_cratesio_release_packaging.sh
node tools/verify_cratesio_release_packaging.mjs
bash tools/test_publish_release_crates_registry_validation.sh
bash tools/test_publish_release_npm_registry_validation.sh
python3 tools/test_publish_sealed_crate.py
python3 tools/test_publish_sealed_crate_cargo_parity.py
python3 tools/test_verify_crate_release_archive.py
bash tools/test_verify_npm_registry_attestation.sh
bash tools/test_verify_sdk_npm_release_package.sh
bash tools/test_verify_python_release_package.sh
bash tools/test_release_sdk_python_lifecycle_boundary.sh
bash tools/test_python_sdk_ci_boundary.sh
bash tools/test_verify_release_sbom.sh
bash tools/test_wasm_npm_package_boundary.sh
npm --prefix packages/exochain-sdk test
python3 -m pytest packages/exochain-py/tests
```

The post-correction exact-head content-sensitive guard rerun, final independent
scan, exclusive environment-secret provider readback, provider CI, and
platform-specific gates in the final test plan remain mandatory before release
authorization. Native macOS and Windows ACL runtime evidence must come from
their required CI lanes; cross-compilation is not runtime proof.

## Rollback and disablement

Before publication, rollback is branch-only: decline or abandon the candidate;
no registry, deployment, or runtime state exists to undo. While either token
remains repository- or organization-scoped, the fail-closed stop is to revoke
that credential or disable the release workflow; the `release` environment is
not an effective credential gate against a branch that removes its declaration.
Only after exclusive protected-environment custody is verified may its approval
and credential controls be treated as the publication stop gate.

After a separately authorized publication, an authorized maintainer must resolve
the exact affected package/version set from the reviewed release inventory and
successful registry readback before retirement. Do not invent publication for an
absent version. A whole-release retirement covers the following inventory;
partial retirement must identify its exact subset and reason.

| Registry or artifact | Complete 0.2.6 retirement scope and readback |
| --- | --- |
| crates.io | All 32 Rust packages listed below, each at `0.2.6`: yank each affected published version and verify its `yanked` flag independently. |
| npm | `@exochain/exochain-wasm@0.2.6`, `@exochain/llm-proxy@0.2.6`, and `@exochain/sdk@0.2.6`: deprecate each affected published version with the retirement reason and verify its metadata. |
| Python | PyPI `exochain` at `0.2.6`: yank the affected release files with the retirement reason and verify every file's yanked status. |
| GitHub | Mark the release and its package-retirement notice consistently; retain the signed tag and provenance artifacts for audit. |
| Deployment | Roll back only an actually deployed version to its last independently verified release; verify the resulting runtime separately. |

The exact 32-package Rust inventory is checked against the workspace manifests
by `tools/test_release_version_alignment.sh`; excluded CGR and fuzz packages are
not silently added to a registry-retirement batch.

<!-- rust-retirement-inventory:start -->
```text
exochain-api
exochain-authority
exochain-avc
exochain-catapult
exochain-consensus
exochain-consent
exochain-core
exochain-dag
exochain-dag-db-api
exochain-dag-db-core
exochain-dag-db-domain
exochain-dag-db-exchange
exochain-dag-db-graph
exochain-dag-db-lab
exochain-dag-db-postgres
exochain-dag-db-retrieval
exochain-decision-forum
exochain-economy
exochain-escalation
exochain-gatekeeper
exochain-gateway
exochain-governance
exochain-identity
exochain-legal
exochain-messaging
exochain-node
exochain-pdp
exochain-proofs
exochain-root
exochain-sdk
exochain-tenant
exochain-wasm
```
<!-- rust-retirement-inventory:end -->

This is a retirement procedure, not evidence that any 0.2.6 package has been
published or that any retirement, deployment or rollback has occurred. Each
provider mutation requires separate authorization and current readback.

Do not describe this candidate as court-ready, Article 26 certified,
production-cryptography reviewed, deployed, or a v0.3.0 close.

## 2026-09-08 helper and macOS ACL checkpoint

Commit `5955eff80ec72f65e1378f5317ebd092508110e6` corrects the sealed LYNK
distribution inventory to exactly 44 build outputs, including the existing
attestation, HTTP, and wire modules, and corrects the npm publisher's copied
verifier basename to `verify_npm_registry_attestation.mjs`. These are committed
release-adapter source changes; they do not establish registry acceptance or
publication.

Completed immutable diff scan `67080c5e-352d-4f06-9325-7f36d376a08e` covers
`8020ceab355eefa7f5185d9cdd0436da7af46efb..4495eb049ad66de30d6d83cb3d71456a9be79799`.
It records two findings: High provider credential scope and Low conditional
macOS ACL enforcement. The canonical scan record has partial coverage with
retained deferrals; completion of the scan run is not complete review coverage
or a clean scan. Later helper and macOS changes are outside that immutable
range. Its sealed artifacts remain unchanged.

The macOS mitigation is committed at
`25a6db81c46977244d7165f6ed9cc5bf4f677369`. The shared private-file adapter
checks native ACLs on files and parents, validates creation permissions before
creating a file, and restricts the new empty file before returning a handle for
secret writes. The reviewed
correction preserves the existing write handle for legitimate mode `0400`
creation and limits initialization-error cleanup to the unchanged empty file.
The workflow change adds release-profile `macos_` tests to the required
`cross-platform` lane; the native CI requirement is recorded in test-plan §10.

Scoped verification recorded during mitigation work includes source-guard
RED/GREEN evidence and a benign RED/GREEN regression for legitimate mode
`0400` creation. Fresh checks immediately before commit `25a6db81` passed:
node `cargo check`, five `macos_` tests with 1,461 tests filtered out, five
individually selected legitimate private-file lifecycle controls with one test
passing per run, owning-crate all-target Clippy with warnings denied, nightly
format, locked/offline `cargo deny` license checks, `actionlint 1.7.12`, and
diff whitespace checks. The tests ran in the actual node target. Three benign
release-helper modes passed at `5955eff8`; helper source is unchanged at
`25a6db81`.
The `block 0.1.6` future-incompatibility notice remains recorded. These are
focused patch results, not a full run on a final immutable candidate head.
No exploit reproductions or adversarial fixtures were executed in this patch
verification. Benign controls and source guards do not establish actual
disclosure reproduction.

Provider custody remains unresolved based on the previously recorded
observations; it was not freshly checked for this checkpoint. Both tokens were
last observed at repository scope, with neither installed in protected
environment `release`. The successful User-owner metadata resolves organization
inheritance applicability only. The §11 protected-environment custody and
publisher prerequisites remain mandatory.

Full exact-head workspace, coverage, feature, fresh-database, SDK/package,
content-sensitive guard, independent-review, required native platform CI, and
provider gates remain outstanding for the final candidate. Earlier green
results retain their historical scope. This checkpoint makes no tag,
publication, deployment, runtime-readback, or release-authorization claim.

## 2026-09-08 DER resolution follow-up

The complete locked/offline workspace release build passed at clean evidence
head `afaee653a523845bb9663534446a0b48fb9fba36`; all GitHub workflow files
also passed `actionlint 1.7.12`. The 86 formal and 52 design ID sets, order,
dispositions, and imported report hash were rechecked without change.

A refreshed dependency audit then exposed the node's exact `der = 0.8.0` pin
as yanked. RustCrypto attributes that yank to its minimum-version CI check,
not a published EXOCHAIN vulnerability. A fresh Cargo fixture carrying the
actual direct dependency and no lockfile failed resolution specifically because
0.8.0 was yanked. Commit `6932a180efb5c7e421072b618af876f86048be22`
updates that exact pin to non-yanked 0.8.2 and its lockfile resolution only;
all other package versions remain unchanged. The same fresh-resolution check
then passed. See the [maintainer changelog](https://github.com/RustCrypto/formats/blob/master/der/CHANGELOG.md).

Node type-check, three existing benign RFC 3161 controls, the five macOS
checks, node all-target Clippy, formatting, and the exact-pin guard passed.
Audit and deny passed under unchanged repository policy; the DER yank warning
is gone, while the previously documented `spin 0.9.8` warning remains.
Independent source review found no concrete unintended dependency change or
source-visible compatibility regression. The full locked/offline workspace
release build for DER-updated source `6932a180` passed in 4m 46s. This is a
separate result from the earlier pre-DER build, not a full test-suite pass.

The same source then passed workspace all-target Clippy with warnings denied
in 50.88s and warning-denied workspace rustdoc in 22.12s. A subsequent
locked/offline readback at `6932a180` reran the full release build, workspace
Clippy, and rustdoc successfully (0.82s, 0.62s, and 0.37s respectively, with
cached outputs). The known `block 0.1.6` future-incompatibility notice remained;
these commands did not execute workspace tests or establish coverage.

The supplementary `tools/test_dependency_hygiene.sh` check failed: 31 duplicate
warnings exceed its retained cap of 24. The complete lockfile duplicate-name
set is unchanged by the DER update. Its cap and unrelated dependencies were
not modified. This manual claim/hygiene check is distinct from the successful
Cargo Deny policy gate; the failure is not evidence of a new vulnerability or
permission to weaken policy. Test-plan follow-up records the remaining scope.

Names-only provider readback still lists `CARGO_REGISTRY_TOKEN` and `NPM_TOKEN`
at repository scope, with an empty `release` environment secret collection.
Repository ownership is `User`; the current account has push/triage/pull, but
not administration or maintain permission. No secret value was read or changed.
An authorized custodian must establish exclusive protected-environment custody
from the approved credential source; encrypted repository secrets must not be
recovered through a workflow. Full final-head verification, native CI evidence,
authorized registry cleanup, and publication also remain outstanding.

## 2026-09-08 spin and package checkpoint

Commit `7108cd0cb96e48099dd8001fd4c029cb9876655a` removes the remaining
root-lock yank warning by updating `spin 0.9.8` to compatible `0.9.9`.
Only its version and checksum change; no dependency ranges, feature settings,
other package versions, or policy exceptions change. Published 0.9.9 includes
an upstream soundness fix; EXOCHAIN exploitability was not reproduced or
established. The three actual consumers allow this patch version, and the CGR
guest lock already selected it. Registry-aware audit with `--deny yanked`
failed before the update and passed afterward with no warnings and zero
unsuppressed vulnerabilities under the unchanged advisory policy.

Independent source review found no concrete graph or compatibility regression.
Workspace all-target Clippy, full Cargo Deny, exact-pin and formatting checks,
all five benign native macOS release-profile tests, the full workspace release
build, and warning-denied rustdoc passed for the reviewed dependency graph.
Three existing RFC 3161 release-profile compatibility controls also passed:
deterministic request generation, canonical nonce round-trip, and direct signer
trust-anchor recording. These are legitimate-behavior checks, not a complete
RFC 3161 test-suite or security-validation result.
Target-filtered metadata resolves the same spin version/features for macOS
ARM64, both Linux targets, and Windows x86-64; this does not prove native CI.
The existing `block 0.1.6` future-incompatibility notice remains.

Before this lock update, clean checkpoint `cb618c44` passed ordinary build and
dry-pack checks for both TypeScript packages and assembled exactly 32 Rust
archives with matching clean source identities. Those archives are historical,
not release artifacts for the updated graph. `TEST-PLAN.md` records exact
commands, scope, and the required remaining gates. Neither the package checks
nor this dependency mitigation supplies complete tests, coverage, native CI,
exclusive provider credential custody, registry cleanup, or release approval.

## Post-spin verification checkpoint

At clean source `a13b460fb51c79a968f2b5963d581af8e72a7a05`, the full
locked/offline release-profile workspace test compilation succeeded: 114 test
executables built in 21m 34s, with zero test cases executed. All three DKG
compatibility tests then passed. A hash-vector check initially failed because
its generated fixture directory was absent; generating the repository's
canonical fixtures in a private directory resolved that setup failure. Rust
and Node both verified the one canonical BLAKE3 vector, and Node verified the
existing public governance-signature fixture. No production code or expected
digest changed. The exact commands and scope limits are in `TEST-PLAN.md`.

An isolated broad offline dependency-resolution experiment was rejected:
duplicate warnings worsened from 31 to 33, and the candidate introduced
additional GraphQL minimum-Rust-version drift. Its lockfile was not adopted.
The manual hygiene failure remains distinct from the passing Cargo Deny policy
gate; no cap, exception, or compatibility claim was relaxed.

The issue refresh confirms six open GitHub issues. Documentation for #810 and
the implemented #832 contract belongs in this candidate; documenting #833's
limitations does not complete its fleet-capacity request. Broader issue closure
requires explicit acceptance of the narrowed scope. These local checks and
scope recommendations do not establish complete tests, coverage, exact-head
native CI, provider custody, release approval, or publication.

## 2026-09-08 full workspace and fresh-database checkpoint

At clean source `8fc4e1e5fa0556e37cfddf300754d6d21299b438`, both complete
locked/offline workspace test commands exited zero. Debug reported 6,618
passes and release reported 6,617; each had 146 result blocks, zero failures,
and six explicit ignores. Three debug-only versus two release-only gateway
tests explain the one-pass difference. These are reported test results,
including doctests, not measured code coverage. No expected value or source
was changed to obtain the passes.

A fresh private PostgreSQL 14.20 loopback cluster passed all 14 gateway
migrations, the exact migration-upgrade regression (1/1), the explicitly
enabled malformed-row regression (1/1), and the gateway `production-db`
library suite (469/469). The workspace integration command produced 75 result
blocks, 585 reported passes, zero failures, and one ignore. That command used
`DATABASE_URL`; the separate migration-upgrade regression used
`EXO_DAGDB_TEST_DATABASE_URL`. The aggregate does not imply that every
database-conditional integration case ran against PostgreSQL. The exact
temporary server was stopped and its disposable data removed.

The same source passed release build, workspace all-target Clippy with
warnings denied, nightly formatting, warning-denied rustdoc, locked metadata
for the workspace/fuzz/CGR guest graphs, all three DKG compatibility tests,
Cargo Deny, and cargo-machete. Registry-aware audit with yanked, unsound, and
unmaintained dependencies denied returned zero unsuppressed vulnerabilities
and no warnings under unchanged policy. The `block 0.1.6` future-Rust
compatibility notice and the previously failed supplementary duplicate-warning
hygiene check are not resolved by these passes.

Both evidence inventories were independently reconciled again: 86 formal
findings and 52 design observations, including exact IDs, order, uniqueness,
classifications, disposition tallies, and expected digests. Inventory equality
does not replace final per-finding source/regression review.

Verification reused the retained target directory, ran Cargo serially with
two build workers, and disabled incremental compilation and dev/test debug
symbols. Only known generated test reports were removed; the worktree was
clean after each batch. Final coverage, feature isolation, complete CI guards,
SDK/package/adjacent gates, required native CI, independent final review,
exclusive provider-secret custody, authorized registry cleanup, approvals, and
publication remain outstanding. No release or runtime claim is made.

## PR #835 CI And Dependency Corrections

The first provider run, `34289808327`, tested PR merge commit
`3137aefd28ad19ccf4f34a267c8f666ef4ff2498` (head
`d13ab6b1347b976e1958d681c9778b9fd2b94d1e` into baseline
`8020ceab355eefa7f5185d9cdd0436da7af46efb`). Its red gates were inspected
individually; no local check is substituted for that native PR-merge evidence.

- Repository truth: Linux listed 6,620 tests while native macOS listed 6,624
  because four ACL cases are macOS-only. README and its guard now require
  platform-specific rows, reject global/duplicate/stale claims, and validate
  the macOS row in the native macOS CI lane. Two new portable tests increase
  the candidate rows to 6,622 Linux and 6,626 macOS; each platform must confirm
  its own final inventory.
- Gates 17/19 ran unrelated integration executables despite their module-only
  reporting scope. Both now select `--bin exochain`; the 80%/100% thresholds
  remain unchanged and all integration tests remain in Gates 2/3.
- Gate 3 failed on SQLite busy handling in the 100-writer anchor test before
  coverage was calculated. Its test harness now uses `--test-threads=1` to
  avoid sibling-test contention during instrumentation. The test still starts
  all 100 internal workers; production SQLite policy and the full 90% gate
  are unchanged. New provider execution must establish that this suffices.
- Gate 18 reported five uncovered lines. A real no-size-hint deserialization
  test plus equivalent DKG return/construction expressions passed local
  Tarpaulin 0.35.4/LLVM coverage at 1,149/1,149 lines, 100.00%, without an
  exclusion or threshold change. Direct matching LLVM inspection confirmed
  the last intermediate miss had no executable region; the output validation
  now uses `Result::map`, preserving zeroizing ownership and error propagation.
- Windows ACL subprocess rejection now reports only bounded exit-code and
  stderr-kind booleans, never private paths or raw stderr. Nonzero exit or any
  stderr still rejects, and exclusive handles, literal paths, and ACL parsing
  are unchanged. Its portable diagnostics/source guards pass locally; the
  underlying Windows runtime failure remains unresolved until native CI.

User-approved npm audits identified additional dependency advisories. The
isolated adjacent LiveSafe correction raises Vitest to 4.1.11, Multer to 2.3.0,
and Nodemailer to 9.1.1. The two upload parsers also explicitly limit array
indices to zero; their expected fields are flat. Four clean installs passed.
After the guard was added, all four audits reported zero vulnerabilities,
158 JavaScript test files/561 tests passed, LiveSafe's Rust checks passed, and
both production UI builds passed. A local Docker version query stalled and
only that query was terminated; Docker services were untouched. Image-build
acceptance therefore requires the LiveSafe CI job. No deployment is claimed.

The corrected path inventory has 324 paths with digest and intake in
`PATH-CLASSIFICATION.md`. A fresh names-only provider check still found both
registry tokens at repository scope and none in the protected `release`
environment; the configured account has push but not admin authority. This
does not authorize bypassing the custody gate. Exact new-head CI, independent
release review, exclusive protected credentials, publisher authority, signed
tag, protected approvals, registry cleanup, and publication remain required.

The final local pre-push batch for this correction set passed release build,
full debug workspace tests (6,620 passes, zero failures, six documented ignores
in 146 result blocks), all-target warning-denied Clippy, nightly formatting,
warning-denied rustdoc, and the native macOS repository-truth guard. The guard
confirmed the new macOS inventory row, 6,626 listed. Linux inventory and Windows
runtime execution remain provider requirements. Test-result totals were
calculated after removing terminal color escapes from the retained logs.

The subsequent focused LLVM anchor integration run at clean `f59ede255b0fa55d876d2e469b7ed72cf05f86b3`
passed all 21 tests, including all 100 concurrent writers. This supports the
sibling-test scheduling correction locally; it is neither a full-workspace
coverage result nor native Linux CI closure. Details are in `TEST-PLAN.md`.

## PR #835 Native Environment Follow-Through

LiveSafe CI run `34300522718` completed successfully for PR merge
`e722bbf7baf1a34da1822c8ee6024d78257d0669` (head
`d521be1e8bb402d2290ca3815a996d87f8592d57`). Its four audits, quality tests,
TypeScript checks, both UI builds, and Docker image build all passed. The
image-build result is not an image publication or deployment claim.

The same-head native Windows jobs each failed six of eight tests with an
ACL subprocess exit code of 1 and stderr present. The inspected launch chain
inherits PowerShell 7 module paths through Cargo into Windows PowerShell,
matching Microsoft's documented module-autoload compatibility problem. The
small correction removes `PSModulePath` only from the two private-file child
commands, preserving the parent environment and every ACL enforcement check.
The existing source guard was observed failing before the correction and
passing afterward; all 19 local private-file tests pass. The exact Windows
exception remains unproven, and native Windows CI must confirm the correction.
See `TEST-PLAN.md` for source evidence, classification, and acceptance commands.

The corrected local source passed the release build, all 6,620 executed debug
workspace tests (zero failures, six unchanged documented ignores), Clippy,
formatting, rustdoc, and repository truth. Independent source review found no
actionable defect but requires exact native Windows evidence. Windows CI can
now start without waiting for the unrelated Linux build; structural comparison
proved that only this scheduling edge changed, while `all-gates` still requires
both jobs and the existing CI boundary guards pass.

The cross-implementation command exited zero with 1/1 canonical Rust/Node
hash vectors and identical normalized summaries from two full Rust runs.
External TypeScript comparison was not available because `EXO_TS_ROOT` and
the companion checkout were absent; no evidence is claimed for that surface.
Generated test reports and vectors are retained outside the branch.

This correction does not authorize use of a different GitHub account or any
provider-credential extraction. Protected credential custody, independent
release review, all required exact-head CI, publisher authority, signed tag,
human approvals, registry cleanup, and publication remain distinct gates.

## Windows Owner Initialization and Explicit Coverage Backend

Source commit `ab940c8ee87a58a63150b6ab1749627ce9fcc4a8` explicitly
initializes new private-file ownership and passes a true null backup argument
to `File.Replace`. Strict owner/DACL admission, exclusive creation, literal
path transport, and exact cleanup comparisons remain. Independent candidate
review identified a post-initialization cleanup regression; the correction
records only a successful owner initialization in the expected identity.
The existing native test now covers both initial-owner states, cleanup/retry
after initialization, and rejection of an unacknowledged owner change. These
native assertions still require Windows execution; local source guards alone
do not close that gate.

CI commit `45c0c95fad7c5ac5743b8aa0ebbd36f106b79c7a` corrects a
confirmed backend-selection defect in the pinned Tarpaulin configuration.
Linux had used its default Ptrace engine despite the CLI LLVM argument. The
existing config now explicitly selects `Llvm`, and each coverage job checks
the effective instrumentation flags before running. Independent review and
parsed-workflow comparison found no other workflow change. All four scopes,
selectors and 90/80/100/100% thresholds remain unchanged. No DKG source change
is included; previous Linux coverage results are not a measurement of LLVM.

Both new source guards were observed failing before their corrections and
passing afterward. All 19 local private-file tests pass, as do the exact
PowerShell publication programs in four benign controls (16 assertions) on
the installed macOS runtime. The final source also passed release build,
full debug workspace tests, all-target warning-denied Clippy, nightly format,
warning-denied rustdoc, repository truth, and effective coverage-engine policy.
The executable test count is unchanged; full results are in `TEST-PLAN.md`.

LiveSafe CI also passed at `0a29af75` in run `34303782587`. That does not
close the native Windows failures at the same head, nor does any local result
replace required CI on this corrected head. The path inventory is now 326
classified files, adding two core coverage-policy paths; no dependency or
adjacent application changes are part of this follow-through.

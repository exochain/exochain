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

Status: source and release-control implementation is committed at
`368721a1ea3577481cf73cdee6d811623159faec`. Exact-head core and feature-matrix
gates, coverage thresholds, all 62 CI-derived shell guards, and the separate
LiveSafe quality/build/image gates passed at that checkpoint. Local candidate
completion additionally requires the committed evidence-head content-sensitive
guard rerun and independent scan. Unless a command is tied below to an immutable
checkpoint, the controls described here are candidate acceptance requirements
rather than completion claims. Provider CI, Windows runtime evidence, tag,
publication, deployment, and runtime readback remain unproven.

## Evidence boundary

| Item | Candidate record |
| --- | --- |
| Imported report | `Exochain-code-review-report-run4.html`; read-only and not committed |
| Report SHA-256 | `d5da7a1291cbf8baaa8e676cd2eebbbbaadc421eb623eddb48dfc6f4e0c89168` |
| Source validation baseline | `8020ceab355eefa7f5185d9cdd0436da7af46efb` |
| Committed implementation checkpoint | `368721a1ea3577481cf73cdee6d811623159faec` |
| Formal findings | 86 candidate dispositions exactly reconciled against the committed implementation checkpoint; source-checkpoint gates passed; committed evidence-head scan required for local completion |
| Design observations | 52 candidate dispositions exactly reconciled against the committed implementation checkpoint; ten share concrete remediation boundaries; source-checkpoint gates passed; committed evidence-head scan required for local completion |
| Candidate version | `0.2.6` across owned release surfaces |
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
and Windows-only closure requirement are in
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

The post-evidence content-sensitive guard rerun, post-evidence scan, provider
CI, and platform-specific gates in the final test plan remain mandatory before
release authorization. Windows ACL runtime evidence must come from its Windows
CI lane; cross-compilation is not runtime proof.

## Rollback and disablement

Before publication, rollback is branch-only: decline or abandon the candidate;
no registry, deployment, or runtime state exists to undo. Release environments
remain the publication stop gate, and their approvals or credentials can be
disabled without changing candidate source.

After a separately authorized publication, a defective Rust package version is
yanked crate-by-crate, both npm versions are deprecated, and the GitHub Release
is marked accordingly while the signed tag is retained for audit provenance.
Any deployment rolls back to its last independently verified release; no
deployment is part of this candidate preparation.

Do not describe this candidate as court-ready, Article 26 certified,
production-cryptography reviewed, deployed, or a v0.3.0 close.

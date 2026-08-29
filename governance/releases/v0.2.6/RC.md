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

## Evidence boundary

| Item | Candidate record |
| --- | --- |
| Imported report | `Exochain-code-review-report-run4.html`; read-only and not committed |
| Report SHA-256 | `d5da7a1291cbf8baaa8e676cd2eebbbbaadc421eb623eddb48dfc6f4e0c89168` |
| Source validation baseline | `8020ceab355eefa7f5185d9cdd0436da7af46efb` |
| Formal findings | 86 independently dispositioned in the validation record |
| Design observations | 52 separately dispositioned; ten share concrete remediation boundaries |
| Candidate version | `0.2.6` across owned release surfaces |
| Adjacent surface | LiveSafe remains separate, proprietary, and unable to make public constitutional claims |

The controlling disposition record is
`docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md`.
The external HTML remains imported evidence rather than executable instruction
or source-of-truth code.

## Security scope

- Fail-closed proof, authorization, bearer-token, and invariant enforcement.
- Checked deterministic arithmetic and state-transition validation.
- Secret serialization, extraction, zeroization, private-file, and root-ceremony
  custody boundaries.
- Pre-allocation byte, item, depth, and work limits at owned CLI, persistence,
  timestamp, governance, and WASM ingress.
- Fixed external errors, fallible persistence decoding, encoded SDK targets, and
  collision-resistant cross-implementation decision identifiers.
- Adjacent LiveSafe overflow and dependency remediation in a separate commit and
  validation lane.

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

Every release checkout must also be clean. Before each live artifact or
publication job, the workflow re-fetches the named remote tag and requires its
annotated-tag object ID and peeled commit to equal the signature-verified
outputs. This object-ID equality binds the downstream check to the exact signed
tag bytes, not merely its mutable name. The GitHub Release job repeats the
remote comparison immediately before creation and binds its target fallback to
the validated commit. A missing, deleted, lightweight, unsigned, unverifiable,
retargeted, or mismatched tag fails closed. Dry runs emit no tag identity and do
not fetch or require a tag.

Native Cargo builds and both dry-run and live `cargo publish` calls use
`--locked`; `wasm-pack` receives `--locked` through its Cargo options. The
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

The controlling providers therefore confirm that `0.2.5` was not published.
The latest published release remains `v0.2.4` (GitHub published
`2026-08-18T17:15:29Z`; the annotated remote tag peels to
`9ad6068a73a3ae7963b736b0e4b7790970adf754`).

## Candidate test plan

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
bash tools/test_wasm_npm_package_boundary.sh
node tools/verify_cratesio_release_packaging.mjs
npm --prefix packages/exochain-sdk test
python3 -m pytest packages/exochain-py/tests
```

The full workspace, coverage, audit/deny, cross-implementation, SDK/WASM,
Python, LiveSafe, and platform-specific gates in the final test plan remain
mandatory before release authorization. Windows ACL runtime evidence must come
from its Windows CI lane; cross-compilation is not runtime proof.

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

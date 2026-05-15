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

# Gauntlet Supply-Chain Validation - 2026-05-15

This record validates the Gauntlet supply-chain findings against current
`main` before remediation. The external finding artifacts remain imported
evidence only:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target before this branch:

- branch: `main`
- commit: `9c754477aad4937fcadd4feb85a7aa03b4137c54`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `.github/workflows/ci.yml` | EXOCHAIN core | CI gate contract for the canonical trust-fabric repository. |
| `Cargo.toml`, `Cargo.lock`, `.cargo/audit.toml`, `deny.toml` | EXOCHAIN core | Rust dependency policy and advisory/license gates. |
| `packages/exochain-sdk/` | Core runtime adapter | JavaScript SDK for core API/runtime interactions. |
| `tools/cross-impl-test/` | EXOCHAIN core | Cross-implementation canonical hash validation tooling. |
| `tools/test_*` | EXOCHAIN core | Source guards and CI hygiene gates. |
| `command-base/` | Adjacent surface | Not part of this core remediation PR. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-120 AGPL license in Apache-2.0 project | Stale / already remediated for core | `cargo deny check licenses advisories bans sources` passes with `licenses ok`; package license checks in `tools/test_repo_truth.sh` enforce Apache-2.0 on core JS packages. |
| F-121 `multer` deprecated with known vulnerabilities | Adjacent surface remains queued | Current match is `command-base/app/package.json`, classified adjacent. It was not edited in this core CI/adapter PR. |
| F-122 Playwright in production dependencies | Current core path not found | Current package-manifest search found no owned core package dependency on Playwright. |
| F-123 unpinned GitHub Action refs | Stale / already remediated | `tools/test_github_actions_pinned.sh` rejects non-SHA external action refs and is wired into CI Gate 9. |
| F-124 curl-pipe-shell in CI | Stale / already remediated | `tools/test_ci_supply_chain_hardening.sh` rejects curl-piped installs and unpinned Cargo tool installs in CI/release workflows. |
| F-125 SemVer ranges on security-critical crates | Stale / already remediated for Rust, live for core JS adapters | Rust workspace dependencies are exact-pinned and guarded by `tools/test_security_critical_dependencies_pinned.sh`. This branch also exact-pins `packages/exochain-sdk` and `tools/cross-impl-test` npm dependencies. |
| F-126 advisory ignores plus zero-vulnerability claim | Stale / already remediated | `.cargo/audit.toml` documents active ignores; `tools/test_audit_ignore_policy.sh` rejects stale or undocumented active advisories. |
| F-127 CI comment misleading about ignore list | Stale / already remediated | `tools/test_audit_policy_docs.sh` and `tools/test_audit_ignore_policy.sh` enforce the current audit-deny language and ignore freshness. |
| F-128 `npm audit || true` suppresses failures | Adjacent surface remains queued | Current `|| true` match is `command-base/app/package.json`, classified adjacent. |
| F-129 no npm audit in CI | Remediated for core JS adapters | This branch adds `tools/test_npm_core_package_hygiene.sh` and wires it into CI Gate 9. The guard runs `npm audit --audit-level=high --omit=dev` for core JS package directories with lockfiles. |
| F-130 missing lockfiles in packages | Remediated for core JS adapters | This branch adds `packages/exochain-sdk/package-lock.json` and requires lockfiles for core package manifests with external npm dependencies. |
| F-131 floating caret versions in production | Remediated for core JS adapters | `@noble/hashes`, `@types/node`, `typescript`, `blake3`, and `cbor` are exact-pinned in owned core JS manifests. Adjacent package ranges remain outside this PR. |
| F-133 CI Clippy misses module-level allows | Stale / already remediated | CI uses `cargo clippy --workspace --all-targets -- -D warnings`, and `tools/test_repo_truth.sh` verifies the all-targets lint gate plus workspace denial of `unwrap_used` and `expect_used`. |

## Commands Run

The following commands completed with exit code 0 unless noted:

```bash
bash tools/test_npm_core_package_hygiene.sh
# First RED run failed as expected because packages/exochain-sdk used semver ranges.
npm install --package-lock-only --ignore-scripts  # packages/exochain-sdk
npm install --package-lock-only --ignore-scripts  # tools/cross-impl-test
npm ci --ignore-scripts                           # packages/exochain-sdk
npm test                                          # packages/exochain-sdk, 67 passed
npm ci --ignore-scripts                           # tools/cross-impl-test
npm test                                          # tools/cross-impl-test, 1 vector passed
bash tools/test_npm_core_package_hygiene.sh
bash tools/test_github_actions_pinned.sh
bash tools/test_ci_supply_chain_hardening.sh
bash tools/test_security_critical_dependencies_pinned.sh
bash tools/test_repo_truth.sh
bash tools/test_audit_ignore_policy.sh
cargo audit --deny unsound --deny unmaintained
cargo deny check licenses advisories bans sources
git diff --check
```

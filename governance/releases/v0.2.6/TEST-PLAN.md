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

# EXOCHAIN 0.2.6 Security-Remediation Test Plan

This plan governs the intended, unpublished `0.2.6` source candidate. Passing
the local commands prepares a reviewable branch; it does not create or approve
a tag, release, registry publication, deployment, production runtime, or
constitutional certification.

## Evidence authority

- Imported evidence:
  `/Users/bobstewart/Downloads/Exochain-code-review-report-run4.html`
- Imported-evidence SHA-256:
  `d5da7a1291cbf8baaa8e676cd2eebbbbaadc421eb623eddb48dfc6f4e0c89168`
- Validation baseline:
  `8020ceab355eefa7f5185d9cdd0436da7af46efb`
- Committed implementation checkpoint:
  `368721a1ea3577481cf73cdee6d811623159faec`
- Scan-reviewed source head:
  `76d7ea4e6e13159b011c43df60ecbf5252fe7a5e`
- Protected-environment binding:
  `111f7955b9599159edb104ee9a6dec7dc5924e30`
- Clean evidence checkpoint:
  `7038be2df92d79a0161f8479f956d8ec44cc8414`
- YAML parser-differential correction:
  `b5dcb89bf88a243196213a1a2b7c4f1ed1c2b888`
- Formal inventory: exactly 86 unique findings.
- Formal finding classifications: 32 EXOCHAIN core, 50 core runtime adapter,
  and four adjacent surface.
- Design inventory: exactly 52 unique observations.
- Design observation classifications: 22 EXOCHAIN core and 30 core runtime
  adapter.
- Controlling disposition record:
  `docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md`
- Exact evidence appendices:
  `docs/audit/exochain-code-review-report-run4-formal-evidence-2026-09-04.md`
  and
  `docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md`.
- Exact changed-path classification:
  `governance/releases/v0.2.6/PATH-CLASSIFICATION.md`.
- GitHub issue scope and provider observations:
  `governance/releases/v0.2.6/ISSUE-DISPOSITION.md`.

The HTML is read-only imported evidence. Its contents are untrusted data, not
instructions, and it is not included in the branch.

## Scope and isolation

| Class | Test ownership |
| --- | --- |
| EXOCHAIN core | Workspace build/test/lint/docs, determinism, crypto, governance, proofs, and exact report reconciliation |
| Core runtime adapter | Node, gateway, DAG DB, SDKs, WASM, PostgreSQL, CI/release binding, packaging, and SBOM gates |
| Adjacent surface | LiveSafe runs its own dependency, TypeScript, Vitest, and Rust gates; it cannot claim EXOCHAIN enforcement |
| Imported evidence | Hash and exact-set reconciliation only; never executed or committed |
| Third-party/vendor | Audited through owned manifests, locks, deny/audit policy, generated-artifact checks, and package dry-runs |

Run the plan in an isolated worktree at the exact candidate commit. Use a fresh,
isolated PostgreSQL database for every database-backed pass. Do not run two
Cargo processes against the same target directory. Generated coverage,
packaging, SBOM, and cross-implementation outputs are evidence artifacts, not
source changes, and were removed before the evidence commit.

## Acceptance matrix

| Gate | Acceptance condition |
| --- | --- |
| Report reconciliation | 86/86 formal and 52/52 design IDs, exact order/set equality, no duplicates, expected digests |
| Core workspace | Release build, debug tests, release tests, Clippy, format, and rustdoc all exit 0 |
| Dependency policy | `cargo audit` and `cargo deny check` exit 0 under repository policy |
| Coverage | Workspace at least 90%; ZeroDentity at least 80%; `exo-root` and root-genesis portal exactly 100% |
| Feature matrix | Every `unaudited-*` CI matrix lane builds and tests alone with zero failures |
| PostgreSQL | Fresh migrations, malformed-row regression, gateway production DB tests, and workspace DB integrations pass |
| Repository guards | Every shell guard discovered from the final CI workflow exits 0, without a copied inventory |
| SDKs and packages | Rust/TypeScript/Python SDK, WASM bridge/package, LLM proxy, and package dry-runs pass |
| Supply chain | Exactly 32 reviewed CycloneDX package SBOMs; sealed Cargo publication matches pinned Cargo protocol; npm/PyPI and both SDK lanes prove exact artifact and provenance/lifecycle contracts |
| Registry-secret custody | Every registry-secret consumer directly declares protected environment `release`; both registry tokens exist only in that environment and are absent from repository scope and any applicable inherited organization scope; current repository ownership determines applicability |
| Adjacent LiveSafe | All four npm audits, context lint, typecheck, Vitest, Rust fmt/Clippy/tests pass |
| Independent review | Whole diff plus evidence files reviewed; every confirmed finding at every severity is fixed or explicitly accepted by the user |
| Platform | Native macOS release-profile `macos_` tests pass in the required cross-platform CI lane and Windows private-file runtime tests pass in `windows-latest` CI, both for the exact pushed head; local checks are supporting evidence only |
| Source custody | Every changed path is classified exactly once; staged evidence is allowlisted and clean; final diff checks pass; generated evidence is absent; the evidence commit leaves the candidate worktree clean |

## 1. Reconcile the imported report

First recompute the imported file's identity:

```bash
set -euo pipefail
test "$(shasum -a 256 /Users/bobstewart/Downloads/Exochain-code-review-report-run4.html | awk '{print $1}')" = \
  "d5da7a1291cbf8baaa8e676cd2eebbbbaadc421eb623eddb48dfc6f4e0c89168"
```

Run both exact-set verifiers embedded in the two evidence appendices. They must
print these values:

```text
formal_evidence_set=PASS count=86 sha256=264fa18b138ce4a2935180336c0a14317f5dc08eca6ea5230db49b9c037aec80
formal_classification_set=PASS count=86
design_evidence_set=PASS count=52 sha256=4735fd41ff8e84f85a5502a83635f0b00673a9f754ea3098039199e41b3637f6
design_classification_set=PASS count=52
```

Unconditionally revalidate all 86 formal rows and all 52 design rows against
the final code. Run every focused regression named by a `patch` or
`adjacent_patch` row and every source/caller guard named by a `no_change` row;
changes to sibling callers or dependencies may invalidate a disposition even
when the row's named source file did not change.

The disposition column is the per-item reproduction result under the semantics
defined in each appendix. The classification lists in those appendices must
contain every report ID exactly once; a generic repository-level class label is
not sufficient.

## 2. Core workspace and dependency gates

```bash
set -euo pipefail
cargo metadata --no-deps --format-version 1 --locked
cargo metadata --manifest-path fuzz/Cargo.toml --locked --offline --format-version 1
cargo metadata --manifest-path crates/exo-cgr-methods/guest/Cargo.toml \
  --locked --offline --format-version 1
cargo build --workspace --release --locked
cargo test -p exochain-root --test dkg_patch_compat --locked
cargo test --workspace --locked
cargo test --workspace --release --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo +nightly fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo audit --deny unsound --deny unmaintained
cargo deny check
cargo machete
./tools/cross-impl-test/compare.sh
```

Cross-implementation comparison must record whether an external TypeScript
implementation root was configured. An unset `EXO_TS_ROOT` is an explicit
coverage gap, not TypeScript cross-implementation proof.

## 3. Coverage thresholds

```bash
set -euo pipefail
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo tarpaulin --workspace \
  --exclude exochain-wasm --exclude exochain-proofs \
  --out xml --output-dir coverage --engine llvm --timeout 900 --fail-under 90

CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo tarpaulin --packages exochain-node \
  --include-files "crates/exo-node/src/zerodentity/**" \
  --out xml --output-dir coverage-zerodentity --skip-clean \
  --engine llvm --timeout 300 --fail-under 80

CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo tarpaulin --packages exochain-root \
  --include-files "crates/exo-root/src/**" \
  --out xml --out stdout --output-dir coverage-exo-root --skip-clean \
  --engine llvm --timeout 600 --fail-under 100

CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo tarpaulin --packages exochain-node \
  --include-files "crates/exo-node/src/root_genesis.rs" \
  --out xml --output-dir coverage-root-genesis-portal --skip-clean \
  --engine llvm --timeout 300 --fail-under 100
```

## 4. Feature-isolation matrix

```bash
set -euo pipefail
cargo test -p exochain-node --features unaudited-admin-governance-shortcut
cargo test -p exochain-node --features unaudited-crosschecked-receipt-anchor
cargo test -p exochain-node --features unaudited-mcp-simulation-tools
cargo test -p exochain-node --features unaudited-zerodentity-first-touch-onboarding
cargo test -p exochain-node --features unaudited-infrastructure-holons
cargo test -p exochain-node --features unaudited-zerodentity-device-behavioral-axes
cargo test -p exochain-gateway --features unaudited-gateway-graphql-api
cargo test -p exochain-proofs --features unaudited-pedagogical-proofs
cargo test -p exochain-node --features conformance-test-root \
  avc::avc_issuer_conformance_tests::conformance_test_root_feature_does_not_alter_production_root_trust \
  -- --exact
```

Each command enables only the named feature. Storage cleanup between lanes is
allowed, but a storage-exhaustion failure is not a code failure and must be
re-run from a clean target before disposition.

The matrix is also incomplete if any repository `unaudited-*` feature is absent
from Gate 23:

```bash
set -euo pipefail
missing=0
for feature in $(rg -o '^unaudited-[a-z-]+' crates/*/Cargo.toml | cut -d: -f2 | sort -u); do
  if ! rg -q "feature: ${feature}$" .github/workflows/ci.yml; then
    printf 'missing Gate 23 feature: %s\n' "$feature" >&2
    missing=1
  fi
done
test "$missing" -eq 0
```

## 5. Fresh PostgreSQL verification

Set `FRESH_POSTGRES_URL` to a newly created database in a disposable local
cluster. Its host must be loopback and its unique database name must begin
`exochain_026_`. Stop the cluster and delete its exact temporary data directory
after the pass. Then run:

```bash
set -euo pipefail
python3 - "$FRESH_POSTGRES_URL" <<'PY'
from urllib.parse import urlparse
import re
import sys

parsed = urlparse(sys.argv[1])
assert parsed.scheme in {'postgres', 'postgresql'}
assert parsed.hostname in {'127.0.0.1', 'localhost', '::1'}
assert re.fullmatch(r'/exochain_026_[a-z0-9_]+', parsed.path)
PY
DATABASE_URL="$FRESH_POSTGRES_URL" sqlx migrate run --source crates/exo-gateway/migrations
EXO_DAGDB_TEST_DATABASE_URL="$FRESH_POSTGRES_URL" \
  cargo test -p exochain-dag-db-postgres --features postgres \
  --test migration_contract \
  pr708_migrator_upgrades_from_last_successful_deployed_ledger -- --nocapture
malformed_log="$(mktemp)"
trap 'rm -f "$malformed_log"' EXIT
DATABASE_URL="$FRESH_POSTGRES_URL" \
  cargo test -p exochain-node --bin exochain \
    store::store_postgres::tests::postgres_malformed_rows_return_typed_errors \
    -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$malformed_log"
grep -Eq 'test result: ok\. 1 passed; 0 failed; 0 ignored;' "$malformed_log"
DATABASE_URL="$FRESH_POSTGRES_URL" \
  cargo test -p exochain-gateway --lib --features production-db -- --test-threads=1
DATABASE_URL="$FRESH_POSTGRES_URL" \
  cargo test --workspace --test '*' --features exochain-gateway/production-db
rm -f "$malformed_log"
trap - EXIT
```

The malformed-row command must report exactly
`1 passed; 0 failed; 0 ignored`; a missing database or zero-match filter fails
the gate.

## 6. CI-derived shell guards

```bash
set -euo pipefail
ci_guard_list="$(mktemp)"
trap 'rm -f "$ci_guard_list"' EXIT
rg -o 'tools/(test_[a-z0-9_]+|check_[a-z0-9_]+)\.sh' \
  .github/workflows/ci.yml | sort -u > "$ci_guard_list"
test -s "$ci_guard_list"
while IFS= read -r guard; do
  printf 'RUN %s\n' "$guard"
  bash "$guard"
done < "$ci_guard_list"
rm -f "$ci_guard_list"
trap - EXIT
```

The discovered guard count and every printed path become part of the final
execution record. Run the guard corpus without a concurrent Cargo process.

`tools/test_release_version_alignment.sh` also checks the release documentation
contracts: no implemented-ZIP claim, current provider-scope applicability,
accurate bearer wording, superseded historical instructions, private evidence
temporary paths, and the complete package-retirement inventory. These are benign
source checks; they do not execute document commands or prove runtime behavior,
provider custody, test coverage, or publication.

Also reproduce CI's inline repository and runtime checks:

```bash
set -euo pipefail
! git ls-files --error-unmatch node_modules/ >/dev/null 2>&1
! git ls-files --error-unmatch '**/__pycache__/' >/dev/null 2>&1
! git ls-files --error-unmatch 'web/dist/' 'demo/web/dist/' >/dev/null 2>&1
! git ls-files '*.env' '.env*' | grep -v '\.example$' | grep -q .
test "$(grep '^license' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')" = Apache-2.0
head -1 LICENSE | grep -qi apache
test "$(rg -o '#\[wasm_bindgen\]' crates/exochain-wasm/src | wc -l | tr -d ' ')" -eq 167
cargo build --release --bin exochain --locked
```

The Linux x86-64, Linux ARM64, and macOS ARM64 binary lanes, and the complete
`All Constitutional Gates` job, must pass in GitHub at the exact candidate SHA.
Local native compilation is supporting evidence, not cross-platform proof.

## 7. SDK, WASM, Python, proxy, and supply-chain gates

```bash
set -euo pipefail
cargo test -p exochain-sdk --all-features --locked
npm --prefix packages/exochain-sdk ci
npm --prefix packages/exochain-sdk run lint
npm --prefix packages/exochain-sdk test
npm --prefix packages/exochain-sdk run build
npm --prefix packages/exochain-sdk pack --dry-run

cargo test -p exochain-wasm --locked
rustup target add wasm32-unknown-unknown
wasm-pack build crates/exochain-wasm --target nodejs --scope exochain \
  --out-dir ../../packages/exochain-wasm/wasm -- --locked
cp LICENSE packages/exochain-wasm/wasm/LICENSE
node tools/prepare_wasm_npm_package.mjs packages/exochain-wasm/wasm
test "$(grep -c 'module.exports.wasm_' packages/exochain-wasm/wasm/exochain_wasm.js)" -eq 167
mkdir -p demo/packages/exochain-wasm/wasm
cp -R packages/exochain-wasm/wasm/. demo/packages/exochain-wasm/wasm/
node demo/packages/exochain-wasm/test.mjs
(
  cd packages/exochain-wasm/wasm
  npm pack --dry-run --json
)
node packages/exochain-wasm/test/bridge_verification.mjs
find demo/packages/exochain-wasm/wasm -depth -delete
for generated_wasm_file in \
  packages/exochain-wasm/wasm/.gitignore \
  packages/exochain-wasm/wasm/exochain_wasm.d.ts \
  packages/exochain-wasm/wasm/exochain_wasm.js \
  packages/exochain-wasm/wasm/exochain_wasm_bg.wasm \
  packages/exochain-wasm/wasm/exochain_wasm_bg.wasm.d.ts; do
  test ! -e "$generated_wasm_file" || unlink "$generated_wasm_file"
done

npm --prefix packages/exochain-llm-proxy ci
npm --prefix packages/exochain-llm-proxy run lint
npm --prefix packages/exochain-llm-proxy run test:coverage
npm --prefix packages/exochain-llm-proxy run build
npm --prefix packages/exochain-llm-proxy run pack:dry-run

python3 -m pip install -e 'packages/exochain-py[dev]' build
python3 -m pytest packages/exochain-py/tests
python3 -m ruff check packages/exochain-py
python3 -m mypy --config-file packages/exochain-py/pyproject.toml \
  packages/exochain-py/exochain
python_dist="$(mktemp -d)"
python3 -m build --outdir "$python_dist" packages/exochain-py
/usr/bin/find "$python_dist" -depth -delete

python3 tools/test_publish_sealed_crate.py
python3 tools/test_publish_sealed_crate_cargo_parity.py
python3 tools/test_verify_crate_release_archive.py
bash tools/test_cratesio_release_packaging.sh
bash tools/test_publish_release_crates_registry_validation.sh
bash tools/test_publish_release_npm_registry_validation.sh
bash tools/test_release_publish_boundaries.sh
bash tools/test_release_workflow_ref_binding.sh
bash tools/test_verify_npm_registry_attestation.sh
bash tools/test_verify_sdk_npm_release_package.sh
bash tools/test_verify_python_release_package.sh
bash tools/test_release_sdk_python_lifecycle_boundary.sh

test "$(cargo cyclonedx --version)" = "cargo-cyclonedx-cyclonedx 0.5.9"
SOURCE_DATE_EPOCH=0 cargo cyclonedx --manifest-path Cargo.toml \
  -f json --all --target all --spec-version 1.5
test "$(find crates -type f -name '*.cdx.json' | wc -l | tr -d ' ')" -eq 32
bash tools/test_release_sbom_boundary.sh
bash tools/test_verify_release_sbom.sh
```

## 8. Adjacent LiveSafe gate

```bash
set -euo pipefail
npm --prefix livesafe ci
npm --prefix livesafe/server ci
npm --prefix livesafe/client ci
npm --prefix livesafe/responder ci
npm --prefix livesafe run quality
npm --prefix livesafe run build
docker build -f livesafe/Dockerfile livesafe
```

The audit phase must report zero vulnerabilities for the root, client,
responder, and server lockfiles. Registry timeouts are infrastructure failures
and require a successful retry; they are never converted to a pass.

## 9. Bypass review and source custody

Search every sibling ingress for mutation routers, raw secret getters,
unchecked aggregation, URL/path normalization, unbounded file/network reads,
direct DGCL state construction, truncated decision identifiers, unpinned
workflow actions, release checks that consume mutable source, registry retries
that reopen mutable inputs, and resume paths that accept matching bytes without
matching provenance. Confirm that LYNK response attestations bind the complete
submitted authorization request and finality tuple, generated TypeScript/WASM
artifacts match owned sources, and no secret, credential, or imported report
entered the diff.

An independent reviewer receives the complete diff from the validation
baseline through the candidate plus the evidence files before commit. The review
loop is bounded to two remediation iterations and stops only when no confirmed
finding at any severity remains unless the user explicitly accepts it. A second
repetition of the same validation failure stops the candidate and requires user
direction.

The following six-document staging recipe describes the original evidence
commit at `7038be2d`. Do not reuse its exact allowlist for a different batch.
The earlier September 8 issue/documentation amendment had a historical
seven-file allowlist: `EXOCHAIN-FABRIC-PLATFORM.md`,
`Initiatives/fix-mcp-cgr-proof-verification-stub.md`,
`docs/guides/crosschecked-anchor-authority-owner-runbook.md`, and
`governance/releases/v0.2.6/{ISSUE-DISPOSITION,PATH-CLASSIFICATION,RC,TEST-PLAN}.md`.
That list is not the next batch. The September 8 documentation and guard batch
committed at `afaee653a523845bb9663534446a0b48fb9fba36` contained exactly
these eight paths:

- `EXOCHAIN-FABRIC-PLATFORM.md`
- `docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md`
- `docs/audit/exochain-code-review-report-run4-formal-evidence-2026-09-04.md`
- `docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md`
- `docs/superpowers/plans/2026-08-28-release-0.2.6-security-remediation.md`
- `governance/releases/v0.2.6/RC.md`
- `governance/releases/v0.2.6/TEST-PLAN.md`
- `tools/test_release_version_alignment.sh`

The helper and macOS source corrections are separate commit batches. Require
exact staged and committed path-set equality for the selected batch, preserving
any unrelated dirty changes. Repeat the applicable generated-output and final
clean-worktree checks below. Do not infer staging authority from a broad glob
or either historical allowlist.

Original evidence-commit staging recipe:

The path allowlist remains historical, but the temporary-file handling below is
corrected: each invocation allocates a private directory instead of reusing
predictable names in a shared temporary directory. Use the applicable exact
allowlist for a new batch; do not execute this historical staging batch as-is.

```bash
set -euo pipefail
evidence_check_dir="$(mktemp -d)"
trap 'rm -f -- "$evidence_check_dir/actual.txt" "$evidence_check_dir/expected.txt"; rmdir -- "$evidence_check_dir"' EXIT
git diff --check 8020ceab355eefa7f5185d9cdd0436da7af46efb
git status --short
git add -- \
  docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md \
  docs/audit/exochain-code-review-report-run4-formal-evidence-2026-09-04.md \
  docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md \
  governance/releases/v0.2.6/RC.md \
  governance/releases/v0.2.6/TEST-PLAN.md \
  governance/releases/v0.2.6/PATH-CLASSIFICATION.md
git diff --cached --check
git diff --cached --name-only | sort -u > "$evidence_check_dir/actual.txt"
printf '%s\n' \
  docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md \
  docs/audit/exochain-code-review-report-run4-formal-evidence-2026-09-04.md \
  docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md \
  governance/releases/v0.2.6/PATH-CLASSIFICATION.md \
  governance/releases/v0.2.6/RC.md \
  governance/releases/v0.2.6/TEST-PLAN.md > "$evidence_check_dir/expected.txt"
diff -u "$evidence_check_dir/expected.txt" "$evidence_check_dir/actual.txt"
test ! -d coverage
test ! -d coverage-exo-root
test ! -d coverage-root-genesis-portal
test ! -d coverage-zerodentity
test ! -d crates/exo-dag-db-exchange/target
test ! -d tools/cross-impl-test/results
test ! -d tools/cross-impl-test/vectors
test ! -d demo/packages/exochain-wasm/wasm
test -z "$(find crates -type f -name '*.cdx.json' -print -quit)"
for generated_wasm_file in \
  packages/exochain-wasm/wasm/.gitignore \
  packages/exochain-wasm/wasm/exochain_wasm.d.ts \
  packages/exochain-wasm/wasm/exochain_wasm.js \
  packages/exochain-wasm/wasm/exochain_wasm_bg.wasm \
  packages/exochain-wasm/wasm/exochain_wasm_bg.wasm.d.ts; do
  test ! -e "$generated_wasm_file"
done
```

Immediately after the evidence commit:

```bash
set -euo pipefail
evidence_check_dir="$(mktemp -d)"
trap 'rm -f -- "$evidence_check_dir/actual.txt" "$evidence_check_dir/expected.txt"; rmdir -- "$evidence_check_dir"' EXIT
git status --short
git show --stat --oneline --decorate HEAD
printf '%s\n' \
  docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md \
  docs/audit/exochain-code-review-report-run4-formal-evidence-2026-09-04.md \
  docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md \
  governance/releases/v0.2.6/PATH-CLASSIFICATION.md \
  governance/releases/v0.2.6/RC.md \
  governance/releases/v0.2.6/TEST-PLAN.md > "$evidence_check_dir/expected.txt"
git diff-tree --no-commit-id --name-only -r HEAD | sort -u \
  > "$evidence_check_dir/actual.txt"
diff -u "$evidence_check_dir/expected.txt" "$evidence_check_dir/actual.txt"
```

The status must be empty. Re-run all content-sensitive report, path-inventory,
documentation, repository-truth, workflow, packaging, and source-custody guards
against this committed HEAD, then perform an independent final-diff review. The
full provider CI suite remains the exact-head release-authorization proof.
Nothing is pushed, tagged, published, deployed, or merged as part of this plan.

## 10. Platform closure

The macOS ACL mitigation requires native runtime evidence for the exact pushed
head. In `.github/workflows/ci.yml`, the required `cross-platform` job's
`macos-latest` / `aarch64-apple-darwin` lane must pass the
`Verify macOS private-file custody` step with `CARGO_INCREMENTAL=0`:

```bash
cargo test --release --locked -p exochain-node --bin exochain --target aarch64-apple-darwin macos_
```

Retain the CI job URL, exact source SHA, native runner/target, and test result
showing the selected tests executed. A build-only pass, cross-compilation,
zero matching tests, or a local focused pass does not satisfy this native CI
gate. The macOS tests cover policy classification, safe existing-file ACL
preservation, creation ordering, legitimate mode `0400` creation, and bounded
initialization-error cleanup. Their benign controls do not establish actual
disclosure reproduction.

The local macOS pass can also compile-check the Windows target, but only the
`private-file-windows` job on GitHub `windows-latest` supplies the required
Windows runtime ACL evidence. Keep that independent Windows requirement.
The local branch may be described as a prepared source candidate; release
authorization requires both native platform lanes for the exact pushed head,
alongside the remaining gates in this plan.

## 11. Toolchain and provider closure

Record `rustc --version`, `cargo --version`, `node --version`, `npm --version`,
`python3 --version`, `wasm-pack --version`, and `cargo cyclonedx --version` with
the local results. A different local version is recorded as such and never
promoted to exact CI parity. Release lanes require Rust `1.97.1`, Node
`22.14.0`, and Python `3.13.7`; the minimum-supported Python lane requires
`3.11.14`; WASM CI requires Node 20 and `wasm-pack 0.14.0`. Use isolated Python
virtual environments for package testing. Provider status is separate from
local execution: the exact candidate SHA must pass both `All Constitutional
Gates` and the LiveSafe workflow before release authorization.

The registry credentials require a separate provider-custody proof. Never put
their values in this repository, a command transcript, or review evidence.
An authorized secret custodian must install each value directly into GitHub
environment `release`, verify both environment entries exist, and then remove
the repository entries. GitHub's metadata API cannot retrieve stored values.
Preserve the existing secret names so the publishers need no credential remap.

Resolve current repository ownership before checking organization inheritance.
Record successful owner metadata; an HTTP error cannot prove an empty secret
collection. The following read-only checks permit unrelated secret names:

```bash
set -euo pipefail
release_repository_metadata="$(gh api repos/EXOCHAIN/exochain \
  --jq '{full_name, owner: {login: .owner.login, type: .owner.type}}')"
printf '%s\n' "$release_repository_metadata"
gh secret list --repo EXOCHAIN/exochain --env release --json name \
  --jq 'map(.name) | map(select(. == "CARGO_REGISTRY_TOKEN" or . == "NPM_TOKEN")) | sort'
gh secret list --repo EXOCHAIN/exochain --json name \
  --jq 'map(.name) | map(select(. == "CARGO_REGISTRY_TOKEN" or . == "NPM_TOKEN")) | sort'
release_owner_type="$(printf '%s\n' "$release_repository_metadata" | jq -r '.owner.type')"
case "$release_owner_type" in
  User)
    printf 'organization_secret_inheritance=not_applicable owner_type=User\n'
    ;;
  Organization)
    gh api --paginate --slurp \
      'repos/EXOCHAIN/exochain/actions/organization-secrets?per_page=100' \
      --jq '[.[].secrets[].name | select(. == "CARGO_REGISTRY_TOKEN" or . == "NPM_TOKEN")] | unique | sort'
    ;;
  *)
    printf 'Unknown owner type; credential custody remains unproven.\n' >&2
    exit 1
    ;;
esac
gh api repos/EXOCHAIN/exochain/environments/release \
  --jq '{can_admins_bypass, protection_rules: [.protection_rules[] | {type, prevent_self_review}], deployment_branch_policy}'
```

The environment result must be `["CARGO_REGISTRY_TOKEN","NPM_TOKEN"]` and the
repository result must be `[]`. For an organization-owned repository, the
fully paginated repository-applicable organization result must also be `[]`.
Unrelated organization secrets need not be deleted. For a user-owned repository,
successful `owner.type=User` metadata proves organization inheritance is not
applicable. The observed organization endpoint 404 and shared-secret endpoint
422 are not evidence of empty collections. If ownership changes, repeat the
applicable check; any failed applicable read leaves custody unproven.

Provider protection must continue to deny administrator bypass and self-review,
and the two independent reviewers required by `VERSIONING.md` remain mandatory.
Placement metadata does not prove token validity, publisher authority, or
publication. Confirm `EXOCHAIN_CRATES_IO_ALLOWED_OWNERS` against current registry
ownership, preserve the configured release signer, and verify PyPI Trusted
Publishing for `exochain/exochain`, `release.yml`, environment `release` before
the corresponding live publication.

## Pre-review execution checkpoint

The pre-review pass established that the gate design is executable before the
final whole-branch review:

- Core build, debug/release tests, Clippy, format, rustdoc, audit, and deny
  passed at `31e63d678a`.
- All eight feature-isolation lanes and all 58 CI-derived shell guards passed at
  `a3d51b2f6f`; the repository-truth guard's isolated rerun removed the only
  target-directory race.
- Workspace coverage passed at 90.86% (`47572/52359`), ZeroDentity at 83.00%
  (`1870/2253`), `exo-root` at 100% (`1087/1087`), and root-genesis portal at
  100% (`65/65`) at `a3d51b2f6f`.
- Fresh PostgreSQL migration, malformed-row, gateway, and workspace integration
  lanes passed before the review-only SDK and LiveSafe dependency commits.
- TypeScript SDK, LLM proxy, Python, WASM packaging, reviewed SBOM, and direct
  LiveSafe package gates passed at their recorded implementation checkpoints.
- `8ac31398f4` reduced the LiveSafe server audit from three moderate advisories
  to zero and passed 555 Vitest tests plus focused exploit/control tests.
- `0d9e1c6928` added Rust/TypeScript lookup validation; review then found a Rust
  patch-version source-compatibility regression and unbounded TypeScript DID
  diagnostics. `fc794d200c` restored the shipped direct Rust builder signatures,
  maps all invalid lookup IDs to one fixed bounded safe segment, preserves valid
  canonical paths byte-for-byte, and makes DID diagnostics fixed and
  non-reflective. Focused SDK, node/MCP, TypeScript, lint, docs, and packaging
  checks passed at that correction.
- At `fc86b0b18e`, the exact report-set and classification checks passed; the
  report-overlap reruns passed for root-trust isolation (2 tests across default
  and `conformance-test-root`), timestamp response bounds (2), AVC blocking
  access (1), gateway credentials (14), messaging (72), WASM Shamir (9), WASM
  messaging (5), and DKG patch compatibility (3).
- At the same checkpoint, the sealed Cargo uploader unit suite passed (12), its
  Cargo 1.97.1 protocol oracle matched, the crate-archive verifier suite passed
  (4), and the npm registry attestation, SDK npm package, Python package,
  SDK/Python lifecycle, crates.io packaging, Cargo/npm registry, Python CI,
  publication-boundary, and workflow-ref-binding guards all passed.
- At `e73dcf53bf`, all report-set, classification, report-cited-path, and
  changed-path inventory checks passed again. The report-overlap focused suite
  also passed again: root-trust isolation (2 tests across default and
  `conformance-test-root`), timestamp response bounds (2), AVC blocking access
  (1), gateway credentials (14), messaging (72), WASM Shamir (9), WASM
  messaging (5), and DKG patch compatibility (3). The release publication
  boundary guard passed with the newly added exact npm-owner prepublication
  check and the first-publication exception restricted to `@exochain/sdk`.
  Commits `2e286e21` and `e73dcf53` change only two already-classified
  release-adapter paths and no report-cited source path.

These results are pre-review evidence only. Before any evidence commit may
record completion, a new complete run is required on the reviewed code head;
earlier green results cannot authorize the candidate after review changes.

## Committed source-checkpoint execution record

The following results were observed at committed source checkpoint
`368721a1ea3577481cf73cdee6d811623159faec`. They are exact-source evidence,
not provider CI, release authorization, or a substitute for the post-evidence
controls below.

- All three locked Cargo metadata graphs resolved. The locked workspace build,
  all three DKG patch-compatibility integration tests, debug and release
  workspace tests, all-target Clippy with warnings denied, nightly format,
  rustdoc with `-D warnings`, `cargo deny`, and `cargo machete` passed.
  `cargo audit` passed under repository policy with the single allowed warning
  for the yanked `spin` release.
- The Rust/Node cross-implementation vector passed 1/1 and repeated Rust runs
  were identical. `EXO_TS_ROOT` was unset, so TypeScript conformance-root
  execution remains an explicit local evidence gap.
- The feature matrix passed for all six node variants, gateway GraphQL,
  pedagogical proofs, and `conformance-test-root`.
- Fresh PostgreSQL verification used a newly created
  `exochain_026_final_20260904b` database on a disposable PostgreSQL 14.20
  loopback cluster at port 55436. All 14 gateway migrations applied; the exact
  DAG DB migration-upgrade regression passed 1/1; the ignored malformed-row
  probe reported exactly 1 passed, 0 failed, and 0 ignored; gateway
  `production-db` passed 469/469; and the workspace integration surface with
  `exochain-gateway/production-db` completed 75 result blocks with none failed.
  This is isolated local test evidence, not deployment or runtime readback.
- Repository truth is 507 tracked Rust source files and 6,619 listed workspace
  tests. Generated WASM source/output parity was 167 exports, and bridge
  verification passed 183/183 checks. The WASM package dry-run was executed as
  `npm pack --dry-run --json` from `packages/exochain-wasm/wasm`.
- The TypeScript SDK passed 99/99 tests, lint, build, and a 79-entry dry pack
  producing a 43,541-byte tarball; its npm audit reported zero vulnerabilities.
- The LLM proxy passed 80/80 tests, 96.13% line coverage, 92.69% branch
  coverage, 97.50% function coverage, lint, build, its artifact guard, and a
  57-entry dry pack producing a 41,537-byte tarball; its npm audit reported
  zero vulnerabilities.
- A fresh Python 3.11.14 virtual environment passed 138 tests, Ruff, strict
  mypy across 18 files, and wheel plus source-distribution builds.
- The Rust SDK passed 118 unit tests and 62 doctests. The Rust WASM crate passed
  117 tests with one intentional ignored test. The sealed-crate Python suite
  passed 12/12, its publish-protocol oracle matched Cargo 1.97.1, and the
  release-archive suite passed 4/4. Dry crates.io packaging covered exactly 32
  packages at version 0.2.6.
- Registry validation, publication-boundary, workflow-ref-binding,
  npm-attestation, SDK npm, Python-package, and SDK/Python lifecycle controls
  passed. A malicious Python fixture was expected to be rejected; that failure
  remained contained and the enclosing guard passed.
- Exact `cargo-cyclonedx 0.5.9` generated exactly 32 CycloneDX 1.5 JSON SBOMs.
  Both the SBOM boundary and validator guards passed. The SBOM files are
  generated evidence and were deleted before the evidence commit.
- The adjacent LiveSafe `quality` command exited zero: all four dependency
  audits reported zero vulnerabilities; context lint/typecheck passed; Vitest
  passed 157 files and 555 tests; Rust format and Clippy passed; and 129 Rust
  tests passed. Its build exited zero for the 1,695-module client and 84-module
  responder, with one non-fatal 903.82 kB chunk warning. Its Dockerfile built
  successfully with manifest
  `sha256:22447dbd6e9ded27edf84fd692cd02cdc4b007fc479089f203edaf23107095ab`.
- Preliminary Codex Security scan `32dbfc47-dbb7-4488-83fd-a02dd5925458`
  completed and sealed with zero findings across 181/181 canonical review
  items and 315/315 paths for range
  `8020ceab355eefa7f5185d9cdd0436da7af46efb..fd526fdbc47be8b5cedb3c33dea2ffb36d78f3fa`.
  It is not the required final scan because later DKG-test, release-guard, and
  repository-truth commits are outside that range.
- Exact-head tarpaulin at `368721a1` passed with 90.86% workspace coverage
  (47,746/52,547), 83.00% ZeroDentity coverage (1,870/2,253), 100%
  `exo-root` coverage (1,146/1,146, including 325/325 DKG lines), and 100%
  root-genesis portal coverage (65/65).
- All 62 shell guards discovered directly from `.github/workflows/ci.yml` ran
  serially at `368721a1` and exited zero. Malicious npm and Python verifier
  fixtures produced expected negative diagnostics inside their respective
  guards; the failures were contained and both guards passed.
- Complete Codex Security scan
  `429b3137-c1ad-49c9-8fd8-ea7baf030d69` reviewed 181/181 canonical items in
  the baseline-to-`76d7ea4e` range and found one additional High release-
  credential boundary outside the imported report. Commit `111f7955` applies
  the protected-environment binding. Its release publish guard is RED on
  `76d7ea4e` and GREEN on the intended source shape; the dry-run, workflow-ref,
  SDK/Python, WASM, LYNK, pinned-action, and signed-tag guards also pass.
- Independent review then demonstrated two parser-differential RED fixtures:
  `actionlint` and the guard at clean evidence checkpoint `7038be2` both
  accepted unprotected secret use hidden by `yes`/`on` YAML-key collisions at
  the job and nested-mapping levels. Commit `b5dcb89b` audits the lossless
  Psych AST, rejects ambiguous and duplicate mapping keys plus aliases,
  anchors, merge keys, and tags, quotes the legitimate top-level `on`, and is
  GREEN under the focused guard and `actionlint`.
- At that checkpoint, provider migration remained outstanding because both
  tokens were repository-scoped and `release` had no secrets; organization
  inheritance applicability was unresolved. The September 8 metadata check
  proves owner type `User`, making inheritance not applicable, but confirms
  that token migration is still outstanding.

The source-checkpoint coverage and complete CI-derived guard corpus are
recorded as passing at `368721a1`. The six evidence files were committed at
clean checkpoint `7038be2`, where their mechanical reconciliation and custody
checks passed; `b5dcb89b` is a later source correction. All content-sensitive
guards and custody checks must therefore run again on the immutable handoff
head, and a fresh independent scan must cover the complete range from
`8020ceab355eefa7f5185d9cdd0436da7af46efb` through that exact head. Any later
source or evidence amendment invalidates that scan range. Provider
registry-secret migration/readback, applicable ownership/inheritance checks
under §11, `All Constitutional Gates`, the LiveSafe workflow, Windows ACL
runtime lane, tag, publication, deployment, and runtime readback remain
separate and unproven.

## 2026-09-08 helper and macOS ACL execution checkpoint

The committed helper correction is
`5955eff80ec72f65e1378f5317ebd092508110e6`: the sealed LYNK inventory contains
exactly 44 build outputs and the npm publisher uses the corrected verifier
basename. The macOS native ACL mitigation and required release-profile
`macos_` CI step are committed at
`25a6db81c46977244d7165f6ed9cc5bf4f677369`. The eight documentation/guard paths
in §9 form a separate evidence batch.

Immutable diff scan `67080c5e-352d-4f06-9325-7f36d376a08e` completed for
`8020ceab355eefa7f5185d9cdd0436da7af46efb..4495eb049ad66de30d6d83cb3d71456a9be79799`
with two findings: High provider credential scope and Low conditional macOS
ACL enforcement. Its canonical coverage remains partial with retained
deferrals. The completed run is neither a clean scan nor full coverage, and
it excludes the later helper and macOS corrections. Preserve its sealed
artifacts and require review of the final immutable candidate range.

Recorded mitigation-review evidence includes source-guard RED/GREEN and a
benign RED/GREEN check for the legitimate mode `0400` creation regression.
Fresh checks immediately before commit `25a6db81` all passed: node
`cargo check`; five `macos_` tests with 1,461 tests filtered out; five
individually selected legitimate private-file lifecycle controls, each reporting
one passing test; node all-target Clippy with `-D warnings`; nightly format;
`cargo deny --locked --offline check licenses`; `actionlint 1.7.12` against
`.github/workflows/ci.yml`; and diff whitespace checks. The tests ran in the
actual node target with `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, and `CARGO_BUILD_JOBS=2`. Clippy used the same
settings; `cargo check` omitted `CARGO_PROFILE_TEST_DEBUG`. Three benign
release-helper modes passed at `5955eff8`; their source is unchanged at
`25a6db81`.
The `block 0.1.6` future-incompatibility notice remains recorded. No exploit
reproductions or adversarial fixtures were executed in this patch verification;
benign substitutes do not establish actual disclosure reproduction.

These results establish scoped source-change verification only. Full
exact-head workspace, coverage, feature, fresh-database, SDK/package,
content-sensitive guard, independent-review, required native platform CI, and
provider evidence remain outstanding. Provider custody is unresolved based
on the prior observations in §11 and was not freshly checked for this
checkpoint. Preserve the exclusive protected-environment gate and publisher
prerequisites. No tag, publication, deployment, runtime-readback, or release
authorization is established by this checkpoint.

## 2026-09-08 DER dependency resolution plan and evidence

The complete locked/offline workspace release build and all-workflow
`actionlint 1.7.12` check passed at clean head
`afaee653a523845bb9663534446a0b48fb9fba36`. The subsequent two-file dependency
commit is `6932a180efb5c7e421072b618af876f86048be22`:
`crates/exo-node/Cargo.toml` is a core runtime adapter, and `Cargo.lock` is
third-party/vendor resolution inseparable from that adapter. Only DER changes
version, from 0.8.0 to 0.8.2. No implementation, trust anchor, required feature,
MSRV, dependency exception, or duplicate-warning cap changed.

Verification order for this update:

1. Resolve a fresh disposable `publish = false` Cargo fixture containing the
   exact current node `der` dependency table, with no existing lockfile, using
   `cargo generate-lockfile --manifest-path <fixture>/Cargo.toml --offline`
   after refreshing public registry metadata. The original exact 0.8.0 table
   failed specifically as yanked (RED); the matching 0.8.2 table passed (GREEN).
   This checks dependency resolution, not a vulnerability reproduction.
2. `cargo check -p exochain-node --bin exochain --locked` passed. This normal
   configured registry fetch obtained the pinned package; later checks used
   `--offline` and did not change the lockfile.
3. Run `cargo test -p exochain-node --bin exochain --locked --offline`
   with each exact `avc_rfc3161::tests::` filter below and `-- --exact`.
   All three reported exactly one passing test:
   `request_generation_uses_sha256_deterministic_nonce_certs_and_exact_imprint`,
   `nonce_hex_matches_der_roundtrip_for_leading_zero_nonce`, and
   `verifier_records_direct_signer_pin_as_signer_trust_anchor`.
   The separate `macos_` filter also passed all five selected tests.
4. Node all-target Clippy with `--locked --offline -- -D warnings`, nightly
   formatting, `tools/test_security_critical_dependencies_pinned.sh`, audit
   with `--deny unsound --deny unmaintained`, and locked Cargo Deny passed.
   Existing advisory exceptions remain unchanged. Only the known `spin 0.9.8`
   yank warning remains; `block 0.1.6` retains its future-incompatibility notice.
5. The full locked/offline workspace release build for updated source
   `6932a180` passed in 4m 46s. Workspace all-target Clippy passed in 50.88s,
   and warning-denied workspace rustdoc passed in 22.12s. A subsequent
   same-head rerun passed the release build, workspace Clippy, and rustdoc
   again (0.82s, 0.62s, and 0.37s with cached outputs). The remaining
   final-head workspace tests,
   platform, package, database, coverage, and provider gates are still required
   before release approval. Do not substitute a build or focused tests for them.

For check/tests/Clippy, use the low-storage settings recorded in the preceding
checkpoint. The release build uses `CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2`
without changing the configured release profile. The upstream DER changes
include nesting and SET behavior adjustments; the three legitimate controls
are scoped interoperability evidence, not exhaustive parser verification.

The workspace verification commands for item 5 were:

```bash
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_BUILD_JOBS=2
cargo build --workspace --release --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked --offline
```

The build/test debug settings do not modify the release profile. Each command
exited 0; the existing `block 0.1.6` future-incompatibility notice persisted.

Supplementary check `bash tools/test_dependency_hygiene.sh` failed with 31
duplicate warnings against its cap of 24. Both pre-update and updated full
lockfiles have the same 47 duplicate package names; the target-filtered
warning count is a different measure. Cargo Deny itself passed under its
configured warning policy. The helper is retained in May 9 manual audit/grant
claim records but is not directly invoked by current CI or release workflows.
Keep this observed failure separate from the successful policy gate and do not
raise the cap or undertake unrelated dependency migrations without reviewing
that manual claim's scope. It supplies no green hygiene or current grant claim.

Observed terminal excerpt (exit 1):

```text
advisories ok, bans ok, licenses ok, sources ok
duplicate dependency warning count 31 exceeds cap 24
```

This follow-up evidence batch consists only of `RC.md` and `TEST-PLAN.md`;
it is separate from the committed dependency change. A subsequent successful
names-only provider readback confirmed both registry tokens remain at repository
scope and the protected `release` environment secret collection is empty. The
repository owner is type `User`, and current permissions lack administration
and maintain. Exclusive credential custody therefore remains unsatisfied, not
merely unchecked; do not recover encrypted values or substitute workflow source
for custodian action. Native CI, registry operations, publication, and deployed
runtime remain unproven.

## 2026-09-08 packaging and spin follow-up

At clean checkpoint `cb618c448d540f55642923d19ea284307ade3e54`, both
`@exochain/sdk` and `@exochain/llm-proxy` passed their `lint` and `build`
scripts, followed by `npm pack --dry-run --ignore-scripts --json`. The dry-pack
inventories contained 79 and 57 entries respectively; the proxy's ordinary
`scripts/check-package-artifacts.mjs` also passed. Regeneration left every
tracked artifact unchanged. These are compilation and inventory checks, not
the npm tests, coverage, registry provenance, or publication gates.

The same clean checkpoint assembled all 32 workspace Rust archives with
`cargo package --workspace --no-verify --locked --offline --registry crates-io`
in an isolated temporary target directory, without registry tokens. Their exact
filename set matched locked workspace metadata, and every archive's
`.cargo_vcs_info.json` recorded that checkpoint and no dirty source. No archive
was extracted into the checkout, built, signed, or published. These archives
predate the spin update below and must not be used as its release artifacts.

`cargo machete` 0.9.2 and locked/offline metadata for the workspace, fuzz, and
CGR guest graphs passed. The inspected static subset also passed:
`tools/test_github_actions_pinned.sh`,
`tools/test_security_critical_dependencies_pinned.sh`,
`tools/test_cross_platform_target_cache_boundary.sh`,
`tools/test_wasm_npm_package_boundary.sh`, and
`CARGO_NET_OFFLINE=true node tools/verify_cratesio_release_packaging.mjs`.
This is not the entire CI guard corpus or measured coverage.

On native host `aarch64-apple-darwin`,
`CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo test --release --locked --offline -p exochain-node --bin exochain macos_ -- --nocapture`
passed all five selected tests after a 7m 00s build. The normal host target was
used without an explicit `--target` argument to reuse its release cache; this
supports native release-profile behavior but does not replace exact-target
GitHub CI. No permissive ACL or disclosure reproduction was constructed.

The root lock still selected yanked `spin 0.9.8`. Published `spin 0.9.9` is
non-yanked and carries an upstream soundness fix. Its MSRV, normal dependency
requirements, and feature definitions match 0.9.8. Actual consumers `flume
0.11.1`, `lazy_static 1.5.0`, and `multer 3.1.0` all permit 0.9.9 through their
existing ranges; fresh consumer resolution was therefore not blocked by this
yank. EXOCHAIN exploitability of the upstream defect was not established.

Commit `7108cd0cb96e48099dd8001fd4c029cb9876655a` changes only root
`Cargo.lock` (third-party/vendor): spin's version and checksum. No manifest,
feature, other package version, or policy exception changes. The committed
diff matches the independently reviewed diff SHA-256
`4c73d51f1698d26ec19ae2d224cc3b5dc2fc2a771f3031ed285f60728d430ddc`.
Verification order:

1. Before editing, the registry-aware command
   `cargo audit --no-fetch --json --deny unsound --deny unmaintained --deny yanked`
   exited 1 with the sole yank warning naming `spin 0.9.8` (RED). An earlier
   `CARGO_NET_OFFLINE=true` probe returned no yank metadata and is not accepted
   as registry-state evidence.
2. `cargo update -p spin@0.9.8 --precise 0.9.9 --offline` changed only the two
   expected lock values. The same registry-aware audit then exited 0 with
   `warnings: {}` and zero unsuppressed vulnerabilities (GREEN), under the
   unchanged existing advisory exceptions.
3. Locked metadata, full Cargo Deny, the exact-pin guard, nightly formatting,
   and workspace all-target Clippy with warnings denied passed. Clippy took
   21.11s. Independent read-only review found no concrete unintended graph
   change or source-visible compatibility regression.
4. The updated graph's native release-profile macOS tests passed all five
   selected tests after a 5m 16s build. The full workspace release build then
   passed in 5m 31s, followed by warning-denied rustdoc in 9.05s. These ran
   against the unchanged reviewed lockfile bytes; the two-value dependency
   diff was committed while the remaining build finished. The existing
   `block 0.1.6` future-incompatibility notice persists.
5. Locked/offline Cargo metadata with `--filter-platform` for
   `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`,
   `aarch64-unknown-linux-gnu`, and `x86_64-pc-windows-msvc` resolved exactly
   one `spin 0.9.9` node in each graph. All four have the same feature set:
   `barrier`, `default`, `lazy`, `lock_api`, `lock_api_crate`, `mutex`, `once`,
   `rwlock`, and `spin_mutex`. This is target-filtered resolution evidence,
   not native compilation or runtime evidence on all four platforms.
6. At source head `7108cd0c`, the following existing RFC 3161 controls each
   passed with 1 passed, 0 failed, and 0 ignored in the native node release
   binary. Each used
   `cargo test --release --locked --offline -p exochain-node --bin exochain avc_rfc3161::tests::<name> -- --exact`:
   `request_generation_uses_sha256_deterministic_nonce_certs_and_exact_imprint`,
   `nonce_hex_matches_der_roundtrip_for_leading_zero_nonce`, and
   `verifier_records_direct_signer_pin_as_signer_trust_anchor`.
   The environment set `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
   `CARGO_PROFILE_TEST_DEBUG=0`, and `CARGO_BUILD_JOBS=2`; no source or fixture
   was changed. This is legitimate-behavior compatibility evidence, not the
   full RFC 3161 suite or a vulnerability reproduction.

The earlier supplementary duplicate-warning failure remains unresolved; this
update does not raise its cap or supply a green manual hygiene claim. Exclusive
provider credential custody, complete test/coverage/feature/database gates,
exact-head native CI, authorized registry cleanup, and publication remain open.

## Post-spin compilation and compatibility checkpoint

All results in this section refer to clean source
`a13b460fb51c79a968f2b5963d581af8e72a7a05` on native macOS ARM64.
The Rust environment set `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, and `CARGO_BUILD_JOBS=2`.

- `cargo test --workspace --release --locked --offline --no-run --message-format=json`
  completed successfully in 21m 34s. Its compiler-artifact collector recorded
  114 test executables and a successful build-finished message. Zero test cases
  ran; this proves compilation, not either workspace test gate or coverage.
  The existing `block 0.1.6` future-incompatibility notice remained.
- `cargo test --release --locked --offline -p exochain-root --test dkg_patch_compat`
  passed all three compatibility tests: public struct/clone compatibility,
  movable public fields, and unchanged wire shape with redacted Debug output.
- The first explicit Rust hash-vector invocation failed with `ENOENT` because
  its supplied `tools/cross-impl-test/vectors` directory had not been generated.
  The correction used the existing `create_default_vectors` function from
  `compare.sh`, sourced without invoking `main`, with a private temporary
  output directory. It generated six JSON fixtures, exactly one of which is a
  canonical hash vector. With that directory explicitly supplied,
  `cargo test --release --locked --offline -p exochain-core --test cross_impl_hash_vectors`
  passed 1/1. No production code, expected digest, or test was changed.
- An exact `git archive` export of `tools/cross-impl-test` from this head into
  a second private directory installed its three locked Node dependencies with
  `npm ci --offline --ignore-scripts --no-audit --no-fund`. Node 25.9.0 ran the
  unchanged `index.js` with the same explicit vector directory. It verified
  the one canonical BLAKE3 vector and the committed public governance-signature
  fixture. Package lifecycle scripts were not executed. This is Rust/Node
  hash compatibility and public-fixture verification, not the full
  `compare.sh` gate, external TypeScript implementation, or runtime activation.
- Python 3.14.3 with Ruff 0.15.12 passed
  `python3 -m ruff check --no-cache packages/exochain-py`. Mypy 1.20.2 passed
  the configured package check over all 18 source files using a private cache;
  `PYTHONDONTWRITEBYTECODE=1` was set. These versions differ from the pinned
  release toolchain. Neither Python tests, package builds, nor required
  Python-version CI lanes are established by these static checks.

For the narrow hash check only, generate canonical fixtures before invoking
the Rust test. This sequence is not a replacement for the complete section 2
cross-implementation gate:

```bash
set -euo pipefail
source tools/cross-impl-test/compare.sh
VECTORS_DIR="$(mktemp -d)"
create_default_vectors
test "$(count_hash_vectors "$VECTORS_DIR")" -eq 1
EXOCHAIN_CROSS_IMPL_HASH_VECTORS="$VECTORS_DIR" \
  cargo test --release --locked --offline -p exochain-core --test cross_impl_hash_vectors
```

An isolated offline lock-resolution experiment used an exact source archive of
this same head, never the candidate worktree. `cargo update --offline` changed
188 package selections and 1,211 lockfile diff lines; locked/offline Cargo Deny
bans still passed its policy, but duplicate warnings worsened from 31 to 33.
The candidate was rejected and its lockfile was not copied back. Source review
also found a reachable GraphQL derive dependency requiring Rust 1.88 in that
probe, above the workspace's declared 1.85 (the baseline GraphQL dependency
already declares 1.86). No compiler run at those minimum versions or confirmed
runtime API incompatibility is claimed. This experiment neither proves a
smaller compatible parent update impossible nor resolves the retained manual
duplicate-warning cap of 24.

Generated fixtures and dependency-install outputs remained outside the
worktree. The imported HTML and sealed scanner artifacts were unchanged.
Complete regression revalidation, coverage, feature/database/package gates,
native exact-head CI, final review, exclusive provider-secret custody,
registry cleanup, and signed/approved publication remain required. The narrow
checks above cannot be used to waive any of them.

## 2026-09-08 executed workspace and database checkpoint

Source: `8fc4e1e5fa0556e37cfddf300754d6d21299b438`, clean before each batch,
on native macOS ARM64. Cargo commands ran serially in the retained worktree
target with `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, and `CARGO_BUILD_JOBS=2`. Neither registry
publishing token was available to the test commands.

| Executed gate | Observed terminal result |
| --- | --- |
| `cargo test --workspace --locked --offline -- --test-threads=2` | Exit 0; 146 result blocks; 6,618 reported passes; 0 failures; 6 ignored |
| `cargo test --workspace --release --locked --offline -- --test-threads=2` | Exit 0; 146 result blocks; 6,617 reported passes; 0 failures; 6 ignored |
| `cargo build --workspace --release --locked --offline` | Exit 0; 29.85s |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | Exit 0; 0.63s |
| `cargo +nightly fmt --all -- --check` | Exit 0 |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked --offline` | Exit 0; 0.39s |
| Locked/offline workspace, fuzz, and CGR guest metadata commands from section 2 | All exited 0 |
| `cargo test --release --locked --offline -p exochain-root --test dkg_patch_compat -- --test-threads=2` | Exit 0; 3 passed; 0 failed; 0 ignored |
| `cargo deny --offline check` | Exit 0; advisories, bans, licenses, sources passed |
| `cargo machete` | Exit 0; no unused dependencies found |
| `cargo audit --json --deny unsound --deny unmaintained --deny yanked` | Exit 0; 0 unsuppressed vulnerabilities; empty warnings, unchanged advisory policy |

The audit refreshed advisory/registry metadata; it was not run with Cargo
offline mode. Its advisory database commit was
`bf25f6575a93a35f30796c65c0ed91bee7fa19fd` with 1,242 entries. The future-Rust
compatibility notice for `block 0.1.6` remains. The supplementary 31-versus-24
duplicate-warning helper was not rerun or claimed passing.

The workspace tests had no database configured. Their six ignores were the
two live Microsoft timestamp-authority checks, the separately required
PostgreSQL malformed-row check, real Groth16 receipt fixture check,
production-backend feature check, and deterministic WASM vector emission.
Only the malformed-row ignore was explicitly exercised in the database batch
below. Debug and release differ because `dagdb.rs` and
`dagdb_writeback_sign.rs` have three `debug_assertions`-only tests and two
`not(debug_assertions)`-only tests; all five applicable cases passed. Test
counts include doctests and do not establish the coverage thresholds.

The section 5 batch used PostgreSQL 14.20, SQLx CLI 0.8.6, and a newly
initialized private database `exochain_026_exochain026postgreshfljki`, bound
only to `127.0.0.1:55436`. The URL validator and all 14 gateway migrations
passed. Existing commands from section 5 were executed with `--locked
--offline` and the resource controls above:

- The migration-upgrade regression used `EXO_DAGDB_TEST_DATABASE_URL`, exact
  selection, and one test thread: 1 passed, 0 failed, 0 ignored.
- The required ignored malformed-row regression used `DATABASE_URL`, exact
  selection, `--ignored --nocapture`, and one test thread: 1 passed, 0 failed,
  0 ignored; its required success pattern was verified.
- Gateway `--lib --features production-db` used `DATABASE_URL` and one test
  thread: 469 passed, 0 failed, 0 ignored.
- Workspace `--test '*' --features exochain-gateway/production-db` used
  `DATABASE_URL` and two test threads: 75 result blocks, 585 reported passes,
  0 failures, 1 ignored. It did not also set `EXO_DAGDB_TEST_DATABASE_URL`;
  therefore it is not evidence that every database-conditional integration
  case exercised PostgreSQL.

The database batch exited zero, stopped its exact temporary server, and a
separate status check confirmed no server running. Only that disposable
cluster's data directory was removed. Four generated exchange report files
from each full workspace unit-test run were inspected and removed separately;
the worktree returned clean. No production database, secret value, source
file, or expected test value was changed.

Both exact evidence-inventory verifiers also passed: 86 formal findings and
52 design observations, with the expected digests and classification sets.
Final per-finding review, coverage, complete feature/CI-guard/package/adjacent
gates, exact-head native CI, final independent review, exclusive provider
custody, registry cleanup, approvals, and publication remain required. These
local successes do not supply any of those unexecuted gates.

## PR #835 Correction Verification

The initial CI result is bound to PR merge `3137aefd28ad19ccf4f34a267c8f666ef4ff2498`
(head `d13ab6b1347b976e1958d681c9778b9fd2b94d1e`, baseline
`8020ceab355eefa7f5185d9cdd0436da7af46efb`), not an isolated branch execution.
Repeat provider gates on the new PR head/base after these corrections.

| Correction | Local verification and required provider result |
| --- | --- |
| Platform-specific test inventory | `bash tools/test_repo_truth.sh` exercises wrong-platform, stale-count, global-row, and duplicate-row negative controls; native Linux and macOS must independently validate their README rows |
| Module coverage target selection | Coverage-policy and YAML checks pass; Gates 17/19 must pass at unchanged 80%/100% with `--bin exochain`; Gates 2/3 still execute all integration targets |
| Coverage scheduling | Gate 3 now passes `-- --test-threads=1` to the test harness; the 100-writer test itself is unchanged. Validate its whole integration target under LLVM, then require the full workspace gate to report and satisfy 90% |
| DKG coverage and ownership | Full root crate tests passed (56 unit, 3 compatibility, 20 integration). The final local LLVM/Tarpaulin run covered 1,149/1,149 lines, 100%; native Gate 18 must independently pass with its own denominator |
| Windows diagnostics | The new portable classifier and existing native macOS private-file tests pass (19 selected tests). Only exit-code/fixed booleans are rendered. The eight native Windows runtime tests remain required; a diagnostic improvement is not a runtime fix |
| LiveSafe dependencies and parser | Four clean installs passed. After both parsers gained the explicit limit, all four audits returned zero vulnerabilities, 158 JavaScript files/561 tests passed, Rust format/Clippy/tests passed, and both UI builds passed. CI must additionally build its Docker image |

Commands for the corrected coverage boundaries (use separate output directories
to retain the prior report, and serialize Cargo with two build workers locally):

```bash
cargo tarpaulin --packages exochain-root \
  --include-files 'crates/exo-root/src/**' --out xml --out stdout \
  --output-dir coverage-exo-root --skip-clean --engine llvm \
  --timeout 600 --fail-under 100
cargo tarpaulin --packages exochain-node \
  --test crosschecked_anchor_persistence --out stdout --skip-clean \
  --engine llvm --timeout 900 -- --test-threads=1
```

The second command is a focused instrumentation diagnostic, not a replacement
for Gate 3's full workspace scope or 90% requirement. The LiveSafe regression
uses harmless small in-memory fields, not a resource-exhaustion payload or live
target, and includes the flat-field positive control. The full source remains
subject to the pre-push release-build, workspace-test, Clippy, format, rustdoc,
repository-truth, and category-isolation checks. No new threshold, coverage
exclusion, ignored test, synthetic production implementation, or secret scope
was introduced by this correction set.

The completed local pre-push batch used locked/offline Cargo, the retained
target, two build workers, no incremental/dev/test debug symbols, and no
database or publishing-token environment variables. Release workspace build,
full debug workspace tests, all-target Clippy with warnings denied, nightly
formatting, warning-denied rustdoc, and the native repository-truth guard all
exited zero. ANSI-normalized test logs contain 146 result blocks: 6,620 passed,
zero failed, six ignored. The native macOS list is 6,626, including the same
six documented ignores; this is not native Linux/Windows or final coverage
evidence. Only four known generated exchange reports were removed afterward.

At clean `f59ede255b0fa55d876d2e469b7ed72cf05f86b3`, the focused LLVM
anchor command above completed with all 21 integration tests passing, zero
failures/ignores, and the unchanged 100-concurrent-writer test passing. The
test binary took 5.43 seconds on native macOS. Its integration-only execution
reported 4.12% (1,770/42,938 lines) against Tarpaulin's broad discovered source
set; that percentage is not Gate 3 evidence. The diagnostic imposed no
coverage threshold and does not replace the complete 90% provider gate.
The worktree remained clean after the command, with no test or production
SQLite timeout change.

## Windows PowerShell Child-Environment Correction

At `d521be1e8bb402d2290ca3815a996d87f8592d57`, both native Windows
jobs failed: push job `102308840895` and PR job `102308871710`. The latter
checked out merge `e722bbf7baf1a34da1822c8ee6024d78257d0669` into baseline
`8020ceab355eefa7f5185d9cdd0436da7af46efb`. Each reported two passing and
six failing runtime tests. ACL process diagnostics consistently reported exit
code 1 with stderr, without the CLIXML header or progress marker. This rules
out the previously considered successful-process progress-output case; raw
stderr and private paths were not exposed by the diagnostic.

The runner invokes Cargo under PowerShell 7, and the Rust node invokes legacy
`powershell.exe` through that intermediate process. The child previously
inherited `PSModulePath`. Microsoft documents that this exact launch chain
can make Windows PowerShell load incompatible PowerShell 7 modules, breaking
autoloaded commands such as `Get-Acl`; its prescribed correction is removing
`PSModulePath` from the child environment so native defaults are reconstructed.
See [PowerShell module-path construction](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath?view=powershell-7.6).
This is a source-supported failure mechanism, not a claim that the hidden
native exception has been identified.

The bounded correction removes that one inherited variable only for the two
existing private-file PowerShell children. It changes neither the parent
environment nor the CI shell. Publication uses the same native environment
as ACL inspection; it continues to invoke the existing static .NET methods.
Exclusive sharing, environment-bound literal paths, owner/ACE validation,
nonzero/stderr rejection, and the eight Windows runtime tests are unchanged.
The affected Rust path is an already-classified core runtime adapter; this
record and `RC.md` are already-classified core governance evidence.

Regression and acceptance plan:

1. Add child-environment assertions to the existing portable source guard.
   Against unchanged production code, the exact guard fails on the missing
   ACL child `env_remove`. After the correction, all 19 native macOS/portable
   private-file tests pass with zero failures or ignored tests.
2. Run the normal pre-push release build, workspace tests, all-target Clippy,
   nightly formatting, warning-denied rustdoc, repository truth, and
   cross-implementation comparison using the retained target and two workers.
3. Require all eight native Windows tests to pass on the corrected PR merge,
   together with the full required CI. Local source guards do not establish
   Windows runtime success. If native rejection persists, inspect a fixed,
   non-secret failure category at the failing ACL stage before changing policy.

The existing test is extended rather than adding a counted test, so the
Linux/macOS inventories and 324-path classification digest remain unchanged.

The pre-push batch passed release build, debug workspace tests (146 result
blocks: 6,620 passes, zero failures, six unchanged documented ignores),
all-target Clippy, nightly formatting, warning-denied rustdoc, and native
repository truth. Independent review of the frozen Rust patch
`d09ac8160900d199f4d4ffc8f4f03e70e0be027a7fa01427707ba3a8ac8d8bb0`
found no actionable defect and explicitly withheld native/runtime clearance.

Windows CI no longer waits for the unrelated Linux release build: it consumes
no Linux artifact/output and builds its own target. `all-gates` still requires
both jobs. A YAML structural assertion failed before removal of that scheduling
edge and passed afterward; parsed-workflow comparison proved that deleting
only this `needs: build` was the sole semantic change. Existing reusable-CI,
supply-chain, Python-CI, and cross-platform cache guards all passed. The CI
path is an already-classified core runtime adapter; no gate, test, threshold,
required-check name, or release dependency was removed.

Repeat the scheduling assertion independently of the Windows runtime tests:

```bash
ruby -ryaml -e 'jobs = YAML.load_file(".github/workflows/ci.yml").fetch("jobs"); abort "Windows runtime unnecessarily waits on another job" if jobs.fetch("private-file-windows").key?("needs"); abort "Required gates missing" unless %w[build private-file-windows].all? { |name| jobs.fetch("all-gates").fetch("needs").include?(name) }; puts "Windows independent scheduling and aggregate gates verified"'
```

The cross-implementation script also exited zero: the canonical Rust/Node
hash vector passed 1/1, and two full Rust executions produced identical
normalized test summaries. Its local harness install audited four packages
with zero vulnerabilities. `EXO_TS_ROOT` was unset, and neither the normal
`/Users/bobstewart/dev/exo` sibling nor the worktree-default companion checkout
existed. External TypeScript comparison therefore remains an explicit coverage
gap; the script's successful exit is not evidence for that absent implementation.
Generated vectors and result reports are retained outside the source worktree.

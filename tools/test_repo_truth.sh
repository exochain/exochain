#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Regression checks for the repo-truth generator and the README claims that are
# supposed to be derived from it.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "repo-truth test failed: $*" >&2
  exit 1
}

check_readme_test_inventory() {
  local readme_file="$1"
  local platform="$2"
  local listed="$3"
  local display
  case "$platform" in Linux|macOS) ;; *) return 1 ;; esac
  case "$listed" in ''|*[!0-9]*) return 1 ;; esac
  display=$(python3 -c 'import sys; print(f"{int(sys.argv[1]):,} listed")' "$listed")
  awk -F'|' -v metric="Workspace tests ($platform)" -v expected="$display" '
    /^\|/ {
      label = $2
      value = $3
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", label)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (label ~ /^Workspace tests/ && label != "Workspace tests (Linux)" && label != "Workspace tests (macOS)") invalid = 1
      if (label == metric) {
        rows++
        if (value != expected) invalid = 1
      }
    }
    END { exit (rows != 1 || invalid) }
  ' "$readme_file"
}

if grep -n -- 'grep -oP' tools/repo_truth.sh >/tmp/repo_truth_portability.txt; then
  cat /tmp/repo_truth_portability.txt >&2
  fail "tools/repo_truth.sh must not use grep -P; macOS grep does not support it"
fi

if git grep -nE '^(<<<<<<<|=======|>>>>>>>)( |$)' -- ':!docs/superpowers/**'; then
  fail "tracked files contain unresolved merge conflict markers"
fi

err_file=$(mktemp)
json_file=$(mktemp)
fake_err_file=$(mktemp)
fake_json_file=$(mktemp)
fake_bin_dir=$(mktemp -d)
trap 'rm -f "$err_file" "$json_file" "$fake_err_file" "$fake_json_file" /tmp/repo_truth_portability.txt; rm -rf "$fake_bin_dir"' EXIT

# Exercise the real claim validator with independently specified native counts.
# A global count, swapped platforms, stale count, or duplicate row must fail.
inventory_fixture="$fake_bin_dir/README.md"
printf '%s\n' '| Workspace tests (Linux) | 6,620 listed | cargo |' \
  '| Workspace tests (macOS) | 6,624 listed | cargo |' >"$inventory_fixture"
check_readme_test_inventory "$inventory_fixture" Linux 6620 \
  || fail "Linux inventory fixture rejected"
check_readme_test_inventory "$inventory_fixture" macOS 6624 \
  || fail "macOS inventory fixture rejected"
if check_readme_test_inventory "$inventory_fixture" Linux 6624 \
  || check_readme_test_inventory "$inventory_fixture" macOS 6620 \
  || check_readme_test_inventory "$inventory_fixture" Linux 6619 \
  || check_readme_test_inventory "$inventory_fixture" Windows 6620; then
  fail "inventory validator accepted a wrong platform or count"
fi
printf '%s\n' '| Workspace tests | 6,624 listed | cargo |' >>"$inventory_fixture"
if check_readme_test_inventory "$inventory_fixture" Linux 6620 \
  || check_readme_test_inventory "$inventory_fixture" macOS 6624; then
  fail "inventory validator accepted a global count alongside scoped rows"
fi
printf '%s\n' '| Workspace tests (Linux) | 6,620 listed | cargo |' \
  '| Workspace tests (macOS) | 6,624 listed | cargo |' >"$inventory_fixture"
printf '%s\n' '| Workspace tests (Linux) | 6,620 listed | cargo |' >>"$inventory_fixture"
if check_readme_test_inventory "$inventory_fixture" Linux 6620; then
  fail "inventory validator accepted duplicate platform rows"
fi
printf '%s\n' '| Workspace tests | 6,624 listed | cargo |' >"$inventory_fixture"
if check_readme_test_inventory "$inventory_fixture" Linux 6620 \
  || check_readme_test_inventory "$inventory_fixture" macOS 6624; then
  fail "inventory validator accepted an unscoped global count"
fi

if ! bash tools/repo_truth.sh --json --skip-tests >"$json_file" 2>"$err_file"; then
  cat "$err_file" >&2
  fail "tools/repo_truth.sh --json --skip-tests exited non-zero"
fi

if [ -s "$err_file" ]; then
  cat "$err_file" >&2
  fail "tools/repo_truth.sh --json --skip-tests must not write stderr"
fi

jq -e . "$json_file" >/dev/null

real_cargo=$(command -v cargo)
cat >"$fake_bin_dir/cargo" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = "+nightly" ] && [ "\${2:-}" = "fmt" ]; then
  echo "nightly formatter unavailable"
  echo "rustup formatter error" >&2
  exit 1
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$fake_bin_dir/cargo"

if ! PATH="$fake_bin_dir:$PATH" bash tools/repo_truth.sh --json --skip-tests >"$fake_json_file" 2>"$fake_err_file"; then
  cat "$fake_err_file" >&2
  fail "tools/repo_truth.sh must still emit JSON when formatter check fails"
fi

if [ -s "$fake_err_file" ]; then
  cat "$fake_err_file" >&2
  fail "formatter check output must not leak to stderr in JSON mode"
fi

jq -e . "$fake_json_file" >/dev/null
fake_fmt_clean=$(jq -r '.fmt_clean' "$fake_json_file")
[ "$fake_fmt_clean" = "false" ] || fail "formatter failure should report fmt_clean=false, got $fake_fmt_clean"

expected_crates=$(cargo metadata --no-deps --format-version 1 | jq '.packages | length')
actual_crates=$(jq '.crates' "$json_file")
[ "$actual_crates" = "$expected_crates" ] || fail "crate count $actual_crates != $expected_crates"

expected_rs_files=$(git ls-files 'crates/**/*.rs' | wc -l | tr -d ' ')
actual_rs_files=$(jq '.rust_source_files' "$json_file")
[ "$actual_rs_files" = "$expected_rs_files" ] || fail "Rust source file count $actual_rs_files != $expected_rs_files"

if ! test_list_output=$(cargo test --workspace -- --list 2>&1); then
  printf '%s\n' "$test_list_output" >&2
  fail "cargo test --workspace -- --list failed while deriving README test count"
fi
expected_tests_listed=$(printf '%s\n' "$test_list_output" | grep -c ': test$' | tr -d ' ')

expected_gates=$(grep -E 'name: "Gate [0-9]+' .github/workflows/ci.yml | sed -E 's/.*Gate ([0-9]+).*/\1/' | sort -n | uniq | wc -l | tr -d ' ')
actual_gates=$(jq '.ci_gates.numbered' "$json_file")
[ "$actual_gates" = "$expected_gates" ] || fail "CI gate count $actual_gates != $expected_gates"

workspace_license=$(awk -F '"' '/^license =/ { print $2; exit }' Cargo.toml)
[ "$workspace_license" = "Apache-2.0" ] || fail "workspace license must remain Apache-2.0, got ${workspace_license:-<missing>}"

check_package_license() {
  local package_file="$1"
  local package_license
  package_license=$(jq -r '.license // "<missing>"' "$package_file")
  [ "$package_license" = "$workspace_license" ] \
    || fail "$package_file license must match workspace license $workspace_license, got $package_license"
}

check_package_license_artifact() {
  local package_dir="$1"
  local package_file="$package_dir/package.json"
  local package_license_file="$package_dir/LICENSE"

  [ -f "$package_license_file" ] || fail "$package_license_file is missing from the npm package source"
  cmp -s LICENSE "$package_license_file" \
    || fail "$package_license_file must exactly match the repository Apache-2.0 LICENSE"
  jq -e '.files | index("LICENSE") != null' "$package_file" >/dev/null \
    || fail "$package_file must explicitly include LICENSE in the npm package"
}

check_package_license packages/exochain-sdk/package.json
check_package_license packages/exochain-llm-proxy/package.json
check_package_license packages/exochain-wasm/wasm/package.json
check_package_license demo/packages/exochain-wasm/package.json
check_package_license_artifact packages/exochain-sdk
check_package_license_artifact packages/exochain-llm-proxy

grep -F 'cargo clippy --workspace --all-targets -- -D warnings' .github/workflows/ci.yml >/dev/null \
  || fail "CI clippy gate must cover all workspace targets"
if grep -nE 'cargo clippy --workspace --(lib|bins|tests|benches)' .github/workflows/ci.yml; then
  fail "CI clippy gate must not split target classes; use --all-targets"
fi

grep -F 'unwrap_used = "deny"' Cargo.toml >/dev/null \
  || fail "workspace must deny clippy::unwrap_used instead of warning"
grep -F 'expect_used = "deny"' Cargo.toml >/dev/null \
  || fail "workspace must deny clippy::expect_used instead of warning"

test_mode=$(jq -r '.tests.mode' "$json_file")
[ "$test_mode" = "skipped" ] || fail "--skip-tests should report tests.mode=skipped, got $test_mode"

# ============================================================================
# README VERACITY GATE
#
# Exact release-facing claims must derive from the current tree. Operators can
# opt out locally while resolving a merge, but CI and ordinary runs default to
# enforcing the complete status, architecture, and repository-structure set.
# ============================================================================
README_VERACITY_GATE="${README_VERACITY_GATE:-on}"

if [ "$README_VERACITY_GATE" = "on" ]; then
  grep -F "| Rust crates | $expected_crates |" README.md >/dev/null || fail "README crate count is not repo-truth derived"
  grep -F "| Rust source files | $expected_rs_files |" README.md >/dev/null || fail "README Rust source file count is not repo-truth derived"
  case "$(uname -s)" in
    Linux) inventory_platform=Linux ;;
    Darwin) inventory_platform=macOS ;;
    *) fail "README workspace test inventory is not defined for this host" ;;
  esac
  check_readme_test_inventory README.md "$inventory_platform" "$expected_tests_listed" \
    || fail "README $inventory_platform workspace test inventory does not match $expected_tests_listed listed tests"
  grep -F "| CI quality gates | $expected_gates |" README.md >/dev/null || fail "README CI gate count is not repo-truth derived"

  grep -F '**Workspace test inventories are platform-specific**' README.md >/dev/null \
    || fail "README must scope its listed test inventories to their platforms"
  grep -F "(Rust, $expected_crates crates)" README.md >/dev/null \
    || fail "README architecture crate count is not repo-truth derived"
  grep -F 'platform-specific listed workspace tests' README.md >/dev/null \
    || fail "README architecture must refer to platform-specific test inventories"
  grep -F "CI pipeline ($expected_gates numbered quality gates plus required aggregator)" README.md >/dev/null \
    || fail "README repository-structure gate count is not repo-truth derived"
  grep -F "**$expected_gates numbered CI quality gates** plus the required \"All Constitutional Gates\" aggregator are defined; workflow runs report their status, while merge enforcement depends on current GitHub ruleset or branch-protection settings" README.md >/dev/null \
    || fail "README must separate defined CI gates from GitHub merge enforcement"
  if grep -F "defined and enforced" README.md >/dev/null; then
    fail "README must not infer GitHub merge enforcement from workflow source"
  fi
  grep -F "Quality Gates](governance/quality_gates.md) — $expected_gates numbered CI gates plus required aggregator" README.md >/dev/null \
    || fail "README governance-link gate count is not repo-truth derived"

  expected_rest_routes=$(
    sed -n '/fn test_all_routes/,/^[[:space:]]*}/p' crates/exo-gateway/src/rest.rs \
      | sed -nE 's/.*assert_eq!\(routes\.len\(\), ([0-9]+)\);.*/\1/p'
  )
  [ -n "$expected_rest_routes" ] || fail "could not derive REST route inventory count"
  grep -F "operational HTTP server with $expected_rest_routes endpoints" README.md >/dev/null \
    || fail "README gateway endpoint count is not route-inventory derived"
  grep -F "health probes ($expected_rest_routes enumerated REST endpoints plus GraphQL)" README.md >/dev/null \
    || fail "README core-crate gateway endpoint count is not route-inventory derived"

  core_crate_rows=$(
    awk '
      /^### Core Crates/ { in_core = 1; next }
      in_core && /^### / { print count; exit }
      in_core && /^\| `/ { count++ }
    ' README.md
  )
  grep -F "### Core Crates ($core_crate_rows)" README.md >/dev/null \
    || fail "README Core Crates heading does not match its table"
fi

trace_total=$(jq '.traceability.total' "$json_file")
trace_implemented=$(jq '.traceability.implemented' "$json_file")
trace_partial=$(jq '.traceability.partial' "$json_file")
trace_planned=$(jq '.traceability.planned' "$json_file")
threat_total=$(jq '.threats.total' "$json_file")
threat_implemented=$(jq '.threats.mitigated' "$json_file")
threat_partial=$(jq '.threats.partial' "$json_file")
threat_planned=$(jq '.threats.planned' "$json_file")
tag_count=$(jq '.releases.tag_count' "$json_file")

if [ "$README_VERACITY_GATE" = "on" ]; then
  grep -F "**Traceability matrix** maps $trace_total requirements" README.md >/dev/null \
    || fail "README traceability count is not repo-truth derived"

  grep -F "**Threat model** covers $threat_total threats tracked: $threat_implemented implemented, $threat_partial partial, $threat_planned planned" README.md >/dev/null \
    || fail "README threat count/status is not repo-truth derived"
fi

if [ "$tag_count" -gt 0 ]; then
  if grep -F "| Published releases | None (pre-release) | \`git tag -l\` |" README.md >/dev/null; then
    fail "README must not cite git tags as evidence for no published releases when tags exist"
  fi
  latest_release_tag=$(git tag -l 'v*' --sort=-version:refname | head -1)
  grep -F "| Latest published release | \`$latest_release_tag\`" README.md >/dev/null \
    || fail "README latest published release does not match the newest version tag"
fi

if grep -F "No GitHub Release or crates.io publication verified" README.md >/dev/null; then
  fail "README contains the stale no-publication claim"
fi

grep -F "| Live node health | Not inferred from repository state; verify each target at deploy or release time |" README.md >/dev/null \
  || fail "README must keep live node health separate from repository truth"

grep -F "tested gatekeeper and decision-forum adjudication paths" README.md >/dev/null \
  || fail "README must scope constitutional invariant enforcement to tested adjudication paths"

grep -F "Scoped 90% coverage threshold" README.md >/dev/null \
  || fail "README must present coverage as scoped coverage"

if grep -n "under constitutional authority" README.md; then
  fail "README must not grant adjacent CommandBase constitutional authority by proximity"
fi

if grep -nE 'Autonomous implementation engine|Core Crates \(16\)|16 crates|1,846 tests|1,603 workspace tests' README.md; then
  fail "README contains stale Basalt truth claims"
fi

echo "repo-truth test passed"

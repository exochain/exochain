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

set -euo pipefail

fail() {
  printf 'release publish boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/release.yml"
[[ -f "$workflow" ]] || fail "$workflow is missing"

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
}

publish_block=$(job_block "publish")
wasm_publish_block=$(job_block "publish-wasm-npm")
llm_proxy_publish_block=$(job_block "publish-llm-proxy-npm")
github_release_block=$(job_block "github-release")

[[ -n "$publish_block" ]] || fail "publish job is missing"
[[ -n "$wasm_publish_block" ]] || fail "publish-wasm-npm job is missing"
[[ -n "$llm_proxy_publish_block" ]] || fail "publish-llm-proxy-npm job is missing"
[[ -n "$github_release_block" ]] || fail "github-release job is missing"

grep -F 'if: ${{ !inputs.dry_run }}' <<<"$publish_block" >/dev/null \
  || fail "publish job must be skipped for dry-run releases"
grep -F 'if: ${{ !inputs.dry_run }}' <<<"$github_release_block" >/dev/null \
  || fail "github-release job must be skipped for dry-run releases"
grep -F 'if: ${{ !inputs.dry_run }}' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must guard the npm publish step for dry-run releases"
grep -F 'if: ${{ !inputs.dry_run }}' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must guard the npm publish step for dry-run releases"

grep -F 'CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}' <<<"$publish_block" >/dev/null \
  || fail "publish job must use the crates.io registry token"
grep -F 'RELEASE_VERSION: ${{ needs.validate-release-inputs.outputs.version }}' <<<"$publish_block" >/dev/null \
  || fail "publish job must bind crates.io checks to the validated release version"
grep -F 'crate_version_published()' <<<"$publish_block" >/dev/null \
  || fail "publish job must support resumable partial publication checks"
grep -F 'https://crates.io/api/v1/crates/${crate}/${RELEASE_VERSION}' <<<"$publish_block" >/dev/null \
  || fail "publish job must check whether each crate version already exists on crates.io"
grep -F "User-Agent: exochain-release-workflow (https://github.com/exochain/exochain)" <<<"$publish_block" >/dev/null \
  || fail "publish job must identify itself to crates.io version checks"
grep -F 'if crate_version_published "$crate"; then' <<<"$publish_block" >/dev/null \
  || fail "publish job must skip crate versions already published by a prior partial release"
grep -F 'status 429 Too Many Requests' <<<"$publish_block" >/dev/null \
  || fail "publish job must classify crates.io rate-limit responses"
grep -F 'try again after' <<<"$publish_block" >/dev/null \
  || fail "publish job must parse crates.io retry-after evidence"
grep -F 'sleep "$retry_seconds"' <<<"$publish_block" >/dev/null \
  || fail "publish job must wait before retrying crates.io rate-limited publishes"
grep -F 'cargo publish -p "$crate" --locked' <<<"$publish_block" >/dev/null \
  || fail "publish job must publish every crate without refreshing the lockfile"
grep -F 'cargo publish -p "$crate" --dry-run --locked' <<<"$publish_block" >/dev/null \
  || fail "publish job must dry-run every crate without refreshing the lockfile"
if grep -F -- '--allow-dirty' <<<"$publish_block" >/dev/null; then
  fail "signed-source-bound cargo publication must not bypass Cargo's dirty-source rejection"
fi

git_control_scrub='unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR'
immutable_guard='/usr/bin/git -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_release_side_effect.sh" | BASH_ENV=/dev/null /bin/bash --noprofile --norc -p'

live_guard_line=$(grep -nF "$immutable_guard" <<<"$publish_block" | head -n 1 | cut -d: -f1 || true)
live_publish_line=$(grep -nF 'cargo publish -p "$crate" --locked' <<<"$publish_block" | head -n 1 | cut -d: -f1)
[[ -n "$live_guard_line" ]] || fail "each live cargo publish retry must reverify source and tag identity"
if [ "$live_guard_line" -ge "$live_publish_line" ]; then
  fail "live cargo publish must reverify source and tag before every attempt"
fi
live_between=""
if [ "$live_publish_line" -gt "$((live_guard_line + 1))" ]; then
  live_between=$(sed -n "$((live_guard_line + 1)),$((live_publish_line - 1))p" <<<"$publish_block")
fi
if grep -E 'cargo (publish|package)' <<<"$live_between" >/dev/null; then
  fail "no cargo artifact side effect may occur between live revalidation and publish"
fi

dry_guard_line=$(grep -nF "$immutable_guard" <<<"$publish_block" | tail -n 1 | cut -d: -f1 || true)
dry_publish_line=$(grep -nF 'cargo publish -p "$crate" --dry-run --locked' <<<"$publish_block" | head -n 1 | cut -d: -f1)
[[ -n "$dry_guard_line" ]] || fail "each cargo publish dry-run must reverify source and tag identity"
if [ "$dry_guard_line" -ge "$dry_publish_line" ]; then
  fail "cargo publish dry-run must reverify source and tag before packaging"
fi
dry_between=""
if [ "$dry_publish_line" -gt "$((dry_guard_line + 1))" ]; then
  dry_between=$(sed -n "$((dry_guard_line + 1)),$((dry_publish_line - 1))p" <<<"$publish_block")
fi
if grep -E 'cargo (publish|package)' <<<"$dry_between" >/dev/null; then
  fail "no cargo artifact side effect may occur between dry-run revalidation and packaging"
fi
grep -F 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm job must use the npm automation token"
grep -F 'name: Verify npm registry authentication' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must verify npm registry authentication before building the package"
grep -F 'npm ping --registry=https://registry.npmjs.org' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must verify npm registry reachability before publishing"
grep -F 'npm whoami --registry=https://registry.npmjs.org' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must verify npm token identity before publishing"
if grep -F 'npm org ls exochain' <<<"$wasm_publish_block" >/dev/null; then
  fail "publish-wasm-npm must not use npm org membership endpoints as publish preflight"
fi
grep -F 'npm_package_version_published()' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must support resumable npm package publication checks"
grep -F 'npm view "@exochain/exochain-wasm@${RELEASE_VERSION}" version --registry=https://registry.npmjs.org' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must check whether the WASM npm package version already exists"
grep -F '@exochain/exochain-wasm ${RELEASE_VERSION} is already published; skipping npm publish.' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must skip already-published WASM npm package versions"
grep -F 'npm publish --access public --provenance' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must publish the public package with npm provenance"
grep -F "$immutable_guard" <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must reverify tracked source and live tag immediately before npm publish"
grep -F 'npm pack --dry-run' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must dry-pack before publish"
grep -F 'manifest.version !== process.env.RELEASE_VERSION' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must bind package version to the validated release version"
grep -F 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm job must use the npm automation token"
grep -F 'name: Verify npm registry authentication' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must verify npm registry authentication before package checks"
grep -F 'npm ping --registry=https://registry.npmjs.org' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must verify npm registry reachability before publishing"
grep -F 'npm whoami --registry=https://registry.npmjs.org' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must verify npm token identity before publishing"
grep -F 'npm run test:coverage' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must run the LYNK package coverage gate"
grep -F 'npm run build' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must build the package after a final identity check"
grep -F 'node scripts/check-package-artifacts.mjs' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must verify built package artifacts"
grep -F 'npm pack --dry-run' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must dry-pack after a separate final identity check"
grep -F 'npm_package_version_published()' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must support resumable npm package publication checks"
grep -F 'npm view "@exochain/llm-proxy@${RELEASE_VERSION}" version --registry=https://registry.npmjs.org' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must check whether the LYNK npm package version already exists"
grep -F '@exochain/llm-proxy ${RELEASE_VERSION} is already published; skipping npm publish.' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must skip already-published LYNK npm package versions"
grep -F 'npm publish --access public --provenance' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must publish the public package with npm provenance"
grep -F "$immutable_guard" <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must reverify source and live tag immediately before npm publish"
grep -F 'manifest.version !== process.env.RELEASE_VERSION' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must bind package version to the validated release version"

assert_inline_guard_before_publish() {
  local job="$1"
  local block="$2"
  local guard_pattern="$3"
  local guard_line
  local publish_line
  local between
  guard_line=$(grep -nF "$guard_pattern" <<<"$block" | tail -n 1 | cut -d: -f1 || true)
  publish_line=$(grep -nF 'npm publish --access public --provenance' <<<"$block" | tail -n 1 | cut -d: -f1)
  [[ -n "$guard_line" ]] || fail "$job must execute its final guard from the immutable dispatch commit"
  if [ "$guard_line" -ge "$publish_line" ]; then
    fail "$job must reverify source and tag before npm publish"
  fi
  between=""
  if [ "$publish_line" -gt "$((guard_line + 1))" ]; then
    between=$(sed -n "$((guard_line + 1)),$((publish_line - 1))p" <<<"$block")
  fi
  if grep -E '^[[:space:]]*(npm|npx|cargo|wasm-pack)[[:space:]]' <<<"$between" >/dev/null; then
    fail "$job must perform no package side effect between final revalidation and npm publish"
  fi
}

assert_inline_guard_before_publish publish-wasm-npm "$wasm_publish_block" \
  "$immutable_guard"
assert_inline_guard_before_publish publish-llm-proxy-npm "$llm_proxy_publish_block" \
  "$immutable_guard"

named_step_block() {
  local block="$1"
  local step_name="$2"
  awk -v step="      - name: ${step_name}" '
    $0 == step { capture = 1; print; next }
    capture && $0 ~ /^      - (name:|uses:)/ { exit }
    capture { print }
  ' <<<"$block"
}

assert_publish_step_rebinds_guard_inputs() {
  local job="$1"
  local block="$2"
  local step_name="$3"
  local clean_mode="$4"
  local step
  step=$(named_step_block "$block" "$step_name")
  [[ -n "$step" ]] || fail "$job is missing step $step_name"

  # GITHUB_ENV is mutable across steps. Every publishing step must therefore
  # override all guard inputs at step scope, including BASH_ENV before bash
  # startup, instead of inheriting values that a prior action could poison.
  for binding in \
    'BASH_ENV: /dev/null' \
    "RELEASE_SOURCE_CLEAN_MODE: $clean_mode" \
    'DRY_RUN: ${{ inputs.dry_run }}' \
    'RELEASE_TAG: ${{ needs.validate-release-inputs.outputs.tag }}' \
    'EXPECTED_TAG_OBJECT_SHA: ${{ needs.verify-signed-tag.outputs.tag_object_sha }}' \
    'EXPECTED_TAG_COMMIT_SHA: ${{ needs.verify-signed-tag.outputs.tag_commit_sha }}' \
    'EXPECTED_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}' \
    'TRUSTED_RELEASE_REF: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' \
    'RELEASE_GITHUB_TOKEN: ${{ github.token }}'; do
    grep -F "$binding" <<<"$step" >/dev/null \
      || fail "$job step $step_name must rebind $binding at step scope"
  done
  grep -F "$immutable_guard" <<<"$step" >/dev/null \
    || fail "$job step $step_name must execute the final guard from the immutable dispatch commit"
  grep -F "$git_control_scrub" <<<"$step" >/dev/null \
    || fail "$job step $step_name must scrub persisted Git controls before the immutable guard"
  grep -F 'export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1' <<<"$step" >/dev/null \
    || fail "$job step $step_name must isolate Git from inherited global and system configuration"
}

assert_publish_step_rebinds_guard_inputs publish "$publish_block" \
  "Publish crates in dependency order" all
assert_publish_step_rebinds_guard_inputs publish-wasm-npm "$wasm_publish_block" \
  "Publish WASM npm package" tracked
assert_publish_step_rebinds_guard_inputs publish-llm-proxy-npm "$llm_proxy_publish_block" \
  "Publish LYNK npm package" all

if grep -E 'cargo publish.*\|\|' <<<"$publish_block" >/dev/null; then
  fail "cargo publish failures must fail the publish job"
fi

grep -E 'needs:.*publish' <<<"$github_release_block" >/dev/null \
  || fail "github-release must depend on successful crates.io publication"
grep -E 'needs:.*publish-wasm-npm' <<<"$github_release_block" >/dev/null \
  || fail "github-release must depend on successful WASM npm package verification/publication"
grep -E 'needs:.*publish-llm-proxy-npm' <<<"$github_release_block" >/dev/null \
  || fail "github-release must depend on successful LYNK npm package verification/publication"

printf 'release publish boundary test passed\n'

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
grep -F 'cargo publish -p "$crate" --allow-dirty' <<<"$publish_block" >/dev/null \
  || fail "publish job must publish every crate in the dependency-ordered loop"
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
grep -F 'npm run pack:dry-run' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must dry-pack before publish"
grep -F 'npm_package_version_published()' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must support resumable npm package publication checks"
grep -F 'npm view "@exochain/llm-proxy@${RELEASE_VERSION}" version --registry=https://registry.npmjs.org' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must check whether the LYNK npm package version already exists"
grep -F '@exochain/llm-proxy ${RELEASE_VERSION} is already published; skipping npm publish.' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must skip already-published LYNK npm package versions"
grep -F 'npm publish --access public --provenance' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must publish the public package with npm provenance"
grep -F 'manifest.version !== process.env.RELEASE_VERSION' <<<"$llm_proxy_publish_block" >/dev/null \
  || fail "publish-llm-proxy-npm must bind package version to the validated release version"

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

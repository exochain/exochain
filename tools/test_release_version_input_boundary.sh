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
  printf 'release version input boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/release.yml"
ci_workflow=".github/workflows/ci.yml"

[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$ci_workflow" ]] || fail "$ci_workflow is missing"

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
}

validate_block=$(job_block "validate-release-inputs")
[[ -n "$validate_block" ]] || fail "release workflow must validate dispatch inputs before release jobs"

grep -F 'version: ${{ steps.validate.outputs.version }}' <<<"$validate_block" >/dev/null \
  || fail "validated release version must be exposed as a job output"
grep -F 'tag: ${{ steps.validate.outputs.tag }}' <<<"$validate_block" >/dev/null \
  || fail "validated release tag must be exposed as a job output"
grep -F 'commit_sha: ${{ steps.validate.outputs.commit_sha }}' <<<"$validate_block" >/dev/null \
  || fail "validated release commit SHA must be exposed as a job output"
grep -F 'trusted_ref: ${{ steps.validate.outputs.trusted_ref }}' <<<"$validate_block" >/dev/null \
  || fail "validated immutable checkout ref must be exposed as a job output"
grep -F 'id: validate' <<<"$validate_block" >/dev/null \
  || fail "validation job must have a stable validate step id"
grep -F 'ref: ${{ github.sha }}' <<<"$validate_block" >/dev/null \
  || fail "validation job must check out the workflow dispatch SHA"
grep -F 'RELEASE_VERSION_INPUT: ${{ inputs.version }}' <<<"$validate_block" >/dev/null \
  || fail "raw dispatch version may only enter the validation step through an environment variable"
grep -E '\^\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+\(-\[0-9A-Za-z\]' <<<"$validate_block" >/dev/null \
  || fail "release version validator must reject anything outside the bounded semver subset"
grep -F 'printf '\''version=%s\n'\'' "$version" >> "$GITHUB_OUTPUT"' <<<"$validate_block" >/dev/null \
  || fail "validation step must write the sanitized version to GITHUB_OUTPUT"
grep -F 'printf '\''tag=v%s\n'\'' "$version" >> "$GITHUB_OUTPUT"' <<<"$validate_block" >/dev/null \
  || fail "validation step must derive the release tag from the sanitized version"
grep -F 'head_sha="$(git rev-parse HEAD)"' <<<"$validate_block" >/dev/null \
  || fail "validation step must resolve checked-out HEAD"
grep -F 'EXPECTED_COMMIT_SHA: ${{ github.sha }}' <<<"$validate_block" >/dev/null \
  || fail "validation step must pass the workflow SHA as its expected commit"
grep -F 'TRUSTED_RELEASE_REF: ${{ github.sha }}' <<<"$validate_block" >/dev/null \
  || fail "validation step must pass the workflow SHA as its trusted ref"
grep -F '/bin/bash --noprofile --norc -p tools/verify_release_source.sh' <<<"$validate_block" >/dev/null \
  || fail "validation step must execute the shared source-identity guard"
grep -F 'RELEASE_VERSION_EXPECTED="$version" bash tools/test_release_version_alignment.sh' <<<"$validate_block" >/dev/null \
  || fail "validation step must bind every release manifest to the sanitized input version"
grep -F 'printf '\''commit_sha=%s\n'\'' "$head_sha" >> "$GITHUB_OUTPUT"' <<<"$validate_block" >/dev/null \
  || fail "validation step must emit the verified checkout commit"
grep -F 'printf '\''trusted_ref=%s\n'\'' "$head_sha" >> "$GITHUB_OUTPUT"' <<<"$validate_block" >/dev/null \
  || fail "validation step must emit an immutable commit SHA as the trusted ref"

raw_version_refs=$(grep -nF '${{ inputs.version }}' "$workflow" || true)
raw_version_count=$(printf '%s\n' "$raw_version_refs" | sed '/^$/d' | wc -l | tr -d ' ')
if [ "$raw_version_count" -ne 1 ]; then
  printf '%s\n' "$raw_version_refs" >&2
  fail "raw inputs.version must appear exactly once, inside validate-release-inputs"
fi
case "$raw_version_refs" in
  *'RELEASE_VERSION_INPUT: ${{ inputs.version }}'*) ;;
  *) fail "the only raw inputs.version reference must be the validation step environment binding" ;;
esac

grep -F '${{ needs.validate-release-inputs.outputs.version }}' "$workflow" >/dev/null \
  || fail "release jobs must consume the sanitized version output"
grep -F '${{ needs.validate-release-inputs.outputs.tag }}' "$workflow" >/dev/null \
  || fail "release jobs must consume the sanitized tag output"

for job in \
  approve approve-second verify-signed-tag release-build package-release \
  install-cargo-cyclonedx generate-sbom validate-sbom attest-release \
  preflight-crates reproduce-crates publish install-wasm-pack build-wasm-npm \
  prepare-wasm-npm test-llm-proxy-npm prepare-llm-proxy-npm \
  publish-wasm-npm publish-llm-proxy-npm github-release; do
  block=$(job_block "$job")
  [[ -n "$block" ]] || fail "job $job is missing"
  grep -F 'validate-release-inputs' <<<"$block" >/dev/null \
    || fail "job $job must depend on the release input validation job"
done

for job in approve approve-second; do
  block=$(job_block "$job")
  grep -F 'RELEASE_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the validated commit SHA"
  grep -F 'TRUSTED_RELEASE_REF: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the validated trusted ref"
done

grep -F 'bash tools/test_release_version_input_boundary.sh' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the release version input boundary guard"

printf 'release version input boundary test passed\n'

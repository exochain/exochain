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
  printf 'release dry-run boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/release.yml"
versioning="VERSIONING.md"
[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$versioning" ]] || fail "$versioning is missing"
versioning_text="$(tr '\n' ' ' < "$versioning")"

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
}

assert_non_dry_run_job() {
  local job="$1"
  local block="$2"
  grep -F 'if: ${{ !inputs.dry_run }}' <<<"$block" >/dev/null \
    || fail "job $job must be skipped for dry-run releases"
}

for job in sbom-and-attest github-release; do
  block=$(job_block "$job")
  [[ -n "$block" ]] || fail "job $job is missing"
  assert_non_dry_run_job "$job" "$block"
done

sbom_block=$(job_block "sbom-and-attest")
github_release_block=$(job_block "github-release")
wasm_publish_block=$(job_block "publish-wasm-npm")
verify_tag_block=$(job_block "verify-signed-tag")

grep -F 'attestations: write' <<<"$sbom_block" >/dev/null \
  || fail "sbom-and-attest must remain the only attestation-writing job"
grep -F 'actions/attest-build-provenance@' <<<"$sbom_block" >/dev/null \
  || fail "sbom-and-attest must remain the SLSA attestation job"
grep -F 'contents: write' <<<"$github_release_block" >/dev/null \
  || fail "github-release must retain release publishing permission for real releases"
grep -F 'softprops/action-gh-release@' <<<"$github_release_block" >/dev/null \
  || fail "github-release must remain the GitHub Release job for real releases"
grep -F 'npm pack --dry-run' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must dry-pack the WASM package"
grep -F 'if: ${{ !inputs.dry_run }}' <<<"$wasm_publish_block" >/dev/null \
  || fail "publish-wasm-npm must guard npm publish for dry-run releases"
grep -F 'printf '\''tag_object_sha=\n'\'' >> "$GITHUB_OUTPUT"' <<<"$verify_tag_block" >/dev/null \
  || fail "dry-run verification must emit no signed-tag object identity"
grep -F 'printf '\''tag_commit_sha=\n'\'' >> "$GITHUB_OUTPUT"' <<<"$verify_tag_block" >/dev/null \
  || fail "dry-run verification must emit no signed-tag commit identity"

if grep -F 'draft: ${{ inputs.dry_run }}' "$workflow" >/dev/null; then
  fail "dry-run releases must not create draft GitHub Releases"
fi

if grep -F 'approved by maintainer' "$workflow" >/dev/null; then
  fail "workflow source must not claim a maintainer approval supplied by repository settings"
fi
grep -Fi 'repository settings determine whether approval is required' "$workflow" >/dev/null \
  || fail "release workflow must distinguish its environment gate from configured approval"

grep -F 'does not create a GitHub Release' <<<"$versioning_text" >/dev/null \
  || fail "VERSIONING.md must state that dry runs do not create GitHub Releases"
grep -F 'still traverses the `release` environment' <<<"$versioning_text" >/dev/null \
  || fail "VERSIONING.md must state that dry runs traverse the release environment"
grep -F 'Only one configured required reviewer needs to approve' <<<"$versioning_text" >/dev/null \
  || fail "VERSIONING.md must document GitHub's one-of required-reviewer semantics"
if grep -F 'The GitHub Release is created as a draft for review.' <<<"$versioning_text" >/dev/null; then
  fail "VERSIONING.md must not claim that a dry run creates a draft release"
fi

printf 'release dry-run boundary test passed\n'

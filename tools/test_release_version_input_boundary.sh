#!/usr/bin/env bash
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
grep -F 'id: validate' <<<"$validate_block" >/dev/null \
  || fail "validation job must have a stable validate step id"
grep -F 'RELEASE_VERSION_INPUT: ${{ inputs.version }}' <<<"$validate_block" >/dev/null \
  || fail "raw dispatch version may only enter the validation step through an environment variable"
grep -E '\^\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+\(-\[0-9A-Za-z\]' <<<"$validate_block" >/dev/null \
  || fail "release version validator must reject anything outside the bounded semver subset"
grep -F 'printf '\''version=%s\n'\'' "$version" >> "$GITHUB_OUTPUT"' <<<"$validate_block" >/dev/null \
  || fail "validation step must write the sanitized version to GITHUB_OUTPUT"
grep -F 'printf '\''tag=v%s\n'\'' "$version" >> "$GITHUB_OUTPUT"' <<<"$validate_block" >/dev/null \
  || fail "validation step must derive the release tag from the sanitized version"

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

for job in approve verify-signed-tag release-build sbom-and-attest publish github-release; do
  block=$(job_block "$job")
  [[ -n "$block" ]] || fail "job $job is missing"
  grep -F 'validate-release-inputs' <<<"$block" >/dev/null \
    || fail "job $job must depend on the release input validation job"
done

grep -F 'bash tools/test_release_version_input_boundary.sh' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the release version input boundary guard"

printf 'release version input boundary test passed\n'

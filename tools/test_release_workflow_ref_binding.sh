#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'release workflow ref-binding test failed: %s\n' "$1" >&2
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

for job in release-build sbom-and-attest publish; do
  block=$(job_block "$job")
  [[ -n "$block" ]] || fail "job $job is missing"
  grep -F 'id: release-ref' <<<"$block" >/dev/null \
    || fail "job $job must resolve the release source ref before checkout"
  grep -F 'RELEASE_TAG: ${{ needs.validate-release-inputs.outputs.tag }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the validated release tag"
  grep -F 'printf '\''ref=refs/tags/%s\n'\'' "$RELEASE_TAG" >> "$GITHUB_OUTPUT"' <<<"$block" >/dev/null \
    || fail "job $job must use the signed validated tag for non-dry-run releases"
  grep -F '${GITHUB_SHA}' <<<"$block" >/dev/null \
    || fail "job $job must keep dry-run builds anchored to the dispatched workflow SHA"
  grep -F 'ref: ${{ steps.release-ref.outputs.ref }}' <<<"$block" >/dev/null \
    || fail "job $job checkout must use the resolved release source ref"
done

printf 'release workflow ref-binding test passed\n'

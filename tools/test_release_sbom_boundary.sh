#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release SBOM boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=.github/workflows/release.yml
ci_workflow=.github/workflows/ci.yml
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

install_block="$(job_block install-cargo-cyclonedx)"
generate_block="$(job_block generate-sbom)"
validate_block="$(job_block validate-sbom)"
attest_block="$(job_block attest-release)"
for specification in \
  "install-cargo-cyclonedx:$install_block" \
  "generate-sbom:$generate_block" \
  "validate-sbom:$validate_block" \
  "attest-release:$attest_block"; do
  [ -n "${specification#*:}" ] || fail "job ${specification%%:*} is missing"
done

grep -F 'permissions: {}' <<<"$install_block" >/dev/null \
  || fail "cargo-cyclonedx installer must have no GitHub permissions"
if grep -F 'actions/checkout@' <<<"$install_block" >/dev/null \
  || grep -F 'github.token' <<<"$install_block" >/dev/null; then
  fail "cargo-cyclonedx installer must not receive repository source or token"
fi
grep -F '"$cargo_path" install cargo-cyclonedx --version 0.5.9 --locked' <<<"$install_block" >/dev/null \
  || fail "cargo-cyclonedx installation must pin 0.5.9 and its lockfile"
grep -F '"$cargo_path" cyclonedx --version)' <<<"$install_block" >/dev/null \
  && grep -F 'cargo-cyclonedx-cyclonedx 0.5.9' <<<"$install_block" >/dev/null \
  || fail "installer must validate the exact cargo plugin-form version"
grep -F 'archive_sha256: ${{ steps.seal-tool.outputs.archive_sha256 }}' <<<"$install_block" >/dev/null \
  || fail "isolated tool bytes need an independently carried digest"

grep -F 'runs-on: ubuntu-24.04' <<<"$generate_block" >/dev/null \
  || fail "SBOM producer must share the pinned Ubuntu ABI with its tool producer"
grep -F 'RELEASE_EXPECTED_TOOL_SHA256: ${{ needs.install-cargo-cyclonedx.outputs.archive_sha256 }}' <<<"$generate_block" >/dev/null \
  || fail "SBOM producer must bind downloaded tool bytes to the installer output"
grep -F -- '--profile cargo-cyclonedx --version 0.5.9' <<<"$generate_block" >/dev/null \
  && grep -F -- '--expected-sha256 "$RELEASE_EXPECTED_TOOL_SHA256"' <<<"$generate_block" >/dev/null \
  || fail "SBOM producer must strict-extract the exact cargo-cyclonedx transport"
grep -F 'SOURCE_DATE_EPOCH=0 release_cargo "$cargo_path" cyclonedx' <<<"$generate_block" >/dev/null \
  && grep -F -- '-f json --all --target all --spec-version 1.5' <<<"$generate_block" >/dev/null \
  || fail "SBOM generation must be deterministic CycloneDX 1.5 target-all output"
if grep -E 'cyclonedx .*--locked' <<<"$generate_block" >/dev/null; then
  fail "cargo-cyclonedx generation must not receive unsupported --locked"
fi
grep -F 'raw_sbom_sha256: ${{ steps.generate-raw-sbom.outputs.raw_sbom_sha256 }}' <<<"$generate_block" >/dev/null \
  && grep -F -- '--profile raw-sbom --version "$RELEASE_VERSION"' <<<"$generate_block" >/dev/null \
  || fail "raw SBOM bytes must cross jobs only through strict transport"

grep -F 'needs: [generate-sbom, verify-signed-tag, validate-release-inputs]' <<<"$validate_block" >/dev/null \
  || fail "canonical SBOM validation must run as a fresh downstream job"
grep -F 'RELEASE_EXPECTED_RAW_SHA256: ${{ needs.generate-sbom.outputs.raw_sbom_sha256 }}' <<<"$validate_block" >/dev/null \
  && grep -F -- '--profile raw-sbom --version "$RELEASE_VERSION"' <<<"$validate_block" >/dev/null \
  && grep -F -- '--expected-sha256 "$RELEASE_EXPECTED_RAW_SHA256"' <<<"$validate_block" >/dev/null \
  || fail "validator must bind raw transport to its independent producer digest"
grep -F '"$cargo_path" metadata --manifest-path "$GITHUB_WORKSPACE/Cargo.toml"' <<<"$validate_block" >/dev/null \
  && grep -F -- '--format-version 1 --locked > "$RELEASE_METADATA"' <<<"$validate_block" >/dev/null \
  || fail "validator must derive exact locked Cargo metadata on its fresh runner"
for binding in \
  '--cargo-metadata "$RELEASE_METADATA"' \
  '--cargo-lock "$GITHUB_WORKSPACE/Cargo.lock"' \
  '--forbid-prefix "$GITHUB_WORKSPACE"' \
  '--forbid-prefix "$RUNNER_TEMP"'; do
  grep -F -- "$binding" <<<"$validate_block" >/dev/null \
    || fail "canonical SBOM validator is missing $binding"
done
grep -F 'path: ${{ runner.temp }}/exochain-sbom-validation/final/exochain-${{ needs.validate-release-inputs.outputs.version }}-*.cdx.json' <<<"$validate_block" >/dev/null \
  || fail "only canonical versioned SBOM files may be uploaded"

grep -F 'needs: [package-release, validate-sbom, verify-signed-tag, validate-release-inputs]' <<<"$attest_block" >/dev/null \
  || fail "attestation must depend on fresh canonical SBOM validation"
grep -F 'attestations: write' <<<"$attest_block" >/dev/null \
  && grep -F 'id-token: write' <<<"$attest_block" >/dev/null \
  && grep -F 'actions/attest-build-provenance@96b4a1ef7235a096b17240c259729fdd70c83d45' <<<"$attest_block" >/dev/null \
  || fail "fresh attestation job must use the pinned OIDC provenance action"
if grep -E 'cargo (install|cyclonedx|build)|wasm-pack|npm (ci|run|pack)' <<<"$attest_block" >/dev/null; then
  fail "attestation authority must not run a repository lifecycle"
fi

grep -F 'bash tools/test_release_sbom_boundary.sh' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the release SBOM boundary guard"

printf 'release SBOM boundary test passed\n'

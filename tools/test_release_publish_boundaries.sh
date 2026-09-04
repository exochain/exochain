#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release publish boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=.github/workflows/release.yml
crate_publisher=tools/publish_release_crates.sh
npm_publisher=tools/publish_release_npm_package.sh
for file in "$workflow" "$crate_publisher" "$npm_publisher"; do
  [ -f "$file" ] || fail "$file is missing"
done

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
}

reproduce_block="$(job_block reproduce-crates)"
publish_block="$(job_block publish)"
wasm_block="$(job_block publish-wasm-npm)"
llm_block="$(job_block publish-llm-proxy-npm)"
github_block="$(job_block github-release)"
for specification in \
  "reproduce-crates:$reproduce_block" "publish:$publish_block" \
  "publish-wasm-npm:$wasm_block" "publish-llm-proxy-npm:$llm_block" \
  "github-release:$github_block"; do
  [ -n "${specification#*:}" ] || fail "job ${specification%%:*} is missing"
done

for block in "$reproduce_block" "$publish_block" "$wasm_block" "$llm_block" "$github_block"; do
  grep -F 'if: ${{ !inputs.dry_run }}' <<<"$block" >/dev/null \
    || fail "every mutating release job must be skipped during dry runs"
  grep -F 'runs-on: ubuntu-24.04' <<<"$block" >/dev/null \
    || fail "every release publisher must use the explicit runner image"
done

# The credential-free reproduction job packages the exact candidates first;
# the fresh publisher receives only both manifests and credentials afterward.
grep -F 'needs: [preflight-crates, verify-signed-tag, validate-release-inputs]' <<<"$reproduce_block" >/dev/null \
  && grep -F 'show "${GITHUB_SHA}:tools/preflight_release_crates.sh"' <<<"$reproduce_block" >/dev/null \
  && grep -F 'name: crate-reproduction-${{ needs.validate-release-inputs.outputs.version }}' <<<"$reproduce_block" >/dev/null \
  || fail "crate candidates must be independently reproduced without credentials"
if grep -F 'CARGO_REGISTRY_TOKEN' <<<"$reproduce_block" >/dev/null; then
  fail "crate reproduction must not receive a registry credential"
fi
for dependency in reproduce-crates prepare-wasm-npm prepare-llm-proxy-npm attest-release; do
  grep -F -- "- $dependency" <<<"$publish_block" >/dev/null \
    || fail "crate publication must wait for $dependency"
done
grep -F 'CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}' <<<"$publish_block" >/dev/null \
  && grep -F 'EXOCHAIN_CRATES_IO_ALLOWED_OWNERS: ${{ vars.EXOCHAIN_CRATES_IO_ALLOWED_OWNERS }}' <<<"$publish_block" >/dev/null \
  || fail "fresh crate publisher must bind its token and explicit owner allowlist"
for capture in \
  'capture_release_helper tools/publish_release_crates.sh publisher_program' \
  'capture_release_helper tools/check_cratesio_namespace_ownership.mjs owner_checker_program' \
  'capture_release_helper tools/verify_release_source.sh source_guard_program' \
  'capture_release_helper tools/verify_release_tag.sh tag_guard_program' \
  'capture_release_helper tools/verify_release_cargo_config.sh cargo_config_program'; do
  grep -F "$capture" <<<"$publish_block" >/dev/null \
    || fail "fresh crate publisher is missing immutable capture: $capture"
done
grep -F 'RELEASE_OWNER_CHECK_PROGRAM="$owner_checker_program"' <<<"$publish_block" >/dev/null \
  && grep -F 'RELEASE_SOURCE_GUARD_PROGRAM="$source_guard_program"' <<<"$publish_block" >/dev/null \
  && grep -F 'RELEASE_TAG_GUARD_PROGRAM="$tag_guard_program"' <<<"$publish_block" >/dev/null \
  || fail "captured publisher guards must enter the isolated publication process"

# Resumption is checksum-bound, not version-only; every irreversible attempt
# gets a live strict owner check, including attempts after retry sleeps.
grep -F 'validate_release_manifests' "$crate_publisher" >/dev/null \
  && grep -F 'preflight != reproduced' "$crate_publisher" >/dev/null \
  && grep -F 'expected_checksum_crates' "$crate_publisher" >/dev/null \
  || fail "publisher must capture exact independently reproduced archive checksums"
grep -F 'validate_crates_io_response' "$crate_publisher" >/dev/null \
  && grep -F 'checksum != expected_checksum' "$crate_publisher" >/dev/null \
  && grep -F 'query_crate_version "$crate" "$expected_checksum"' "$crate_publisher" >/dev/null \
  || fail "partial crate publication must resume only on exact archive checksum"
[ "$(grep -cF 'verify_crate_ownership "$crate"' "$crate_publisher")" -eq 5 ] \
  || fail "publisher must check ownership before mutation and after every exact-checksum observation"
[ "$(grep -cF 'verify_crate_ownership "$crate" require-claimed' "$crate_publisher")" -eq 3 ] \
  || fail "every exact-checksum acceptance path must require an already-claimed approved namespace"
grep -F 'status 429 Too Many Requests' "$crate_publisher" >/dev/null \
  && grep -F 'try again after' "$crate_publisher" >/dev/null \
  && grep -F '/bin/sleep "$retry_seconds"' "$crate_publisher" >/dev/null \
  || fail "crate publication needs bounded rate-limit retry behavior"
grep -F '"$trusted_cargo" publish' "$crate_publisher" >/dev/null \
  && grep -F -- '--no-verify' "$crate_publisher" >/dev/null \
  && grep -F -- '--locked' "$crate_publisher" >/dev/null \
  || fail "crate publisher must publish exact locked candidates without build-script verification"
if grep -F -- '--allow-dirty' "$crate_publisher" >/dev/null \
  || grep -F -- '--allow-dirty' <<<"$publish_block" >/dev/null; then
  fail "crate publication must not bypass dirty-source protection"
fi

# After the first possible registry mutation, the helper may use only captured
# in-memory facts and bounded registry responses—never Git or a helper reload.
package_line="$(grep -nF 'release_cargo package' tools/preflight_release_crates.sh | tail -n 1 | cut -d: -f1)"
preflight_tail="$(sed -n "${package_line},\$p" tools/preflight_release_crates.sh)"
if grep -E 'trusted_git|run_exact_guard|verify_(release|cargo_config)|GITHUB_SHA.*tools/' <<<"$preflight_tail" >/dev/null; then
  fail "crate preflight reloads Git or a trust guard after Cargo packaging starts"
fi
publish_line="$(grep -nF '"$trusted_cargo" publish' "$crate_publisher" | cut -d: -f1)"
crate_tail="$(sed -n "${publish_line},\$p" "$crate_publisher")"
if grep -E '(/usr/bin/)?git|GITHUB_SHA|RELEASE_(SOURCE|TAG_GUARD|CARGO_CONFIG|PREFLIGHT_MANIFEST|REPRODUCED_MANIFEST)' <<<"$crate_tail" >/dev/null; then
  fail "crate publisher reads Git, a guard, or a downloaded trust input after publication starts"
fi

check_npm_publisher_job() {
  local job="$1"
  local block="$2"
  local dependency="$3"
  grep -F -- "- $dependency" <<<"$block" >/dev/null \
    || fail "$job must depend on its exact token-free tarball producer"
  grep -F 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}' <<<"$block" >/dev/null \
    && grep -F 'id-token: write' <<<"$block" >/dev/null \
    || fail "$job must receive only npm token and OIDC publication authority"
  grep -F 'actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548' <<<"$block" >/dev/null \
    && grep -F 'python-version: 3.13.7' <<<"$block" >/dev/null \
    && grep -F 'RELEASE_PYTHON: ${{ steps.setup-python.outputs.python-path }}' <<<"$block" >/dev/null \
    || fail "$job must validate tarballs with pinned Python 3.13.7"
  grep -F 'show "${GITHUB_SHA}:tools/publish_release_npm_package.sh"' <<<"$block" >/dev/null \
    || fail "$job must load its publisher from the exact immutable commit"
}
check_npm_publisher_job publish-wasm-npm "$wasm_block" prepare-wasm-npm
check_npm_publisher_job publish-llm-proxy-npm "$llm_block" prepare-llm-proxy-npm
grep -F 'RELEASE_EXPECTED_TARBALL_SHA256: ${{ needs.prepare-wasm-npm.outputs.tarball_sha256 }}' <<<"$wasm_block" >/dev/null \
  || fail "WASM publisher must bind the exact token-free tarball digest"
grep -F 'RELEASE_EXPECTED_TARBALL_SHA256: ${{ needs.prepare-llm-proxy-npm.outputs.tarball_sha256 }}' <<<"$llm_block" >/dev/null \
  || fail "LYNK publisher must bind the exact token-free tarball digest"
grep -F 'registry_has_exact_tarball()' "$npm_publisher" >/dev/null \
  && grep -F 'validate_npm_registry_response' "$npm_publisher" >/dev/null \
  && grep -F 'value?.dist?.integrity !== process.env.EXPECTED_INTEGRITY' "$npm_publisher" >/dev/null \
  || fail "npm resumption must compare strict registry integrity to the exact tarball"
grep -F '"$node_path" "$npm_cli_path" publish "$RELEASE_NPM_TARBALL"' "$npm_publisher" >/dev/null \
  && grep -F -- '--access public --provenance --ignore-scripts' "$npm_publisher" >/dev/null \
  || fail "npm publisher must publish only the prepared tarball with provenance and no scripts"
npm_publish_line="$(grep -nF '"$node_path" "$npm_cli_path" publish' "$npm_publisher" | cut -d: -f1)"
npm_tail="$(sed -n "${npm_publish_line},\$p" "$npm_publisher")"
if grep -E '(/usr/bin/)?git|GITHUB_SHA|verify_release|RELEASE_GITHUB_TOKEN' <<<"$npm_tail" >/dev/null; then
  fail "npm publisher reads Git or a release guard after npm publish starts"
fi

for dependency in publish publish-wasm-npm publish-llm-proxy-npm attest-release validate-sbom; do
  grep -F "$dependency" <<<"$github_block" >/dev/null \
    || fail "GitHub release must wait for $dependency"
done

printf 'release publish boundary test passed\n'

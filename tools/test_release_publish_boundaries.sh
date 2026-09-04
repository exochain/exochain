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
sealed_crate_publisher=tools/publish_sealed_crate.py
npm_publisher=tools/publish_release_npm_package.sh
for file in "$workflow" "$crate_publisher" "$sealed_crate_publisher" "$npm_publisher"; do
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
# the fresh publisher receives only both sealed archive sets, their manifests,
# and credentials afterward.
grep -F 'needs: [preflight-crates, verify-signed-tag, validate-release-inputs]' <<<"$reproduce_block" >/dev/null \
  && grep -F 'show "${GITHUB_SHA}:tools/preflight_release_crates.sh"' <<<"$reproduce_block" >/dev/null \
  && grep -F 'name: crate-reproduction-${{ needs.validate-release-inputs.outputs.version }}' <<<"$reproduce_block" >/dev/null \
  && grep -F '${{ runner.temp }}/exochain-crate-reproduction-output/package/*.crate' <<<"$reproduce_block" >/dev/null \
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
  'capture_release_helper tools/publish_sealed_crate.py sealed_crate_publisher_program' \
  'capture_release_helper tools/check_cratesio_namespace_ownership.mjs owner_checker_program' \
  'capture_release_helper tools/verify_release_source.sh source_guard_program' \
  'capture_release_helper tools/verify_release_tag.sh tag_guard_program'; do
  grep -F "$capture" <<<"$publish_block" >/dev/null \
    || fail "fresh crate publisher is missing immutable capture: $capture"
done
grep -F 'RELEASE_OWNER_CHECK_PROGRAM="$owner_checker_program"' <<<"$publish_block" >/dev/null \
  && grep -F 'RELEASE_SOURCE_GUARD_PROGRAM="$source_guard_program"' <<<"$publish_block" >/dev/null \
  && grep -F 'RELEASE_TAG_GUARD_PROGRAM="$tag_guard_program"' <<<"$publish_block" >/dev/null \
  && grep -F 'RELEASE_SEALED_CRATE_PUBLISHER_PROGRAM="$sealed_crate_publisher_program"' <<<"$publish_block" >/dev/null \
  && grep -F 'RELEASE_CRATE_ARCHIVE_DIR="$RELEASE_CRATE_ARCHIVE_DIR"' <<<"$publish_block" >/dev/null \
  || fail "captured publisher guards and sealed archive uploader must enter the isolated publication process"

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
grep -F "status 429 ' <<<\"\$output\"" "$crate_publisher" >/dev/null \
  && grep -F 'release_retry_sleep "$retry_seconds"' "$crate_publisher" >/dev/null \
  && grep -F '/bin/sleep "$1"' "$crate_publisher" >/dev/null \
  || fail "crate publication needs bounded rate-limit retry behavior"
grep -F 'release_sealed_crate_publish "$crate" "$expected_checksum"' "$crate_publisher" >/dev/null \
  && grep -F 'body=sealed.request_body' "$sealed_crate_publisher" >/dev/null \
  || fail "crate publisher must transmit only the exact sealed candidate bytes"
if grep -F '"$trusted_cargo" publish' "$crate_publisher" >/dev/null; then
  fail "credentialed crate publisher must not repackage live workspace source"
fi
if grep -F -- '--allow-dirty' "$crate_publisher" >/dev/null \
  || grep -F -- '--allow-dirty' <<<"$publish_block" >/dev/null; then
  fail "crate publication must not bypass dirty-source protection"
fi

# The publisher must keep immutable helper bodies in memory, but it must rerun
# the live source and signed-tag bindings immediately before every irreversible
# registry attempt, including attempts after a retry delay.
package_line="$(grep -nF 'release_cargo package' tools/preflight_release_crates.sh | tail -n 1 | cut -d: -f1)"
preflight_tail="$(sed -n "${package_line},\$p" tools/preflight_release_crates.sh)"
if grep -E 'trusted_git|run_exact_guard|verify_(release|cargo_config)|GITHUB_SHA.*tools/' <<<"$preflight_tail" >/dev/null; then
  fail "crate preflight reloads Git or a trust guard after Cargo packaging starts"
fi
publish_line="$(grep -nF 'release_sealed_crate_publish "$crate" "$expected_checksum"' "$crate_publisher" | tail -n 1 | cut -d: -f1)"
crate_tail="$(sed -n "${publish_line},\$p" "$crate_publisher")"
grep -F 'verify_live_release_binding' "$crate_publisher" >/dev/null \
  && grep -F 'source_guard_program' "$crate_publisher" >/dev/null \
  && grep -F 'tag_guard_program' "$crate_publisher" >/dev/null \
  || fail "crate publisher must retain immutable source and tag guard programs"
publish_attempt_block="$(sed -n '/while \[ "$attempt" -le "$max_attempts" \]; do/,/if output="$(release_sealed_crate_publish/p' "$crate_publisher")"
grep -F 'verify_live_release_binding' <<<"$publish_attempt_block" >/dev/null \
  || fail "every crate publication attempt must rerun live source and tag binding"
if grep -E 'RELEASE_(SOURCE|TAG_GUARD|CARGO_CONFIG|PREFLIGHT_MANIFEST|REPRODUCED_MANIFEST)' <<<"$crate_tail" >/dev/null; then
  fail "crate publisher must use captured guard bodies, not mutable release guard inputs"
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
grep -F 'run_authenticated_npm publish "$RELEASE_NPM_TARBALL"' "$npm_publisher" >/dev/null \
  && grep -F -- '--access public --provenance --ignore-scripts' "$npm_publisher" >/dev/null \
  || fail "npm publisher must publish only the prepared tarball with provenance and no scripts"
npm_mutation_block="$(sed -n '/if \[ "$publish_needed" = true \]; then/,/run_authenticated_npm publish "$RELEASE_NPM_TARBALL"/p' "$npm_publisher")"
grep -F 'verify_prepublication_npm_authority' <<<"$npm_mutation_block" >/dev/null \
  || fail "npm publisher must prove exact owner authority immediately before publication"
npm_authority_function="$(sed -n '/^verify_prepublication_npm_authority() {/,/^}/p' "$npm_publisher")"
grep -F 'run_authenticated_npm owner ls "$package_name"' <<<"$npm_authority_function" >/dev/null \
  && grep -F 'package_registry_url' <<<"$npm_authority_function" >/dev/null \
  && grep -F '404)' <<<"$npm_authority_function" >/dev/null \
  && grep -F '[ "$profile" = sdk ]' <<<"$npm_authority_function" >/dev/null \
  && grep -F '[ "$package_name" = @exochain/sdk ]' <<<"$npm_authority_function" >/dev/null \
  || fail "npm first-publication authority exception must be authenticated, registry-proven, and package-scoped"
if grep -F '@exochain/exochain-wasm|@exochain/llm-proxy|@exochain/sdk)' <<<"$npm_authority_function" >/dev/null; then
  fail "established npm packages must not share the SDK first-publication exception"
fi
npm_publish_line="$(grep -nF 'run_authenticated_npm publish "$RELEASE_NPM_TARBALL"' "$npm_publisher" | cut -d: -f1)"
npm_tail="$(sed -n "${npm_publish_line},\$p" "$npm_publisher")"
grep -F 'verify_registry_acceptance' <<<"$npm_tail" >/dev/null \
  && [ "$(grep -cF 'verify_release_binding' <<<"$npm_tail" || true)" -ge 1 ] \
  || fail "npm acceptance must finish with exact registry proof and a final source/tag rebind"
if grep -E 'npm (ci|pack)|run_authenticated_npm (ci|pack)' <<<"$npm_tail" >/dev/null; then
  fail "npm publisher must not rebuild or repackage after registry mutation starts"
fi

for dependency in publish publish-wasm-npm publish-llm-proxy-npm attest-release validate-sbom; do
  grep -F "$dependency" <<<"$github_block" >/dev/null \
    || fail "GitHub release must wait for $dependency"
done

printf 'release publish boundary test passed\n'

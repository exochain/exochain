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
  printf 'WASM npm package boundary test failed: %s\n' "$1" >&2
  exit 1
}

ci_workflow=".github/workflows/ci.yml"
release_workflow=".github/workflows/release.yml"
package_json="packages/exochain-wasm/wasm/package.json"
package_license="packages/exochain-wasm/wasm/LICENSE"
prep_script="tools/prepare_wasm_npm_package.mjs"
publisher="tools/publish_release_npm_package.sh"
transport="tools/transport_wasm_release_output.py"

for file in "$ci_workflow" "$release_workflow" "$package_json" "$package_license" \
  "$prep_script" "$publisher" "$transport"; do
  [[ -f "$file" ]] || fail "$file is missing"
done

grep -F 'wasm-pack build crates/exochain-wasm --target nodejs --scope exochain' "$ci_workflow" >/dev/null \
  || fail "CI WASM build must generate the scoped @exochain package"
grep -F 'node tools/prepare_wasm_npm_package.mjs packages/exochain-wasm/wasm' "$ci_workflow" >/dev/null \
  || fail "CI WASM build must normalize npm package metadata"
grep -F 'npm pack --dry-run' "$ci_workflow" >/dev/null \
  || fail "CI WASM build must dry-pack the npm package"

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$release_workflow"
}

install_block="$(job_block install-wasm-pack)"
build_block="$(job_block build-wasm-npm)"
prepare_block="$(job_block prepare-wasm-npm)"
publish_block="$(job_block publish-wasm-npm)"
for specification in \
  "install-wasm-pack:$install_block" "build-wasm-npm:$build_block" \
  "prepare-wasm-npm:$prepare_block" "publish-wasm-npm:$publish_block"; do
  [ -n "${specification#*:}" ] || fail "release job ${specification%%:*} is missing"
done

grep -F 'permissions: {}' <<<"$install_block" >/dev/null \
  && grep -F '"$cargo_path" install wasm-pack --version 0.14.0 --locked' <<<"$install_block" >/dev/null \
  && grep -F 'archive_sha256: ${{ steps.seal-tool.outputs.archive_sha256 }}' <<<"$install_block" >/dev/null \
  || fail "wasm-pack must be installed without repository authority and transported by independent digest"
if grep -F 'actions/checkout@' <<<"$install_block" >/dev/null \
  || grep -F 'github.token' <<<"$install_block" >/dev/null; then
  fail "wasm-pack installer must not receive repository source or token"
fi

grep -F 'RELEASE_EXPECTED_TOOL_SHA256: ${{ needs.install-wasm-pack.outputs.archive_sha256 }}' <<<"$build_block" >/dev/null \
  && grep -F -- '--profile wasm-pack --version 0.14.0' <<<"$build_block" >/dev/null \
  && grep -F -- '--expected-sha256 "$RELEASE_EXPECTED_TOOL_SHA256"' <<<"$build_block" >/dev/null \
  || fail "WASM build must execute strict-extracted isolated wasm-pack bytes"
grep -F '"$wasm_pack_path" build "$GITHUB_WORKSPACE/crates/exochain-wasm"' <<<"$build_block" >/dev/null \
  && grep -F -- '--target nodejs --scope exochain' <<<"$build_block" >/dev/null \
  && grep -F -- '--out-dir "$RELEASE_WASM_PACKAGE_DIR" -- --locked' <<<"$build_block" >/dev/null \
  || fail "release workflow must build locked scoped WASM output outside tracked source"
grep -F 'transport_sha256: ${{ steps.transport-wasm.outputs.transport_sha256 }}' <<<"$build_block" >/dev/null \
  && grep -F 'transport_wasm_release_output.py' <<<"$build_block" >/dev/null \
  || fail "WASM lifecycle output must cross jobs only as strict untrusted transport"

grep -F 'needs: [build-wasm-npm, verify-signed-tag, validate-release-inputs]' <<<"$prepare_block" >/dev/null \
  && grep -F 'RELEASE_WASM_TRANSPORT_SHA256: ${{ needs.build-wasm-npm.outputs.transport_sha256 }}' <<<"$prepare_block" >/dev/null \
  && grep -F -- '--expected-sha256 "$RELEASE_WASM_TRANSPORT_SHA256"' <<<"$prepare_block" >/dev/null \
  || fail "fresh WASM packager must bind lifecycle transport to its independent digest"
grep -F '"${GITHUB_SHA}:packages/exochain-wasm/wasm/package.json"' <<<"$prepare_block" >/dev/null \
  && grep -F 'tools/verify_npm_release_package.mjs:$verify_script' <<<"$prepare_block" >/dev/null \
  && grep -F 'tools/verify_npm_release_tarball.py:$tarball_guard' <<<"$prepare_block" >/dev/null \
  || fail "fresh WASM packager must load immutable package validators"
if grep -F -- '--out-dir ../../packages/exochain-wasm/wasm' "$release_workflow" >/dev/null; then
  fail "release workflow must not overwrite the tracked WASM package fixture"
fi
authenticated_npm_block="$(sed -n '/^run_authenticated_npm() {/,/^}/p' "$publisher")"
publish_command_block="$(grep -A1 -F 'run_authenticated_npm publish "$RELEASE_NPM_TARBALL"' "$publisher")"
grep -F '/usr/bin/env -i \' <<<"$authenticated_npm_block" >/dev/null \
  && grep -F 'NODE_AUTH_TOKEN="$NODE_AUTH_TOKEN"' <<<"$authenticated_npm_block" >/dev/null \
  && grep -F '"$node_path" "$npm_cli_path" "$@"' <<<"$authenticated_npm_block" >/dev/null \
  && grep -F 'run_authenticated_npm publish "$RELEASE_NPM_TARBALL"' <<<"$publish_command_block" >/dev/null \
  && grep -F -- '--access public --provenance --ignore-scripts --registry=https://registry.npmjs.org' \
    <<<"$publish_command_block" >/dev/null \
  || fail "release workflow must publish npm package with provenance"
grep -F 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}' <<<"$publish_block" >/dev/null \
  || fail "release workflow must use the npm token for authenticated npm release steps"
grep -F 'RELEASE_EXPECTED_TARBALL_SHA256: ${{ needs.prepare-wasm-npm.outputs.tarball_sha256 }}' <<<"$publish_block" >/dev/null \
  && grep -F 'show "${GITHUB_SHA}:tools/publish_release_npm_package.sh"' <<<"$publish_block" >/dev/null \
  || fail "fresh WASM publisher must bind and execute the exact token-free tarball"
grep -F 'registry_has_exact_tarball()' "$publisher" >/dev/null \
  && grep -F 'validate_npm_registry_response' "$publisher" >/dev/null \
  || fail "npm publisher must resume only when registry integrity matches the exact tarball"
grep -F 'id-token: write' <<<"$publish_block" >/dev/null \
  || fail "release workflow must grant OIDC for npm provenance"

node - "$package_json" <<'NODE'
const fs = require('node:fs');
const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const fail = (message) => {
  console.error(message);
  process.exit(1);
};
if (manifest.name !== '@exochain/exochain-wasm') {
  fail(`expected scoped package name, got ${manifest.name}`);
}
if (manifest.license !== 'Apache-2.0') {
  fail(`expected Apache-2.0 license, got ${manifest.license}`);
}
for (const required of ['LICENSE', 'exochain_wasm_bg.wasm', 'exochain_wasm.js', 'exochain_wasm.d.ts']) {
  if (!manifest.files.includes(required)) {
    fail(`package files must include ${required}`);
  }
}
NODE

printf 'WASM npm package boundary test passed\n'

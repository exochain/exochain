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

for file in "$ci_workflow" "$release_workflow" "$package_json" "$package_license" "$prep_script"; do
  [[ -f "$file" ]] || fail "$file is missing"
done

grep -F 'wasm-pack build crates/exochain-wasm --target nodejs --scope exochain' "$ci_workflow" >/dev/null \
  || fail "CI WASM build must generate the scoped @exochain package"
grep -F 'node tools/prepare_wasm_npm_package.mjs packages/exochain-wasm/wasm' "$ci_workflow" >/dev/null \
  || fail "CI WASM build must normalize npm package metadata"
grep -F 'npm pack --dry-run' "$ci_workflow" >/dev/null \
  || fail "CI WASM build must dry-pack the npm package"

grep -F 'wasm-pack build crates/exochain-wasm --target nodejs --scope exochain --out-dir ../../packages/exochain-wasm/wasm -- --locked' "$release_workflow" >/dev/null \
  || fail "release workflow must generate the scoped @exochain package without refreshing Cargo.lock"
grep -F 'npm publish --access public --provenance' "$release_workflow" >/dev/null \
  || fail "release workflow must publish npm package with provenance"
grep -F 'NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}' "$release_workflow" >/dev/null \
  || fail "release workflow must use the npm token for authenticated npm release steps"
grep -F 'name: Verify npm registry authentication' "$release_workflow" >/dev/null \
  || fail "release workflow must verify npm registry authentication before building the package"
grep -F 'npm ping --registry=https://registry.npmjs.org' "$release_workflow" >/dev/null \
  || fail "release workflow must verify npm registry reachability before publishing"
grep -F 'npm whoami --registry=https://registry.npmjs.org' "$release_workflow" >/dev/null \
  || fail "release workflow must verify the npm token identity before publishing"
if grep -F 'npm org ls exochain' "$release_workflow" >/dev/null; then
  fail "release workflow must not use npm org membership endpoints as publish preflight"
fi
grep -F 'npm_package_version_published()' "$release_workflow" >/dev/null \
  || fail "release workflow must support resumable npm package publication checks"
grep -F 'npm view "@exochain/exochain-wasm@${RELEASE_VERSION}" version --registry=https://registry.npmjs.org' "$release_workflow" >/dev/null \
  || fail "release workflow must check whether the WASM npm package version is already published"
grep -F '@exochain/exochain-wasm ${RELEASE_VERSION} is already published; skipping npm publish.' "$release_workflow" >/dev/null \
  || fail "release workflow must skip already-published WASM npm package versions"
grep -F 'id-token: write' "$release_workflow" >/dev/null \
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

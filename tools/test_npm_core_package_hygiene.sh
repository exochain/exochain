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

cd "$(dirname "$0")/.."

fail() {
  printf 'npm core package hygiene test failed: %s\n' "$1" >&2
  exit 1
}

core_package_dirs=(
  "packages/exochain-sdk"
  "tools/cross-impl-test"
)

for package_dir in "${core_package_dirs[@]}"; do
  package_json="${package_dir}/package.json"
  [[ -f "$package_json" ]] || fail "$package_json is missing"

  node - "$package_json" <<'NODE'
const fs = require("fs");

const packagePath = process.argv[2];
const manifest = JSON.parse(fs.readFileSync(packagePath, "utf8"));

const dependencySections = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
];

const exactSemver = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const allowedInternalSpec = /^(?:file:|workspace:)/;
const violations = [];
let hasExternalDependency = false;

for (const section of dependencySections) {
  for (const [name, spec] of Object.entries(manifest[section] || {})) {
    if (allowedInternalSpec.test(spec)) {
      continue;
    }

    hasExternalDependency = true;
    if (!exactSemver.test(spec)) {
      violations.push(`${section}.${name}=${spec}`);
    }
  }
}

if (violations.length > 0) {
  console.error(`${packagePath} has non-exact external dependency specs:`);
  for (const violation of violations) {
    console.error(`  - ${violation}`);
  }
  process.exit(1);
}

if (hasExternalDependency && !fs.existsSync(packagePath.replace(/package\.json$/, "package-lock.json"))) {
  console.error(`${packagePath} declares external dependencies but has no package-lock.json`);
  process.exit(1);
}
NODE

  if [[ -f "${package_dir}/package-lock.json" ]]; then
    (
      cd "$package_dir"
      npm audit --audit-level=high --omit=dev
    )
  fi
done

printf 'npm core package hygiene test passed\n'

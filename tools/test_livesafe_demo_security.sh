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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app_dir="$repo_root/demo/apps/livesafe"
vite_config="$app_dir/vite.config.ts"
package_json="$app_dir/package.json"
package_lock="$app_dir/package-lock.json"

if grep -Eq 'allowedHosts:[[:space:]]*true' "$vite_config"; then
  echo "LiveSafe demo Vite preview must not disable Host header checks" >&2
  exit 1
fi

if ! grep -Eq 'allowedHosts:[[:space:]]*previewAllowedHosts' "$vite_config"; then
  echo "LiveSafe demo Vite preview must use the explicit previewAllowedHosts allowlist" >&2
  exit 1
fi

node - "$package_json" "$package_lock" <<'NODE'
const fs = require('node:fs');
const [packagePath, lockPath] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(packagePath, 'utf8'));

if (!fs.existsSync(lockPath)) {
  throw new Error('LiveSafe demo package-lock.json is required for deploy reproducibility');
}

const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
const rootLock = lock.packages?.[''];

if (!rootLock) {
  throw new Error('LiveSafe demo package-lock.json must include root package metadata');
}

for (const section of ['dependencies', 'devDependencies']) {
  const declared = manifest[section] || {};
  const locked = rootLock[section] || {};

  for (const [name, version] of Object.entries(declared)) {
    if (/^[~^*<>]/u.test(version)) {
      throw new Error(`${section}.${name} must be pinned exactly, got ${version}`);
    }

    if (locked[name] !== version) {
      throw new Error(`${section}.${name} package-lock mismatch: ${locked[name]} != ${version}`);
    }
  }
}
NODE

echo "LiveSafe demo security guard passed"

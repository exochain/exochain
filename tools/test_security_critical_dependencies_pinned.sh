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

manifest="Cargo.toml"

python3 - <<'PY'
import sys
import tomllib

with open("Cargo.toml", "rb") as manifest:
    cargo = tomllib.load(manifest)

with open("deny.toml", "rb") as deny_manifest:
    deny = tomllib.load(deny_manifest)

bans = deny["bans"]
if bans.get("wildcards") != "deny":
    print('cargo-deny must reject wildcard dependency requirements: set [bans].wildcards = "deny"', file=sys.stderr)
    sys.exit(1)
if bans.get("allow-wildcard-paths") is not True:
    print("cargo-deny must allow only private path dependency wildcards: set [bans].allow-wildcard-paths = true", file=sys.stderr)
    sys.exit(1)

workspace_package = cargo["workspace"].get("package", {})
if workspace_package.get("publish") is not False:
    print("workspace packages must inherit publish = false so cargo-deny can allow private path dependency wildcards only", file=sys.stderr)
    sys.exit(1)

dependencies = cargo["workspace"]["dependencies"]

unpinned = []
for name, spec in sorted(dependencies.items()):
    version = spec if isinstance(spec, str) else spec.get("version")
    if version and not version.startswith("="):
        unpinned.append(f"{name} ({version})")

if unpinned:
    print("workspace dependencies must be exactly pinned:", file=sys.stderr)
    for dependency in unpinned:
        print(f"  - {dependency}", file=sys.stderr)
    sys.exit(1)
PY

require_exact_pin() {
  local crate="$1"
  local version="$2"
  if grep -Eq "^${crate}[[:space:]]*=[[:space:]]*\"=${version}\"([[:space:]]*(#.*)?)?$" "$manifest"; then
    return 0
  fi
  if grep -Eq "^${crate}[[:space:]]*=[[:space:]]*\\{[^}]*version[[:space:]]*=[[:space:]]*\"=${version}\"" "$manifest"; then
    return 0
  fi

  echo "security-critical dependency is not exactly pinned: ${crate} must use =${version}" >&2
  return 1
}

require_exact_pin "serde" "1.0.228"
require_exact_pin "serde_json" "1.0.145"
require_exact_pin "ciborium" "0.2.2"
require_exact_pin "blake3" "1.8.2"
require_exact_pin "ed25519-dalek" "2.2.0"
require_exact_pin "x25519-dalek" "2.0.1"
require_exact_pin "sha2" "0.10.9"
require_exact_pin "hmac" "0.12.1"
require_exact_pin "chacha20poly1305" "0.10.1"
require_exact_pin "hkdf" "0.12.4"
require_exact_pin "rand" "0.8.6"
require_exact_pin "zeroize" "1.8.2"
require_exact_pin "ml-dsa" "0.1.0-rc.7"

echo "workspace dependency exact pin test passed"

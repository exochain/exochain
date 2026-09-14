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
import json
import subprocess
from pathlib import Path

with open("Cargo.toml", "rb") as manifest:
    cargo = tomllib.load(manifest)

with open("deny.toml", "rb") as deny_manifest:
    deny = tomllib.load(deny_manifest)

bans = deny["bans"]
if bans.get("wildcards") != "deny":
    print('cargo-deny must reject wildcard dependency requirements: set [bans].wildcards = "deny"', file=sys.stderr)
    sys.exit(1)
if bans.get("allow-wildcard-paths") is not False:
    print("cargo-deny must reject path dependency wildcards for publishable workspace packages: set [bans].allow-wildcard-paths = false", file=sys.stderr)
    sys.exit(1)

workspace_package = cargo["workspace"].get("package", {})
workspace_version = workspace_package.get("version")
if not isinstance(workspace_version, str) or not workspace_version:
    print("workspace package version must be set before checking path dependency release pins", file=sys.stderr)
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

def dependency_tables(manifest):
    for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield table_name, manifest.get(table_name, {})
    for target_name, target in manifest.get("target", {}).items():
        for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield f"target.{target_name}.{table_name}", target.get(table_name, {})

expected_path_version = f"={workspace_version}"
path_pin_violations = []
manifest_paths = [Path(member) / "Cargo.toml" for member in sorted(cargo["workspace"]["members"])]
manifest_paths.extend(Path(path) for path in ("fuzz/Cargo.toml",))

for manifest_path in manifest_paths:
    if not manifest_path.exists():
        continue
    with manifest_path.open("rb") as member_manifest:
        member_cargo = tomllib.load(member_manifest)
    for table_name, table in dependency_tables(member_cargo):
        for dependency_name, spec in sorted(table.items()):
            if not isinstance(spec, dict) or "path" not in spec:
                continue
            version = spec.get("version")
            if version != expected_path_version:
                path_pin_violations.append(
                    f"{manifest_path}:{table_name}.{dependency_name} "
                    f"path={spec['path']!r} version={version!r}"
                )

if path_pin_violations:
    print("publishable workspace path dependencies must be exactly release-pinned:", file=sys.stderr)
    for violation in path_pin_violations:
        print(f"  - {violation}", file=sys.stderr)
    sys.exit(1)

# RUSTSEC-2026-0285 affects Rustls 0.23.13 through 0.23.44. Check every
# committed Cargo resolution, including the separately resolved zkVM guest,
# so a safe root pin cannot hide a vulnerable sibling lockfile.
for lock_path in (
    Path("Cargo.lock"),
    Path("fuzz/Cargo.lock"),
    Path("livesafe/Cargo.lock"),
    Path("crates/exo-cgr-methods/guest/Cargo.lock"),
):
    with lock_path.open("rb") as lock_file:
        locked = tomllib.load(lock_file)
    for package in locked["package"]:
        if package["name"] != "rustls":
            continue
        version = package["version"]
        release = version.split("-", 1)[0].split("+", 1)[0]
        components = tuple(int(part) for part in release.split("."))
        if len(components) != 3 or (0, 23, 13) <= components < (0, 23, 45):
            print(
                f"{lock_path}: rustls {version} violates RUSTSEC-2026-0285 policy; "
                "resolve the patched dependency before release",
                file=sys.stderr,
            )
            sys.exit(1)

# Ask Cargo to resolve workspace inheritance in the published package
# contracts. A root lockfile alone cannot constrain downstream consumers.
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
    text=True,
))
for name in ("exochain-dag", "exochain-dag-db-postgres"):
    package = next(p for p in metadata["packages"] if p["name"] == name)
    tls = [d for d in package["dependencies"] if d["name"] == "rustls"]
    if len(tls) != 1 or tls[0]["req"] != "=0.23.45" or not tls[0]["optional"]:
        raise SystemExit(f"{name}: standalone PostgreSQL consumers lack the patched Rustls constraint")
    if "dep:rustls" not in package["features"]["postgres"]:
        raise SystemExit(f"{name}: PostgreSQL does not activate the Rustls security constraint")
    if package["features"]["default"] or tls[0]["uses_default_features"]:
        raise SystemExit(f"{name}: TLS constraint must preserve the disabled-by-default adapter")
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
require_exact_pin "rustls" "0.23.45"

echo "workspace dependency exact pin test passed"

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

def split_version(version):
    release, sep, pre = version.partition("-")
    release = release.split("+", 1)[0]
    try:
        numbers = tuple(int(part) for part in release.split("."))
    except ValueError:
        return None
    if len(numbers) != 3:
        return None
    pre_idents = tuple(pre.split(".")) if sep else ()
    return numbers, pre_idents

def cmp_idents(left, right):
    if not left and not right:
        return 0
    if not left:
        return 1
    if not right:
        return -1
    for index in range(max(len(left), len(right))):
        if index >= len(left):
            return -1
        if index >= len(right):
            return 1
        a = left[index]
        b = right[index]
        a_num = a.isdigit()
        b_num = b.isdigit()
        if a_num and b_num:
            delta = int(a) - int(b)
            if delta:
                return -1 if delta < 0 else 1
        elif a_num:
            return -1
        elif b_num:
            return 1
        elif a != b:
            return -1 if a < b else 1
    return 0

def version_cmp(left, right):
    parsed_left = split_version(left)
    parsed_right = split_version(right)
    if parsed_left is None or parsed_right is None:
        raise ValueError(f"unparseable version {left!r} or {right!r}")
    if parsed_left[0] != parsed_right[0]:
        return -1 if parsed_left[0] < parsed_right[0] else 1
    return cmp_idents(parsed_left[1], parsed_right[1])

def version_lt(left, right):
    return version_cmp(left, right) < 0

def rustls_rejected(version):
    # RUSTSEC-2026-0346 is unaffected below 0.21.0 and patched in 0.23.46.
    # That span includes 0.21.x, 0.22.x, and 0.23.0 through 0.23.45, which
    # also covers RUSTSEC-2026-0285 and RUSTSEC-2026-0347 through 0349.
    if split_version(version) is None:
        return True
    return not version_lt(version, "0.21.0") and version_lt(version, "0.23.46")

def rustls_webpki_rejected(version):
    # RUSTSEC-2026-0382 is patched in >=0.103.16 <0.104.0-alpha.1 and in
    # >=0.104.0-alpha.8.
    if split_version(version) is None:
        return True
    stable = (
        not version_lt(version, "0.103.16")
        and version_lt(version, "0.104.0-alpha.1")
    )
    return not (stable or not version_lt(version, "0.104.0-alpha.8"))

def webpki_roots_lock_rejected(versions):
    # RUSTSEC-2026-0381 is patched in >=1.0.10. 0.26.11 is the unaffected
    # compatibility crate and is only safe when its 1.x parent is patched.
    if any(split_version(version) is None for version in versions):
        return True
    patched_v1 = [
        version
        for version in versions
        if split_version(version)[0][0] >= 1 and not version_lt(version, "1.0.10")
    ]
    for version in versions:
        numbers, pre = split_version(version)
        if numbers[0] >= 1:
            if version_lt(version, "1.0.10"):
                return True
            continue
        if numbers == (0, 26, 11) and not pre:
            if not patched_v1:
                return True
            continue
        return True
    return False

for version, rejected in (
    ("0.20.9", False),
    ("0.21.0", True),
    ("0.21.12", True),
    ("0.22.4", True),
    ("0.23.0", True),
    ("0.23.12", True),
    ("0.23.13", True),
    ("0.23.45", True),
    ("0.23.46-rc.1", True),
    ("0.23.46", False),
    ("0.23.47", False),
):
    if rustls_rejected(version) != rejected:
        raise SystemExit(f"rustls policy fixture failed for {version}")

for version, rejected in (
    ("0.103.14", True),
    ("0.103.15", True),
    ("0.103.16", False),
    ("0.103.17", False),
    ("0.104.0-alpha.7", True),
    ("0.104.0-alpha.8", False),
    ("0.104.0-alpha.10", False),
    ("0.104.0", False),
):
    if rustls_webpki_rejected(version) != rejected:
        raise SystemExit(f"rustls-webpki policy fixture failed for {version}")

for versions, rejected in (
    ([], False),
    (["1.0.10"], False),
    (["1.0.9"], True),
    (["0.26.11", "1.0.10"], False),
    (["0.26.11", "1.0.9"], True),
    (["0.26.11"], True),
    (["0.26.10", "1.0.10"], True),
):
    if webpki_roots_lock_rejected(versions) != rejected:
        raise SystemExit(f"webpki-roots policy fixture failed for {versions}")

# Check every committed Cargo resolution, including the separately resolved
# zkVM guest, so a safe root pin cannot hide a vulnerable sibling lockfile.
for lock_path in (
    Path("Cargo.lock"),
    Path("fuzz/Cargo.lock"),
    Path("livesafe/Cargo.lock"),
    Path("crates/exo-cgr-methods/guest/Cargo.lock"),
):
    with lock_path.open("rb") as lock_file:
        locked = tomllib.load(lock_file)
    by_name = {}
    for package in locked["package"]:
        by_name.setdefault(package["name"], []).append(package["version"])
    for version in by_name.get("rustls", []):
        if rustls_rejected(version):
            print(
                f"{lock_path}: rustls {version} is below the 0.23.46 patch; "
                "resolve the patched dependency before release",
                file=sys.stderr,
            )
            sys.exit(1)
    for version in by_name.get("rustls-webpki", []):
        if rustls_webpki_rejected(version):
            print(
                f"{lock_path}: rustls-webpki {version} is below the 0.103.16 patch; "
                "resolve the patched dependency before release",
                file=sys.stderr,
            )
            sys.exit(1)
    if webpki_roots_lock_rejected(by_name.get("webpki-roots", [])):
        print(
            f"{lock_path}: webpki-roots {by_name.get('webpki-roots', [])} "
            "is below the 1.0.10 patch; resolve the patched dependency before release",
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
    if len(tls) != 1 or tls[0]["req"] != "=0.23.46" or not tls[0]["optional"]:
        raise SystemExit(f"{name}: standalone PostgreSQL consumers lack the patched Rustls constraint")
    if "dep:rustls" not in package["features"]["postgres"]:
        raise SystemExit(f"{name}: PostgreSQL does not activate the Rustls security constraint")
    if package["features"]["default"] or tls[0]["uses_default_features"]:
        raise SystemExit(f"{name}: TLS constraint must preserve the disabled-by-default adapter")

# A workspace Cargo.lock is not a constraint for downstream crates.io
# consumers. exochain-sdk's http-client feature and exochain-node must publish
# the patched floors themselves.
published_floors = (
    ("rustls", "=0.23.46"),
    ("rustls-webpki", "=0.103.16"),
    ("webpki-roots", "=1.0.10"),
    ("quinn-proto", "=0.11.19"),
)

def direct_deps(package, dep_name):
    return [
        dep
        for dep in package["dependencies"]
        if dep["name"] == dep_name
        and dep.get("target") is None
        and dep.get("kind") in (None, "normal")
    ]

def require_floor(package, dep_name, req, *, optional):
    deps = direct_deps(package, dep_name)
    if len(deps) != 1 or deps[0]["req"] != req or bool(deps[0]["optional"]) != optional:
        raise SystemExit(
            f"{package['name']}: published {dep_name} floor must be {req} "
            f"optional={optional}; found {deps}"
        )
    if dep_name in {"rustls", "rustls-webpki", "quinn-proto"} and deps[0]["uses_default_features"]:
        raise SystemExit(f"{package['name']}: {dep_name} must disable default features")
    if dep_name == "rustls" and set(deps[0]["features"]) != {"ring", "std", "tls12"}:
        raise SystemExit(f"{package['name']}: rustls features must stay ring, std, tls12")

sdk = next(p for p in metadata["packages"] if p["name"] == "exochain-sdk")
if "http-client" in sdk["features"].get("default", []):
    raise SystemExit("exochain-sdk http-client must stay off by default")
http_client = sdk["features"].get("http-client", [])
for dep_name, req in published_floors:
    require_floor(sdk, dep_name, req, optional=True)
    if f"dep:{dep_name}" not in http_client:
        raise SystemExit(f"exochain-sdk http-client does not activate {dep_name}")

node = next(p for p in metadata["packages"] if p["name"] == "exochain-node")
for dep_name, req in published_floors:
    require_floor(node, dep_name, req, optional=False)
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
require_exact_pin "rustls" "0.23.46"
require_exact_pin "rustls-webpki" "0.103.16"
require_exact_pin "webpki-roots" "1.0.10"
require_exact_pin "quinn-proto" "0.11.19"

# Issue #812: default features pull pkcs8 and break crates.io consumers.
require_default_features_disabled() {
  local crate="$1"
  if grep -Eq "^${crate}[[:space:]]*=[[:space:]]*\\{[^}]*default-features[[:space:]]*=[[:space:]]*false" "$manifest"; then
    return 0
  fi
  echo "security-critical dependency must disable default features: ${crate}" >&2
  return 1
}

require_default_features_disabled "ml-dsa"

echo "workspace dependency exact pin test passed"

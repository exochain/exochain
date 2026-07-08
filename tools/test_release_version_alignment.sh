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

python3 - <<'PY'
import json
import pathlib
import re
import sys
import tomllib


def fail(message: str) -> None:
    print(f"release version alignment test failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str) -> str:
    return pathlib.Path(path).read_text(encoding="utf-8")


def json_version(path: str, key_path: tuple[str, ...] = ("version",)) -> str:
    value = json.loads(read(path))
    for key in key_path:
        value = value[key]
    if not isinstance(value, str) or not value:
        fail(f"{path} {'.'.join(key_path)} must be a non-empty string")
    return value


def regex_value(path: str, pattern: str, label: str) -> str:
    match = re.search(pattern, read(path))
    if match is None:
        fail(f"{path} must define {label}")
    return match.group(1)


def pep440_version(version: str) -> str:
    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-([A-Za-z][0-9A-Za-z-]*)", version)
    if match is None:
        return version
    base, prerelease = match.groups()
    if prerelease == "alpha":
        return f"{base}a0"
    if prerelease == "beta":
        return f"{base}b0"
    rc_match = re.fullmatch(r"rc[.-]?([0-9]+)", prerelease)
    if rc_match is not None:
        return f"{base}rc{rc_match.group(1)}"
    fail(f"unsupported Python package prerelease mapping for {version}")


cargo = tomllib.loads(read("Cargo.toml"))
expected = cargo["workspace"]["package"]["version"]
expected_python = pep440_version(expected)

checks = {
    "packages/exochain-wasm/wasm/package.json": json_version(
        "packages/exochain-wasm/wasm/package.json"
    ),
    "packages/exochain-sdk/package.json": json_version("packages/exochain-sdk/package.json"),
    "packages/exochain-sdk/package-lock.json": json_version(
        "packages/exochain-sdk/package-lock.json"
    ),
    "packages/exochain-sdk/package-lock.json packages.@exochain/sdk": json_version(
        "packages/exochain-sdk/package-lock.json", ("packages", "", "version")
    ),
    "packages/exochain-llm-proxy/package.json": json_version(
        "packages/exochain-llm-proxy/package.json"
    ),
    "packages/exochain-llm-proxy/package-lock.json": json_version(
        "packages/exochain-llm-proxy/package-lock.json"
    ),
    "packages/exochain-llm-proxy/package-lock.json packages.@exochain/llm-proxy": json_version(
        "packages/exochain-llm-proxy/package-lock.json", ("packages", "", "version")
    ),
    "crates/exochain-sdk/src/lib.rs PROTOCOL_VERSION": regex_value(
        "crates/exochain-sdk/src/lib.rs",
        r'PROTOCOL_VERSION:\s*&str\s*=\s*"([^"]+)"',
        "PROTOCOL_VERSION",
    ),
    "packages/exochain-sdk/src/index.ts PROTOCOL_VERSION": regex_value(
        "packages/exochain-sdk/src/index.ts",
        r"PROTOCOL_VERSION\s*=\s*'([^']+)'",
        "PROTOCOL_VERSION",
    ),
    "packages/exochain-py/exochain/__init__.py PROTOCOL_VERSION": regex_value(
        "packages/exochain-py/exochain/__init__.py",
        r'PROTOCOL_VERSION\s*=\s*"([^"]+)"',
        "PROTOCOL_VERSION",
    ),
    "packages/exochain-sdk/dist/index.js PROTOCOL_VERSION": regex_value(
        "packages/exochain-sdk/dist/index.js",
        r"PROTOCOL_VERSION\s*=\s*'([^']+)'",
        "PROTOCOL_VERSION",
    ),
    "packages/exochain-sdk/dist/index.d.ts PROTOCOL_VERSION": regex_value(
        "packages/exochain-sdk/dist/index.d.ts",
        r'PROTOCOL_VERSION\s*=\s*"([^"]+)"',
        "PROTOCOL_VERSION",
    ),
}

for source, actual in checks.items():
    if actual != expected:
        fail(f"{source} is {actual}, expected {expected}")

python_package_checks = {
    "packages/exochain-py/pyproject.toml": tomllib.loads(
        read("packages/exochain-py/pyproject.toml")
    )["project"]["version"],
    "packages/exochain-py/exochain/__init__.py __version__": regex_value(
        "packages/exochain-py/exochain/__init__.py",
        r'__version__\s*=\s*"([^"]+)"',
        "__version__",
    ),
    "packages/exochain-py/exochain/transport/http.py user agent": regex_value(
        "packages/exochain-py/exochain/transport/http.py",
        r'exochain-py/([^"]+)"',
        "Python user agent package version",
    ),
}

for source, actual in python_package_checks.items():
    if actual != expected_python:
        fail(f"{source} is {actual}, expected Python package version {expected_python}")

print(f"release version alignment test passed: {expected}")
PY

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
import os
import pathlib
import re
import sys
import tomllib


contradiction_fixture_document = os.environ.get(
    "EXOCHAIN_RELEASE_ALIGNMENT_CONTRADICTION_FIXTURE_DOCUMENT"
)
contradiction_fixture_kind = os.environ.get(
    "EXOCHAIN_RELEASE_ALIGNMENT_CONTRADICTION_FIXTURE_KIND", "prior-python-sha256"
)
contradiction_fixture_claims = {
    "prior-python-sha256": (
        "The Python SDK still uses **SHA-256** for client-side content-addressed "
        "proposal IDs and decision IDs."
    ),
    "python-identifier-sha256": (
        "Python's decision identifier algorithm is still SHA256."
    ),
    "two-sdk-decision-digest": (
        "Only Rust and TypeScript governance builders share the same BLAKE3 "
        "decision digest."
    ),
}
if (
    contradiction_fixture_document is not None
    and contradiction_fixture_kind not in contradiction_fixture_claims
):
    raise SystemExit("unknown contradiction fixture kind")


def fail(message: str) -> None:
    print(f"release version alignment test failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str) -> str:
    contents = pathlib.Path(path).read_text(encoding="utf-8")
    if path == contradiction_fixture_document:
        contents += f"\n\n{contradiction_fixture_claims[contradiction_fixture_kind]}\n"
    return contents


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
requested = os.environ.get("RELEASE_VERSION_EXPECTED")
if requested is not None and expected != requested:
    fail(f"workspace version is {expected}, expected validated release input {requested}")


def resolved_package_version(manifest_path: pathlib.Path, manifest: dict) -> str:
    version = manifest["package"].get("version")
    if isinstance(version, str):
        return version
    if isinstance(version, dict) and version.get("workspace") is True:
        return expected
    fail(f"{manifest_path} must define a direct version or inherit workspace.package.version")


repo_root = pathlib.Path.cwd().resolve()
workspace_members = cargo["workspace"]["members"]
release_manifests = [repo_root / member / "Cargo.toml" for member in workspace_members]
release_manifests.extend(
    [
        repo_root / "crates/exo-cgr-methods/Cargo.toml",
        repo_root / "crates/exo-cgr-methods/guest/Cargo.toml",
        repo_root / "crates/exo-cgr-prover/Cargo.toml",
    ]
)

for manifest_path in release_manifests:
    if not manifest_path.is_file():
        fail(f"release manifest is missing: {manifest_path.relative_to(repo_root)}")
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    actual = resolved_package_version(manifest_path, manifest)
    if actual != expected:
        fail(f"{manifest_path.relative_to(repo_root)} package version is {actual}, expected {expected}")

for inherited_manifest in [
    repo_root / "crates/exo-core/Cargo.toml",
    repo_root / "crates/exo-dag-db-api/Cargo.toml",
]:
    manifest = tomllib.loads(inherited_manifest.read_text(encoding="utf-8"))
    if manifest["package"].get("version") != {"workspace": True}:
        fail(f"{inherited_manifest.relative_to(repo_root)} must inherit workspace version")

fuzz_manifest_path = repo_root / "fuzz/Cargo.toml"
fuzz_manifest = tomllib.loads(fuzz_manifest_path.read_text(encoding="utf-8"))
if fuzz_manifest["package"].get("version") != "0.0.0":
    fail("fuzz/Cargo.toml package version must remain 0.0.0")

all_manifests = [*release_manifests, fuzz_manifest_path]
dependency_table_names = {"dependencies", "dev-dependencies", "build-dependencies"}
first_party_pin_count = 0


def verify_dependency_tables(manifest_path: pathlib.Path, value: object) -> None:
    global first_party_pin_count
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if key in dependency_table_names and isinstance(child, dict):
            for dependency, specification in child.items():
                if not isinstance(specification, dict) or "path" not in specification:
                    continue
                target_manifest = (manifest_path.parent / specification["path"] / "Cargo.toml").resolve()
                try:
                    target_manifest.relative_to(repo_root)
                except ValueError:
                    continue
                if not target_manifest.is_file():
                    fail(
                        f"{manifest_path.relative_to(repo_root)} dependency {dependency} "
                        f"points to missing manifest {target_manifest}"
                    )
                target = tomllib.loads(target_manifest.read_text(encoding="utf-8"))
                target_name = target["package"].get("name")
                if isinstance(target_name, str) and target_name.startswith("exochain-"):
                    if "version" not in specification:
                        if (
                            manifest_path == repo_root / "crates/exo-cgr-prover/Cargo.toml"
                            and target_name == "exochain-cgr-methods"
                        ):
                            continue
                        fail(
                            f"{manifest_path.relative_to(repo_root)} dependency {dependency} "
                            f"must retain an exact first-party version pin"
                        )
                    required = f"={expected}"
                    if specification.get("version") != required:
                        fail(
                            f"{manifest_path.relative_to(repo_root)} dependency {dependency} "
                            f"must pin {target_name} at {required}"
                        )
                    first_party_pin_count += 1
        elif isinstance(child, dict):
            verify_dependency_tables(manifest_path, child)


for manifest_path in all_manifests:
    verify_dependency_tables(
        manifest_path,
        tomllib.loads(manifest_path.read_text(encoding="utf-8")),
    )

if first_party_pin_count != 158:
    fail(f"found {first_party_pin_count} exact first-party dependency pins, expected 158")

expected_lock_counts = {
    "Cargo.lock": 32,
    "crates/exo-cgr-methods/guest/Cargo.lock": 16,
    "fuzz/Cargo.lock": 5,
}
for lock_path, expected_count in expected_lock_counts.items():
    lock = tomllib.loads(read(lock_path))
    owned = [package for package in lock["package"] if package["name"].startswith("exochain-")]
    if len(owned) != expected_count:
        fail(f"{lock_path} has {len(owned)} first-party packages, expected {expected_count}")
    for package in owned:
        if package["version"] != expected:
            fail(
                f"{lock_path} package {package['name']} is {package['version']}, expected {expected}"
            )

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
    "crates/exochain-sdk/src/lib.rs protocol test": regex_value(
        "crates/exochain-sdk/src/lib.rs",
        r'assert_eq!\(PROTOCOL_VERSION,\s*"([^"]+)"\)',
        "protocol version test literal",
    ),
    "packages/exochain-sdk/test/index.test.ts protocol test": regex_value(
        "packages/exochain-sdk/test/index.test.ts",
        r"strictEqual\(PROTOCOL_VERSION,\s*'([^']+)'\)",
        "protocol version test literal",
    ),
    "packages/exochain-sdk/dist-test/src/index.js PROTOCOL_VERSION": regex_value(
        "packages/exochain-sdk/dist-test/src/index.js",
        r"PROTOCOL_VERSION\s*=\s*'([^']+)'",
        "PROTOCOL_VERSION",
    ),
    "packages/exochain-sdk/dist-test/test/index.test.js protocol test": regex_value(
        "packages/exochain-sdk/dist-test/test/index.test.js",
        r"strictEqual\(PROTOCOL_VERSION,\s*'([^']+)'\)",
        "protocol version test literal",
    ),
    "packages/exochain-py/tests/test_crypto.py protocol test": regex_value(
        "packages/exochain-py/tests/test_crypto.py",
        r'assert\s+PROTOCOL_VERSION\s*==\s*"([^"]+)"',
        "protocol version test literal",
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

decision_id_contract_docs = [
    "CHANGELOG.md",
    "governance/releases/v0.2.6/RC.md",
    "packages/README.md",
    "packages/exochain-sdk/README.md",
    "docs/guides/sdk-quickstart-python.md",
    "docs/guides/sdk-quickstart-typescript.md",
]
decision_id_contract = (
    "For title, description, and proposer strings accepted by all three SDKs, "
    "Rust, TypeScript, and Python `DecisionBuilder` use full BLAKE3 over the "
    "same canonical CBOR v2 decision frame."
)
stale_decision_id_claims = (
    "python decision ids are unchanged",
    "python decision ids remain the first 16 hex characters",
    "python decision ids retain their existing 16 hex sha 256 prefix",
    "rust and typescript decisionbuilder agree on decision ids",
    "rust and typescript decisionbuilder now derive the same 64 hex decision id",
)
legacy_decision_id_terms = re.compile(
    r"\b(?:sha ?256|first (?:16|sixteen)|(?:16|sixteen) hex|truncat\w*|prefix)\b"
)
two_sdk_parity_terms = re.compile(
    r"\b(?:agree|align\w*|both|contract|derive|same|share|use)\b"
)
python_exclusion_terms = re.compile(r"\b(?:excluded|not part|outside)\b")


def normalized_claim_clauses(documentation: str) -> list[str]:
    flattened = " ".join(documentation.split())
    return [
        re.sub(r"[^a-z0-9]+", " ", clause.casefold()).strip()
        for clause in re.split(r"[.!?;]+|\b(?:but|whereas|while)\b", flattened, flags=re.I)
        if clause.strip()
    ]

for documentation_path in decision_id_contract_docs:
    documentation = read(documentation_path)
    normalized_documentation = " ".join(documentation.split())
    if decision_id_contract not in normalized_documentation:
        fail(
            f"{documentation_path} must state the three-SDK canonical decision-ID contract"
        )
    for claim in normalized_claim_clauses(documentation):
        for stale_claim in stale_decision_id_claims:
            if stale_claim in claim:
                fail(f"{documentation_path} retains stale decision-ID text: {stale_claim}")
        mentions_decision_identity = (
            re.search(r"\bdecision (?:digests?|hash(?:es)?|ids?|identifiers?)\b", claim)
            is not None
        )
        mentions_decision_builder = "decisionbuilder" in claim
        if mentions_decision_identity and legacy_decision_id_terms.search(claim):
            fail(f"{documentation_path} retains contradictory decision-ID claim")
        if (
            (mentions_decision_identity or mentions_decision_builder)
            and "python" in claim
            and python_exclusion_terms.search(claim)
        ):
            fail(f"{documentation_path} retains contradictory decision-ID claim")
        if (
            (mentions_decision_identity or mentions_decision_builder)
            and "rust" in claim
            and "typescript" in claim
            and "python" not in claim
            and two_sdk_parity_terms.search(claim)
        ):
            fail(
                f"{documentation_path} retains a two-SDK-only decision-ID claim"
            )

print(f"release version alignment test passed: {expected}")
PY

if [[ -z "${EXOCHAIN_RELEASE_ALIGNMENT_CONTRADICTION_FIXTURE_DOCUMENT:-}" ]]; then
  contradiction_contract_docs=(
    "CHANGELOG.md"
    "docs/guides/sdk-quickstart-python.md"
    "docs/guides/sdk-quickstart-typescript.md"
    "governance/releases/v0.2.6/RC.md"
    "packages/README.md"
    "packages/exochain-sdk/README.md"
  )
  contradiction_fixture_kinds=(
    "prior-python-sha256"
    "python-identifier-sha256"
    "two-sdk-decision-digest"
  )

  for fixture_kind in "${contradiction_fixture_kinds[@]}"; do
    for documentation_path in "${contradiction_contract_docs[@]}"; do
      if contradiction_output="$({
        EXOCHAIN_RELEASE_ALIGNMENT_CONTRADICTION_FIXTURE_DOCUMENT="$documentation_path" \
          EXOCHAIN_RELEASE_ALIGNMENT_CONTRADICTION_FIXTURE_KIND="$fixture_kind" \
          bash "$0"
      } 2>&1)"; then
        printf '%s\n' \
          "release version alignment test failed: $fixture_kind contradiction-injection case unexpectedly passed for $documentation_path" \
          >&2
        exit 1
      fi
      if [[ "$contradiction_output" != *"decision-ID claim"* ]]; then
        printf '%s\n%s\n' \
          "release version alignment test failed: $fixture_kind contradiction-injection case failed for the wrong reason in $documentation_path" \
          "$contradiction_output" \
          >&2
        exit 1
      fi
    done
  done
fi

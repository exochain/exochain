#!/usr/bin/env python3
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

"""Validate and identify one Cargo release archive without extracting it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(f"crate release archive verification failed: {message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("crate")
    parser.add_argument("version")
    parser.add_argument("commit")
    args = parser.parse_args()

    if not args.crate or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in args.crate
    ):
        fail("crate name contains an unsafe character")
    version_parts = args.version.split(".")
    if len(version_parts) != 3 or any(not part.isdigit() for part in version_parts):
        fail("version must contain exactly three numeric components")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        fail("commit must be a full lowercase SHA-1 object name")

    if args.archive.is_symlink():
        fail("archive must not be a symbolic link")
    archive = args.archive.resolve(strict=True)
    if not archive.is_file():
        fail("archive must be a real regular file")
    expected_name = f"{args.crate}-{args.version}.crate"
    if archive.name != expected_name:
        fail(f"archive name must be {expected_name}")
    expected_prefix = f"{args.crate}-{args.version}"

    records: list[bytes] = []
    seen_paths: set[str] = set()
    file_contents: dict[str, bytes] = {}
    regular_file_count = 0
    total_file_bytes = 0
    found_manifest = False
    try:
        with tarfile.open(archive, mode="r:gz") as package:
            members = package.getmembers()
            if not members:
                fail("archive is empty")
            if len(members) > 20_000:
                fail("archive contains too many filesystem entries")
            for member in members:
                member_path = PurePosixPath(member.name)
                if (
                    not member.name
                    or member.name.startswith("/")
                    or "\n" in member.name
                    or "\x00" in member.name
                    or member_path.parts[0] != expected_prefix
                    or any(part in {"", ".", ".."} for part in member_path.parts)
                ):
                    fail(f"archive contains unsafe path {member.name!r}")
                if member.name in seen_paths:
                    fail(f"archive contains duplicate path {member.name!r}")
                seen_paths.add(member.name)

                if member.isdir():
                    records.append(f"d\t{member.mode:o}\t{member.name}\0".encode())
                    continue
                if not member.isfile():
                    fail(f"archive contains a non-regular member {member.name!r}")
                if member.size > 128 * 1024 * 1024:
                    fail(f"archive member is unreasonably large: {member.name!r}")
                extracted = package.extractfile(member)
                if extracted is None:
                    fail(f"archive member {member.name!r} has no readable bytes")
                member_bytes = extracted.read()
                member_digest = hashlib.sha256(member_bytes).hexdigest()
                records.append(
                    f"f\t{member.mode:o}\t{member.name}\t{member_digest}\0".encode()
                )
                file_contents[member.name] = member_bytes
                regular_file_count += 1
                total_file_bytes += len(member_bytes)
                if total_file_bytes > 512 * 1024 * 1024:
                    fail("archive expands beyond the release size limit")
                if member.name == f"{expected_prefix}/Cargo.toml":
                    found_manifest = True
    except (OSError, tarfile.TarError) as error:
        fail(f"archive is unreadable: {error}")

    if regular_file_count == 0:
        fail("archive contains no regular files")
    if not found_manifest:
        fail("archive is missing its normalized Cargo.toml")

    forbidden_names = {
        ".gitignore",
        ".npmignore",
        ".npmrc",
        ".yarnrc",
        ".yarnrc.yml",
        "credentials",
        "credentials.toml",
    }
    for member_name in file_contents:
        relative_parts = PurePosixPath(member_name).parts[1:]
        if any(part in forbidden_names for part in relative_parts):
            fail(f"archive contains release-control file {member_name!r}")
        if len(relative_parts) >= 2 and relative_parts[-2] == ".cargo" \
                and relative_parts[-1] in {"config", "config.toml"}:
            fail(f"archive contains Cargo configuration {member_name!r}")

    vcs_path = f"{expected_prefix}/.cargo_vcs_info.json"
    try:
        vcs_info = json.loads(file_contents[vcs_path])
    except KeyError:
        fail("archive is missing .cargo_vcs_info.json")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"archive has invalid .cargo_vcs_info.json: {error}")
    if not isinstance(vcs_info, dict) or not isinstance(vcs_info.get("git"), dict):
        fail("archive VCS metadata must contain one Git identity")
    if vcs_info["git"].get("sha1") != args.commit:
        fail("archive VCS metadata does not bind the immutable release commit")
    if vcs_info["git"].get("dirty") not in {None, False}:
        fail("archive VCS metadata reports dirty release source")
    path_in_vcs = vcs_info.get("path_in_vcs")
    if not isinstance(path_in_vcs, str) or not path_in_vcs \
            or PurePosixPath(path_in_vcs).is_absolute() \
            or ".." in PurePosixPath(path_in_vcs).parts:
        fail("archive VCS path must be a safe repository-relative path")

    normalized_path = f"{expected_prefix}/Cargo.toml"
    original_path = f"{expected_prefix}/Cargo.toml.orig"
    lock_path = f"{expected_prefix}/Cargo.lock"
    try:
        normalized_manifest = file_contents[normalized_path].decode("utf-8")
        file_contents[original_path].decode("utf-8")
        packaged_lock = file_contents[lock_path].decode("utf-8")
    except KeyError as error:
        fail(f"archive is missing required Cargo metadata {error.args[0]!r}")
    except UnicodeDecodeError as error:
        fail(f"Cargo metadata must be UTF-8: {error}")

    package_section = re.search(
        r"(?ms)^\[package\]\n(?P<body>.*?)(?=^\[|\Z)", normalized_manifest
    )
    if package_section is None:
        fail("normalized Cargo.toml is missing [package]")
    package_body = package_section.group("body")
    required_package_lines = {
        f'name = "{args.crate}"',
        f'version = "{args.version}"',
        "publish = true",
        'license = "Apache-2.0"',
    }
    package_lines = {line.strip() for line in package_body.splitlines()}
    missing_package_lines = required_package_lines - package_lines
    if missing_package_lines:
        fail(
            "normalized Cargo.toml lacks required release metadata: "
            + ", ".join(sorted(missing_package_lines))
        )

    dependency_section = False
    for raw_line in normalized_manifest.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            dependency_section = ".dependencies." in line or line.startswith(
                ("[dependencies.", "[dev-dependencies.", "[build-dependencies.")
            )
            continue
        if dependency_section and re.match(r"^(path|git|registry)\s*=", line):
            fail("normalized dependency metadata contains a non-crates.io source")

    if 'version = 4' not in packaged_lock:
        fail("packaged Cargo.lock must use the locked version-4 graph")
    if "path+" in packaged_lock or "git+" in packaged_lock:
        fail("packaged Cargo.lock contains an unpublishable dependency source")
    for package_record in packaged_lock.split("[[package]]")[1:]:
        name_match = re.search(r'(?m)^name = "([^"]+)"$', package_record)
        version_match = re.search(r'(?m)^version = "([^"]+)"$', package_record)
        if name_match and name_match.group(1).startswith("exochain-"):
            if version_match is None or version_match.group(1) != args.version:
                fail("packaged Cargo.lock contains a drifted EXOCHAIN version")

    records.sort()
    member_manifest_sha256 = hashlib.sha256(b"".join(records)).hexdigest()
    print(
        "\t".join(
            [args.crate, args.version, sha256_file(archive), member_manifest_sha256]
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

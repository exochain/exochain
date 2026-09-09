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

"""Publish one already-sealed Cargo archive through the stable registry API.

Cargo's supported ``publish`` command always packages its source tree before it
uploads.  This helper deliberately accepts only the exact ``.crate`` bytes that
two credential-free release jobs have already reproduced and hashed.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import struct
import sys
import tarfile
import tomllib
from typing import Any, Callable, NamedTuple, NoReturn


CRATES_IO_HOST = "crates.io"
CRATES_IO_PORT = 443
CRATES_IO_PUBLISH_PATH = "/api/v1/crates/new"
MAX_CRATE_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_METADATA_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
NETWORK_TIMEOUT_SECONDS = 120
SAFE_CRATE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*")
SAFE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SAFE_SHA256 = re.compile(r"[0-9a-f]{64}")
SAFE_COMMIT = re.compile(r"[0-9a-f]{40}")
BARE_VERSION_REQUIREMENT = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}")
EXACT_VERSION_REQUIREMENT = re.compile(
    r"=[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


class SealedCrateError(RuntimeError):
    """The candidate or registry response failed closed."""


class CratesIoHttpError(SealedCrateError):
    """A non-success crates.io response, including the retryable 429 case."""

    def __init__(self, status: int, reason: str) -> None:
        self.status = status
        self.reason = reason
        super().__init__(f"crates.io returned HTTP {status} {reason}")


class SealedCrate(NamedTuple):
    archive_bytes: bytes
    metadata: dict[str, Any]
    metadata_bytes: bytes
    request_body: bytes


def reject(message: str) -> NoReturn:
    raise SealedCrateError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            reject(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def invalid_constant(value: str) -> NoReturn:
    reject(f"JSON contains invalid constant {value!r}")


def parse_strict_json(payload: bytes, label: str) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=unique_object,
            parse_constant=invalid_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"{label} is malformed JSON: {error}")


def stable_stat(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_regular_file_once(path: Path, maximum: int, label: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not isinstance(nofollow, int) or nofollow == 0:
        reject(f"{label} cannot be opened safely because O_NOFOLLOW is unavailable")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        reject(f"{label} cannot be securely opened: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            reject(f"{label} must be one regular file")
        if before.st_nlink != 1:
            reject(f"{label} must be non-hardlinked")
        if before.st_size <= 0 or before.st_size > maximum:
            reject(f"{label} size is outside the accepted range")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                reject(f"{label} was truncated while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            reject(f"{label} grew while it was read")
        after = os.fstat(descriptor)
        if stable_stat(before) != stable_stat(after):
            reject(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def require_string(value: Any, label: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value:
        reject(f"{label} must be a non-empty string")
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        reject(f"{label} must be an array of non-empty strings")
    return list(value)


def safe_archive_relative_path(value: str, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        value != str(path)
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        reject(f"{label} must be a safe archive-relative path")
    return path


def canonical_version_requirement(value: Any, label: str) -> str:
    """Match Cargo's VersionReq display for the 0.2.6 manifest corpus.

    Cargo parses every dependency requirement before constructing NewCrate.
    Its display form prefixes a bare one-, two-, or three-component requirement
    with ``^``. All remaining 0.2.6 dependencies are exact, including the
    bounded pre-release requirements. Anything outside that audited grammar
    fails closed instead of guessing at Cargo's publish metadata.
    """

    requirement = require_string(value, label)
    if BARE_VERSION_REQUIREMENT.fullmatch(requirement):
        return f"^{requirement}"
    if EXACT_VERSION_REQUIREMENT.fullmatch(requirement):
        return requirement
    reject(f"{label} is outside the audited Cargo requirement grammar")


def collect_archive_metadata(
    archive_bytes: bytes,
    expected_prefix: str,
    expected_commit: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    selected: dict[str, bytes] = {}
    seen_paths: set[str] = set()
    expanded_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as package:
            members = package.getmembers()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                reject("crate archive has an invalid filesystem inventory")
            for member in members:
                member_path = PurePosixPath(member.name)
                canonical_member_name = str(member_path)
                canonical_spelling = (
                    member.name in {canonical_member_name, f"{canonical_member_name}/"}
                    if member.isdir()
                    else member.name == canonical_member_name
                )
                if (
                    not member.name
                    or member.name.startswith("/")
                    or "\n" in member.name
                    or "\x00" in member.name
                    or not member_path.parts
                    or member_path.parts[0] != expected_prefix
                    or any(part in {"", ".", ".."} for part in member_path.parts)
                    or not canonical_spelling
                ):
                    reject(f"crate archive contains unsafe path {member.name!r}")
                if canonical_member_name in seen_paths:
                    reject(f"crate archive contains duplicate path {member.name!r}")
                seen_paths.add(canonical_member_name)
                if member.isdir():
                    continue
                if not member.isfile():
                    reject(f"crate archive contains non-regular member {member.name!r}")
                if member.size < 0 or member.size > 128 * 1024 * 1024:
                    reject(f"crate archive member is unreasonably large: {member.name!r}")
                expanded_bytes += member.size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    reject("crate archive expands beyond the release size limit")
                relative = PurePosixPath(*member_path.parts[1:])
                selected_name = str(relative)
                if selected_name not in {
                    ".cargo_vcs_info.json",
                    "Cargo.toml",
                    "Cargo.toml.orig",
                    "Cargo.lock",
                } and not selected_name.endswith(("README", "README.md", "README.txt")):
                    continue
                if member.size > MAX_METADATA_MEMBER_BYTES:
                    reject(f"crate metadata member is too large: {member.name!r}")
                extracted = package.extractfile(member)
                if extracted is None:
                    reject(f"crate metadata member is unreadable: {member.name!r}")
                payload = extracted.read(MAX_METADATA_MEMBER_BYTES + 1)
                if len(payload) != member.size:
                    reject(f"crate metadata member changed size: {member.name!r}")
                selected[selected_name] = payload
    except SealedCrateError:
        raise
    except (OSError, EOFError, tarfile.TarError) as error:
        reject(f"crate archive is unreadable: {error}")

    for required in (".cargo_vcs_info.json", "Cargo.toml", "Cargo.toml.orig", "Cargo.lock"):
        if required not in selected:
            reject(f"crate archive is missing {required}")
    vcs = parse_strict_json(selected[".cargo_vcs_info.json"], "crate VCS metadata")
    if not isinstance(vcs, dict) or not isinstance(vcs.get("git"), dict):
        reject("crate VCS metadata lacks one Git identity")
    if vcs["git"].get("sha1") != expected_commit:
        reject("crate VCS metadata does not bind the expected release commit")
    if vcs["git"].get("dirty") not in {None, False}:
        reject("crate VCS metadata reports dirty source")
    path_in_vcs = vcs.get("path_in_vcs")
    if not isinstance(path_in_vcs, str) or not path_in_vcs:
        reject("crate VCS metadata lacks a repository-relative package path")
    safe_archive_relative_path(path_in_vcs, "crate VCS path")
    return vcs, selected


def dependency_record(alias: str, value: Any, kind: str, target: str | None) -> dict[str, Any]:
    if not SAFE_CRATE_NAME.fullmatch(alias):
        reject(f"dependency alias contains unsafe characters: {alias!r}")
    if isinstance(value, str):
        dependency = {"version": value}
    elif isinstance(value, dict):
        dependency = value
    else:
        reject(f"dependency {alias!r} has invalid metadata")
    allowed_keys = {"version", "features", "optional", "default-features", "package"}
    unexpected = set(dependency) - allowed_keys
    if unexpected:
        reject(
            f"dependency {alias!r} contains unsupported publish fields: "
            + ", ".join(sorted(unexpected))
        )
    version = canonical_version_requirement(
        dependency.get("version"), f"dependency {alias!r} version"
    )
    package_name = dependency.get("package", alias)
    if not isinstance(package_name, str) or not SAFE_CRATE_NAME.fullmatch(package_name):
        reject(f"dependency {alias!r} package name is invalid")
    features = require_string_list(dependency.get("features", []), f"dependency {alias!r} features")
    optional = dependency.get("optional", False)
    default_features = dependency.get("default-features", True)
    if not isinstance(optional, bool) or not isinstance(default_features, bool):
        reject(f"dependency {alias!r} boolean metadata is invalid")
    record = {
        "name": package_name,
        "version_req": version,
        "features": features,
        "optional": optional,
        "default_features": default_features,
        "target": target,
        "kind": kind,
    }
    # Cargo's NewCrateDependency serde contract omits absent registry/artifact
    # fields and a false `lib` field. The 0.2.6 corpus has no registry or
    # artifact dependencies; renamed dependencies retain the explicit alias.
    if "package" in dependency:
        record["explicit_name_in_toml"] = alias
    return record


def collect_dependencies(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    def add_group(group: Any, kind: str, target: str | None) -> None:
        if group is None:
            return
        if not isinstance(group, dict):
            reject(f"{kind} dependency table is invalid")
        for alias in sorted(group):
            records.append(dependency_record(alias, group[alias], kind, target))

    add_group(manifest.get("dependencies"), "normal", None)
    add_group(manifest.get("dev-dependencies"), "dev", None)
    add_group(manifest.get("build-dependencies"), "build", None)
    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        reject("target dependency table is invalid")
    for target in sorted(targets):
        require_string(target, "dependency target")
        tables = targets[target]
        if not isinstance(tables, dict):
            reject(f"dependency target {target!r} is invalid")
        unexpected = set(tables) - {
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
        }
        if unexpected:
            reject(f"dependency target {target!r} contains unsupported tables")
        add_group(tables.get("dependencies"), "normal", target)
        add_group(tables.get("dev-dependencies"), "dev", target)
        add_group(tables.get("build-dependencies"), "build", target)
    records.sort(
        key=lambda item: (
            item["kind"],
            item["target"] or "",
            item.get("explicit_name_in_toml") or item["name"],
        )
    )
    return records


def build_publish_metadata(
    manifest_bytes: bytes,
    archive_files: dict[str, bytes],
    expected_crate: str,
    expected_version: str,
) -> dict[str, Any]:
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        reject(f"normalized Cargo.toml is malformed: {error}")
    package = manifest.get("package")
    if not isinstance(package, dict):
        reject("normalized Cargo.toml lacks [package]")
    if package.get("name") != expected_crate or package.get("version") != expected_version:
        reject("normalized Cargo.toml package identity differs from the sealed candidate")
    if package.get("publish") is not True:
        reject("normalized Cargo.toml does not authorize publication")

    authors = require_string_list(package.get("authors", []), "package authors")
    keywords = require_string_list(package.get("keywords", []), "package keywords")
    categories = require_string_list(package.get("categories", []), "package categories")
    features_value = manifest.get("features", {})
    if not isinstance(features_value, dict):
        reject("package features must be a string-array mapping")
    features: dict[str, list[str]] = {}
    for name in sorted(features_value):
        if not isinstance(name, str) or not name:
            reject("package feature name is invalid")
        features[name] = require_string_list(features_value[name], f"feature {name!r}")

    badges_value = manifest.get("badges", {})
    if not isinstance(badges_value, dict):
        reject("package badges must be a mapping")
    badges: dict[str, dict[str, str]] = {}
    for name in sorted(badges_value):
        values = badges_value[name]
        if not isinstance(name, str) or not isinstance(values, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in values.items()
        ):
            reject("package badge metadata is invalid")
        badges[name] = dict(sorted(values.items()))

    readme_value = package.get("readme")
    if readme_value is None or readme_value is False:
        readme = None
        readme_file = None
    elif isinstance(readme_value, str):
        readme_path = str(safe_archive_relative_path(readme_value, "package readme"))
        if readme_path not in archive_files:
            reject("package readme is absent from the sealed archive")
        try:
            readme = archive_files[readme_path].decode("utf-8")
        except UnicodeDecodeError as error:
            reject(f"package readme is not UTF-8: {error}")
        readme_file = readme_value
    else:
        reject("package readme metadata is invalid")

    license_file = package.get("license-file")
    if license_file is not None:
        license_file = require_string(license_file, "package license file")
        license_path = str(safe_archive_relative_path(license_file, "package license file"))
        if license_path not in archive_files:
            reject("package license file is absent from the sealed archive")

    def optional_package_string(key: str) -> str | None:
        return require_string(package.get(key), f"package {key}", optional=True)

    return {
        "name": expected_crate,
        "vers": expected_version,
        "deps": collect_dependencies(manifest),
        "features": features,
        "authors": authors,
        "description": optional_package_string("description"),
        "documentation": optional_package_string("documentation"),
        "homepage": optional_package_string("homepage"),
        "readme": readme,
        "readme_file": readme_file,
        "keywords": keywords,
        "categories": categories,
        "license": optional_package_string("license"),
        "license_file": license_file,
        "repository": optional_package_string("repository"),
        "badges": badges,
        "links": optional_package_string("links"),
        "rust_version": optional_package_string("rust-version"),
    }


def load_sealed_crate(
    archive_path: Path,
    *,
    expected_crate: str,
    expected_version: str,
    expected_sha256: str,
    expected_commit: str,
) -> SealedCrate:
    if not SAFE_CRATE_NAME.fullmatch(expected_crate):
        reject("expected crate name is invalid")
    if not SAFE_VERSION.fullmatch(expected_version):
        reject("expected crate version is invalid")
    if not SAFE_SHA256.fullmatch(expected_sha256):
        reject("expected crate SHA-256 is invalid")
    if not SAFE_COMMIT.fullmatch(expected_commit):
        reject("expected release commit is invalid")
    expected_name = f"{expected_crate}-{expected_version}.crate"
    if archive_path.name != expected_name:
        reject(f"sealed archive name must be {expected_name}")

    payload = read_regular_file_once(archive_path, MAX_CRATE_BYTES, "sealed crate archive")
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        reject("sealed crate archive SHA-256 differs from both reproductions")
    prefix = f"{expected_crate}-{expected_version}"
    _vcs, archive_files = collect_archive_metadata(payload, prefix, expected_commit)
    metadata = build_publish_metadata(
        archive_files["Cargo.toml"],
        archive_files,
        expected_crate,
        expected_version,
    )
    metadata_bytes = json.dumps(
        metadata,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(metadata_bytes) > 0xFFFFFFFF or len(payload) > 0xFFFFFFFF:
        reject("sealed crate request exceeds the registry framing limit")
    request_body = b"".join(
        (
            struct.pack("<I", len(metadata_bytes)),
            metadata_bytes,
            struct.pack("<I", len(payload)),
            payload,
        )
    )
    return SealedCrate(payload, metadata, metadata_bytes, request_body)


def validate_success_response(payload: bytes) -> dict[str, Any]:
    response = {} if not payload else parse_strict_json(payload, "crates.io publish response")
    if not isinstance(response, dict):
        reject("crates.io publish response must be one JSON object")
    if "errors" in response:
        errors = response["errors"]
        if not isinstance(errors, list) or any(not isinstance(item, dict) for item in errors):
            reject("crates.io publish response contains malformed errors")
        details = [item.get("detail") for item in errors]
        if any(not isinstance(detail, str) or not detail for detail in details):
            reject("crates.io publish response contains malformed error details")
        detail_text = "; ".join(details)
        reject(
            "crates.io rejected the sealed crate"
            + (f": {detail_text}" if detail_text else "")
        )
    warnings = response.get("warnings", {})
    if not isinstance(warnings, dict):
        reject("crates.io success response contains malformed warnings")
    normalized_warnings: dict[str, list[str]] = {}
    for key in ("invalid_categories", "invalid_badges", "other"):
        normalized_warnings[key] = require_string_list(
            warnings.get(key, []), f"crates.io warning field {key}"
        )
    normalized = dict(response)
    normalized["warnings"] = normalized_warnings
    return normalized


def publish_sealed_crate(
    archive_path: Path,
    *,
    expected_crate: str,
    expected_version: str,
    expected_sha256: str,
    expected_commit: str,
    token: str,
    connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > 4096 or any(
        character in token for character in "\r\n\x00"
    ):
        reject("crates.io token is missing or malformed")
    # All candidate bytes and API metadata are validated and captured in memory
    # before a network connection exists. A later path mutation cannot affect
    # the irreversible request.
    sealed = load_sealed_crate(
        archive_path,
        expected_crate=expected_crate,
        expected_version=expected_version,
        expected_sha256=expected_sha256,
        expected_commit=expected_commit,
    )
    context = ssl.create_default_context()
    connection = None
    try:
        connection = connection_factory(
            CRATES_IO_HOST,
            CRATES_IO_PORT,
            timeout=NETWORK_TIMEOUT_SECONDS,
            context=context,
        )
        connection.request(
            "PUT",
            CRATES_IO_PUBLISH_PATH,
            body=sealed.request_body,
            headers={
                "Accept": "application/json",
                "Authorization": token,
                "Content-Length": str(len(sealed.request_body)),
                "Content-Type": "application/octet-stream",
                "User-Agent": "exochain-release-workflow (https://github.com/exochain/exochain)",
            },
        )
        response = connection.getresponse()
        response_payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(response_payload) > MAX_RESPONSE_BYTES:
            reject("crates.io publish response exceeds the size limit")
        if response.status < 200 or response.status >= 300:
            reason = response.reason if isinstance(response.reason, str) else "registry error"
            raise CratesIoHttpError(response.status, reason)
        return validate_success_response(response_payload)
    except (SealedCrateError, CratesIoHttpError):
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        reject(f"secure crates.io upload failed: {error}")
    finally:
        if connection is not None:
            try:
                connection.close()
            except (OSError, ssl.SSLError, http.client.HTTPException):
                pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("crate")
    parser.add_argument("version")
    parser.add_argument("archive_sha256")
    parser.add_argument("commit")
    args = parser.parse_args()
    token = os.environ.pop("CARGO_REGISTRY_TOKEN", "")
    try:
        response = publish_sealed_crate(
            args.archive,
            expected_crate=args.crate,
            expected_version=args.version,
            expected_sha256=args.archive_sha256,
            expected_commit=args.commit,
            token=token,
        )
    except CratesIoHttpError as error:
        print(f"status {error.status} {error.reason}", file=sys.stderr)
        return 75 if error.status == 429 else 1
    except SealedCrateError as error:
        print(f"sealed crate publication failed: {error}", file=sys.stderr)
        return 1
    warnings = response["warnings"]
    for warning in warnings["other"]:
        print(f"crates.io warning: {warning}", file=sys.stderr)
    print(f"uploaded sealed crate {args.crate} {args.version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

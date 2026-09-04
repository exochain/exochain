#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Verify exact Python release artifacts and bounded PyPI registry readback."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_AGGREGATE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_PROVENANCE_BYTES = 8 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[ab]|rc)?[0-9]*\Z")
PACKAGE_SOURCE_FILES = {
    "exochain/__init__.py",
    "exochain/authority/__init__.py",
    "exochain/authority/chain.py",
    "exochain/client.py",
    "exochain/consent/__init__.py",
    "exochain/consent/bailment.py",
    "exochain/crypto/__init__.py",
    "exochain/crypto/hash.py",
    "exochain/errors.py",
    "exochain/governance/__init__.py",
    "exochain/governance/decision.py",
    "exochain/governance/vote.py",
    "exochain/identity/__init__.py",
    "exochain/identity/did.py",
    "exochain/identity/keypair.py",
    "exochain/py.typed",
    "exochain/transport/__init__.py",
    "exochain/transport/http.py",
    "exochain/types.py",
}
SDIST_SUPPORT_FILES = {
    ".gitignore",
    "README.md",
    "examples/create_identity.py",
    "examples/governance_decision.py",
    "examples/propose_bailment.py",
    "pyproject.toml",
    "tests/__init__.py",
    "tests/test_authority.py",
    "tests/test_consent.py",
    "tests/test_crypto.py",
    "tests/test_governance.py",
    "tests/test_identity.py",
    "tests/test_transport.py",
}
MIN_PACKAGE_SOURCE_BYTES = 32 * 1024
MIN_SDIST_SUPPORT_BYTES = 16 * 1024
PUBLISH_ATTESTATION_TYPE = "https://docs.pypi.org/attestations/publish/v1"
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_OID_PREFIX = "1.3.6.1.4.1.57264.1."


def fail(message: str) -> NoReturn:
    print(f"Python release package verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def stable_stat(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_regular_file(path: Path, limit: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        fail("platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot securely open {label}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"{label} must be a regular non-symlink, non-hardlinked file")
        if before.st_size <= 0 or before.st_size > limit:
            fail(f"{label} size is outside the accepted range")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{label} was truncated while read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if stable_stat(before) != stable_stat(after):
            fail(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def safe_archive_path(raw: str, expected_root: str | None = None) -> PurePosixPath:
    if "\\" in raw or "\x00" in raw or "\n" in raw:
        fail(f"archive contains an unsafe path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"archive contains an unsafe path: {raw!r}")
    if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
        fail("release archives must not contain Python bytecode caches")
    if expected_root is not None and path.parts[0] != expected_root:
        fail(f"source archive path is outside {expected_root}")
    return path


def verify_metadata(contents: bytes, package_name: str, version: str, label: str) -> None:
    if not contents or len(contents) > MAX_METADATA_BYTES:
        fail(f"{label} size is outside the accepted range")
    metadata = BytesParser().parsebytes(contents, headersonly=True)
    exact_singletons = {
        "Name": package_name,
        "Version": version,
        "License-Expression": "Apache-2.0",
        "Requires-Python": ">=3.11",
    }
    for header, expected in exact_singletons.items():
        if metadata.get_all(header, []) != [expected]:
            fail(f"{label} {header} differs from the exact reviewed package metadata")
    if metadata.get_all("License", []):
        fail(f"{label} must use only the exact SPDX license expression")
    expected_dependencies = {
        "blake3>=0.4.1",
        "cryptography>=42.0.0",
        "httpx>=0.25.0",
        "mypy>=1.7; extra == 'dev'",
        "pydantic>=2.5.0",
        "pytest-asyncio>=0.23; extra == 'dev'",
        "pytest>=7.4; extra == 'dev'",
        "ruff>=0.1.8; extra == 'dev'",
    }
    actual_dependencies = metadata.get_all("Requires-Dist", [])
    if len(actual_dependencies) != len(expected_dependencies) or set(actual_dependencies) != expected_dependencies:
        fail(f"{label} dependencies differ from the exact reviewed SDK contract")
    if metadata.get_all("Provides-Extra", []) != ["dev"]:
        fail(f"{label} optional dependency groups differ from the exact reviewed SDK contract")


def verify_wheel(path: Path, package_name: str, version: str) -> dict[str, str]:
    metadata_name = f"{package_name.replace('-', '_')}-{version}.dist-info/METADATA"
    dist_info = f"{package_name.replace('-', '_')}-{version}.dist-info"
    expected_names = PACKAGE_SOURCE_FILES | {
        metadata_name,
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
    }
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(infos) > MAX_ARCHIVE_MEMBERS or len(names) != len(set(names)):
                fail("wheel member count or uniqueness is invalid")
            expanded = 0
            for info in infos:
                safe_archive_path(info.filename)
                unix_mode = info.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    fail("wheel must not contain symbolic links")
                expanded += info.file_size
                if info.file_size > MAX_ARTIFACT_BYTES or expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    fail("wheel expanded size exceeds the accepted budget")
            if set(names) != expected_names:
                fail("wheel file inventory differs from the exact reviewed Python SDK")
            source_bytes = 0
            source_digests: dict[str, str] = {}
            for name in PACKAGE_SOURCE_FILES:
                contents = archive.read(name)
                source_digests[name] = hashlib.sha256(contents).hexdigest()
                if name.endswith(".py"):
                    if len(contents) < 128:
                        fail(f"wheel contains a placeholder Python module: {name}")
                    source_bytes += len(contents)
            if source_bytes < MIN_PACKAGE_SOURCE_BYTES:
                fail("wheel Python implementation is below the meaningful-source threshold")
            verify_metadata(archive.read(metadata_name), package_name, version, "wheel metadata")
            record_name = f"{dist_info}/RECORD"
            try:
                record_text = archive.read(record_name).decode("utf-8")
                record_rows = list(csv.reader(io.StringIO(record_text, newline="")))
            except (UnicodeDecodeError, csv.Error) as error:
                fail(f"wheel RECORD is malformed: {error}")
            if len(record_rows) != len(expected_names) or any(len(row) != 3 for row in record_rows):
                fail("wheel RECORD must enumerate the exact package inventory")
            actual_record_names = [row[0] for row in record_rows]
            if set(actual_record_names) != expected_names or len(actual_record_names) != len(set(actual_record_names)):
                fail("wheel RECORD names differ from the exact package inventory")
            for name, digest_field, size_field in record_rows:
                if name == record_name:
                    if digest_field or size_field:
                        fail("wheel RECORD self-entry must not assert an unverifiable digest")
                    continue
                contents = archive.read(name)
                encoded = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=").decode()
                if digest_field != f"sha256={encoded}" or size_field != str(len(contents)):
                    fail(f"wheel RECORD digest or size differs for {name}")
            return source_digests
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        fail(f"cannot validate wheel: {error}")


def verify_sdist(path: Path, package_name: str, version: str) -> dict[str, str]:
    expected_root = f"{package_name}-{version}"
    metadata_name = f"{expected_root}/PKG-INFO"
    metadata: bytes | None = None
    has_pyproject = False
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(members) > MAX_ARCHIVE_MEMBERS or len(names) != len(set(names)):
                fail("sdist member count or uniqueness is invalid")
            expanded = 0
            expected_names = {
                f"{expected_root}/{name}" for name in PACKAGE_SOURCE_FILES | SDIST_SUPPORT_FILES
            } | {metadata_name}
            if set(names) != expected_names:
                fail("sdist file inventory differs from the exact reviewed Python SDK")
            source_bytes = 0
            support_bytes = 0
            source_digests: dict[str, str] = {}
            for member in members:
                safe_archive_path(member.name, expected_root)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    fail("sdist must contain only directories and regular files")
                if not (member.isdir() or member.isfile()):
                    fail("sdist contains an unsupported member type")
                expanded += member.size
                if member.size > MAX_ARTIFACT_BYTES or expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    fail("sdist expanded size exceeds the accepted budget")
                if member.name == metadata_name:
                    stream = archive.extractfile(member)
                    if stream is None:
                        fail("sdist metadata cannot be read")
                    metadata = stream.read(MAX_METADATA_BYTES + 1)
                if member.name == f"{expected_root}/pyproject.toml" and member.isfile():
                    has_pyproject = True
                relative_name = member.name.removeprefix(f"{expected_root}/")
                if relative_name in PACKAGE_SOURCE_FILES:
                    stream = archive.extractfile(member)
                    if stream is None:
                        fail(f"sdist package source cannot be read: {relative_name}")
                    contents = stream.read(MAX_ARTIFACT_BYTES + 1)
                    if len(contents) != member.size:
                        fail(f"sdist package source size is inconsistent: {relative_name}")
                    source_digests[relative_name] = hashlib.sha256(contents).hexdigest()
                    if relative_name.endswith(".py"):
                        if member.size < 128:
                            fail(f"sdist contains a placeholder Python module: {relative_name}")
                        source_bytes += member.size
                if relative_name in SDIST_SUPPORT_FILES:
                    if member.size < 64:
                        fail(f"sdist contains a placeholder support file: {relative_name}")
                    support_bytes += member.size
            if metadata is None or not has_pyproject:
                fail("sdist lacks exact PKG-INFO or pyproject.toml")
            if source_bytes < MIN_PACKAGE_SOURCE_BYTES:
                fail("sdist Python implementation is below the meaningful-source threshold")
            if support_bytes < MIN_SDIST_SUPPORT_BYTES:
                fail("sdist tests, examples, and project files are below the meaningful threshold")
            verify_metadata(metadata, package_name, version, "sdist metadata")
            return source_digests
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot validate sdist: {error}")


def validate_identity(package_name: str, version: str) -> None:
    if package_name != "exochain":
        fail("only the owned exochain Python distribution may be released")
    if VERSION_RE.fullmatch(version) is None:
        fail("version must be an exact supported PEP 440 release")


def artifact_records(directory: Path, package_name: str, version: str) -> list[tuple[str, str, int]]:
    validate_identity(package_name, version)
    try:
        directory_stat = directory.lstat()
    except OSError as error:
        fail(f"cannot inspect distribution directory: {error}")
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
        fail("distribution directory must be a real directory")
    entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
    expected_names = {
        f"{package_name}-{version}-py3-none-any.whl",
        f"{package_name}-{version}.tar.gz",
    }
    if {entry.name for entry in entries} != expected_names:
        fail("distribution directory must contain exactly one wheel and one sdist")
    records: list[tuple[str, str, int]] = []
    aggregate = 0
    wheel_sources: dict[str, str] | None = None
    sdist_sources: dict[str, str] | None = None
    for entry in entries:
        data = read_regular_file(entry, MAX_ARTIFACT_BYTES, f"distribution {entry.name}")
        aggregate += len(data)
        if aggregate > MAX_AGGREGATE_BYTES:
            fail("distribution aggregate exceeds the accepted budget")
        if entry.name.endswith(".whl"):
            wheel_sources = verify_wheel(entry, package_name, version)
        else:
            sdist_sources = verify_sdist(entry, package_name, version)
        records.append((entry.name, hashlib.sha256(data).hexdigest(), len(data)))
    if wheel_sources is None or sdist_sources is None or wheel_sources != sdist_sources:
        fail("wheel and sdist must contain byte-identical exact Python SDK sources")
    return records


def manifest_bytes(records: list[tuple[str, str, int]]) -> bytes:
    return "".join(f"{name}\t{digest}\t{size}\n" for name, digest, size in records).encode()


def parse_manifest(path: Path) -> list[tuple[str, str, int]]:
    contents = read_regular_file(path, MAX_METADATA_BYTES, "artifact manifest")
    try:
        text = contents.decode("ascii")
    except UnicodeDecodeError:
        fail("artifact manifest must be ASCII")
    records: list[tuple[str, str, int]] = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or SHA256_RE.fullmatch(fields[1]) is None:
            fail("artifact manifest contains a malformed record")
        try:
            size = int(fields[2])
        except ValueError:
            fail("artifact manifest size is malformed")
        if size <= 0 or size > MAX_ARTIFACT_BYTES:
            fail("artifact manifest size is outside the accepted range")
        records.append((fields[0], fields[1], size))
    if len(records) != 2 or records != sorted(records) or len({row[0] for row in records}) != 2:
        fail("artifact manifest must contain two unique sorted records")
    return records


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key}")
        result[key] = value
    return result


def parse_strict_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"{label} is not strict JSON: {error}")


def decode_canonical_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) is None:
        fail(f"{label} is not canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        fail(f"{label} is not valid base64: {error}")
    if base64.b64encode(decoded).decode() != value:
        fail(f"{label} is not canonical base64")
    return decoded


def certificate_extension_text(certificate: Any, oid: str, label: str) -> str:
    from cryptography.x509 import ExtensionNotFound, UnrecognizedExtension
    from cryptography.x509.oid import ObjectIdentifier

    try:
        extension = certificate.extensions.get_extension_for_oid(ObjectIdentifier(oid)).value
    except ExtensionNotFound:
        fail(f"provenance certificate lacks {label}")
    if not isinstance(extension, UnrecognizedExtension):
        fail(f"provenance certificate {label} has an unexpected representation")
    raw = extension.value
    # Newer Fulcio profiles wrap these values as a DER UTF8String while the
    # legacy GitHub profile stores UTF-8 bytes directly.
    if raw.startswith(b"\x0c"):
        if len(raw) < 2:
            fail(f"provenance certificate {label} is malformed")
        first_length = raw[1]
        if first_length & 0x80:
            length_octets = first_length & 0x7F
            if length_octets == 0 or length_octets > 4 or len(raw) < 2 + length_octets:
                fail(f"provenance certificate {label} is malformed")
            length = int.from_bytes(raw[2 : 2 + length_octets], "big")
            value_start = 2 + length_octets
        else:
            length = first_length
            value_start = 2
        if value_start + length != len(raw):
            fail(f"provenance certificate {label} is malformed")
        raw = raw[value_start:]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"provenance certificate {label} is not UTF-8")
    if not value or "\n" in value or "\x00" in value:
        fail(f"provenance certificate {label} is malformed")
    return value


def verify_provenance(
    response_path: Path,
    artifact_path: Path,
    repository: str,
    workflow: str,
    environment: str,
    expected_ref: str,
    expected_commit: str,
) -> None:
    if repository != "exochain/exochain" or workflow != "release.yml" or environment != "release":
        fail("trusted-publisher identity must be exochain/exochain release.yml in release")
    if (
        re.fullmatch(r"refs/(?:heads|tags)/[0-9A-Za-z._/-]+", expected_ref) is None
        or ".." in expected_ref
        or re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None
    ):
        fail("expected provenance ref or commit is malformed")
    artifact = read_regular_file(artifact_path, MAX_ARTIFACT_BYTES, "provenance artifact")
    artifact_name = artifact_path.name
    if safe_archive_path(artifact_name) != PurePosixPath(artifact_name):
        fail("provenance artifact name is unsafe")
    artifact_digest = hashlib.sha256(artifact).hexdigest()
    payload = parse_strict_json(
        read_regular_file(response_path, MAX_PROVENANCE_BYTES, "PyPI provenance response"),
        "PyPI provenance response",
    )
    if not isinstance(payload, dict) or payload.get("version") != 1:
        fail("PyPI provenance response version is unsupported")
    bundles = payload.get("attestation_bundles")
    if not isinstance(bundles, list) or len(bundles) != 1 or not isinstance(bundles[0], dict):
        fail("PyPI provenance must contain exactly one publisher identity bundle")
    bundle = bundles[0]
    publisher = bundle.get("publisher")
    expected_publisher = {
        "claims": None,
        "environment": environment,
        "kind": "GitHub",
        "repository": repository,
        "workflow": workflow,
    }
    if publisher != expected_publisher:
        fail("PyPI trusted-publisher identity differs from the exact release policy")
    attestations = bundle.get("attestations")
    if not isinstance(attestations, list) or len(attestations) != 1 or not isinstance(attestations[0], dict):
        fail("PyPI provenance must contain exactly one publish attestation")
    attestation = attestations[0]
    if attestation.get("version") != 1:
        fail("PyPI publish attestation version is unsupported")
    envelope = attestation.get("envelope")
    if not isinstance(envelope, dict):
        fail("PyPI publish attestation envelope is malformed")
    statement = parse_strict_json(
        decode_canonical_base64(envelope.get("statement"), "PyPI attestation statement"),
        "PyPI attestation statement",
    )
    decode_canonical_base64(envelope.get("signature"), "PyPI attestation signature")
    expected_subject = [{"name": artifact_name, "digest": {"sha256": artifact_digest}}]
    if (
        not isinstance(statement, dict)
        or statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != PUBLISH_ATTESTATION_TYPE
        or statement.get("predicate") is not None
        or statement.get("subject") != expected_subject
    ):
        fail("PyPI publish statement does not bind the exact artifact name and digest")
    material = attestation.get("verification_material")
    if not isinstance(material, dict):
        fail("PyPI attestation verification material is malformed")
    entries = material.get("transparency_entries")
    if not isinstance(entries, list) or not entries or any(not isinstance(item, dict) for item in entries):
        fail("PyPI attestation lacks a transparency-log proof")

    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        certificate = x509.load_der_x509_certificate(
            decode_canonical_base64(material.get("certificate"), "PyPI attestation certificate")
        )
        san = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        if not isinstance(san, x509.SubjectAlternativeName):
            fail("provenance certificate SAN has an unexpected representation")
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    except ImportError as error:
        fail(f"PyPI provenance certificate verifier is unavailable: {error}")
    except (ValueError, x509.ExtensionNotFound) as error:
        fail(f"PyPI provenance certificate cannot be parsed: {error}")
    workflow_uri = f"https://github.com/{repository}/.github/workflows/{workflow}@{expected_ref}"
    if uris != [workflow_uri]:
        fail("provenance certificate SAN differs from the exact release workflow and ref")
    exact_extensions = {
        "1": (GITHUB_OIDC_ISSUER, "OIDC issuer"),
        "2": ("workflow_dispatch", "workflow event"),
        "3": (expected_commit, "workflow commit"),
        "5": (repository, "source repository"),
        "6": (expected_ref, "source ref"),
        "11": ("github-hosted", "runner environment"),
    }
    for suffix, (expected, label) in exact_extensions.items():
        actual = certificate_extension_text(certificate, f"{GITHUB_OID_PREFIX}{suffix}", label)
        if actual != expected:
            fail(f"provenance certificate {label} differs from the exact release")


def verify_registry_response(
    response_path: Path,
    package_name: str,
    version: str,
    manifest_path: Path,
) -> None:
    validate_identity(package_name, version)
    data = read_regular_file(response_path, MAX_REGISTRY_BYTES, "PyPI registry response")
    payload = parse_strict_json(data, "PyPI registry response")
    info = payload.get("info") if isinstance(payload, dict) else None
    if not isinstance(info, dict) or info.get("name") != package_name or info.get("version") != version:
        fail("PyPI registry identity does not match the release")
    expected = {name: (digest, size) for name, digest, size in parse_manifest(manifest_path)}
    urls = payload.get("urls")
    if not isinstance(urls, list) or len(urls) != len(expected):
        fail("PyPI registry file inventory does not match the exact release")
    actual: dict[str, tuple[str, int]] = {}
    for item in urls:
        if not isinstance(item, dict):
            fail("PyPI registry file record must be an object")
        filename = item.get("filename")
        digests = item.get("digests")
        size = item.get("size")
        if (
            not isinstance(filename, str)
            or filename in actual
            or not isinstance(digests, dict)
            or SHA256_RE.fullmatch(str(digests.get("sha256", ""))) is None
            or not isinstance(size, int)
        ):
            fail("PyPI registry file record is malformed or duplicated")
        actual[filename] = (digests["sha256"], size)
    if actual != expected:
        fail("PyPI registry artifacts do not match the token-free package digests")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    artifacts = subparsers.add_parser("artifacts")
    artifacts.add_argument("directory", type=Path)
    artifacts.add_argument("package_name")
    artifacts.add_argument("version")
    manifest = artifacts.add_mutually_exclusive_group(required=True)
    manifest.add_argument("--write-manifest", type=Path)
    manifest.add_argument("--expect-manifest", type=Path)
    registry = subparsers.add_parser("registry-response")
    registry.add_argument("response", type=Path)
    registry.add_argument("package_name")
    registry.add_argument("version")
    registry.add_argument("manifest", type=Path)
    provenance = subparsers.add_parser("provenance")
    provenance.add_argument("response", type=Path)
    provenance.add_argument("artifact", type=Path)
    provenance.add_argument("repository")
    provenance.add_argument("workflow")
    provenance.add_argument("environment")
    provenance.add_argument("expected_ref")
    provenance.add_argument("expected_commit")
    args = parser.parse_args()

    if args.command == "artifacts":
        records = artifact_records(args.directory, args.package_name, args.version)
        expected = manifest_bytes(records)
        if args.write_manifest is not None:
            output = args.write_manifest
            if not output.is_absolute() or "\n" in str(output):
                fail("manifest output must be an absolute safe path")
            try:
                descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(expected)
            except OSError as error:
                fail(f"cannot create artifact manifest: {error}")
        else:
            actual = read_regular_file(args.expect_manifest, MAX_METADATA_BYTES, "artifact manifest")
            if actual != expected:
                fail("Python distributions differ from the token-free artifact manifest")
    elif args.command == "registry-response":
        verify_registry_response(args.response, args.package_name, args.version, args.manifest)
    else:
        verify_provenance(
            args.response,
            args.artifact,
            args.repository,
            args.workflow,
            args.environment,
            args.expected_ref,
            args.expected_commit,
        )


if __name__ == "__main__":
    main()

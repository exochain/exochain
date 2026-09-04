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

"""Create and extract canonical transports for release tools and raw SBOMs."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import NoReturn

MAGIC = b"EXOCHAIN-RELEASE-FILE-SET-V1"
TOOL_FILES = {
    "cargo-cyclonedx": "cargo-cyclonedx",
    "wasm-pack": "wasm-pack",
}
SBOM_PROFILE = "raw-sbom"
LLM_DIST_PROFILE = "llm-dist"
LLM_DIST_FILES = tuple(
    f"{stem}{suffix}"
    for stem in ("cli", "delivery", "evidence", "index", "mcp", "openai", "receipt", "types")
    for suffix in (".d.ts", ".d.ts.map", ".js", ".js.map")
)
SBOM_NAME = re.compile(r"exochain-[a-z0-9-]+\.cdx\.json")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SHA256 = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"0|[1-9][0-9]*")
TOOL_FILE_LIMIT = 64 * 1024 * 1024
SBOM_FILE_LIMIT = 8 * 1024 * 1024
MAX_ARCHIVE_SIZE = 96 * 1024 * 1024
MAX_INVENTORY_SIZE = 64 * 1024
READ_CHUNK = 1024 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release file-set transport failed: {message}")


def validate_profile(profile: str) -> None:
    if profile not in {*TOOL_FILES, SBOM_PROFILE, LLM_DIST_PROFILE}:
        fail("profile must be cargo-cyclonedx, wasm-pack, raw-sbom, or llm-dist")


def validate_version(version: str) -> None:
    if VERSION.fullmatch(version) is None:
        fail("artifact version must contain exactly three numeric components")


def validate_names(profile: str, names: list[str]) -> tuple[str, ...]:
    if names != sorted(names) or len(names) != len(set(names)):
        fail("file names must be unique and sorted")
    if profile in TOOL_FILES:
        expected = [TOOL_FILES[profile]]
        if names != expected:
            fail(f"{profile} transport must contain exactly {expected[0]}")
    elif profile == SBOM_PROFILE:
        if len(names) != 32:
            fail("raw SBOM transport must contain exactly 32 files")
        if any(SBOM_NAME.fullmatch(name) is None for name in names):
            fail("raw SBOM transport contains an invalid file name")
    elif names != sorted(LLM_DIST_FILES):
        fail("LYNK dist transport must contain exactly the 32 reviewed build outputs")
    return tuple(names)


def file_limit(profile: str) -> int:
    return SBOM_FILE_LIMIT if profile in {SBOM_PROFILE, LLM_DIST_PROFILE} else TOOL_FILE_LIMIT


def file_mode(profile: str) -> int:
    return 0o644 if profile in {SBOM_PROFILE, LLM_DIST_PROFILE} else 0o755


def absolute_path(raw: str, label: str) -> Path:
    if "\0" in raw:
        fail(f"{label} contains a NUL byte")
    path = Path(raw)
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    return path


def open_flags(*, directory: bool = False, writable: bool = False) -> int:
    required = ["O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"]
    if directory:
        required.append("O_DIRECTORY")
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        fail(f"platform lacks secure open flags: {', '.join(missing)}")
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_WRONLY if writable else os.O_RDONLY
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def read_descriptor(descriptor: int, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(READ_CHUNK, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            fail(f"{label} exceeds its size limit")


def read_stable_descriptor(descriptor: int, limit: int, label: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be a regular non-symlink, non-hardlinked file")
    if before.st_size <= 0 or before.st_size > limit:
        fail(f"{label} has an invalid size")
    payload = read_descriptor(descriptor, limit, label)
    after = os.fstat(descriptor)
    stable = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if stable(before) != stable(after) or len(payload) != before.st_size:
        fail(f"{label} changed while it was read")
    return payload


def read_regular_path(path: Path, limit: int, label: str) -> bytes:
    try:
        descriptor = os.open(path, open_flags())
    except OSError as error:
        fail(f"cannot securely open {label}: {error}")
    try:
        return read_stable_descriptor(descriptor, limit, label)
    finally:
        os.close(descriptor)


def read_input(input_path: Path, profile: str) -> dict[str, bytes]:
    try:
        directory = os.open(input_path, open_flags(directory=True))
    except OSError as error:
        fail(f"cannot securely open input directory: {error}")
    try:
        status = os.fstat(directory)
        if not stat.S_ISDIR(status.st_mode) or status.st_nlink < 1:
            fail("input directory must be a real directory")
        names = validate_names(profile, sorted(os.listdir(directory)))
        payloads: dict[str, bytes] = {}
        for name in names:
            try:
                descriptor = os.open(name, open_flags(), dir_fd=directory)
            except OSError as error:
                fail(f"cannot securely open input file {name}: {error}")
            try:
                payloads[name] = read_stable_descriptor(
                    descriptor,
                    file_limit(profile),
                    f"input file {name}",
                )
            finally:
                os.close(descriptor)
        if sorted(os.listdir(directory)) != list(names):
            fail("input directory changed while it was read")
        return payloads
    finally:
        os.close(directory)


def fresh_path(raw: str, label: str) -> Path:
    path = absolute_path(raw, label)
    if path.name in {"", ".", ".."}:
        fail(f"{label} has no final component")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        fail(f"{label} parent is unavailable: {error}")
    destination = parent / path.name
    try:
        os.lstat(destination)
    except FileNotFoundError:
        return destination
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    fail(f"{label} must not already exist")


def build_archive(profile: str, payloads: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
        for name in sorted(payloads):
            payload = payloads[name]
            member = tarfile.TarInfo(name)
            member.type = tarfile.REGTYPE
            member.mode = file_mode(profile)
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.size = len(payload)
            member.mtime = 0
            member.linkname = ""
            member.pax_headers = {}
            bundle.addfile(member, io.BytesIO(payload))
    archive = output.getvalue()
    if not archive or len(archive) > MAX_ARCHIVE_SIZE:
        fail("canonical archive has an invalid size")
    return archive


def build_inventory(
    profile: str,
    version: str,
    archive: bytes,
    payloads: dict[str, bytes],
) -> bytes:
    tokens = [
        MAGIC,
        b"profile",
        profile.encode("ascii"),
        b"artifact-version",
        version.encode("ascii"),
        b"archive-sha256",
        hashlib.sha256(archive).hexdigest().encode("ascii"),
        b"archive-size",
        str(len(archive)).encode("ascii"),
    ]
    for name in sorted(payloads):
        payload = payloads[name]
        tokens.extend(
            [
                b"file",
                name.encode("ascii"),
                str(len(payload)).encode("ascii"),
                hashlib.sha256(payload).hexdigest().encode("ascii"),
            ]
        )
    tokens.append(b"end")
    inventory = b"\0".join(tokens) + b"\0"
    if len(inventory) > MAX_INVENTORY_SIZE:
        fail("inventory exceeds its size limit")
    return inventory


def write_exclusive(path: Path, payload: bytes, mode: int, label: str) -> None:
    try:
        descriptor = os.open(path, open_flags(writable=True) | os.O_CREAT | os.O_EXCL, mode)
    except OSError as error:
        fail(f"cannot create {label}: {error}")
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                fail(f"short write while creating {label}")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_transport(args: argparse.Namespace) -> None:
    validate_profile(args.profile)
    validate_version(args.version)
    input_path = absolute_path(args.input_dir, "input directory")
    archive_path = fresh_path(args.archive, "archive")
    inventory_path = fresh_path(args.inventory, "inventory")
    if archive_path == inventory_path:
        fail("archive and inventory paths must differ")
    payloads = read_input(input_path, args.profile)
    archive = build_archive(args.profile, payloads)
    inventory = build_inventory(args.profile, args.version, archive, payloads)
    created: list[Path] = []
    complete = False
    try:
        write_exclusive(archive_path, archive, 0o600, "archive")
        created.append(archive_path)
        write_exclusive(inventory_path, inventory, 0o600, "inventory")
        created.append(inventory_path)
        complete = True
    finally:
        if not complete:
            for path in reversed(created):
                try:
                    path.unlink()
                except OSError:
                    pass
    print(hashlib.sha256(archive).hexdigest())


def parse_decimal(raw: bytes, maximum: int, label: str) -> int:
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"inventory {label} is not ASCII")
    if DECIMAL.fullmatch(value) is None:
        fail(f"inventory {label} is not canonical decimal")
    number = int(value)
    if number > maximum:
        fail(f"inventory {label} exceeds its limit")
    return number


def parse_inventory(
    raw: bytes,
    expected_profile: str,
    expected_version: str,
) -> tuple[str, int, dict[str, tuple[int, str]]]:
    if not raw.endswith(b"\0"):
        fail("inventory is not NUL terminated")
    tokens = raw.split(b"\0")
    tokens.pop()
    cursor = 0

    def take(label: str) -> bytes:
        nonlocal cursor
        if cursor >= len(tokens):
            fail(f"inventory is truncated before {label}")
        value = tokens[cursor]
        cursor += 1
        return value

    if take("magic") != MAGIC or take("profile label") != b"profile":
        fail("inventory header is invalid")
    try:
        profile = take("profile").decode("ascii")
    except UnicodeDecodeError:
        fail("inventory profile is not ASCII")
    if profile != expected_profile:
        fail("inventory profile does not match the expected profile")
    if take("version label") != b"artifact-version":
        fail("inventory artifact-version label is invalid")
    try:
        version = take("artifact version").decode("ascii")
    except UnicodeDecodeError:
        fail("inventory artifact version is not ASCII")
    if version != expected_version:
        fail("inventory artifact version does not match")
    if take("archive checksum label") != b"archive-sha256":
        fail("inventory archive checksum label is invalid")
    try:
        archive_sha = take("archive checksum").decode("ascii")
    except UnicodeDecodeError:
        fail("inventory archive checksum is not ASCII")
    if SHA256.fullmatch(archive_sha) is None:
        fail("inventory archive checksum is invalid")
    if take("archive size label") != b"archive-size":
        fail("inventory archive size label is invalid")
    archive_size = parse_decimal(take("archive size"), MAX_ARCHIVE_SIZE, "archive size")

    records: dict[str, tuple[int, str]] = {}
    while True:
        marker = take("file record or end marker")
        if marker == b"end":
            break
        if marker != b"file":
            fail("inventory file marker is invalid")
        try:
            name = take("file name").decode("ascii")
            checksum = take("file checksum placeholder").decode("ascii")
        except UnicodeDecodeError:
            fail("inventory file record is not ASCII")
        # The size precedes the checksum. Decode it after retaining strict field order.
        raw_size = checksum.encode("ascii")
        try:
            checksum = take("file checksum").decode("ascii")
        except UnicodeDecodeError:
            fail("inventory file checksum is not ASCII")
        if name in records:
            fail(f"inventory contains duplicate file {name}")
        size = parse_decimal(raw_size, file_limit(expected_profile), f"size for {name}")
        if SHA256.fullmatch(checksum) is None:
            fail(f"inventory checksum for {name} is invalid")
        records[name] = (size, checksum)
    names = validate_names(expected_profile, list(records))
    if list(records) != list(names) or cursor != len(tokens):
        fail("inventory file order or termination is invalid")
    return archive_sha, archive_size, records


def safe_member_name(name: str) -> None:
    if not name or any(character in name for character in "\0\n\r"):
        fail("archive member has an invalid name")
    path = PurePosixPath(name)
    if path.is_absolute() or len(path.parts) != 1 or path.parts[0] in {".", ".."}:
        fail(f"archive member has an unsafe path: {name}")


def read_archive(
    archive: bytes,
    profile: str,
    records: dict[str, tuple[int, str]],
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    names = tuple(records)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            for index, member in enumerate(bundle):
                if index >= len(names):
                    fail("archive contains extra or duplicate members")
                safe_member_name(member.name)
                if member.name != names[index] or member.name in payloads:
                    fail("archive member order or set differs from inventory")
                if member.type != tarfile.REGTYPE or not member.isreg() or member.linkname:
                    fail(f"archive member is not a plain regular file: {member.name}")
                if (
                    member.mode != file_mode(profile)
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.mtime != 0
                    or member.pax_headers
                ):
                    fail(f"archive member metadata is not canonical: {member.name}")
                expected_size, expected_sha = records[member.name]
                if member.size != expected_size:
                    fail(f"archive member size differs from inventory: {member.name}")
                extracted = bundle.extractfile(member)
                if extracted is None:
                    fail(f"archive member cannot be read: {member.name}")
                with extracted:
                    payload = extracted.read(member.size + 1)
                if len(payload) != member.size:
                    fail(f"archive member payload is truncated: {member.name}")
                if hashlib.sha256(payload).hexdigest() != expected_sha:
                    fail(f"archive member checksum differs from inventory: {member.name}")
                payloads[member.name] = payload
    except tarfile.TarError as error:
        fail(f"archive is malformed: {error}")
    if tuple(payloads) != names:
        fail("archive is missing an inventoried member")
    if build_archive(profile, payloads) != archive:
        fail("archive has noncanonical headers, padding, or trailing bytes")
    return payloads


def prepare_output(path: Path) -> tuple[int, bool]:
    created = False
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        try:
            parent = path.parent.resolve(strict=True)
            os.mkdir(parent / path.name, 0o700)
            path = parent / path.name
            created = True
        except OSError as error:
            fail(f"cannot create output directory: {error}")
    except OSError as error:
        fail(f"cannot inspect output directory: {error}")
    else:
        if not stat.S_ISDIR(status.st_mode):
            fail("output must be a real directory")
    try:
        directory = os.open(path, open_flags(directory=True))
    except OSError as error:
        fail(f"cannot securely open output directory: {error}")
    if os.listdir(directory):
        os.close(directory)
        fail("output directory must be empty")
    return directory, created


def materialize(path: Path, profile: str, payloads: dict[str, bytes]) -> None:
    directory, created = prepare_output(path)
    created_names: list[str] = []
    complete = False
    try:
        for name, payload in payloads.items():
            descriptor = os.open(
                name,
                open_flags(writable=True) | os.O_CREAT | os.O_EXCL,
                file_mode(profile),
                dir_fd=directory,
            )
            created_names.append(name)
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        fail(f"short write while extracting {name}")
                    offset += written
                os.fchmod(descriptor, file_mode(profile))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if sorted(os.listdir(directory)) != sorted(payloads):
            fail("output directory changed during extraction")
        complete = True
    finally:
        if not complete:
            for name in reversed(created_names):
                try:
                    os.unlink(name, dir_fd=directory)
                except OSError:
                    pass
        os.close(directory)
        if not complete and created:
            try:
                os.rmdir(path)
            except OSError:
                pass


def extract_transport(args: argparse.Namespace) -> None:
    validate_profile(args.profile)
    validate_version(args.version)
    if SHA256.fullmatch(args.expected_sha256) is None:
        fail("expected archive SHA-256 is invalid")
    archive_path = absolute_path(args.archive, "archive")
    inventory_path = absolute_path(args.inventory, "inventory")
    output_path = absolute_path(args.output_dir, "output directory")
    inventory = read_regular_path(inventory_path, MAX_INVENTORY_SIZE, "inventory")
    inventory_sha, archive_size, records = parse_inventory(
        inventory,
        args.profile,
        args.version,
    )
    if inventory_sha != args.expected_sha256:
        fail("inventory archive checksum differs from expected checksum")
    archive = read_regular_path(archive_path, MAX_ARCHIVE_SIZE, "archive")
    if len(archive) != archive_size or hashlib.sha256(archive).hexdigest() != inventory_sha:
        fail("archive bytes differ from inventory")
    payloads = read_archive(archive, args.profile, records)
    materialize(output_path, args.profile, payloads)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "extract"):
        child = commands.add_parser(command)
        child.add_argument("--profile", required=True)
        child.add_argument("--version", required=True)
        child.add_argument("--archive", required=True)
        child.add_argument("--inventory", required=True)
        if command == "create":
            child.add_argument("--input-dir", required=True)
        else:
            child.add_argument("--expected-sha256", required=True)
            child.add_argument("--output-dir", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if args.command == "create":
            create_transport(args)
        else:
            extract_transport(args)
    except (OSError, OverflowError, ValueError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()

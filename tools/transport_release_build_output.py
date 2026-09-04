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

"""Create or extract the strict raw native release-build transport."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import NoReturn

EXPECTED_FILES = (
    "libexo_api.rlib",
    "libexo_authority.rlib",
    "libexo_avc.rlib",
    "libexo_catapult.rlib",
    "libexo_consensus.rlib",
    "libexo_consent.rlib",
    "libexo_core.rlib",
    "libexo_dag.rlib",
    "libexo_dag_db_api.rlib",
    "libexo_dag_db_core.rlib",
    "libexo_dag_db_domain.rlib",
    "libexo_dag_db_exchange.rlib",
    "libexo_dag_db_graph.rlib",
    "libexo_dag_db_lab.rlib",
    "libexo_dag_db_postgres.rlib",
    "libexo_dag_db_retrieval.rlib",
    "libexo_economy.rlib",
    "libexo_escalation.rlib",
    "libexo_gatekeeper.rlib",
    "libexo_gateway.rlib",
    "libexo_governance.rlib",
    "libexo_identity.rlib",
    "libexo_legal.rlib",
    "libexo_messaging.rlib",
    "libexo_node.rlib",
    "libexo_pdp.rlib",
    "libexo_proofs.rlib",
    "libexo_root.rlib",
    "libexo_tenant.rlib",
)
FILE_SIZE_LIMITS = {name: 256 * 1024 * 1024 for name in EXPECTED_FILES}
MAX_TOTAL_PAYLOAD_SIZE = 512 * 1024 * 1024
MAX_ARCHIVE_SIZE = MAX_TOTAL_PAYLOAD_SIZE + (len(EXPECTED_FILES) + 2) * 10240
MAX_INVENTORY_SIZE = 64 * 1024
INVENTORY_MAGIC = b"EXOCHAIN-RELEASE-BUILD-TRANSPORT-V1"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DECIMAL_PATTERN = re.compile(r"0|[1-9][0-9]*")
READ_CHUNK_SIZE = 1024 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release build transport failed: {message}")


def absolute_path(raw_path: str, label: str) -> Path:
    if "\0" in raw_path:
        fail(f"{label} path contains a NUL byte")
    path = Path(raw_path)
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    return path


def open_flags(*, directory: bool = False, writable: bool = False) -> int:
    required = ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if directory:
        required += ("O_DIRECTORY",)
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        fail(f"platform lacks required secure open flags: {', '.join(missing)}")
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_RDONLY if not writable else os.O_WRONLY
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def read_descriptor(descriptor: int, size_limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(
            descriptor,
            min(READ_CHUNK_SIZE, size_limit + 1 - total),
        )
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > size_limit:
            fail(f"{label} exceeds its size limit")


def read_regular_path(path: Path, size_limit: int, label: str) -> bytes:
    try:
        descriptor = os.open(path, open_flags())
    except OSError as error:
        fail(f"cannot securely open {label}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"{label} must be a regular non-symlink, non-hardlinked file")
        if before.st_size <= 0 or before.st_size > size_limit:
            fail(f"{label} must be nonempty and within its size limit")
        payload = read_descriptor(descriptor, size_limit, label)
        after = os.fstat(descriptor)
        stable_fields = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if stable_fields != (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(payload) != before.st_size:
            fail(f"{label} changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def read_input_files(input_path: Path) -> tuple[Path, dict[str, bytes]]:
    try:
        input_root = input_path.resolve(strict=True)
    except OSError as error:
        fail(f"input directory is unavailable: {error}")
    try:
        directory = os.open(input_path, open_flags(directory=True))
    except OSError as error:
        fail(f"cannot securely open input directory: {error}")
    try:
        directory_status = os.fstat(directory)
        if not stat.S_ISDIR(directory_status.st_mode):
            fail("input directory must be a real non-symlink directory")
        names = os.listdir(directory)
        if len(names) != len(EXPECTED_FILES) or set(names) != set(EXPECTED_FILES):
            fail("input directory must contain exactly the 29 expected release libraries")

        opened_files: list[tuple[str, int, os.stat_result]] = []
        total_size = 0
        for name in EXPECTED_FILES:
            try:
                descriptor = os.open(name, open_flags(), dir_fd=directory)
            except OSError as error:
                fail(f"cannot securely open input file {name}: {error}")
            opened_files.append((name, descriptor, os.fstat(descriptor)))
        try:
            for name, _descriptor, before in opened_files:
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    fail(f"input file {name} must be regular, non-symlink, and non-hardlinked")
                if stat.S_IMODE(before.st_mode) != 0o644:
                    fail(f"input file {name} must have canonical mode 0644")
                limit = FILE_SIZE_LIMITS[name]
                if before.st_size <= 0 or before.st_size > limit:
                    fail(f"input file {name} must be nonempty and within its size limit")
                total_size += before.st_size
                if total_size > MAX_TOTAL_PAYLOAD_SIZE:
                    fail("input release libraries exceed the aggregate size limit")

            payloads: dict[str, bytes] = {}
            for name, descriptor, before in opened_files:
                payload = read_descriptor(
                    descriptor,
                    FILE_SIZE_LIMITS[name],
                    f"input file {name}",
                )
                after = os.fstat(descriptor)
                stable_fields = (
                    before.st_dev,
                    before.st_ino,
                    before.st_nlink,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                if stable_fields != (
                    after.st_dev,
                    after.st_ino,
                    after.st_nlink,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) or len(payload) != before.st_size:
                    fail(f"input file {name} changed while it was read")
                payloads[name] = payload
        finally:
            for _name, descriptor, _before in opened_files:
                os.close(descriptor)
        return input_root, payloads
    finally:
        os.close(directory)


def canonical_fresh_destination(raw_path: str, label: str) -> Path:
    path = absolute_path(raw_path, label)
    if path.name in {"", ".", ".."}:
        fail(f"{label} path has no file name")
    try:
        parent = path.parent.resolve(strict=True)
        parent_status = os.lstat(parent)
    except OSError as error:
        fail(f"{label} parent directory is unavailable: {error}")
    if not stat.S_ISDIR(parent_status.st_mode):
        fail(f"{label} parent must be a directory")
    destination = parent / path.name
    try:
        os.lstat(destination)
    except FileNotFoundError:
        return destination
    except OSError as error:
        fail(f"cannot inspect {label} destination: {error}")
    fail(f"{label} destination must not already exist")


def is_within(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def build_archive(payloads: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w",
        format=tarfile.USTAR_FORMAT,
    ) as bundle:
        for name in EXPECTED_FILES:
            payload = payloads[name]
            member = tarfile.TarInfo(name)
            member.type = tarfile.REGTYPE
            member.mode = 0o644
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
        fail("deterministic archive exceeds its size limit")
    return archive


def inventory_bytes(
    archive_sha256: str,
    archive_size: int,
    payloads: dict[str, bytes],
) -> bytes:
    tokens = [
        INVENTORY_MAGIC,
        b"archive-sha256",
        archive_sha256.encode("ascii"),
        b"archive-size",
        str(archive_size).encode("ascii"),
    ]
    for name in EXPECTED_FILES:
        payload = payloads[name]
        tokens.extend(
            (
                b"file",
                name.encode("ascii"),
                str(len(payload)).encode("ascii"),
                hashlib.sha256(payload).hexdigest().encode("ascii"),
            )
        )
    tokens.append(b"end")
    inventory = b"\0".join(tokens) + b"\0"
    if len(inventory) > MAX_INVENTORY_SIZE:
        fail("inventory metadata exceeds its size limit")
    return inventory


def write_exclusive(path: Path, payload: bytes, label: str) -> None:
    flags = open_flags(writable=True) | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        fail(f"cannot create {label}: {error}")
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                fail(f"short write while creating {label}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remove_created(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def create_transport(args: argparse.Namespace) -> None:
    input_path = absolute_path(args.input_dir, "input directory")
    archive_path = canonical_fresh_destination(args.archive, "archive")
    inventory_path = canonical_fresh_destination(args.inventory, "inventory")
    if archive_path == inventory_path:
        fail("archive and inventory destinations must be distinct")

    input_root, payloads = read_input_files(input_path)
    if is_within(archive_path, input_root):
        fail("archive destination must not be nested beneath the input directory")
    if is_within(inventory_path, input_root):
        fail("inventory destination must not be nested beneath the input directory")

    archive = build_archive(payloads)
    archive_sha256 = hashlib.sha256(archive).hexdigest()
    inventory = inventory_bytes(archive_sha256, len(archive), payloads)
    archive_created = False
    inventory_created = False
    complete = False
    try:
        write_exclusive(archive_path, archive, "archive")
        archive_created = True
        write_exclusive(inventory_path, inventory, "inventory")
        inventory_created = True
        complete = True
    finally:
        if not complete:
            if inventory_created:
                remove_created(inventory_path)
            if archive_created:
                remove_created(archive_path)
    print(archive_sha256)


def parse_decimal(raw: bytes, label: str, maximum: int) -> int:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"inventory {label} is not ASCII")
    if DECIMAL_PATTERN.fullmatch(text) is None:
        fail(f"inventory {label} is not canonical decimal")
    value = int(text)
    if value > maximum:
        fail(f"inventory {label} exceeds its size limit")
    return value


def parse_sha256(raw: bytes, label: str) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"inventory {label} is not ASCII")
    if SHA256_PATTERN.fullmatch(text) is None:
        fail(f"inventory {label} is not a lowercase SHA-256")
    return text


def parse_inventory(
    raw_inventory: bytes,
) -> tuple[str, int, dict[str, tuple[int, str]]]:
    if not raw_inventory.endswith(b"\0"):
        fail("inventory must end at a NUL field boundary")
    tokens = raw_inventory.split(b"\0")
    if tokens[-1] != b"":
        fail("inventory has malformed termination")
    tokens.pop()
    cursor = 0

    def take(label: str) -> bytes:
        nonlocal cursor
        if cursor >= len(tokens):
            fail(f"inventory is truncated before {label}")
        token = tokens[cursor]
        cursor += 1
        return token

    if take("magic") != INVENTORY_MAGIC:
        fail("inventory magic is invalid")
    if take("archive SHA-256 label") != b"archive-sha256":
        fail("inventory archive SHA-256 label is invalid")
    archive_sha256 = parse_sha256(take("archive SHA-256"), "archive SHA-256")
    if take("archive size label") != b"archive-size":
        fail("inventory archive size label is invalid")
    archive_size = parse_decimal(
        take("archive size"),
        "archive size",
        MAX_ARCHIVE_SIZE,
    )

    records: dict[str, tuple[int, str]] = {}
    for expected_name in EXPECTED_FILES:
        if take(f"file marker for {expected_name}") != b"file":
            fail(f"inventory lacks a file marker for {expected_name}")
        raw_name = take(f"file name for {expected_name}")
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            fail("inventory contains a non-ASCII file name")
        if name in records:
            fail(f"inventory contains a duplicate file record: {name}")
        if name != expected_name:
            fail("inventory file order or set is invalid")
        size = parse_decimal(
            take(f"size for {name}"),
            f"size for {name}",
            FILE_SIZE_LIMITS[name],
        )
        if size == 0:
            fail(f"inventory file {name} must be nonempty")
        checksum = parse_sha256(
            take(f"SHA-256 for {name}"),
            f"SHA-256 for {name}",
        )
        records[name] = (size, checksum)

    if take("end marker") != b"end":
        fail("inventory end marker is invalid")
    if cursor != len(tokens):
        fail("inventory contains trailing fields")
    return archive_sha256, archive_size, records


def safe_member_name(raw_name: str) -> None:
    if not raw_name or any(character in raw_name for character in "\0\n\r"):
        fail("archive member has an invalid name")
    path = PurePosixPath(raw_name)
    if path.is_absolute() or len(path.parts) != 1:
        fail(f"archive member has an unsafe path: {raw_name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        fail(f"archive member has an unsafe path: {raw_name}")


def read_archive(
    archive: bytes,
    records: dict[str, tuple[int, str]],
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            for index, member in enumerate(bundle):
                if index >= len(EXPECTED_FILES):
                    fail("archive contains extra or duplicate members")
                safe_member_name(member.name)
                expected_name = EXPECTED_FILES[index]
                if member.name in payloads:
                    fail(f"archive contains a duplicate member: {member.name}")
                if member.name != expected_name:
                    fail("archive member order or set is invalid")
                if member.type != tarfile.REGTYPE or not member.isreg():
                    fail(f"archive member is not a regular file: {member.name}")
                if member.linkname:
                    fail(f"archive member has link metadata: {member.name}")
                if (
                    member.mode != 0o644
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                    or member.pax_headers
                ):
                    fail(f"archive member metadata is not canonical: {member.name}")
                size_limit = FILE_SIZE_LIMITS[member.name]
                if member.size <= 0 or member.size > size_limit:
                    fail(f"archive member must be nonempty and within its size limit: {member.name}")
                inventory_size, inventory_checksum = records[member.name]
                if member.size != inventory_size:
                    fail(f"archive member size differs from inventory: {member.name}")
                extracted = bundle.extractfile(member)
                if extracted is None:
                    fail(f"archive member cannot be read: {member.name}")
                with extracted:
                    payload = extracted.read(member.size + 1)
                if len(payload) != member.size:
                    fail(f"archive member has a truncated payload: {member.name}")
                if hashlib.sha256(payload).hexdigest() != inventory_checksum:
                    fail(f"archive member checksum differs from inventory: {member.name}")
                payloads[member.name] = payload
    except tarfile.TarError as error:
        fail(f"archive is malformed: {error}")
    if tuple(payloads) != EXPECTED_FILES:
        fail("archive is missing one or more expected members")
    if build_archive(payloads) != archive:
        fail("archive is not in the canonical deterministic format")
    return payloads


def prepare_output_directory(output_path: Path) -> tuple[int, bool]:
    created = False
    try:
        status = os.lstat(output_path)
    except FileNotFoundError:
        try:
            parent = output_path.parent.resolve(strict=True)
            if not stat.S_ISDIR(os.lstat(parent).st_mode):
                fail("output parent must be a directory")
            os.mkdir(parent / output_path.name, mode=0o700)
            output_path = parent / output_path.name
            created = True
        except OSError as error:
            fail(f"cannot create output directory: {error}")
    except OSError as error:
        fail(f"cannot inspect output directory: {error}")
    else:
        if not stat.S_ISDIR(status.st_mode):
            fail("output must be a real non-symlink directory")

    try:
        directory = os.open(output_path, open_flags(directory=True))
    except OSError as error:
        if created:
            try:
                os.rmdir(output_path)
            except OSError:
                pass
        fail(f"cannot securely open output directory: {error}")
    if os.listdir(directory):
        os.close(directory)
        if created:
            try:
                os.rmdir(output_path)
            except OSError:
                pass
        fail("output directory must be empty")
    return directory, created


def materialize_output(output_path: Path, payloads: dict[str, bytes]) -> None:
    directory, created_directory = prepare_output_directory(output_path)
    created_files: list[str] = []
    complete = False
    try:
        for name in EXPECTED_FILES:
            flags = open_flags(writable=True) | os.O_CREAT | os.O_EXCL
            try:
                descriptor = os.open(name, flags, 0o644, dir_fd=directory)
            except OSError as error:
                fail(f"cannot safely create output file {name}: {error}")
            created_files.append(name)
            try:
                payload = payloads[name]
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        fail(f"short write while extracting {name}")
                    offset += written
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if set(os.listdir(directory)) != set(EXPECTED_FILES):
            fail("output directory changed during extraction")
        complete = True
    finally:
        if not complete:
            for name in reversed(created_files):
                try:
                    os.unlink(name, dir_fd=directory)
                except OSError:
                    pass
        os.close(directory)
        if not complete and created_directory:
            try:
                os.rmdir(output_path)
            except OSError:
                pass


def extract_transport(args: argparse.Namespace) -> None:
    archive_path = absolute_path(args.archive, "archive")
    inventory_path = absolute_path(args.inventory, "inventory")
    output_path = absolute_path(args.output_dir, "output directory")
    expected_sha256 = args.expected_sha256
    if SHA256_PATTERN.fullmatch(expected_sha256) is None:
        fail("expected archive SHA-256 must be 64 lowercase hexadecimal characters")

    raw_inventory = read_regular_path(
        inventory_path,
        MAX_INVENTORY_SIZE,
        "inventory",
    )
    inventory_sha256, inventory_archive_size, records = parse_inventory(raw_inventory)
    if inventory_sha256 != expected_sha256:
        fail("inventory archive SHA-256 differs from the expected SHA-256")

    archive = read_regular_path(archive_path, MAX_ARCHIVE_SIZE, "archive")
    if len(archive) != inventory_archive_size:
        fail("archive size differs from inventory")
    if hashlib.sha256(archive).hexdigest() != expected_sha256:
        fail("archive SHA-256 differs from the expected SHA-256")
    payloads = read_archive(archive, records)
    materialize_output(output_path, payloads)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transport the exact raw EXOCHAIN native release build output",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--input-dir", required=True)
    create.add_argument("--archive", required=True)
    create.add_argument("--inventory", required=True)
    extract = commands.add_parser("extract")
    extract.add_argument("--archive", required=True)
    extract.add_argument("--expected-sha256", required=True)
    extract.add_argument("--inventory", required=True)
    extract.add_argument("--output-dir", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    try:
        if args.command == "create":
            create_transport(args)
        elif args.command == "extract":
            extract_transport(args)
        else:
            fail("unknown transport command")
    except (OSError, OverflowError, ValueError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()

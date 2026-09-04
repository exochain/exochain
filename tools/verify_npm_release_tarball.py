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

"""Validate and safely extract one npm release tarball."""

from __future__ import annotations

import os
import shutil
import sys
import tarfile
import io
import stat
import zlib
from pathlib import Path, PurePosixPath
from typing import NoReturn

MAX_MEMBERS = 10_000
MAX_MEMBER_SIZE = 64 * 1024 * 1024
MAX_TOTAL_SIZE = 256 * 1024 * 1024
MAX_ARCHIVE_SIZE = 256 * 1024 * 1024
MAX_TAR_STREAM_SIZE = 512 * 1024 * 1024
READ_CHUNK = 1024 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(f"npm release tarball verification failed: {message}")


def validate_path(raw_name: str) -> PurePosixPath:
    if not raw_name or "\0" in raw_name or "\n" in raw_name or "\r" in raw_name:
        fail("archive member has an invalid name")
    path = PurePosixPath(raw_name)
    if path.is_absolute() or path.parts[:1] != ("package",):
        fail(f"archive member is outside package/: {raw_name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        fail(f"archive member has an unsafe path: {raw_name}")
    return path


def read_one_gzip_member(archive: Path) -> bytes:
    required_flags = ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags):
        fail("platform lacks secure archive open flags")
    try:
        descriptor = os.open(
            archive,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
    except OSError as error:
        fail(f"cannot securely open archive: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail("archive must be a regular non-symlink, non-hardlinked file")
        if before.st_size <= 0 or before.st_size > MAX_ARCHIVE_SIZE:
            fail("archive compressed size is outside the accepted range")
        chunks: list[bytes] = []
        total = 0
        while total < before.st_size:
            chunk = os.read(descriptor, min(READ_CHUNK, before.st_size - total))
            if not chunk:
                fail("archive was truncated while it was read")
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        stable = lambda value: (
            value.st_dev, value.st_ino, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns,
        )
        if stable(before) != stable(after):
            fail("archive changed while it was read")
    finally:
        os.close(descriptor)

    inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        tar_stream = inflater.decompress(raw, MAX_TAR_STREAM_SIZE + 1)
        # max_length deliberately leaves compressed input unconsumed once the
        # expansion limit is reached.  Reject that condition before flush:
        # an unbounded flush would otherwise materialize the rest of a gzip
        # bomb in memory merely to reject it afterward.
        if inflater.unconsumed_tail or len(tar_stream) > MAX_TAR_STREAM_SIZE:
            fail("archive gzip member expands beyond the accepted size")
        remaining = MAX_TAR_STREAM_SIZE - len(tar_stream)
        tar_stream += inflater.flush(remaining + 1)
    except zlib.error as error:
        fail(f"archive gzip member is malformed: {error}")
    if len(tar_stream) > MAX_TAR_STREAM_SIZE:
        fail("archive gzip member expands beyond the accepted size")
    if not inflater.eof or inflater.unconsumed_tail:
        fail("archive does not contain one complete bounded gzip member")
    if inflater.unused_data:
        fail("archive contains bytes after its one gzip member")
    return tar_stream


def validate_tar_boundary(tar_stream: bytes, members: list[tarfile.TarInfo]) -> None:
    if len(tar_stream) % tarfile.BLOCKSIZE != 0:
        fail("tar stream is not block aligned")
    cursor = 0
    for member in members:
        # TarInfo.offset includes any contiguous GNU/PAX extension records that
        # apply to the member.  TarInfo.offset_data points just beyond the
        # member's real header.  Requiring the next logical member to begin at
        # the padded end of the previous one proves that tarfile did not skip a
        # second logical stream or any unparsed gap, while still accepting the
        # metadata records emitted by npm's supported tar implementations.
        if (
            member.offset != cursor
            or member.offset_data < cursor + tarfile.BLOCKSIZE
            or member.offset_data % tarfile.BLOCKSIZE != 0
        ):
            fail("tar stream contains hidden extension headers or noncanonical gaps")
        cursor = member.offset_data + ((member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
    trailer = tar_stream[cursor:]
    if len(trailer) < 2 * tarfile.BLOCKSIZE or any(trailer):
        fail("tar stream lacks an exact zero-only end marker and padding")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: verify_npm_release_tarball.py <archive.tgz> <output-dir>")
    archive = Path(sys.argv[1])
    output = Path(sys.argv[2])
    if not archive.is_absolute():
        fail("archive must be an absolute path")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        fail("output directory must be a fresh absolute path")

    tar_stream = read_one_gzip_member(archive)
    output.mkdir(mode=0o700, parents=True)
    seen: set[PurePosixPath] = set()
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_stream), mode="r:") as bundle:
            members: list[tarfile.TarInfo] = []
            while True:
                member = bundle.next()
                if member is None:
                    break
                if len(members) >= MAX_MEMBERS:
                    fail("archive member count is outside the accepted range")
                members.append(member)
            if not members:
                fail("archive member count is outside the accepted range")
            validate_tar_boundary(tar_stream, members)
            for member in members:
                relative = validate_path(member.name)
                if relative in seen:
                    fail(f"archive contains a duplicate member: {member.name}")
                seen.add(relative)
                if not (member.isdir() or member.isreg()):
                    fail(f"archive member is not a directory or regular file: {member.name}")
                if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                    fail(f"archive member is too large: {member.name}")
                total_size += member.size
                if total_size > MAX_TOTAL_SIZE:
                    fail("archive expands beyond the accepted size")

                destination = output.joinpath(*relative.parts)
                if member.isdir():
                    destination.mkdir(mode=0o755, parents=True, exist_ok=False)
                    continue
                destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    fail(f"archive regular file cannot be read: {member.name}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                descriptor = os.open(destination, flags, member.mode & 0o777)
                try:
                    with os.fdopen(descriptor, "wb") as target:
                        shutil.copyfileobj(source, target)
                finally:
                    source.close()
                os.chmod(destination, member.mode & 0o777)
    except (OSError, tarfile.TarError) as error:
        fail(str(error))

    package_root = output / "package"
    if not package_root.is_dir() or package_root.is_symlink():
        fail("archive does not contain one package/ directory")


if __name__ == "__main__":
    main()

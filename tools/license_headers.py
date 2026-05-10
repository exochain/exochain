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

"""Apply and verify EXOCHAIN Apache-2.0 file headers."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COPYRIGHT_LINE = "Copyright 2026 Exochain Foundation"
SPDX_LINE = "SPDX-License-Identifier: Apache-2.0"
HEADER_LINES = [
    COPYRIGHT_LINE,
    "",
    'Licensed under the Apache License, Version 2.0 (the "License");',
    "you may not use this file except in compliance with the License.",
    "You may obtain a copy of the License at:",
    "",
    "    https://www.apache.org/licenses/LICENSE-2.0",
    "",
    "Unless required by applicable law or agreed to in writing, software",
    'distributed under the License is distributed on an "AS IS" BASIS,',
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
    "See the License for the specific language governing permissions and",
    "limitations under the License.",
    "",
    SPDX_LINE,
]

EXCLUDED_PREFIXES = (
    "coverage/",
    "demo/coverage/",
    "packages/exochain-sdk/dist/",
    "packages/exochain-sdk/dist-test/",
    "command-base/.claude/reports/",
    "command-base/.claude/research/",
)
EXCLUDED_SUFFIXES = (
    ".lock",
    ".map",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".zip",
    ".typed",
)
EXCLUDED_NAMES = ("LICENSE",)

SLASH_SUFFIXES = (".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs")
HASH_SUFFIXES = (".py", ".sh", ".toml", ".yml", ".yaml", ".service")
XML_SUFFIXES = (".md", ".html", ".svg", ".xml")
SUPPORTED_SUFFIXES = SLASH_SUFFIXES + HASH_SUFFIXES + XML_SUFFIXES + (
    ".css",
    ".sql",
    ".tla",
)
SUPPORTED_NAMES = (
    "Dockerfile",
    "CODEOWNERS",
    ".dockerignore",
    ".env.example",
    ".gitignore",
    ".npmrc",
)


def tracked_files() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
    )
    return [ROOT / item.decode("utf-8") for item in output.split(b"\0") if item]


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def is_excluded(rel_path: str, name: str) -> bool:
    return (
        name in EXCLUDED_NAMES
        or rel_path.startswith(EXCLUDED_PREFIXES)
        or rel_path.endswith(EXCLUDED_SUFFIXES)
    )


def comment_kind(path: Path) -> str | None:
    rel_path = relative(path)
    name = path.name
    suffix = path.suffix
    if is_excluded(rel_path, name):
        return None
    if name.startswith("Dockerfile") or name in SUPPORTED_NAMES:
        return "hash"
    if suffix in SLASH_SUFFIXES:
        return "slash"
    if suffix in HASH_SUFFIXES:
        return "hash"
    if suffix in XML_SUFFIXES:
        return "xml"
    if suffix == ".css":
        return "css"
    if suffix == ".sql":
        return "sql"
    if suffix == ".tla":
        return "tla"
    return None


def make_header(kind: str, newline: str) -> str:
    if kind == "slash":
        return newline.join(f"// {line}" if line else "//" for line in HEADER_LINES) + newline + newline
    if kind == "hash":
        return newline.join(f"# {line}" if line else "#" for line in HEADER_LINES) + newline + newline
    if kind == "sql":
        return newline.join(f"-- {line}" if line else "--" for line in HEADER_LINES) + newline + newline
    if kind == "tla":
        return newline.join(f"\\* {line}" if line else "\\*" for line in HEADER_LINES) + newline + newline
    if kind == "css":
        body = newline.join(f" * {line}" if line else " *" for line in HEADER_LINES)
        return f"/*{newline}{body}{newline} */{newline}{newline}"
    if kind == "xml":
        return f"<!--{newline}{newline.join(HEADER_LINES)}{newline}-->{newline}{newline}"
    raise ValueError(f"unsupported comment kind: {kind}")


def has_header(text: str) -> bool:
    head = "\n".join(text.splitlines()[:80])
    return COPYRIGHT_LINE in head and SPDX_LINE in head


def insertion_index(lines: list[str], kind: str, path: Path) -> int:
    if not lines:
        return 0
    first = lines[0]
    suffix = path.suffix
    name = path.name

    if first.startswith("#!") and not first.startswith("#!["):
        return 1
    if name.startswith("Dockerfile"):
        index = 0
        while index < len(lines):
            lower = lines[index].lower()
            if lower.startswith("# syntax=") or lower.startswith("# escape="):
                index += 1
                continue
            break
        return index
    if kind == "xml" and suffix == ".md" and first.strip() == "---":
        for index in range(1, len(lines)):
            if lines[index].strip() == "---":
                return index + 1
    if kind == "xml" and suffix in (".html", ".svg", ".xml"):
        stripped = first.strip().lower()
        if stripped.startswith("<!doctype") or stripped.startswith("<?xml"):
            return 1
    if kind == "css" and first.strip().lower().startswith("@charset"):
        return 1
    if kind == "tla" and first.startswith("---- MODULE "):
        return 1
    return 0


def add_header(path: Path, kind: str) -> bool:
    data = path.read_bytes()
    text = data.decode("utf-8")
    if has_header(text):
        return False

    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    index = insertion_index(lines, kind, path)
    header = make_header(kind, newline)
    if not text:
        updated = header.rstrip("\r\n") + newline
    else:
        updated = "".join(lines[:index]) + header + "".join(lines[index:])
    path.write_bytes(updated.encode("utf-8"))
    return True


def eligible_files() -> list[tuple[Path, str]]:
    files = []
    for path in tracked_files():
        kind = comment_kind(path)
        if kind is not None:
            files.append((path, kind))
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write missing headers")
    parser.add_argument("--check", action="store_true", help="fail if eligible files lack headers")
    parser.add_argument("--list-missing", action="store_true", help="print eligible files missing headers")
    args = parser.parse_args()

    if not (args.apply or args.check or args.list_missing):
        parser.error("choose --apply, --check, or --list-missing")

    missing = []
    changed = []
    for path, kind in eligible_files():
        text = path.read_text(encoding="utf-8")
        if has_header(text):
            continue
        missing.append(path)
        if args.apply and add_header(path, kind):
            changed.append(path)

    if args.list_missing:
        for path in missing:
            print(relative(path))

    if args.apply:
        print(f"headers_added={len(changed)}")

    if args.check:
        current_missing = [
            path
            for path, _kind in eligible_files()
            if not has_header(path.read_text(encoding="utf-8"))
        ]
        if current_missing:
            for path in current_missing:
                print(f"missing header: {relative(path)}", file=sys.stderr)
            return 1
        print("license header check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

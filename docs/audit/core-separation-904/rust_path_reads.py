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
"""Paths outside their own crate named by Rust sources (issue #904 audit, part 5).

Usage: rust_path_reads.py <path-classification.tsv> <repo-root>

For every tracked `.rs` file under `crates/` and `fuzz/`, every string literal
on a line is tested three ways:
  - `rel-file`: resolved against the file's directory (how `include_str!`
    and `#[path]` resolve), when the literal contains `../`;
  - `rel-crate`: resolved against the crate directory (how a literal joined
    to `CARGO_MANIFEST_DIR` resolves), when the literal contains `../`;
  - `root`: taken as a repository-root path, when the literal contains a
    slash, and the file mentions `CARGO_MANIFEST_DIR` or `../..` anywhere.
A candidate is reported when it equals a tracked file or tracked directory
that is outside the file's own crate directory.

Writes tab-separated rows on stdout:
source, source_class, line, literal, how, target, match (file|dir),
target_classes, in_test (yes when the file is under `tests/` or the line is
at or after the first `#[cfg(test)]` in the file).

A row says the literal resolves to a tracked path. It does not prove the
path is opened: a literal can be a message, a URL fragment or a fixture
value. Pure and deterministic for a given tree.
"""

import collections
import os
import posixpath
import re
import sys

LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')


def main():
    tsv, root = sys.argv[1], sys.argv[2]
    with open(tsv, encoding="utf-8") as handle:
        rows = [line.rstrip("\n").split("\t") for line in handle][1:]
    cls = {r[0]: r[1] for r in rows}
    dirs = collections.defaultdict(set)
    for path, c in cls.items():
        parts = path.split("/")
        for i in range(1, len(parts)):
            dirs["/".join(parts[:i])].add(c)

    def crate_dir(path):
        parts = path.split("/")
        return "/".join(parts[:2]) if parts[0] == "crates" else parts[0]

    out = sys.stdout
    out.reconfigure(encoding="utf-8", newline="\n")
    out.write("source\tsource_class\tline\tliteral\thow\ttarget\tmatch\ttarget_classes\tin_test\n")
    for src in sorted(p for p in cls if p.endswith(".rs") and p.split("/")[0] in ("crates", "fuzz")):
        try:
            with open(os.path.join(root, src), encoding="utf-8") as handle:
                lines = handle.read().split("\n")
        except (UnicodeDecodeError, OSError):
            continue
        text = "\n".join(lines)
        rooted = "CARGO_MANIFEST_DIR" in text or "../.." in text
        own = crate_dir(src)
        test_from = next((i for i, l in enumerate(lines, 1) if "#[cfg(test)]" in l), None)
        in_tests_dir = "/tests/" in src or "/benches/" in src or src.startswith("fuzz/")
        for number, line in enumerate(lines, 1):
            seen = set()
            for literal in LITERAL.findall(line):
                if "/" not in literal or len(literal) > 200 or " " in literal:
                    continue
                candidates = []
                if "../" in literal:
                    candidates.append(("rel-file", posixpath.normpath(posixpath.join(posixpath.dirname(src), literal))))
                    candidates.append(("rel-crate", posixpath.normpath(posixpath.join(own, literal))))
                elif rooted:
                    candidates.append(("root", posixpath.normpath(literal)))
                for how, target in candidates:
                    target = target.rstrip("/")
                    if target.startswith("..") or target in seen:
                        continue
                    if target == own or target.startswith(own + "/"):
                        continue
                    if target in cls:
                        match, classes = "file", {cls[target]}
                    elif target in dirs and "/" in target:
                        match, classes = "dir", dirs[target]
                    else:
                        continue
                    seen.add(target)
                    in_test = "yes" if in_tests_dir or (test_from and number >= test_from) else "no"
                    out.write(
                        f"{src}\t{cls[src]}\t{number}\t{literal}\t{how}\t{target}\t{match}\t"
                        f"{';'.join(sorted(classes))}\t{in_test}\n"
                    )


if __name__ == "__main__":
    main()

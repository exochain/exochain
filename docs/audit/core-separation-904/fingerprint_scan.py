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
"""Product-fingerprint scan for the issue #904 audit (part 3).

Usage: fingerprint_scan.py <path-classification.tsv> <repo-root>

For every path that part 1 does NOT propose as "adjacent surface", read the
file from the working tree and count case-insensitive matches of each term
below. Writes a tab-separated list on stdout, one row per (path, term) with a
non-zero count.

Columns: path, proposed_class, term, matches, first_line.

A term that matches the path itself adds a row `path-name:<term>` with
first_line 0, whether or not the file is text.

Files containing a NUL byte are reported once with term `binary-not-scanned`.
A binary file with no NUL byte is decoded as text with replacement characters.
This is a text search. It finds names; it does not decide whether a match is
product material, a guard against it, or a coincidence. Pure and
deterministic for a given tree.
"""

import re
import sys

SKIP_CLASS = "adjacent surface"

# (term id, regex). Product names come from
# governance/commercial-product-licensing.json, AGENTS.md and the adjacent
# top-level directories found in part 1.
TERMS = [
    ("livesafe", r"live[-_ ]?safe"),
    ("cybermedica", r"cyber[-_ ]?medica"),
    ("commandbase", r"command[-_ ]?base"),
    ("crosschecked", r"cross[-_ ]?checked"),
    ("legaldyne", r"legal[-_ ]?dyne"),
    ("honorgood", r"honor[-_ ]?good"),
    ("exoforge", r"exo[-_ ]?forge"),
    ("heartfield", r"heartfield"),
    ("zerodentity", r"[0o]dentity"),
    ("archon", r"archon"),
    ("sybil-cli", r"sybil[-_]cli"),
    ("gap-incubator", r"gap[-_ ]incubator"),
    ("customer-zero", r"customer[-_ ]zero"),
    # Any form of the name, including the crate name `decision-forum`.
    ("decision-forum-name", r"decision[-. ]forum"),
    ("hipaa-phi", r"\bhipaa\b|\bphi\b|protected health"),
    # Names met while reading the first scan's hit sites.
    ("paperclip", r"paperclip"),
    ("apex-velocity", r"apex[-_ ]?velocity"),
    ("lynk", r"\blynk\b"),
    ("telegram", r"telegram"),
    # Names both reviewers found missing from the first two passes.
    ("vitallock", r"vital[-_ ]?lock"),
    ("syntaxis", r"syntaxis"),
    ("decision-forge", r"decision[-_ ]?forge"),
    ("cognitiveplane", r"cognitive[-_ ]?plane"),
    # References to adjacent top-level directories as paths.
    ("pathref:livesafe", r"(?<![A-Za-z0-9_-])livesafe/"),
    ("pathref:cybermedica", r"(?<![A-Za-z0-9_-])cybermedica/"),
    ("pathref:command-base", r"(?<![A-Za-z0-9_-])command-base/"),
    ("pathref:exoforge", r"(?<![A-Za-z0-9_-])exoforge/"),
    ("pathref:demo", r"(?<![A-Za-z0-9_-])demo/[A-Za-z0-9_.-]"),
    ("pathref:web", r"(?<![A-Za-z0-9_-])web/[A-Za-z0-9_.-]"),
    ("pathref:site", r"(?<![A-Za-z0-9_-])site/[A-Za-z0-9_.-]"),
    ("pathref:gap", r"(?<![A-Za-z0-9_-])gap/[A-Za-z0-9_.-]"),
    ("pathref:Initiatives", r"(?<![A-Za-z0-9_-])Initiatives/"),
]

COMPILED = [(tid, re.compile(rx, re.IGNORECASE)) for tid, rx in TERMS]


def main():
    tsv, root = sys.argv[1], sys.argv[2].rstrip("/\\")
    out = sys.stdout
    out.reconfigure(encoding="utf-8", newline="\n")
    out.write("path\tproposed_class\tterm\tmatches\tfirst_line\n")
    with open(tsv, encoding="utf-8") as handle:
        rows = [line.rstrip("\n").split("\t") for line in handle][1:]
    for path, cls in sorted((r[0], r[1]) for r in rows):
        if cls == SKIP_CLASS:
            continue
        for tid, rx in COMPILED:
            if not tid.startswith("pathref:") and rx.search(path):
                out.write(f"{path}\t{cls}\tpath-name:{tid}\t1\t0\n")
        with open(f"{root}/{path}", "rb") as handle:
            data = handle.read()
        if b"\x00" in data:
            out.write(f"{path}\t{cls}\tbinary-not-scanned\t1\t-\n")
            continue
        lines = data.decode("utf-8", errors="replace").split("\n")
        for tid, rx in COMPILED:
            count, first = 0, 0
            for number, line in enumerate(lines, 1):
                found = len(rx.findall(line))
                if found and not first:
                    first = number
                count += found
            if count:
                out.write(f"{path}\t{cls}\t{tid}\t{count}\t{first}\n")


if __name__ == "__main__":
    main()

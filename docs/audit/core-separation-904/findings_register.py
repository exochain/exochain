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
"""Check the findings register against the part records (part 7).

Usage:
    python -I findings_register.py <audit-directory>

Checks, and exits non-zero on any failure:

  1. every finding id (F-n) that has a summary-table row in parts 1-6
     appears exactly once in findings-register.tsv, and the register holds
     no other id;
  2. the `part` column names the part whose summary table defines the id;
  3. every disposition word is one of the repository's vocabulary
     (`patch`, `adjacent_patch`, `no_change`) or `pending`;
  4. the disposition words are compared with those in that part's
     summary-table row; a difference is printed as a note, not a failure,
     because the summary rows abbreviate the finding text (part 7 explains
     each note);
  5. `blocks` is one of cutover, release, claim, conditional, none, and
     every row that blocks carries a note; `owner_basis` says whether the
     owner is named in the part, inferred in part 7, or absent;
  6. every id in `linked` exists; every status is `open`;
  7. every SHA-256 digest that part 7 prints beside a table name
     (`<name>.tsv` followed by a 64-digit value) equals the digest of
     that file's bytes in the audit directory.

It checks form and agreement between files. It does not check that a
finding is true.
"""

import collections
import glob
import hashlib
import os
import re
import sys

VOCAB = {"patch", "adjacent_patch", "no_change", "pending"}
BLOCKS = {"cutover", "release", "claim", "conditional", "none"}
BASIS = {"named in the part", "inferred in part 7", "none"}
ROW = re.compile(r"^\| (F-\d+) \|(.*)$")
DIGEST = re.compile(r"`([A-Za-z0-9_.-]+\.tsv)`[^`\n]{0,20}`([0-9a-f]{64})`")
PART7 = "07-FINDINGS-REGISTER.md"


def part_rows(directory):
    found = {}
    for name in sorted(glob.glob(os.path.join(directory, "0[1-6]-*.md"))):
        part = int(os.path.basename(name)[:2])
        with open(name, encoding="utf-8") as handle:
            for line in handle:
                match = ROW.match(line)
                if match:
                    if match.group(1) in found:
                        raise SystemExit(f"{match.group(1)} has two summary rows")
                    found[match.group(1)] = (part, match.group(2))
    return found


def digest_errors(directory):
    with open(os.path.join(directory, PART7), encoding="utf-8") as handle:
        printed = DIGEST.findall(handle.read())
    errors = []
    if not printed:
        errors.append(f"{PART7}: no table digests found")
    for name, value in printed:
        try:
            with open(os.path.join(directory, name), "rb") as handle:
                actual = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            errors.append(f"{name}: named in {PART7} but not readable")
            continue
        if actual != value:
            errors.append(f"{name}: {PART7} prints {value}, file is {actual}")
    return errors, len(printed)


def main():
    directory = sys.argv[1]
    defined = part_rows(directory)
    errors, notes = [], []
    seen = collections.Counter()
    rows = []
    with open(os.path.join(directory, "findings-register.tsv"), encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        for line in handle:
            cells = line.rstrip("\n").split("\t")
            if len(cells) != len(header):
                errors.append(f"wrong column count: {cells[0]}")
                continue
            rows.append(dict(zip(header, cells)))
    ids = {row["id"] for row in rows}
    for row in rows:
        fid = row["id"]
        seen[fid] += 1
        if fid not in defined:
            errors.append(f"{fid}: not defined in parts 1-6")
            continue
        part, text = defined[fid]
        if str(part) != row["part"]:
            errors.append(f"{fid}: part {row['part']} but defined in part {part}")
        words = {w.strip() for w in row["proposed_disposition"].split(";")}
        if not words <= VOCAB:
            errors.append(f"{fid}: disposition outside vocabulary: {sorted(words - VOCAB)}")
        in_part = set(re.findall(r"`(patch|adjacent_patch|no_change)`", text))
        if re.search(r"[Pp]ending", text):
            in_part.add("pending")
        if words != in_part:
            notes.append(f"{fid}: register {sorted(words)} / part {part} row {sorted(in_part)}")
        if row["blocks"] not in BLOCKS:
            errors.append(f"{fid}: blocks value {row['blocks']}")
        if row["owner_basis"] not in BASIS:
            errors.append(f"{fid}: owner_basis {row['owner_basis']}")
        if (row["owner_basis"] == "none") != row["decision_owner"].startswith("not named"):
            errors.append(f"{fid}: owner and owner_basis disagree")
        if row["blocks"] != "none" and not row["blocking_note"]:
            errors.append(f"{fid}: blocks without a note")
        for link in filter(None, (x.strip() for x in row["linked"].split(";"))):
            if link not in ids:
                errors.append(f"{fid}: linked id {link} not in register")
        if row["status"] != "open":
            errors.append(f"{fid}: status {row['status']}")
    for fid in defined:
        if seen[fid] != 1:
            errors.append(f"{fid}: appears {seen[fid]} times in the register")
    digest_failures, digest_count = digest_errors(directory)
    errors.extend(digest_failures)
    print("digests checked", digest_count)
    by_block = collections.Counter(row["blocks"] for row in rows)
    by_area = collections.Counter(row["area"] for row in rows)
    print("owner_basis", dict(sorted(collections.Counter(row["owner_basis"] for row in rows).items())))
    print("findings", len(rows), "defined", len(defined))
    print("blocks", dict(sorted(by_block.items())))
    print("area", dict(sorted(by_area.items())))
    for note in notes:
        print("note", note)
    for error in errors:
        print("ERROR", error)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()

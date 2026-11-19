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
"""Reference counts for the issue #904 audit (part 6, F-47).

Usage:
    python -I reference_counts.py <repo> <commit> <path-classification.tsv>

Reads, at <commit>, every file part 1 proposes as EXOCHAIN core or core
runtime adapter that decodes as UTF-8, and writes `name<TAB>value` rows on
stdout:

  files_read, files_skipped_not_utf8
  commit_refs          file-level references: for each file, each distinct
                       40-digit lower-case hex string that is a commit
                       reachable from <commit>
  commit_ref_files     files with at least one such reference
  commit_refs_in:<dir> the same count by first two path components
  other_strings:<type> the remaining distinct 40-digit strings, by the type
                       of the object they name in the local clone (`commit`,
                       `tag`, `tree`, `blob`) or `missing`
  links:<kind>         links to github.com/exochain/exochain by the path
                       segment that follows (`pull`, `issues`, ...), or
                       `repo-root` when none of the known segments follows
  link_files           files with at least one such link

The `commit_refs` rows depend only on <commit>. The `other_strings` rows
depend on which other objects the local clone holds (other branches, tags,
fetched pull requests), so they can differ between clones. A 40-digit
string is tested as an object name only; nothing says the author meant a
git object. File contents are read from the commit, not the working tree.
"""

import collections
import re
import subprocess
import sys

CLASSES = ("EXOCHAIN core", "core runtime adapter")
HEX40 = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
LINK = re.compile(
    r"github\.com/exochain/exochain(?:\.git)?"
    r"(/(issues|pull|blob|tree|commit|releases|actions|compare|discussions)\b)?",
    re.IGNORECASE,
)


def git(repo, *args, data=None):
    return subprocess.run(["git", "--no-pager", "-C", repo, *args], input=data,
                          check=True, capture_output=True).stdout


def blobs(repo, commit, paths):
    """Yield (path, bytes) for each path at the commit, using one git process."""
    request = "".join(f"{commit}:{path}\n" for path in paths).encode("utf-8")
    out = git(repo, "cat-file", "--batch", data=request)
    pos = 0
    for path in paths:
        end = out.index(b"\n", pos)
        header = out[pos:end].split()
        pos = end + 1
        if header[-1] == b"missing":
            raise SystemExit(f"not in {commit}: {path}")
        size = int(header[2])
        yield path, out[pos:pos + size]
        pos += size + 1


def main():
    repo, commit, classes_path = sys.argv[1:4]
    with open(classes_path, encoding="utf-8") as handle:
        next(handle)
        paths = sorted(cols[0] for cols in (line.rstrip("\n").split("\t") for line in handle)
                       if cols[1] in CLASSES)
    reachable = set(git(repo, "rev-list", commit).decode("ascii").split())
    refs = collections.Counter()
    other = set()
    links = collections.Counter()
    link_files = set()
    read = skipped = 0
    for path, data in blobs(repo, commit, paths):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        read += 1
        for value in set(HEX40.findall(text)):
            if value in reachable:
                refs[path] += 1
            else:
                other.add(value)
        for match in LINK.finditer(text):
            links[(match.group(2) or "repo-root").lower()] += 1
            link_files.add(path)
    types = collections.Counter()
    if other:
        ordered = sorted(other)
        checked = git(repo, "cat-file", "--batch-check",
                      data=("\n".join(ordered) + "\n").encode("ascii")).decode("ascii")
        for line in checked.splitlines():
            types[line.split()[1]] += 1
    by_dir = collections.Counter()
    for path, count in refs.items():
        by_dir["/".join(path.split("/")[:2])] += count
    rows = [("files_read", read), ("files_skipped_not_utf8", skipped),
            ("commit_refs", sum(refs.values())), ("commit_ref_files", len(refs))]
    rows += [(f"commit_refs_in:{name}", count) for name, count in sorted(by_dir.items())]
    rows += [(f"other_strings:{name}", count) for name, count in sorted(types.items())]
    rows += [(f"links:{name}", count) for name, count in sorted(links.items())]
    rows.append(("link_files", len(link_files)))
    for name, value in rows:
        print(f"{name}\t{value}")


if __name__ == "__main__":
    main()

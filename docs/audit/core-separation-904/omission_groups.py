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
"""Group the part 1 path table into proposed omissions (part 7).

Usage:
    python -I omission_groups.py <path-classification.tsv> <out.tsv>

Every tracked path at the audited commit falls into exactly one handling:

  omit-tree      the path lies in a product tree proposed to stay in the
                 legacy repository as a whole (both adjacent-class and
                 vendor-class paths inside it)
  omit-file      an adjacent-class path inside a directory that is otherwise
                 proposed to be copied
  pending        a path whose inclusion a named panel decision settles
  undecided      tracked generated output for which parts 1-6 make no proposal
  copy           everything else (not written to the output)

The output has one row per group. Membership is by path prefix plus the
proposed class, so the per-path list can be rebuilt from the part 1 table.
Nothing here has been carried out: these are proposals for the panel.
"""

import collections
import re
import sys

ADJACENT = "adjacent surface"
TREES = ("livesafe", "cybermedica", "command-base", "demo", "exoforge", "site", "web", "gap")
FILE_GROUPS = (".archon/", ".claude/", ".cursor/", ".superpowers/", ".github/workflows/",
               ".github/ISSUE_TEMPLATE/", "docs/commandbase-foundation/", "docs/heartfield/",
               "docs/decision-forum/", "scripts/", "tools/sybil-cli/")
DIST = re.compile(r"^packages/[^/]+/dist(-test)?/")


def handling(path, cls):
    top = path.split("/", 1)[0]
    if "/" in path and top in TREES:
        return "omit-tree", top + "/"
    if cls == ADJACENT:
        for prefix in FILE_GROUPS:
            if path.startswith(prefix):
                return "omit-file", prefix
        return "omit-file", "UNGROUPED"
    if path.startswith("tools/syntaxis/"):
        return "pending", "tools/syntaxis/"
    if DIST.match(path):
        return "undecided", "/".join(path.split("/")[:3]) + "/"
    return "copy", ""


def main():
    src, out = sys.argv[1:3]
    groups = collections.defaultdict(collections.Counter)
    totals = collections.Counter()
    with open(src, encoding="utf-8") as handle:
        next(handle)
        for line in handle:
            path, cls = line.rstrip("\n").split("\t")[:2]
            how, group = handling(path, cls)
            totals[how] += 1
            if how != "copy":
                groups[(how, group)][cls] += 1
    if any(group == "UNGROUPED" for _, group in groups):
        sys.exit("adjacent-class path outside every listed group")
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("handling\tgroup\tpaths\tby_class\n")
        for (how, group), counts in sorted(groups.items()):
            by_class = "; ".join(f"{k} {v}" for k, v in sorted(counts.items()))
            handle.write(f"{how}\t{group}\t{sum(counts.values())}\t{by_class}\n")
    print(dict(sorted(totals.items())), "total", sum(totals.values()))


if __name__ == "__main__":
    main()

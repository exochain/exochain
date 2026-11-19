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
"""Per-subtree summary of license-inventory.tsv (issue #904 audit, part 4).

Usage: license_by_subtree.py <license-inventory.tsv>

A subtree is `crates/<name>`, `packages/<name>`, `tools/<name>` for tool
directories, the first directory otherwise, or `(root files)`. Paths are
grouped by subtree and part 1 class. Writes a tab-separated list on stdout.

Columns: subtree, proposed_class, paths, apache_header, spdx_only,
proprietary_marker, none_eligible, none_excluded, none_unsupported, binary,
nearest_license (distinct values, comma-separated),
declared (distinct manifest licence fields, comma-separated).

Counts statements detected by license_inventory.py. It does not decide what
licence applies. Pure and deterministic for a given input.
"""

import collections
import sys

TWO_LEVEL = ("crates", "packages")


def subtree(path):
    parts = path.split("/")
    if len(parts) == 1:
        return "(root files)"
    if parts[0] in TWO_LEVEL and len(parts) > 2:
        return "/".join(parts[:2])
    if parts[0] == "tools" and len(parts) > 2:
        return "/".join(parts[:2])
    if parts[0] == "tools":
        return "tools (top-level files)"
    return parts[0]


def bucket(header, tool):
    if header == "apache-header":
        return "apache_header"
    if header == "binary":
        return "binary"
    if header.startswith("spdx:Apache"):
        return "spdx_only"
    if header == "proprietary" or header.startswith("spdx:"):
        return "proprietary_marker"
    return {"eligible": "none_eligible", "excluded": "none_excluded"}.get(tool, "none_unsupported")


COLS = ("apache_header", "spdx_only", "proprietary_marker", "none_eligible", "none_excluded", "none_unsupported", "binary")


def main():
    with open(sys.argv[1], encoding="utf-8") as handle:
        rows = [line.rstrip("\n").split("\t") for line in handle][1:]
    counts = collections.defaultdict(collections.Counter)
    near = collections.defaultdict(set)
    decl = collections.defaultdict(set)
    for path, cls, nearest, header, tool, declared, _other in rows:
        key = (subtree(path), cls)
        counts[key][bucket(header, tool)] += 1
        near[key].add("(self)" if nearest == path else nearest)
        if declared != "-":
            decl[key].add(declared)
    out = sys.stdout
    out.reconfigure(encoding="utf-8", newline="\n")
    out.write("subtree\tproposed_class\tpaths\t" + "\t".join(COLS) + "\tnearest_license\tdeclared\n")
    for key in sorted(counts):
        c = counts[key]
        out.write(
            f"{key[0]}\t{key[1]}\t{sum(c.values())}\t"
            + "\t".join(str(c[col]) for col in COLS)
            + f"\t{', '.join(sorted(near[key]))}\t{', '.join(sorted(decl[key])) or '-'}\n"
        )


if __name__ == "__main__":
    main()

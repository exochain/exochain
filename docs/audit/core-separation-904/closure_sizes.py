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
"""Closure sizes for the issue #904 audit (part 2).

Usage:
    python -I closure_sizes.py <workspace-dependency-edges.tsv> \
        <path-classification.tsv>

Walks the declared edges of the first table transitively and writes a
tab-separated table on stdout: one row per workspace crate that has an
edge, with its part 1 class and the number of other workspace crates it
reaches in three closures, then three `#union` rows for the closures taken
from all core-class crates together (the roots are counted).

  native_hard     normal edges that are not optional, including edges
                  declared for a native target only
  native_default  those, plus the optional edges (part 2 shows that each
                  is enabled by a default feature of the declaring crate)
  wasm_hard       normal edges that are neither optional nor declared for
                  a target

Dev edges are never followed. A crate's class is the class part 1 proposes
for its `crates/<dir>/Cargo.toml`.

Declared edges only: this does not prove what the compiler links. Pure and
deterministic for given inputs.
"""

import collections
import sys

CORE, ADAPTER = "EXOCHAIN core", "core runtime adapter"
CLOSURES = ("native_hard", "native_default", "wasm_hard")


def reach(graph, roots):
    seen, todo = set(), list(roots)
    while todo:
        for nxt in graph[todo.pop()]:
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return seen


def main():
    edges_path, classes_path = sys.argv[1:3]
    graphs = {name: collections.defaultdict(set) for name in CLOSURES}
    crates = set()
    with open(edges_path, encoding="utf-8") as handle:
        next(handle)
        for line in handle:
            src, dst, kind, optional, _gate, target = line.rstrip("\n").split("\t")
            crates.update((src, dst))
            if kind != "normal":
                continue
            graphs["native_default"][src].add(dst)
            if optional == "no":
                graphs["native_hard"][src].add(dst)
                if target == "-":
                    graphs["wasm_hard"][src].add(dst)
    klass = {}
    with open(classes_path, encoding="utf-8") as handle:
        next(handle)
        for line in handle:
            path, proposed = line.split("\t")[:2]
            parts = path.split("/")
            if len(parts) == 3 and parts[0] == "crates" and parts[2] == "Cargo.toml":
                klass[parts[1]] = proposed
    missing = sorted(crates - set(klass))
    if missing:
        raise SystemExit(f"no class for: {missing}")
    print("crate\tproposed_class\t" + "\t".join(CLOSURES))
    for crate in sorted(crates):
        sizes = [len(reach(graphs[name], [crate]) - {crate}) for name in CLOSURES]
        print(f"{crate}\t{klass[crate]}\t" + "\t".join(map(str, sizes)))
    core = sorted(c for c in crates if klass[c] == CORE)
    for name in CLOSURES:
        closure = reach(graphs[name], core) | set(core)
        adapters = sorted(c for c in closure if klass[c] == ADAPTER)
        print(f"#union\t{name}\troots={len(core)}\tcrates={len(closure)}\t"
              f"adapter={','.join(adapters) or '-'}")


if __name__ == "__main__":
    main()

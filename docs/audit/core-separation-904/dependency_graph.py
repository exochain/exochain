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
"""Workspace dependency edges for the issue #904 audit (part 2).

Reads `cargo metadata --no-deps --format-version 1` JSON on stdin and writes a
tab-separated edge list on stdout: one row per declared dependency from one
workspace package to another.

Columns: from_dir, to_dir, kind (normal|dev|build), optional (yes|no),
gated_by (features of the dependent crate that enable an optional edge, or -),
target (the `cfg` expression of a target-specific dependency table, or -).

Declared edges only: this does not prove what the compiler links, and it does
not see `#[cfg]` gates inside source files. Pure and deterministic.
"""

import json
import sys


def crate_dir(manifest_path):
    parts = manifest_path.replace("\\", "/").split("/")
    return parts[-2]


def main():
    meta = json.load(sys.stdin)
    by_name = {p["name"]: crate_dir(p["manifest_path"]) for p in meta["packages"]}
    rows = set()
    for pkg in meta["packages"]:
        src = crate_dir(pkg["manifest_path"])
        for dep in pkg["dependencies"]:
            if dep["name"] not in by_name or dep.get("path") is None:
                continue
            key = dep.get("rename") or dep["name"]
            gates = sorted(
                feat
                for feat, items in pkg["features"].items()
                if any(i in (key, f"dep:{key}") or i.startswith(f"{key}/") for i in items)
            )
            optional = "yes" if dep["optional"] else "no"
            rows.add(
                (
                    src,
                    by_name[dep["name"]],
                    dep["kind"] or "normal",
                    optional,
                    ",".join(gates) if dep["optional"] and gates else "-",
                    dep.get("target") or "-",
                )
            )
    out = sys.stdout
    out.reconfigure(encoding="utf-8", newline="\n")
    out.write("from_dir\tto_dir\tkind\toptional\tgated_by\ttarget\n")
    for row in sorted(rows):
        out.write("\t".join(row) + "\n")


if __name__ == "__main__":
    main()

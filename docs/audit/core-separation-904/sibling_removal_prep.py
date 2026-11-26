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
"""Inputs for the sibling-removal experiment of the issue #904 audit (part 5).

Usage:
    python -I sibling_removal_prep.py <path-classification.tsv> <ci.yml> \
        <removal-list-out> <guard-list-out>

Writes two files:

  removal list: every path part 1 proposes as `adjacent surface`, plus every
      `third-party/vendor` path under the six product trees named in
      PRODUCT_TREES, sorted, one per line.
  guard list: one row per `ci.yml` line that ends in a single
      `bash tools/...` or `python3 tools/...` command, as
      `<ci.yml line>\t<command>`. Lines naming a helper in SKIP are left
      out: they are not guards, or they need a release context. A command
      that ci.yml runs on several lines is listed once per line.

Both follow part 1's proposed boundary. A different boundary gives a
different removal list. Pure and deterministic for given inputs.
"""

import re
import sys

PRODUCT_TREES = {"command-base", "cybermedica", "demo", "livesafe", "site", "web"}
SKIP = ("ci_cargo_retry", "write_ci_candidate", "test_release_npm_runtime_contract",
        "--token-contract", "prepare_wasm_npm_package")
COMMAND = re.compile(r"((?:bash|python3?(?: -[A-Za-z]+)*) tools/[A-Za-z0-9_.-]+(?: --[a-z-]+)?)\s*$")


def main():
    tsv, ci, out_remove, out_guards = sys.argv[1:5]
    with open(tsv, encoding="utf-8") as handle:
        rows = [line.rstrip("\n").split("\t") for line in handle][1:]
    remove = [r[0] for r in rows
              if r[1] == "adjacent surface"
              or (r[1] == "third-party/vendor" and r[0].split("/")[0] in PRODUCT_TREES)]
    with open(out_remove, "w", encoding="utf-8", newline="\n") as out:
        out.write("\n".join(sorted(remove)) + "\n")
    guards = []
    with open(ci, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            match = COMMAND.search(line)
            if match and not any(word in line for word in SKIP):
                guards.append(f"{number}\t{match.group(1)}")
    with open(out_guards, "w", encoding="utf-8", newline="\n") as out:
        out.write("\n".join(guards) + "\n")
    print(len(remove), "paths to remove;", len(guards), "guard commands")


if __name__ == "__main__":
    main()

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
"""Licence and notice inventory for the issue #904 audit (part 4).

Usage: license_inventory.py <path-classification.tsv> <repo-root>

For every path in part 1's classification, record what the file itself and
its surroundings say about its licence. Writes a tab-separated list on stdout.

Columns:
  path, proposed_class,
  nearest_license   nearest tracked ancestor-directory file named LICENSE*,
                    COPYING* or NOTICE* ("-" if none; the file itself if it
                    is one)
  header            what the first 80 lines carry:
                      apache-header   the repository's Copyright line and
                                      the Apache-2.0 SPDX line
                      spdx:<id>       some other SPDX identifier
                      apache-text     Apache grant wording, no SPDX line
                      proprietary     "Proprietary and Confidential" or
                                      "UNLICENSED"
                      none            none of the above
                      binary          file contains a NUL byte
  header_tool       how tools/license_headers.py treats the path:
                      eligible, excluded, unsupported-type
  declared          for Cargo.toml / package.json / pyproject.toml, the
                    licence field as written ("-" otherwise)
  other_copyright   first copyright line in the first 80 lines that does
                    not name Exochain Foundation ("-" if none)

This reports what files say. It does not decide what licence applies to a
file, and a header is not proof of a right to grant it. Pure and
deterministic for a given tree.
"""

import json
import re
import sys

COPYRIGHT_LINE = "Copyright 2026 Exochain Foundation"
SPDX_APACHE = "SPDX-License-Identifier: Apache-2.0"

# Mirrors tools/license_headers.py at the audited commit.
EXCLUDED_PREFIXES = (
    "coverage/",
    "demo/coverage/",
    "demo/apps/livesafe/",
    "livesafe/",
    "cybermedica/",
    "command-base/",
    "packages/exochain-sdk/dist/",
    "packages/exochain-sdk/dist-test/",
)
EXCLUDED_SUFFIXES = (".lock", ".map", ".pdf", ".png", ".jpg", ".jpeg", ".zip", ".typed")
SUPPORTED_SUFFIXES = (
    ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs",
    ".py", ".sh", ".toml", ".yml", ".yaml", ".service",
    ".md", ".html", ".svg", ".xml", ".css", ".sql", ".tla",
)
SUPPORTED_NAMES = ("Dockerfile", "CODEOWNERS", ".dockerignore", ".env.example", ".gitignore", ".npmrc")

# Upper-case names only, so `license-boundary.test.mjs` is not a licence file.
LICENSE_NAME = re.compile(r"^(LICEN[SC]E|COPYING|NOTICE)([.-][A-Za-z0-9.-]*)?$")
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([^\s*<>\"']+(?:\s+(?:WITH|OR|AND)\s+[^\s*<>\"']+)*)")
COPYRIGHT_RE = re.compile(r"copyright\s+(?:\(c\)|©|\d{4})", re.IGNORECASE)
CARGO_LICENSE_RE = re.compile(r"^\s*(license(?:\.workspace|-file)?)\s*=\s*(.+?)\s*$", re.MULTILINE)


def header_tool(path):
    name = path.rsplit("/", 1)[-1]
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name[1:] else ""
    if (
        name == "LICENSE"
        or (path.startswith("demo/") and not path.startswith("demo/packages/exochain-wasm/"))
        or path.startswith(EXCLUDED_PREFIXES)
        or path.endswith(EXCLUDED_SUFFIXES)
    ):
        return "excluded"
    if name.startswith("Dockerfile") or name in SUPPORTED_NAMES or suffix in SUPPORTED_SUFFIXES:
        return "eligible"
    return "unsupported-type"


def nearest_license(path, license_files):
    name = path.rsplit("/", 1)[-1]
    if LICENSE_NAME.match(name):
        return path
    parts = path.split("/")[:-1]
    while True:
        directory = "/".join(parts)
        if directory in license_files:
            return license_files[directory]
        if not parts:
            return "-"
        parts.pop()


def declared(path, text):
    name = path.rsplit("/", 1)[-1]
    if name == "package.json":
        try:
            value = json.loads(text).get("license")
        except (ValueError, AttributeError):
            return "unparsed"
        return "absent" if value is None else json.dumps(value, sort_keys=True)
    if name in ("Cargo.toml", "pyproject.toml"):
        found = CARGO_LICENSE_RE.findall(text)
        if not found:
            return "absent"
        return "; ".join(f"{key} = {value}" for key, value in found)
    return "-"


def main():
    tsv, root = sys.argv[1], sys.argv[2].rstrip("/\\")
    out = sys.stdout
    out.reconfigure(encoding="utf-8", newline="\n")
    with open(tsv, encoding="utf-8") as handle:
        rows = sorted((r[0], r[1]) for r in (line.rstrip("\n").split("\t") for line in handle.readlines()[1:]))
    license_files = {}
    for path, _cls in rows:
        name = path.rsplit("/", 1)[-1]
        if LICENSE_NAME.match(name):
            directory = path.rsplit("/", 1)[0] if "/" in path else ""
            license_files.setdefault(directory, path)
    out.write("path\tproposed_class\tnearest_license\theader\theader_tool\tdeclared\tother_copyright\n")
    for path, cls in rows:
        with open(f"{root}/{path}", "rb") as handle:
            data = handle.read()
        near = nearest_license(path, license_files)
        tool = header_tool(path)
        if b"\x00" in data:
            out.write(f"{path}\t{cls}\t{near}\tbinary\t{tool}\t-\t-\n")
            continue
        text = data.decode("utf-8", errors="replace")
        head_lines = text.splitlines()[:80]
        head = "\n".join(head_lines)
        spdx = SPDX_RE.search(head)
        if COPYRIGHT_LINE in head and SPDX_APACHE in head:
            header = "apache-header"
        elif spdx:
            header = "spdx:" + spdx.group(1)
        elif "Licensed under the Apache License" in head:
            header = "apache-text"
        elif "Proprietary and Confidential" in head or "UNLICENSED" in head:
            header = "proprietary"
        else:
            header = "none"
        other = "-"
        for line in head_lines:
            if COPYRIGHT_RE.search(line) and "Exochain Foundation" not in line:
                other = " ".join(line.split())[:120]
                break
        out.write(f"{path}\t{cls}\t{near}\t{header}\t{tool}\t{declared(path, text)}\t{other}\n")


if __name__ == "__main__":
    main()

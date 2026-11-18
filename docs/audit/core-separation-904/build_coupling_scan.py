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
"""Path references in build, CI and deployment files (issue #904 audit, part 5).

Usage: build_coupling_scan.py <path-classification.tsv> <repo-root>

Sources scanned (tracked, not proposed as adjacent by part 1):
  - `.github/workflows/*`
  - files named Dockerfile*, docker-compose*, .dockerignore, railway.json
  - everything under `deploy/` and `.cargo/`
  - root `Cargo.toml`, `tarpaulin.toml`, `deny.toml`, `rustfmt.toml`
  - `build.rs` files
  - `tools/` files whose path appears in a workflow (source kind
    `ci-invoked-tool`), one level only

For each source line, every token of path characters is tested against the
tracked path list: an exact tracked file, or a tracked directory (with or
without a trailing slash). A leading `./` is dropped. A token without a slash
is reported only when it names a top-level directory that holds adjacent
paths, and is marked `bare`: such a match can be an ordinary word.

Writes tab-separated rows on stdout:
source, source_class, source_kind, line, token, match (file|dir|bare),
target_classes (distinct part 1 classes under the target, `;`-separated).

A row says the text names a path. It does not say the path is read, built or
required at run time. Pure and deterministic for a given tree.
"""

import collections
import os
import re
import sys

TOKEN = re.compile(r"[A-Za-z0-9_.@/-]+")
ROOT_FILES = ("Cargo.toml", "tarpaulin.toml", "deny.toml", "rustfmt.toml")
ADJ = "adjacent surface"


def kind(path):
    name = path.rsplit("/", 1)[-1]
    if path.startswith(".github/workflows/"):
        return "workflow"
    if name.startswith("Dockerfile") or name == ".dockerignore":
        return "docker"
    if name.startswith("docker-compose"):
        return "compose"
    if name == "railway.json":
        return "railway"
    if path.startswith("deploy/"):
        return "deploy"
    if path.startswith(".cargo/") or path in ROOT_FILES:
        return "cargo-config"
    if name == "build.rs":
        return "build-script"
    return None


def read(root, path):
    try:
        with open(os.path.join(root, path), encoding="utf-8") as handle:
            return handle.read().split("\n")
    except (UnicodeDecodeError, OSError):
        return []


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
    bare = {d for d, cs in dirs.items() if "/" not in d and ADJ in cs}

    sources = {p: kind(p) for p in cls if kind(p) and cls[p] != ADJ}
    workflow_text = "\n".join(
        "\n".join(read(root, p)) for p in sorted(sources) if sources[p] == "workflow"
    )
    for token in set(TOKEN.findall(workflow_text)):
        token = token[2:] if token.startswith("./") else token
        if token.startswith("tools/") and token in cls and cls[token] != ADJ:
            sources.setdefault(token, "ci-invoked-tool")

    out = sys.stdout
    out.reconfigure(encoding="utf-8", newline="\n")
    out.write("source\tsource_class\tsource_kind\tline\ttoken\tmatch\ttarget_classes\n")
    for src in sorted(sources):
        for number, line in enumerate(read(root, src), 1):
            seen = set()
            for token in TOKEN.findall(line):
                token = token[2:] if token.startswith("./") else token
                token = token.rstrip("/.") or token
                if token in seen or token == src:
                    continue
                if token in cls:
                    match, classes = "file", {cls[token]}
                elif "/" in token and token in dirs:
                    match, classes = "dir", dirs[token]
                elif token in bare:
                    match, classes = "bare", dirs[token]
                else:
                    continue
                seen.add(token)
                out.write(
                    f"{src}\t{cls[src]}\t{sources[src]}\t{number}\t{token}\t{match}\t"
                    f"{';'.join(sorted(classes))}\n"
                )


if __name__ == "__main__":
    main()

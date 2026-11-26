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
"""Path classifier for the issue #904 clean-separation audit (part 1).

Reads a newline-delimited list of tracked paths on stdin (the output of
`git ls-tree -r --name-only <commit>`) and writes a tab-separated inventory on
stdout: path, proposed class, basis, rule id, flags.

Classification order:
  1. Exact-path precedent from governance/releases/v0.2.6/PATH-CLASSIFICATION.md
     (passed as argv[1]); rule id P0, basis precedent-exact.
  2. The ordered RULES table below; the first matching rule wins.

The output is a proposed partition under the five AGENTS.md classes. It does
not decide what moves to the new core repository.

Pure and deterministic: no clock, no network, no randomness, sorted output.
"""

import re
import sys

CORE = "EXOCHAIN core"
ADAPTER = "core runtime adapter"
ADJACENT = "adjacent surface"
IMPORTED = "imported evidence"
VENDOR = "third-party/vendor"
CLASSES = (CORE, ADAPTER, ADJACENT, IMPORTED, VENDOR)

# Basis vocabulary:
#   precedent-exact   this exact path is classified in the v0.2.6 inventory
#   precedent-family  an in-repo record classifies the directory or family the
#                     path belongs to; extending it to this path is this
#                     audit's inference
#   rule              the AGENTS.md class definition names this kind of path
#   judgment          this audit's call
# Everything except precedent-exact needs panel confirmation.
PX, PF, RULE, JUDG = "precedent-exact", "precedent-family", "rule", "judgment"

# (rule id, regex, class, basis, flags)
RULES = [
    # --- generated and locked dependency records (v0.2.6 convention) ---
    ("V1", r"(^|/)(Cargo\.lock|package-lock\.json)$", VENDOR, PF, ""),
    ("V2", r"^tools/python-release-requirements\.lock$", VENDOR, PF, ""),
    ("V3", r"^packages/[^/]+/(dist|dist-test)/", VENDOR, PF, "generated"),
    ("V4", r"^demo/coverage/", VENDOR, JUDG, "generated"),
    # --- adjacent product subtrees ---
    ("A1", r"^livesafe/", ADJACENT, PF, "product:livesafe"),
    ("A2", r"^cybermedica/", ADJACENT, PF, "product:cybermedica"),
    ("A3", r"^command-base/", ADJACENT, PF, "product:commandbase"),
    ("A4", r"^demo/", ADJACENT, PF, "product:demo"),
    ("A5", r"^exoforge/", ADJACENT, PF, "product:exoforge"),
    ("A6", r"^\.archon/", ADJACENT, PF, "agent-artifact"),
    ("A7", r"^site/", ADJACENT, RULE, "website"),
    ("A8", r"^web/", ADJACENT, JUDG, "product:decision-forum"),
    ("A9", r"^gap/", ADJACENT, JUDG, "product:gap-incubator"),
    ("A10", r"^docs/commandbase-foundation/", ADJACENT, JUDG, "product:commandbase"),
    ("A11", r"^docs/heartfield/", ADJACENT, PF, "product:heartfield"),
    ("A12", r"^docs/decision-forum/", ADJACENT, JUDG, "product:decision-forum"),
    ("A13", r"^scripts/livesafe-", ADJACENT, JUDG, "product:livesafe"),
    ("A14", r"^\.github/workflows/livesafe-", ADJACENT, JUDG, "product:livesafe"),
    ("A15", r"^\.github/(workflows/exoforge-|ISSUE_TEMPLATE/)", ADJACENT, PF, "product:exoforge"),
    ("A16", r"^\.(claude|cursor|superpowers)/", ADJACENT, JUDG, "agent-artifact"),
    ("A17", r"^tools/sybil-cli/", ADJACENT, JUDG, "product:decision-forum"),
    # --- core runtime adapters ---
    ("R1", r"^crates/(exo-api|exo-gateway|exo-node|exochain-sdk|exochain-wasm)/", ADAPTER, PF, ""),
    ("R2", r"^crates/exo-dag-db-[^/]+/", ADAPTER, PF, ""),
    ("R3", r"^packages/", ADAPTER, PF, ""),
    ("R4", r"^\.github/workflows/retire-", ADAPTER, JUDG, ""),
    ("R5", r"^(Dockerfile|railway\.json|init-db\.sh|docker-compose[^/]*\.yml|\.dockerignore|\.env\.example)$", ADAPTER, RULE, "deployment"),
    ("R6", r"^deploy/", ADAPTER, RULE, "deployment"),
    ("R7", r"^artifacts/trust/", ADAPTER, JUDG, "deployment;trust-bundle"),
    ("C3p", r"^tools/test_(livesafe|commandbase|heartfield|demo)_[^/]*$", CORE, PF, "product-guard"),
    ("R8", r"^tools/[^/]*(release|publish|recover|retire|transport|cratesio|sbom|sealed|stage_llm)[^/]*$", ADAPTER, PF, ""),
    ("R8b", r"^tools/[^/]*(wasm_npm|railway|docker|deployment|live_node|public_exochain_route|public_route|root-trust|root_trust|avc_emit|avc_rfc3161|llm_usage)[^/]*$", ADAPTER, JUDG, ""),
    ("R9", r"^docs/guides/", ADAPTER, PF, ""),
    ("R9b", r"^docs/(dagdb|reference)/", ADAPTER, JUDG, ""),
    ("R10", r"^INTEGRATION\.md$", ADAPTER, JUDG, ""),
    # --- EXOCHAIN core ---
    ("C1", r"^crates/", CORE, PF, ""),
    ("C2", r"^fuzz/", CORE, PF, ""),
    ("C2b", r"^(tla|tests)/", CORE, JUDG, ""),
    ("C3", r"^tools/(cross-impl-test/|test_[^/]*$)", CORE, PF, ""),
    ("C3b", r"^tools/", CORE, JUDG, ""),
    ("C4", r"^governance/releases/", CORE, PF, ""),
    ("C4b", r"^governance/", CORE, RULE, ""),
    ("C5", r"^docs/(audit|superpowers)/", CORE, PF, ""),
    ("C5b", r"^docs/", CORE, JUDG, ""),
    ("C6", r"^\.github/", CORE, JUDG, "ci-governance"),
    ("C7", r"^\.cargo/audit\.toml$", CORE, PF, ""),
    ("C7b", r"^(\.cargo|\.exochain)/", CORE, JUDG, ""),
    ("C8", r"^Initiatives/", CORE, PF, "agent-artifact"),
    ("C8b", r"^agents/", CORE, JUDG, "agent-artifact"),
    ("C9", r"^[^/]+$", CORE, JUDG, ""),
]

# Product-name fingerprints. Matched case-insensitively against the full
# repository-relative path (directories included), on paths not proposed as
# adjacent. Names only; content fingerprints are part 3 of the audit.
NAME_FINGERPRINTS = [
    ("livesafe", r"livesafe"),
    ("crosschecked", r"crosschecked"),
    ("commandbase", r"command[-_]?base"),
    ("cybermedica", r"cybermedica"),
    ("exoforge", r"exoforge"),
    ("zerodentity", r"zerodentity|0dentity"),
    ("honorgood", r"honor[-_]?good|(^|[/_-])hg[-_]"),
    ("catapult", r"catapult"),
    ("heartfield", r"heartfield"),
    ("archon", r"archon"),
]

# Boundary flags. Matched against the full path of every row, whatever its
# class. Issue #904 names the Decision Forum/workflow and economy boundaries;
# catapult and consensus are this audit's additions.
BOUNDARY_FINGERPRINTS = [
    ("boundary:decision-forum", r"decision[-_.]?forum|^crates/exo-consensus/|^web/|^tools/sybil-cli/"),
    ("boundary:workflow", r"syntaxis"),
    ("boundary:economy", r"econom|honor[-_]?good|settlement|(^|[/_-])hg[-_]|^\.exochain/|commercial-product-licensing"),
    ("boundary:catapult", r"catapult"),
]

# AGENTS.md lists "node, gateway, SDK, WASM" and "CI gates" under EXOCHAIN
# core, while v0.2.6 classifies these paths as core runtime adapter.
AGENTS_TEXT_NAMES_CORE = re.compile(
    r"^crates/(exo-gateway|exo-node|exochain-sdk|exochain-wasm)/|^\.github/workflows/(ci|release)\.yml$"
)

# Paths where another in-repo record gives a different class from the one
# proposed here. Listed in the record's precedent-conflict table.
PRECEDENT_CONFLICTS = {
    ".github/workflows/ci.yml": "conflict:supply-chain-record-says-core",
    "Cargo.lock": "conflict:supply-chain-record-says-core",
    "cybermedica/package-lock.json": "conflict:subtree-record-says-adjacent",
}

MIXED_CONTENT = re.compile(r"^gap/ULTRAPLAN-GAP-")

PRECEDENT_ROW = re.compile(r"^\| `([^`]+)` \| ([^|]+?) \|")
COMPILED = [(rid, re.compile(rx), cls, basis, flags) for rid, rx, cls, basis, flags in RULES]
FINGERPRINTS = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in NAME_FINGERPRINTS]
BOUNDARIES = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in BOUNDARY_FINGERPRINTS]


def load_precedent(path):
    table = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = PRECEDENT_ROW.match(line)
            if match and match.group(2).strip() in CLASSES:
                table[match.group(1)] = match.group(2).strip()
    return table


def classify(path, precedent):
    for rid, rx, cls, basis, flags in COMPILED:
        if rx.search(path):
            break
    else:
        raise SystemExit(f"unclassified path: {path}")
    flag_set = {f for f in flags.split(";") if f}
    if path in precedent:
        if precedent[path] != cls:
            flag_set.add(f"rule-would-say:{rid}")
        cls, basis, rid = precedent[path], PX, "P0"
    if cls != ADJACENT:
        for name, rx in FINGERPRINTS:
            if rx.search(path):
                flag_set.add(f"name:{name}")
    for name, rx in BOUNDARIES:
        if rx.search(path):
            flag_set.add(name)
    if AGENTS_TEXT_NAMES_CORE.search(path) and cls == ADAPTER:
        flag_set.add("agents-text-names-core")
    if path in PRECEDENT_CONFLICTS:
        flag_set.add(PRECEDENT_CONFLICTS[path])
    if MIXED_CONTENT.search(path):
        flag_set.add("mixed-content")
    if re.search(r"\.(pdf|png|jpg|jpeg|gif|ico|woff2?)$", path, re.IGNORECASE):
        flag_set.add("binary")
    return cls, basis, rid, ";".join(sorted(flag_set))


def main():
    precedent = load_precedent(sys.argv[1]) if len(sys.argv) > 1 else {}
    lines = [line.strip() for line in sys.stdin if line.strip()]
    paths = sorted(set(lines))
    if len(paths) != len(lines):
        raise SystemExit("duplicate paths in input")
    missing = sorted(set(precedent) - set(paths))
    if missing:
        raise SystemExit(f"precedent paths absent from input: {missing[:5]}")
    out = sys.stdout
    out.reconfigure(encoding="utf-8", newline="\n")
    out.write("path\tproposed_class\tbasis\trule\tflags\n")
    for path in paths:
        cls, basis, rid, flags = classify(path, precedent)
        out.write(f"{path}\t{cls}\t{basis}\t{rid}\t{flags}\n")


if __name__ == "__main__":
    main()

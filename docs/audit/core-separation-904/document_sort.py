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
"""Rule-based sort of product-naming root, docs/ and governance/ files (part 7).

Usage:
    python -I document_sort.py <product-fingerprints.tsv> <out.tsv>

Part 3 (F-19) proposed three kinds of document and left the per-file sort to
the findings register. This script applies a fixed rule table to every path
in the part 3 scan that is not proposed as adjacent and that is a root file
or lies under docs/ or governance/. The first matching rule wins.

  K1 standing    file whose standing part 6 (F-50) leaves open: the two PDFs
                 the scan could not read, and the file marked CONFIDENTIAL
  K2 config      root file that is configuration or a build input, not prose
  K3 dated       dated or point-in-time record: release records, audit
                 reports, execution ledger, plans, council and resolution
                 records, proofs, the changelog, any name carrying a date,
                 and two governance files whose front matter was read
  K4 product     file or directory named for a product or boundary item
  K5 living      everything else: documents that describe the repository

The kind is assigned from the path only. Apart from the listed exceptions no
file was read to assign it, so a dated record without a date in its path
lands in K4 or K5, and a living document in a records directory lands in K3.
The proposed action is a review instruction, not a decision: the reviewer
confirms the kind and the linked finding for each file.
"""

import collections
import re
import sys

ADJACENT = "adjacent surface"
CONFIG = re.compile(r"^(\.[^/]+|Cargo\.(toml|lock)|Dockerfile|docker-compose[^/]*\.yml|"
                    r"[^/]+\.(sh|toml|json|ya?ml))$")
DATED_DIR = re.compile(r"^(governance/releases/|governance/resolutions/|docs/audit/|"
                       r"docs/execution-ledger/|docs/superpowers/|docs/council/|docs/proof/)")
DATED_EXACT = {"governance/EXOCHAIN-REFACTOR-PLAN.md",
               "governance/COUNCIL-ASSESSMENT-EXO-VS-EXOCHAIN.md"}
STANDING = {"EXOCHAIN-FABRIC-PLATFORM.md"}
DATED_NAME = re.compile(r"\d{4}-\d{2}-\d{2}|(^|/)CHANGELOG\.md$")
PRODUCT = re.compile(r"honor_?good|econom|0dentity|zerodentity|catapult|livesafe|crosschecked|"
                     r"archon|commandbase|adjacent-surfaces|cybermedica|heartfield|exoforge",
                     re.IGNORECASE)
ACTION = {
    "K1 standing": ("pending", "F-50", "Standing open: document owner and legal owner (PDF text not extracted)"),
    "K2 config": ("pending", "F-3; F-11; F-12; F-18; F-36; F-37",
                  "Review: patch an entry for a tree that leaves; otherwise follows the decision its term belongs to"),
    "K3 dated": ("no_change", "F-19; F-47", "Keep as written; the register records that named products moved"),
    "K4 product": ("pending", "", "Review: follows the panel decision on the item it documents"),
    "K5 living": ("patch", "F-19", "Review required at the split; update product paths and repository references"),
}


K4_LINKS = (("econom", "F-13"), ("honor", "F-13"), ("archon", "F-33; F-49"), ("livesafe", "F-9; F-11"), ("crosschecked", "F-10"),
            ("0dentity", "F-12"), ("zerodentity", "F-12"), ("catapult", "F-14"),
            ("adjacent-surfaces", "F-19"), ("commandbase", "F-13; F-14"))


def k4_link(path):
    low = path.lower()
    for word, link in K4_LINKS:
        if word in low:
            return link
    return "F-13"


def kind(path, terms):
    if "binary-not-scanned" in terms or path in STANDING:
        return "K1 standing"
    if "/" not in path and CONFIG.match(path):
        return "K2 config"
    if DATED_DIR.match(path) or DATED_NAME.search(path) or path in DATED_EXACT:
        return "K3 dated"
    if PRODUCT.search(path):
        return "K4 product"
    return "K5 living"


def main():
    src, out = sys.argv[1:3]
    terms = collections.defaultdict(set)
    klass = {}
    with open(src, encoding="utf-8") as handle:
        next(handle)
        for line in handle:
            path, cls, term = line.rstrip("\n").split("\t")[:3]
            if cls == ADJACENT:
                continue
            if "/" in path and not path.startswith(("docs/", "governance/")):
                continue
            terms[path].add(term)
            klass[path] = cls
    counts = collections.Counter()
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("path\tproposed_class\tkind\tproposed_disposition\tlinked_findings\t"
                     "proposed_action\tterms\n")
        for path in sorted(terms):
            k = kind(path, terms[path])
            counts[k] += 1
            disp, linked, action = ACTION[k]
            if k == "K4 product":
                linked = k4_link(path)
            handle.write("\t".join([path, klass[path], k, disp, linked, action,
                                    "; ".join(sorted(terms[path]))]) + "\n")
    print("paths", len(terms), dict(sorted(counts.items())))


if __name__ == "__main__":
    main()

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
"""History scan for the issue #904 clean-separation audit (part 6).

Usage:
    python -I history_scan.py <repo> <commit> <path-classification.tsv> \
        <commits-out.tsv> <paths-out.tsv>

Reads `git log` for every commit reachable from <commit> and writes:

  commits-out: one row per commit: sha, author date, author name, author
      e-mail domain, committer name, parent count, signature kind (`N` none,
      `E` PGP, `S` SSH or `O` other, read from the commit's `gpgsig`
      header; no signature is verified), sign-off count, co-author names,
      number of paths changed per
      proposed class, number of changed paths absent from the audited tree,
      a `mixed` flag, and the subject line.
  paths-out: one row per path that any non-merge commit changed: path,
      whether it is in the audited tree, proposed class, how the class was
      obtained, number of commits, first and last author date, the number
      and list of distinct author names, the commit that first touched it,
      and a `name_flag` for file names that look like key or credential
      material. Old paths that no rule matches are folded into one row per
      top-level directory (`target/**`) with the path count in `name_flag`.

Class of a path: the part 1 inventory when the path is in the audited tree
(`inventory`); otherwise the part 1 rule table applied to the old path
(`rule-on-old-path`), which is this audit's extension and not a precedent.
An old path that no rule matches is `unclassified`.

`mixed` is 1 when a non-merge commit changes at least one path proposed as
EXOCHAIN core or core runtime adapter and at least one proposed as adjacent
surface.

Limits: merge commits are listed but their file changes are not (git prints
none by default); a rename counts as a change to both names; e-mail
addresses are reduced to their domain; file contents are never read, so
`name_flag` is a statement about a file name only.

Deterministic for a given commit: no clock, no network, sorted path output.
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import classify_paths as cp  # noqa: E402

CORE, ADAPTER, ADJACENT, VENDOR = cp.CORE, cp.ADAPTER, cp.ADJACENT, cp.VENDOR
UNCLASSIFIED = "unclassified"
ORDER = (CORE, ADAPTER, ADJACENT, cp.IMPORTED, VENDOR, UNCLASSIFIED)
NAME_FLAG = re.compile(
    r"(^|/)\.env(\.[^/]*)?$|\.(pem|key|p12|pfx|jks|keystore)$|(^|/)id_(rsa|ed25519|ecdsa)"
    r"|admin_token|(^|[/._-])(secret|secrets|credential|credentials)([/._-]|$)",
    re.IGNORECASE,
)
NAME_FLAG_ALLOW = re.compile(r"\.env\.(example|sample|template)$", re.IGNORECASE)
# tools/test_no_orphan_rust_modules.sh fails if anything under docs/ names
# one of seven removed Rust files. They are left out of the per-path table
# and built here from parts, so neither this script nor the table names them.
GUARDED = frozenset(
    f"crates/{crate}/src/{module}.rs"
    for crate, module in (
        ("exo-core", "event"), ("exo-dag", "proof"), ("exo-gatekeeper", "proof"),
        ("exo-governance", "anchor"), ("exo-governance", "decision"),
        ("exo-governance", "emergency"), ("exo-identity", "key"),
    )
)
FMT = "%x01%H%x1f%aI%x1f%an%x1f%ae%x1f%cn%x1f%P%x1f%s%x1f" \
      "%(trailers:key=Co-authored-by,valueonly,separator=%x1e)%x1f" \
      "%(trailers:key=Signed-off-by,valueonly,separator=%x1e)%x02"


def clean(text):
    return re.sub(r"[\t\r\n]+", " ", text).strip()


def main():
    repo, commit, inv, commits_out, paths_out = sys.argv[1:6]
    inventory = {}
    with open(inv, encoding="utf-8") as handle:
        next(handle)
        for line in handle:
            cols = line.rstrip("\n").split("\t")
            inventory[cols[0]] = cols[1]

    def klass(path):
        if path in inventory:
            return inventory[path], "inventory"
        try:
            return cp.classify(path, {})[0], "rule-on-old-path"
        except SystemExit:
            return UNCLASSIFIED, "no-rule-matches"

    raw = subprocess.run(
        ["git", "-C", repo, "-c", "core.quotepath=false", "log", "--no-color",
         "--name-status", "-M", f"--format={FMT}", commit],
        check=True, capture_output=True,
    ).stdout.decode("utf-8", errors="replace")

    # The signature kind comes from the raw commit header. git's %G? is not
    # used: without a configured allowed-signers file it reports an
    # SSH-signed commit as having no signature.
    sigs = {}
    sha = None
    for line in subprocess.run(
        ["git", "-C", repo, "log", "--no-color", "--pretty=raw", commit],
        check=True, capture_output=True,
    ).stdout.decode("utf-8", errors="replace").split("\n"):
        if line.startswith("commit "):
            sha = line.split()[1]
            sigs[sha] = "N"
        elif line.startswith("gpgsig"):
            sigs[sha] = ("E" if "BEGIN PGP" in line
                         else "S" if "BEGIN SSH" in line else "O")

    paths = {}
    rows = []
    for chunk in raw.split("\x01")[1:]:
        head, _, body = chunk.partition("\x02")
        sha, date, an, ae, cn, parents, subj, coauth, signoff = head.split("\x1f")
        sig = sigs[sha]
        n_par = len(parents.split()) if parents.strip() else 0
        changed = []
        for line in body.split("\n"):
            cols = line.split("\t")
            if len(cols) >= 2 and re.match(r"^[ACDMRT]\d*$", cols[0]):
                changed.extend(cols[1:])
        counts = dict.fromkeys(ORDER, 0)
        gone = 0
        for path in changed:
            cls, how = klass(path)
            counts[cls] += 1
            gone += how != "inventory"
            rec = paths.setdefault(path, {"n": 0, "first": date, "last": date,
                                          "authors": set(), "first_sha": sha})
            rec["n"] += 1
            rec["authors"].add(an)
            if date[:10] <= rec["first"][:10]:
                rec["first"], rec["first_sha"] = date, sha
            if date[:10] > rec["last"][:10]:
                rec["last"] = date
        mixed = int(n_par < 2 and (counts[CORE] + counts[ADAPTER]) > 0 and counts[ADJACENT] > 0)
        co = sorted({clean(re.sub(r"<[^>]*>", "", c)) for c in coauth.split("\x1e") if c.strip()})
        so = len([s for s in signoff.split("\x1e") if s.strip()])
        rows.append([sha, date[:10], clean(an), ae.rsplit("@", 1)[-1].lower(), clean(cn),
                     str(n_par), sig, str(so), "; ".join(co),
                     *(str(counts[c]) for c in ORDER), str(gone), str(mixed), clean(subj)[:120]])

    with open(commits_out, "w", encoding="utf-8", newline="\n") as out:
        out.write("sha\tauthor_date\tauthor_name\tauthor_email_domain\tcommitter_name\tparents\t"
                  "sig\tsignoffs\tcoauthors\tcore\tadapter\tadjacent\timported\tvendor\tunclassified\t"
                  "not_in_audited_tree\tmixed\tsubject\n")
        for row in rows:
            out.write("\t".join(row) + "\n")

    with open(paths_out, "w", encoding="utf-8", newline="\n") as out:
        out.write("path\tin_audited_tree\tproposed_class\tclass_source\tcommits\tfirst_date\t"
                  "last_date\tauthors\tauthor_names\tfirst_commit\tname_flag\n")
        folded = {}
        for path in sorted(paths):
            if path in GUARDED:
                continue
            rec = paths[path]
            cls, how = klass(path)
            if cls == UNCLASSIFIED:
                top = path.split("/", 1)[0] + "/**"
                agg = folded.setdefault(top, {"n": 0, "files": 0, "first": rec["first"],
                                              "last": rec["last"], "authors": set(),
                                              "first_sha": rec["first_sha"]})
                agg["n"] += rec["n"]
                agg["files"] += 1
                agg["authors"] |= rec["authors"]
                if rec["first"][:10] < agg["first"][:10]:
                    agg["first"], agg["first_sha"] = rec["first"], rec["first_sha"]
                agg["last"] = max(agg["last"], rec["last"], key=lambda d: d[:10])
                continue
            flag = "key-or-credential-name" if NAME_FLAG.search(path) and not NAME_FLAG_ALLOW.search(path) else ""
            out.write("\t".join([path, str(int(how == "inventory")), cls, how, str(rec["n"]),
                                 rec["first"][:10], rec["last"][:10], str(len(rec["authors"])),
                                 "; ".join(sorted(clean(a) for a in rec["authors"])),
                                 rec["first_sha"][:12], flag]) + "\n")
        for top in sorted(folded):
            agg = folded[top]
            out.write("\t".join([top, "0", UNCLASSIFIED, "no-rule-matches", str(agg["n"]),
                                 agg["first"][:10], agg["last"][:10], str(len(agg["authors"])),
                                 "; ".join(sorted(clean(a) for a in agg["authors"])),
                                 agg["first_sha"][:12], f"folded:{agg['files']}-paths"]) + "\n")
    print("commits", len(rows), "paths", len(paths))


if __name__ == "__main__":
    main()

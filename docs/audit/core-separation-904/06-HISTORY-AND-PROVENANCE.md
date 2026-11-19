<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Clean-separation audit (#904), part 6: source history and provenance

**Status: DRAFT audit evidence. Not panel-reviewed. Not a split plan, not
legal advice, and not a cryptographic certification.**

Issue #904 asks the audit to "record source-history/provenance disclosure
requirements and filtered-history concerns", and adds: "Full history remains
in the renamed legacy repository; no rewriting is authorized here." Its
acceptance criteria ask for findings covering "history/provenance". This
record describes the commit history behind the audited commit, what that
history shows about who wrote the proposed core and under what stated terms,
and what a new repository would have to disclose about where its content
came from.

Nothing in the history was rewritten, filtered or removed for this record.

It builds on part 1 (proposed class of every path), part 2 (dependency
closure, F-1 to F-8), part 3 (product names in the proposed core, F-9 to
F-21), part 4 (licence inventory, F-22 to F-30) and part 5 (build, CI and
release coupling, F-31 to F-40). Findings continue that numbering.

## What this record does and does not establish

It establishes, for the commits reachable from the audited commit:

- the shape of the history: commit, merge and root counts, tags, and the
  point where two unrelated histories were joined;
- for every commit, the author name git records, whether a signature field
  is present, which trailers it carries, and how many paths it changed in
  each class part 1 proposes;
- for every path any non-merge commit changed, when and by which author
  names;
- how the licence statements in the root manifest and in one product tree
  changed over time;
- which tracked files in the proposed core cite commits, pull requests or
  tags of this repository.

It does not establish:

- **who owns the copyright in any file, or whether any licence statement is
  valid.** An author name in git is typed by whoever made the commit. It is
  not proof of identity, employment, or the terms the work was written
  under. Those are questions for the accountable legal owner;
- that any commit is authentic. No signature was verified (F-46);
- that the history is free of secrets or personal data. File names were
  checked; file contents in history were not (O-38);
- that no third-party code was copied into the proposed core. Two leads from
  part 4 stay open (F-49);
- what the hosting or registry side records: pull-request reviews, registry
  publisher settings and published package contents were not read;
- whether the new repository should carry history. That decision belongs to
  the split plan (#903). This record lists what each choice would require.

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` |
| Per-commit table | `docs/audit/core-separation-904/history-commits.tsv`, 2,176 rows |
| Per-commit table SHA-256 | `169fe95e871935ef67516c6b51a984e53bc4b674da79c066bada100ced4bf4c1` |
| Per-path table | `docs/audit/core-separation-904/history-paths.tsv`, 3,445 rows |
| Per-path table SHA-256 | `7cfc33896b58516c9e7f43fb27cdb5566658d1eeea05d16fbf82325c6d73b410` |
| Rows left out of the per-path table | 7. The repository guard `tools/test_no_orphan_rust_modules.sh` fails if anything under `docs/` names one of seven removed Rust files, so the script skips them. All seven were classed EXOCHAIN core by a rule on the old path, are absent from the audited tree, and had 2 to 6 commits each. The guard lists them. Figures elsewhere in this part were computed before these rows were removed and still include them |
| Script | `history_scan.py` in the same directory |
| Input | `path-classification.tsv` (part 1), `license-inventory.tsv` (part 4), and a full local clone |
| Repository metadata read | Created 2025-12-14, public, not a fork, 2 forks, licence field `Apache-2.0` (GitHub API, 2026-11-17) |

"Core and adapter" below means the two classes part 1 proposes as
`EXOCHAIN core` and `core runtime adapter`. "Product tree" means the six
top-level directories `command-base/`, `cybermedica/`, `demo/`,
`livesafe/`, `site/` and `web/`. Both are proposals from part 1, not
decisions.

## Method

1. **History scan.** `history_scan.py` reads `git log --name-status -M` for
   every commit reachable from the audited commit. It writes one row per
   commit and one row per path. A path in the audited tree takes its class
   from part 1's inventory. A path that no longer exists is classified by
   applying part 1's rule table to the old path; that extension is this
   audit's inference. 7,925 old paths under `target/` match no rule and are
   folded into one row.
2. **Author data.** Author and committer names are copied from git. E-mail
   addresses are reduced to their domain in the tables. The signature column
   is read from each commit's `gpgsig` header: `N` for none, `E` for a PGP
   signature and `S` for an SSH signature. No signature was verified. An earlier version of this table used git's
   `%G?` field, which reports an SSH-signed commit as unsigned when no
   allowed-signers file is configured; that undercounted signed commits
   by 67 and has been corrected.
3. **Trailers.** `Co-authored-by` and `Signed-off-by` trailers are read with
   git's trailer parser. A commit is counted as naming an AI tool or agent
   when its author or a co-author name matches one of: Claude, Cursor,
   Copilot, Codex, GPT, Paperclip, Gemini, Devin, Aeon.
4. **Licence history.** `git log -G` and `git show` on the root
   `Cargo.toml`, `git log --follow` on `LICENSE`, and the content of 204
   `command-base/` files at three commits.
5. **Reference scan.** Every 40-character hexadecimal string in a core or
   adapter text file was tested against the commits reachable from the
   audited commit, then against all objects in the local clone. Links to
   `github.com/exochain/exochain` were counted by kind.
6. **Document checks.** The first 60 lines of every non-adjacent `.md`,
   `.html`, `.json`, `.txt` and `.csv` file were searched for words that
   mark an external report (for example "Prepared by", "Confidential",
   "consultant", "scan output"). The 11 matching files were read at the
   matching lines. The two root PDF files were read as bytes: the document
   information fields and a string search of the decompressed streams. They
   were not rendered or read as documents.
7. **Reading.** Every finding below was checked against the cited file,
   line, commit or table.

Steps 4 to 6 were run with helper scripts kept outside the repository. The
scripts are not covered by this record's digests. Reproduction gives
commands for the licence-history and join facts; the reference counts
(F-47), the document search and the PDF checks (F-50) are described by rule
only and are supplied results, not fully reproducible from this record.

## The history at the audited commit

| Measure | Value |
| --- | ---: |
| Commits reachable from the audited commit | 2,176 |
| Merge commits | 575 |
| Non-merge commits | 1,601 |
| Root commits | 2 |
| First and last author date | 2025-12-14, 2026-11-16 |
| Tags in the local clone | 23 |
| Tags that are not ancestors of the audited commit | 2 |
| Releases listed on GitHub | 10 |
| Distinct paths changed by any non-merge commit | 11,376 |
| Of those, in the audited tree | 3,175 |
| Of those, no longer in the tree | 8,201 |

Non-merge commits by the classes of the paths they change:

| Changes | Commits |
| --- | ---: |
| Core or adapter paths, no adjacent path | 1,384 |
| Adjacent paths, no core or adapter path | 110 |
| Both ("mixed") | 95 |
| No core, adapter or adjacent path (9 vendor-class only, 2 only paths no rule matches, 1 with no path) | 12 |

Author names on all 2,176 commits: Bob Stewart 2,049; Cursor Agent 46;
exochain 25; mstewartbz 21; John Fitzpatrick, John C Fitzpatrick and John C.
Fitzpatrick 22 together; Aeon/ExoChain Council 5; railway-app[bot] 4; Walley
Fipps 3; cursor[bot] 1. GitHub's contributor list (read 2026-11-17) has
eight accounts whose commit counts match these names once the three
Fitzpatrick spellings are added together. This record does not verify which
account or person is behind any name.

## Findings

Dispositions use the vocabulary of the earlier parts: `patch`,
`adjacent_patch`, `no_change`, or pending with an owner. "Blocking" says
what the finding blocks.

### F-41. The history joins two unrelated lines and holds a committed build directory

The audited commit has two root commits:

| Root | Date | Author name | Commits only on this line |
| --- | --- | --- | ---: |
| `eda286e5` "Initial commit" | 2025-12-14 | exochain | 32 |
| `8089b6aa` "EXOCHAIN: Constitutional trust fabric for safe superintelligence governance" | 2026-03-18 | Bob Stewart | 1 (the root itself) |

Merge `da518a1e` (2026-03-18, "Merge remote main — our constitutional
refactor supersedes prior code") joins them. Its tree differs from the new
root by 8,289 paths and from the older line's head (`f3de1fc8`) by 139: 55
paths added and 84 modified. So the merge kept the older line's tree and
laid the new root's 139 files over it, replacing 84 existing files.

The older line contains commit `f09c610b` (2025-12-15, "build: Generate Rust
compilation artifacts and Node.js dependency files"), which added 7,925
paths under `target/`: compiler output including `.exe`, `.pdb`, `.rlib`,
`.rmeta` and `.o` files. They were removed on 2026-03-21 in `b73c9c6f`. One
of them, `target/.rustc_info.json`, records the build host as
`x86_64-pc-windows-msvc`. The other files were not opened. Debug files of
this kind commonly embed the absolute paths of the machine that built them;
whether these do was not checked. The same commit also changed the root
`LICENSE` file (F-43) and added 245 files under `tools/` and 33 under
`crates/`, so its subject line understates what it contains.

Why it matters for the split. The issue keeps the full history in the legacy
repository, so these objects stay public there whatever the new repository
does. They matter for the new repository only if it carries history: a
history filtered by today's paths would drop `target/` (it is not in the
tree), while a full copy would carry it. The first three months of the
proposed core's files come from the older line, including the root
`LICENSE`, `CONTRIBUTING.md` and both specification PDFs (F-50).

Proposed disposition: `no_change` to the history, because no rewriting is
authorised. Pending for the split plan (#903): a history option that would
keep the `target/` objects needs them inspected first. Not blocking for a
copy without history, or for a filter that drops them. **Blocking** for any
history option that retains those objects, until inspected.

### F-42. 95 commits change core and product paths together

95 non-merge commits change at least one core or adapter path and at least
one adjacent path. 71 of them date from March to May 2026. Examples:

| Commit | Date | Core | Adapter | Adjacent | Subject |
| --- | --- | ---: | ---: | ---: | --- |
| `97a4b973` | 2026-05-10 | 338 | 233 | 623 | chore: add Apache license headers |
| `d39e83b1` | 2026-03-16 | 53 | 13 | 52 | feat: decision.forum governance refactor + LiveSafe.ai integration |
| `985cd9ba` | 2026-07-04 | 3 | 0 | 490 | feat(livesafe): relocate LiveSafe app into monorepo as proprietary subtree |
| `d0786abb` | 2026-04-07 | 2 | 5 | 222 | feat: CommandBase.ai — cognitiveplane.ai hypervisor with 110-function WASM bridge and GSD control surfaces (#82) |

A further 110 commits change only adjacent paths.

Why it matters for the split. A history filtered to the core paths would
keep the 95 mixed commits with their product files removed. Each would then
have a subject line, and often a body, describing product work that the
commit no longer contains. A rewritten commit, and every commit after it,
gets a new identifier (see F-47). No filter was specified or run for this
record, so these effects are expected, not observed. Commit messages were
not searched for product names; part 3's fingerprint scan covers file
contents only.

Proposed disposition: pending, split plan owner (#903). This record does not
recommend for or against carrying history. If filtered history is chosen,
the new repository must say that the commits were rewritten, by what rule,
and from which source commit. Not blocking for a copy without history.
**Blocking** for a filtered-history option until the rule and its effect on
these commits are written down.

### F-43. Licence statements changed during the history

Five things are visible. This record states what the files said and when.
It does not say what legal effect any of it has.

**The licence text itself.** The root `LICENSE` has two commits. `eda286e5`
(2025-12-14) added it. `f09c610b` (2025-12-15), the build-output commit of
F-41, changed it by 3 lines added and 28 removed: section 4(a) is re-wrapped,
section 5 reads "without any additional terms and conditions" where the
earlier version read "terms or conditions", and the closing appendix ("How
to apply the Apache License to your work") is removed. The file has not
changed since. The same content (blob `58f6cab5`) is the `LICENSE` in
`packages/exochain-sdk/`, `packages/exochain-llm-proxy/` and
`packages/exochain-wasm/wasm/`. Part 4 described these four files as
"Apache-2.0 text" and as identical to each other; it did not compare them
with the text the Apache Software Foundation publishes. Neither did this
record: the comparison here is only between the two commits.

**The root manifest.** The new root `8089b6aa` (2026-03-18) declared
`license = "AGPL-3.0-or-later"` in `Cargo.toml` and contained no `LICENSE`
file. The `LICENSE` file, with Apache-2.0 text, came from the older line
through the join the same day. Commit `2154da7d` (2026-03-20) changed the
field to `Apache-2.0`. So the manifest and the licence file disagreed for
two days. `docs/legal/LICENSING-POSITION.md` section 7 calls the field an
error. The first tag, `v0.1.0-alpha`, is dated 2026-03-30, after the change.
Whether any crate was published to a registry in those two days was not
checked: the registries were not queried.

**Other AGPL statements after that date.** The root-manifest change did not
end every AGPL statement in the repository.
`demo/packages/exochain-wasm/package.json` (package name
`@exochain/exochain-wasm`; adjacent by part 1's rules) declared
`"license": "AGPL-3.0-or-later"` from `30caa74c` (2026-03-19) until
`64fd2ff4` (2026-05-09, "fix(wasm): align package license metadata"). The
tags `v0.1.0-alpha` (2026-03-30) and `v0.1.0-beta` (2026-04-10) contain that
declaration. `README.md` also carried the string `AGPL-3.0-or-later` for
part of 2026-04-04 (added in `0862ff53`, removed in `b3df72ec`). Whether the
package was published to npm in that period was not checked.

**Product licence files arrived late.** The per-tree licence files were
first added on 2026-07-04 (`livesafe/LICENSE`), 2026-07-10
(`cybermedica/LICENSE`), 2026-07-14 (`demo/LICENSE`) and 2026-07-15
(`command-base/LICENSE`). `site/` and `web/` have none. Before those dates
the root `LICENSE` was the only licence file above those trees.

**`command-base/`.** Commit `97a4b973` (2026-05-10) added the Apache-2.0
header to 204 files under `command-base/`. All 204 carried the header text
at that commit and at the parent of `a2af67aa`. Commit `a2af67aa`
(2026-07-15, "docs(commandbase): enforce proprietary license boundary")
removed it from all 204. Part 4's inventory records them today with no
header. Three release tags fall in that window and contain the Apache-headed
files: `v0.2.0-beta`, `v0.2.1-beta` and `livesafe-v0.1.0-beta`. The
repository is public.

**Other product trees in the same commit.** `97a4b973` also changed 117
`demo/` paths, 119 `site/` paths and 68 `web/` paths. Today 114 of the
`demo/` files have no header, and all 119 `site/` and 68 `web/` files still
carry the Apache header (part 4). The content of the `demo/`, `site/` and
`web/` files at `97a4b973` was not checked.

Why it matters for the split. The legacy repository keeps these commits and
tags. Whether a header that was public for two months has any continuing
effect is a legal question this record does not answer. For the proposed
core the practical point is narrower: a statement such as "the products
were never offered under Apache-2.0" or "the core has always been
Apache-2.0" is not supported by the history.

Proposed disposition: pending, accountable legal owner (`CONTRIBUTING.md`
line 209 names Bob Stewart for legal and compliance matters).
`adjacent_patch` is not proposed, because the present files are already
changed. The owner also decides whether the root `LICENSE` is restored to
the published Apache-2.0 text (a `patch` if so). **Blocking** for any claim
about the legal effect of past licence statements, for a statement that the
core has always been Apache-2.0, and for a statement that the core carries
the standard Apache-2.0 text until the file is compared with it. Reporting
the dated facts above is not blocked. Copying the files is not blocked;
describing the copy as Apache-2.0 without qualification is.

### F-44. One author name is recorded on most core commits, and no separate contribution agreement was found

By git author name:

| Measure | Value |
| --- | ---: |
| Non-merge commits that change a core or adapter path | 1,479 |
| Of those, author name Bob Stewart | 1,380 |
| Core and adapter paths in the audited tree | 1,245 |
| Of those, changed only by the author name Bob Stewart | 898 |
| Of those, changed by exactly one author name | 1,107 |

The other author names on core and adapter paths are mstewartbz (229
paths), Cursor Agent (63), the three Fitzpatrick spellings (64 together),
Aeon/ExoChain Council (11), railway-app[bot] (6), exochain (6) and Walley
Fipps (1).

These counts use the author field only. `Co-authored-by` trailers name
further parties that are not AI tools: "stewart" (39 non-merge commits, all
touching core or adapter paths), "oakwindholdings" (7, of which 6 touch core
or adapter paths), "exochain" (8, of which 5), "Bob Stewart" (2) and
"Maxwell Stewart" (1). So "changed only by the author name Bob Stewart" does
not mean no other party is credited on those paths. Who these names are was
not established.

What the repository records about the terms of those contributions:

- No commit of the 2,176 carries a `Signed-off-by` trailer.
- No contributor licence agreement, certificate of origin, sign-off rule or
  inbound-licence statement was found. The search covered the root `*.md`
  files, `.github/`, `governance/**/*.md` and `docs/legal/`.
- `CONTRIBUTING.md` line 278 asks contributors to "Uphold the Apache 2.0
  License". `LICENSING-POSITION.md` line 122 says the Apache patent grant
  "covers contributions made by ExoChain contributors".
- There is no `.mailmap`, `AUTHORS`, `CONTRIBUTORS` or `NOTICE` file.
- The file headers name "Exochain Foundation" as copyright holder. No
  tracked document was found that identifies that body as a legal entity or
  records a transfer of rights from the authors to it. The search was the
  same as above; other locations were not searched.

Part 4's F-22 listed 290 non-adjacent files that are eligible for the
standard header and lack it (213 adapter, 60 core, 17 vendor-class), and
deferred them here for authorship. By author name: 142 were changed only by mstewartbz, 108 only by Bob Stewart,
one only by John C Fitzpatrick, one only by railway-app[bot], and 38 by more
than one name.

Why it matters for the split. The tracked `LICENSE` has a section 5 on
"Submission of Contributions" (lines 130-136; see F-43 for a wording change
in it). Whether and how that section applies to any contribution here is
for the accountable legal owner; this record takes no view. The history
cannot show that the body named in the headers holds the rights the headers
assert, and it does not show the employment or contract terms of any
author. A new repository copied without history also loses the per-file
author-name record, which today exists only in git.

Proposed disposition: pending, accountable legal owner. The owner decides
whether the headers' holder is correct, whether an inbound-licence rule is
adopted, and whether the 290 files may take the header. A `patch` to add
headers stays conditional on that answer, as in F-22. **Blocking** for an
"Apache-2.0 core" claim that covers the 290 files (carried from F-22).
Copying the files is not blocked; the licence claim made about the copy is
what stays open.

### F-45. 221 non-merge commits name an AI tool or agent as author or co-author

Of the 1,601 non-merge commits, 221 have an author name or a
`Co-authored-by` trailer that names an AI tool or agent account. 204 of them
change a core or adapter path. The trailer names and their counts across
all commits are: Claude Opus 4.6 (45, plus 27 with a "1M context" suffix),
Paperclip (35), Claude Sonnet 4.6 (32), Claude Opus 4.7 (21) and Claude Opus
4.8 (2), both with that suffix, Cursor Agent (12) and Cursor (5). 46 commits
have the author name Cursor Agent, 45 of them non-merge.

This is a lower bound, and it is a count of recorded names. A trailer is
optional. A commit without one says nothing about how its content was
produced, and a commit with one does not say which part of it a tool
produced.

`CONTRIBUTING.md` has a section "AI-Assisted Development" (line 93) that
points to `AGENTS.md`. Neither that section nor the legal document says who
holds rights in AI-assisted contributions or how they are to be marked.

Why it matters for the split. The history is today the only record of which
changes named an AI tool. A copy without history removes it. Whether
AI-assisted content affects the copyright statement in the headers is a
legal question this record does not answer.

Proposed disposition: pending, accountable legal owner, for the policy
question. For the split: the provenance statement of the new repository
should say that the source history records AI-assisted commits and where
that history lives (D-4 below). Not blocking for copying the core.
**Blocking** for any claim that the core is wholly human-authored.

### F-46. The history does not follow the repository's stated commit rules

`CONTRIBUTING.md` states two rules:

- line 73: "All commits **MUST** be GPG/SSH signed. Unsigned commits will be
  rejected by the gatekeeper."
- line 74: "**Linear History**: No merge commits. Rebase on `main`."

The history shows:

| Measure | Value |
| --- | ---: |
| Commits with no signature | 1,235 of 2,176 |
| Commits with a signature present | 941 |
| Of those, PGP signature, committer "GitHub" (made on the hosting side) | 716 |
| Of those, PGP signature, committer Bob Stewart | 158 |
| Of those, SSH signature, committer Cursor Agent | 46 |
| Of those, SSH signature, committer mstewartbz | 21 |
| Merge commits | 575 |

Both rules entered `CONTRIBUTING.md` in `148fc016` (2025-12-16); eight
commits are older than that. No signature was verified, so "present" does
not mean "valid", and the signer of the 716 was not identified: the table
records only that the committer name is "GitHub" and a signature field
exists. Part 5's F-32 found no branch protection or ruleset visible to the
audit token, which is consistent with unsigned commits reaching `main`.

Tags are separate. 21 of the 23 tags are annotated tags carrying a
signature block, and `release.yml` has a signed-tag verification step. Those
signatures were not verified here either.

Why it matters for the split. A provenance statement for the new repository
cannot rely on "every commit is signed". If the 716 are signatures the
hosting service adds to commits it creates (the usual case for merges and
web edits, not confirmed here), they would speak to where the commit was
made, not to who wrote the change.

Proposed disposition: `patch`: either the rules in `CONTRIBUTING.md` are
changed to describe what is enforced, or enforcement is added (with F-32).
Which one is a maintainer decision. Not blocking for the split.
**Blocking** for any claim that all commits are signed, or that commit
provenance has been verified.

### F-47. Core records cite commits, pull requests and tags that will exist only in the legacy repository

In core and adapter text files:

| Reference | Count |
| --- | ---: |
| File-level references to a commit reachable from the audited commit | 502, in 72 files |
| Other 40-character strings that are commits in the local clone but not reachable from the audited commit | 190 |
| Other 40-character strings that are tag objects | 11 |
| Other 40-character strings that match no object in the local clone | 64 |
| Links to `github.com/exochain/exochain/pull/…` | 792 |
| Links to `…/issues/…` | 15 |
| Links to `…/releases/…` | 9 |
| Links to `…/actions/…` | 7 |
| Links to the repository itself | 41 |

406 of the 502 are in `docs/execution-ledger/` and 34 in
`governance/releases/`. The rest include release-recovery tools and tests
under `tools/` and source files in `crates/exo-root` and `crates/exo-node`.
The 64 unmatched strings may be digests of other kinds; they were not
examined. The root `Cargo.toml` (line 70) and
`packages/exochain-sdk/package.json` (line 8) give the repository URL as
`https://github.com/exochain/exochain`.

This audit adds to the count. `history-commits.tsv` lists all 2,176 commit
identifiers and the author names, and part 1's rule C5 proposes everything
under `docs/audit/` as core. If the audit records are copied into the new
repository they carry those references with them. Whether the two history
tables belong in the new repository or stay with the legacy one is a
question for part 7 and the split plan.

Why it matters for the split. In a new repository created by copying files,
none of these commits, pull requests or tags exists. If the new repository
takes the name `exochain/exochain`, as #903 describes, a link to that name
would be expected to reach the new repository, where the number may not
exist or may later belong to an unrelated item. #903 calls this the
redirect hazard and marks the hosting behaviour unverified; this record did
not test it either. A filtered history is unlikely to help: a commit whose
tree, parents or message change gets a new identifier, and so does every
commit after it. Release records that bind a release to a source commit
could then be checked only against the legacy repository, unless a map from
old to new identifiers is published.

Proposed disposition: `patch`, under the split plan: decide for each kind of
reference whether it is rewritten to the legacy repository's new name,
kept, or annotated. The tables here give the plan its counts; they are not
a full link catalogue, which #903 requires separately. **Blocking** for the
cutover, on the same footing as #903's redirect requirement.

### F-48. Release provenance is tied to the identity of the current repository

`release.yml` at the audited commit:

| What | Evidence |
| --- | --- |
| Build provenance attestation over release archives | `actions/attest-build-provenance` (line 1632), in a job with `attestations: write` and `id-token: write` (lines 1525-1526) |
| npm publication passes the repository name, repository id and owner id to its publish script | Lines 4329-4331, repeated at 4566-4568 and 4764-4766 |
| npm publication uses a registry token | `NODE_AUTH_TOKEN` (line 4325 and others) |
| PyPI publication through the registry's publish action with attestations on | Lines 5000-5003 and 6459 |
| crates.io publication uses a registry token | `CARGO_REGISTRY_TOKEN` (line 2302) |

Attestations of this kind record the repository and workflow that produced
an artifact. What the existing attestations for past releases contain was
not inspected, and the publisher settings held by each registry are not
visible from the repository.

Why it matters for the split (inferred from the workflow text). Past
release attestations name the present repository. After a rename they
belong to the legacy repository, while a new repository with the old name
is a different repository to the hosting service. Any registry rule that
trusts a publisher by repository identity would need to be set up again,
and a verifier following the documented check for an old release would need
to be told which repository to name.

Proposed disposition: pending, release owner, under #903's "package and
release boundary". Needs a read of one existing attestation and of each
registry's publisher settings. **Blocking** for the first release from the
new repository. Not blocking for copying the core.

### F-49. The provenance leads from parts 2 and 4

**Archon and Paperclip (part 4, F-24; part 3, F-13).**
`crates/exo-economy/src/honorgood.rs` has two public library functions
(lines 147 and 180; the test module starts at line 355) that build "legacy
receipts". One records a contribution named "Archon" with
`source_uri: "https://github.com/coleam00/Archon"` and `license: "MIT"`
(lines 152-156), the other one named "Paperclip" with
`source_uri: "https://github.com/paperclip-ui/paperclip"` and
`license: "MIT"` (lines 185-189). The receipts mark the contributions as
requiring attribution and as in material use. Each names its receiving
system as an adjacent product (`ExoForge` and `CommandBase`), has status
`Proposed` and legal effect `VoluntaryRecognitionOnly`. So the core's own
code states that two adjacent products materially use two outside
MIT-licensed projects. That is a statement in the code, not evidence that source from either project is
in the tree, and no attribution notice for either was found (part 4: there
is no `NOTICE` file).

The `.archon/` directory holds 13 files, all named `exochain-*` or
`exoforge-*`. Eleven were first added on 2026-03-20 under the author name
Bob Stewart, one on 2026-06-29 under the same name, and one on 2026-07-12
under the author name Cursor Agent. They are configuration for that tool. They were not compared with the
tool's own distributed files, so copying or adaptation is neither shown nor
ruled out. Part 1 proposes `.archon/` as adjacent, so it would not move
with the core. "Paperclip" also appears as a co-author name on 35 commits
(F-45).

**Tracked `dist` bundles (part 4, F-29).** 196 built files are tracked:
76 under `packages/exochain-sdk/dist`, 56 under
`packages/exochain-sdk/dist-test` and 64 under
`packages/exochain-llm-proxy/dist`. A string search for licence banners, copyright lines other than the
Foundation's, and `node_modules/` paths found only the Foundation header
(62 matches). No file is larger than 200 KB. This suggests the bundles do
not inline third-party packages. It is a string search, not a review of the
build.

**Committed proof fixtures (part 2, F-8).** The two files in
`crates/exo-cgr-prover/fixtures/` were added in one commit, `160e3fe2`
(2026-08-17), together with the binary that generates them
(`src/bin/generate-cgr-receipt-fixture.rs`). The commit does not record the
machine, toolchain version or command that produced the committed bytes.
`crates/exo-verify/fixtures/offline-bundle/` was added in the audited
commit itself (#912) with a `README.md` that describes each file; the two
`.pem` files in it are test certificates, not private keys, by that
description.

Proposed disposition: **pending** for the Archon comparison and for the
attribution question the receipts raise (owner of `.archon/`, legal owner). `no_change` proposed for the `dist` bundles on
this evidence, conditional on a build review if a "notices complete" claim
is made. `patch` for the proof fixtures: record how the committed receipt
was generated, or regenerate it in CI. None blocks copying the core.
Part 4's condition stands: no "notices complete" claim until the Archon
lead is closed.

### F-50. Three documents in the proposed core have unclear standing

**`EXOCHAIN-FABRIC-PLATFORM.md`.** Line 31 reads "Classification:
CONFIDENTIAL" and line 33 "Document Owner: EXOCHAIN Foundation". The file
has been in the public repository since 2025-12-14 (`db44770f`) and has
carried the Apache-2.0 header since `97a4b973`. Part 1 proposes it as core.
A confidentiality marking and an open-source licence header sit on the same
public file and have not been reconciled. Line 37 of the file says it is
"not the normative specification" and names Specification v2.2 as
normative.

**The two root PDF files.** `EXOCHAIN_Specification_v2.2.pdf` and
`EXOCHAIN_Whitepaper_v1.0.pdf` were added on 2025-12-14 and 2025-12-15 by
the author name "exochain" through the hosting web interface ("Add files
via upload"). Their document information gives the author as "Un-named" and
the producer as a word processor. No editable source for either is tracked.
The only rights text found by string search is in embedded font notices.
`CONTRIBUTING.md` line 34 says that if the code disagrees with the
specification PDF, "the *code* is wrong". These checks identified no author
and no licence statement for the file the repository treats as its
governing specification. The PDFs were not rendered, so a statement inside
the page text may have been missed.

**Imported evidence.** Part 1 assigned no path to the class "imported
evidence" and left the review to this part (O-9). The keyword search in
Method item 6 found 11 candidate files. On reading, none identifies itself
as an outside party's report or as scanner output: the matches are the
marking above, in-house audit records, a test fixture, and documents that
discuss how such evidence must be handled. The class stays empty on that
evidence. A report pasted in without such wording would not be found this
way.

Proposed disposition: `patch` for `EXOCHAIN-FABRIC-PLATFORM.md` (the
document owner removes the marking or the file is withheld from the core).
Pending, document owner and legal owner, for the PDFs: record the author
and the terms, and confirm the normative designation the Markdown file
already states. As a precaution, **blocking** for copying those three files
under an Apache-2.0 claim until the owners answer. Not blocking for the
rest of the core.

### F-51. Files named as health-record requests are tracked in a product tree

17 PDF files named `hipaa-request-*` are tracked under
`livesafe/server/letters/` and have been in the public history since
`985cd9ba` (2026-07-04). Each is about 3.8 KB. They were deliberately not
opened, so whether they hold real personal or health data, templates or
test output is unknown.

Why it matters for the split. The files are in a product tree and would not
move with the core. But the issue keeps the full history in the legacy
repository and authorises no rewriting, so if they do hold personal data,
it stays public there whatever the split does.

Proposed disposition: pending, LiveSafe owner and the security panel, to
inspect the files and decide. Out of scope for the core copy.
**Blocking** for any statement that the repository or its history is free
of personal data.

## Proposed disclosure requirements

The issue asks for disclosure requirements. These are proposals for the
split plan and the panel, drawn from the findings above. None is in force.

| ID | The new repository should state | From |
| --- | --- | --- |
| D-1 | The source repository under its new name, and the exact source commit the files were copied from | Issue #904; F-47 |
| D-2 | Whether it carries no history, or a filtered history; if filtered, the rule used and that commit identifiers differ from the source | F-41, F-42, F-47 |
| D-3 | If no history is carried: that per-file author names and co-author trailers are recorded only in the source repository's history, and that those names are unverified | F-44 |
| D-4 | That the source history records commits naming AI tools as author or co-author | F-45 |
| D-5 | That commit signatures in the source history are partial and were not verified | F-46 |
| D-6 | Every omission or redaction made in copying, the reason, and its successor location where one exists, without reproducing sensitive removed content. Part 7 keeps the proposed list in its section "Proposed omissions and their successor locations" and in `proposed-omissions.tsv` | Issue #904; F-50, F-51 |
| D-7 | That earlier licence statements differed: the root manifest field before 2026-03-20, the AGPL declaration in the WASM demo package until 2026-05-09 and the tags that contain it, the Apache headers on product files between 2026-05-10 and 2026-07-15, and the change to the `LICENSE` text, with a pointer to the legal position document | F-43 |
| D-8 | How to verify a release made before the split, naming the repository that holds its source commit and attestation | F-47, F-48 |
| D-9 | For each kind of commit, pull-request and issue reference in copied records, whether it refers to the source repository | F-47 |
| D-10 | If history is filtered: a published map from source to rewritten commit and tag identifiers, the commits dropped, how merges were handled, and that signatures on rewritten commits no longer verify | F-42, F-46, F-47 |
| D-11 | Which branches and tags the legacy repository keeps, including the two tags outside the audited history | O-36, O-42 |
| D-12 | The provenance questions still open at the time of the copy: attribution for the outside projects the core names, documents withheld or of unsettled standing, and that no content scan for secrets or third-party code was made | F-44, F-49, F-50, O-38 |
| D-13 | The source commit of any later import from the legacy repository, not only the first copy | F-47 |

Concerns that apply only if the new repository carries a filtered history.
No filter was specified or run, so these are expected effects:

- the committed `target/` objects must be inspected or excluded (F-41);
- 95 mixed commits would keep messages about product work (F-42);
- rewritten commits and their descendants get new identifiers, so in-tree
  references and release records would point at commits the new repository
  does not contain (F-47);
- signatures on rewritten commits no longer verify (F-46);
- tags would have to be recreated on rewritten commits, and five existing
  tags contain either Apache-headed product files or the AGPL package
  declaration (F-43);
- a filter by path keeps the history of every kept file, so it would
  republish the AGPL root manifest at `8089b6aa`, the `LICENSE` change, and
  the history of `EXOCHAIN-FABRIC-PLATFORM.md` (F-43, F-50);
- git history carries full author and committer e-mail addresses. The
  tables in this audit reduce them to domains; a copied history would not.

## Findings summary

| ID | Finding | Disposition | Blocking |
| --- | --- | --- | --- |
| F-41 | Two unrelated histories joined on 2026-03-18; 7,925 build-output paths were committed and later removed | `no_change` to history; inspection pending | Only for a history option that keeps those objects |
| F-42 | 95 commits change core and product paths together | Pending, split plan | Only for a filtered-history option |
| F-43 | Licence statements changed: the `LICENSE` text was edited; AGPL in the root manifest for two days and in a demo package until May, inside two tags; 204 `command-base/` files Apache-headed for two months, inside three tags | Pending, legal owner | Yes: claims about legal effect, "always Apache-2.0", or standard licence text |
| F-44 | One author name on 1,380 of 1,479 non-merge commits that touch core or adapter paths; other parties credited in trailers; no sign-off, separate agreement or holder record found | Pending, legal owner | Yes: Apache-2.0 claim over the 290 headerless files |
| F-45 | 221 non-merge commits name an AI tool or agent (lower bound) | Pending, legal owner; disclose | Yes: any wholly-human-authored claim |
| F-46 | 1,235 unsigned commits and 575 merges against rules requiring signatures and linear history | `patch` rules or enforcement | Yes: claims that all commits are signed or verified |
| F-47 | 502 commit references and 792 pull-request links in core and adapter records point at the legacy repository; this audit's tables add more | `patch` under the split plan | Yes: cutover |
| F-48 | Release attestations and publication are tied to the current repository's identity (inferred) | Pending, release owner | Yes: first release from the new repository |
| F-49 | Core code states material use of two outside MIT projects, with no notice found; Archon comparison open; built bundles show no third-party banners; proof fixtures lack a generation record | Pending; `no_change`; `patch` | No; "notices complete" stays conditional |
| F-50 | A public file marked CONFIDENTIAL under an Apache header; a specification PDF and a whitepaper PDF with no author or terms identified | `patch`; pending | Yes (precaution): for those three files |
| F-51 | 17 tracked files named as health-record requests, not opened | Pending, LiveSafe owner and security panel | Yes: any "free of personal data" statement |

## Items earlier parts sent here

| Item | From | Status |
| --- | --- | --- |
| O-9, imported evidence | Part 1 | Addressed in F-50 by a keyword search; class stays empty with that limit |
| F-8, provenance of committed receipts | Part 2 | Addressed in F-49; generation record missing |
| F-13, named arrangements in `exo-economy` | Parts 3 and 4 | Addressed in F-49: library functions state material use of two MIT projects; attribution and copying **not resolved** |
| F-22, authorship of 290 headerless files | Part 4 | Author names given in F-44. **Not resolved**: the right to apply the header is a legal-owner decision |
| F-24, Archon lead | Part 4 | Still open (F-49) |
| F-24 and F-29, `dist` bundles | Part 4 | String search done (F-49); build not reviewed |
| F-27, authority to grant the licence | Part 4 | **Not resolved.** No record of the holder's standing found (F-44) |
| O-24, AGPL manifest field | Part 4 | Dated in F-43, which also finds a second AGPL declaration lasting until 2026-05-09; registry publication not checked |
| `LICENSE` described as Apache-2.0 text | Part 4 | **New here** (F-43): the file was edited after the first commit; comparison with the published text still to do |
| O-25, contributor terms | Part 4 | Confirmed absent across the wider search in F-44 |
| O-27, three spellings of the copyright holder | Part 4 | Unchanged; no document defines the entity (F-44) |
| F-39, package contents | Part 5 | **Not done here.** Still needs a release dry run on CI |

## Observations

| ID | Observation | Evidence | Goes to |
| --- | --- | --- | --- |
| O-35 | Three similar author-name strings appear (John Fitzpatrick, John C Fitzpatrick, John C. Fitzpatrick) and there is no `.mailmap`. Whether they are one person was not verified; counts by name keep them apart. | `history-commits.tsv` | Part 7 |
| O-36 | Two tags, both named `refuted-do-not-merge/…`, point at commits that are not ancestors of the audited commit. Which branches and tags the legacy repository keeps is a split-plan matter. | `git tag`, ancestry check | #903 |
| O-37 | Raised to finding F-51. | | |
| O-38 | A search of path names in the history for key, token and credential file names found no `.env` file, private key or token file. The 15 names it flagged are source files, documents and two test certificates. The search has gaps: the 7,925 folded `target/` paths were not tested, names ending `.env.example`, `.env.sample` or `.env.template` are skipped by design, and it is one fixed pattern. No content scan of the history was run, and no secret-scanning step was found in `ci.yml` by name. This is not evidence that the history holds no secrets. | `history-paths.tsv`, column `name_flag`; `history_scan.py` lines 65-70, 149-161 | Security panel |
| O-39 | The header commit `97a4b973` changed 1,194 paths in one commit under one author name. How it was produced and what review preceded it were not examined. A bulk change of this size is consistent with part 4's caution that a header alone does not show per-file review of authorship. | `history-commits.tsv` | Part 7 |
| O-40 | Names that look like automation appear as authors or committers: Cursor Agent (46 commits), "ExoForge Bot" (committer on 14), Aeon/ExoChain Council (5), railway-app[bot] (4), cursor[bot] (1). The names alone do not show what made the commits. | `history-commits.tsv` | Part 7 |
| O-41 | `CONTRIBUTING.md` requires approval by two independent human maintainers before merge (lines 199, 216). Pull-request reviews were not read, so this record says nothing on whether that rule was met. | `CONTRIBUTING.md` | Part 7; panel |
| O-42 | The local clone used for this record had 761 remote-tracking references across two remotes when checked on 2026-11-17 (a count that changes with every fetch). Only commits reachable from the audited commit were analysed. | `git for-each-ref refs/remotes` | #903 |

## Limits

- Only commits reachable from the audited commit were analysed. Other
  branches, pull-request heads and deleted branches were not.
- Merge commits are listed, but the paths a merge changes are not counted,
  so content introduced while resolving a merge is not attributed.
- Author and committer names are whatever was typed into git. Counts by
  name are not counts by person, and nothing here verifies identity. Dates
  are the author dates git records; they were not checked against anything
  else.
- A rename is counted as a change to both names. Paths that no longer exist
  are classified by rule, not by a reviewed inventory. Counts are per path,
  not per line: they do not show who wrote which part of a file.
- This record was prepared under one of the author names in this history
  (Walley Fipps, 3 commits, one core path), with AI assistance, and has had
  no review by a party outside that team.
- Trailer counts are lower bounds on AI-assisted work.
- No signature was verified.
- No file content in the history was read except the specific files named
  in the findings. In particular the `target/` objects and the LiveSafe
  letters were not opened.
- Pull-request reviews, registry records, published packages and existing
  attestations were not read.
- The two PDF files were not rendered.
- The Archon comparison was not made.
- This record gives no legal opinion. Where it says a question is legal, it
  means the accountable owner has to answer it.

## Reproduction

From the repository root, with a full clone:

```bash
python -I docs/audit/core-separation-904/history_scan.py . e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e docs/audit/core-separation-904/path-classification.tsv history-commits.tsv history-paths.tsv
```

```bash
sha256sum history-commits.tsv history-paths.tsv
```

```bash
git rev-list --max-parents=0 e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e
```

```bash
git log -1 --format='%H %P %s' da518a1e
```

```bash
git show 8089b6aa:Cargo.toml
```

```bash
git show a2af67aa~1:command-base/.claude/CQI-BOOTSTRAP-CHANGELOG.md
```

```bash
git log --format='%h %ad %s' --date=short --diff-filter=D e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e -- target/.rustc_info.json
```

```bash
git show f09c610b -- LICENSE
```

```bash
git show v0.1.0-beta:demo/packages/exochain-wasm/package.json
```

```bash
git diff --name-status f3de1fc8 da518a1e
```

```bash
gh api repos/exochain/exochain/contributors
```

`history_scan.py` imports `classify_paths.py` (part 1) from the same
directory. The last command needs network access and a GitHub token.

The counts in F-44 and F-45 come from filtering the two tables on the
columns named in `history_scan.py`. The reference counts in F-47 come from
a helper script that is not tracked; its rule is given in Method item 5.

## Path classification of this record

| Path | Proposed class | Basis |
| --- | --- | --- |
| `docs/audit/core-separation-904/06-HISTORY-AND-PROVENANCE.md` | EXOCHAIN core | Part 1 rule C5 (`docs/audit/`) |
| `docs/audit/core-separation-904/history_scan.py` | EXOCHAIN core | Part 1 rule C5 |
| `docs/audit/core-separation-904/history-commits.tsv` | EXOCHAIN core | Part 1 rule C5 |
| `docs/audit/core-separation-904/history-paths.tsv` | EXOCHAIN core | Part 1 rule C5 |

No file under `crates/`, `packages/`, `governance/`, `tools/`, CI or
deployment was changed for this record.

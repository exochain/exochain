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

# Clean-separation audit (#904), part 7: findings register

**Status: DRAFT audit evidence. Not panel-reviewed. Not a split plan, not
legal advice, and not a cryptographic certification.**

Issue #904 asks the audit to "produce a findings register with each
omission/redaction explained and linked to its successor location", and
adds: "This is not a cryptographic certification." This record is that
register. It collects the 52 findings of parts 1 to 6 in one table, says
which of them block the split (#903) and which only block a statement,
lists what is proposed to be left out of a new core repository and where
each left-out item would live afterwards, and sets the result against the
issue's acceptance criteria.

**No omission and no redaction has been made.** No file was removed, moved,
renamed or edited in the audited tree, and no history was rewritten. Every
omission and redaction below is a proposal for the panels and the split plan
owner. The register is the place where an executed omission would be
recorded once someone is authorised to make it.

It adds no new finding. It does add three things the earlier parts left to
it: the per-file sort of product-naming documents (part 3, F-19), the list
of proposed omissions (part 6, D-6), and the status of every forwarded
observation.

## What this record does and does not establish

It establishes:

- one row per finding F-1 to F-52, with the disposition its part proposed,
  the owner its part named, and what it blocks;
- that the register and the six part records agree on which findings exist
  and which part defines each (checked by script);
- a proposed handling for every one of the 3,175 tracked paths: copy, leave
  in the legacy repository, pending a named decision, or undecided;
- a proposed kind and disposition for each of 159 product-naming files at
  the root, under `docs/` and under `governance/`;
- where each of the 42 observations ended up.

It does not establish:

- that any finding is true beyond the evidence its own part gives. Nothing
  was re-examined here except one keyword search (O-34) and the front
  matter of two governance files (document sort). An error in a part is
  carried into the register;
- that any disposition is decided. Every row has status `open`. No panel
  review of any part is recorded, and reviews by AI agents during drafting
  are not panel or owner reviews;
- that the proposed core is free of product material, or that it is
  Apache-2.0 throughout. Parts 3, 4 and 6 give reasons neither statement
  can be made today (see "Statements the evidence does not support");
- that the proposed core builds or passes tests without the product trees.
  No such run exists (F-40);
- a successor location in the form of a URL. Issue #903 has not selected
  the legacy repository's name;
- anything cryptographic. Hashes in this record identify the files it
  describes. They do not certify their content, authorship or completeness.

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` (`main`) |
| Tracked paths | 3,175 |
| Path table (part 1) | `path-classification.tsv`, SHA-256 `0640fb42fa7d2b69ff13599d9e2ee25ea825bfa8cd4553a0ef5a7ac280d79667` |
| Fingerprint table (part 3) | `product-fingerprints.tsv`, SHA-256 `92b105d61be0ae1a9e9bf0b275663270d9961be92e7825bf40c8b5c1da347a5b` |
| Register | `findings-register.tsv`, 52 rows |
| Omission groups | `proposed-omissions.tsv`, 23 rows |
| Document sort | `document-sort.tsv`, 159 rows |
| Issue #904 | Open, no comments, read 2026-11-17 |
| Issue #903 | Open, no comments, read 2026-11-17; "blocked by #904" |

All file names are relative to `docs/audit/core-separation-904/`. The
commit is the one every earlier part audited. `main` may have moved since;
nothing here was checked against a later commit.

## Method

1. Every summary-table row `| F-n |` in parts 1 to 6 was copied into
   `findings-register.tsv`: its part, the issue category it answers, the
   proposed disposition, any condition, the owner, and what it blocks.
   The `owner_basis` column says whether the part names that owner, whether
   this record inferred it from a related finding or decision table, or
   whether there is none. `findings_register.py` then checks the table against the
   parts (ids, part numbers, vocabulary, links).
2. What each finding blocks was reduced to one of five values. Where a
   part's one-line summary cell and its full finding text differ, the full
   text was followed (this moves F-22 and F-31, whose summary cells read
   "Yes", to `claim`; the note column says so):

   | Value | Meaning |
   | --- | --- |
   | `cutover` | The part says the finding blocks the split or a green core build or test run, restricts copying named files, or needs a recorded panel decision first |
   | `release` | Copying could proceed, but a release or distribution from the new repository could not |
   | `claim` | The split could proceed, but a named statement could not be made |
   | `conditional` | It blocks only under an option that has not been chosen, or only through other findings |
   | `none` | The part says it does not block |

   The reduction is this record's reading. The part's own wording is kept
   in the `blocking_note` column and governs if the two differ.
3. `omission_groups.py` assigns each row of part 1's path table a handling
   by path prefix and proposed class, and writes one row per group.
4. `document_sort.py` assigns each product-naming root, `docs/` and
   `governance/` file a kind from its path alone, by a fixed rule table.
5. Observations O-1 to O-42 were traced through the "items earlier parts
   sent here" tables of parts 5 and 6 and the finding text of parts 3 to 6.

Dispositions use the vocabulary of the earlier parts: `patch`,
`adjacent_patch`, `no_change`, and `pending` where a named owner has to
decide first.

## The register

The full table is `findings-register.tsv`. This is its short form. An
owner in plain text is named by the part. An owner marked † is **inferred
here** from a related finding or from part 2's decision table and is a
suggestion, not an assignment (14 rows). "Not named" means no part names
one and this record suggests none (8 rows).

### Dependencies (part 2)

| ID | Finding | Proposed | Owner | Blocks |
| --- | --- | --- | --- | --- |
| F-1 | Kernel crate manifest requires four DAG DB crates and `sqlx` directly on native targets, and seven DAG DB crates through them | `patch` | Architecture and Security panels | cutover |
| F-2 | Kernel crate takes `exo-api` by default | `no_change` if accepted as core | Architecture and Security panels | cutover |
| F-3 | Decision Forum crate required, ungated, by gateway, consensus and WASM | `no_change` under option A | Architecture panel | cutover |
| F-4 | Four declared Decision Forum dependencies not named in source | `patch` | not named | none |
| F-5 | No core-class crate requires economy; three adapters do | `no_change` under option A | Architecture panel | cutover |
| F-6 | Four core-class crates outside the node and gateway closures | `no_change` | Architecture panel | none |

### Product fingerprints (part 3)

| ID | Finding | Proposed | Owner | Blocks |
| --- | --- | --- | --- | --- |
| F-9 | LiveSafe-named API in `exo-avc`, SDK, node route, credential, CLI | `patch`, form undecided | Architecture panel | cutover |
| F-10 | CrossChecked anchor in `exo-api` and `exo-node` | `patch`, form undecided | Architecture panel | cutover |
| F-11 | Four LiveSafe tables, erasure path, root deployment files | `patch`; tables pending | Architecture and Security panels | cutover |
| F-12 | ExoForge, 0dentity and Telegram surfaces in the node | `patch` (ExoForge); rest pending | Architecture panel † | cutover |
| F-13 | Named arrangements in the economy crate's API | `patch` | Architecture panel † | cutover |
| F-14 | CommandBase metadata in `exo-catapult` | `patch` if the crate is kept | Architecture panel | conditional |
| F-17 | Decision Forum crate not resolved by a name search | `no_change` in part 3 | Architecture panel | cutover |
| F-18 | Smaller code references | `patch` | not named | none |
| F-20 | VitalLock in a core key-exchange context | `no_change` (constant); `patch` (comment) | Security panel | cutover |

### Builds, CI and deployment (parts 2, 3 and 5)

| ID | Finding | Proposed | Owner | Blocks |
| --- | --- | --- | --- | --- |
| F-8 | Workspace tests read fixtures from an excluded crate | `patch`, pending a fixture decision | Architecture panel | cutover |
| F-15 | Two gateway unit tests read 19 files in five adjacent trees | `patch` | not named | cutover (inferred) |
| F-16 | Guards and CI steps inspect adjacent trees | per assertion | not named | cutover (inferred) |
| F-31 | CI fails at the audited commit on Gates 6 and 7 | `patch` | core maintainers | claim |
| F-32 | No required checks visible on `main` | pending | administrator, Security panel | claim |
| F-33 | At least twelve guard steps fail without the adjacent paths | `patch`; `adjacent_patch`; pending | core maintainers † | cutover |
| F-34 | Gate 21 runs `demo/` code | pending classification | Architecture panel † | cutover |
| F-35 | Four CI jobs run two tests that read 19 product files | `patch` | core maintainers † | cutover (inferred) |
| F-36 | Only tracked node deployment runs through the LiveSafe workflow | `patch`; `adjacent_patch`; hosting pending | operations owner, Security panel | cutover |
| F-37 | Images copy only proposed-core paths | `no_change`; `patch` dead config | core maintainers † | none |
| F-38 | Three compiler versions (and a nightly for formatting), little `--locked`, images by tag | `patch` | core maintainers † | claim |
| F-39 | Release names no product tree; inherits CI couplings | `no_change`; contents pending | release owner † | conditional |
| F-40 | No CI job builds or tests the core without the sibling trees; the deploy image build compiles two binaries from `crates/` alone but runs no tests | `patch` (CI job) | core maintainers, Build Lead | cutover |

### Documents and inventory (parts 2 and 3)

| ID | Finding | Proposed | Owner | Blocks |
| --- | --- | --- | --- | --- |
| F-7 | `AGENTS.md` and `crates/README.md` differ from the manifests | `patch` | not named | none |
| F-19 | Documents name the products | by kind; see "Document sort" | not named | none |
| F-21 | Vendor-class files inside adjacent trees | `adjacent_patch` | tree owners † | none |

### Licences and notices (parts 4 and 6)

| ID | Finding | Proposed | Owner | Blocks |
| --- | --- | --- | --- | --- |
| F-22 | 290 eligible non-adjacent files lack the header; check fails, not in CI | `patch` after F-44 | legal owner | claim |
| F-23 | Dependency policy stated two ways | `patch` | not named | none |
| F-24 | No NOTICE or COPYING file; third-party source not ruled out | pending | panel, legal owner † | claim |
| F-25 | `tools/syntaxis` declares MIT under Apache headers | `patch` once intent is stated | not named | none |
| F-26 | Licence-text placement; package contents unverified | `patch` (three units); rest pending | release owner † | release |
| F-27 | Product-named code under Apache headers | pending | legal owner, Architecture panel † | cutover |
| F-28 | Adjacent is not a licence class | `adjacent_patch` | tree owners † | none |
| F-29 | Files outside the header check; two PDFs that state other terms | `no_change`, conditional; PDFs pending | panel; document owner, legal owner | claim |
| F-30 | Vendor-class files inside proprietary trees | `adjacent_patch` | tree owners | none |
| F-49 | Stated use of two outside MIT projects, no notice found; Archon comparison open; proof fixtures lack a generation record | pending (Archon, attribution); `no_change` (`dist` bundles); `patch` (fixture record) | owner of `.archon/`, legal owner | claim |
| F-52 | `cybermedica/` carried Apache-2.0 headers and manifest until 2026-07-10, inside three tags; escalated as the issue asks | pending | legal owner | claim |

### History and provenance (part 6)

| ID | Finding | Proposed | Owner | Blocks |
| --- | --- | --- | --- | --- |
| F-41 | Two histories joined; 7,925 build-output paths committed, later removed | `no_change` to history; inspection pending | split plan owner † | conditional |
| F-42 | 95 commits change core and product paths together | pending | split plan owner | conditional |
| F-43 | Licence statements changed over time, inside tags; the terms file held a contributor agreement until 2026-05-10 | pending | legal owner | claim |
| F-44 | One author name on 1,380 of 1,479 non-merge commits that touch core or adapter paths; inbound terms changed in 2026-05; no record of acceptance or of the holder's standing | pending | legal owner | claim |
| F-45 | 221 non-merge commits name an AI tool or agent (lower bound) | pending; disclose | legal owner | claim |
| F-46 | 1,235 unsigned commits and 575 merges against the stated rules | `patch` | core maintainers | claim |
| F-47 | 502 commit references and 792 pull-request links in core and adapter records point at the legacy repository | `patch` under the split plan | split plan owner | cutover |
| F-48 | Release attestations tied to the current repository identity (inferred) | pending | release owner | release |
| F-50 | A public file and the specification PDF marked CONFIDENTIAL; the whitepaper PDF states CC BY-NC-SA 4.0 | `patch`; pending | document owner, legal owner | cutover (those three files, under an Apache-2.0 claim) |
| F-51 | 17 tracked files named as health-record requests, not opened | pending | LiveSafe owner, Security panel | claim |

Totals: 22 `cutover`, 2 `release`, 13 `claim`, 4 `conditional`, 11 `none`.

## What blocks the split

Twenty-two findings block #903's cutover as their parts state them, and two
more block the first release after it. The table groups them by who has to
act. It is a routing summary only: **each finding's own closure conditions,
in its part, still apply**, and the last column names the main ones without
replacing them.

| Group | Findings | Main conditions (not exhaustive) |
| --- | --- | --- |
| Boundary decisions | F-1, F-2, F-3, F-5, F-8, F-17 | The Architecture panel (with Security for DAG DB and `exo-api`) records which boundary crates travel with the core; part 2's decision table lists eight items, all pending. Recording a choice is not enough: part 2 attaches conditions to option A for Decision Forum and for economy, and one of them, reading the Decision Forum crate's 9,145 lines against a stated definition of "primitive", was not done (F-17). F-8 needs a decision for each fixture: copied, supplied from elsewhere, or regenerated |
| Product names in the core's public surface | F-9, F-10, F-11, F-12, F-13, F-20, F-27 | The Architecture panel chooses the form for each: a rename, a relocation, or (for F-9 and F-10) accepting a documented named integration. The Security panel records a decision on F-20 and on the LiveSafe tables and erasure path. The legal owner answers F-27 |
| A core that builds and tests alone | F-15, F-16, F-33, F-34, F-35, F-40 | Product assertions move out of core tests and guards, `demo/` is classified, and the CI job part 5 specifies under F-40 (named gates, the DB integration configuration, both image builds) runs without the product trees. Until it has run, F-15, F-16 and F-35 are inferences from reading; F-33's guard failures were seen only in a local experiment (part 5), not in CI |
| An independent deployment | F-36 | A node deployment path exists that does not run through the LiveSafe workflow and hosting project |
| References and three files | F-47, F-50 | The split plan says how each kind of reference to the legacy repository is handled. For F-50, part 6 restricts copying three files *under an Apache-2.0 claim* until the document owner and legal owner answer |
| First release (not the copy) | F-26, F-48 | Each packaged unit's licence files are resolved before that unit is distributed; one existing attestation and each registry's publisher settings are read before the first release from the new repository |

F-31 (CI fails at the audited commit on two advisory gates) is counted as
`claim` because its full text blocks "any 'green CI' or
advisory-compliance claim", while its summary cell reads "Yes: no green CI
baseline". Either way a split that wants to show a passing core afterwards
needs a passing baseline first.

Four findings block only under a choice not yet made or through other
findings: F-14 (if `exo-catapult` is kept), F-39 (through F-31 and F-33 to
F-35, and only while the package classifications stay as proposed), and
F-41 and F-42 (if the new repository carries history).

## Statements the evidence does not support

The issue's acceptance criteria include "No unsupported Apache-2.0 or
product-free claim". This record makes neither claim. The table lists
statements that the findings rule out today, and what each would need.

| Statement | Why not, today | Finding |
| --- | --- | --- |
| "The core is free of product material" | Product names are in public APIs, a route, credentials, schema and an erasure path; 12 binary files were not scanned, and the specification PDF names 0dentity, LegalDyne and LYNK; unnamed product logic was not searched for | F-9 to F-13, F-18, F-20; part 3 "Not scanned" |
| "The core is Apache-2.0 throughout" | 290 eligible files lack the header; who may apply it is not recorded; a root PDF states CC BY-NC-SA 4.0 and another is marked CONFIDENTIAL; the terms file says documentation is not automatically Apache-2.0 | F-22, F-29, F-44, F-50 |
| "CyberMedica, or the products, were never offered under Apache-2.0" | `cybermedica/` files carried the Apache header and its manifest said Apache-2.0 from 2026-05-26 to 2026-07-10, and 204 `command-base/` files carried the header from 2026-05-10 to 2026-07-15, inside three release tags | F-43, F-52 |
| "The repository has always been Apache-2.0" or "ships the standard licence text" | The root manifest declared AGPL for two days, before the first tag; a demo package declared it until 2026-05-09, inside two tags; the `LICENSE` text was edited and has not been compared with the published text | F-43 |
| "Third-party notices are complete" | No NOTICE file; two outside projects are named as sources without a notice; one comparison is open | F-24, F-49 |
| "Published packages carry the right licence files" | Package contents were not inspected; that needs a release dry run | F-26, F-39 |
| "The core builds and passes tests on its own" | No test run without the sibling trees exists. The deploy image build compiles two binaries from `crates/` alone; its runs were not inspected | F-40 |
| "Builds are reproducible" | Three compiler versions (and a nightly for formatting), little `--locked`, images by tag | F-38 |
| "CI gates are enforced on `main`" | No required checks were visible to the account used | F-32 |
| "All commits are signed or verified" | 1,235 commits carry no signature field; none was verified | F-46 |
| "The code is wholly human-authored" | 221 non-merge commits name an AI tool or agent, a lower bound | F-45 |
| "The tree or its history holds no personal data or secrets" | 17 files named as health-record requests were not opened; history was searched by file name only | F-51, O-38 |
| "The new repository can publish and attest releases as the current one does" | Attestations and publication are tied to the current repository identity (inferred; no attestation or registry setting was read) | F-48 |
| "This register certifies the split" | It is a list of proposals and open questions, checked for form only | this record |

## Open decisions by owner

Findings marked † have an owner inferred here, not named by their part.
Observation owners are this record's suggestions unless the observation's
own row names one (O-28, O-30, O-32, O-36, O-38, O-42 do).

| Owner | Decides | Findings and items |
| --- | --- | --- |
| Architecture panel | Boundary crates and fixtures; form of product-name patches; class of `demo/`, `web/`, `gap/`, `tools/syntaxis/`; which record governs path class | F-1 to F-3, F-5, F-6, F-8 to F-11, F-12†, F-13†, F-14, F-17, F-27†, F-34†; part 1's 379 judgment rows; O-6, O-7, O-13 |
| Security panel | DAG DB and `exo-api` in the core; LiveSafe tables and erasure; VitalLock constant; required checks; hosting; the 17 letters; identifiers in a tracked workflow; history secret scan | F-1, F-2, F-11, F-20, F-32, F-36, F-51; O-32, O-38; O-23 (suggested) |
| Panel, not specified by the part | Notice mechanism for files outside the header check | F-24†, F-29 |
| Accountable legal owner | Right to apply headers; effect of earlier licence statements, CyberMedica's among them; contributor terms; AI-assisted commits; notices; standing of three files | F-22, F-24†, F-27†, F-29, F-43, F-44, F-45, F-49, F-50, F-52; D-3, D-4, D-7, D-12 |
| Document owner | The CONFIDENTIAL markings on the Markdown file and the specification PDF; whether the whitepaper's CC BY-NC-SA 4.0 licence stands | F-29, F-50 |
| Owner of `.archon/` | Comparison with the outside project | F-49 |
| Split plan owner (#903) | History option; reference handling; legacy name; branches and tags kept; where disclosures are published | F-41†, F-42, F-47; O-36, O-42; D-1 to D-13 |
| Release owner | Package contents; first release from a new repository | F-26†, F-39†, F-48; D-8 |
| Core maintainers | Advisories; guards; toolchain pinning; the sibling-free job; signature rules | F-31, F-40, F-46; F-33†, F-35†, F-37†, F-38† |
| Build Lead | Runner placement for the sibling-free job | F-40 |
| Repository administrator | Branch protection as configured | F-32 |
| Operations owner | Independent node deployment | F-36 |
| LiveSafe owner and other tree owners | Files that leave with their trees | F-30, F-51; F-21†, F-28†; O-28, O-30, O-31 |
| Not named, none suggested | An owner is needed before these can close | F-4, F-7, F-15, F-16, F-18, F-19, F-23, F-25 |

The Operations panel named in issue #904 has no finding assigned to it by
name in parts 1 to 6. F-31, F-36, F-38 and F-40 are the likeliest to fall to
it; that is for the panels to say.

## Proposed omissions and their successor locations

"Omission" here means a tracked path at the audited commit that the new
core repository would not contain. `proposed-omissions.tsv` has one row per
group. Membership is by path prefix and proposed class, so the per-path
list can be rebuilt from part 1's table.

**Successor location.** Issue #903 keeps the current repository, "retaining
full history and product subtrees there", under a legacy name it has not
yet selected. For every group below the proposed successor location is
therefore: *the legacy repository, same path, at commit
`e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` or later*. No URL can be given
until the name is chosen, and #903 lists the redirect behaviour of the old
URL as unverified. If a product later moves to a repository of its own,
that is a second move and needs its own entry.

| Handling | Paths | Share |
| --- | ---: | --- |
| Copy to the new repository | 1,241 | Proposed core and adapter paths, lockfiles and other vendor-class paths in kept directories |
| Proposed to omit: whole product tree | 1,668 | Eight trees. For three of them (`demo/`, `web/`, `gap/`; 360 paths) the classification itself is pending |
| Proposed to omit: adjacent file in a kept directory | 58 | Eleven locations. For two (`tools/sybil-cli/`, `docs/decision-forum/`; 21 paths) part 2 lists the decision as pending |
| Proposed to omit, core-class, pending | 12 | `tools/syntaxis/` |
| Tracking undecided | 196 | Tracked build output under `packages/` |
| **Total** | **3,175** | |

Every omission is a proposal. The split in the table is between proposals
that rest on an existing in-repo classification and those where a part
says a named decision is still open: 393 paths (360, 21 and 12) are in the
second kind. Part 5 also leaves open where the guards that test `.archon/`
content go (F-33), which bears on that directory's 13 paths.

The 1,241 "copy" paths are the remainder, not a reviewed list. They still
include every boundary crate whose inclusion is pending (F-1 to F-6) and
the three files of F-50. This audit's own directory is not among the 3,175
paths: it is not tracked at the audited commit.

### Whole trees proposed to stay in the legacy repository

| Tree | Paths | Of which vendor-class | Reason | Basis | Confirmation still needed |
| --- | ---: | ---: | --- | --- | --- |
| `livesafe/` | 505 | 5 | Product; excluded from the Cargo workspace | Part 1 rule A1 and v0.2.6 record | F-11, F-36, F-51 before it is detached |
| `cybermedica/` | 386 | 1 | Product | Part 1 rule A2 | None raised |
| `command-base/` | 257 | 1 | Product | Part 1 rule A3 | Replacement for its `file:` link to the WASM build (O-31) |
| `demo/` | 217 | 37 | Demonstration apps and generated coverage | Part 1 rule A4, V4 | **Pending** classification: CI Gate 21 runs it (F-34) |
| `site/` | 145 | 1 | Website | Part 1 rule A7 | None raised |
| `web/` | 84 | 1 | Decision Forum web UI | Part 1 judgment row | **Pending**: follows the Decision Forum decision (F-3) |
| `gap/` | 59 | 0 | Incubator workspace | Part 1 judgment row | **Pending**: seven files discuss core gaps |
| `exoforge/` | 15 | 0 | Product | Part 1 rule A5 | F-12; replacement for its `file:` link (O-31) |

### Adjacent files inside directories that would be copied

| Location | Paths | Reason | Linked |
| --- | ---: | --- | --- |
| `.archon/` | 13 | Agent commands and workflows for an outside tool | F-16, F-33, F-49 |
| `.claude/`, `.cursor/`, `.superpowers/` | 3 | Developer and agent tool state | Part 1 judgment row |
| `.github/workflows/` (`livesafe-ci.yml`, `livesafe-railway-deploy.yml`, `exoforge-triage.yml`) | 3 | Automation for one product | F-36, F-12 |
| `.github/ISSUE_TEMPLATE/` | 3 | Templates tied to the ExoForge triage flow (part 1 rule A15) | F-12 |
| `scripts/livesafe-railway-smoke.sh` | 1 | Product deployment check | F-36 |
| `docs/commandbase-foundation/` | 10 | Product documentation | F-19 |
| `docs/decision-forum/` | 5 | Product documentation | F-3 |
| `docs/heartfield/` | 4 | Product documentation | F-19 |
| `tools/sybil-cli/` | 16 | Product tool; a core guard tests it | F-3, F-33 |

Removing the three issue templates would leave the new repository with
none; the split plan would need to supply replacements.

### Pending, undecided and precautionary

| Item | Paths | State | Decision owner |
| --- | ---: | --- | --- |
| `tools/syntaxis/` | 12 | Part 2 proposes it stays in the legacy repository; core-class in part 1; MIT manifest under Apache headers (F-25) | Architecture panel |
| `packages/exochain-sdk/dist`, `dist-test`; `packages/exochain-llm-proxy/dist` | 196 | Tracked build output. On provenance, part 6 proposes `no_change` (a string search found no third-party banners, F-49; the build was not reviewed). **Whether the new repository tracks build output at all is a separate question no part answers** (O-4): copy as tracked, or do not track and build at release | Not named; release owner suggested |
| `EXOCHAIN-FABRIC-PLATFORM.md`, `EXOCHAIN_Specification_v2.2.pdf`, `EXOCHAIN_Whitepaper_v1.0.pdf` | 3 | Part 6 (F-50) blocks copying them *under an Apache-2.0 claim* until the owners answer. Its remedies: for the Markdown file, the document owner removes the marking or the file is withheld; for the PDFs, the owners say whether the specification's CONFIDENTIAL marking and the whitepaper's CC BY-NC-SA 4.0 licence stand, and confirm the normative designation the Markdown file states. **This record adds its own suggestion**: hold all three out of the first copy until then. The PDFs' text was extracted after the owner's review: the specification names 0dentity, LegalDyne and LYNK, reserved marks in its Appendix H, and neither file names the other products (part 3, "Not scanned") | Document owner, legal owner |
| Boundary crates and their documents | part 2 | Not proposed for omission. Option B for economy (issue #902) and the `exo-catapult`, `exo-messaging`, `exo-tenant` and `exo-cgr-*` questions would add omissions if chosen | Architecture panel |
| `history-commits.tsv`, `history-paths.tsv`, and the other tables in this directory | this audit | They describe the legacy repository at one commit and cite its commit ids (F-47). This directory is not part of the audited tree. Suggested: keep the tables with the audit record wherever the panel files it, labelled as describing the source repository; do not regenerate them in the new one | Split plan owner |

## Proposed redactions

"Redaction" here means changing text in a file that is copied, as opposed
to leaving the file out. None has been made. Each is a finding with a
`patch` disposition; the register's `omission_or_redaction` column marks
them.

| What would change | Findings | Successor location of the removed text |
| --- | --- | --- |
| Product names in public API, routes, credential names and CLI | F-9, F-10, F-13, F-14 | The unpatched source stays in the legacy repository at the audited commit. A rename has no successor file. If the panel relocates a product-specific module, its destination is not yet defined. Parts 3's options for F-9 and F-10 also include keeping the name as a documented integration, in which case nothing is redacted |
| A doc comment naming VitalLock beside a core wire constant | F-20 | None; the constant itself is proposed `no_change` unless the Security panel decides otherwise |
| Product service entries in root deployment and configuration files | F-11, F-18, F-36, F-37 | The legacy repository's copies of the same files |
| Product assertions in core tests and guards | F-15, F-16, F-33, F-35 | The originals stay in the legacy repository at their present paths. Proposed to move to the product trees they test, or to be deleted once the trees are gone; no destination file exists yet |
| ExoForge module in the node | F-12 | The module stays in the legacy repository at its present path under `crates/exo-node/`. Part 3 names no destination if it is relocated |
| Product references in living documents | F-19 | None; the unpatched documents stay in the legacy repository |

Three cautions from earlier parts apply to every redaction:

- a rename in a published API is a breaking change for anyone using it.
  Parts 3 and 5 did not survey outside users;
- the four LiveSafe tables and the erasure path (F-11) hold or delete
  data. Renaming or moving them is a migration, not a text edit, and needs
  the Security panel;
- dated records are not proposed for redaction (next section). They will
  go on naming products after those products have moved.

## Document sort (F-19)

Part 3 found that root documents, `docs/` and `governance/` name the
products throughout, proposed three kinds, and left the per-file sort to
this part. `document-sort.tsv` sorts the 159 paths in those locations that
have a row in part 3's scan table and are not proposed as adjacent.

Part 3 counted 140 files (22, 88 and 30). The scan table has 159 (25, 97
and 37). The table includes rows for boundary terms, path-name matches and
unscanned binaries that the F-19 count appears to leave out; the two
numbers were **not reconciled row by row**. The sort covers the larger set.

| Kind | Files | Proposed | What happens at the split |
| --- | ---: | --- | --- |
| K5 living | 48 | `patch` after review | Reviewed and updated: product paths, repository name, links. Includes `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `INTEGRATION.md`, the guides and architecture documents |
| K4 product | 24 | pending | Follows the decision on the item it documents; the table links each file to one finding by the product word in its path (F-13 for 16 of them): `docs/honorgood/`, `docs/economy/`, the two root "compact" files, `docs/0DENTITY-APP-SPEC.md`, the Archon, catapult, CrossChecked and LiveSafe-ceremony documents |
| K3 dated | 75 | `no_change` | Kept as written. Release records, audit reports, the execution ledger, dated plans, council and resolution records, the changelog, and two governance files whose front matter was read |
| K2 config | 9 | pending review | Root configuration and build inputs. An entry for a tree that leaves is patched (F-11, F-18, F-36, F-37). An entry that names a boundary item follows that decision instead: `Dockerfile` and `Cargo.lock` match on Decision Forum (F-3, F-17), `tarpaulin.toml` on Telegram (F-12, O-19). `Cargo.lock` is generated and is never edited by hand |
| K1 standing | 3 | pending | The two PDFs (the specification marked CONFIDENTIAL, the whitepaper under CC BY-NC-SA 4.0) and `EXOCHAIN-FABRIC-PLATFORM.md` (F-50) |

**Dated records and moved products.** The 75 dated records name LiveSafe,
CommandBase, CrossChecked, ExoForge and the other products as they stood
when each record was written. Rewriting them would alter the record. The
proposal is to keep them unchanged and to state once, in the new
repository, that records dated before the split refer to a repository that
then also held the product trees, and that those trees are in the legacy
repository at the same paths. Where that statement lives is a split-plan
choice (D-1, D-9).

Limits of the sort:

- every proposed action in the table is a review instruction. The
  reviewer confirms the kind and the linked finding file by file;
- the kind comes from the path, not from reading the file. A dated record
  with no date in its name and outside the listed record directories is
  sorted as living or product; a living document inside a records directory
  is sorted as dated. Two such files were found in review and are listed
  as exceptions in the script (`governance/EXOCHAIN-REFACTOR-PLAN.md`,
  marked historical, and `governance/COUNCIL-ASSESSMENT-EXO-VS-EXOCHAIN.md`,
  created 2026-03-18). A reviewer reported that
  `docs/catapult-integration-report.md` (K4) is also a dated report; that
  was not confirmed here. There are probably others;
- some K5 rows are not prose: `docs/c2/mission-graph.yaml`,
  `docs/dagdb/api/openapi.json` and
  `governance/commercial-product-licensing.json` are data files that name
  products and need the same review;
- K4 is selected by product words in the path. A product document with a
  neutral name is sorted as living, which errs toward review;
- files with no row in the scan table are not in the sort. That means the
  scan's terms did not match them, not that they are product-free;
- adjacent-class documents are not sorted. They leave with their trees.

## Corrections to earlier parts

Later parts changed what earlier parts say. The earlier records were not
edited; the later statement governs. The exception is the owner's review
of this record, after which parts 3, 4, 5 and 6 were corrected in place
(last two rows).

| Earlier statement or gap | Part | Correction | Source |
| --- | --- | --- | --- |
| `LICENSE` described as Apache-2.0 text | 4 | The file was edited after the first commit (wording in section 5, and the appendix removed). It has not been compared with the published text, so "Apache-2.0 text" is unconfirmed | Part 6, F-43 |
| O-24 records an AGPL field in the root manifest and looks no further | 4 | A second AGPL declaration, in `demo/packages/exochain-wasm/package.json`, lasted until 2026-05-09 and is inside two tags | Part 6, F-43 |
| 17 PDF files recorded as an observation (O-5, O-37) | 1, 6 | Raised to finding F-51 | Part 6 |
| Counts of product coupling taken by proposed class alone | 3, 5 | Part 5 found the gap: vendor-class paths inside product trees are missed (`livesafe/Cargo.lock`). Counts are by directory as well as class (O-29). `omission_groups.py` therefore groups by tree first | Part 5 |
| F-19: 140 documents | 3 | 159 scan paths in the same locations; not reconciled (above) | This record |
| F-22 and F-31 summary cells read "Yes" under blocking | 4, 5 | Their full text blocks a claim, not the copy; the register follows the full text | This record |
| No part read `TERMS-CONDITIONS-AND-PRIVACY.md`; O-25 and F-44 said no contributor terms existed; the two PDFs' text was not extracted; CyberMedica's earlier licence statements had no finding | 3, 4, 6 | Corrected in place: part 4 reads the terms file and its first version (O-25, F-22, F-29, new F-52); part 6 carries the history (F-43, F-44, F-50, D-3, D-7, D-12); part 3 records the PDF extraction | Owner review on the pull request |
| F-31 said the cause of the advisory failures "was not determined" | 5 | Corrected in place: the lockfile changed only by the workspace's own `exochain-verify` and the advisory configuration did not change since the last green run, so the cause is advisories published in between; a later run also reports RUSTSEC-2026-0543 (`chrono`) | Maintainer review on the pull request |

The checker prints seven notes where a register row carries more or fewer
disposition words than the part's one-line summary row. In each case the
register follows the finding's full text, which the summary row shortens:
F-12, F-19, F-20 and F-29 (the summary gives one of two or three stated
dispositions); F-16 (the summary says "per assertion"; the text gives
`patch` and `adjacent_patch`); F-17 (the word "pending" in the summary
describes the panel decision, not the disposition); F-23 (the pending
`cargo deny` result was supplied by part 5, F-31).

## Observations

Where each forwarded observation ended. "Open" means no part resolved it
and it is carried to the panel named.

| ID | Subject | Ended as |
| --- | --- | --- |
| O-1 | 1,680 adjacent and 250 vendor paths | Used here: omission table. Still path counts, not sizes |
| O-2 | Four boundary-flagged core crates | F-3, F-5, F-6; decisions pending |
| O-3 | Product names in 101 non-adjacent paths | F-9 to F-19 |
| O-4 | Tracked build output | **Open** on tracking policy. Part 5 found no check on `packages/*/dist`; part 6 proposes `no_change` on provenance (F-49) |
| O-5 | 17 PDF files | F-51 |
| O-6 | Eight v0.2.6 classes differ from the rule table | **Open.** Kept as v0.2.6 has them; Architecture panel to confirm |
| O-7 | In-repo records disagree on four paths or path families | **Open.** Part 1 followed v0.2.6; Architecture panel to say which record governs |
| O-8 | 27 agent or tool artifact paths | 16 proposed for omission above; `agents/` (5, a judgment row) and `Initiatives/` (6, by v0.2.6 precedent) stay core-class |
| O-9 | No path classed as imported evidence | F-50, by keyword search only |
| O-10 | No document in the locations part 1 searched classifies every top-level directory | **Open.** Other locations were not searched; part 1 is a proposal until reviewed |
| O-11 | Four product-named documents not proposed as adjacent | Sorted: three as K4 (pending), the execution-ledger entry as K3 |
| O-12 | Seven guards exist to test a product boundary | F-16, F-33 |
| O-13 | `AGENTS.md` and v0.2.6 disagree on 161 rows | **Open.** Changes headline totals, not what was examined; Architecture panel |
| O-14 | 34 Rust files with manifest-relative paths | Partly resolved in F-35 (whole-literal paths only) |
| O-15 | 22 `package.json` files naming the WASM package | O-31 |
| O-16 | Boundary crate names in release tooling | **Open** (F-39) |
| O-17 | LiveSafe-named gateway migration | F-11 |
| O-18 | Compose context `../livesafe` | F-36 |
| O-19 | Coverage exclusion for `telegram.rs` | Stays with the Telegram decision (F-12) |
| O-20 | LYNK release jobs and guards | F-39; they stay if LYNK is core, which no part decides |
| O-21 | Build output repeats names from F-13 | Follows O-4 and F-13 |
| O-22 | LegalDyne in documents and one guard | No finding raised; its documents are in the sort |
| O-23 | A personal account name and a maintainer's user name in non-adjacent files | **Open.** Sent to part 6, which did not take it up. Security panel suggested |
| O-24 | Earlier AGPL manifest field | F-43 |
| O-25 | Contributor terms | Corrected after the owner's review: the terms file's §5 states inbound terms, and its first version held a contributor agreement (F-43, F-44); acceptance not recorded |
| O-26 | Licence steps in CI; none per file, none for npm or Python | Unchanged (part 5); see F-22 |
| O-27 | Copyright holder written three ways | Unchanged; F-44 |
| O-28 | Other licences in adjacent lockfiles | Adjacent owners; leaves with the trees |
| O-29 | Class filter misses vendor paths in product trees | Applied here (corrections table) |
| O-30 | LiveSafe quality gate failed at the audited commit | LiveSafe owner; cause not read |
| O-31 | Adjacent packages link to core build output by relative path | **Open.** Two `file:` links and one build script break at the split. See "Integration" below |
| O-32 | Hosting identifiers in a tracked workflow | Security panel |
| O-33 | One CI job mixes core and product guards | Follows F-33: splitting the guards splits the job |
| O-34 | Two workflows scanned, not read | Keyword search repeated here for `livesafe`, `cybermedica`, `command-base`, `commandbase`, `demo/`, `site/`, `web/`, `exoforge` and `archon`: no match in either file. Still not read in full |
| O-35 | Three similar author-name strings; no `.mailmap` | **Open.** Legal owner suggested, with F-44 |
| O-36 | Two tags outside the audited history | #903 (D-11) |
| O-37 | (raised) | F-51 |
| O-38 | History searched by file name only | **Open.** Security panel; no content scan was run |
| O-39 | Header commit changed 1,194 paths at once | **Open.** Legal owner suggested, with F-22 and F-44 |
| O-40 | Automation-like author and committer names | **Open.** Legal owner suggested, with F-45 |
| O-41 | Two-maintainer approval rule; reviews not read | **Open.** The row names "panel"; no part read pull-request reviews |
| O-42 | 761 remote-tracking references; only reachable commits analysed | #903 (D-11) |

## Disclosure requirements (D-1 to D-13)

Part 6 proposes thirteen things a new repository would have to disclose
about where its content came from. None is adopted, and none can be
written until #903 chooses a history option and a legacy name. This table
only says who would have to supply each and what it waits on.

| ID | Subject | Waits on | Supplied by |
| --- | --- | --- | --- |
| D-1 | Source repository and exact source commit | Legacy name; the commit actually copied | Split plan owner |
| D-2 | No history or filtered history; the rule used | History option (F-41, F-42) | Split plan owner |
| D-3 | Author names live only in the source history, unverified; inbound terms at each date | History option | Split plan owner, legal owner (F-43, F-44) |
| D-4 | Source history names AI tools as author or co-author | Legal owner's policy decision (F-45) | Legal owner |
| D-5 | Signatures partial and unverified | Nothing; can be stated now (F-46) | Core maintainers |
| D-6 | Every omission or redaction, reason and successor location | Execution of the split; this record holds the proposals | Split plan owner |
| D-7 | Earlier licence statements differed, `cybermedica/` and the terms file among them | Legal owner's answer (F-43, F-52) | Legal owner |
| D-8 | How to verify a pre-split release | Legacy name; F-48 | Release owner |
| D-9 | Which references in copied records point at the source repository | Reference handling (F-47) | Split plan owner |
| D-10 | If filtered: identifier map, dropped commits, merge handling, signature effect | Applies only to a filtered-history option | Split plan owner |
| D-11 | Branches and tags the legacy repository keeps | #903 (O-36, O-42) | Split plan owner |
| D-12 | Provenance questions still open at the copy | F-43, F-44, F-49, F-50, O-38 | Legal owner, Security panel |
| D-13 | Source commit of any later import | Applies to every import after the first | Core maintainers, once a process exists |

## Integration: what the split means for anything that connects to the core

One observation bears on work outside the split itself. Two product
packages reach the core by a relative `file:` link to the WASM build
output, and one demo script compiles a core crate in place (O-31). Product
tests and guards live inside core tests (F-15, F-16, F-35). Product names
are in the core's API (F-9, F-10, F-13). Each is a product connected to the
core through the shared directory tree instead of through a published
interface.

After a split there is no shared tree, so each of these connections needs
a replacement. Part 5 names a published package as one option (O-31);
others exist, such as a pinned git dependency or a vendored copy, and no
part chooses between them. Which interfaces the core should offer for
this (crates, npm or Python packages, the gateway's HTTP routes, the
node's MCP tools) is a design question for a later record, not a finding
here. The register supplies its inputs:

| Input | From |
| --- | --- |
| Which packages the core publishes, and that their contents are unverified | F-26, F-39 |
| Which connections today bypass a published interface | O-31, F-15, F-16, F-35 |
| Which product-specific names a neutral interface would replace | F-9, F-10, F-13, F-14 |
| What an adjacent surface must state before it connects | `AGENTS.md`, "Adjacent Surface Intake Gate" |
| That verification of pre-split releases needs the legacy repository | F-48, D-8 |

## Evidence still owed

None of these was done in parts 1 to 7. Each is needed before the finding
beside it can close.

| Evidence | Needed for | Why not done |
| --- | --- | --- |
| A CI run of the proposed core without the product trees | F-40; turns F-8, F-15, F-16, F-33, F-34, F-35 from inference to observation | Needs a branch pushed to a repository with CI; nothing has been pushed |
| A release dry run and inspection of package contents | F-26, F-39 | Same |
| Registry records: what was published under which licence field, and publisher settings | F-43, F-48 | Not read |
| A read of the Decision Forum crate (9,145 lines) against a stated definition of "primitive" | F-17; part 2's condition on option A | Not done in part 3 |
| Inspection of the 7,925 removed `target/` objects | F-41, before any history option that keeps them | Not opened |
| A record of how the committed proof fixtures were generated, or regeneration in CI | F-8, F-49 | The adding commit records no machine, toolchain or command |
| Reading the two CyberMedica product-requirements binaries (`.docx` and `.pdf`) | F-52 | Not opened. (The two root PDFs' text was extracted after the owner's review; part 3, "Not scanned") |
| Comparison of `.archon/` and named sources with the outside projects | F-24, F-49 | Not made |
| Comparison of `LICENSE` with the published Apache-2.0 text | F-43 | Not made |
| Signature verification | F-46 | Not attempted |
| A content scan of the tree and history for secrets and personal data | F-51, O-38 | Not run; the 17 letters were deliberately not opened |
| Branch-protection settings as an administrator sees them | F-32, F-46 | The account used could not see them |
| Behaviour of the old URL after a rename and name reuse | #903 hazard; F-47 | Not tested. #903 says it can be tested in a non-production namespace or confirmed by a reviewer first |
| Pull-request review records | O-41 | Not read |
| Panel review of every part | All | Has not occurred |

## Status against issue #904's acceptance criteria

| Criterion (quoted) | Status | Basis |
| --- | --- | --- |
| "Inventory/dependency map identifies source SHA and receives review" | **Partly met.** The inventory (part 1) and dependency map (part 2) name the source commit and are reproducible. **Review has not occurred** | Parts 1, 2 |
| "Findings cover history/provenance, product fingerprints, dependencies, builds, CI/CD, docs, and licences/notices" | **Met in coverage, with stated gaps.** Findings per category: history/provenance 10, product fingerprints 9, dependencies 6, builds 5, CI/CD 8, docs 2, licences/notices 11, inventory 1. Gaps are in "Evidence still owed" | Register |
| "No unsupported Apache-2.0 or product-free claim" | **Met by this audit's own text**, which makes neither claim and lists why neither can be made. It cannot speak for other documents in the repository: part 4 and part 6 record existing statements that go further than the evidence (F-22, F-43) | Above |
| "Every finding has evidence-backed disposition or is explicitly blocking" | **Partly met.** All 52 have a proposed disposition with the evidence cited in their part, or a pending one with what it waits on, and 41 say what they block. Whether each disposition is in fact backed by its evidence is what review has to judge; the one review round of this register found owner and blocking errors, since corrected. None is decided. Separately, eight findings have no owner named or suggested and fourteen have only a suggested one | Register |
| "Panel review occurs before the split is ready for admin execution" | **Not met on the record.** No panel review is recorded: issue #904 has no comments and no part carries a review. Reviews outside the issue, if any, were not visible | Issue #904 |

The issue is not ready to close, and #903 stays blocked.

## Limits

- This record adds almost no evidence: one keyword search (O-34) and the
  front matter of two governance files. Otherwise it reorganises parts 1
  to 6. Their limits apply in full and are not repeated here.
- The register was assembled by reading the parts and typing rows. The
  checker confirms ids, parts, vocabulary and links. It does not confirm
  that a row's wording matches its finding, and it cannot detect a finding
  whose part gives it no summary-table row.
- The `blocks` value is a reading (Method, item 2). Three of the `cutover`
  rows (F-15, F-16, F-35) are inferred from source reading, not from a
  failed run.
- "Owner" repeats what the parts say for 30 findings and is this record's
  inference for 14 (`owner_basis` column). Only issue #904's "proposed
  owner" line and its three panel names come from the issue; "accountable legal
  owner", "release owner", "operations owner", "split plan owner" and "core
  maintainers" are roles the parts name without identifying a person.
- The omission table is by path prefix. It does not show that the
  remaining 1,241 paths form a working repository.
- The document sort is by path (its limits are listed with it).
- Successor locations are stated relative to a repository name that does
  not exist yet.
- All seven parts were prepared by one team, with AI assistance, under a
  name that appears in the audited history. Drafts were reviewed by AI
  reviewers from two model families; that is not independent review, and
  it is not the panel review the issue requires.
- The files of this record carry the repository's standard header naming
  the Exochain Foundation, as the repository's rules require of new files.
  F-44 records that no document found defines that holder's standing; the
  header here is not evidence on that question.
- This record gives no legal opinion.

## Reproduction

From `docs/audit/core-separation-904/`:

```bash
python -I findings_register.py .
```

```bash
python -I omission_groups.py path-classification.tsv proposed-omissions.tsv
```

```bash
python -I document_sort.py product-fingerprints.tsv document-sort.tsv
```

```bash
sha256sum findings-register.tsv proposed-omissions.tsv document-sort.tsv
```

```bash
gh issue view 904 --repo exochain/exochain --json state,updatedAt,comments
```

| Table | SHA-256 |
| --- | --- |
| `findings-register.tsv` | `bdf880fa4b9baf85252d7e38bfdbcf1c31ed7a009421ae35f5c496d0b4f8eda5` |
| `proposed-omissions.tsv` | `1acf98f452caac67038f96c06e2d5abd14eb10981e3b36c9131386a79ff4af85` |
| `document-sort.tsv` | `5eb46661c5852df79e8d7b07f88bb34eb5ce8a80451c1cf45ce4de3473ca2eb9` |

The first command exits non-zero if the register and the parts disagree on
which findings exist, their part, the vocabulary, links or status, or if a
table digest printed in this part differs from the file beside it. A
difference in disposition words is printed as a note and does not change
the exit status.
The last needs network access and a GitHub token. `findings-register.tsv`
is maintained by hand; the other two tables are generated.

## Path classification of this record

| Path | Proposed class | Basis |
| --- | --- | --- |
| `docs/audit/core-separation-904/07-FINDINGS-REGISTER.md` | EXOCHAIN core | Part 1 rule C5 (`docs/audit/`) |
| `docs/audit/core-separation-904/findings-register.tsv` | EXOCHAIN core | Part 1 rule C5 |
| `docs/audit/core-separation-904/findings_register.py` | EXOCHAIN core | Part 1 rule C5 |
| `docs/audit/core-separation-904/proposed-omissions.tsv` | EXOCHAIN core | Part 1 rule C5 |
| `docs/audit/core-separation-904/omission_groups.py` | EXOCHAIN core | Part 1 rule C5 |
| `docs/audit/core-separation-904/document-sort.tsv` | EXOCHAIN core | Part 1 rule C5 |
| `docs/audit/core-separation-904/document_sort.py` | EXOCHAIN core | Part 1 rule C5 |

No file under `crates/`, `packages/`, `governance/`, `tools/`, CI or
deployment was changed for this record.

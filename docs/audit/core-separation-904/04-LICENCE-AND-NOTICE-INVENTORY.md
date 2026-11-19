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

# Clean-separation audit (#904), part 4: licence and notice inventory

**Status: DRAFT audit evidence. Not panel-reviewed. Not legal advice, not a
split plan, and not a cryptographic certification.**

Issue #904 asks the audit to "inventory license/notice terms by included
file/subtree", and its acceptance criteria include "no unsupported Apache-2.0
or product-free claim". This record lists, for every tracked path, a fixed set
of licence statement signals (header, nearest licence file, manifest field),
and compares them with what the repository's own licensing documents say.

It is an inventory of statements with the open questions marked. It is not a
completed licence determination for the split. Each finding says what is
settled, what is pending, and which later part or panel owns the rest.

It builds on part 1 (proposed class of every path) and part 3 (product names
in the proposed core, findings F-9 to F-21). Findings here continue that
numbering.

## What this record does and does not establish

It establishes which of the signals below each file **carries**. The signals
are fixed strings in the first 80 lines of text files, so this is not a
complete reading of every notice in every file, and binary files were not
read. It does not establish:

- **what licence applies to any file.** A header records a statement by
  whoever added it. It is not proof that the stated holder owns the content
  or had the right to grant the licence. Authorship and contribution terms
  are part 6;
- that the proposed core is "Apache-2.0" as a whole. 375 core and adapter
  files carry no recognised statement (F-22, F-29), and the repository's own
  scope rule makes the notice the test for part of the tree;
- that any module is free of product code. Licence intent, provenance and the
  product boundary are three separate questions (F-27);
- the licences of third-party dependencies. The Rust check is a CI step
  (`cargo deny`, `ci.yml:327`) that was not run here, and no per-dependency
  list was produced (see Limits);
- what any published package or crate archive contains. No archive was built
  or inspected (F-26);
- anything about trademarks, patents, or the commercial terms the
  proprietary notices refer to;
- legal conclusions. Where this record says two statements differ, it means
  the texts differ. What follows from that is for counsel and the panels.

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` |
| Inventory | `docs/audit/core-separation-904/license-inventory.tsv` |
| Inventory SHA-256 | `e204399b057b463753fdb7e0e4e6c71e01a266f0544f0dd868d9e209d96b4444` |
| Per-subtree summary | `docs/audit/core-separation-904/license-by-subtree.tsv` |
| Per-subtree SHA-256 | `f00f1c24fbc4adfcbab3c1ecd5bff7300106b7ff29acdd5dcd36bd5b92f7c95e` |
| Scripts | `license_inventory.py`, `license_by_subtree.py` in the same directory |
| Input | `path-classification.tsv` from part 1 and the working tree at the audited commit |

## Method

For each of the 3,175 paths in part 1's classification the script records:

- **nearest licence file**: the closest tracked file named `LICENSE*`,
  `COPYING*` or `NOTICE*` in the path's directory or an ancestor;
- **header**: what the first 80 lines carry. `apache-header` means both the
  line "Copyright 2026 Exochain Foundation" and the Apache-2.0 SPDX line, the
  same test `tools/license_headers.py` uses;
- **header tool treatment**: whether `tools/license_headers.py` treats the
  path as eligible, excluded, or an unsupported file type;
- **declared licence**: the licence field of each `Cargo.toml`,
  `package.json` and `pyproject.toml`;
- the first copyright line that does not name Exochain Foundation.

The repository's licensing documents were then read in full:
`LICENSE`, the five proprietary licence files, `README.md` (License
section), `docs/legal/LICENSING-POSITION.md`,
`governance/commercial-product-licensing.json`, `deny.toml`,
`tools/license_headers.py` and `tools/test_proprietary_license_boundaries.sh`.

## What the repository says its licensing is

| Source | Statement |
| --- | --- |
| `LICENSE` (root) | Apache License 2.0 text |
| `Cargo.toml` `[workspace.package]` (lines 65-71) | `license = "Apache-2.0"`, `publish = true` |
| `README.md:373-384` | "Apache-2.0 applies to EXOCHAIN core primitives"; Decision Forum product, LegalDyne, CrossChecked, `livesafe/` and `cybermedica/` need commercial terms; CommandBase is proprietary |
| `docs/legal/LICENSING-POSITION.md` §2 | The Apache grant applies to "the canonical Rust trust primitives in `crates/`" and to "core-supporting tooling, CI rules, governance records, and documentation **that carry an explicit Apache-2.0 notice**". "It does not apply to product-branded applications, product shells, customer-zero surfaces, or product demos." |
| Same, §2a | "Product-branded demo or prototype code has the same product license posture." |
| `governance/commercial-product-licensing.json` | Five commercial products, each `apache_by_proximity: false` |

There are nine licence files. No tracked file is named `NOTICE*` or
`COPYING*`:

| File | Content |
| --- | --- |
| `LICENSE`, `packages/exochain-sdk/LICENSE`, `packages/exochain-llm-proxy/LICENSE`, `packages/exochain-wasm/wasm/LICENSE` | Apache-2.0 text; the four are byte-identical |
| `livesafe/LICENSE`, `cybermedica/LICENSE`, `command-base/LICENSE`, `demo/apps/livesafe/LICENSE` | "Proprietary and Confidential", copyright Exochain Foundation, no licence granted |
| `demo/LICENSE` | Proprietary notice for `demo/`, with a carve-out: `demo/packages/exochain-wasm` is Apache-2.0 |

## Inventory results

Header carried, by part 1 class:

| Class | Paths | Apache header | Apache SPDX line only | Proprietary marker | No recognised statement | Binary |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| EXOCHAIN core | 625 | 493 | 1 | 0 | 124 | 7 |
| Core runtime adapter | 620 | 364 | 0 | 0 | 251 | 5 |
| Third-party/vendor | 250 | 62 | 0 | 10 | 176 | 2 |
| Adjacent surface | 1,680 | 337 | 0 | 419 | 891 | 33 |

"Proprietary marker" is the SPDX identifier `LicenseRef-Exochain-Proprietary`
(387 files, all adjacent) or the words "Proprietary and Confidential" or
`UNLICENSED` (42 files: 32 adjacent and 10 vendor-class, see F-30). "No
recognised statement" means the script's fixed strings were not found in the
first 80 lines; it does not mean the file has no notice of any kind. The one
SPDX-only file is `tools/test_demo_adjacent_boundaries.sh`.

The 551 non-adjacent paths with no recognised statement, by how the header
tool treats them:

| Class | Eligible (a type the tool can stamp) | Excluded by the tool | Unsupported type | Total |
| --- | ---: | ---: | ---: | ---: |
| EXOCHAIN core | 59 | 1 | 64 | 124 |
| Core runtime adapter | 213 | 4 | 34 | 251 |
| Third-party/vendor | 17 | 153 | 6 | 176 |
| Total | 289 | 158 | 104 | 551 |

Core and adapter together: 375 (272 eligible, 5 excluded, 98 unsupported).
F-22 covers the eligible column; F-29 covers the other two.

All 1,495 non-adjacent paths by header tool treatment:

| Header tool treatment | Paths | Apache header | SPDX line only | No recognised statement | Proprietary marker | Binary |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Eligible | 1,161 | 871 | 1 | 289 | 0 | 0 |
| Excluded by the tool | 219 | 47 | 0 | 158 | 10 | 4 |
| Unsupported type (JSON, keys, digests and similar) | 115 | 1 | 0 | 104 | 0 | 10 |

By area, non-adjacent paths only (the full per-subtree list, 93 rows
including each crate and each adjacent tree, is `license-by-subtree.tsv`):

| Area | Class | Paths | Apache header | No statement, eligible | No statement, excluded | No statement, unsupported | Other | Manifest licence fields | Nearest licence file |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| `crates/` | core | 282 | 256 | 13 | 0 | 8 | 5 binary | `Apache-2.0`; one manifest without a field | root |
| `crates/` | adapter | 354 | 145 | 184 | 0 | 20 | 5 binary | `Apache-2.0` | root |
| `crates/` | vendor | 1 | 0 | 0 | 1 | 0 | | | root |
| `docs/` | core | 121 | 92 | 27 | 0 | 2 | | | root |
| `docs/` | adapter | 34 | 15 | 16 | 0 | 3 | | | root |
| `governance/` | core | 105 | 43 | 15 | 0 | 47 | | | root |
| `packages/exochain-llm-proxy` | adapter | 50 | 36 | 10 | 1 | 3 | | `Apache-2.0` | own `LICENSE` |
| `packages/exochain-llm-proxy` | vendor | 65 | 15 | 17 | 32 | 1 | | | own `LICENSE` |
| `packages/exochain-sdk` | adapter | 36 | 32 | 0 | 1 | 3 | | `Apache-2.0` | own `LICENSE` |
| `packages/exochain-sdk` | vendor | 133 | 47 | 0 | 85 | 1 | | | own `LICENSE` |
| `packages/exochain-py` | adapter | 32 | 31 | 0 | 1 | 0 | | `Apache-2.0` | root |
| `packages/exochain-wasm` and `packages/` top level | adapter, vendor | 4 | 2 | 0 | 1 | 1 | | `Apache-2.0` | root; `wasm/LICENSE` for one |
| `tools/` top-level files | core | 44 | 40 | 3 | 0 | 0 | 1 SPDX only | | root |
| `tools/` top-level files | adapter | 90 | 87 | 3 | 0 | 0 | | | root |
| `tools/syntaxis` | core | 12 | 10 | 0 | 0 | 2 | | `MIT` | root |
| `tools/cross-impl-test`, `tools/codegen` | core | 8 | 4 | 1 | 0 | 3 | | none (`cross-impl-test`) | root |
| `tools/` | vendor | 2 | 0 | 0 | 1 | 1 | | | root |
| Root files | core, adapter, vendor | 33 | 28 | 0 | 2 | 1 | 2 binary (PDFs) | `Apache-2.0` | root |
| `fuzz/` | core, vendor | 6 | 5 | 0 | 1 | 0 | | none | root |
| `.cargo`, `.exochain`, `.github`, `Initiatives`, `agents`, `artifacts`, `deploy`, `tests`, `tla` | core, adapter | 37 | 31 | 0 | 0 | 6 | | | root |
| Vendor-class paths inside adjacent trees (F-30) | vendor | 46 | 0 | 0 | 32 | 2 | 10 proprietary marker, 2 binary | | proprietary files (44); root (2) |

Nearest licence file: all 625 core paths and 533 of the 620 adapter paths
have only the root `LICENSE` above them (the other adapter paths sit under
the SDK's or the LLM proxy's own Apache `LICENSE`, or are a licence file
themselves). 359 adjacent paths also have only the root `LICENSE`. The rest
sit under one of the five proprietary files, of which `demo/LICENSE` carves
out `demo/packages/exochain-wasm` as Apache-2.0.

Licence fields in manifests (non-adjacent):

| Manifest | Declared |
| --- | --- |
| Root `Cargo.toml` and 33 crate manifests | `Apache-2.0` (33 by `license.workspace = true`) |
| `crates/exo-cgr-methods`, `crates/exo-cgr-prover` | `license = "Apache-2.0"`, set directly |
| `crates/exo-cgr-methods/guest/Cargo.toml`, `fuzz/Cargo.toml` | No licence field (`fuzz` is `publish = false`) |
| `packages/exochain-sdk`, `packages/exochain-llm-proxy`, `packages/exochain-wasm/wasm` (`package.json`), `packages/exochain-py` (`pyproject.toml`) | `Apache-2.0` |
| `tools/syntaxis/package.json` | `MIT` |
| `tools/cross-impl-test/package.json` | No licence field |

No file outside the adjacent trees has, in its first 80 lines, a copyright
line naming anyone other than the Foundation. Four guides spell the holder
"EXOCHAIN Foundation" with the years 2025–2026 where the standard header
says "Exochain Foundation" and 2026.

## Findings

Dispositions use the repository's vocabulary (`patch`, `adjacent_patch`,
`no_change`) and are proposals. "Pending" means this record does not settle
the point and names who does.

### F-22. 290 non-adjacent header-eligible files lack the standard header, and the header check fails at the audited commit

`python3 tools/license_headers.py --check` exits 1 at the audited commit and
lists 292 files: 213 core runtime adapter, 60 core, 17 vendor-class and 2
adjacent. This script's count agrees file for file. Of the 290 non-adjacent
files, 289 carry no recognised statement and one (core) carries the Apache
SPDX line without the copyright line.

| Area | Eligible files without the standard header |
| --- | ---: |
| Seven `crates/exo-dag-db-*` crates with no headed file at all (`core` 7, `domain` 27, `exchange` 11, `graph` 6, `lab` 24, `postgres` 67, `retrieval` 15) | 157 |
| `crates/exo-gateway` (13 migrations, `src/dagdb.rs`, a binary, two tests) | 17 |
| `crates/exo-root` | 9 |
| `crates/exo-node` | 6 |
| Seven other crates (`exo-api` 2; `exo-dag-db-api`, `exo-avc`, `exo-dag`, `exo-gatekeeper`, `exo-verify`, `exochain-sdk` 1 each) | 8 |
| `docs/` | 43 |
| `governance/` | 15 |
| `packages/exochain-llm-proxy` (10 adapter examples and snippets; 17 vendor-class `dist` files) | 27 |
| `tools/` (7 with no statement, 1 SPDX only) | 8 |

Seventeen of the 35 crate directories have at least one such file.

No reference to the header tool was found in `.github/`. It is referenced by
three guard scripts that grep its exclusion list
(`tools/test_proprietary_license_boundaries.sh`,
`tools/test_livesafe_demo_security.sh`,
`tools/test_commandbase_release_hardening.sh`) and by one execution-ledger
line that lists an invocation (`docs/execution-ledger/2026-05-10-commandbase.md:31`).
So the per-file check is not wired into CI.

Why it matters for the split. This is a comparison of texts, not a ruling on
what the grant covers:

- The licensing position (§2) ties the grant for tooling, CI rules,
  governance records and documentation to an "explicit Apache-2.0 notice".
  65 of these files are in `docs/`, `governance/` and `tools/` and carry no
  recognised notice; one more in `tools/` carries the SPDX line only. The 27 under `packages/exochain-llm-proxy` lack it too, but sit
  under that package's own Apache `LICENSE` and manifest field.
- The 197 under `crates/` fall within the document's location wording,
  subject to its other two tests: it speaks of "canonical Rust trust
  primitives" and excludes product-branded applications. Whether SQL
  migrations, test fixtures or product-named files (F-27) are "trust
  primitives" is an interpretation this record does not make. Among the 197
  are two files part 3 named in F-9:
  `crates/exo-avc/tests/livesafe_public_output_ceremony_tests.rs` and
  `crates/exo-node/src/livesafe_public_output_ceremony_cli.rs`.

Adding a header is a licence statement. Whether the Foundation can make it
for each file depends on who wrote the file and on what terms, which is
part 6. This record does not recommend running `--apply`.

Proposed disposition: `patch`, after part 6 confirms authorship for the
affected areas. **Blocking** for any "Apache-2.0 core" claim covering these
files.

### F-23. The two statements of dependency licence policy differ

`docs/legal/LICENSING-POSITION.md` §4 and `deny.toml` both state which
dependency licences are allowed:

| Licence | Licensing position | `deny.toml` |
| --- | --- | --- |
| MPL-2.0 | Denied | In the general allow list (lines 105-107), so allowed for any dependency. `exceptions = []`. The comment names two `async-graphql` dependencies as the reason |
| Apache-2.0 WITH LLVM-exception, CDLA-Permissive-2.0 | Not listed | Allowed |
| Unicode-DFS-2016, OpenSSL | Allowed | Not in the allow list |

`deny.toml` is what the `cargo deny` step at `ci.yml:327` reads. Whether that
step passes at the audited commit, and whether it is a required check, was
not verified (part 5). `Cargo.lock` contains `ascii_utils` and
`fast_chemail`, the two crates the `deny.toml` comment names as MPL-2.0, so
the tree as locked appears to depend on a licence the position document says
is denied. Their licences were read from that comment, not from the crates.

`deny.toml` also clarifies `ring` as "MIT AND ISC AND OpenSSL" while OpenSSL
is not in its allow list. Whether that passes the step is a question for
part 5.

A second difference in the same document: §1 and §6 say all workspace crates
inherit the licence "via `license.workspace = true`". Two crates
(`exo-cgr-methods`, `exo-cgr-prover`) set `license = "Apache-2.0"` directly,
and one nested manifest has no field. The declared licence is the same; the
document's description of how is not accurate.

The document's "Any divergence is a bug" (§6) is said of core sources
declaring Apache-2.0 and of the proprietary boundary. It is not said of the
dependency list, so this record does not rely on it here.

Proposed disposition: `patch` (make the document and `deny.toml` agree; the
panel chooses which is right). Not blocking by itself. Pending for part 5:
the result of the `cargo deny` step and the `ring` clarification.

### F-24. No tracked NOTICE or COPYING file; third-party notices not located

What the search establishes: no tracked file is named `NOTICE*` or
`COPYING*`. A third-party notice list under another name was not searched
for exhaustively and none was noticed in the documents read.

The position document tells downstream users to "include the license notice
and any NOTICE file" (line 120). Apache-2.0 does not require a project to
have a NOTICE file.

Third-party source inside the tree is **not ruled out**. The evidence is
limited to this: no non-adjacent file has another holder's copyright line in
its first 80 lines, and "vendored" in `crates/exo-proofs` refers to the
`risc0-zkvm` crate as a dependency. That method cannot detect copied or
adapted code without a notice, and the header tool stamps the Foundation
header on any eligible file it is run over. Two leads for part 6:

- `honorgood.rs:155` records a `source_uri` of
  `https://github.com/coleam00/Archon`, and the repository has an `.archon/`
  directory. Neither proves copying.
- the tracked `dist` bundles under `packages/` (F-29) were not inspected for
  bundled third-party code.

Proposed disposition: **pending**, not `no_change`. Part 5 owns what the
release jobs ship and whether notices travel with it. Part 6 owns the two
provenance leads. The panel decides whether the split core adopts a NOTICE
or third-party notice file. Condition: no "notices complete" claim for the
split core until those three are done.

### F-25. `tools/syntaxis` declares MIT; its files carry Apache-2.0 headers

`tools/syntaxis/package.json` declares `"license": "MIT"` and author
"ExoChain Team". Ten of the twelve files in the directory carry the
Apache-2.0 header; the other two are JSON. Part 1 proposes the directory as
core (per `path-classification.tsv`), and part 3 recorded the name Syntaxis
in the Decision Forum crate.

The two declarations differ. This record does not say which is mistaken, or
whether the manifest and the files were meant to have different scopes.

Proposed disposition: `patch`, once the owner states the intended licence
and scope; then make the manifest, the headers and any licence text agree.

### F-26. Source-tree licence-text placement; package contents unverified

Apache-2.0 §4(a) asks redistributors to give recipients a copy of the
licence. This table describes the **source directories and manifests**. No
package archive was built or inspected, and which units are in fact
published was not verified.

| Unit | In the source tree |
| --- | --- |
| `packages/exochain-sdk`, `packages/exochain-llm-proxy`, `packages/exochain-wasm/wasm` | Own `LICENSE`; each `package.json` lists `LICENSE` in `files`. `ci.yml:945` also copies `LICENSE` into the wasm package |
| `packages/exochain-py` | No `LICENSE` in the directory; the field and classifier say Apache-2.0 |
| 35 crate directories | None has a `LICENSE` file; each declares the licence by manifest field. The workspace sets `publish = true` (`Cargo.toml:71`) |
| `crates/exo-cgr-methods/guest`, `tools/cross-impl-test` | No licence field and no licence file |

Whether a crate published without the licence text meets §4(a) is a legal
question. Crates are often published with the manifest field alone; this
record did not survey that.

Proposed disposition: `patch` for the Python package and the two manifests
without a field. **Pending** for part 5: publication status and the actual
contents of each packaged unit. The crates are a panel decision. Condition:
resolve for a unit before that unit is distributed from the split core.

### F-27. Product-named code under Apache-2.0 headers (from part 3)

Part 3 forwarded four items. Three questions are kept apart here: what
licence the repository intends, who has authority to grant it (part 6), and
whether the code is on the core side of the product boundary (part 3 and the
panel). Answering one does not answer the others.

| Part 3 item | Licence statements | Status |
| --- | --- | --- |
| F-9, LiveSafe-named API in `exo-avc` and the node | Source files carry the Apache header (two lack any header, F-22). The registry says LiveSafe is commercial, boundary "`livesafe/` adjacent subtree" | **Texts in tension; open.** The registry scopes the product to `livesafe/`, but §2 says the grant "does not apply to product-branded applications" and §2a says "Product-branded demo or prototype code has the same product license posture". No document says whether a module named for the product, with the subject fixed to "livesafe.ai", falls under those sentences |
| F-10, CrossChecked anchor in `exo-api` and `exo-node` | Apache header. Registry: "External proprietary product", no core primitive named | **Texts in tension; open**, for the same reason. Unlike Decision Forum, no document names an Apache primitive for CrossChecked |
| F-13, named arrangements in `exo-economy` | Apache header | **Not resolved.** Whether the named arrangements or their sources carry licence implications was not examined. Forwarded to part 6 |
| F-17, `crates/decision-forum` | Apache header; §1, §2, the registry and the README say the crate is the Apache primitive and the product is separate | The documents agree with each other on licence intent. Part 3's boundary point (the crate describes itself as an application) stays open with the panel |

Proposed disposition: **pending**; no change proposed on licence grounds
alone. A registry entry stating, for LiveSafe and CrossChecked, which in-core
code the Foundation intends as Apache-licensed would settle intent only. It
would not show authority to license, and it would not make the code
product-free. Until intent, authority and boundary are each answered, an
"all Apache" or "product-free" claim for these modules is unsupported.
**Blocking**, together with part 3's F-9 and F-10.

### F-28. Not every adjacent tree is proprietary

"Adjacent" in part 1 is not a licence class. By tree:

| Adjacent tree | What its files state |
| --- | --- |
| `livesafe/`, `cybermedica/`, `command-base/`, `demo/` | Own proprietary licence file. `cybermedica/` marks 367 files with the proprietary SPDX identifier; `livesafe/` marks 26 (20 by SPDX identifier) and leaves 453 with no statement; `command-base/` leaves 253 with none |
| `site/` (139), `web/` (72), `gap/` (58), `exoforge/` (14), `.archon/` (13), and adjacent files under `docs/` (18), `tools/` (15), `.github/` (6) | Apache-2.0 headers; no licence file of their own |
| `demo/packages/exochain-wasm` | Declared Apache-2.0 by the carve-out in `demo/LICENSE` |

337 adjacent files carry the Apache header (the 335 above and 2 under
`demo/`), and 359 adjacent paths have only the root `LICENSE` above them.
These are statements, not a finding about what licence applies. If those
paths move to a repository without the root `LICENSE`, they would have no
licence file unless one is added, and the owner would need to say what is
intended for each tree. CommandBase is proprietary by its licence file and
the README but is not in the product registry; `site/package.json`,
`web/package.json` and `exoforge/package.json` declare no licence.

Proposed disposition: `adjacent_patch`. Does not block the core.

### F-29. Files outside the header check: tracked build output, unstampable types, two PDFs

262 non-adjacent paths with no recognised statement are outside the header
check (158 excluded, 104 unsupported type). Their notice, if any, comes from
a licence file or manifest above them:

| Group | Files | Statement sources above them |
| --- | ---: | --- |
| `packages/exochain-sdk` `dist` and `dist-test` output, excluded (vendor-class) | 85 | SDK `LICENSE` and manifest field |
| `packages/exochain-llm-proxy` excluded files (`dist`, lockfile; vendor-class) | 32 | LLM proxy `LICENSE` and manifest field |
| Vendor-class files inside adjacent trees, excluded | 32 | Proprietary licence files (F-30) |
| Other excluded vendor-class files (root, `crates/`, `fuzz/`, `tools/`: lockfiles and similar) | 4 | Root `LICENSE` |
| The four Apache `LICENSE` texts and `packages/exochain-py` `py.typed` (core and adapter) | 5 | They are the licence text, or an empty marker |
| JSON in core and adapter paths, of which 46 are under `governance/releases` | 85 | Root `LICENSE`; a package `LICENSE` for 6 |
| Keys, digests, signatures and text fixtures in `crates/` and `tools/cross-impl-test` | 13 | Root `LICENSE` and the crate manifest field |
| Vendor-class unsupported types (JSON) | 6 | Root or package `LICENSE` |

Three further points:

- The tracked build output (part 3, O-21) is 196 files across the three
  `dist` directories, 62 with the header and 134 without.
- One unsupported-type file does carry the header
  (`tools/python-release-requirements.in`).
- The two root PDFs (specification and whitepaper) are excluded by the tool
  and binary to this script. Whether they state a licence, and which, is
  unknown.

The 47 `governance/` JSON files and the other governance and tooling files
here fall under the position document's "explicit Apache-2.0 notice" wording
and cannot carry a header. No document says how such files are covered.

Proposed disposition: `no_change` to the files, **conditional** on the panel
recording a notice mechanism for file types that cannot carry a header (for
example a statement in the position document or a per-directory licence
file). The PDFs are **open** and need a text extraction pass (also owed from
part 3).

### F-30. Vendor-class files inside proprietary trees

44 paths part 1 classes as third-party/vendor sit under a proprietary
licence file (part 3, F-21, lists the same kind of path):

| Tree | Paths | What they are |
| --- | ---: | --- |
| `demo/` (36 under `demo/LICENSE`, 1 under `demo/apps/livesafe/LICENSE`) | 37 | 5 lockfiles and 32 files of tracked coverage output under `demo/coverage` |
| `livesafe/` | 5 | 4 npm lockfiles and `Cargo.lock` |
| `command-base/`, `cybermedica/` | 2 | One lockfile each |

Ten of the twelve lockfiles carry a proprietary marker in their first 80
lines; of the other 34 paths, 32 carry no recognised statement and 2 are
binary images. "Vendor" is part
1's class for generated or third-party-derived files. It says nothing about
their licence, and a lockfile lists dependencies under many licences (O-28).

These files belong to their adjacent trees and do not travel with the core.

Proposed disposition: `adjacent_patch` (the tree owner decides whether
generated files should be tracked and how they are marked). Does not block
the core.

## Findings summary

| ID | Finding | Proposed disposition | Blocks cutover, and why |
| --- | --- | --- | --- |
| F-22 | 290 non-adjacent eligible files (60 core, 213 adapter, 17 vendor-class) lack the standard header; the header check fails and is not in CI | `patch` after part 6 | Yes: an "Apache-2.0 core" claim is unsupported for them |
| F-23 | Dependency policy stated two ways; manifests described inaccurately | `patch`; `cargo deny` result pending (part 5) | No, but the document and the configuration disagree |
| F-24 | No tracked NOTICE or COPYING file; third-party source not ruled out | Pending: parts 5 and 6, panel | No "notices complete" claim until done |
| F-25 | `tools/syntaxis` MIT against Apache headers | `patch` once intent is stated | No |
| F-26 | Licence-text placement in source; package contents unverified | `patch` for three units; rest pending (part 5, panel) | Per unit: resolve before distributing it |
| F-27 | Product-named code under Apache headers | Pending: intent, authority and boundary are separate | Yes: with part 3's F-9 and F-10 |
| F-28 | Adjacent is not a licence class | `adjacent_patch` | No |
| F-29 | Files outside the header check; two PDFs | `no_change`, conditional on a recorded notice mechanism; PDFs open | PDFs open |
| F-30 | Vendor-class files inside proprietary trees | `adjacent_patch` | No |

## Observations forwarded to later parts

Forwarding records where the question goes. It does not settle it.

| ID | Observation | Evidence | Goes to |
| --- | --- | --- | --- |
| O-24 | Before 2026-03-20 the root `Cargo.toml` declared `AGPL-3.0-or-later` while `LICENSE` held Apache-2.0 text. The position document calls it a scaffolding error. Whether anything was published or contributed under the AGPL field is a history question. | `docs/legal/LICENSING-POSITION.md` §7; `CHANGELOG.md:502` | Part 6 |
| O-25 | `CONTRIBUTING.md` asks contributors to "uphold the Apache 2.0 License" (line 278). No contributor licence agreement, sign-off rule or inbound-licence statement was found by a search of that file. | `CONTRIBUTING.md` | Part 6 |
| O-26 | `ci.yml` has licence steps in two places (lines 392-405): the root manifest field against the first line of `LICENSE`, and the proprietary boundary guard. Neither checks per-file headers. No licence check on npm or Python dependencies was found in `ci.yml`. What the boundary guard covers in full was not assessed. | `ci.yml` | Part 5 |
| O-27 | The copyright holder is written three ways: "Exochain Foundation" (headers), "EXOCHAIN Foundation" with 2025–2026 (four guides), "ExoChain Team" (`tools/syntaxis/package.json`). | Inventory; manifest | Part 6 |
| O-28 | Lockfiles in adjacent trees record MPL-2.0, CC-BY-4.0, Python-2.0 and packages with no licence field, by the lockfiles' own `license` fields; the packages were not inspected. They leave with their trees. | `package-lock.json` files under `demo/`, `livesafe/`, `site/`, `web/` | Adjacent owners |

## Limits

- This reads statements. It does not determine ownership, authorship or the
  right to grant a licence.
- The header test looks at the first 80 lines for two fixed strings. A file
  with a differently worded Apache notice counts as "no recognised
  statement"; the script found no such file outside the four guides in
  O-27, which do carry the standard header as well.
- Third-party dependency licences were not inventoried. `cargo metadata`
  could not resolve offline on the audit machine, and nothing was compiled
  or downloaded. `Cargo.lock` lists 669 packages including workspace
  members. The three non-adjacent npm lockfiles list eight packages in all,
  each MIT or Apache-2.0 by the lockfile's own field.
- No CI run was read. Statements about CI describe what `ci.yml` contains,
  not whether a step passes or is required.
- No package or crate archive was built or inspected.
- Binary files and the two PDFs were not read.
- Cross-references to parts 1 and 3 rely on those records as written
  (`path-classification.tsv`, `03-PRODUCT-FINGERPRINTS.md`).
- Adjacent trees were inventoried by header and licence file only; their
  licence texts were read but their terms were not assessed.
- Nothing here is legal advice.

## Reproduction

From a checkout of the audited commit whose working tree is clean apart from
this audit directory's untracked files:

```bash
python3 docs/audit/core-separation-904/license_inventory.py \
  docs/audit/core-separation-904/path-classification.tsv . | sha256sum
```

The digest must equal the inventory SHA-256 above.

```bash
python3 docs/audit/core-separation-904/license_by_subtree.py \
  docs/audit/core-separation-904/license-inventory.tsv | sha256sum
```

The digest must equal the per-subtree SHA-256 above.

The repository's own check. The first command should print 292:

```bash
python3 tools/license_headers.py --list-missing | wc -l
```

The second should exit with status 1:

```bash
python3 tools/license_headers.py --check
```

The files this audit adds are untracked until committed, and each text file
among them that the tool can stamp carries the standard header, so they do
not change that count.

## Path classification of this record

| Path | Classification |
| --- | --- |
| `docs/audit/core-separation-904/04-LICENCE-AND-NOTICE-INVENTORY.md` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/license_inventory.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/license-inventory.tsv` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/license_by_subtree.py` | EXOCHAIN core (governance evidence) |
| `docs/audit/core-separation-904/license-by-subtree.tsv` | EXOCHAIN core (governance evidence) |

Core regression statement: this record adds five files under `docs/audit/`.
It changes nothing under `crates/`, `packages/`, `governance/`, `tools/`,
`.github/` or any deployment file, and it does not edit `GAP-REGISTRY.md`.

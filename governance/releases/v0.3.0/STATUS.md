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

# v0.3.0 status index

## Terminal status

| Field | Value |
| --- | --- |
| Release objective | `UNCHANGED` |
| Integration lane | `CANONICAL_DRAFT_ONLY` |
| Release-bearing | `YES` |
| G00 | `NOT_ESTABLISHED_IN_TRACKED_RECORD` |
| Formal successor-plan authoring | `PROHIBITED` |
| Source development | `NOT_AUTHORIZED_BY_THIS_LANE` |
| Open-issue implementation | `INACTIVE_PENDING_G00_AND_SEPARATE_AUTHORITY` |
| EXO-DAG-DB implementation | `INACTIVE_PENDING_G00_AND_SEPARATE_AUTHORITY` |
| Draft pull request | `REQUIRED` |
| Merge | `PROHIBITED` |
| Tag, signing, publication, deployment, activation | `PROHIBITED` |
| Public release claim or v0.3.0 issuance | `PROHIBITED` |
| Overall decision | `RELEASE_STOPPED_FAIL_CLOSED` |

## Meaning of release-bearing

The branch, this tracked record, its Draft pull request, and its linked
tracking issue are the canonical integration vehicle for work intended for
v0.3.0. Their release-bearing classification does not make incomplete work
approved, mergeable, deployable, signed, published, or released.

## Change classification

Every file in this initial commit is classified as **EXOCHAIN core —
constitutional governance artifacts**. The commit changes no Rust crate,
runtime adapter, package, workflow, CI contract, deployment contract, secret
configuration, imported evidence, third-party code, or adjacent surface.

## Stop conditions

The lane stops on any of the following:

- G00 failure or absence of its required unanimous independent approvals;
- authority, evidence, base, head, tree, mode, byte-length, or path mismatch;
- any tracked path outside this directory in the initial commit;
- any source, test, CI, deployment, secret, screenshot, ignored-evidence, raw
  incident, or machine-local-path inclusion;
- any non-Draft pull request, merge, tag, signature, publication, deployment,
  activation, GitHub Release, public release claim, or issuance attempt;
- activation of the open-issue or EXO-DAG-DB intakes before both G00 and the
  required separate authority are established; or
- any review rejection or missing mandatory review.

No stopped condition may be inferred away from repository visibility, a
passing CI display, a pull-request comment, or this record's existence.

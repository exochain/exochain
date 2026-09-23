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

# v0.3.0 evidence index

This is a sanitized inventory, not a copy of restricted evidence. It neither
activates an intake nor proves a gate whose decision remains pending.

## Restricted evidence bindings

| Identifier | SHA-256 | Bytes | Mode | Classification | Bounded status |
| --- | --- | ---: | --- | --- | --- |
| Sanitized controller-credential incident record | `4d291a0dedad83d563dbf2500c0e2af54ce53998beaf9d362150cf8af6c3173b` | 4626 | `100644` | Restricted incident evidence | Bound; raw content excluded |
| Open-issue integrity intake | `42a90e13eeb97184fcf3ca935fe170b13ea08cbd6e6be0becad7dbffc14db25c` | 8827 | `100644` | Mandatory successor-planning intake | Preserved; inactive |
| EXO-DAG-DB inclusion assessment | `40874c0253093fa5160b39ff93ee9f10170a6e03cc303c067f38d3d51b1cab4f` | 10729 | `100644` | Mandatory successor-planning intake | Preserved; inactive |
| Cursor User API Key zero-state screenshot | `0ca8e8c5089e10212a78a4ae8c75a61c84eea6545687ea627df672918f49e1a0` | 203304 | `100644` | Restricted image evidence | Raw image excluded |
| Independent Cursor User API Key zero-state verification | `685dcb4de51ab2184456c1fd07e59e03879da40f82746591e85566923b0125ad` | 1011 | `100644` | Independent verification | Bound decision below |

Bound independent decision:

`SCREENSHOT_PROVES_ZERO_VISIBLE_CURSOR_USER_API_KEYS`

That decision is limited to the Chair-fixed Cursor User API Keys scope. It is
not a statement about any broader credential surface and is not authority to
perform a provider operation.

## G00 candidate preservation binding

| Field | Value |
| --- | --- |
| Frozen recovery base commit | `98bd90ee2081ab28f506236cfb009d726118c494` |
| Preserved candidate guard SHA-256 | `99e55df63bb228d74da3a9a91bdd8ca85849b92e105080811b383d17b8b275ab` |
| Preserved candidate guard bytes | `209646` |
| Preserved candidate guard mode | `100755` |
| Status | `LOCAL_CANDIDATE_NOT_APPROVED_NOT_INTEGRATED` |

The candidate binding is preservation metadata only. It is not a commit,
approval, G00 completion, GREEN authorization, integration instruction, or
release evidence. The frozen recovery worktree remains outside this lane and
must not be modified through it.

## Evidence admission rules

Evidence becomes release-admissible only when its authorized producer,
independent verifier, exact artifact tuple, relevant source commit, commands,
exit codes, diagnostics, and required review decisions are bound together.
Where reproducibility is required, repeated outputs must satisfy the governing
byte-identity rule.

The following do not independently close a gate:

- a local file's existence;
- a screenshot or dashboard display;
- a hash without authorized provenance and verification;
- a branch, commit, pull request, issue, comment, check display, or agent
  statement; or
- a test result that is not bound to the exact reviewed source and command.

Any restricted evidence added later must remain outside source control unless
separate authority explicitly makes a sanitized derivative tracked and the
applicable evidence rules permit it.

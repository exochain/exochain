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

# v0.3.0 authority index

This index records bounded authority lineage without reproducing private
documents or treating their filenames as authority. A SHA-256 and byte-length
tuple identifies bytes; only the Chair's explicit issuance makes those bytes
operative.

## Predecessor lineage

| Identifier | SHA-256 or commit | Bytes | Status in this lane |
| --- | --- | ---: | --- |
| Predecessor release plan | `86bf931624aa99a7440fadb39e0ef4964d8d5b4e141a8e6d2f4be9a2996752f6` | Not republished | Bound lineage; exhausted |
| Final-exhaustion ruling | `517d67e51b3d899be1a435435983b88556898612ee74c093a368f9d6eb05fff6` | Not republished | Bound lineage |
| Final manifest | `83178dba46f4b3d9af3cf4336d4337adc6397d31606eea30ab9a3d0623d60ad8` | Not republished | Bound lineage |
| Terminated lease | `98b0ffc2cb24a1d33d939cee5746830dda67e42888bf80bb9840db87e96d7e32` | Not republished | Terminated; grants no current authority |
| Predecessor commit | `8eb75e58ef9d33288873e4c5b18bc78b7c281014` | Not applicable | Bound lineage |

## Issued recovery authority

| Identifier | SHA-256 | Bytes | Bounded effect |
| --- | --- | ---: | --- |
| G00 evidence-recovery principal directive | `c3239796eb258bd9ff430b675f2844d25824d1fe617e274517c97b2d22a0f494` | 27189 | Narrow G00 recovery authority only |
| G00 post-exposure continuation directive | `edc4663630cff8366aa3b82a3d77b990d40f65578e7a2e3cd563a4cd7251aece` | 15736 | Narrow post-exposure continuation subject to later minimum supersession |
| G00 Cursor User API Key containment and continuation directive | `c0b7fd27722afb3cf8e4014e7cb9b26ed675ec179b34903ce5743dbf3c9f96c5` | 43849 | One-shot in-scope containment bridge and conditional return to unfinished G00 recovery |

The Cursor containment scope is **Cursor User API Keys only**. Broader key
surfaces are not requirements or gates. The directive grants no credential,
source, GitHub, deployment, or release authority.

## Canonical GitHub integration authority

Chair authority issued on `2026-08-13` permits exactly this initial lane:

- read-only authentication and fetch of the remote default branch;
- one isolated branch named `bob-stewart/v0.3.0-release-integration`;
- one documentation-only initial commit under this directory;
- one push, one Draft pull request to `main`, and one linked tracking issue;
- sanitized recording of exact base, head, tree, paths, artifact digests,
  lengths, URLs, and CI status; and
- team review and coordination through that canonical release-bearing lane.

## Withheld authority

This lane grants none of the following:

- modification of the frozen G00 recovery worktree;
- bypass of an issued G00 directive or change to the release objective;
- unreviewed source, test, adapter, governance, open-issue, or EXO-DAG-DB
  implementation;
- merge, tag, signing, publication, deployment, activation, public release
  claim, GitHub Release creation, or v0.3.0 issuance; or
- inference that a digest reference, Draft pull request, issue, or passing
  check establishes a governance or release decision.

All powers not explicitly granted remain withheld. Every later workstream must
carry its own exact authority and may integrate only after its required
evidence and independent approvals are established.

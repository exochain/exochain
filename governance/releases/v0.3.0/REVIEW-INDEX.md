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

# v0.3.0 review index

## Initial documentation commit

| Review duty | Required identity separation | State |
| --- | --- | --- |
| Writer | Sole documentation writer; cannot approve own work | `ASSIGNED` |
| Authority and scope verification | Read-only; distinct from writer | `PENDING` |
| Evidence-hygiene and secret-safety verification | Read-only; distinct from writer | `PENDING` |
| Git base, tree, path, mode, digest, and push verification | Read-only; distinct from writer | `PENDING` |
| Controller integration decision | Distinct from writer and reviewers | `PENDING` |

The initial commit may be pushed only after the authorized writer's local
checks pass and the base has not drifted. The Draft pull request and tracking
issue may be created only after the controller accepts independent
verification. The writer records facts but issues no approval.

## G00 separation

G00 review is governed by the operative G00 directives, not by this GitHub
lane. Fresh, distinct, read-only `SPEC-G00`, `QUAL-G00`, `ADV-G00`, and
`VER-G00` identities must unanimously approve the same frozen repaired commit
and guard SHA-256 before the required G00 result may be established. None may
be the writer or controller. Prior reviews do not carry to a new commit.

This initial documentation writer, its reviewers, and the integration
controller do not become G00 producers, council members, or final reviewers by
participating in this lane.

## Review contract for later workstreams

| Review class | Minimum question |
| --- | --- |
| Authority | Did the exact issued authority permit every changed path and operation? |
| Specification | Does the change implement the bounded requirement without expanding it? |
| Quality | Do RED-first tests, focused tests, and required full gates prove the intended behavior? |
| Adversarial | Do bypass, mutation, race, determinism, malformed-input, and sibling-ingress tests cover the affected class? |
| Evidence | Are commands, outputs, hashes, modes, lengths, commits, and identities authentic and internally consistent? |
| Release | Are all prerequisite gates closed on the same immutable release candidate? |

Every required reviewer must return an explicit approval or rejection bound to
one immutable commit and tree. Silence, partial review, an automated green
check, prior approval, or approval of different bytes is not unanimity.

## Pull-request posture

The canonical pull request remains Draft until every mandatory release gate is
complete and separate authority permits changing that posture. Review comments
and linked issues are coordination evidence only; they cannot enlarge
authority, overrule a stop, or activate a workstream.

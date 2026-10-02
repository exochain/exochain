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

# EXOCHAIN v0.3.0 release record

This directory is the canonical, release-bearing coordination record for the
unchanged EXOCHAIN v0.3.0 Evidence-Grade Trust release objective. It is part of
the intended release record; it is not a release approval, release artifact,
deployment authorization, or public claim that v0.3.0 has shipped.

## Fail-closed status

`RELEASE_STOPPED_FAIL_CLOSED`

The current G00 recovery result has not been established in this tracked
record. The integration pull request must remain a Draft, and no merge, tag,
signing, publication, deployment, activation, GitHub Release, public release
claim, or v0.3.0 issuance is authorized.

## Canonical lane

| Field | Bound value |
| --- | --- |
| Repository | `exochain/exochain` |
| Base branch | `main` |
| Base commit | `86e9a029b7a62417b658b04d0def7a979e21fc8b` |
| Base tree | `36d9c2715742443a4c0431f633a7d6f827fc1fe4` |
| Integration branch | `bob-stewart/v0.3.0-release-integration` |
| Initial change class | `EXOCHAIN core — constitutional governance artifacts` |
| Initial tracked scope | `governance/releases/v0.3.0/` only |
| Source change | `NONE` |
| Test or CI change | `NONE` |
| Deployment change | `NONE` |
| Release authority | `WITHHELD` |

GitHub-assigned pull-request and tracking-issue identities, their URLs, and
their observed CI status cannot exist inside the commit that precedes their
creation. They must be frozen in the Draft pull-request and linked issue
metadata after creation, together with this commit's exact head and tree.

## Indexes

- [Status index](STATUS.md)
- [Authority index](AUTHORITY-INDEX.md)
- [Evidence index](EVIDENCE-INDEX.md)
- [Workstream index](WORKSTREAM-INDEX.md)
- [Review index](REVIEW-INDEX.md)
- [Release-gate index](RELEASE-GATE-INDEX.md)

## Integrity rules

- Restricted inputs are represented only by sanitized identifiers, SHA-256
  digests, byte lengths, modes where relevant, and bounded decisions.
- Raw restricted evidence, screenshots, credentials, ignored evidence,
  machine-local paths, and incident narrative are excluded.
- An evidence reference is not evidence verification, authority activation, or
  permission to read or mutate the referenced source.
- Every source, test, adapter, governance, issue-remediation, or EXO-DAG-DB
  change requires its separately authorized isolated workstream, strict TDD,
  applicable independent review, and explicit integration evidence.
- Ambiguity, scope drift, evidence mismatch, secret exposure, base drift, or a
  failed mandatory gate keeps the release stopped.

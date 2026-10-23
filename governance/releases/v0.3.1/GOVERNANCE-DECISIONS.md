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

# Governance decision records — v0.3.1

**Status: GD-031-01 is SIGNED for path B, subject to its conditions.
GD-031-02 through GD-031-11 remain PENDING. This document does not claim
release readiness.**

Humans authorize decisions, signatures, and dates. GD-031-01 is transcribed
at the Chief Executive's explicit instruction on 2026-10-23, naming Max
and Robert as the two release approvers. An agent must not be any approver.
The engineer recommendation is context for review. It is not a vote and it
is not a default that takes effect on silence.

Roles:

| Role | Who may fill it | Cannot be |
| --- | --- | --- |
| Chief Executive, EXOCHAIN PBC | Bob Stewart, or a successor human designated in the corporate record | An agent, or the same person as both release approvers |
| Release approver A | The human bound to environment `release` | The authoring agent; approver B |
| Release approver B | The human bound to environment `release-second` | The authoring agent; approver A |
| Legal counsel | Counsel accountable for EXOCHAIN PBC product claims | The authoring agent |
| Security reviewer | A human reviewer of the threat model and TSA pins | The authoring agent; not sufficient alone for publication |

#789 remains the publication stop: A and B are distinct, self-review stays
off, and an administrator bypass does not count.

## GD-031-01 — Authorize v0.3.1 planning to become an implementation release

| Field | Entry |
| --- | --- |
| Status | SIGNED |
| Question | May engineers implement `governance/releases/v0.3.1/` after a v0.3.0 close, and not before? |
| Approver roles | Chief Executive, EXOCHAIN PBC; Release approver A; Release approver B |
| Decision | Path B: the v0.3.0 close is written in `V030-CLOSE-RECORD.md`, inside the 0.3.1 release. There is no separate `v0.3.0` tag. |
| Conditions | This decision records the close location and release shape. Completion evidence for P1–P8 remains required before implementation of C1–C8; other required GD-031 records remain pending. Do not create a `v0.3.0` or `v0.3.1` tag from PR #887. Publication still requires the two distinct release-environment approvers under #789. |
| Rationale | Adopt the assessed path B so the v0.3.0 close is milestone 1 of v0.3.1, with one release record and no separate v0.3.0 publication cycle. Preserve the prerequisite evidence and publication controls. |
| Dissent | None recorded. |
| Date | 2026-10-23 |
| Signatures | Bob Stewart — Chief Executive, EXOCHAIN PBC (`bob-stewart`); Max Stewart — Release approver A (`mstewartbz`, `release`); Robert Stewart — Release approver B (`robst3w`, `release-second`). |

The three human names above are recorded at the Chief Executive's explicit
instruction. PR #887 also records approvals by `robst3w` on 2026-10-22 at
20:23:54 UTC and `mstewartbz` at 20:29:50 UTC. This transcription is not an
agent approval or a release-environment approval. The signed decision is
limited to path B and remains subject to the conditions above.

| Field | Recorded scope |
| --- | --- |
| Selected shape | Path B in [GOAL.md](GOAL.md). The v0.3.0 close is recorded inside the 0.3.1 release. There is no separate `v0.3.0` tag. |
| Where the close record lives | [V030-CLOSE-RECORD.md](V030-CLOSE-RECORD.md), inside `governance/releases/v0.3.1/`. GD-031-01 is signed there; completion evidence for P1–P8 is still required to satisfy the `V030-CLOSE` precondition in [DEMO.md](DEMO.md). |
| What stays refused | Path A. A standalone `v0.3.0` tag is not the selected shape. |
| What this decision does not do | It does not authorize C1–C8 before the required close evidence and other decisions. It does not claim that prerequisite rows P1–P8 hold. It does not close issue #810 or #813. It does not claim specification §19.6.1. It does not authorize a tag from this pull request. |

The Chief Executive's 2026-10-22 4:00 PM ET path B ruling is background,
not a signature. The dated Signatures field above records the three names;
the ruling does not substitute for it.

## GD-031-02 — Marketplace take-rate, a v0.3.0 non-goal

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Does v0.3.1 reverse the v0.3.0 non-goal that excludes a marketplace take-rate? |
| Why this record exists | The mission title can be read as a platform fee. The proposal does not include one. Silence must not be read as reversal. |
| Approver roles | Chief Executive, EXOCHAIN PBC; Legal counsel |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not reverse. Party-to-party x402
evidence stays. `exo-economy` zero-launch pricing stays. A fee requires a
later record that states the integer basis points and the recipient.

CEO direction, 2026-10-09, not a signature and not a decision: Bob Stewart,
CEO, wrote at 11:33 PM ET, "We have to finish 0.3.0 or roll it up and in… the
commercial lines is preparatory as we have no assurance partner yet." The
commercial line this record covers stays preparatory. Settlement in this
package is interfaces and schemas only. No take-rate is authorized. This
record stays PENDING signature.

## GD-031-03 — Second evidence-pack product on AVC validate, a v0.3.0 non-goal

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Does v0.3.1 reverse the non-goal that forbids a second evidence-pack product on AVC validate? |
| Why this record exists | Capability C6 asks for canonical portable evidence. The proposal puts that evidence in a new manifest and leaves `POST /api/v1/avc/validate` free and unchanged. |
| Approver roles | Chief Executive, EXOCHAIN PBC; Security reviewer |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not reverse. Confirm the
manifest is a different object.

CEO direction, 2026-10-09, not a signature and not a decision: Bob Stewart,
CEO, wrote at 11:33 PM ET, "We have to finish 0.3.0 or roll it up and in… the
commercial lines is preparatory as we have no assurance partner yet." The
portable evidence bundle stays a schema and a composition manifest.
Commercial productization of that bundle stays preparatory. This record
stays PENDING signature.

## GD-031-04 — AACP, a v0.3.0 non-goal

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Does v0.3.1 reverse the non-goal labelled AACP? |
| Why this record exists | The token is not defined in this checkout. None of C1–C8 is identified as AACP. Reversal is impossible to scope until a human defines the token. |
| Approver roles | Chief Executive, EXOCHAIN PBC |
| Definition of AACP, if any | |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not reverse and do not invent a
definition in the implementation.

## GD-031-05 — EXO Credits, a v0.3.0 non-goal

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Does v0.3.1 reverse the non-goal that excludes EXO Credits? |
| Approver roles | Chief Executive, EXOCHAIN PBC; Legal counsel |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not reverse. Amounts are integer
minor units of an external currency inside payment evidence, not a new
EXOCHAIN instrument.

## GD-031-06 — LegalDyne branding, a v0.3.0 non-goal

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Does v0.3.1 reverse the non-goal that excludes LegalDyne branding? |
| Approver roles | Chief Executive, EXOCHAIN PBC; Legal counsel |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not reverse. LegalDyne stays an
external proprietary product. This market path makes no LegalDyne claim.

## GD-031-07 — CIM fiction, a v0.3.0 non-goal

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Does v0.3.1 reverse the non-goal labelled CIM fiction? |
| Why this record exists | The token is not defined in this checkout. C1–C8 do not add a fiction product. |
| Approver roles | Chief Executive, EXOCHAIN PBC |
| Definition of CIM fiction, if any | |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not reverse.

## GD-031-08 — Gamma, a v0.3.0 non-goal

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Does v0.3.1 reverse the non-goal labelled Gamma? |
| Why this record exists | The token is not defined in this checkout. C1–C8 do not add a Gamma surface. |
| Approver roles | Chief Executive, EXOCHAIN PBC |
| Definition of Gamma, if any | |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not reverse.

## GD-031-09 — Risk-proportionate human approval for autonomous AI-SDLC

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | Which human approvals are required before an agent-authored change may merge, by risk tier? |
| Approver roles | Chief Executive, EXOCHAIN PBC; Release approver A; Release approver B |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Proposed text awaiting a decision. It has no effect while this record is
PENDING.

| Tier | Work | Humans required | Agent |
| --- | --- | --- | --- |
| 0 | Docs, schemas, fixtures that do not change runtime | One human merger, distinct from the agent | May draft. May not merge |
| 1 | Adapter code inside an existing fail-closed boundary, no new permission | One human reviewer distinct from the agent | May draft. May not approve |
| 2 | Authority, consent, delegation, payment evidence, TSA pins | Two distinct humans, one of whom holds a release-approver role | May not be either human |
| 3 | Kernel invariants, non-goal reversals, assurance-partner policy, publication | Chief Executive plus release approvers A and B, all distinct | May not be any of them |

Mechanical rule, if this text is adopted: the acting engineering identity
that authored the change cannot appear in the approver set. That is the
same shape as `NoSelfGrant`. A written instruction to the agent is not the
control.

## GD-031-10 — Assurance-partner policy

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | May any named independent issuer attach a surety, insurance, bonding, or reinsurance product to the v0.3.1 interface? |
| Approver roles | Chief Executive, EXOCHAIN PBC; Legal counsel |
| Named issuer, if any | |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: leave the issuer empty. The
interface stays at `coverage_claim = none` and `exochain_is_obligor = false`.
EXOCHAIN does not become an insurer, surety, or bonding company by shipping
the schema.

CEO direction, 2026-10-09, not a signature and not a decision: Bob Stewart,
CEO, wrote at 11:33 PM ET, "We have to finish 0.3.0 or roll it up and in… the
commercial lines is preparatory as we have no assurance partner yet." There
is no assurance partner yet. Assurance pieces stay interfaces and schemas
only, with `coverage_claim` fixed to `none`. The named-issuer field stays
empty. This record stays PENDING signature.

## GD-031-11 — Microsoft timestamp dependency

| Field | Entry |
| --- | --- |
| Status | PENDING |
| Question | May the minimum demonstration depend on Microsoft's documented Artifact Signing RFC 3161 TSA at `http://timestamp.acs.microsoft.com`, with public SPKI verification and a labelled fallback to other RFC 3161 TSAs? |
| What is not being decided | An EXOCHAIN–Microsoft contract. None is asserted. Azure Confidential Ledger and Signing Transparency are not substitutes. |
| Approver roles | Chief Executive, EXOCHAIN PBC; Security reviewer |
| Pinned SPKI values for the demonstration | |
| Fallback TSA URL, OID, and pin, if any | |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: reuse the existing node adapter for
the demonstration, keep the pin inside the public bundle, and do not treat
HTTP reachability of the TSA as a contract or as token validity.

## Open questions for the Chief Executive

These are the blanks that block implementation. They are questions, not
decisions.

1. GD-031-01: path B is SIGNED on 2026-10-23 above and in [V030-CLOSE-RECORD.md](V030-CLOSE-RECORD.md), with Bob Stewart, Max Stewart, and Robert Stewart named. The close is recorded inside the 0.3.1 release; there is no separate v0.3.0 tag. Completion evidence remains required under its conditions. Neither a v0.3.0 nor a v0.3.1 tag is authorized from this pull request.
2. GD-031-02: confirm that market-making does not include a take-rate. CEO direction on 2026-10-09 calls the commercial lines preparatory. The signature line is blank.
3. GD-031-03: confirm that portable evidence is not a second product on AVC validate. CEO direction on 2026-10-09 keeps that commercial line preparatory. The signature line is blank.
4. GD-031-04, GD-031-07, GD-031-08: define AACP, CIM fiction, and Gamma, or confirm they stay undefined and unreversed.
5. GD-031-05 and GD-031-06: confirm EXO Credits and LegalDyne branding stay out.
6. GD-031-09: accept, edit, or replace the tier table.
7. GD-031-10: name an assurance partner, or confirm there is none. CEO direction on 2026-10-09 says there is no assurance partner yet, so `coverage_claim` stays `none`. The signature line is blank.
8. GD-031-11: accept the public Microsoft TSA as a demonstration dependency, and supply the SPKI pin through the existing operator configuration. Do not send a private key to the repository.

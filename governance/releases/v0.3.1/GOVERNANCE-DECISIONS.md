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

**Status: PROPOSAL. Every record below is PENDING. None is approved. This
document does not claim release readiness.**

Humans fill the blank fields. An agent must not write a decision, a
signature, or a date into those fields. An agent must not be any approver.
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
| Status | PENDING |
| Question | May engineers implement `governance/releases/v0.3.1/` after a v0.3.0 close, and not before? |
| Approver roles | Chief Executive, EXOCHAIN PBC; Release approver A; Release approver B |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

Engineer recommendation, not a decision: do not authorize implementation in
this pull request. Require a signed `V030-CLOSE` first. Keep this record
PENDING until those three humans sign. Do not treat the draft below as that
signature.

Proposed decision text, awaiting signature. It has no effect while this
record is PENDING. It does not fill Decision, Conditions, Rationale,
Dissent, Date, or Signatures above. An agent wrote the draft. An agent did
not sign it, did not write a name into Signatures, and did not mark this
record approved.

| Field | Proposed entry |
| --- | --- |
| Selected shape | Path B in [GOAL.md](GOAL.md). The v0.3.0 close is recorded inside the 0.3.1 release. There is no separate `v0.3.0` tag. |
| Where the close record lives | [V030-CLOSE-RECORD.md](V030-CLOSE-RECORD.md), inside `governance/releases/v0.3.1/`. That file is a draft. It is not a signed close, and it does not satisfy the `V030-CLOSE` precondition in [DEMO.md](DEMO.md). |
| What stays refused | Path A. A standalone `v0.3.0` tag is not the selected shape. |
| What this text does not do | It does not approve this record. It does not authorize C1–C8. It does not claim that prerequisite rows P1–P8 hold. It does not close issue #810 or #813. It does not claim specification §19.6.1. |

Chief Executive ruling, 2026-10-22 at 4:00 PM ET, not a signature and not a
decision: path B. The v0.3.0 close is recorded inside the 0.3.1 release.
There is no separate v0.3.0 tag. The Signatures field stays empty. Status
stays PENDING. This record is not approved.

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

1. GD-031-01: the Chief Executive ruled path B on 2026-10-22 at 4:00 PM ET. The v0.3.0 close is recorded inside the 0.3.1 release. There is no separate v0.3.0 tag. That ruling is drafted above and in [V030-CLOSE-RECORD.md](V030-CLOSE-RECORD.md). It is not signed. The signature line is blank. Status stays PENDING. The record is not approved. Release approver A and release approver B have not signed.
2. GD-031-02: confirm that market-making does not include a take-rate. CEO direction on 2026-10-09 calls the commercial lines preparatory. The signature line is blank.
3. GD-031-03: confirm that portable evidence is not a second product on AVC validate. CEO direction on 2026-10-09 keeps that commercial line preparatory. The signature line is blank.
4. GD-031-04, GD-031-07, GD-031-08: define AACP, CIM fiction, and Gamma, or confirm they stay undefined and unreversed.
5. GD-031-05 and GD-031-06: confirm EXO Credits and LegalDyne branding stay out.
6. GD-031-09: accept, edit, or replace the tier table.
7. GD-031-10: name an assurance partner, or confirm there is none. CEO direction on 2026-10-09 says there is no assurance partner yet, so `coverage_claim` stays `none`. The signature line is blank.
8. GD-031-11: accept the public Microsoft TSA as a demonstration dependency, and supply the SPKI pin through the existing operator configuration. Do not send a private key to the repository.

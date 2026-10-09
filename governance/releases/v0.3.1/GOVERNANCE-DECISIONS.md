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
this pull request. Require `V030-CLOSE` first. Keep this record PENDING until
those three humans sign.

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

1. GD-031-01: authorize implementation only after a v0.3.0 close, or not at all.
2. GD-031-02: confirm that market-making does not include a take-rate.
3. GD-031-03: confirm that portable evidence is not a second product on AVC validate.
4. GD-031-04, GD-031-07, GD-031-08: define AACP, CIM fiction, and Gamma, or confirm they stay undefined and unreversed.
5. GD-031-05 and GD-031-06: confirm EXO Credits and LegalDyne branding stay out.
6. GD-031-09: accept, edit, or replace the tier table.
7. GD-031-10: name an assurance partner, or confirm there is none.
8. GD-031-11: accept the public Microsoft TSA as a demonstration dependency, and supply the SPKI pin through the existing operator configuration. Do not send a private key to the repository.

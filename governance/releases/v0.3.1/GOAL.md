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

# v0.3.1 proposal goal

**Status: PROPOSAL. Pending constitutional authorization and approved successor
release planning. Not approved. Not a release. This document does not claim
release readiness.**

Source directive: EXOCHAIN v0.3.1 Market-Making Platform Engineering Directive,
issued by Bob Stewart, CEO, EXOCHAIN PBC. The directive's own status line is
"Proposed; pending constitutional authorization and approved successor release
planning." This goal restates that directive as a review package. It does not
convert the directive into an authorization.

Normative context: [ADR-001](../../../docs/adr/ADR-001-authority-of-text.md).
Specification v2.2 remains the normative specification. v0.3.0's goal remains
[governance/releases/v0.3.0/GOAL.md](../v0.3.0/GOAL.md): "PDP decides. AVC
records. x402 adapts."

## Mission

Extend the v0.3.0 evidence-grade trust foundation into an agent-native
market-making platform for independently governed, verifiable economic
relationships.

v0.3.1 cannot start implementation, cannot be tagged, and cannot be described
as the successor release until v0.3.0 is closed by a human release record.
There is no `v0.3.0` tag on this checkout. The first shippable cut of the
PDP / AVC / x402 split shipped as 0.2.4
([governance/releases/v0.2.4/RC.md](../v0.2.4/RC.md)). That RC says it is not a
v0.3.0 close, and that issue #813 stays open.

## What v0.3.0 must deliver first

The behaviors below are the v0.3.0 must-be-true list. Several already exist in
source on `main` because 0.2.4 landed the first cut. Existence in source is not
a v0.3.0 close. Market implementation waits until a human records that each
item holds. The proposed shape in the next section is path B (milestone 1
inside this release). It is not adopted. #789's two-person publication stop
still applies to any later tag.

| # | v0.3.0 prerequisite | Where the first cut lives | What v0.3.1 still requires |
| --- | --- | --- | --- |
| P1 | Missing payment on an otherwise permitted commercial mandate is `Challenge` (HTTP 402), not `Deny` (HTTP 403) | `exo-pdp` `map_decision_to_http` | v0.3.0 close. v0.3.1 settlement reuses this mapping and must not add a second decision brain |
| P2 | Deny still outranks a bound payment hash | `exo-pdp` verify hop | Same. A paid hash never converts Deny into Allow |
| P3 | Payment evidence is a non-zero BLAKE3 hash of canonical CBOR. Zero hash and header-only proofs fail closed | `PAYMENT_EVIDENCE_DOMAIN` = `exo.x402.payment.evidence.v1`. Header-only is tested. The canonical-CBOR digest and the zero-hash test are still open; see the assessment | Milestone 1 finishes that digest in `exo-pdp`. v0.3.1 does not define a second payment hash |
| P4 | AVC receipts can record `payment_evidence_hash` without breaking legacy signing payloads | `exo-avc` `AvcTrustReceipt` | The market evidence bundle references that hash. It does not fork the receipt |
| P5 | #812 — `exochain-core` builds from crates.io (`ml-dsa` without default `pkcs8`) | Tracked by the v0.3.0 goal | v0.3.0 record that the condition still holds. v0.3.1 does not reopen it as new work |
| P6 | Open x402 PRs #815 and #816 stay superseded by this stack, not merged as a second brain | v0.3.0 goal | v0.3.1 x402 profile is the same adapter |
| P7 | #810 CGR traces stay out of the tag unless the release claims spec §19.6.1 | v0.3.0 goal | v0.3.1 does not claim spec §19.6.1 |
| P8 | #789 two-person release approval remains a publication stop even after the code is green | Environments `release` and `release-second` | Applies to any later v0.3.0 tag and to any later v0.3.1 tag. This proposal is not that tag |

Until those eight hold as a recorded close, every market work item in
[ISSUES.md](ISSUES.md) is blocked. [V030-CLOSE-ASSESSMENT.md](V030-CLOSE-ASSESSMENT.md)
scores the eight rows against `main` at `a2667295`. Rows 1, 2, 4, 5, 6, and 8
already hold in source and in GitHub state. Row 3 is partial. Row 7 is a
missing release sentence. That score is an assessment. It is not the close.

## Proposed release shape

Bob Stewart, CEO, wrote on 2026-10-09 at 11:33 PM ET: "We have to finish 0.3.0
or roll it up and in… the commercial lines is preparatory as we have no
assurance partner yet." The sentence leaves both shapes open. The engineer
recommendation in the assessment is path B. GD-031-01 stays PENDING, so this
section is a draft structure, not an adopted plan.

| Milestone | Contents | Gate |
| --- | --- | --- |
| 0 | This package: documents, schemas, fixtures | Review only. Closes nothing. Authorizes nothing |
| 1 | v0.3.0 close. Finish the partial payment-evidence hash (row 3). Record that spec §19.6.1 is not claimed and that #810 stays open (row 7). Record that the other six rows already hold on `a2667295`. Leave #813 outside this milestone unless humans narrow it | A human records that the eight rows hold. Market issues stay blocked until that record exists |
| 2 and after | Capabilities C1–C8, in the order in [DEPENDENCY-GRAPH.md](DEPENDENCY-GRAPH.md) | Milestone 1 record, plus the GD-031 signatures |

Path B does not cut a separate `v0.3.0` tag. The publication cost observed on
0.2.7 (environment `release` reviewer `mstewartbz`, environment
`release-second` reviewer Taz or Robert, and a fragile draft upload) is paid
once, when a later authorized release is published. Path A, a standalone
0.3.0 tag first, repeats that publication before any market work.

## Required capabilities

| # | Capability | Reuse | New, and only after authorization |
| --- | --- | --- | --- |
| C1 | Standards-based MCP and A2A discovery, with portable HTTP APIs and SDKs | `GET /.well-known/exochain.json`; node MCP `initialize` / `tools/list` (advertised protocol `2024-11-05`); `packages/exochain-sdk`, `packages/exochain-py`, `packages/exochain-llm-proxy` | A2A Agent Card profile. No A2A implementation exists in this checkout |
| C2 | Cryptographically verified principal and agent identity, bounded delegation, consent, revocation, and policy | `exo-identity`, `exo-authority` (scope only narrows), `exo-consent`, `exo-avc`, `exo-pdp`, gatekeeper invariants | Market-action binding that runs those checks in one order. 0dentity device/behavior axes stay default-off unaudited features |
| C3 | Machine-negotiable bilateral and multipartite bailments: proposal, counteroffer, commitment, fulfillment, discharge, dispute | Bilateral `exo-consent` bailment (`Proposed`, `Active`, `Suspended`, `Terminated`, `Expired`) and `exo-economy` `BailmentTerms` | Counteroffer, multipartite party set, fulfillment, discharge, and dispute states |
| C4 | Lightweight claim attestation with Microsoft-backed trusted timestamps and independently verifiable receipts | `POST /api/v1/avc/claims/stamp` and `exo-node` RFC 3161 verifier against `http://timestamp.acs.microsoft.com` | Public second-party verification profile and an explicit fallback TSA. See [specs/MICROSOFT-TIMESTAMP-ADAPTER.md](specs/MICROSOFT-TIMESTAMP-ADAPTER.md) |
| C5 | x402 commercial settlement with authorization enforcement and verifiable payment evidence | `exo-pdp` `/x402/verify` adapter. EXOCHAIN does not move money | Market mandate profile that calls that adapter. No second x402 stack |
| C6 | Canonical portable evidence connecting identity, authority, agreements, payments, execution, and outcomes | `exo-pdp` `EvidencePack`, `exo-legal` `EvidenceBundle`, AVC trust receipts | A composition manifest that references those hashes. Not a second product on `POST /api/v1/avc/validate` |
| C7 | Extensible financial-assurance schemas and adapters | `exo-economy` `AssuranceClass` is a pricing classifier (`Free` through `Critical`). It is not coverage | Interface schemas only. EXOCHAIN does not provide insurance, surety, or bonding |
| C8 | Autonomous AI-SDLC under constitutional governance, with risk-proportionate human approval and independent verification | Gatekeeper `NoSelfGrant` and `HumanOverride`; #789 two-person publication stop | The tier table in [GOVERNANCE-DECISIONS.md](GOVERNANCE-DECISIONS.md). Agents never hold approver roles |

The exists-versus-new map is specified in [ARCHITECTURE.md](ARCHITECTURE.md).

## Engineering constraints

- Reuse the implementations named above. Do not create a parallel PDP, AVC,
  x402 stack, bailment engine, or timestamp client.
- Preserve v0.3.0 trust, authority, and cryptographic invariants: no floating
  point, `BTreeMap`/`BTreeSet` only, canonical CBOR via `ciborium` for hashed
  payloads, HLC timestamps supplied by the caller, randomness only for key
  generation, no `unsafe`.
- Do not merge, deploy, publish, or claim release readiness before the
  decision records in [GOVERNANCE-DECISIONS.md](GOVERNANCE-DECISIONS.md) are
  filled by the named human roles.
- Deterministic tests, reproducible evidence, and auditable provenance are
  acceptance criteria, specified in [TEST-PLAN.md](TEST-PLAN.md).
- Separate discovery, negotiation, authority evaluation, execution, settlement,
  and verification. A message in one layer cannot perform another layer's act.
- Third-party interoperability is an acceptance criterion, stated below.
- Assurance interfaces are not coverage.
- Agents may optimize implementation. Agents must never expand their own
  authority. That prohibition is mechanical: `ConstitutionalInvariant::NoSelfGrant`
  already rejects `is_self_grant`, and `exo-authority` rejects scope widening.
  The market path must set `is_self_grant` when the acting DID is the grantor,
  and must reject any negotiated permission set that is not a subset of the
  human-issued mandate. A comment, prompt, or agent policy is not the control.

Future implementation of this proposal ships default-off, in the same
unaudited-feature pattern as Gate 23, until the authorizing decisions and the
v0.3.0 close both exist. This package adds no Cargo feature and no workflow.

## Non-goals for this proposal

### CEO direction, 2026-10-09

Bob Stewart, CEO, wrote on 2026-10-09 at 11:33 PM ET: "We have to finish 0.3.0
or roll it up and in… the commercial lines is preparatory as we have no
assurance partner yet."

This package records that direction. It does not mark GD-031-02, GD-031-03,
or GD-031-10 approved, and it does not fill their signature lines.

Commercial settlement (C5) and financial assurance (C7) stay interfaces and
schemas. `coverage_claim` stays the constant `none`. No assurance partner is
named. A marketplace take-rate stays out (GD-031-02, PENDING). A second
evidence-pack product on AVC validate stays out (GD-031-03, PENDING). The
assurance-partner issuer stays empty (GD-031-10, PENDING).

This proposal does not reverse a v0.3.0 non-goal. A reversal happens only when
the matching record in [GOVERNANCE-DECISIONS.md](GOVERNANCE-DECISIONS.md) is
filled by the named roles. Until then the v0.3.0 non-goals remain in force:

AACP, CIM fiction, marketplace take-rate, LegalDyne branding, EXO Credits,
Gamma, and a second evidence-pack product on AVC validate.

### Collisions that need an explicit decision

Two non-goals collide with a careless reading of this mission. They are not
reversed here. Humans must say so in the decision records, because silence
would let a later implementation reverse them by accident.

| v0.3.0 non-goal | Why a market-making reading collides | Disposition in this proposal |
| --- | --- | --- |
| Marketplace take-rate | "Market-making platform" can be read as a platform fee | Not in scope. Party-to-party x402 settlement is the v0.3.0 foundation. `exo-economy` zero-launch pricing stays. GD-031-02 |
| Second evidence-pack product on AVC validate | Capability C6 can be read as a new pack returned by validate | Refused. Validate stays free, unpaywalled, and does not mint a bundle. The composition manifest is a different object. GD-031-03 |

### Non-goals this mission does not imply

These tokens appear only as the v0.3.0 non-goal line. This checkout does not
define AACP, CIM fiction, or Gamma. v0.3.1 does not define them and does not
request their reversal.

| v0.3.0 non-goal | Why v0.3.1 does not request a reversal | Decision record |
| --- | --- | --- |
| AACP | Undefined in this checkout. None of C1–C8 is labelled AACP | GD-031-04 |
| EXO Credits | Settlement evidence is the existing payment-evidence hash, not a new instrument | GD-031-05 |
| LegalDyne branding | LegalDyne remains an external proprietary product. This package makes no LegalDyne claim | GD-031-06 |
| CIM fiction | Undefined here. No narrative product is in C1–C8 | GD-031-07 |
| Gamma | Undefined here. No Gamma surface is in C1–C8 | GD-031-08 |

Also out of scope, consistent with current open ledger rows:

- Production SNARK/STARK/ZKML soundness (VCG-001). This proposal makes no
  zero-knowledge soundness claim.
- Treating MCP tool execution as constitutional adjudication (VCG-004).
- Enabling 0dentity device or behavior axes (VCG-008, VCG-009). Those remain
  default-off unaudited features.
- Hardware TEE attestation as a trust root (VCG-011).
- Spec §19.6.1 CGR completeness (#810).
- Billing savings, thesis acceptance, or DAG DB production claims beyond the
  gateway REST paths already described in `INTEGRATION.md`.

## Minimum release demonstration

The demonstration is specified as a script in [DEMO.md](DEMO.md). It is not
executed by this package. Acceptance is the conjunction of the checks below.
Each check names an artifact the demonstration must emit and a check a later
harness can run without a human in the loop.

An independent agent discovers an EXOCHAIN-compatible commercial service,
verifies its own authority, negotiates a multipartite bailment, completes an
authorized x402 payment, receives the service, obtains independently verifiable
Microsoft-timestamped evidence, and discharges the agreed obligations. A second
independent system verifies the resulting evidence without proprietary
privileged access.

| ID | Acceptance criterion | Pass condition |
| --- | --- | --- |
| AC-1 | Discovery | The agent fetches the public discovery document and an A2A Agent Card. The card names HTTP endpoints and SDK package names. It grants no permission |
| AC-2 | Authority before negotiation | The agent presents a credential whose scope is a subset of a human principal's mandate. A self-grant attempt returns Deny under `NoSelfGrant` and does not reach 402 |
| AC-3 | Multipartite bailment | At least three distinct party DIDs sign proposal, counteroffer, and commitment. Commitment does not add permissions. Fulfillment, discharge, and a rejected dispute are all represented in the transcript |
| AC-4 | x402 settlement | A commercial mandate with missing payment returns HTTP 402 Challenge. The same mandate after Deny returns HTTP 403 even if a payment hash is attached. A non-zero BLAKE3 payment-evidence hash is the only paid proof. `PAYMENT-SIGNATURE` alone is not paid. `POST /api/v1/avc/validate` stays unpaywalled |
| AC-5 | Service and discharge | Execution starts only after PDP Allow and an active bailment. Discharge is a signed state transition. It does not edit the kernel |
| AC-6 | Microsoft timestamp | The claim stamp carries an RFC 3161 token whose message imprint matches the canonical claim bytes, whose policy and authority identity are recorded, and whose signer key is pinned by SPKI shipped inside the public bundle |
| AC-7 | Portable evidence | One canonical bundle references identity, authority, agreement, payment, execution, and outcome hashes. A tampered byte changes the bundle hash |
| AC-8 | Third-party interoperability | A second implementation, written against the published schemas and fixtures only, replays AC-1 through AC-7. It does not link the EXOCHAIN workspace |
| AC-9 | Second verifier | The verifier's inputs are the public bundle, detached signatures, the RFC 3161 token, and pinned SPKI. It has no database URL, bearer token, Azure credential, or EXOCHAIN private key. It accepts the intact bundle and rejects each tamper fixture |
| AC-10 | Non-coverage | The bundle's assurance section has `coverage_claim = none` and `exochain_is_obligor = false`. Any other value fails validation |
| AC-11 | No self-authority expansion | For every negotiated message in the transcript, the acting agent's permission set after the message is a subset of its permission set before the message. The gatekeeper context has `is_self_grant = false` on the successful path and `is_self_grant = true` on the negative fixture |
| AC-12 | Human override preserved | The successful transcript still has `human_override_preserved = true`. A fixture that clears it is rejected by `HumanOverride` |
| AC-13 | Determinism | Two runs over the same fixtures produce identical canonical CBOR and identical BLAKE3 hashes |
| AC-14 | Governance still pending is a failure of a release, and a success of this proposal | A release tag is forbidden while any GD-031 record is PENDING. This proposal is valid only while those records stay PENDING |

AC-14 is the acceptance criterion for **this pull request**. AC-1 through AC-13
are acceptance criteria for a later, separately authorized implementation.
They are not claimed to pass here.

## Gap registry

Do not add v0.3.1 rows to `GAP-REGISTRY.md` under the current convention. That
ledger is the single source of truth for critical systemic-integrity gaps
VCG-001 through VCG-015. Its guard requires those exact headings and forbids a
parallel critical-gap registry at the repository root. Proposal work items live
in [ISSUES.md](ISSUES.md) until a human authorizes implementation and a
coordinator promotes any item that has become a critical gap on `main`.

## North star

Superintelligence-speed innovation. Human-legitimate authority.
Cryptographically accountable economic relationships.

The speed applies to drafting and optimization. Authority stays with the human
roles named in the decision records.

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

# v0.3.1 proposal threat model

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

This model covers the proposed market path. It does not replace
`docs/architecture/THREAT-MODEL.md`, which remains the repository threat
taxonomy under ADR-001. It also does not claim the mitigations are
implemented. Mitigations that say "existing" name code on `main`. Mitigations
that say "proposed" are requirements on a later implementation.

Method: STRIDE on each of the six layers, then the eight named abuse cases.
Impact is rated for the proposal as written, assuming an implementer follows
it. A shortcut that skips a layer raises the rating.

## STRIDE by layer

| Layer | Spoofing | Tampering | Repudiation | Information disclosure | Denial of service | Elevation of privilege |
| --- | --- | --- | --- | --- | --- | --- |
| Discovery | Forged Agent Card or MCP catalog | Edited well-known document in transit | Service denies publishing a card | Card leaks a token or key | Huge card, tool-list flood | Card claims `grants_authority: true` |
| Negotiation | Party DID signed by the wrong key | Counteroffer swaps terms hash | Party denies a commit signature | Terms carry raw payment instruments | Dispute or counteroffer flood | Message adds permissions or a new role |
| Authority evaluation | Stolen agent key used inside its real scope | Caller passes `is_self_grant: false` | PDP evidence omitted | Revocation reason leaks secrets | Revocation-set stall | Self-grant, scope widening, role union |
| Execution | Fulfillment signed by a party who was not Allowed | Fulfillment hash over different bytes | Service denies performing | Service response includes another tenant's data | Slow service holds a reservation | Execution starts on Deny or on a proposed bailment |
| Settlement | Facilitator reference copied from another payment | Payment preimage swapped under the same header | Payer denies the hash binding | Evidence preimage contains a PAN or secret | Challenge retry loop | Header or zero hash treated as paid; Deny mapped to 402 |
| Verification | Second verifier trusts a substituted SPKI | Manifest section edited after signing | TSA or party signature missing | Bundle contains a bearer token | Oversized token | Assurance section read as coverage or as Allow |

### Discovery mitigations

Existing: `/.well-known/exochain.json` is a fixed document, MCP public
transport is off, response sizes on the SDK HTTP client are capped.
Proposed: service signature over the card, client pin of the service DID,
schema rejection unless `grants_authority` is false, discard any permission
found in a tool result. Poisoning is T7 below.

### Negotiation mitigations

Existing: consent bailment signatures, terms domain separation.
Proposed: hash-linked transcript, subset check on every counteroffer,
integer dispute caps, no status change toward commit without authority
Allow. Griefing is T6. Collusion is T5.

### Authority mitigations

Existing: eight invariants; `exo-authority` rejects scope widening;
AVC validation is fail-closed; PDP Deny outranks payment.
Proposed: the ingress computes `is_self_grant` instead of trusting the
caller. This is the mechanical control for T1 and T2. An agent prompt that
says "do not self-grant" is not a mitigation in this model.

### Execution mitigations

Proposed: execution module refuses to run without a PDP Allow evidence hash
and an `Active` bailment id. Fulfillment is a hash, not a second decision.
Human override stays set (T-adjacent to `HumanOverride`).

### Settlement mitigations

Existing: non-zero BLAKE3 domain, header ignored, zero hash rejected,
never-paywall list, `never_moves_money`.
Proposed: preimage binds mandate hash and terms hash so a hash cannot be
replayed onto another transcript (T3). No take-rate line.

### Verification mitigations

Existing: RFC 3161 verifier checks imprint, nonce, policy, and pinned SPKI.
Proposed: second verifier has no privileged input (AC-9). Assurance constants
fail closed (T8). Manifest signatures cover the hash of every section.

## Named abuse cases

### T1 — Agent self-authority expansion

**Actor.** An agent whose AVC is valid for a narrow scope.
**Action.** The agent submits a counteroffer, a new authority link, an MCP
tool call, or an AI-SDLC change that adds a permission, a party role, a
longer lifetime, or a release-approver role for its own DID.
**Why the current flag is not enough by itself.** `check_no_self_grant`
returns an error only when `ctx.is_self_grant` is already true. A caller who
leaves the flag false skips the invariant. The market ingress must set the
flag from the bytes: actor DID equals grantor DID, or the requested
permission set is not a subset of the intersection of chain scope, AVC
scope, and bailment ceiling.
**Result required.** `NoSelfGrant`, HTTP 403 if a decision is mapped, no
402, no transcript append, no feature-flag edit, no release approval.
**Residual.** A stolen human principal key is outside this case. That is
theft of the principal, and the agent is then acting inside a real grant.
Revocation is the response, not a wider agent right.

### T2 — Delegation widening

**Actor.** A delegatee with a narrowed link.
**Action.** Re-delegate with a broader permission set, a broader counterparty
list, or `delegation_allowed` flipped from false to true.
**Existing control.** `exo-authority` returns scope-widening errors. AVC
`delegation_allowed` is part of the credential.
**Proposed control.** Negotiation treats a widening counteroffer as T1.
Child credentials cannot be minted by an agent whose credential forbids
delegation. Depth limits already in the kernel stay in force.
**Result required.** Reject the link. Do not partially apply the subset.

### T3 — Replayed or forged payment evidence

**Actor.** A payer, a facilitator, or a network attacker.
**Action.** Present `PAYMENT-SIGNATURE` without a hash; present the zero
hash; present a valid hash for mandate A against mandate B; replay a 200
response after revocation.
**Existing control.** Header is not payment. Zero hash fails closed. Deny
outranks a bound hash.
**Proposed control.** Evidence preimage includes mandate hash, terms hash,
amount, and currency. Reservation commit is single-use for that mandate
hash. Revocation is re-checked before the final Allow.
**Result required.** 402 if unpaid and otherwise permitted; 403 if denied or
revoked; 200 only with a matching non-zero hash.

### T4 — Timestamp-authority compromise

**Actor.** The configured TSA, a network attacker on the HTTP TSA URL, or an
operator who swaps the URL.
**Action.** Issue a token over a different imprint, omit the nonce, swap the
policy OID, or present a token from a different CA while keeping the
Microsoft DID label.
**Existing control.** `avc_rfc3161` checks imprint, nonce, policy, EKU, and
pinned SPKI. The stamp path currently requires the Microsoft DID and policy
OID.
**Proposed control.** The pin travels in the public bundle. Fallback TSAs
are explicit and labelled. Azure Confidential Ledger and Signing
Transparency are not silent substitutes. Generalized time does not reorder
HLC history.
**Residual.** A TSA that is honest about the time and dishonest about
whether it should have signed still produces a valid token over whatever
imprint it was given. The token does not prove the claim's truth. Parties'
signatures and the PDP evidence do that. Pin rotation after a key
compromise is an operator action under GD-031-11, and old tokens verify
under the pin that was current in that bundle, not under a quietly new pin.
**Result required.** Second verifier rejects substituted tokens and accepts
a genuinely signed Microsoft token using only public bytes.

### T5 — Multipartite collusion

**Actor.** Two or more parties, including a service and a witness.
**Action.** Sign a commitment that looks unanimous while excluding a bailor,
or sign a fulfillment the service did not perform, or split roles so each
party's individual scope looks narrow while the union is wide.
**Control.** Threshold counts required roles, not a vague majority. The
union of permissions is still subject to each actor's own ceiling. A party
cannot contribute permissions it does not have. The bundle lists every
signer. Independence is not claimed. A market commitment is not an
`exo-governance` quorum and must not be labelled one.
**Result required.** A commitment missing a required bailor or bailee does
not activate the consent bailment. Collusion among authorized parties is
visible in the signer set. It is not prevented by cryptography, and the
evidence must not say it is.

### T6 — Dispute griefing

**Actor.** A party who wants to stall discharge.
**Action.** Repeat disputes, dispute an unrelated transcript, or dispute in
order to gain a permission or a fee waiver.
**Proposed control.** One open dispute per transcript, a small integer cap
per party, no deadline reset on rejection, no permission change, human
override stays available so a human can terminate the bailment.
**Result required.** Further disputes after the cap are rejected messages.
The original fulfillment hash remains. No 402 is minted by a dispute.

### T7 — Discovery poisoning

**Actor.** A publisher of a lookalike card, or a compromised MCP catalog.
**Action.** Point `supported_interfaces` at an attacker host, advertise a
tool that asks the agent to grant itself `Govern`, or omit the signature.
**Proposed control.** Clients pin the service DID out of band for the
demonstration (the pin is a public byte string in the test vector, not a
secret). Unsigned or mismatched cards are dropped. Tool output cannot grant.
The existing discovery document's `base_url` is not overwritten by the card.
**Result required.** The agent either talks to the pinned service or stops.
It does not negotiate with the lookalike.

### T8 — Misrepresenting assurance as coverage

**Actor.** A market operator, an SDK, a partner adapter, or an agent writing
docs.
**Action.** Set `coverage_claim` to anything but `none`, set
`exochain_is_obligor` true, map `AssuranceClass::LegalGrade` to "insured",
or describe the interface as a bond in force.
**Proposed control.** Schema constants. Adapter rejection. A forbidden-phrase
scan in the test plan. GD-031-10 stays PENDING, so no partner issuer is
authorized by this package.
**Result required.** Invalid documents fail validation. Valid documents say,
in the fixed sentence, that no coverage is in force.

## Top risks if the proposal were implemented carelessly

Ordered by how directly they break human-legitimate authority or make a
false economic claim.

1. **T1 self-grant**, if the ingress trusts the caller's flag.
2. **T3 forged or replayed payment evidence**, if a new route treats the
   header as paid or skips the mandate binding.
3. **T4 TSA compromise or mislabel**, if a fallback token is presented as
   the Microsoft TSA or the SPKI pin is not in the public bundle.
4. **T8 assurance presented as coverage**, if the schema constants are
   documented and then ignored in UI or SDK strings.
5. **T2 combined with T5**, delegation widening inside a multipartite
   counteroffer, if the union of party requests is applied instead of the
   intersection of ceilings.

T6 and T7 are serious and specified. They sit behind those five because a
griefing dispute or a poisoned card, under this design, stops or stalls one
transcript, while T1–T4 and T8 mint authority, payment, time, or a false
promise.

## Out of model

Production zero-knowledge soundness, TEE attestation, and MCP-as-kernel are
open VCG rows. This model does not assume they are solved and does not use
them as mitigations.

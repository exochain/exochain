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

# x402 settlement profile

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Capability C5. Layer: settlement. Depends on v0.3.0 prerequisites P1–P4 and
P6. This profile is the existing adapter, applied to a market mandate. It is
not a second payment brain.

## Adapter contract already in source

`exo-pdp` documents the rule: the PDP decides; the x402 module maps that
decision onto facilitator HTTP and binds payment evidence by hash.
`PAYMENT-SIGNATURE` header presence is not payment. `never_moves_money` is
true on `X402VerifyResponse`. EXOCHAIN does not settle funds.

| PDP decision | Payment hash bound and non-zero | HTTP |
| --- | --- | --- |
| Deny | ignored | 403. Deny outranks the hash |
| Challenge | n/a | 402 |
| Allow | no | 402 for this commercial profile |
| Allow | yes | 200 |

`map_decision_to_http` is the source of that table. A market route calls it.
A market route that returns 402 for a Deny is a defect.

Payment evidence:

```text
domain = "exo.x402.payment.evidence.v1"
hash = BLAKE3(canonical_cbor(domain, evidence_bytes))
```

The hash is 32 bytes, non-zero. The zero hash and a header without a hash
fail closed. AVC receipts may store the hash on `payment_evidence_hash`
without changing the legacy signing payload. That is P4. The market bundle
references the same hash.

Never-paywalled paths stay never-paywalled:

- `POST /api/v1/avc/validate`
- paths containing `/api/v1/0dentity/`
- `/api/v1/agents/.../consent`

Facilitators call the verify hop only. They do not call validate to mint a
402, and they do not call the claim stamp to invent a payment.

## Market mandate

A commercial market action is a `WireMandate` the PDP already understands,
plus:

- the bailment transcript id and current terms hash;
- the integer `amount_minor` from the committed terms;
- the currency code from the committed terms;
- the caller-supplied HLC as `now_ms` (non-zero; the adapter already rejects
  a missing `now_ms`).

The mandate's permission set is the negotiation ceiling after subset checks.
Settlement does not edit it.

Challenge body, when 402 is returned, names the amount, currency, transcript
id, and the domain string. It does not include a private key, a bearer
token, or card data. EXOCHAIN does not collect card data in this profile.
The facilitator, outside this process, is what obtains payment and returns
the evidence bytes whose hash the client then submits.

## Replay and forgery

The evidence preimage includes the mandate hash, the terms hash, the amount,
the currency, and a facilitator reference string. A hash over a different
mandate does not satisfy this mandate. Replaying the same hash against a new
transcript fails the binding check inside authority evaluation before Allow.

The PDP reservation book (`reserve`, `commit`, `release`) is the existing
tool for holding a mandate during the challenge window. The market profile
uses it. It does not invent a second lock.

## Take-rate

No line item in this profile is a platform fee. `exo-economy` launch pricing
still resolves charged amounts to zero under `PricingPolicy::zero_launch_default`.
A marketplace take-rate is GD-031-02 and is not authorized by this profile.
Recording a party-to-party amount inside the payment-evidence hash is
settlement evidence. Skimming that amount is a different decision.

## Out of scope

EXO Credits, a new currency, facilitator custody inside EXOCHAIN, and merging
PRs #815 or #816 as a parallel stack.

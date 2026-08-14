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

# Broker narrative: one wedge, two SKUs, two options

This is the PE / broker story after a code walk of this repository. It
replaces five-engine CIM language. Adjacent verticals are design partners,
not GMV.

## One-liner

We’re the constitutional authorization and evidence layer in front of
agentic payments (x402/MPP). We decide whether this agent, under this
principal, with this consent posture, may pay and consume — and we issue
the signed, RFC 3161-timestamped receipt. We never move the money.

Do not say “insurance-underwritable” in the first sentence. No carrier has
accepted a pack.

## What is real

- Kernel adjudication over the eight invariants (`Permitted | Denied | Escalated`).
- Bailment consent (`Proposed → Active → Suspended/Terminated/Expired`), default-deny.
- AVC issue/validate on the node, including `ChallengeRequired` when the only
  reasons are payment-challenge codes.
- Payment evidence is a generic hash (`exo.avc.payment.evidence.v1`) bound
  into receipts. Header presence (`PAYMENT-SIGNATURE`) is not settlement.
- RFC 3161 is a node TSA client. It is not `AssuranceClass::LegalGrade`.
- LYNK usage receipts bind token/cost hashes.
- Economy types exist and launch at zero. `/api/v1/avc/validate` stays free.
- `exo-legal` can assemble an `EvidenceBundle` + FRE 902(11) snapshot that
  still requires a human declarant. That is SKU B, not a LegalDyne product.

## What is not real (cut from present-tense materials)

| Claim to cut | Reality |
|---|---|
| Marketplace take-rate 8–15% | `RevenueShareTemplate` exists; launch policy zeros amounts. No catalog take-rate engine. |
| LegalDyne | No package, crate, or module. |
| AI-IRB Institute | `ProviderSeat` implementations are mock/deterministic. No live LLM HTTP. |
| Council retainers | Docs, roster, and a DAG DB council route. Not a staffed review desk. |
| Carrier capacity / preferred-risk reinsurance | No underwriting crate. CyberMedica insurance is readiness scoring. |
| Multiple compounding engines | One wedge. Two paid SKUs. Two year-2 options. |

## The wedge

Hosted authorization + RFC 3161 evidence in front of x402.

```
agent → edge translator → POST /api/v1/avc/validate
      → ChallengeRequired / 402 PAYMENT-REQUIRED
      → external facilitator (Coinbase / Cloudflare)
      → retry with bound PaymentEvidence.hash
      → origin + LYNK / RFC 3161 receipt
```

Exochain is the authorization facilitator, not a payments company. Keep
payment facilitation external. Do not import Coinbase/x402/USDC types into
`exo-avc`.

## Two paid SKUs

**SKU A — Hosted node + Authorized Action Evidence Pack.**
Hosted `exochain` node: AVC validate (free), LYNK usage receipt, optional
RFC 3161, 0dentity score, DAG DB fail-closed writes. The paid artifact is
`POST /api/v1/avc/evidence-packs/assemble`: Allow decision + action
commitment + LYNK hash + optional RFC 3161 token + previous-receipt link +
bound payment evidence. Price the pack, not validation.

**SKU B — Counsel / compliance export.**
`EvidenceBundle` + FRE 902(11) + optional `AiTransparencyReport`, shipped
as “Authorized Action Evidence Pack — Counsel Edition.” Human declarant
and counsel review stay in the product. `filing_ready` is true only after
both. Do not brand this LegalDyne until a package exists.

## Two year-2 options

- **Marketplace take-rate** only after a resource catalog actually gates on
  AVC + bailment + receipt. Economy types can flip from zero without a
  rewrite. That is a feature, not a forecast.
- **Insurance** only after production evidence packs have been reviewed by
  one broker and one carrier. Then sell “preferred-risk evidence,” not
  “we unlock capacity.”

## Design partners, not GMV

- **LiveSafe:** first consumer-adjacent hop with a fail-closed adapter
  boundary (`trustClaimsAllowed: false` until verified). Proves
  identified + consented + receipted. Hash/commitment only. Not an
  insurance engine.
- **CyberMedica:** high-risk / clinical / AI Act deployer story and
  contract language. Insurance module is a readiness checklist. Useful
  for broker conversations; not risk transfer.
- **decision.forum:** later add-on once there is a hosted UX and
  verified-human voter registry. Sell the fiduciary package, not Council
  retainers.
- **0dentity:** identity axis inside SKU A (node API). Do not sell the
  LiveSafe-local scorer.
- **AI-IRB / CrossChecked:** internal / demo until `ProviderSeat` does
  live, receipted calls.

## Diligence one-pager (show in this order)

1. `validate_avc` decision table, including `ChallengeRequired` for
   payment-only reasons and Deny still mapping to 403.
2. `exo-x402` mapping: Deny→403, HumanApproval→428, Challenge→402,
   unpaid Allow→402. Settlement is `payment_settled_from_bound_evidence`.
3. Live node routes in `avc_router`, including evidence-pack assemble and
   the RFC 3161 client.
4. `PricingPolicy::zero_launch_default` + never-paywalled validate /
   0dentity / consent paths.
5. One LiveSafe boundary test proving fail-closed when core is unverified.
6. Explicit non-claims: no LegalDyne, no live AI-IRB, no take-rate, no
   carrier integration.

## How a broker should say it

Keep: category creation, not-a-payments-company, free-core moat, x402 +
AI Act timing, capital-light open core, strategic exit to
Cloudflare-scale infra or large compliance platforms.

Cut or demote to “options”: 8–15% take-rate, LegalDyne, AI-IRB Institute,
Council retainers, preferred-risk reinsurance, “multiple compounding
engines.”

Suggested close:

“I’d like you to meet the founding team. The constitutional core is
implemented and fail-closed — AVC, bailments, kernel invariants, and
RFC 3161 receipts are in the node today. The x402 authorization
facilitator is an adapter that never becomes a payments company;
settlement is a bound payment-evidence hash, not a header. The near-term
plan is to sell hosted evidence packs and use LiveSafe/CyberMedica as
regulated design partners. Marketplace and insurance are options that
become credible only after receipt volume exists. Happy to set a short
call so you can pressure-test that against the repo.”

## Valuation quote (after the requisite parts close)

Closing the hop and the two SKUs makes the company diligence-ready. It
does not make it a buyout platform.

“If they ship the authorization hop and the evidence pack — which is
mostly finishing work already in the repo — you are looking at a
**$25–50M** diligence-ready asset with a path to **$80–120M** on a
**$6–10M ARR** book. The $250M+ outcome is if they become the default
‘may this agent pay’ receipt on regulated x402 hops. The $1B slide is a
strategic-exit option, not a base case. We are not selling a marketplace
or an insurance company.”

Do not put $1B on a CIM after “closing the parts.”

A named edge distribution deal (Cloudflare, AWS CloudFront/WAF, or
Coinbase Agentic.Market as the authorization sidecar) changes the range
more than extra SKUs.

## Classification

| Path | Classification |
|---|---|
| `docs/g2m/broker-narrative.md` | Documentation. Does not change core runtime behavior. |

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

# v0.3.1 dependency graph

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Arrows mean "cannot be implemented honestly until". They are not an
authorization to implement.

## v0.3.0 blocks v0.3.1

```mermaid
flowchart TD
  P1["P1 Challenge is 402"]
  P2["P2 Deny outranks payment"]
  P3["P3 non-zero BLAKE3 payment evidence"]
  P4["P4 AVC receipt records the hash"]
  P5["P5 issue 812 crates.io ml-dsa"]
  P6["P6 issues 815 and 816 stay superseded"]
  P7["P7 no spec 19.6.1 claim"]
  P8["P8 issue 789 two-person stop"]
  Close["V030-CLOSE no v0.3.0 tag exists yet"]
  Authz["GD-031 decision records still PENDING"]
  Impl["v0.3.1 implementation issues"]
  P1 --> Close
  P2 --> Close
  P3 --> Close
  P4 --> Close
  P5 --> Close
  P6 --> Close
  P7 --> Close
  P8 --> Close
  Close --> Impl
  Authz --> Impl
```

`main` already contains the 0.2.4 cut of P1–P4. The node `V030-CLOSE` is still
open because [v0.3.0/GOAL.md](../v0.3.0/GOAL.md) says that cut is not a v0.3.0
close, and because this checkout has no `v0.3.0` tag. Issue #813 remains the
evidence-grade train named by the 0.2.4 RC and the 0.2.6 issue disposition.

## Crate and module graph

Existing crates are solid. Proposed modules are dashed in the labels. No new
crate is requested. A new crate would be a parallel implementation.

```mermaid
flowchart TD
  Core["exo-core HLC CBOR Hash256"]
  Id["exo-identity DID"]
  Auth["exo-authority chain narrowing"]
  Cons["exo-consent bilateral bailment"]
  Avc["exo-avc credential receipt payment_evidence_hash"]
  Pdp["exo-pdp decide and x402 adapter"]
  Gk["exo-gatekeeper eight invariants"]
  Legal["exo-legal EvidenceBundle"]
  Econ["exo-economy BailmentTerms AssuranceClass zero-launch"]
  Node["exo-node MCP AVC routes avc_rfc3161"]
  Gw["exo-gateway discovery and routing"]
  Api["exo-api DTOs"]
  Sdk["exochain-sdk and exochain-py"]
  Lynk["exochain-llm-proxy LYNK"]
  Neg["proposed negotiation states inside exo-consent"]
  Card["proposed A2A card on exo-gateway"]
  Manifest["proposed bundle manifest beside exo-legal"]
  Assure["proposed assurance interface beside exo-economy"]
  Core --> Id
  Core --> Auth
  Core --> Cons
  Core --> Avc
  Core --> Econ
  Auth --> Pdp
  Cons --> Pdp
  Avc --> Pdp
  Gk --> Pdp
  Id --> Node
  Pdp --> Node
  Avc --> Node
  Legal --> Node
  Econ --> Node
  Node --> Gw
  Api --> Gw
  Api --> Sdk
  Node --> Lynk
  Cons --> Neg
  Auth --> Neg
  Gw --> Card
  Legal --> Manifest
  Pdp --> Manifest
  Avc --> Manifest
  Node --> Manifest
  Econ --> Assure
  Manifest --> Assure
```

Module-level reuse inside the crates:

| Proposed behavior | Call this | Do not create |
| --- | --- | --- |
| Allow / Deny / Challenge | `PolicyDecisionPoint::verify_before_settle` | A market PDP |
| HTTP 402 / 403 / 200 | `exo_pdp::x402::map_decision_to_http` | A market status map |
| Payment hash | `PAYMENT_EVIDENCE_DOMAIN` and non-zero `Hash256` | A second domain |
| Receipt of that hash | `AvcTrustReceipt.payment_evidence_hash` | A parallel receipt type |
| Timestamp | `avc_rfc3161` and `POST /api/v1/avc/claims/stamp` | A new TSA crate |
| Scope check | `AuthorityChain` verification | A market permission algebra |
| Self-grant | `check_no_self_grant` with a computed flag | An agent-signed waiver |
| Bilateral propose | `exo_consent::bailment::propose` | A second `Bailment` struct |
| Pricing classifier | `AssuranceClass` | A coverage enum |
| Discovery document | `ExochainDiscoveryResponse` | A second well-known identity document that omits the existing routes |
| LLM commercial calls | LYNK receipt path | A market protocol inside the proxy |

## Work-item order

Issue identifiers are local to [ISSUES.md](ISSUES.md). They are not GitHub
issue numbers.

```mermaid
flowchart TD
  Close["V030-CLOSE"]
  D01["V031-D01 discovery pointers"]
  D02["V031-D02 A2A card"]
  D03["V031-D03 SDK clients"]
  D04["V031-D04 poisoning controls"]
  A01["V031-A01 computed NoSelfGrant"]
  A02["V031-A02 delegation narrowing"]
  A03["V031-A03 consent and revocation"]
  A04["V031-A04 DID identity binding"]
  N01["V031-N01 bilateral states"]
  N02["V031-N02 counteroffer"]
  N03["V031-N03 multipartite"]
  N04["V031-N04 fulfillment and discharge"]
  N05["V031-N05 dispute bounds"]
  E01["V031-E01 Allow-gated execution"]
  E02["V031-E02 fulfillment hash"]
  E03["V031-E03 human override"]
  S01["V031-S01 x402 profile"]
  S02["V031-S02 hash binding"]
  S03["V031-S03 never-paywall and no take-rate"]
  V01["V031-V01 claim stamp reuse"]
  V02["V031-V02 Microsoft public verify"]
  V03["V031-V03 fallback TSA"]
  V04["V031-V04 bundle manifest"]
  V05["V031-V05 two-system vectors"]
  F01["V031-F01 assurance interfaces"]
  F02["V031-F02 non-coverage guard"]
  G01["V031-G01 approval tiers"]
  G02["V031-G02 independent verification"]
  Close --> A01
  Close --> S01
  Close --> V01
  A04 --> A01
  A02 --> A01
  A03 --> N01
  A01 --> N01
  N01 --> N02
  N02 --> N03
  N03 --> N04
  N03 --> N05
  S01 --> S02
  S01 --> S03
  A01 --> E01
  N04 --> E01
  S02 --> E01
  E01 --> E02
  E03 --> E01
  D01 --> D02
  D02 --> D04
  D01 --> D03
  E02 --> V04
  S02 --> V04
  V01 --> V02
  V02 --> V03
  V02 --> V04
  V04 --> V05
  D03 --> V05
  F01 --> F02
  V04 --> F01
  G01 --> G02
  A01 --> G01
```

G01 and G02 govern how any of the other items may be written. They do not
unblock `V030-CLOSE`. An agent may draft an issue's tests after authorization.
An agent cannot approve the decision records and cannot be either release
approver.

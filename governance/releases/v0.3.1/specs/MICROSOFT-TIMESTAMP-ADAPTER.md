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

# Microsoft-backed timestamp adapter

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Capability C4, timestamp half. This file is research plus an adapter
specification. It does not assert that EXOCHAIN holds a Microsoft contract,
subscription, support plan, or SLA. No such contract was found in this
checkout, and none is assumed.

The adapter EXOCHAIN already runs is the one to reuse:
`crates/exo-node/src/avc_rfc3161.rs` and `POST /api/v1/avc/claims/stamp`.

## What Microsoft documents

Reviewed 2026-10-09 against Microsoft Learn.

### 1. Artifact Signing RFC 3161 TSA — the candidate this profile uses

Microsoft Learn, "Artifact Signing certificate management", states that
Artifact Signing provides a generally available RFC 3161 time-stamping
authority at `http://timestamp.acs.microsoft.com`, and that the countersignature
is a timestamp token from a TSA that meets the Code Signing Baseline
Requirements.

<https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management>

"Set up signing integrations to use Artifact Signing" names that endpoint
"Artifact Signing’s Microsoft Public RSA Time Stamping Authority" and shows
`signtool` `/tr http://timestamp.acs.microsoft.com`.

<https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations>

The Artifact Signing FAQ says an operator can check health with
`curl http://timestamp.acs.microsoft.com` and treat HTTP 200 as healthy.

<https://learn.microsoft.com/en-us/azure/artifact-signing/faq>

The same URL is still described on the older "Trusted Signing certificate
management" page. Trusted Signing is the previous product name in that
document. The current Learn path used above is Artifact Signing. This
proposal uses the name and URL on the current page, and mentions Trusted
Signing only so reviewers can match the older title.

<https://learn.microsoft.com/en-us/azure/trusted-signing/concept-trusted-signing-cert-management>

What those pages support:

- an RFC 3161 TSA;
- a public HTTP URL;
- a recommendation that Artifact Signing *subscribers* use it to countersign
  signatures those subscribers produce.

What those pages do not support:

- an EXOCHAIN-specific tenant, quota, or commercial commitment;
- a statement that arbitrary application claims, as opposed to code-signing
  countersignatures, are an included product;
- a statement that the URL will remain stable.

GD-031-11 is the decision to depend on this URL anyway, because the node
already does, and because the token verifies without an Azure login.

The in-tree profile already pins this URL in tests, uses policy OID
`1.3.6.1.4.1.601.10.3.1`, and uses authority DID
`did:exo:microsoft-public-rsa-tsa`. The DID is an EXOCHAIN identifier for the
TSA, not a Microsoft DID. The policy OID is the value the current stamp path
requires. It is recorded here as observed source, not as a Microsoft
marketing claim.

### 2. Azure Confidential Ledger — not the claim TSA

Azure Confidential Ledger is a customer-managed, append-only ledger the
customer creates in the customer's own subscription.

<https://learn.microsoft.com/en-us/azure/confidential-ledger/overview>

That is not an RFC 3161 TSA. A second party cannot verify a customer ledger
entry without whatever access that ledger requires. This profile does not use
it for claim attestation. A future design that wanted a ledger receipt would
be a different evidence type and a different decision.

### 3. Microsoft's Signing Transparency Ledger — not the claim TSA

Microsoft's Signing Transparency is a Microsoft-managed append-only log of
software signing events, built on the confidential-ledger platform. Microsoft
Learn says verification through that service is currently scoped to specific
Microsoft services. Receipts are COSE receipts over ledger inclusion.
Timestamp is described as optional metadata on the signing event, not as an
RFC 3161 token over an arbitrary EXOCHAIN hash.

<https://learn.microsoft.com/en-us/azure/confidential-ledger/about-microsoft-signing-transparency-ledger>

<https://learn.microsoft.com/en-us/azure/confidential-ledger/microsoft-signing-transparency-concepts>

This profile does not send market claims to Signing Transparency, and it does
not treat a Signing Transparency receipt as a substitute for the RFC 3161
token.

### 4. Protocol

The token format is RFC 3161.

<https://www.rfc-editor.org/rfc/rfc3161>

## Adapter behavior

Preferred profile for the minimum demonstration: the existing Microsoft
Artifact Signing TSA URL, the existing policy OID check on the stamp path,
and SPKI pins supplied as public bytes.

Request: RFC 3161 `TimeStampReq` over the SHA-256 imprint of the canonical
claim subject, with a nonce from `exo.avc.rfc3161.nonce.v1`. The current
code builds that request. This proposal does not replace it.

Response stored in the bundle:

| Field | Why a second party needs it |
| --- | --- |
| `token_der_base64` | The CMS token itself |
| `message_imprint_sha256` | Bind the token to the claim bytes |
| `policy_oid` | Detect substitution of a different TSA policy |
| `serial_number_hex` | Identify the token |
| `nonce_hex` | Bind the token to this request |
| `tsa_public_key_spki_der_hex` or issuing CA SPKI | Verify without asking Microsoft or EXOCHAIN for a private lookup |
| `authority_did` | Say which configured TSA signed |
| `tsa_url` | Say which URL was contacted. The URL is not the trust anchor. The SPKI is |

Verification uses the steps in [CLAIM-ATTESTATION.md](CLAIM-ATTESTATION.md).
No step reads `DATABASE_URL`, a bearer token, an Azure client secret, or an
EXOCHAIN signing key.

### Fallback

The node already selects the TSA URL from
`EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL` when kind is `rfc3161`. A fallback
is another RFC 3161 TSA at another URL, with its own DID, policy OID, and
SPKI pin. The bundle records those values. A verifier accepts the token only
under the pin in the bundle, and rejects a token whose policy OID does not
match the bundle.

The current stamp handler additionally hard-checks the Microsoft DID and the
Artifact Signing policy OID. That means the hash-only claim hop, as written,
will not accept a fallback token. This proposal does not change that code.
An authorized implementation that wants fallback on the claim hop must:

- keep the Microsoft profile as the demonstration default;
- accept a fallback only when the bundle says which TSA, which OID, and
  which pin;
- refuse a response that omits the pin;
- refuse to relabel a fallback token as the Microsoft TSA.

Silent substitution is a timestamp-authority compromise, covered in the
threat model.

### Transport

The documented URL is `http://`, not `https://`. Integrity is the CMS
signature under the pinned SPKI, not the transport. Endpoint substitution on
the network is still in the threat model: an attacker who answers the HTTP
request with a different token fails the SPKI pin. An attacker who also
substitutes the pin inside a bundle fails the parties' signatures on the
manifest hash.

Health probes against the TSA URL are operator diagnostics. They are not
evidence that a particular token is valid.

## What this adapter must not say

- That Microsoft has approved EXOCHAIN, this release, or this claim.
- That a token is a warranty.
- That Azure Confidential Ledger or Signing Transparency was consulted,
  unless a future bundle section actually carries one of those receipts and
  a decision authorizes it.
- That the in-repo publication snapshot's Microsoft references, if any,
  create a contract. They do not. The contract question is GD-031-11.

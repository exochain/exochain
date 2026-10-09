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

# Claim attestation profile

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Capability C4. Layer: verification. The timestamp transport is specified in
[MICROSOFT-TIMESTAMP-ADAPTER.md](MICROSOFT-TIMESTAMP-ADAPTER.md).

## Existing hop

`POST /api/v1/avc/claims/stamp` is the hash-only claim hop.

Request body today (`HashOnlyClaimStampRequest`):

| Field | Constraint in current code |
| --- | --- |
| `preimage_hash` | Non-zero 32-byte hash, hex |
| `hash_profile` | Must be `blake3-256` |
| `kind` | `crosschecked.action_receipt.v2`, `crosschecked.decision.v1`, or `crosschecked.claim.v1` |

The node builds canonical CBOR under domain
`exo.avc.claim.evidence_subject.v1`, takes SHA-256 of those bytes as the
RFC 3161 message imprint, and BLAKE3 of those bytes as `subject_hash`. The
response carries `timestamp_provenance = ExternalTimestampAuthority`,
`proof_kind = Rfc3161`, the authority DID, and the token. The current stamp
handler also requires the authority DID
`did:exo:microsoft-public-rsa-tsa` and policy OID
`1.3.6.1.4.1.601.10.3.1`. The hop does not mint a trust receipt.

This profile reuses that hop. It does not add a second stamper.

## What is attested

The attested object is a hash, not a paragraph. For the minimum
demonstration the preimage is the canonical portable evidence bundle bytes,
and the kind is the existing `crosschecked.claim.v1`. A new market-specific
kind is a later decision. It is not required to demonstrate the hop.

The stamp says: this hash existed, in this form, at a time the TSA agreed to
sign. It does not say the claim is true, the service was performed, the
payment cleared, or a court must accept it. Those are separate signatures
inside the bundle (PDP evidence, fulfillment, payment-evidence hash).

## Receipt the caller keeps

The independently verifiable receipt is the stamp response plus the token
bytes. A verifier needs:

- the canonical claim bytes, or enough to recompute them;
- `preimage_hash`, `hash_profile`, `kind`;
- the RFC 3161 `TimeStampToken` (CMS `SignedData`) as standard-base64 DER;
- the policy OID, serial, nonce, and message imprint recorded by
  `AvcReceiptRfc3161TimestampProof`;
- the pinned signer SPKI or issuing-CA SPKI that the node already required
  in `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX` or
  `EXO_AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX`.

Those pins are public configuration bytes. They are copied into the bundle.
A second party does not need the environment variables, the node, or an Azure
account.

## Verification steps for a second party

1. Recompute canonical CBOR of the claim subject. Reject on mismatch with
   `subject_hash` (BLAKE3) or with the SHA-256 imprint inside the token.
2. Parse the token as RFC 3161 `TimeStampResp` / CMS `SignedData`. Reject if
   the imprint algorithm is not SHA-256, the nonce does not match the
   request nonce derived under `exo.avc.rfc3161.nonce.v1`, or the policy OID
   differs from the bundle.
3. Verify the CMS signature under the pinned SPKI using the RSA algorithm
   the token names (`sha256WithRSAEncryption`, `sha384WithRSAEncryption`, or
   `sha512WithRSAEncryption`, matching the verifier in `avc_rfc3161`).
4. Check the certificate's extended key usage includes the timestamping
   purpose (`1.3.6.1.5.5.7.3.8`) when the token carries that certificate.
5. Record the TSA generalized time as evidence. Do not replace HLC ordering
   inside EXOCHAIN with that time.

If any step fails, the claim is not attested. The rest of the bundle may
still be inspected, and it must not be reported as timestamped.

## What this receipt is not

- Not a trust receipt. `claims/stamp` does not mint one. Payment evidence
  continues to live on `AvcTrustReceipt.payment_evidence_hash` when a receipt
  is minted by `POST /api/v1/avc/receipts/emit`.
- Not an Azure Confidential Ledger write.
- Not a Microsoft Signing Transparency registration.
- Not coverage, legal advice, or a warranty.

## Failure

Missing TSA configuration fails closed, as the node does today when
`EXO_AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY` is set and the URL, DID, and
trust anchor are absent. A timeout or a bad token is an attestation failure.
It is not an Allow, and it is not a reason to skip the pin and accept the
token anyway.

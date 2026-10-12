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

# Canonical portable evidence bundle

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Capability C6. Layer: verification.

## Not a second product on AVC validate

v0.3.0's non-goal forbids a second evidence-pack product on AVC validate.
This manifest honors that non-goal.

| Existing object | Stays responsible for | This manifest |
| --- | --- | --- |
| `exo-pdp` `EvidencePack` | The PDP decision record | Stores `evidence_hash` only |
| `exo-legal` `EvidenceBundle` | Forensic bundle: events, consent summaries, certification snapshot, DAG anchor, optional CGR program | Stores `legal_bundle_hash` when one exists. Does not require CGR, and does not claim spec §19.6.1 |
| `AvcTrustReceipt` | Credentialed action receipt, including optional `payment_evidence_hash` | Stores the receipt hash when one was minted |
| `POST /api/v1/avc/claims/stamp` | RFC 3161 over a hash. Does not mint a receipt | Stores the stamp response fields |
| `POST /api/v1/avc/validate` | Free validation | Unchanged. Does not return this manifest |

The interchange document is an envelope. `body` is the hashed manifest.
`timestamp` sits beside `body` and is not part of the hash. Detached
signatures sit beside both and are not part of the hash.

```text
domain = "exo.market.evidence_bundle.v1"
body_hash = BLAKE3(canonical_cbor(domain, body))
```

The stamp hop receives `body_hash` as `preimage_hash`. The RFC 3161 imprint
is over the stamp hop's own canonical claim bytes for that hash, which is
the existing `claims/stamp` behavior. The token, nonce, serial, policy, and
the rest of `timestamp` are written into the envelope after the TSA returns.
Adding them does not change `body_hash`. A verifier recomputes `body_hash`
from `body` and checks the imprint against that hash.

## Sections

The manifest connects six hashes. Each section is present. A section that
does not apply uses a reason code instead of a zero hash presented as
success. The zero hash is never a successful reference.

| Section | Required reference | Absent only when |
| --- | --- | --- |
| Identity | Principal DID, agent DID, AVC credential id, credential hash | Never, for a market demonstration |
| Authority | Authority-chain hash, PDP evidence hash, decision enum | Never |
| Agreement | Bailment transcript id, committed terms hash, party DID list | Never |
| Payment | `payment_evidence_hash` or reason `not_commercial` / `challenge_open` / `denied` | A non-commercial Allow may use `not_commercial`. A 200 commercial Allow must carry the non-zero hash |
| Execution | Fulfillment hash or reason `not_executed` | Deny and open Challenge use `not_executed` |
| Outcome | `reason = discharged` with a non-zero `discharge_hash` and `dispute_hash` null; `reason = disputed` with a non-zero `dispute_hash` and `discharge_hash` null; or `reason = open` with both hashes null | Discharge demonstration uses the discharge hash. A disputed outcome names the dispute hash |
| Artifact references | `artifact_refs.pdp_pack_hash` (required, non-zero), plus `legal_bundle_hash`, `avc_receipt_hash`, and `stamp_response_hash` (each a non-zero hash or null when that artifact was not produced) | The PDP pack hash is always present on a market bundle. The other three are null only when that artifact does not exist |

`artifact_refs` is how the manifest points at the existing PDP pack, the
legal bundle, the AVC receipt, and the stamp response. Those objects stay
in their own stores. The manifest stores the hashes.

Payment `reason = bound` requires a non-zero `payment_evidence_hash`. Reasons
`not_commercial`, `challenge_open`, and `denied` require that hash to be
null. A zero hash is not a bound payment. A non-null hash paired with
`denied` is invalid. Execution uses the same shape: `fulfilled` with a
non-zero hash, or `not_executed` with null.

Timestamp section, outside `body`:

- `proof_kind`: `Rfc3161`;
- token base64, SHA-256 imprint, policy OID, `serial_number_hex`,
  `nonce_hex`, authority DID;
- pinned SPKI hex;
- `tsa_url` actually used.

`nonce_hex` and `serial_number_hex` are required. A timestamp object without
them is not RFC 3161 evidence for this profile.

Assurance, inside `body` when present, obeys
[FINANCIAL-ASSURANCE.md](FINANCIAL-ASSURANCE.md). The field is optional.
Omission means no assurance interface was requested. Omission does not mean
coverage. The minimum demonstration includes the section with
`coverage_claim = none` so a verifier can see the non-claim. A bundle that
omits the section still validates.

## Portability

The manifest is JSON for interchange
([../schemas/evidence-bundle.schema.json](../schemas/evidence-bundle.schema.json))
and CBOR for the hash. A verifier that has the JSON, the detached Ed25519
signatures, the RFC 3161 token, and the pinned SPKI can recompute the hash
and run the checks in [CLAIM-ATTESTATION.md](CLAIM-ATTESTATION.md) and
[X402-SETTLEMENT.md](X402-SETTLEMENT.md). No field in the manifest is a
secret. Bearer tokens, private keys, connection strings, and raw payment
instruments are forbidden fields. A schema that adds one fails review.

Signatures on the manifest are from the service DID and from each committing
party, over the manifest hash. They attest that those parties saw that hash.
They do not create new authority.

## Tamper

Changing any byte of `body` changes `body_hash`. The second verifier rejects
the detached signatures and rejects the imprint match. Changing the token,
nonce, serial, or other `timestamp` field leaves `body_hash` the same and
fails timestamp verification instead. There is no repair path inside
verification. Repair is a new transcript.

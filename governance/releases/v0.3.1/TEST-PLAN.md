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

# v0.3.1 test plan

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

No test in this plan is claimed to pass in this pull request, except the
repository guards that already apply to documentation-only changes
(publication-claim checker, systemic-integrity claim checker, gap-registry
truth guard). Those guards are run because this package must not trip them.
They are not the market demonstration.

## Determinism

Every future test supplies HLC timestamps, ids, and key bytes as fixtures.
Tests do not call `SystemTime::now` or `Instant::now`. They do not use
floating point. They compare canonical CBOR bytes and BLAKE3 digests.

| Test | Assert |
| --- | --- |
| Same transcript twice | Identical CBOR and identical BLAKE3 |
| Party JSON reordered | Identical CBOR, because the hashed map is sorted |
| Counteroffer that only changes integer amount | Predictable new terms hash, permission ceiling unchanged |
| RFC 3161 nonce | Derived from the domain `exo.avc.rfc3161.nonce.v1` and the subject bytes, matching `avc_rfc3161` |

## Conformance vectors

Fixtures live in [test-vectors/](test-vectors/). A future harness loads each
file, validates it against the named schema, and checks the expected
decision. The expected decision is data. It is not a test result from this
PR.

| Vector | Schema | Expected |
| --- | --- | --- |
| `discovery-card.json` | discovery profile | Accept. `grants_authority` is false |
| `discovery-card-poison.json` | discovery profile | Reject. Signature key does not match the pin |
| `bailment-multipartite.json` | bailment negotiation | Accept as a committed transcript shape. Does not itself Allow execution |
| `self-grant-denied.json` | bailment negotiation | Authority decision Deny, invariant `no-self-grant`, HTTP 403, not 402 |
| `x402-challenge.json` | x402 settlement | HTTP 402, hash absent |
| `x402-deny-outranks-hash.json` | x402 settlement | HTTP 403 even though a non-zero hash is present |
| `claim-stamp-request.json` | claim attestation | Shape only. Kind `crosschecked.claim.v1`, profile `blake3-256` |
| `evidence-bundle-manifest.json` | evidence bundle | Accept structurally. `coverage_claim` none |
| `assurance-interface.json` | financial assurance | Accept. Constants `none` and false |
| `assurance-rejects-coverage.json` | financial assurance | Reject. `coverage_claim` is not `none` |
| `second-verifier-public-inputs.json` | `schemas/second-verifier-inputs.schema.json` | Allowed input names only |

Negative vectors are part of conformance. A harness that only runs the happy
path fails the plan.

## Authorization invariants

| Fixture | Invariant |
| --- | --- |
| Agent DID equals grantor DID | `NoSelfGrant` |
| Permission superset | `NoSelfGrant` and authority scope-widening error |
| `human_override_preserved` false | `HumanOverride` |
| No active bailment | `ConsentRequired` |
| Kernel field present on a market message | `KernelImmutability` |
| Deny plus payment hash | PDP Deny, HTTP 403 |
| Zero payment hash | Rejected before Allow |
| Header without hash | Unpaid |

## Two independent systems

System A is a future EXOCHAIN implementation, after authorization, using the
crates named in the architecture.

System B is a separate program. Its inputs are:

- the files in `schemas/` and `test-vectors/`;
- the public bundle JSON produced by the demonstration;
- detached signatures;
- the RFC 3161 token bytes;
- the pinned SPKI bytes contained in the bundle.

System B's inputs exclude, and a packaging test fails if any appear:

- `DATABASE_URL` or any other connection string;
- bearer tokens or admin tokens;
- Azure client secrets, tenant ids used as credentials, or Artifact Signing
  account names;
- EXOCHAIN private keys or seed bytes;
- the workspace source tree.

System B recomputes BLAKE3 over canonical CBOR, checks Ed25519 signatures,
and checks the CMS timestamp under the pinned SPKI. It prints the same
decision strings as System A for each vector: `accept`, `deny_self_grant`,
`challenge_402`, `deny_403`, `reject_schema`, `reject_timestamp`.

Disagreement is a failed demonstration. System B is not required to produce
tokens. It only verifies them. Token production in the minimum demonstration
uses the existing stamp path when a human operator has configured the TSA.
If that configuration is absent, the demonstration stops at a recorded
fail-closed attestation error. It does not substitute a locally signed fake
and call it Microsoft.

## Third-party interoperability

AC-8 is this table plus System B. Additionally, an HTTP client that is not
the EXOCHAIN SDK performs:

1. `GET /.well-known/exochain.json`
2. `GET /.well-known/agent-card.json`
3. signature check
4. `POST` of the proposal message to the URL on the card

The client is documented as a short script in the future implementation's
test directory. This proposal does not add that script, because a script
that spoke to a live service would be implementation.

## Guards this proposal already expects

| Guard | Why it applies now |
| --- | --- |
| `python3 tools/check_published_release_claim.py` | This package must not create or break a publication claim |
| `bash tools/check_systemic_integrity_claims.sh` | New docs are outside the claim-file list. The guard must still pass |
| `bash tools/test_gap_registry_truth.sh` | `GAP-REGISTRY.md` is unchanged and must stay the only VCG ledger |

## What is not a test

A narrative walkthrough, a green CI run on this docs PR, and an agent
statement that the design "handles" a threat are not acceptance. The issue
list names the tests that would count later.

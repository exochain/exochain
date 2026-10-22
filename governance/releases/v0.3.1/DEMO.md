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

# Minimum demonstration script

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

This is a script for a later, authorized build. It is not a claim that the
demonstration has been run. Actors are roles, not production identities.

## Cast

| Role | DID in the future fixture | Holds |
| --- | --- | --- |
| Human principal | `did:exo:demo-principal` | The mandate. Grantor. Not an agent |
| Independent agent | `did:exo:demo-agent` | A narrowed AVC. Cannot be grantor |
| Service | `did:exo:demo-service` | The commercial skill |
| Witness | `did:exo:demo-witness` | Signs. Not in the default threshold |
| Second verifier | none | No DID, no key, no account |

Keys are fixture bytes generated in the future test, recorded by value in
the evidence directory of that run. They are not generated in this package.

## Preconditions that are outside this package

- GD-031-01 and the records the script relies on are no longer PENDING.
  While they are PENDING, running this script against a deployed service is
  out of bounds.
- `V030-CLOSE` exists as a signed close. [V030-CLOSE-RECORD.md](V030-CLOSE-RECORD.md)
  is an unsigned draft of where that close is recorded. The draft does not
  satisfy this precondition.
- The market feature flag is explicitly enabled for the demo process and
  off by default everywhere else.
- TSA configuration for the Microsoft profile is present, or the script
  stops at the stamp step with a fail-closed error and does not invent a
  token.

## Steps

1. **Discover.** The agent HTTP-GETs `/.well-known/exochain.json` and
   `/.well-known/agent-card.json` from the service origin. It verifies the
   card under the pinned service key. It does not load an MCP permission.
2. **Self-check.** The agent submits a copy of the proposal whose permission
   list adds one name. Expect Deny, invariant `no-self-grant`, HTTP 403.
   Then it submits the real proposal, which is inside the ceiling.
3. **Negotiate.** Principal, agent (as agent of the principal), and service
   exchange proposal and one counteroffer that lowers `amount_minor` and
   does not add permissions. Witness signs and is not required. All three
   required signatures commit. Authority evaluation returns Allow for the
   commit action only.
4. **Pay.** The commercial execute call without a payment hash returns 402.
   The client submits a non-zero BLAKE3 hash of the canonical payment
   evidence bound to this mandate and terms hash. A parallel call that is
   Deny for another reason, with a hash attached, returns 403.
5. **Receive.** Execution runs only after the bailment is `Active`. It emits
   a fulfillment hash. The agent receives the service payload defined by the
   fixture, which contains no other tenant's data.
6. **Discharge.** Threshold signatures discharge. The outcome is
   `discharged` and carries `discharge_hash`. The transcript is retained.
   This happens before the evidence body is hashed, so the outcome in the
   body is the terminal outcome.
7. **Assemble the hashed body.** Build `body` of
   `exo.market.evidence_bundle.v1`: identity, authority, agreement, payment,
   execution, outcome (including the discharge hash), `artifact_refs`, and
   assurance with `coverage_claim=none`. Compute
   `body_hash = BLAKE3(canonical_cbor("exo.market.evidence_bundle.v1", body))`.
   `body` does not contain the timestamp token, nonce, serial, or other
   timestamp metadata.
8. **Stamp that preimage.** The node stamps `body_hash` through
   `POST /api/v1/avc/claims/stamp` with `hash_profile=blake3-256` and
   `kind=crosschecked.claim.v1`. The response includes an RFC 3161 token.
   Write `timestamp` beside `body`. Recompute `body_hash` and require it to
   equal the hash that was stamped. Attaching the token must not change it.
9. **Second system.** A process with only the public artifact directory
   reruns verification. Its inputs include the committing parties' public
   keys, the service public key, the detached signatures, the RFC 3161
   token, and the TSA SPKI pin. It accepts the bundle. It rejects a copy
   with one flipped bit in the payment hash, a copy with the Microsoft DID
   on a fallback token, and a copy with `coverage_claim` set to `in_force`.

## Evidence artifacts the run must produce

Written to a directory named by the run id, mode 0755 for the directory and
0644 for the files, with no private keys:

| File | Contents |
| --- | --- |
| `01-exochain.json` | Discovery document bytes |
| `02-agent-card.json` | Card and signature |
| `03-self-grant-deny.json` | 403 body and invariant id |
| `04-transcript.cbor` | Canonical transcript |
| `04-transcript.blake3` | Hex digest |
| `05-challenge-402.json` | Unpaid response |
| `05-deny-403.json` | Deny with a hash attached |
| `05-allow-200.json` | Allow with the bound hash |
| `06-fulfillment.json` | Fulfillment hash and Allow evidence hash |
| `07-discharge.json` | Terminal discharge, including `discharge_hash`, written before the body is hashed |
| `08-evidence-body.cbor` | Canonical CBOR of `body` only. This is the stamp preimage's manifest bytes |
| `08-body.blake3` | `body_hash` |
| `09-rfc3161-token.b64` | Token attached after the stamp |
| `09-rfc3161-meta.json` | OID, serial, nonce, imprint, SPKI pin, URL, authority DID |
| `09-evidence-bundle.json` | Envelope: `body` plus `timestamp`. Signatures are detached |
| `10-committing-party-public-keys.json` | Public Ed25519 keys for the parties who signed, keyed by DID |
| `10-service-public-key.hex` | Service card signing key, public |
| `10-second-verifier.txt` | Decision lines, the inputs it opened, and the content-scan result |

`10-second-verifier.txt` may say that the input set contained no connection
string, bearer token, Azure secret, or EXOCHAIN private key only after a
content scan of every artifact file, of the verifier process environment,
and of the verifier argv. The scan reads bytes. A directory listing is
recorded and is not that proof. The scan rejects PEM private-key blocks,
`Bearer` authorization values, database URLs, and Azure client-secret
assignments. It does not treat a public-key field as a private key. A scan
failure fails the demonstration.

## Stop conditions

Stop and record the step id if any expected status differs, if a hash is
non-deterministic across two local replays, if the stamp path is
unconfigured, or if any GD-031 record required for the run is PENDING.
Do not continue with a substitute success.

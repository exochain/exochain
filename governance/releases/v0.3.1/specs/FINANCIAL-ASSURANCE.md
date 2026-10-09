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

# Financial-assurance schema and adapter interfaces

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Capability C7.

## These are interfaces, not coverage

This specification defines schemas and adapter interfaces where an
independent issuer might later attach a surety bond, an insurance policy, a
bonding instrument, or a reinsurance contract.

**EXOCHAIN does not provide insurance. EXOCHAIN does not provide surety.
EXOCHAIN does not provide bonding. EXOCHAIN does not provide reinsurance.
Nothing in this file, the schema, or a bundle that validates against the
schema is a policy, a bond, a binder, or a promise to pay.**

`exo-economy::AssuranceClass` (`Free`, `Standard`, `Anchored`, `LegalGrade`,
`Regulated`, `Critical`) is a pricing classifier. It is not a coverage
class. A value of `LegalGrade` or `Critical` must not be described as
insurance.

The schema fixes two constants:

| Field | Fixed value | Meaning |
| --- | --- | --- |
| `coverage_claim` | `none` | This object claims no coverage |
| `exochain_is_obligor` | `false` | EXOCHAIN is not the insurer, surety, principal on a bond, or reinsurer |

A document that sets any other value is invalid under this schema. An
implementation that accepts another value is a defect. Marketing text,
health endpoints, MCP tool descriptions, and SDK error strings are subject
to the same rule. GD-031-10 is the human policy for whether a named partner
may later issue a product that references these interfaces. Until that
record is filled, no partner is authorized, and the interface still claims
no coverage.

## Adapter shape

An adapter is a function, specified here and not implemented, with this
behavior:

```text
submit(interface_object) -> Accepted { partner_reference_hash } | Rejected { reason }
```

`submit` sends the hash of the canonical interface object to a partner
endpoint configured outside EXOCHAIN. The partner returns a reference hash
and a signature under the partner's key. EXOCHAIN stores those bytes as
evidence that a request was made and a response was signed. Storage is not
acceptance of risk by EXOCHAIN.

The adapter fails closed when:

- the partner URL, partner DID, or partner SPKI pin is missing;
- `coverage_claim` is not `none` on the outbound object;
- the partner response tries to set `exochain_is_obligor` to true;
- the partner response's signature does not verify;
- the partner response claims EXOCHAIN is the issuer.

A failed adapter does not block a bailment that did not require assurance,
and it does not convert a PDP Deny into Allow. Assurance is not payment and
not authority.

## Interface object

Fields, all required on the proposed schema:

| Field | Rule |
| --- | --- |
| `schema` | `exo.market.assurance.interface.v1` |
| `coverage_claim` | constant `none` |
| `exochain_is_obligor` | constant `false` |
| `instrument_family` | one of `surety`, `insurance`, `bonding`, `reinsurance`, `unspecified` |
| `issuer_did` | empty string unless GD-031-10 names an issuer. Empty means no issuer |
| `subject_bundle_hash` | BLAKE3 of the evidence manifest this note would attach to |
| `limit_minor` | integer. Zero unless an authorized issuer sets it. A non-zero limit with an empty `issuer_did` is invalid |
| `currency` | ISO-like currency code string. Not an EXO Credit |
| `terms_hash` | hash of the partner's own terms, or 32 zero bytes only when `issuer_did` is empty. A zero hash with a non-empty issuer is invalid |
| `statement` | the fixed sentence below |

Fixed `statement` value:

```text
Interface only. EXOCHAIN does not provide insurance, surety, or bonding. No coverage is in force.
```

`instrument_family` names the slot a future partner product would fill. It
does not fill it. `unspecified` is the value for the minimum demonstration.

## What a later partner would have to be

If GD-031-10 is ever filled, the partner is an independent issuer. EXOCHAIN
would verify the partner signature and store the reference hash. The partner
policy, the partner's license, and the partner's obligation stay outside the
kernel. Human override against EXOCHAIN does not rewrite a partner contract.
This paragraph is a constraint on a future decision. It is not that decision.

## Forbidden representations

The following sentences are defects if they appear as claims about this
interface: "insured by EXOCHAIN", "bonded by EXOCHAIN", "EXOCHAIN surety",
"coverage included", "reinsured by the protocol". The test plan includes a
source scan for those phrases in any future market crate. This proposal
states the prohibition so the scan has a spec to enforce.

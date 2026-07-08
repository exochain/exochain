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

# LLM Usage Custody

EXOCHAIN LYNK Protocol receipts are minimized by default. They bind a model or
tool call to hashes, scoped authority, tenant and namespace, action identity,
usage counters, custody policy, timestamps, finality evidence, and safe metadata.
AVC receipts must not contain raw prompts, completions, tool arguments, tool
results, files, secrets, bearer tokens, private keys, raw signatures, KMS
material, raw object URIs, or decryptable payload references.

DAG DB is separate governed custody. When explicitly authorized, it may store
memory objects, summaries, graph and context records, and CBOR payloads under
tenant/namespace isolation, consent, signatures, idempotency, receipts, finality,
RLS, and route-level authority. Receipt minimization is an adapter policy; it is
not a global claim that EXOCHAIN never stores governed data.

## Storage Modes

| Mode | Receipt Contents | DAG DB Contents | Customer Storage |
| --- | --- | --- | --- |
| `receipt_minimized` | Hashes, usage counters, safe metadata, custody policy hash, receipt and finality refs. | None required. | Raw provider payload may remain only in caller memory. |
| `external_payload_ref` | Hashes plus opaque hashed encrypted-ref ids and ciphertext/policy hashes. | Optional safe metadata only. | Encrypted prompt/output blobs under customer object storage and customer KMS. |
| `dagdb_custody` | Hashes, usage counters, safe metadata, custody policy hash, and DAG DB receipt refs. | Governed tenant data under explicit consent, policy, signatures, idempotency, RLS, and receipts. | Optional external backup outside EXOCHAIN. |

## Write Boundary

DAG DB governed custody is reachable only through served routes and persistence
APIs that apply tenant/session authority, consent, signature, idempotency,
receipt, and RLS checks. Consumers must not write `dagdb_*` tables directly and
must not treat raw `exo_dag_db_postgres::postgres::*` functions as a public
governance-bearing surface.

Raw or decryptable prompts, completions, tool arguments, and tool results require
explicit `dagdb_custody` plus separate consent and custody-policy evidence. In
`receipt_minimized` and `external_payload_ref` modes, AVC receipts and DAG DB
metadata may carry only hashes, usage counters, safe metadata, receipt links, and
opaque hashed references.

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

# Proposed conformance fixtures

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release.**

Hex digests and signatures in these files are shape fixtures: 64 hex
characters for a 32-byte hash, 128 hex characters for an Ed25519 signature,
64 hex characters for an Ed25519 public key. They are not the output of a
BLAKE3 or signature computation performed for this package. A future harness
replaces them with digests it computes, then checks the expected decision in
`expectations.json`.

`assurance-rejects-coverage.json` is intentionally invalid under
`financial-assurance.schema.json`.
